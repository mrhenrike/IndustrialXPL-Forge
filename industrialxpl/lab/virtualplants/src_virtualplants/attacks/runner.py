"""Controlled attack runner with confirm, timeout and snapshot rollback.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, Optional

from . import AttackRecord, get_attack
from .adapters import plan_adapter
from .pocs import run_internal
from ..core.events import PlantEvent
from ..core.safety import LabSafetyError, assert_lab_target, iter_safe_argv, require_confirmation
from ..core.scenario import ScenarioManifest
from ..core.snapshots import SnapshotStore
from ..core.telemetry import TelemetryBus


LOGGER = logging.getLogger("virtualplants.runner")


async def run_attack(
    record: AttackRecord,
    manifest: ScenarioManifest,
    host: str,
    port: int,
    *,
    confirm: bool,
    telemetry: Optional[TelemetryBus] = None,
    snapshots: Optional[SnapshotStore] = None,
    extra: Optional[Dict[str, str]] = None,
) -> Dict[str, object]:
    """Execute one catalogued attack against a validated lab target."""
    require_confirmation(confirm, record.attack_id)
    if record.attack_id not in manifest.allowed_attacks:
        raise LabSafetyError("attack is not allowed on this scenario")
    target = assert_lab_target(host, manifest.allowed_targets)
    plan = plan_adapter(record, target, port)
    if telemetry:
        telemetry.emit(
            PlantEvent(
                event_type="attack_start",
                source="attack-runner",
                message="Starting %s" % record.attack_id,
                scenario_id=manifest.scenario_id,
                details={"adapter": record.adapter, "host": target, "port": port},
            )
        )
    result: Dict[str, object]
    try:
        if plan.executable == "internal":
            result = await asyncio.wait_for(
                run_internal(record.attack_id, target, port, extra or {}),
                timeout=manifest.resource_limits.request_timeout_seconds * 4,
            )
        else:
            if not plan.available:
                result = {"ok": False, "skipped": True, "reason": plan.reason}
            else:
                argv = [plan.executable, *iter_safe_argv(plan.argv)]
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=manifest.timeout_seconds,
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    raise LabSafetyError("attack timed out")
                result = {
                    "ok": proc.returncode == 0,
                    "returncode": proc.returncode,
                    "stdout": stdout.decode("utf-8", "replace")[-2000:],
                    "stderr": stderr.decode("utf-8", "replace")[-2000:],
                }
    finally:
        if snapshots is not None and snapshots.has_snapshot() and record.rollback == "snapshot":
            snapshots.restore()
    if telemetry:
        telemetry.emit(
            PlantEvent(
                event_type="attack_end",
                source="attack-runner",
                message="Finished %s" % record.attack_id,
                scenario_id=manifest.scenario_id,
                details={"result_ok": bool(result.get("ok")), "skipped": bool(result.get("skipped"))},
            )
        )
    return result


async def run_attack_id(
    attack_id: str,
    manifest: ScenarioManifest,
    host: str,
    port: int,
    *,
    confirm: bool,
    telemetry: Optional[TelemetryBus] = None,
    snapshots: Optional[SnapshotStore] = None,
) -> Dict[str, object]:
    """Lookup catalog id then run."""
    record = get_attack(attack_id)
    return await run_attack(
        record,
        manifest,
        host,
        port,
        confirm=confirm,
        telemetry=telemetry,
        snapshots=snapshots,
    )
