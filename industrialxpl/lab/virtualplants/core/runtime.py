"""Scenario runtime: start pairing targets or the bottle-filling plant.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Optional

from ..core.detection import DetectionEngine
from ..core.scenario import ScenarioManifest
from ..core.snapshots import SnapshotStore
from ..core.telemetry import TelemetryBus
from ..lab import DeltaDvpTarget, FuxaHttpTarget, ProtocolCrashTarget


LOGGER = logging.getLogger("virtualplants.runtime")


@dataclass
class RunningLab:
    """Handle to a started lab scenario."""

    manifest: ScenarioManifest
    telemetry: TelemetryBus
    detections: DetectionEngine
    snapshots: SnapshotStore
    service: Any
    host: str
    port: int

    async def stop(self) -> None:
        """Stop the underlying service."""
        stop = getattr(self.service, "stop", None)
        if stop is not None:
            await stop()


async def start_pairing_lab(manifest: ScenarioManifest, telemetry: TelemetryBus) -> RunningLab:
    """Start a non-plant pairing target from a manifest."""
    detections = DetectionEngine(telemetry)
    snapshots = SnapshotStore()
    endpoint = manifest.endpoints[0]
    host = manifest.bind_host
    port = endpoint.port
    plant = manifest.plant
    patched = manifest.profile == "patched"
    service: Any
    if plant == "delta-dvp12se":
        service = DeltaDvpTarget(
            host,
            port,
            patched=patched,
            telemetry=telemetry,
            scenario_id=manifest.scenario_id,
            limits=manifest.resource_limits,
        )
        await service.start()
        port = service.server.bound_port
        snapshots = service.snapshots
    elif plant == "fuxa":
        service = FuxaHttpTarget(host, port, patched=patched, telemetry=telemetry, scenario_id=manifest.scenario_id)
        await service.start()
        port = service.bound_port
    elif plant in {"libiec61850", "lib60870", "open62541"}:
        family = {"libiec61850": "iec61850", "lib60870": "iec60870", "open62541": "open62541"}[plant]
        service = ProtocolCrashTarget(
            host,
            port,
            patched=patched,
            family=family,
            telemetry=telemetry,
            scenario_id=manifest.scenario_id,
        )
        await service.start()
        port = service.bound_port
    else:
        raise RuntimeError("unsupported pairing plant: %s" % plant)
    return RunningLab(
        manifest=manifest,
        telemetry=telemetry,
        detections=detections,
        snapshots=snapshots,
        service=service,
        host=host,
        port=port,
    )
