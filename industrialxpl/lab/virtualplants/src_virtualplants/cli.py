"""Command-line entry for VirtualPlants lab operations.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
from typing import Sequence

from . import APP_VERSION
from .attacks import load_catalog
from .attacks.runner import run_attack_id
from .core.runtime import start_pairing_lab
from .core.safety import LabSafetyError, validate_bind_host
from .core.scenario import get_manifest, list_manifests
from .core.telemetry import TelemetryBus
from .paths import ensure_workspace_dirs
from .protocols import PROTOCOL_CONTRACTS


def _parser() -> argparse.ArgumentParser:
    """Build CLI parser."""
    parser = argparse.ArgumentParser(description="VirtualPlants-For-OT lab controller")
    parser.add_argument("--log-level", default="INFO")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list-scenarios", help="List validated scenarios")
    sub.add_parser("list-attacks", help="List catalogued lab attacks")
    sub.add_parser("list-protocols", help="Show protocol contracts")

    start = sub.add_parser("start", help="Start a pairing scenario (not bottle-filling UI)")
    start.add_argument("--scenario", required=True)
    start.add_argument("--host", default="127.0.0.1")
    start.add_argument("--port", type=int, default=0)
    start.add_argument("--expose-lan", action="store_true")

    attack = sub.add_parser("attack", help="Run a catalogued attack against a local scenario endpoint")
    attack.add_argument("--scenario", required=True)
    attack.add_argument("--id", required=True)
    attack.add_argument("--host", default="127.0.0.1")
    attack.add_argument("--port", type=int, required=True)
    attack.add_argument("--confirm", action="store_true")
    return parser


async def _cmd_start(args: argparse.Namespace) -> int:
    """Start pairing lab and wait until interrupted."""
    manifest = get_manifest(args.scenario)
    if manifest.plant == "bottle-filling":
        raise LabSafetyError(
            "bottle-filling starts with plants/bottle-filling/plantctl.ps1 or plantctl.sh, not this command"
        )
    bind = validate_bind_host(args.host, bool(args.expose_lan))
    object.__setattr__(manifest, "bind_host", bind)
    if args.port:
        endpoint = manifest.endpoints[0]
        object.__setattr__(endpoint, "port", int(args.port))
    bus = TelemetryBus()
    lab = await start_pairing_lab(manifest, bus)
    logging.getLogger("virtualplants.cli").info(
        "Scenario %s listening on %s:%s (profile=%s). Ctrl+C to stop.",
        manifest.scenario_id,
        lab.host,
        lab.port,
        manifest.profile,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            break
    try:
        await stop.wait()
    except asyncio.CancelledError:
        pass
    finally:
        await lab.stop()
    return 0


async def _cmd_attack(args: argparse.Namespace) -> int:
    """Run one attack."""
    manifest = get_manifest(args.scenario)
    bus = TelemetryBus()
    result = await run_attack_id(
        args.id,
        manifest,
        args.host,
        int(args.port),
        confirm=bool(args.confirm),
        telemetry=bus,
    )
    sys.stdout.write(json.dumps(result, indent=2) + "\n")
    return 0 if result.get("ok") or result.get("skipped") else 2


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint."""
    ensure_workspace_dirs()
    parser = _parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        if args.command == "list-scenarios":
            for manifest in list_manifests():
                sys.stdout.write(
                    "%s\t%s\t%s\t%s\n"
                    % (manifest.scenario_id, manifest.profile, manifest.plant, manifest.reproduction)
                )
            return 0
        if args.command == "list-attacks":
            for record in load_catalog():
                sys.stdout.write("%s\t%s\t%s\t%s\n" % (record.attack_id, record.adapter, record.cve, record.license))
            return 0
        if args.command == "list-protocols":
            for contract in PROTOCOL_CONTRACTS:
                sys.stdout.write("%s\t%s\t%s\t%s\n" % (contract.name, contract.status, contract.default_port, contract.notes))
            return 0
        if args.command == "start":
            return asyncio.run(_cmd_start(args))
        if args.command == "attack":
            return asyncio.run(_cmd_attack(args))
    except KeyboardInterrupt:
        return 130
    except LabSafetyError as exc:
        logging.getLogger("virtualplants.cli").error("%s", exc)
        return 2
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
