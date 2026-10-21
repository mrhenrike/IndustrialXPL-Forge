"""Entrypoint for modern bottle-filling virtual plant services.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import socket
import sys
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
from typing import Dict

import uvicorn

from . import APP_VERSION
from .config import AppConfig
from .protocols.modbus_server import ModbusBridge
from .protocols.opcua_server import OpcUaBridge
from .simulation import BottleFillingSimulation
from .state import SharedPlantState
from .web_apps import create_control_hmi_app, create_hmi_app, create_world_app


LOGGER = logging.getLogger("virtualplants.main")


def _ensure_core_on_path() -> None:
    """Import virtualplants from the repository src tree."""
    repo_root = Path(__file__).resolve().parents[4]
    core_src = repo_root / "src"
    if core_src.is_dir() and str(core_src) not in sys.path:
        sys.path.insert(0, str(core_src))


def parse_args() -> argparse.Namespace:
    """Parse runtime arguments."""
    parser = argparse.ArgumentParser(description="Modern Bottle Filling Virtual Plant")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--world-port", type=int, default=80)
    parser.add_argument("--hmi-port", type=int, default=8080)
    parser.add_argument("--control-port", type=int, default=8082)
    parser.add_argument("--modbus-port", type=int, default=15020)
    parser.add_argument("--opcua-port", type=int, default=14840)
    parser.add_argument("--tick-seconds", type=float, default=0.02)
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--expose-lan", action="store_true", help="Allow private LAN bind instead of loopback")
    parser.add_argument("--lab-profile", choices=("vulnerable", "patched"), default="vulnerable")
    parser.add_argument(
        "--opcua-profile",
        choices=("insecure", "authenticated", "sign-encrypt"),
        default="insecure",
    )
    return parser.parse_args()


def can_bind_port(host: str, port: int) -> bool:
    """Check if current user can bind host/port."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def resolve_ports(config: AppConfig) -> AppConfig:
    """Resolve fallback web ports when privileged ports are unavailable."""
    if not can_bind_port(config.bind_host, config.world_port):
        LOGGER.warning(
            "Cannot bind world port %s, using fallback %s",
            config.world_port,
            config.world_fallback_port,
        )
        config.world_port = config.world_fallback_port

    if not can_bind_port(config.bind_host, config.hmi_port):
        LOGGER.warning(
            "Cannot bind HMI port %s, using fallback %s",
            config.hmi_port,
            config.hmi_fallback_port,
        )
        config.hmi_port = config.hmi_fallback_port

    if not can_bind_port(config.bind_host, config.control_port):
        LOGGER.warning(
            "Cannot bind control HMI port %s, using fallback %s",
            config.control_port,
            config.control_fallback_port,
        )
        config.control_port = config.control_fallback_port

    return config


def configure_logging(level: str) -> None:
    """Setup logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


async def run_services(config: AppConfig) -> None:
    """Start and run all service components."""
    _ensure_core_on_path()
    from virtualplants.core.detection import DetectionEngine
    from virtualplants.core.safety import validate_bind_host
    from virtualplants.core.telemetry import TelemetryBus

    config.bind_host = validate_bind_host(config.bind_host, config.expose_lan)
    telemetry = TelemetryBus()
    DetectionEngine(telemetry)

    shared_state = SharedPlantState()
    simulation = BottleFillingSimulation(shared_state=shared_state, tick_seconds=config.tick_seconds)
    modbus = ModbusBridge(
        state=shared_state,
        host=config.bind_host,
        port=config.modbus_port,
        telemetry=telemetry,
        lab_profile=config.lab_profile,
    )
    opcua = OpcUaBridge(
        state=shared_state,
        host=config.bind_host,
        port=config.opcua_port,
        security_profile=config.opcua_profile,
        telemetry=telemetry,
    )

    world_app = create_world_app(shared_state)
    hmi_app = create_hmi_app(shared_state)
    control_hmi_app = create_control_hmi_app(shared_state)

    world_server = uvicorn.Server(
        uvicorn.Config(
            app=world_app,
            host=config.bind_host,
            port=config.world_port,
            log_level=config.log_level.lower(),
            access_log=False,
        )
    )
    hmi_server = uvicorn.Server(
        uvicorn.Config(
            app=hmi_app,
            host=config.bind_host,
            port=config.hmi_port,
            log_level=config.log_level.lower(),
            access_log=False,
        )
    )
    control_hmi_server = uvicorn.Server(
        uvicorn.Config(
            app=control_hmi_app,
            host=config.bind_host,
            port=config.control_port,
            log_level=config.log_level.lower(),
            access_log=False,
        )
    )

    shutdown_event = asyncio.Event()

    def _handle_signal(*_args: object) -> None:
        LOGGER.info("Shutdown signal received")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal)
        except NotImplementedError:
            signal.signal(sig, lambda *_x: _handle_signal())

    tasks = [
        asyncio.create_task(simulation.run(), name="simulation"),
        asyncio.create_task(modbus.start(), name="modbus-server"),
        asyncio.create_task(opcua.start(), name="opcua-server"),
        asyncio.create_task(world_server.serve(), name="world-web"),
        asyncio.create_task(hmi_server.serve(), name="hmi-web"),
        asyncio.create_task(control_hmi_server.serve(), name="control-hmi-web"),
    ]

    LOGGER.info("VirtualPlants Bottle Filling v%s", APP_VERSION)
    LOGGER.info("World URL: http://%s:%s", config.bind_host, config.world_port)
    LOGGER.info("HMI Monitor URL: http://%s:%s", config.bind_host, config.hmi_port)
    LOGGER.info("HMI Control URL: http://%s:%s", config.bind_host, config.control_port)
    LOGGER.info("Modbus TCP: %s:%s", config.bind_host, config.modbus_port)
    LOGGER.info("OPC UA: opc.tcp://%s:%s/virtualplants/bottle-filling/", config.bind_host, config.opcua_port)

    await shutdown_event.wait()

    simulation.stop()
    world_server.should_exit = True
    hmi_server.should_exit = True
    control_hmi_server.should_exit = True
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


def build_config(args: argparse.Namespace) -> AppConfig:
    """Create config object from CLI args."""
    return AppConfig(
        bind_host=args.host,
        world_port=args.world_port,
        hmi_port=args.hmi_port,
        control_port=args.control_port,
        modbus_port=args.modbus_port,
        opcua_port=args.opcua_port,
        tick_seconds=args.tick_seconds,
        log_level=args.log_level.upper(),
        expose_lan=bool(args.expose_lan),
        lab_profile=str(args.lab_profile),
        opcua_profile=str(args.opcua_profile),
    )


def main() -> int:
    """Application entrypoint."""
    args = parse_args()
    config = resolve_ports(build_config(args))
    configure_logging(config.log_level)
    LOGGER.debug("Runtime config: %s", asdict(config))
    asyncio.run(run_services(config))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
