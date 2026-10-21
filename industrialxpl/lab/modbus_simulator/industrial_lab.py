#!/usr/bin/env python3
"""Poll the local IED, RTU and PLC simulators through an industrial gateway."""

from __future__ import annotations

import argparse
import time
from typing import Dict

from modbus_simulator_ctl import ModbusController


ENDPOINTS = {
    "ied": (15031, 1),
    "rtu": (15032, 2),
    "plc": (15033, 3),
    "gateway": (15034, 4),
}


def connect_all(host: str, timeout: float) -> Dict[str, ModbusController]:
    controllers: Dict[str, ModbusController] = {}
    for name, (port, unit_id) in ENDPOINTS.items():
        controller = ModbusController(host, port, unit_id, timeout)
        if not controller.connect():
            for connected in controllers.values():
                connected.disconnect()
            raise RuntimeError(f"unable to connect to {name} at {host}:{port}")
        controllers[name] = controller
    return controllers


def poll_once(controllers: Dict[str, ModbusController]) -> None:
    voltage = controllers["ied"].read_holding_registers(0, 1)
    temperature = controllers["rtu"].read_holding_registers(0, 1)
    speed = controllers["plc"].read_holding_registers(0, 1)
    if voltage is None or temperature is None or speed is None:
        raise RuntimeError("a field device returned no process value")

    values = [voltage[0], temperature[0], speed[0]]
    if not controllers["gateway"].write_multiple_registers(10, values):
        raise RuntimeError("gateway rejected its cache update")
    print(
        "Gateway cache: voltage=%d V, temperature=%.1f degC, speed=%d rpm"
        % (values[0], values[1] / 10.0, values[2])
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--cycles", type=int, default=10)
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("industrial_lab.py is restricted to loopback")
    if not 0.1 <= args.interval <= 60.0 or not 1 <= args.cycles <= 10000:
        raise SystemExit("interval or cycle count is outside the safe range")

    controllers = connect_all(args.host, 3.0)
    try:
        for _ in range(args.cycles):
            poll_once(controllers)
            time.sleep(args.interval)
    finally:
        for controller in controllers.values():
            controller.disconnect()


if __name__ == "__main__":
    main()
