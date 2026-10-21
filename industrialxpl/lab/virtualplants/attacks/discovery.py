#!/usr/bin/env python3
"""Poll holding registers from bottle-filling plant.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""

from __future__ import annotations

import argparse
import logging
import time
from typing import Final

from pymodbus.client import ModbusTcpClient

from lab_guard import LabTargetError, assert_lab_target


LOGGER: Final[logging.Logger] = logging.getLogger("attacks.discovery")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Read HR[1..16] continuously")
    parser.add_argument("--host", default="127.0.0.1", help="Modbus server host")
    parser.add_argument("--port", type=int, default=15020, help="Modbus TCP port")
    parser.add_argument("--interval", type=float, default=1.0, help="Poll interval in seconds")
    return parser.parse_args()


def main() -> int:
    """Entrypoint."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    args = parse_args()
    try:
        assert_lab_target(args.host)
    except LabTargetError as exc:
        LOGGER.error("%s", exc)
        return 2
    client = ModbusTcpClient(host=args.host, port=args.port)
    if not client.connect():
        LOGGER.error("Unable to connect to %s:%s", args.host, args.port)
        return 1

    try:
        while True:
            response = client.read_holding_registers(address=0, count=16, device_id=1)
            if response.isError():
                LOGGER.error("Read error on HR block")
            else:
                LOGGER.info("HR=%s", response.registers)
            time.sleep(max(0.1, float(args.interval)))
    except KeyboardInterrupt:
        LOGGER.info("Polling interrupted by user")
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
