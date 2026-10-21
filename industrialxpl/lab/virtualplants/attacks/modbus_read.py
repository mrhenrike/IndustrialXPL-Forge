"""Read arbitrary holding-register window.

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


LOGGER: Final[logging.Logger] = logging.getLogger("attacks.modbus_read")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Read holding registers in loop")
    parser.add_argument("-i", "--ip", default="127.0.0.1", help="Modbus server IP/host")
    parser.add_argument("-p", "--port", type=int, default=15020, help="Modbus TCP port")
    parser.add_argument("-r", "--reg", type=int, default=1, help="Start holding register (1-based)")
    parser.add_argument("-c", "--count", type=int, default=16, help="Number of registers")
    parser.add_argument("--interval", type=float, default=1.0, help="Read interval in seconds")
    return parser.parse_args()


def main() -> int:
    """Entrypoint."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    args = parse_args()
    try:
        assert_lab_target(args.ip)
    except LabTargetError as exc:
        LOGGER.error("%s", exc)
        return 2
    address = max(1, int(args.reg)) - 1
    count = max(1, min(125, int(args.count)))

    client = ModbusTcpClient(host=args.ip, port=args.port)
    if not client.connect():
        LOGGER.error("Unable to connect to %s:%s", args.ip, args.port)
        return 1

    try:
        while True:
            response = client.read_holding_registers(address=address, count=count, device_id=1)
            if response.isError():
                LOGGER.error("Read error HR[%04d..%04d]", address + 1, address + count)
            else:
                LOGGER.info("HR[%04d..%04d]=%s", address + 1, address + count, response.registers)
            time.sleep(max(0.1, float(args.interval)))
    except KeyboardInterrupt:
        LOGGER.info("Interrupted by user")
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
