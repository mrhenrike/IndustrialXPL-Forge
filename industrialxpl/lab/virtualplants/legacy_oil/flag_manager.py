#!/usr/bin/env python3
"""Legacy CTF flag writer for the external oil plant VM.

Writes flags under a local .tmp directory by default. The original lab used
/home/plant/noVNC/ on a dedicated VM.
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

from pymodbus.client import ModbusTcpClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab_guard import LabTargetError, assert_lab_target


LOGGER = logging.getLogger("legacy.flag_manager")
FLAG1 = "Flag1:bdkf84hj4cfbd5ce3ae91ef7021flv04\n-> Sending critical alert..."
FLAG2 = (
    "Flag2:0d348fuac66272769fghj3409smfh995\n"
    "-> Sending critical alert...\n\nThe Oil Plant has been compromised!!"
)


def main() -> int:
    """Poll Modbus and persist CTF flags locally."""
    logging.basicConfig(level=logging.INFO)
    try:
        assert_lab_target("127.0.0.1")
    except LabTargetError as exc:
        LOGGER.error("%s", exc)
        return 2
    output_dir = Path(__file__).resolve().parents[2] / ".tmp" / "legacy-oil-flags"
    output_dir.mkdir(parents=True, exist_ok=True)
    client = ModbusTcpClient(host="127.0.0.1", port=5020)
    if not client.connect():
        LOGGER.error("unable to connect to local oil VM on 5020")
        return 1
    try:
        while True:
            response = client.read_holding_registers(address=1, count=16, device_id=1)
            if response.isError() or not getattr(response, "registers", None):
                time.sleep(1)
                continue
            registers = response.registers
            if registers[0] == 1 and registers[2] == 0:
                (output_dir / "flag1.txt").write_text(FLAG1, encoding="utf-8")
                LOGGER.info("flag1 written")
            elif len(registers) > 6 and registers[6] > 1000 and registers[5] < 2:
                (output_dir / "flag2.txt").write_text(FLAG2, encoding="utf-8")
                LOGGER.info("flag2 written")
            time.sleep(5)
    except KeyboardInterrupt:
        LOGGER.info("stopped")
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
