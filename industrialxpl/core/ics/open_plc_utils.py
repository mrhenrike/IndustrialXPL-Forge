"""open-plc-utils CLI wrapper — MIT vendor reference."""

from __future__ import annotations

import shutil
from typing import Any


def open_plc_status() -> dict[str, Any]:
    plc = shutil.which("plcping") or shutil.which("open-plc-utils")
    return {
        "success": True,
        "simulate": True,
        "binary": plc or "not installed",
        "fallback": "ixf modbus/s7 scanners",
        "bacsfuzz": {"available": False, "note": "OPTIONAL_SKIP — serial BACnet lab only"},
    }
