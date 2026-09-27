"""IEC 60870-5-104 stack — MIT stdlib (lib60870 REFERENCE_ONLY)."""

from __future__ import annotations

import struct
from typing import Any

# APCI types
STARTDT_ACT = 0x07
STARTDT_CON = 0x0B
TESTFR_ACT = 0x43
TESTFR_CON = 0x83


def build_apci(apdu_len: int, ctrl: int) -> bytes:
    """Build 6-byte APCI header."""
    length = apdu_len + 2
    return bytes([0x68, length, length, ctrl & 0xFF, 0x00, 0x00])


def build_startdt_act() -> bytes:
    return bytes([0x68, 0x04, STARTDT_ACT, 0x00, 0x00, 0x00])


def build_startdt_con() -> bytes:
    return bytes([0x68, 0x04, STARTDT_CON, 0x00, 0x00, 0x00])


def build_testfr_act() -> bytes:
    return bytes([0x68, 0x04, TESTFR_ACT, 0x00, 0x00, 0x00])


def build_testfr_con() -> bytes:
    return bytes([0x68, 0x04, TESTFR_CON, 0x00, 0x00, 0x00])


def build_asdu(
    type_id: int,
    cot: int,
    common_addr: int,
    ioa: int,
    value: int = 0,
) -> bytes:
    """Build I-format APDU with minimal ASDU (single point)."""
    ioa3 = ioa & 0xFFFFFF
    asdu = struct.pack(
        "<BBHH",
        type_id & 0xFF,
        0x01,  # VSQ
        cot & 0xFFFF,
        common_addr & 0xFFFF,
    ) + bytes([
        ioa3 & 0xFF,
        (ioa3 >> 8) & 0xFF,
        (ioa3 >> 16) & 0xFF,
        value & 0xFF,
    ])
    apci = build_apci(len(asdu), 0x02)
    return apci + asdu


def parse_apci(data: bytes) -> dict[str, Any]:
    if len(data) < 6 or data[0] != 0x68:
        return {"valid": False}
    ctrl = data[2]
    return {
        "valid": True,
        "length": data[1],
        "ctrl": ctrl,
        "is_startdt_con": ctrl == STARTDT_CON,
        "is_testfr_con": ctrl == TESTFR_CON,
        "is_i_format": (ctrl & 1) == 0 and ctrl not in (STARTDT_ACT, STARTDT_CON, TESTFR_ACT, TESTFR_CON),
    }


def simulate_session() -> dict[str, Any]:
    start = build_startdt_act()
    con = build_startdt_con()
    test = build_testfr_act()
    asdu = build_asdu(45, 6, 1, 1000, 1)  # C_SC_NA_1 style
    return {
        "success": True,
        "simulate": True,
        "frames": {
            "startdt_act": start.hex(),
            "startdt_con": con.hex(),
            "testfr_act": test.hex(),
            "asdu_c_sc": asdu.hex(),
        },
        "parsed_con": parse_apci(con),
    }
