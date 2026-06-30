"""Unified Modbus toolkit — ModBusPwn-inspired MIT helpers."""

from __future__ import annotations

import struct
from typing import Any

from industrialxpl.core.ics.modbus_client import ModbusClient


def build_fc03(unit: int = 1, addr: int = 0, count: int = 1, trans_id: int = 1) -> bytes:
    pdu = struct.pack(">BBHH", unit, 3, addr, count)
    return struct.pack(">HHH", trans_id, 0, len(pdu)) + pdu


def build_fc16(unit: int = 1, addr: int = 0, values: list[int] | None = None, trans_id: int = 1) -> bytes:
    vals = values or [0]
    byte_count = len(vals) * 2
    pdu = struct.pack(">BBHHB", unit, 16, addr, len(vals), byte_count)
    for v in vals:
        pdu += struct.pack(">H", v & 0xFFFF)
    return struct.pack(">HHH", trans_id, 0, len(pdu)) + pdu


def simulate_toolkit(host: str = "127.0.0.1") -> dict[str, Any]:
    return {
        "success": True,
        "simulate": True,
        "host": host,
        "frames": {
            "fc03": build_fc03().hex(),
            "fc16": build_fc16().hex(),
        },
        "shodan": "opt-in via SHODAN_API_KEY env — default offline",
    }


def read_holding(host: str, addr: int = 0, count: int = 1, *, simulate: bool = True) -> dict[str, Any]:
    if simulate:
        return {"success": True, "simulate": True, "frame": build_fc03(addr=addr, count=count).hex()}
    try:
        c = ModbusClient(host)
        c.connect()
        data = c.read_holding_registers(addr, count)
        c.disconnect()
        return {"success": True, "values": data}
    except Exception as exc:
        return {"success": False, "error": str(exc)}
