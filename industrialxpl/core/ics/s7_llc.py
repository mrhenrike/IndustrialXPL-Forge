"""S7 LLC / rack scan helpers — MIT stdlib (s7scan-inspired)."""

from __future__ import annotations

import socket
import struct
from typing import Any

S7_PORT = 102

_COTP_CR = bytes([
    0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00,
    0x00, 0x01, 0x00, 0xC1, 0x02, 0x01, 0x00, 0xC2,
    0x02, 0x01, 0x02, 0xC0, 0x01, 0x0A,
])


def build_cotp_connection(rack: int = 0, slot: int = 2) -> bytes:
    """Build ISO-on-TCP COTP Connection Request for rack/slot."""
    dst_tsap = struct.pack(">H", 0x0100 | ((rack & 0x07) << 5) | (slot & 0x1F))
    params = (
        b"\xc0\x01\x0a"
        + b"\xc1\x02\x01\x00"
        + bytes([0xC2, 0x02]) + dst_tsap
    )
    pdu_len = 6 + len(params)
    cotp = bytes([pdu_len, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00]) + params
    return struct.pack(">BBH", 3, 0, len(cotp) + 4) + cotp


def parse_cotp_response(data: bytes) -> dict[str, Any]:
    if len(data) < 7 or data[0] != 0x03:
        return {"valid": False, "error": "not TPKT"}
    cotp = data[4:]
    if not cotp:
        return {"valid": False, "error": "empty COTP"}
    pdu_type = cotp[1] if len(cotp) > 1 else 0
    return {
        "valid": True,
        "tpkt_len": struct.unpack(">H", data[2:4])[0],
        "cotp_type": pdu_type,
        "accepted": pdu_type in (0xD0, 0xE0),
        "bytes": len(data),
    }


def rack_scan_plan(host: str, racks: tuple[int, ...] = (0, 1), slots: tuple[int, ...] = (1, 2, 3)) -> dict[str, Any]:
    """Dry-run rack/slot enumeration plan."""
    combos = []
    for rack in racks:
        for slot in slots:
            combos.append({
                "rack": rack,
                "slot": slot,
                "cotp_hex": build_cotp_connection(rack, slot).hex(),
            })
    return {"success": True, "simulate": True, "host": host, "combos": combos, "count": len(combos)}


def probe_rack_slot(host: str, rack: int, slot: int, timeout: float = 3.0) -> dict[str, Any]:
    pkt = build_cotp_connection(rack, slot)
    try:
        s = socket.create_connection((host, S7_PORT), timeout=timeout)
        s.sendall(pkt)
        resp = s.recv(256)
        s.close()
        parsed = parse_cotp_response(resp)
        return {
            "rack": rack,
            "slot": slot,
            "detected": parsed.get("accepted", False),
            "detail": parsed,
        }
    except OSError as exc:
        return {"rack": rack, "slot": slot, "detected": False, "error": str(exc)}


def scan_racks(
    host: str,
    racks: tuple[int, ...] = (0, 1),
    slots: tuple[int, ...] = (1, 2, 3),
    *,
    simulate: bool = False,
    timeout: float = 3.0,
) -> dict[str, Any]:
    if simulate:
        return rack_scan_plan(host, racks, slots)
    results = []
    found = 0
    for rack in racks:
        for slot in slots:
            r = probe_rack_slot(host, rack, slot, timeout)
            results.append(r)
            if r.get("detected"):
                found += 1
    return {
        "success": True,
        "host": host,
        "found": found,
        "results": results,
    }
