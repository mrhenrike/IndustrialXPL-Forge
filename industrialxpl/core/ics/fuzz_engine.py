"""IXF native ICS protocol fuzzing — 8 mutation strategies (MIT, stdlib)."""

from __future__ import annotations

import random
import struct
from typing import Any

STRATEGY_NAMES = (
    "bitflip",
    "byteinc",
    "swap",
    "truncate",
    "extend",
    "random",
    "zero",
    "duplicate",
)


def build_modbus_fc03(unit: int = 1, addr: int = 0, count: int = 1, trans_id: int = 1) -> bytes:
    pdu = struct.pack(">BHH", 3, addr, count)
    mbap = struct.pack(">HHH", trans_id, 0, len(pdu) + 1) + struct.pack(">B", unit)
    return mbap + pdu


def build_s7_cotp_probe() -> bytes:
    return bytes([
        0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00,
        0x00, 0x01, 0x00, 0xC1, 0x02, 0x01, 0x00, 0xC2,
        0x02, 0x01, 0x02, 0xC0, 0x01, 0x0A,
    ])


def mutate(payload: bytes, strategy: int, seed: int = 42) -> bytes:
    """Apply one of 8 fuzz strategies (matches _native/fuzzing/fuzz_mutator.c)."""
    if not payload:
        return payload
    rng = random.Random(seed)
    buf = bytearray(payload)
    n = len(buf)
    pos = rng.randrange(n)
    s = strategy % 8

    if s == 0:
        buf[pos] ^= 1 << rng.randrange(8)
    elif s == 1:
        buf[pos] = (buf[pos] + 1) & 0xFF
    elif s == 2 and pos + 1 < n:
        buf[pos], buf[pos + 1] = buf[pos + 1], buf[pos]
    elif s == 3 and n > 4:
        buf = buf[:-1]
    elif s == 4 and n < 256:
        buf.append(buf[-1])
    elif s == 5:
        buf[pos] = rng.randrange(256)
    elif s == 6:
        buf[pos] = 0
    elif s == 7 and n < 256:
        buf.insert(pos, buf[pos])
    return bytes(buf)


def fuzz_campaign(protocol: str = "modbus", *, seed: int = 42) -> dict[str, Any]:
    base = build_modbus_fc03() if protocol == "modbus" else build_s7_cotp_probe()
    cases = []
    for i, name in enumerate(STRATEGY_NAMES):
        mutated = mutate(base, i, seed + i)
        cases.append({
            "strategy": i,
            "name": name,
            "hex": mutated.hex(),
            "len": len(mutated),
        })
    return {
        "success": True,
        "protocol": protocol,
        "base_hex": base.hex(),
        "strategies": len(STRATEGY_NAMES),
        "cases": cases,
    }
