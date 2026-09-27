"""BACnet offensive helpers — MIT stdlib (BACteria-inspired)."""

from __future__ import annotations

import socket
import struct
from typing import Any

BACNET_PORT = 47808


def build_whois() -> bytes:
    return bytes([0x81, 0x0B, 0x00, 0x0C, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08])


def build_iam(device_id: int = 1234) -> bytes:
    """Minimal I-Am style frame for lab simulate."""
    return bytes([0x81, 0x00, 0x0C, 0x00, 0x01, 0x00]) + struct.pack(">I", device_id)[1:]


def build_read_property(device_id: int = 1234, prop_id: int = 77) -> bytes:
    """ReadProperty simulate PDU (object-type analog-value)."""
    return bytes([
        0x81, 0x0A, 0x00, 0x11, 0x01, 0x20,
        (device_id >> 16) & 0xFF, (device_id >> 8) & 0xFF, device_id & 0xFF,
        0x0C, 0x02, 0x3E, 0x19, prop_id & 0xFF,
    ])


def fuzz_frame(seed: int = 0) -> bytes:
    base = bytearray(build_whois())
    for i in range(min(4, len(base))):
        base[i] ^= (seed + i) & 0xFF
    return bytes(base)


def whois_probe(host: str, timeout: float = 3.0) -> dict[str, Any]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_whois(), (host, BACNET_PORT))
        resp = sock.recv(4096)
        return {"detected": bool(resp), "bytes": len(resp), "hex": resp[:32].hex()}
    except OSError as exc:
        return {"detected": False, "error": str(exc)}
    finally:
        sock.close()


def simulate_campaign(host: str = "127.0.0.1") -> dict[str, Any]:
    return {
        "success": True,
        "simulate": True,
        "host": host,
        "frames": {
            "whois": build_whois().hex(),
            "iam": build_iam().hex(),
            "read_property": build_read_property().hex(),
            "fuzz_0": fuzz_frame(0).hex(),
        },
    }
