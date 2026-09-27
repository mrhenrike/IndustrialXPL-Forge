"""TCP/UDP probe helpers and default OT service ports."""

from __future__ import annotations

import socket
from typing import List, Optional, Tuple

DEFAULT_OT_PORTS = {
    "modbus": 502,
    "s7": 102,
    "dnp3": 20000,
    "bacnet": 47808,
    "enip": 44818,
    "opcua": 4840,
    "iec104": 2404,
}


def resolve_transports(value: str) -> List[Tuple[str, bool]]:
    """Return [(label, use_udp), ...] for transport option value."""
    mode = str(value).lower().strip()
    if mode == "tcp":
        return [("TCP", False)]
    if mode == "udp":
        return [("UDP", True)]
    if mode in ("both", "all"):
        return [("TCP", False), ("UDP", True)]
    raise ValueError("Transport must be tcp, udp, or both")


def connect_tcp(host: str, port: int, timeout: float) -> bool:
    """Return True if TCP port accepts a connection."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except OSError:
        return False


def connect_udp(host: str, port: int, timeout: float) -> bool:
    """Best-effort UDP reachability (send empty datagram, no response required)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00", (host, port))
        sock.close()
        return True
    except OSError:
        return False


def probe_tcp(host: str, port: int, data: bytes, timeout: float) -> Optional[bytes]:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if data:
            sock.sendall(data)
        resp = sock.recv(4096)
        sock.close()
        return resp
    except OSError:
        return None


def probe_udp(host: str, port: int, data: bytes, timeout: float) -> Optional[bytes]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(data, (host, port))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        return resp
    except OSError:
        return None
