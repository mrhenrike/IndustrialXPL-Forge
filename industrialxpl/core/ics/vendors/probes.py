"""Per-vendor OT discovery probes — stdlib UDP/TCP."""

from __future__ import annotations

import socket
import struct
from typing import Any, Callable

VENDOR_NAMES: tuple[str, ...] = (
    "beckhoff",
    "phoenix",
    "mitsubishi",
    "omron",
    "ewon",
    "hirschmann",
    "schneider",
)


def _tcp(host: str, port: int, timeout: float) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def _udp(host: str, port: int, payload: bytes, timeout: float) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        return sock.recv(4096)
    except OSError:
        return b""
    finally:
        sock.close()


def probe_beckhoff(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = _tcp(host, 48898, timeout)  # ADS
    return {"vendor": "beckhoff", "detected": ok, "port": 48898, "detail": "TwinCAT ADS" if ok else "closed"}


def probe_phoenix(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = _tcp(host, 1962, timeout)  # PLCnext
    return {"vendor": "phoenix", "detected": ok, "port": 1962, "detail": "PLCnext" if ok else "closed"}


def probe_mitsubishi(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = _tcp(host, 5007, timeout)  # MELSEC
    return {"vendor": "mitsubishi", "detected": ok, "port": 5007, "detail": "MELSEC TCP" if ok else "closed"}


def probe_omron(host: str, timeout: float = 3.0) -> dict[str, Any]:
    resp = _udp(host, 9600, b"\x80\x00\x02\x00", timeout)
    return {"vendor": "omron", "detected": bool(resp), "port": 9600, "detail": "FINS UDP" if resp else "no response"}


def probe_ewon(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = _tcp(host, 1188, timeout)
    return {"vendor": "ewon", "detected": ok, "port": 1188, "detail": "eWON VPN" if ok else "closed"}


def probe_hirschmann(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = _udp(host, 161, struct.pack("!BB", 0x30, 0x26), timeout) != b""
    return {"vendor": "hirschmann", "detected": ok, "port": 161, "detail": "SNMP UDP" if ok else "no response"}


def probe_schneider(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = _tcp(host, 502, timeout)
    return {"vendor": "schneider", "detected": ok, "port": 502, "detail": "Modbus/TCP (Schneider)" if ok else "closed"}


PROBE_MAP: dict[str, Callable[[str, float], dict[str, Any]]] = {
    "beckhoff": probe_beckhoff,
    "phoenix": probe_phoenix,
    "mitsubishi": probe_mitsubishi,
    "omron": probe_omron,
    "ewon": probe_ewon,
    "hirschmann": probe_hirschmann,
    "schneider": probe_schneider,
}


def simulate_all(host: str = "127.0.0.1") -> dict[str, Any]:
    return {
        "success": True,
        "simulate": True,
        "host": host,
        "vendors": list(VENDOR_NAMES),
        "results": {v: {"mode": "simulate", "fn": PROBE_MAP[v].__name__} for v in VENDOR_NAMES},
    }


def probe_vendor(vendor: str, host: str, *, simulate: bool = False, timeout: float = 3.0) -> dict[str, Any]:
    key = vendor.strip().lower()
    if simulate:
        fn = PROBE_MAP.get(key)
        return {
            "success": True,
            "simulate": True,
            "vendor": key,
            "would_probe": fn.__name__ if fn else "missing",
        }
    fn = PROBE_MAP.get(key)
    if not fn:
        return {"success": False, "error": "unknown vendor: {}".format(vendor)}
    return {"success": True, **fn(host, timeout)}
