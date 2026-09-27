"""ISF/icssploit port — MIT protocol handlers (REFERENCE_ONLY upstream GPL)."""

from __future__ import annotations

import socket
from typing import Any

from industrialxpl.core.ics.cip_client import CIPClient
from industrialxpl.core.ics.wdb2_client import Wdb2Client


PROTOCOL_HANDLERS: tuple[str, ...] = ("dnp3", "enip", "opc-ua", "profinet", "vxworks")


def simulate_inventory() -> dict[str, Any]:
    return {
        "success": True,
        "simulate": True,
        "protocols": list(PROTOCOL_HANDLERS),
        "ixf_routes": {
            "dnp3": "scanners/ics/dnp3_scanner",
            "enip": "scanners/ics/enip_scanner",
            "opc-ua": "scanners/ics/opcua_discover",
            "profinet": "scanners/ics/profinet_dcp_scanner",
            "vxworks": "core/ics/wdb2_client",
        },
    }


def probe_dnp3(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = False
    try:
        s = socket.create_connection((host, 20000), timeout=timeout)
        s.close()
        ok = True
    except OSError:
        pass
    return {"protocol": "dnp3", "detected": ok, "port": 20000}


def probe_enip(host: str, timeout: float = 3.0) -> dict[str, Any]:
    try:
        c = CIPClient(host, timeout=timeout)
        c.connect()
        c.disconnect()
        return {"protocol": "enip", "detected": True, "port": 44818}
    except Exception as exc:
        return {"protocol": "enip", "detected": False, "error": str(exc)[:80]}


def probe_opcua(host: str, timeout: float = 3.0) -> dict[str, Any]:
    try:
        s = socket.create_connection((host, 4840), timeout=timeout)
        s.close()
        return {"protocol": "opc-ua", "detected": True, "port": 4840}
    except OSError as exc:
        return {"protocol": "opc-ua", "detected": False, "error": str(exc)}


def probe_profinet(host: str, timeout: float = 3.0) -> dict[str, Any]:
    dcp = bytes([0xFE, 0xFD, 0x82, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(dcp, (host, 34962))
        resp = sock.recv(4096)
        return {"protocol": "profinet", "detected": bool(resp), "bytes": len(resp)}
    except OSError as exc:
        return {"protocol": "profinet", "detected": False, "error": str(exc)}
    finally:
        sock.close()


def probe_vxworks(host: str, timeout: float = 3.0) -> dict[str, Any]:
    try:
        w = Wdb2Client(host, timeout=timeout)
        if w.connect():
            info = w.get_target_info() or {}
            w.disconnect()
            return {"protocol": "vxworks", "detected": True, "detail": info}
        return {"protocol": "vxworks", "detected": False, "error": "connect failed"}
    except Exception as exc:
        return {"protocol": "vxworks", "detected": False, "error": str(exc)[:80]}


_PROBE_FNS = {
    "dnp3": probe_dnp3,
    "enip": probe_enip,
    "opc-ua": probe_opcua,
    "profinet": probe_profinet,
    "vxworks": probe_vxworks,
}


def scan_protocols(host: str, protocols: list[str] | None = None, *, simulate: bool = False) -> dict[str, Any]:
    if simulate:
        return simulate_inventory()
    selected = protocols or list(PROTOCOL_HANDLERS)
    results = {}
    for p in selected:
        fn = _PROBE_FNS.get(p)
        results[p] = fn(host) if fn else {"error": "unknown"}
    return {"success": True, "host": host, "results": results}
