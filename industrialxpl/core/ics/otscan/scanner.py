"""OTscan orchestrator — unified multi-protocol identify/assess."""

from __future__ import annotations

from typing import Any

from industrialxpl.core.ics.otscan.probes import PROBE_MAP

# Canonical protocol list (otscan-style coverage)
PROTOCOLS: tuple[str, ...] = (
    "modbus",
    "s7",
    "iec104",
    "bacnet",
    "dnp3",
    "opc-ua",
    "enip",
    "fox",
    "fins",
    "codesys",
    "hart-ip",
    "mqtt",
    "profinet",
)


def _normalize_protocols(names: list[str] | None) -> list[str]:
    if not names:
        return list(PROTOCOLS)
    out: list[str] = []
    for raw in names:
        key = raw.strip().lower().replace("_", "-")
        if key in PROBE_MAP and key not in out:
            out.append(key)
        elif key == "opcua" and "opc-ua" not in out:
            out.append("opc-ua")
        elif key == "ethernetip" and "enip" not in out:
            out.append("enip")
    return out or list(PROTOCOLS)


def probe_missing(host: str, timeout: float = 3.0) -> dict[str, Any]:
    return {"detected": False, "error": "unknown protocol"}


def simulate_scan(
    host: str = "127.0.0.1",
    protocols: list[str] | None = None,
) -> dict[str, Any]:
    """Dry-run — returns probe plan without network I/O."""
    selected = _normalize_protocols(protocols)
    return {
        "success": True,
        "simulate": True,
        "host": host,
        "protocols": selected,
        "count": len(selected),
        "results": {
            p: {
                "detected": None,
                "mode": "simulate",
                "would_run": PROBE_MAP.get(p, probe_missing).__name__,
            }
            for p in selected
        },
    }


def scan(
    host: str,
    protocols: list[str] | None = None,
    *,
    simulate: bool = False,
    timeout: float = 3.0,
) -> dict[str, Any]:
    if simulate:
        return simulate_scan(host, protocols)

    selected = _normalize_protocols(protocols)
    results: dict[str, Any] = {}
    detected = 0
    for proto in selected:
        fn = PROBE_MAP.get(proto, probe_missing)
        r = fn(host, timeout)
        results[proto] = r
        if r.get("detected"):
            detected += 1

    return {
        "success": True,
        "host": host,
        "protocols": selected,
        "detected_count": detected,
        "results": results,
    }
