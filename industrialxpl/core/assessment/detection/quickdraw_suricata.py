"""Quickdraw/Suricata rule generator — NSE expansion helper (F20)."""

from __future__ import annotations

from typing import Any

OT_NSE_SCRIPTS = (
    "BACnet-discover-enumerate.nse",
    "modbus-discover.nse",
    "s7-info.nse",
    "dnp3-info.nse",
    "enip-info.nse",
    "opcua-discover.nse",
    "profinet-discover.nse",
    "stuxnet-detect.nse",
)


def suricata_rule_from_mitre(technique: str, protocol: str = "modbus") -> str:
    return (
        'alert {proto} any any -> any any (msg:"IXF OT {tech} on {proto}"; '
        'classtype:attempted-admin; sid:9900001; rev:1;)'
    ).format(proto=protocol, tech=technique)


def nse_inventory(installed: list[str] | None = None) -> dict[str, Any]:
    have = set(installed or [])
    return {
        "success": True,
        "catalog": list(OT_NSE_SCRIPTS),
        "installed_count": len(have & set(OT_NSE_SCRIPTS)),
        "sample_rule": suricata_rule_from_mitre("T0855"),
    }
