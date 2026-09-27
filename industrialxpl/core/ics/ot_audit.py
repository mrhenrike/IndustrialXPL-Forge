"""OT segmentation / cred audit helpers — OTAUD-inspired (partial, no overlap with otscan)."""

from __future__ import annotations

from typing import Any

OT_AUDIT_CHECKS: tuple[str, ...] = (
    "flat_network",
    "default_creds",
    "unencrypted_modbus",
    "exposed_engineering_station",
    "missing_iec62443_zones",
)


def run_audit(host: str = "127.0.0.1", *, simulate: bool = True) -> dict[str, Any]:
    if simulate:
        return {
            "success": True,
            "simulate": True,
            "host": host,
            "checks": {c: {"status": "would_run", "severity": "medium"} for c in OT_AUDIT_CHECKS},
            "note": "Cred/segmentation audit — complements otscan discovery",
        }
    return {"success": True, "host": host, "checks": {}, "note": "Live audit requires lab targets"}


def diff_vs_otscan(otscan_protocols: list[str]) -> dict[str, Any]:
    """Anti-overlap matrix — audit checks not duplicated by protocol probes."""
    probe_set = set(p.lower() for p in otscan_protocols)
    unique = [c for c in OT_AUDIT_CHECKS if c not in probe_set]
    return {"overlap_ok": True, "audit_unique": unique, "otscan_count": len(probe_set)}
