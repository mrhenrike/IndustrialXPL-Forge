"""S7 ladder-logic forensics — stdlib-only (no pandas/snap7/loguru)."""

from __future__ import annotations

import csv
import json
import socket
import struct
from pathlib import Path
from typing import Any

from industrialxpl.core.ics.s7_client import S7Client

_PKG = Path(__file__).resolve().parents[2]
_FORENSICS_VENDOR = _PKG / "resources" / "vendor" / "submodules__ics-tools__ics-forensics-tools"
_IOC_DB = _PKG / "resources" / "ioc" / "awesome-ics-malware-hashes.json"
_YARA_DIR = _PKG / "resources" / "ioc" / "yara"


def _load_ioc_db() -> dict[str, Any]:
    if not _IOC_DB.is_file():
        return {"families": {}}
    try:
        return json.loads(_IOC_DB.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"families": {}}


def ioc_inventory() -> dict[str, Any]:
    db = _load_ioc_db()
    families = db.get("families", {})
    hash_count = sum(len(f.get("hashes", [])) for f in families.values())
    yara_rules = sorted(p.name for p in _YARA_DIR.glob("*.yar")) if _YARA_DIR.is_dir() else []
    return {
        "success": True,
        "families": len(families),
        "hash_count": hash_count,
        "yara_rules": yara_rules,
        "source": str(_IOC_DB),
    }


def match_ioc_hash(digest: str) -> dict[str, Any]:
    """Match SHA256/SHA1/MD5 against awesome-ics-malware IOC corpus."""
    needle = digest.strip().lower()
    db = _load_ioc_db()
    for family, meta in db.get("families", {}).items():
        for h in meta.get("hashes", []):
            if h.get("value", "").lower() == needle:
                return {
                    "matched": True,
                    "family": family,
                    "hash_type": h.get("type", "unknown"),
                    "label": h.get("label", ""),
                }
    return {"matched": False, "digest": needle}


def scan_file_hashes(path: Path) -> dict[str, Any]:
    """Hash a local file and check IOC DB (lab samples only)."""
    import hashlib

    if not path.is_file():
        return {"success": False, "error": "file not found"}
    data = path.read_bytes()
    digests = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    hits = []
    for kind, val in digests.items():
        m = match_ioc_hash(val)
        if m.get("matched"):
            hits.append({"algo": kind, **m})
    return {"success": True, "path": str(path), "hits": hits, "digests": digests}


def _probe_s7(host: str, port: int = 102, rack: int = 0, slot: int = 2) -> dict[str, Any]:
    client = S7Client(host, port=port, rack=rack, slot=slot, timeout=3.0)
    if not client.connect():
        return {"success": False, "error": "S7 connect failed on {}:{}".format(host, port)}
    info = client.get_plc_info()
    client.disconnect()
    return {"success": True, "host": host, "plc_info": info}


def _load_ob_mapping() -> dict[str, Any]:
    mapping = _FORENSICS_VENDOR / "mapping" / "ob_mapping.json"
    if not mapping.is_file():
        return {}
    try:
        return json.loads(mapping.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def inventory() -> dict[str, Any]:
    scripts = sorted(p.name for p in _FORENSICS_VENDOR.glob("**/*.py") if p.is_file())[:30]
    ob_map = _load_ob_mapping()
    return {
        "success": True,
        "vendor": str(_FORENSICS_VENDOR),
        "python_modules": scripts,
        "ob_mapping_entries": len(ob_map) if isinstance(ob_map, dict) else 0,
        "mode": "stdlib-native",
        "note": "Full ladder graphs need vendor pandas; IXF provides S7 probe + OB mapping.",
    }


def scan_plc(host: str, port: int = 102) -> dict[str, Any]:
    return _probe_s7(host, port)


def export_ob_roles_csv(rows: list[dict[str, Any]], out_path: Path) -> dict[str, Any]:
    if not rows:
        return {"success": False, "error": "no rows"}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({k for r in rows for k in r.keys()})
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow(row)
    return {"success": True, "path": str(out_path), "rows": len(rows)}


def parse_ob_sample(host: str) -> dict[str, Any]:
    """Build minimal OB role table without pandas."""
    ob_map = _load_ob_mapping()
    func_map = ob_map.get("func_mapping", ob_map) if isinstance(ob_map, dict) else {}
    rows = []
    if isinstance(func_map, dict):
        for block_id, names in list(func_map.items())[:15]:
            label = names
            if isinstance(names, dict):
                label = names.get("default") or names.get("300") or str(names)
            rows.append({"ip": host, "block_id": block_id, "type": "OB", "label": str(label)[:80]})
    return {"success": True, "host": host, "ob_preview": rows, "mapping_keys": len(func_map) if isinstance(func_map, dict) else 0}
