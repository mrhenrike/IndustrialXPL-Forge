"""Attack catalog loader.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..paths import CATALOG_DIR


ALLOWED_KEYS = frozenset(
    {
        "id",
        "title",
        "cve",
        "product",
        "version",
        "license",
        "origin",
        "commit",
        "sha256",
        "mitre_ics",
        "scenario_ids",
        "adapter",
        "argv_template",
        "preconditions",
        "expected_impact",
        "evidence",
        "rollback",
        "reproduction",
        "destructive",
        "persona",
    }
)
ALLOWED_ADAPTERS = frozenset(
    {
        "internal-modbus",
        "internal-http",
        "internal-tcp",
        "modbus-cli",
        "metasploit",
        "embedxpl",
        "routersploit",
        "pret",
    }
)
ALLOWED_PERSONAS = frozenset({"plant", "plc", "scada", "gateway", "printer", "protocol"})


class CatalogError(ValueError):
    """Invalid catalog record."""


@dataclass(frozen=True)
class AttackRecord:
    """One catalogued lab attack."""

    attack_id: str
    title: str
    cve: str
    product: str
    version: str
    license: str
    origin: str
    commit: str
    sha256: str
    mitre_ics: List[str]
    scenario_ids: List[str]
    adapter: str
    argv_template: List[str]
    preconditions: str
    expected_impact: str
    evidence: str
    rollback: str
    reproduction: str
    destructive: bool
    persona: str


def _reject_unknown(data: Dict[str, Any]) -> None:
    """Deny extra keys."""
    unexpected = set(data) - set(ALLOWED_KEYS)
    if unexpected:
        raise CatalogError("unexpected catalog keys: %s" % ", ".join(sorted(unexpected)))


def parse_record(data: Dict[str, Any]) -> AttackRecord:
    """Validate one catalog object."""
    _reject_unknown(data)
    adapter = str(data.get("adapter") or "")
    if adapter not in ALLOWED_ADAPTERS:
        raise CatalogError("unsupported adapter")
    persona = str(data.get("persona") or "plant")
    if persona not in ALLOWED_PERSONAS:
        raise CatalogError("unsupported persona")
    license_name = str(data.get("license") or "").strip()
    if not license_name:
        raise CatalogError("license is required")
    argv = data.get("argv_template") or []
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise CatalogError("argv_template must be a list of strings")
    attack_id = str(data.get("id") or "").strip()
    if not attack_id:
        raise CatalogError("id is required")
    return AttackRecord(
        attack_id=attack_id,
        title=str(data.get("title") or attack_id),
        cve=str(data.get("cve") or ""),
        product=str(data.get("product") or ""),
        version=str(data.get("version") or ""),
        license=license_name,
        origin=str(data.get("origin") or "in-tree"),
        commit=str(data.get("commit") or ""),
        sha256=str(data.get("sha256") or ""),
        mitre_ics=[str(item) for item in (data.get("mitre_ics") or [])],
        scenario_ids=[str(item) for item in (data.get("scenario_ids") or [])],
        adapter=adapter,
        argv_template=list(argv),
        preconditions=str(data.get("preconditions") or ""),
        expected_impact=str(data.get("expected_impact") or ""),
        evidence=str(data.get("evidence") or ""),
        rollback=str(data.get("rollback") or "snapshot"),
        reproduction=str(data.get("reproduction") or "process"),
        destructive=bool(data.get("destructive", False)),
        persona=persona,
    )


def load_catalog(root: Optional[Path] = None) -> List[AttackRecord]:
    """Load every JSON record in the catalog directory."""
    base = root or CATALOG_DIR
    records: List[AttackRecord] = []
    if not base.exists():
        return records
    for path in sorted(base.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise CatalogError("catalog file must contain an object: %s" % path.name)
        records.append(parse_record(raw))
    return records


def get_attack(attack_id: str, root: Optional[Path] = None) -> AttackRecord:
    """Fetch one attack by id."""
    for record in load_catalog(root):
        if record.attack_id == attack_id:
            return record
    raise CatalogError("unknown attack: %s" % attack_id)
