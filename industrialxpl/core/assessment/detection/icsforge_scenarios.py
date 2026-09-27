"""ICSForge detection scenarios — ATT&CK ICS lab YAML loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_SCENARIOS = Path(__file__).resolve().parents[3] / "resources" / "detection" / "icsforge_scenarios.json"


def load_scenarios() -> list[dict[str, Any]]:
    if not _SCENARIOS.is_file():
        return []
    try:
        data = json.loads(_SCENARIOS.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return data.get("scenarios", [])


def export_sigma_rule(scenario_id: str) -> dict[str, Any]:
    for sc in load_scenarios():
        if sc.get("id") == scenario_id:
            return {
                "success": True,
                "simulate": True,
                "scenario": sc,
                "sigma": {
                    "title": sc.get("title", scenario_id),
                    "logsource": {"product": "ics", "service": sc.get("protocol", "modbus")},
                    "detection": sc.get("detection", {}),
                },
            }
    return {"success": False, "error": "scenario not found: {}".format(scenario_id)}


def inventory() -> dict[str, Any]:
    scenarios = load_scenarios()
    return {
        "success": True,
        "count": len(scenarios),
        "ids": [s.get("id") for s in scenarios],
        "mitre_techniques": sorted({t for s in scenarios for t in s.get("mitre", [])}),
    }
