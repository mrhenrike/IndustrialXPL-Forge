#!/usr/bin/env python3
"""Score incorporation backlog from deep-study results.

Usage:
  PYTHONPATH=. python3 tools/score_incorporation.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / "industrialxpl" / "resources" / "research" / "awesome-ics-malware"
STUDIES = RESEARCH / "studies"
BACKLOG = RESEARCH / "incorporation_backlog.json"

# IXF module coverage map (awesome-ics-malware families)
IXF_COVERAGE = {
    "fast16": {"status": "gap", "target": "modules/cve/malware/fast16_simulation_sabotage.py"},
    "stuxnet": {"status": "partial", "target": "scanners/ics + stuxnet_analyze"},
    "night-dragon": {"status": "covered", "target": "modules/cve/malware/night_dragon_oil_gas.py"},
    "duqu": {"status": "skip", "target": "reference-only"},
    "shamoon-malware": {"status": "covered", "target": "modules/cve/malware/shamoon_destructive_wiper.py"},
    "havex": {"status": "covered", "target": "modules/cve/malware/havex_dragonfly_opc.py"},
    "blackenergy2": {"status": "covered", "target": "modules/cve/malware/blackenergy2_hmi_attack.py"},
    "blackenergy3": {"status": "covered", "target": "modules/cve/malware/blackenergy3_industrial.py"},
    "irongate": {"status": "covered", "target": "modules/cve/malware/irongate_siemens_simulation.py"},
    "industroyer": {"status": "covered", "target": "modules/cve/malware/crashoverride_industroyer.py"},
    "triton": {"status": "covered", "target": "modules/cve/malware/triton_tristation_native.py"},
    "industroyer2": {"status": "covered", "target": "modules/cve/apt/industroyer2_iec104_rtu.py"},
    "pipedream": {"status": "covered", "target": "modules/cve/malware/incontroller_pipedream_suite.py"},
    "cosmicenergy": {"status": "covered", "target": "modules/cve/malware/cosmicenergy_iec104.py"},
    "frostygoop": {"status": "covered", "target": "modules/cve/apt/frostygoop_modbus_heating.py"},
    "fuxnet": {"status": "covered", "target": "modules/cve/malware/fuxnet_sensor_gateway_brick.py"},
    "iocontrol": {"status": "covered", "target": "modules/cve/malware/iocontrol_iot_ot_backdoor.py"},
    "chaya_003": {"status": "gap", "target": "modules/cve/malware/chaya_003_siemens_eng_kill.py"},
    "dynowiper": {"status": "gap", "target": "modules/cve/malware/dynowiper_hmi_wiper.py"},
    "zionsiphon": {"status": "gap", "target": "modules/cve/malware/zionsiphon_water_lab.py"},
}


def main() -> int:
    manifest_path = RESEARCH / "manifest.json"
    if not manifest_path.is_file():
        print("missing manifest", file=sys.stderr)
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    high_value: list[dict] = []
    if STUDIES.is_dir():
        for p in sorted(STUDIES.glob("*.json")):
            try:
                s = json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            if s.get("incorporation_score", 0) >= 2:
                high_value.append({
                    "url": s.get("url"),
                    "score": s.get("incorporation_score"),
                    "protocols": s.get("protocols", []),
                    "ixf_targets": s.get("ixf_target_paths", []),
                })

    gaps = [fam for fam, meta in IXF_COVERAGE.items() if meta["status"] == "gap"]
    partial = [fam for fam, meta in IXF_COVERAGE.items() if meta["status"] == "partial"]

    backlog = {
        "families": IXF_COVERAGE,
        "gaps": gaps,
        "partial": partial,
        "high_value_links": sorted(high_value, key=lambda x: -x["score"])[:40],
        "manifest_urls": manifest.get("url_count", 0),
    }
    BACKLOG.write_text(json.dumps(backlog, indent=2), encoding="utf-8")
    print("backlog: {} gaps, {} partial, {} high-value links -> {}".format(
        len(gaps), len(partial), len(high_value), BACKLOG
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
