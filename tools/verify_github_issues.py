#!/usr/bin/env python3
"""Verify GitHub open issues have corresponding IXF deliverables."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def check_issue_1() -> list[str]:
    p = ROOT / "industrialxpl/modules/assessment/mitre_ics/gap_technique_coverage.py"
    if not p.is_file():
        return ["#1 gap_technique_coverage missing"]
    from industrialxpl.modules.assessment.mitre_ics.gap_technique_coverage import GAP_TECHNIQUES
    if len(GAP_TECHNIQUES) < 15:
        return ["#1 gap techniques < 15"]
    return []


def check_issue_2() -> list[str]:
    script = ROOT / "tools/ingest_cisa_ics_advisories.py"
    if not script.is_file():
        return ["#2 ingest_cisa_ics_advisories.py missing"]
    return []


def check_issue_3() -> list[str]:
    nse = ROOT / "industrialxpl/resources/nse_scripts"
    needed = (
        "ics-modbus-coils.nse", "ics-dnp3-enum.nse", "ics-opcua-nodes.nse",
        "ics-iec104-info.nse", "ics-scada-fingerprint.nse",
        "ics-triton-check.nse", "ics-malware-ioc.nse",
    )
    missing = [n for n in needed if not (nse / n).is_file()]
    return ["#3 missing NSE: {}".format(", ".join(missing))] if missing else []


def check_issue_4() -> list[str]:
    p = ROOT / "industrialxpl/modules/assessment/sast/firmware_binary_analyzer.py"
    if not p.is_file():
        return ["#4 firmware_binary_analyzer missing"]
    from industrialxpl.modules.assessment.sast.firmware_binary_analyzer import analyze_firmware
    if not callable(analyze_firmware):
        return ["#4 analyze_firmware not callable"]
    return []


def check_issue_5() -> list[str]:
    vendors = (
        "mikrotik", "motorola_solutions", "fanuc", "fatek", "grundfos",
        "hitachi", "hms_networks", "hollysys", "jtekt", "krohne",
        "prosoft", "ptc", "ruggedcom", "sel", "sick_ag", "belden_hirschmann",
    )
    missing = []
    for v in vendors:
        p = ROOT / "industrialxpl/modules/creds/{}/default_creds.py".format(v)
        if not p.is_file():
            missing.append(v)
    return ["#5 missing creds: {}".format(", ".join(missing))] if missing else []


def check_issue_6() -> list[str]:
    main_src = (ROOT / "industrialxpl/__main__.py").read_text(encoding="utf-8")
    printer_src = (ROOT / "industrialxpl/core/exploit/printer.py").read_text(encoding="utf-8")
    failures = []
    if "configure_console" not in printer_src:
        failures.append("#6 configure_console missing in printer.py")
    if "--no-color" not in main_src:
        failures.append("#6 --no-color flag missing in __main__.py")
    return failures


def check_issue_7() -> list[str]:
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    if "3.14" not in ci:
        return ["#7 Python 3.14 not in CI matrix"]
    return []


def check_issue_8() -> list[str]:
    if not (ROOT / "docs/ARCHITECTURE.md").is_file():
        return ["#8 ARCHITECTURE.md missing"]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "docs/ARCHITECTURE.md" not in readme:
        return ["#8 README missing ARCHITECTURE link"]
    return []


def check_issue_9() -> list[str]:
    if not (ROOT / "industrialxpl/api/server.py").is_file():
        return ["#9 API server missing"]
    main_src = (ROOT / "industrialxpl/__main__.py").read_text(encoding="utf-8")
    if "serve" not in main_src:
        return ["#9 ixf serve subcommand missing"]
    return []


def _exploit_level_a(path: Path) -> bool:
    src = path.read_text(encoding="utf-8")
    return '"exploit_level"' in src and '"A"' in src.split('"exploit_level"')[1][:40]


def check_issue_10() -> list[str]:
    modules = (
        "industrialxpl/modules/cve/unitronics/cve_2023_6448_unistream_default_creds.py",
        "industrialxpl/modules/cve/emerson/cve_2022_29965_roc800_hardcoded_creds.py",
        "industrialxpl/modules/cve/siemens/cve_2021_22681_s7_1200_hardcoded_key.py",
        "industrialxpl/modules/cve/yokogawa/cve_2022_30993_fast_tools_xxe.py",
        "industrialxpl/modules/cve/johnson_controls/cve_2023_4486_metasys_auth_bypass.py",
    )
    missing = []
    for rel in modules:
        p = ROOT / rel
        if not p.is_file() or not _exploit_level_a(p):
            missing.append(Path(rel).name)
    return ["#10 Level A missing: {}".format(", ".join(missing))] if missing else []


CHECKS = {
    1: check_issue_1,
    2: check_issue_2,
    3: check_issue_3,
    4: check_issue_4,
    5: check_issue_5,
    6: check_issue_6,
    7: check_issue_7,
    8: check_issue_8,
    9: check_issue_9,
    10: check_issue_10,
}


def main() -> int:
    failures: list[str] = []
    for num, fn in sorted(CHECKS.items()):
        failures.extend(fn())
    if failures:
        for f in failures:
            print("FAIL", f)
        return 1
    print("GitHub issues deliverables: OK (issues #1-#10)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
