#!/usr/bin/env python3
"""Verify all 12 malware + 7 ics-tools families — no runtime surprises."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from industrialxpl.core.malware.catalog import MalwareCatalog
from industrialxpl.core.malware.compiler import MalwareCompiler
from industrialxpl.core.malware.family_capabilities import capability_matrix, get_capability
from industrialxpl.core.malware.native_actions import run_native_action
from industrialxpl.core.malware.orchestrator import MalwareOrchestrator
from industrialxpl.core.ics_tools import IcsToolsCatalog, IcsToolsRunner


def check_malware() -> list[str]:
    failures: list[str] = []
    cat = MalwareCatalog()
    orch = MalwareOrchestrator()
    comp = MalwareCompiler()
    comp.refresh()

    for slug in cat.list_slugs():
        cap = get_capability(slug)
        if not cap:
            failures.append("malware {}: missing capability".format(slug))
            continue
        fam = cat.get(slug)
        if not fam or not fam.vendor_path.is_dir():
            failures.append("malware {}: vendor missing".format(slug))
            continue
        a = orch.analyze(slug)
        if not a.get("ixf_module"):
            failures.append("malware {}: no ixf_module".format(slug))
        nat = run_native_action(slug)
        if cap.native_action and not nat.get("success") and not nat.get("skipped"):
            failures.append("malware {}: native_action failed: {}".format(slug, nat))

        for tname in cap.compile_targets[:2]:
            t = comp.get_target(tname)
            if not t:
                failures.append("malware {}: compile target {} not registered".format(slug, tname))

    # compile smoke (fast targets only)
    for tname in ("akaja_akaja", "killdisk"):
        r = comp.compile(tname)
        if not r.get("success"):
            failures.append("compile {}: {}".format(tname, (r.get("error") or "")[:100]))

    mir = comp.compile("mirai_bot_debug")
    if not mir.get("success"):
        failures.append("compile mirai_bot_debug: {}".format((mir.get("error") or "")[:120]))

    bl = comp.compile("bashlite_bot_debug")
    if not bl.get("success"):
        failures.append("compile bashlite_bot_debug: {}".format((bl.get("error") or "")[:120]))

    return failures


def check_ics() -> list[str]:
    failures: list[str] = []
    cat = IcsToolsCatalog()
    runner = IcsToolsRunner()

    for slug in cat.list_slugs():
        fam = cat.get(slug)
        if not fam or not fam.vendor_path.is_dir():
            failures.append("ics {}: vendor missing".format(slug))
            continue
        if not fam.entry_script and slug not in ("scadapass", "otscan"):
            failures.append("ics {}: no entry_script".format(slug))
        inv = runner.run_entry(slug, simulate=False, prefer_native=True)
        if not inv.get("success") and not inv.get("simulate"):
            failures.append(
                "ics {} native: {}".format(slug, inv.get("error") or inv.get("stderr", "")[:80])
            )

    return failures


def check_phase_registrations(phase_id: str | None = None) -> list[str]:
    """Optional hook for incorporation gates — extend per phase."""
    failures: list[str] = []
    if phase_id in (None, "F-AIM0", "F-AIM1"):
        manifest = ROOT / "industrialxpl/resources/research/awesome-ics-malware/manifest.json"
        if not manifest.is_file():
            failures.append("F-AIM: manifest.json missing (run ingest_awesome_ics_malware.py)")
        else:
            import json
            data = json.loads(manifest.read_text(encoding="utf-8"))
            if len(data.get("urls", [])) < 80:
                failures.append("F-AIM: manifest urls < 80")
    if phase_id in (None, "F-AIM1"):
        ioc = ROOT / "industrialxpl/resources/ioc/awesome-ics-malware-hashes.json"
        if not ioc.is_file():
            failures.append("F-AIM1: IOC hash file missing")
    return failures


def main() -> int:
    print("=== MALWARE CAPABILITY MATRIX ===")
    for row in capability_matrix():
        print("{slug:22} {mode:12} compile={compile:28} -> {ixf_module}".format(**row))

    print("\n=== ICS-TOOLS ===")
    for slug in IcsToolsCatalog().list_slugs():
        fam = IcsToolsCatalog().get(slug)
        print("{:22} entry={} native=IXF".format(slug, fam.entry_script if fam else ""))

    mf = check_malware()
    ic = check_ics()
    all_f = mf + ic
    if all_f:
        print("\nFAILURES ({}):".format(len(all_f)))
        for f in all_f:
            print(" -", f)
        return 1
    print("\nALL FAMILIES OK ({} malware + {} ics-tools)".format(
        len(MalwareCatalog().list_slugs()),
        len(IcsToolsCatalog().list_slugs()),
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
