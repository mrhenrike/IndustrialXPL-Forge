#!/usr/bin/env python3
"""Run incorporation phase gates — blocks merge when checks fail.

Usage:
  PYTHONPATH=. python3 tools/verify_incorporation_gate.py --phase F00
  PYTHONPATH=. python3 tools/verify_incorporation_gate.py --phase ALL
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATES_FILE = Path(__file__).resolve().parent / "incorporation_gates.json"
RESEARCH = ROOT / "industrialxpl" / "resources" / "research" / "awesome-ics-malware"
IOC_HASHES = ROOT / "industrialxpl" / "resources" / "ioc" / "awesome-ics-malware-hashes.json"


def _run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str]:
    import os
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    r = subprocess.run(
        cmd,
        cwd=str(cwd or ROOT),
        capture_output=True,
        text=True,
        env=env,
    )
    out = (r.stdout or "") + (r.stderr or "")
    return r.returncode, out


def load_gates() -> dict:
    if not GATES_FILE.is_file():
        raise SystemExit("missing {}".format(GATES_FILE))
    return json.loads(GATES_FILE.read_text(encoding="utf-8"))


def step_env_doctor() -> list[str]:
    code, _out = _run([sys.executable, "tools/env_doctor.py"])
    if code != 0:
        return ["env_doctor exited {}".format(code)]
    return []


def step_verify_family_matrix() -> list[str]:
    code, out = _run([sys.executable, "tools/verify_family_matrix.py"])
    if code != 0:
        return ["verify_family_matrix failed:\n" + out[-500:]]
    return []


def step_ingest_awesome() -> list[str]:
    code, out = _run([sys.executable, "tools/ingest_awesome_ics_malware.py"])
    if code != 0:
        return ["ingest_awesome_ics_malware failed:\n" + out[-400:]]
    manifest = RESEARCH / "manifest.json"
    if not manifest.is_file():
        return ["manifest.json not created"]
    return []


def step_deep_study() -> list[str]:
    code, out = _run([sys.executable, "tools/deep_study_external.py"])
    if code != 0:
        return ["deep_study_external failed:\n" + out[-400:]]
    return []


def step_score_incorporation() -> list[str]:
    code, out = _run([sys.executable, "tools/score_incorporation.py"])
    if code != 0:
        return ["score_incorporation failed:\n" + out[-400:]]
    return []


def step_forensics_ioc() -> list[str]:
    if not IOC_HASHES.is_file():
        return ["IOC hash file missing: {}".format(IOC_HASHES)]
    data = json.loads(IOC_HASHES.read_text(encoding="utf-8"))
    families = data.get("families", {})
    total = sum(len(v.get("hashes", [])) for v in families.values())
    if total < 50:
        return ["IOC hashes too few: {} (need >=50)".format(total)]
    try:
        from industrialxpl.core.ics_tools.forensics_engine import ioc_inventory, match_ioc_hash

        inv = ioc_inventory()
        if not inv.get("success"):
            return ["ioc_inventory failed"]
        if inv.get("hash_count", 0) < 50:
            return ["forensics hash_count < 50"]
        sample = next(iter(families.values()))["hashes"][0]["value"]
        m = match_ioc_hash(sample)
        if not m.get("matched"):
            return ["match_ioc_hash smoke failed for sample hash"]
    except Exception as exc:
        return ["forensics_ioc import/check: {}".format(exc)]
    return []


def step_aim2_modules() -> list[str]:
    try:
        from industrialxpl.core.malware.aim2_helpers import aim2_family_status

        st = aim2_family_status()
        if not st.get("all_ok"):
            missing = [k for k, v in st.get("present", {}).items() if not v]
            return ["F-AIM2 modules missing: {}".format(", ".join(missing))]
        from industrialxpl.core.malware.aim2_helpers import (
            chaya_eng_kill_plan,
            dynowiper_plan,
            fast16_demo_sequence,
            zionsiphon_probe,
        )

        if not fast16_demo_sequence():
            return ["fast16_demo_sequence empty"]
        if not chaya_eng_kill_plan().get("targets"):
            return ["chaya plan empty"]
        if not dynowiper_plan().get("extensions"):
            return ["dynowiper plan empty"]
        z = zionsiphon_probe("127.0.0.1", simulate=True)
        if not z.get("modbus_frame_hex"):
            return ["zionsiphon probe missing frame"]
    except Exception as exc:
        return ["aim2_modules: {}".format(exc)]
    return []


STEP_RUNNERS = {
    "env_doctor": step_env_doctor,
    "verify_family_matrix": step_verify_family_matrix,
    "ingest_awesome": step_ingest_awesome,
    "deep_study": step_deep_study,
    "score_incorporation": step_score_incorporation,
    "forensics_ioc": step_forensics_ioc,
    "aim2_modules": step_aim2_modules,
}


def check_phase_constraints(phase_id: str, cfg: dict) -> list[str]:
    failures: list[str] = []
    manifest = RESEARCH / "manifest.json"
    if cfg.get("min_manifest_urls") and manifest.is_file():
        data = json.loads(manifest.read_text(encoding="utf-8"))
        n = len(data.get("urls", []))
        need = int(cfg["min_manifest_urls"])
        if n < need:
            failures.append("manifest urls {} < {}".format(n, need))

    summary = RESEARCH / "study_summary.json"
    if cfg.get("min_study_ok_ratio") and summary.is_file():
        data = json.loads(summary.read_text(encoding="utf-8"))
        ratio = data.get("ok_ratio", 0)
        need = float(cfg["min_study_ok_ratio"])
        if ratio < need:
            failures.append("study ok_ratio {:.2f} < {:.2f}".format(ratio, need))

    return failures


def run_phase(phase_id: str, gates: dict) -> list[str]:
    phases = gates.get("phases", {})
    if phase_id not in phases:
        return ["unknown phase: {}".format(phase_id)]
    cfg = phases[phase_id]
    failures: list[str] = []
    print("\n=== Gate {} — {} ===".format(phase_id, cfg.get("label", "")))
    for step in cfg.get("steps", []):
        print("  -> {}".format(step))
        runner = STEP_RUNNERS.get(step)
        if not runner:
            failures.append("no runner for step {}".format(step))
            continue
        step_fail = runner()
        if step_fail:
            failures.extend(step_fail)
            print("     FAIL")
        else:
            print("     OK")
    failures.extend(check_phase_constraints(phase_id, cfg))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="IXF incorporation phase gate runner")
    parser.add_argument("--phase", default="F00", help="Phase id or ALL")
    args = parser.parse_args()
    gates = load_gates()
    phase_ids = list(gates.get("phases", {}).keys()) if args.phase.upper() == "ALL" else [args.phase]

    all_failures: list[str] = []
    for pid in phase_ids:
        all_failures.extend(run_phase(pid, gates))

    if all_failures:
        print("\nGATE FAILURES ({}):".format(len(all_failures)))
        for f in all_failures:
            print(" -", f)
        return 1
    print("\nGATE OK ({})".format(", ".join(phase_ids)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
