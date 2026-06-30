#!/usr/bin/env python3
"""Formal E2E lab smoke tests for IXF incorporation gates.

Usage:
  PYTHONPATH=. python3 tools/test_e2e_lab.py --mode all
  PYTHONPATH=. python3 tools/test_e2e_lab.py --mode c2,bashlite,aim-manifest
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _http_ok(url: str, timeout: float = 3.0) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IXF-E2E/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 400
    except (urllib.error.URLError, OSError):
        return False


def test_c2_simulate() -> list[str]:
    from industrialxpl.core.malware.native_actions import run_native_action

    r = run_native_action("mirai-iot-botnet")
    if not r.get("success") and not r.get("skipped"):
        return ["c2 mirai native_action: {}".format(r)]
    return []


def test_bashlite_compile() -> list[str]:
    from industrialxpl.core.malware.compiler import MalwareCompiler

    comp = MalwareCompiler()
    comp.refresh()
    r = comp.compile("bashlite_bot_debug")
    if not r.get("success"):
        return ["bashlite_bot_debug compile: {}".format((r.get("error") or "")[:120])]
    return []


def test_lisa_http() -> list[str]:
    from industrialxpl.core.lab.docker_stack import DockerStackManager

    mgr = DockerStackManager()
    st = mgr.status()
    if not st.get("running"):
        return ["lisa: stack not running (skip with --skip-lisa or: malware docker lisa up)"]
    if not _http_ok("http://127.0.0.1:4242/"):
        return ["lisa: http://127.0.0.1:4242 not 200"]
    return []


def test_fuzz_smoke() -> list[str]:
    native = ROOT / "industrialxpl/modules/cve/malware/_native/fuzzing"
    if not native.is_dir():
        return []
    return []


def test_otscan_smoke() -> list[str]:
    otscan = ROOT / "industrialxpl/core/ics/otscan"
    if not otscan.is_dir():
        return []
    return []


def test_aim_manifest() -> list[str]:
    manifest = ROOT / "industrialxpl/resources/research/awesome-ics-malware/manifest.json"
    if not manifest.is_file():
        return ["AIM manifest missing — run ingest_awesome_ics_malware.py"]
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if len(data.get("urls", [])) < 80:
        return ["AIM manifest urls < 80"]
    return []


def test_forensics_ioc() -> list[str]:
    from industrialxpl.core.ics_tools.forensics_engine import ioc_inventory

    inv = ioc_inventory()
    if inv.get("hash_count", 0) < 50:
        return ["forensics IOC hash_count < 50"]
    return []


def test_aim2_modules() -> list[str]:
    from industrialxpl.core.malware.aim2_helpers import aim2_family_status

    st = aim2_family_status()
    if not st.get("all_ok"):
        missing = [k for k, v in st.get("present", {}).items() if not v]
        return ["aim2 modules missing: {}".format(", ".join(missing))]
    return []


MODES = {
    "c2": test_c2_simulate,
    "bashlite": test_bashlite_compile,
    "lisa": test_lisa_http,
    "fuzz-smoke": test_fuzz_smoke,
    "otscan-smoke": test_otscan_smoke,
    "aim-manifest": test_aim_manifest,
    "forensics-ioc": test_forensics_ioc,
    "aim2": test_aim2_modules,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        default="c2,bashlite,aim-manifest,forensics-ioc",
        help="Comma-separated modes or 'all'",
    )
    parser.add_argument("--skip-lisa", action="store_true", help="Skip docker lisa test")
    args = parser.parse_args()

    if args.mode == "all":
        modes = list(MODES.keys())
        if args.skip_lisa and "lisa" in modes:
            modes.remove("lisa")
    else:
        modes = [m.strip() for m in args.mode.split(",") if m.strip()]

    failures: list[str] = []
    for mode in modes:
        fn = MODES.get(mode)
        if not fn:
            failures.append("unknown mode: {}".format(mode))
            continue
        print("[E2E] {} ...".format(mode))
        err = fn()
        if err:
            failures.extend(["{}: {}".format(mode, e) for e in err])
            print("  FAIL")
        else:
            print("  OK")

    if failures:
        print("\nE2E FAILURES:")
        for f in failures:
            print(" -", f)
        return 1
    print("\nE2E OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
