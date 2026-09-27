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


def step_fuzz_compile() -> list[str]:
    try:
        from industrialxpl.core.ics.fuzz_engine import fuzz_campaign
        from industrialxpl.core.malware.compiler import MalwareCompiler

        camp = fuzz_campaign("modbus")
        if len(camp.get("cases", [])) != 8:
            return ["fuzz_campaign expected 8 strategies"]
        comp = MalwareCompiler()
        comp.refresh()
        for tname in ("fuzz_modbus_smoke", "fuzz_s7_smoke"):
            r = comp.compile(tname)
            if not r.get("success"):
                return ["compile {}: {}".format(tname, (r.get("error") or "")[:100])]
    except Exception as exc:
        return ["fuzz_compile: {}".format(exc)]
    return []


def step_otscan_smoke() -> list[str]:
    try:
        from industrialxpl.core.ics.otscan import PROTOCOLS, simulate_scan
        from industrialxpl.core.ics_tools import IcsToolsCatalog, IcsToolsRunner
        from industrialxpl.core.ics_tools.native_handlers import run_native

        if len(PROTOCOLS) < 10:
            return ["otscan expected >= 10 protocols, got {}".format(len(PROTOCOLS))]
        plan = simulate_scan("127.0.0.1")
        if not plan.get("success") or plan.get("count", 0) < 10:
            return ["otscan simulate_scan failed"]
        if "otscan" not in IcsToolsCatalog().list_slugs():
            return ["otscan not in IcsToolsCatalog"]
        inv = IcsToolsRunner().run_entry("otscan", simulate=False, prefer_native=True)
        if not inv.get("success"):
            return ["otscan native inventory: {}".format(inv.get("error") or inv.get("stdout", "")[:80])]
        nat = run_native("otscan", ["-t", "127.0.0.1"], simulate=True)
        if not nat or not nat.get("simulate"):
            return ["otscan run_native simulate failed"]
    except Exception as exc:
        return ["otscan_smoke: {}".format(exc)]
    return []


def step_aim3_modules() -> list[str]:
    try:
        from industrialxpl.core.malware.aim3_helpers import aim3_status

        st = aim3_status()
        if not st.get("all_ok"):
            missing = [k for k, v in st.get("present", {}).items() if not v]
            return ["F-AIM3 deepen missing: {}".format(", ".join(missing))]
        if not (ROOT / "industrialxpl/modules/cve/malware/stuxnet_analyze.py").is_file():
            return ["stuxnet_analyze.py missing"]
    except Exception as exc:
        return ["aim3_modules: {}".format(exc)]
    return []


def step_s7scan_smoke() -> list[str]:
    try:
        from industrialxpl.core.ics.s7_llc import build_cotp_connection, parse_cotp_response, rack_scan_plan

        pkt = build_cotp_connection(0, 2)
        if len(pkt) < 20:
            return ["s7_llc packet too short"]
        plan = rack_scan_plan("127.0.0.1")
        if plan.get("count", 0) < 1:
            return ["rack_scan_plan empty"]
        parse_cotp_response(pkt[:22] + b"\xd0\x00")
    except Exception as exc:
        return ["s7scan_smoke: {}".format(exc)]
    return []


def step_vendors_smoke() -> list[str]:
    try:
        from industrialxpl.core.ics.vendors import VENDOR_NAMES, simulate_all

        if len(VENDOR_NAMES) < 7:
            return ["vendors < 7"]
        if not simulate_all().get("success"):
            return ["vendors simulate failed"]
    except Exception as exc:
        return ["vendors_smoke: {}".format(exc)]
    return []


def step_bacnet_smoke() -> list[str]:
    try:
        from industrialxpl.core.ics.bacnet_offensive import simulate_campaign
        from industrialxpl.core.ics_tools import IcsToolsCatalog
        from industrialxpl.core.ics_tools.native_handlers import run_native

        camp = simulate_campaign()
        if len(camp.get("frames", {})) < 3:
            return ["bacnet frames < 3"]
        if "bacteria" not in IcsToolsCatalog().list_slugs():
            return ["bacteria not in catalog"]
        if not run_native("bacteria", simulate=True):
            return ["bacteria native failed"]
    except Exception as exc:
        return ["bacnet_smoke: {}".format(exc)]
    return []


def step_iec104_smoke() -> list[str]:
    try:
        from industrialxpl.core.ics.iec104_stack import simulate_session

        sess = simulate_session()
        if not sess.get("frames", {}).get("startdt_act"):
            return ["iec104 startdt missing"]
    except Exception as exc:
        return ["iec104_smoke: {}".format(exc)]
    return []


def step_isf_port_smoke() -> list[str]:
    try:
        from industrialxpl.core.ics.isf_port import PROTOCOL_HANDLERS, simulate_inventory

        if len(PROTOCOL_HANDLERS) < 5:
            return ["isf_port protocols < 5"]
        if not simulate_inventory().get("success"):
            return ["isf_port inventory failed"]
    except Exception as exc:
        return ["isf_port_smoke: {}".format(exc)]
    return []


def step_mozi_smoke() -> list[str]:
    try:
        from industrialxpl.core.malware.mozi_dht import mozi_inventory
        from industrialxpl.core.malware.family_capabilities import get_capability
        from industrialxpl.core.malware.native_actions import run_native_action

        if "mozi-p2p" not in __import__(
            "industrialxpl.core.malware.catalog", fromlist=["MalwareCatalog"]
        ).MalwareCatalog().list_slugs():
            return ["mozi-p2p not in MalwareCatalog"]
        if not get_capability("mozi-p2p"):
            return ["mozi-p2p capability missing"]
        if not mozi_inventory().get("success"):
            return ["mozi_inventory failed"]
        nat = run_native_action("mozi-p2p")
        if not nat.get("success"):
            return ["mozi native_action failed"]
    except Exception as exc:
        return ["mozi_smoke: {}".format(exc)]
    return []


def step_ricnar_smoke() -> list[str]:
    try:
        from industrialxpl.core.ics.ricnar_pocs import get_poc, list_pocs

        if len(list_pocs()) < 1:
            return ["ricnar pocs empty"]
        if not get_poc("seig_modbus_dos").get("payload_hex"):
            return ["seig poc missing"]
    except Exception as exc:
        return ["ricnar_smoke: {}".format(exc)]
    return []


def step_icsforge_smoke() -> list[str]:
    try:
        from industrialxpl.core.assessment.detection.icsforge_scenarios import export_sigma_rule, inventory

        inv = inventory()
        if inv.get("count", 0) < 5:
            return ["icsforge scenarios < 5"]
        if not export_sigma_rule(inv["ids"][0]).get("sigma"):
            return ["sigma export failed"]
    except Exception as exc:
        return ["icsforge_smoke: {}".format(exc)]
    return []


def step_ot_audit_smoke() -> list[str]:
    try:
        from industrialxpl.core.ics.ot_audit import diff_vs_otscan, run_audit
        from industrialxpl.core.ics.otscan import PROTOCOLS

        if not run_audit(simulate=True).get("success"):
            return ["ot_audit failed"]
        if not diff_vs_otscan(list(PROTOCOLS)).get("overlap_ok"):
            return ["ot_audit overlap check failed"]
    except Exception as exc:
        return ["ot_audit_smoke: {}".format(exc)]
    return []


def step_modbus_toolkit_smoke() -> list[str]:
    try:
        from industrialxpl.core.ics.modbus_toolkit import simulate_toolkit

        if not simulate_toolkit().get("frames"):
            return ["modbus_toolkit empty"]
    except Exception as exc:
        return ["modbus_toolkit_smoke: {}".format(exc)]
    return []


def step_mirai_loader_smoke() -> list[str]:
    try:
        from industrialxpl.core.malware.compiler import MalwareCompiler

        comp = MalwareCompiler()
        comp.refresh()
        r = comp.compile("mirai_loader_smoke")
        if not r.get("success"):
            return ["mirai_loader_smoke compile: {}".format((r.get("error") or "")[:80])]
    except Exception as exc:
        return ["mirai_loader_smoke: {}".format(exc)]
    return []


def step_incontroller_smoke() -> list[str]:
    try:
        from industrialxpl.core.malware.incontroller_protocols import PROTOCOLS, simulate_suite

        if len(PROTOCOLS) < 5:
            return ["incontroller protocols < 5"]
        if not simulate_suite().get("modules"):
            return ["incontroller suite empty"]
    except Exception as exc:
        return ["incontroller_smoke: {}".format(exc)]
    return []


def step_frostygoop_json_smoke() -> list[str]:
    try:
        from industrialxpl.core.malware.frostygoop_json import simulate_parse

        r = simulate_parse()
        if r.get("task_count", 0) < 1:
            return ["frostygoop tasks < 1"]
    except Exception as exc:
        return ["frostygoop_json_smoke: {}".format(exc)]
    return []


def step_edb_smoke() -> list[str]:
    try:
        from industrialxpl.core.ics.s7_packets import packet_inventory
        from industrialxpl.core.malware.compiler import MalwareCompiler

        inv = packet_inventory()
        if not inv.get("packets", {}).get("stop"):
            return ["s7_packets stop missing"]
        comp = MalwareCompiler()
        comp.refresh()
        r = comp.compile("modbus_seig_dos")
        if not r.get("success"):
            return ["modbus_seig_dos: {}".format((r.get("error") or "")[:80])]
    except Exception as exc:
        return ["edb_smoke: {}".format(exc)]
    return []


def step_openplc_smoke() -> list[str]:
    overlay = ROOT / "industrialxpl/lab_overlays/openplc/docker-compose.override.yml"
    if not overlay.is_file():
        return ["openplc overlay missing"]
    return []


def step_s2opc_smoke() -> list[str]:
    try:
        from industrialxpl.core.lab.s2opc_lab import s2opc_status

        if not s2opc_status().get("success"):
            return ["s2opc status failed"]
    except Exception as exc:
        return ["s2opc_smoke: {}".format(exc)]
    return []


def step_open_plc_smoke() -> list[str]:
    try:
        from industrialxpl.core.ics.open_plc_utils import open_plc_status

        if not open_plc_status().get("success"):
            return ["open_plc status failed"]
    except Exception as exc:
        return ["open_plc_smoke: {}".format(exc)]
    return []


def step_nse_quickdraw_smoke() -> list[str]:
    try:
        from industrialxpl.core.assessment.detection.quickdraw_suricata import nse_inventory

        inv = nse_inventory()
        if len(inv.get("catalog", [])) < 8:
            return ["nse catalog < 8"]
        if "alert" not in inv.get("sample_rule", ""):
            return ["suricata rule sample missing"]
    except Exception as exc:
        return ["nse_quickdraw_smoke: {}".format(exc)]
    return []


def step_corpus_smoke() -> list[str]:
    corpus = ROOT / "industrialxpl/resources/corpus/torii_hajime.json"
    if not corpus.is_file():
        return ["torii_hajime corpus missing"]
    data = json.loads(corpus.read_text(encoding="utf-8"))
    if len(data.get("families", {})) < 2:
        return ["corpus families < 2"]
    return []


STEP_RUNNERS = {
    "env_doctor": step_env_doctor,
    "verify_family_matrix": step_verify_family_matrix,
    "ingest_awesome": step_ingest_awesome,
    "deep_study": step_deep_study,
    "score_incorporation": step_score_incorporation,
    "forensics_ioc": step_forensics_ioc,
    "aim2_modules": step_aim2_modules,
    "fuzz_compile": step_fuzz_compile,
    "otscan_smoke": step_otscan_smoke,
    "aim3_modules": step_aim3_modules,
    "s7scan_smoke": step_s7scan_smoke,
    "vendors_smoke": step_vendors_smoke,
    "bacnet_smoke": step_bacnet_smoke,
    "iec104_smoke": step_iec104_smoke,
    "isf_port_smoke": step_isf_port_smoke,
    "mozi_smoke": step_mozi_smoke,
    "ricnar_smoke": step_ricnar_smoke,
    "icsforge_smoke": step_icsforge_smoke,
    "ot_audit_smoke": step_ot_audit_smoke,
    "modbus_toolkit_smoke": step_modbus_toolkit_smoke,
    "mirai_loader_smoke": step_mirai_loader_smoke,
    "incontroller_smoke": step_incontroller_smoke,
    "frostygoop_json_smoke": step_frostygoop_json_smoke,
    "edb_smoke": step_edb_smoke,
    "openplc_smoke": step_openplc_smoke,
    "s2opc_smoke": step_s2opc_smoke,
    "open_plc_smoke": step_open_plc_smoke,
    "nse_quickdraw_smoke": step_nse_quickdraw_smoke,
    "corpus_smoke": step_corpus_smoke,
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
