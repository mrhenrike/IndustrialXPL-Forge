"""MITRE ATT&CK for ICS, CVE lookup and TTP sweep commands (mixin)."""


from typing import TYPE_CHECKING

from industrialxpl.core.exploit.printer import (
    print_error,
    print_info,
    print_status,
    print_success,
    print_table,
)
from industrialxpl.core.exploit.utils import humanize_path

if TYPE_CHECKING:
    pass


class MITRECommandsMixin:
    """CVE, MITRE and TTP commands extracted from IXFInterpreter."""

    # -- CVE commands ------------------------------------------------------

    def command_cve(self, args: str, **kwargs) -> None:
        cve_id = args.strip().upper()
        if not cve_id.startswith("CVE-") and not cve_id.startswith("CNVD-"):
            print_error("Usage: cve <CVE-ID>  (e.g. cve CVE-2022-29953)")
            return
        matches = [
            m for m in self.modules
            if cve_id.lower().replace("-", "_") in m.lower()
        ]
        if not matches:
            print_error(f"No IXF module found for {cve_id}. Check resources/cve/ics_cve_database.json")
            return
        if len(matches) == 1:
            self.command_use(humanize_path(matches[0]))
        else:
            print_success(f"{len(matches)} module(s) for {cve_id}:")
            for m in matches:
                print_info(f"  use {humanize_path(m)}")

    def command_cve_scan(self, args: str, **kwargs) -> None:
        cidr = args.strip()
        if not cidr:
            print_error("Usage: cve-scan <CIDR>")
            return
        print_status(f"[cve-scan] Discovery + CVE testing on {cidr}...")
        print_info("Feature: auto-fingerprint each host then run applicable CVE modules.")
        print_info(f"Use mitre-scan discovery {cidr} to start with passive scanning.")

    def command_report(self, args: str, **kwargs) -> None:
        fmt = args.strip().lower() or "json"
        from industrialxpl.core.reporting.reporter import IXFReporter
        reporter = IXFReporter()
        output = reporter.generate(fmt)
        print_success(f"Report generated: {output}")

    # -- MITRE commands -----------------------------------------------------

    def command_mitre(self, args: str, **kwargs) -> None:
        tid = args.strip().upper()
        if not tid:
            print_error("Usage: mitre <TID>  (e.g. mitre T0843)")
            return
        from industrialxpl.core.mitre.index import TECHNIQUE_INDEX, build_index
        build_index(self.modules)
        mods = TECHNIQUE_INDEX.get(tid, [])
        if not mods:
            print_error(f"No modules for {tid}. Try 'mitre-list' to see all.")
            return
        print_success(f"{len(mods)} module(s) cover {tid}:")
        for m in mods:
            print_info(f"  use {humanize_path(m)}")

    def command_mitre_list(self, args: str, **kwargs) -> None:
        from industrialxpl.core.mitre.index import TACTIC_INDEX, TECHNIQUE_INDEX, build_index
        from industrialxpl.core.mitre.tactics import TACTIC_ALIASES
        build_index(self.modules)
        tactic_filter = args.strip().lower() or None
        tactic_id = TACTIC_ALIASES.get(tactic_filter) if tactic_filter else None
        rows = []
        for tid, mods in sorted(TECHNIQUE_INDEX.items()):
            if tactic_id:
                tac_mods = TACTIC_INDEX.get(tactic_id, [])
                if not any(m in tac_mods for m in mods):
                    continue
            rows.append((tid, str(len(mods)), humanize_path(mods[0]) if mods else ""))
        title = "MITRE ATT&CK for ICS{}".format(
            f" : {tactic_filter}" if tactic_filter else ""
        )
        print_table(["TID", "# Modules", "Primary Module"], rows, title=title)

    def command_mitre_scan(self, args: str, **kwargs) -> None:
        parts = args.strip().split()
        if len(parts) < 2:
            print_error("Usage: mitre-scan <tactic|TID> <target/CIDR> [--destructive]")
            return
        tactic_or_tid, target = parts[0], parts[1]
        destructive = "--destructive" in parts
        simulate = "--simulate" in parts
        from industrialxpl.core.mitre.sweeper import MitreTacticSweeper
        sweeper = MitreTacticSweeper(
            target=target, simulate=simulate, destructive=destructive,
        )
        t = tactic_or_tid.upper()
        if t.startswith("T0") or t.startswith("T1"):
            sweeper.sweep_technique(t)
        else:
            sweeper.sweep_tactic(tactic_or_tid)

    def command_mitre_all(self, args: str, **kwargs) -> None:
        target = args.strip()
        if not target:
            print_error("Usage: mitre-all <target>")
            return
        from industrialxpl.core.mitre.sweeper import MitreTacticSweeper
        msg = "[mitre-all] Full MITRE ICS sweep on {} (live; use --simulate for dry-run)"
        print_status(msg.format(target))
        MitreTacticSweeper(target=target, simulate=False).sweep_all()

    def command_mitre_coverage(self, args: str, **kwargs) -> None:
        from industrialxpl.core.mitre.index import TECHNIQUE_INDEX, build_index
        from industrialxpl.core.mitre.tactics import TACTIC_TIDS, TACTICS
        build_index(self.modules)
        rows = []
        total_cov = total_tids = 0
        for tid_id, tname in TACTICS.items():
            tids = TACTIC_TIDS.get(tid_id, [])
            covered = sum(1 for t in tids if TECHNIQUE_INDEX.get(t))
            pct = int(covered / len(tids) * 100) if tids else 0
            rows.append((tid_id, tname, str(len(tids)), str(covered), f"{pct}%"))
            total_tids += len(tids)
            total_cov += covered
        global_pct = int(total_cov / total_tids * 100) if total_tids else 0
        rows.append(("TOTAL", "--", str(total_tids), str(total_cov), f"{global_pct}%"))
        print_table(
            ["Tactic ID", "Tactic", "Total TIDs", "Covered", "%"],
            rows,
            title="IXF MITRE ATT&CK for ICS Coverage",
        )

    def command_mitre_report(self, args: str, **kwargs) -> None:
        fmt = args.strip().lower() or "layer"
        from industrialxpl.core.mitre.reporter import MitreSweepReporter
        output = MitreSweepReporter().generate_layer(fmt)
        print_success(f"MITRE report generated: {output}")

    def command_mitre_tactic(self, args: str, **kwargs) -> None:
        self.command_mitre_scan(args, **kwargs)

    # -- TTP commands -------------------------------------------------------

    def command_ttp(self, args: str, **kwargs) -> None:
        parts = args.strip().split()
        if len(parts) < 2:
            print_error("Usage: ttp <TID> <target/CIDR> [--destructive] [--stop-on-first] [--output <file>]")
            print_info("Examples:")
            print_info("  ixf > ttp T0843 192.168.1.100")
            print_info("  ixf > ttp T0878 10.0.0.0/24")
            print_info("  ixf > ttp T0843.001 192.168.1.100 --stop-on-first")
            return
        tid, target = parts[0].upper(), parts[1]
        destructive = "--destructive" in parts
        simulate = "--simulate" in parts
        stop_first = "--stop-on-first" in parts
        output_file = parts[parts.index("--output") + 1] if "--output" in parts else None
        rate_ms = int(parts[parts.index("--rate-limit") + 1]) if "--rate-limit" in parts else 500
        from industrialxpl.core.mitre.sweeper import MitreTacticSweeper
        sweeper = MitreTacticSweeper(
            target=target,
            simulate=simulate,
            destructive=destructive,
            rate_limit_ms=rate_ms,
            stop_on_first_vuln=stop_first,
        )
        results = sweeper.sweep_technique(tid)
        if output_file:
            from industrialxpl.core.mitre.reporter import MitreSweepReporter
            MitreSweepReporter(results).save(output_file)
            print_success(f"Results saved to {output_file}")

    def command_ttp_check(self, args: str, **kwargs) -> None:
        parts = args.strip().split()
        if len(parts) < 2:
            print_error("Usage: ttp-check <TID> <target>")
            return
        tid, target = parts[0].upper(), parts[1]
        from industrialxpl.core.mitre.sweeper import MitreTacticSweeper
        MitreTacticSweeper(target=target, simulate=False, check_only=True).sweep_technique(tid)

    def command_ttp_simulate(self, args: str, **kwargs) -> None:
        parts = args.strip().split()
        if len(parts) < 2:
            print_error("Usage: ttp-simulate <TID> <target>")
            return
        tid, target = parts[0].upper(), parts[1]
        from industrialxpl.core.mitre.sweeper import MitreTacticSweeper
        MitreTacticSweeper(target=target, simulate=True).sweep_technique(tid)

    def command_ttp_list(self, args: str, **kwargs) -> None:
        from industrialxpl.core.mitre.index import TACTIC_INDEX, TECHNIQUE_INDEX, build_index
        from industrialxpl.core.mitre.tactics import TACTIC_ALIASES
        build_index(self.modules)
        tactic_filter = None
        if "--tactic" in args:
            parts = args.split("--tactic")
            tactic_filter = parts[1].strip().split()[0].lower() if len(parts) > 1 else None
        tactic_id = TACTIC_ALIASES.get(tactic_filter) if tactic_filter else None
        rows = []
        for tid, mods in sorted(TECHNIQUE_INDEX.items()):
            if tactic_id:
                tac_mods = TACTIC_INDEX.get(tactic_id, [])
                if not any(m in tac_mods for m in mods):
                    continue
            rows.append((tid, str(len(mods)), humanize_path(mods[0]) if mods else ""))
        title = "TTP-IDs{}".format(f" : {tactic_filter}" if tactic_filter else " (all)")
        print_table(["TTP-ID", "# Modules", "Primary Module"], rows, title=title)
