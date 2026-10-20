"""Stats, vendors, protocols and coverage commands (mixin)."""


from industrialxpl.core.exploit.printer import print_info, print_table
from industrialxpl.core.exploit.utils import index_modules


class StatsCommandsMixin:
    """Module statistics, vendor coverage and protocol listing."""

    def command_stats(self, args: str = "", **kwargs) -> None:
        """Show IXF module statistics and coverage summary."""
        mods = index_modules()
        from collections import Counter
        top_cats = Counter(m.split(".")[0] for m in mods)
        print_info("IXF Module Statistics")
        print_table(
            ["Category", "Count", "%"],
            [(k, str(v), f"{v * 100 // len(mods)}%") for k, v in sorted(top_cats.items(), key=lambda x: -x[1])],
            title=f"Total: {len(mods)} modules",
        )
        vendors = set()
        for m in mods:
            parts = m.split(".")
            if parts[0] == "cve" and len(parts) >= 2 and not parts[1].startswith("cve_"):
                vendors.add(parts[1])
        malware = sum(1 for m in mods if "malware" in m or m.startswith("cve.apt."))
        print_info(f"Vendors covered: {len(vendors)} | Malware TTPs: {malware}")
        print_info("MITRE ATT&CK for ICS: 12 tactics, 103 techniques mapped")
        print_info("PyPI: pip install industrialxpl-forge | GitHub: github.com/mrhenrike/IndustrialXPL-Forge")

    def command_vendors(self, args: str = "", **kwargs) -> None:
        """List all OT/ICS vendors covered with module count. Usage: vendors [filter]"""
        mods = index_modules()
        vendors: dict = {}
        for m in mods:
            parts = m.split(".")
            if parts[0] == "cve" and len(parts) >= 2 and not parts[1].startswith("cve_"):
                v = parts[1]
                vendors[v] = vendors.get(v, 0) + 1
        flt = args.strip().lower()
        rows = [
            (v.replace("_", " ").title(), str(cnt))
            for v, cnt in sorted(vendors.items(), key=lambda x: -x[1])
            if not flt or flt in v.lower()
        ]
        print_table(["Vendor", "Modules"], rows, title=f"Vendors ({len(rows)} covered)")

    def command_protocols(self, args: str = "", **kwargs) -> None:
        """List all OT/ICS protocols covered. Usage: protocols"""
        mods = index_modules()
        protos: dict = {}
        for m in mods:
            if "protocols" in m:
                parts = m.split(".")
                idx = parts.index("protocols") if "protocols" in parts else -1
                if idx >= 0 and idx + 1 < len(parts):
                    p = parts[idx + 1]
                    protos[p] = protos.get(p, 0) + 1
        rows = [(p.upper().replace("_", "-"), str(cnt)) for p, cnt in sorted(protos.items())]
        print_table(["Protocol", "Exploit Modules"], rows, title=f"Protocol Coverage ({len(rows)} protocols)")

    def command_coverage(self, args: str = "", **kwargs) -> None:
        """Show MITRE ATT&CK for ICS coverage. Alias for: mitre coverage"""
        self.command_mitre_coverage(args)
