        sub = args.strip().lower()
        from collections import defaultdict
        tree: dict = defaultdict(lambda: defaultdict(list))
        for m in self.modules:
            parts = m.split(".")
            if len(parts) >= 3:
                cat    = parts[0]   # e.g. scanners, assessment, cve, exploits
                subcat = parts[1]   # e.g. ics, mining, detection
                name   = ".".join(parts[2:])
                tree[cat][subcat].append(name)
            elif len(parts) == 2:
                cat, name = parts
                tree[cat][""].append(name)
            elif len(parts) == 1:
                tree[parts[0]][""].append(parts[0])

        if not sub:
            print_success(f"Top-level categories ({len(tree)} total, {len(self.modules)} modules):")
            for cat in sorted(tree.keys()):
                subcats = sorted(s for s in tree[cat].keys() if s)
                total = sum(len(v) for v in tree[cat].values())
                print_info("  {:20s} {:4d} modules  subcats: {}".format(
                    cat, total, ", ".join(subcats[:8]) + ("..." if len(subcats) > 8 else "")
                ))
            print_info("")
            print_info("Drill down: modules <category>  (e.g. 'modules scanners', 'modules assessment')")
            return

        if sub not in tree:
            similar = [c for c in tree if sub in c or c in sub]
            print_error(f"Category '{sub}' not found.")
            if similar:
                print_info("  Did you mean: {}".format(", ".join(similar)))
            else:
                cats = ", ".join(sorted(tree.keys()))
                print_info(f"  Available: {cats}")
            return

        print_success(f"Category '{sub}' -- {len(tree[sub])} subcategory/subcategories:")
        for subcat in sorted(tree[sub].keys()):
            mods = tree[sub][subcat]
            label = f"{sub}/{subcat}" if subcat else sub
            print_info(f"  [{len(mods):3d}]  {label}")
            for modname in sorted(mods)[:6]:
                if subcat:
                    path = humanize_path(f"{sub}.{subcat}.{modname}")
                else:
                    path = humanize_path(f"{sub}.{modname}")
                print_info(f"           use {path}")
            if len(mods) > 6:
                print_info(f"           ... and {len(mods) - 6} more -- use: search {subcat or sub}")

    def command_exec(self, args: str, **kwargs) -> None:
        if not args.strip():
            print_error("Usage: exec <shell command>")
            return
        try:
            result = subprocess.run(
                args, shell=True, capture_output=True, text=True, timeout=30
            )
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print_warning(result.stderr)
        except subprocess.TimeoutExpired:
            print_error("Command timed out.")

    def command_discover(self, args: str, **kwargs) -> None:
        cidr = args.strip()
        if not cidr:
            print_error("Usage: discover <CIDR>  (e.g. discover 192.168.1.0/24)")
            return
        print_status(f"Discovering OT/ICS assets on {cidr}…")
        self.command_use("scanners/ics/modbus_detect")
        if self.current_module:
            print_warning(f"Set target to each host in {cidr} and run check().")
            print_info(f"For automated CIDR sweep: ixf > ttp T0846.001 {cidr}")

    def parse_line(self, line: str) -> tuple:
        """Normalise hyphens in commands (mitre-list -> mitre_list)."""
        line = line.strip()
        if not line:
            return "", "", {}
        parts = line.split(None, 1)
        command = parts[0].replace("-", "_").lower()
        args = parts[1] if len(parts) > 1 else ""
        return command, args, {}
