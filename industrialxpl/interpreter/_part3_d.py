    def command_setg(self, args: str, **kwargs) -> None:
        parts = args.split(None, 1)
        if len(parts) < 2:
            print_error("Usage: setg <option> <value>")
            self._help_global()
            return
        key, value = parts[0].lower(), parts[1].strip()
        self._global_opts[key] = value

        # Apply well-known global options immediately
        if key in ("loglevel", "log_level"):
            set_log_level(value)
            print_success(f"[global] loglevel => {value}")
            return
        if key == "verbose":
            set_log_level("debug" if value.lower() in ("true", "1", "on", "yes") else "info")
            self._global_opts["loglevel"] = get_log_level()
            print_success(f"[global] verbose => {value}  (loglevel={get_log_level()})")
            return
        if key == "threads":
            try:
                t = int(value)
                if t < 1:
                    raise ValueError
                self._global_opts["threads"] = str(t)
                print_success(f"[global] threads => {t}")
                return
            except ValueError:
                print_error(f"threads must be a positive integer, got: {value}")
                return

        if key in ("host_timeout", "max_retries", "min_retries", "scan_delay", "max_rate"):
            try:
                v = int(value)
                if v < 0:
                    raise ValueError
                self._global_opts[key] = str(v)
                print_success(f"[global] {key} => {v}")
                return
            except ValueError:
                print_error(f"{key} must be a non-negative integer, got: {value}")
                return

        if key == "probe_level":
            try:
                v = int(value)
                if not 1 <= v <= 5:
                    raise ValueError
                self._global_opts[key] = str(v)
                print_success(f"[global] probe_level => {v} (service detection depth)")
                return
            except ValueError:
                print_error(f"probe_level must be 1-5, got: {value}")
                return

        if key == "safemode":
            _TRUE = {"true", "yes", "1", "on"}
            _FALSE = {"false", "no", "0", "off"}
            lv = value.lower().strip()
            if lv in _TRUE:
                self._global_opts["safemode"] = "true"
                print_success("[global] SAFEMODE => true  (legacy flag; does not override module options)")
            elif lv in _FALSE:
                self._global_opts["safemode"] = "false"
                print_info("[global] SAFEMODE => false  (legacy flag; module options control execution)")
            else:
                print_error(f"SAFEMODE must be true or false, got: {value}")
            return

        if key in ("ping_first", "skip_ping"):
            _TRUE = {"true", "yes", "1", "on"}
            _FALSE = {"false", "no", "0", "off"}
            lv = value.lower().strip()
            if lv in _TRUE:
                self._global_opts[key] = "true"
            elif lv in _FALSE:
                self._global_opts[key] = "false"
            else:
                print_error(f"{key} must be true/false, got: {value}")
                return
            print_success(f"[global] {key} => {self._global_opts[key]}")
            return

        if key == "port":
            try:
                from industrialxpl.core.modbus.transport import parse_port_expression
                expr = value.strip()
                if expr.isdigit():
                    p = int(expr)
                    if not 1 <= p <= 65535:
                        raise ValueError
                else:
                    parse_port_expression(expr)
                self._global_opts["port"] = expr
                print_success(f"[global] PORT => {expr}")
                if self.current_module and "port" in self.current_module.options:
                    try:
                        self.current_module.port = expr
                    except Exception:
                        pass
                return
            except (ValueError, Exception) as exc:
                print_error(f"Invalid port expression: {value} ({exc})")
                self._help_option_port()
                return

        if key == "transport":
            allowed = {"tcp", "udp", "both"}
            lv = value.lower().strip()
            if lv not in allowed:
                print_error(f"TRANSPORT must be tcp, udp, or both, got: {value}")
                self._help_option_transport()
                return
            self._global_opts["transport"] = lv
            print_success(f"[global] TRANSPORT => {lv}")
            if self.current_module and "transport" in self.current_module.options:
                try:
                    self.current_module.transport = lv
                except Exception:
                    pass
            return

        if key == "unit_id":
            try:
                uid = int(value)
                if not 0 <= uid <= 255:
                    raise ValueError
                self._global_opts["unit_id"] = str(uid)
                print_success(f"[global] UNIT_ID => {uid}")
                if self.current_module and "unit_id" in self.current_module.options:
                    try:
                        self.current_module.unit_id = uid
                    except Exception:
                        pass
                return
            except ValueError:
                print_error(f"UNIT_ID must be 0-255, got: {value}")
                return

        if key in ("timing", "scan_timing"):
            try:
                from industrialxpl.core.modbus.timing import ModbusTiming
                profile = ModbusTiming.resolve(value)
                self._global_opts["timing"] = str(value)
                print_success(f"[global] timing => {value} ({profile.name})")
                if self.current_module and "timing" in self.current_module.options:
                    try:
                        self.current_module.timing = value
                    except Exception:
                        pass
                return
            except ValueError as exc:
                print_error(str(exc))
                self._help_timing()
                return

        if self.current_module and key in self.current_module.options:
            try:
                setattr(self.current_module, key, value)
            except Exception:
                pass
        print_success(f"[global] {key} => {value}")

    def command_unsetg(self, args: str, **kwargs) -> None:
        key = args.strip()
        if key in self._global_opts:
            del self._global_opts[key]
            print_success(f"[global] {key} cleared.")
        else:
            print_warning(f"'{key}' was not set globally.")

    def command_show(self, args: str = "", **kwargs) -> None:
        sub = args.strip().lower() or "options"

        # Context-free show commands (work without module)
        if sub in ("global", "globals", "global_options"):
            self._help_global()
            return
        if sub in ("sector", "sectors"):
            self._help_sectors()
            return
        if sub in ("type", "types", "category", "categories"):
            self._help_types()
            return
        if sub in ("simulate", "simulation"):
            self._help_simulate()
            return
        if sub in ("loglevel", "verbose"):
            self._help_loglevel()
            return
        if sub in ("mitre", "ttp"):
            self._help_mitre()
            return
        # Per-option help via show
        omap = self._get_option_help_map()
        if sub in omap:
            omap[sub]()
            return

        if not self.current_module:
            if sub in ("modules", "all", "options", ""):
                print_status(f"{len(self.modules)} modules indexed. Use 'search <keyword>' to find modules.")
                print_info("  search modbus       -- keyword search")
                print_info("  search sector=energy -- sector filter")
                print_info("  search type=scanner -- type filter")
                print_info("  modules             -- browse categories")
                print_info("  show global         -- global options")
                print_info("  show sectors        -- available sectors")
                print_info("  show types          -- module categories")
            else:
                print_error("No module loaded. Use 'use <module_path>' first.")
            return
        mod = self.current_module
        info = mod.get_info()

        if sub == "info":
            pprint_dict_in_order(info, header="Module Information")
        elif sub in ("options", "advanced"):
            rows = [
                (k.upper(), str(v[0]), "yes" if not v[2] else "adv", v[1])
                for k, v in mod.exploit_attributes.items()
                if sub == "advanced" or not v[2]
            ]
            print_table(["Option", "Value", "Required", "Description"], rows,
                        title="Options -- {}".format(info.get("name", str(mod))))
            print_info("  Options are case-insensitive: SET TARGET, set target, and Set Target all work.")
            print_info("  Type 'set OPTION ?' or 'help OPTION' for detailed help on any option.")
        elif sub == "devices":
            devices = info.get("devices", [])
            print_info("Devices: {}".format(", ".join(devices) if devices else "Any"))
        elif sub == "all":
            self.command_show("info")
            self.command_show("options")
        else:
            print_error("show [info|options|advanced|devices|all]")

    @module_required
    def command_run(self, args: str = "", **kwargs) -> None:
        """Execute the current module using per-module simulate/destructive options."""
        mod = self.current_module
        info = mod.get_info()
        name = info.get("name", str(mod))

        sim = bool(mod.simulate)
        destr = bool(mod.destructive)
        mod._simulate_mode = sim
        mod._destructive_mode = destr
        mod._safemode = False

        if sim:
            print_status(f"{name} [SIMULATE] -- dry-run per module option")
        elif destr:
            print_status(f"{name} [DESTRUCTIVE] -- reads and writes per module option")
            print_warning("  Destructive mode enabled. Device state may change.")
        else:
            print_status(f"{name} [LIVE] -- real execution per module options")

        try:
            mod.run()
        except NotImplementedError:
            print_warning("Module run() not yet implemented.")

    @module_required
    def command_check(self, args: str = "", **kwargs) -> None:
        mod = self.current_module
        info = mod.get_info()
        impact = info.get("impact", "LOW").upper()
        if impact in ("INFO", "READ"):
            print_info("This module is assessment-only. Use 'run' to start the questionnaire.")
            return
        print_status("Checking {}…".format(info.get("name", str(mod))))
        try:
            result = mod.check()
            if result is None:
                print_info("check() not applicable for this module type.")
            elif result:
                print_success("VULNERABLE -- {}".format(info.get("name", "")))
            else:
                print_info("NOT_VULNERABLE -- {}".format(info.get("name", "")))
        except NotImplementedError:
            print_warning("Module check() not yet implemented.")

    # Sector/industry keyword mapping for discovery
    _SECTOR_ALIASES = {
        "energy": ["siemens", "abb", "schneider", "ge", "emerson", "power", "scada", "dnp3"],
        "oilgas": ["oilgas", "oil_gas", "night_dragon", "vsat", "cobham", "dnp3"],
        "oil": ["night_dragon", "oil_gas", "dnp3", "modbus"],
        "gas": ["gas", "modbus", "dnp3"],
        "water": ["water", "modbus", "dnp3", "scada"],
        "pharma": ["pharma", "batch", "opc", "profinet"],
        "manufacturing": ["modbus", "enip", "profinet", "plc", "rockwell", "siemens", "abb"],
        "building": ["bacnet", "knx", "bms", "hvac", "automated_logic", "webctrl"],
        "automotive": ["profinet", "can", "upa", "obd"],
        "maritime": ["ais", "nmea", "vsat", "gps"],
        "aviation": ["ads_b", "asterix", "fms"],
        "mining": ["modbus", "dnp3", "abb", "siemens"],
        "railway": ["modbus", "profinet", "dnp3", "cbtc"],
        "chemical": ["modbus", "profinet", "siemens", "safety", "triton"],
        "nuclear": ["modbus", "profinet", "siemens", "plc"],
        "hospital": ["modbus", "bacnet", "bms", "ics"],
        "datacenter": ["modbus", "bacnet", "bms", "hvac", "ups"],
        "smart_grid": ["dnp3", "iec104", "iec61850", "modbus"],
        "scada": ["scada", "hmi", "historian", "opc"],
        "plc": ["plc", "modbus", "s7comm", "enip", "profinet"],
        "firepower": ["schneider", "rockwell", "siemens", "plc"],
        "dcs": ["dcs", "yokogawa", "emerson", "abb", "honeywell"],
        "rtu": ["rtu", "modbus", "dnp3"],
        "mining": ["mining", "fms", "minestar", "wenco", "komatsu", "caterpillar",
                   "lorawan", "gnss", "ahs", "dispatch", "pitram", "modular"],
        "mineracao": ["mining", "fms", "minestar", "wenco", "caterpillar",
                      "lorawan", "gnss", "ahs", "pitram"],
        "mineradora": ["mining", "fms", "minestar", "wenco", "caterpillar",
                       "lorawan", "gnss", "sap"],
        "sap": ["sap", "netweaver", "cve_2025_31324", "s4hana"],
    }

    def _get_search_engine(self):
        """Return a cached multilingual SearchEngine."""
        if not hasattr(self, "_search_engine") or self._search_engine is None:
            from industrialxpl.core.search.engine import SearchEngine
            self._search_engine = SearchEngine(self.modules)
        return self._search_engine

    def command_search(self, args: str, **kwargs) -> None:
        """Multilingual search: supports PT-BR, EN-US, ES, accents, sector/type filters."""
        term = args.strip()
        if not term:
            print_error("Usage: search <keyword>")
            print_info("  search modbus              -- keyword (English)")
            print_info("  search mineracao           -- PT-BR term (maps to mining)")
            print_info("  search minerio             -- without accent, same result")
            print_info("  search minério             -- with accent, also works")
            print_info("  search sector=mining       -- sector filter (English)")
            print_info("  search sector=mineracao    -- sector filter (PT-BR)")
            print_info("  search sector=energia      -- sector filter (PT-BR/ES)")
            print_info("  search type=scanner        -- filter by module type")
            print_info("  search type=varredura      -- PT-BR type filter")
            print_info("  help search                -- full multilingual guide")
            return

        engine = self._get_search_engine()
        result = engine.search(term)

        if result.found:
            label = result.display_name or term
            print_success(f"{len(result)} module(s) for '{label}':")
            for m in result.modules[:50]:
                print_info(f"  use {humanize_path(m)}")
            if len(result.modules) > 50:
                print_info(f"  ... and {len(result.modules) - 50} more. Refine your search.")
            if result.expansion_note:
                print_info(f"  [i] {result.expansion_note}")
            return

        # No results found
        print_info(f"No modules found for '{term}'.")
        if result.suggestions:
            print_info("  Did you mean: {}".format(", ".join(result.suggestions)))
            print_info(f"  Try: search {result.suggestions[0]}")
        if result.multilingual_hint:
            print_info(f"  {result.multilingual_hint}")
        if result.hint:
            print_info(f"  {result.hint}")
        print_info("  Tip: search sector=<name>  |  search type=<category>  |  help search")

    def command_modules(self, args: str = "", **kwargs) -> None:
        """Drill-down module browser by top-level category.

        Module paths from index_modules() are relative: assessment.detection.module_name
        Parts: [category, subcategory, module_name]
        """
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
