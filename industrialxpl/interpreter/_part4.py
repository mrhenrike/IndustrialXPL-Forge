            return

        if answer in ("", "y", "yes"):
            print_status("Running: pip install --upgrade industrialxpl")
            import subprocess as _sp
            try:
                result = _sp.run(
                    [sys.executable, "-m", "pip", "install", "--upgrade", "industrialxpl"],
                    capture_output=False,
                    text=True,
                )
                if result.returncode == 0:
                    print_success(f"Upgrade complete. Restart IXF to use v{latest}.")
                else:
                    print_error(f"pip exited with code {result.returncode}. Check the output above.")
            except Exception as exc:
                print_error(f"Upgrade failed: {exc}")
        else:
            print_info("Upgrade skipped. Run 'update' again when ready.")

    # Alias
    def command_upgrade(self, args: str = "", **kwargs) -> None:
        self.command_update(args, **kwargs)

    def command_exit(self, args: str = "", **kwargs) -> None:
        print_info("Exiting IndustrialXPL-Forge. Stay safe.")
        sys.exit(0)

    def command_use(self, module_path: str, **kwargs) -> None:
        module_path = pythonize_path(module_path.strip())
        full_path = f"industrialxpl.modules.{module_path}"
        try:
            cls = import_exploit(full_path)
            self.current_module = cls()
            # Apply global options to module where names match
            _SKIP_GLOBAL = {"loglevel", "verbose", "output", "report_fmt", "threads"}
            for key, val in self._global_opts.items():
                if key in _SKIP_GLOBAL:
                    continue
                if key in self.current_module.options:
                    try:
                        setattr(self.current_module, key, val)
                    except Exception:
                        pass
            # Explicit globals for targeting (port/transport/unit_id override module defaults)
            for gkey in ("port", "transport", "unit_id"):
                gval = self._global_opts.get(gkey, "")
                if gval and gkey in self.current_module.options:
                    try:
                        setattr(self.current_module, gkey, gval)
                    except Exception:
                        pass
            # Always propagate target if module has it and global is set
            g_target = self._global_opts.get("target", "")
            if g_target and "target" in self.current_module.options:
                try:
                    if not getattr(self.current_module, "target", ""):
                        self.current_module.target = g_target
                except Exception:
                    pass
            # Warn if poly language requires external runtime
            info = self.current_module.get_info()
            poly_lang = info.get("poly_language", "python")
            if poly_lang != "python":
                from industrialxpl.core.poly.poly_runner import PolyExploitRunner
                runner = PolyExploitRunner()
                if not runner.check_runtime(poly_lang):
                    print_warning(
                        f"[opt] Runtime '{poly_lang}' not found -- Python fallback will be used."
                    )
            # Inject global scan opts into Modbus modules
            _SCAN_KEYS = {"host_timeout", "max_retries", "min_retries",
                          "scan_delay", "max_rate", "probe_level",
                          "ping_first", "skip_ping"}
            scan_opts = {k: v for k, v in self._global_opts.items() if k in _SCAN_KEYS}
            # Fill defaults for any unset scan keys
            for k, dv in self._GLOBAL_DEFAULTS.items():
                if k in _SCAN_KEYS and k not in scan_opts:
                    scan_opts[k] = dv
            if hasattr(self.current_module, "_apply_global_scan_opts"):
                self.current_module._apply_global_scan_opts(scan_opts)

            print_success("Module loaded: {}".format(info.get("name", module_path)))
        except IXFException as exc:
            print_error(str(exc))

    def command_back(self, args: str = "", **kwargs) -> None:
        self.current_module = None
        print_info("Module deselected.")

    @module_required
    def command_set(self, args: str, **kwargs) -> None:
        parts = args.split(None, 1)
        if len(parts) < 2:
            # 'set <option>' with no value -- show help for that option
            if len(parts) == 1:
                opt = parts[0].lower()
                omap = self._get_option_help_map()
                if opt in omap:
                    omap[opt]()
                    return
            print_error("Usage: set <option> <value>  |  set <option> ?")
            if self.current_module:
                self.command_show("options")
            return
        key_raw, value = parts[0], parts[1]
        # Case-insensitive option matching
        key = key_raw.lower()
        # '?' as value = show help for that option
        if value.strip() == "?":
            omap = self._get_option_help_map()
            if key in omap:
                omap[key]()
            else:
                print_info(f"No dedicated help for '{key}'. Type 'help {key}' to search.")
            return
        if key not in self.current_module.options:
            print_error(f"Unknown option: '{key_raw}' -- type 'show options' to list valid options")
            return
        try:
            setattr(self.current_module, key, value)
            self.current_module.exploit_attributes[key][0] = value
            print_success(f"{key} => {value}")
        except Exception as exc:
            print_error(f"Cannot set '{key}': {exc}")
            omap = self._get_option_help_map()
            if key in omap:
                print_info(f"  Type 'set {key} ?' for accepted values.")

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
