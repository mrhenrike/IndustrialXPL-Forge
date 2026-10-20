class IXFInterpreter(
    MITRECommandsMixin,
    MalwareCommandsMixin,
    ICSCommandsMixin,
    StatsCommandsMixin,
    SASTCommandsMixin,
    BaseInterpreter,
):
    """IXF-specific interpreter with all OT/ICS commands.

    Command groups live in industrialxpl.cli.commands_* mixins.
    BaseInterpreter provides readline, dispatch and REPL.
    """

    history_file = os.path.expanduser("~/.ixf_history")

    def __init__(self) -> None:
        super().__init__()
        try:
            from industrialxpl.core.malware.crosscompile import ensure_cross_path_in_env
            ensure_cross_path_in_env()
        except Exception:
            pass
        print_status("Indexing modules…")
        self.modules: list = index_modules()
        print_success(f"{len(self.modules)} modules indexed.")
        self._bind_completer()
        self._resume_persistent_c2()

    def _resume_persistent_c2(self) -> None:
        """If C2_PERSIST / saved state - show bots reporting after IXF restart."""
        try:
            from industrialxpl.core.malware.c2_server import resume_on_startup
            r = resume_on_startup()
            if not r.get("resumed"):
                return
            online = r.get("bots_online", 0)
            total = r.get("bots_total", 0)
            pid = r.get("daemon_pid", " - ")
            cfg = r.get("config") or {}
            print_info(
                "C2 persistente - {} bots online / {} total | py={} go={}".format(
                    online, total, pid, r.get("go_cnc_pid", " - "),
                )
            )
        except Exception:
            pass

    # -- Global commands ----------------------------------------------------

    # Known terms that have dedicated help pages
    _HELP_TOPICS = {
        "sector", "sectors", "type", "types", "global", "globals",
        "simulate", "destructive", "loglevel", "verbose", "threads",
        "search", "modules", "mitre", "ttp", "cve", "assess", "assessment",
    }

    def command_help(self, args: str = "", **kwargs) -> None:
        term = args.strip().lower()

        # help <term> -- topic-based help
        if term:
            if term in ("sector", "sectors"):
                self._help_sectors()
                return
            if term in ("type", "types", "category", "categories"):
                self._help_types()
                return
            if term in ("global", "globals", "global_options"):
                self._help_global()
                return
            if term in ("safemode", "safe_mode", "safety"):
                self._help_safemode()
                return
            if term in ("simulate", "simulation"):
                self._help_simulate()
                return
            if term in ("loglevel", "verbose", "verbosity"):
                self._help_loglevel()
                return
            if term in ("timing", "t0", "t1", "t2", "t3", "t4", "t5", "nmap"):
                self._help_option_timing()
                return
            if term in ("search",):
                self._help_search()
                return
            if term in ("mitre", "ttp"):
                self._help_mitre()
                return
            # Check per-option help map
            option_map = self._get_option_help_map()
            if term in option_map:
                option_map[term]()
                return
            # Try to load the module and print its options
            module_path = pythonize_path(term)
            full_path = f"industrialxpl.modules.{module_path}"
            try:
                cls = import_exploit(full_path)
                tmp = cls()
                info = tmp.get_info()
                pprint_dict_in_order(info, header="Module Information -- {}".format(info.get("name", term)))
                rows = [
                    (k, str(v[0]), "yes" if not v[2] else "adv", v[1])
                    for k, v in tmp.exploit_attributes.items()
                    if not v[2]
                ]
                print_table(
                    ["Option", "Default", "Required", "Description"],
                    rows,
                    title="Options -- {}".format(info.get("name", term)),
                )
                return
            except Exception:
                pass
            # Search for modules matching the term and show a mini help
            results = [m for m in self.modules if term in m.lower()]
            if results:
                print_success(f"{len(results)} module(s) match '{term}':")
                for m in results[:20]:
                    print_info(f"  use {humanize_path(m)}")
                if len(results) > 20:
                    print_info(f"  … and {len(results) - 20} more. Use: search {term}")
                print_info("\nTip: 'help <full/module/path>' shows that module's options.")
                return
            print_info(f"No help topic or module found for '{term}'. Known topics:")
            print_info("  " + "  ".join(sorted(self._HELP_TOPICS)))
            return

        # Default: context-sensitive help
        if self.current_module:
            print(_MODULE_HELP)
        else:
            print(_GLOBAL_HELP)

    def _help_sectors(self) -> None:
        print_info("\nAvailable sectors for 'search sector=<name>':\n")
        rows = []
        for sector in sorted(self._SECTOR_ALIASES.keys()):
            aliases = self._SECTOR_ALIASES[sector]
            count = len(set(
                m for alias in aliases for m in self.modules if alias in m.lower()
            ))
            rows.append((sector, str(count), ", ".join(aliases[:4]) + ("…" if len(aliases) > 4 else "")))
        print_table(
            ["Sector", "~Modules", "Matched keywords"],
            rows,
            title="Sectors -- search sector=<name>",
        )
        print_info("\nUsage:  search sector=energy")
        print_info("        search sector=oilgas")
        print_info("        search sector=manufacturing\n")

    def _help_types(self) -> None:
        _CAT_MAP = {
            "scanner":    "scanners/",
            "exploit":    "exploits/",
            "cve":        "cve/",
            "assessment": "assessment/",
            "creds":      "creds/",
        }
        print_info("\nModule categories for 'search type=<name>':\n")
        rows = []
        for cat, prefix in sorted(_CAT_MAP.items()):
            count = len([m for m in self.modules if prefix in m.lower()])
            rows.append((cat, str(count), f"search type={cat}"))
        print_table(["Type", "Modules", "Usage"], rows, title="Module Types")
        print_info("\nUsage:  search type=scanner")
        print_info("        search type=exploit")
        print_info("        search type=assessment\n")

    # Global option defaults -- safe and conservative for OT environments
    _GLOBAL_DEFAULTS = {
        "loglevel":       "info",
        "verbose":        "false",
        "safemode":       "false",   # legacy global flag; does not override module options
        "timing":         "T3",
        "threads":        "5",
        "host_timeout":   "30",
        "max_retries":    "2",
        "min_retries":    "0",
        "scan_delay":     "300",
        "max_rate":       "10",
        "probe_level":    "2",
        "ping_first":     "true",
        "skip_ping":      "false",
        "target":         "",
        "port":           "",
        "transport":      "",
        "unit_id":        "",
        "output":         "",
        "report_fmt":     "markdown",
    }

    def _get_global(self, key: str) -> str:
        return str(self._global_opts.get(key, self._GLOBAL_DEFAULTS.get(key, "")))

    def _help_global(self) -> None:
        # Section 0: Safety
        safety_rows = [
            ("SAFEMODE",   self._get_global("safemode"),
             "legacy flag (no longer overrides module simulate/destructive)"),
        ]
        print_table(["Option", "Current", "Description"],
                    safety_rows, title="Global: Safety (most important)")

        # Section 1: Output / Verbosity
        out_rows = [
            ("LOGLEVEL",   self._get_global("loglevel"),
             "debug | info | warning | error"),
            ("VERBOSE",    self._get_global("verbose"),
             "true | false  (alias: loglevel=debug)"),
            ("OUTPUT",     self._get_global("output"),
             "filepath  (tee output to file)"),
            ("REPORT_FMT", self._get_global("report_fmt"),
             "json | html | markdown | csv"),
        ]
        # Section 2: Scan Behavior
        scan_rows = [
            ("TIMING",       self._get_global("timing"),
             "T0..T5  or  paranoid/sneaky/polite/normal/aggressive/insane"),
            ("THREADS",      self._get_global("threads"),
             "integer >= 1  (parallel probes, default 5)"),
            ("HOST_TIMEOUT", self._get_global("host_timeout"),
             "seconds per host before giving up (default 30, 0=no limit)"),
            ("MAX_RETRIES",  self._get_global("max_retries"),
             "max TCP retry attempts per probe (default 2)"),
            ("MIN_RETRIES",  self._get_global("min_retries"),
             "min retries before moving on (default 0)"),
            ("SCAN_DELAY",   self._get_global("scan_delay"),
             "ms between probes to same host (default 300ms)"),
            ("MAX_RATE",     self._get_global("max_rate"),
             "max probes per second across all hosts (default 10)"),
            ("PROBE_LEVEL",  self._get_global("probe_level"),
             "service detection depth 1-5 (like nmap --version-intensity, default 2)"),
            ("PING_FIRST",   self._get_global("ping_first"),
             "true=TCP-ping host before scanning (default true, safer)"),
            ("SKIP_PING",    self._get_global("skip_ping"),
             "true=skip alive check, scan anyway (like nmap -Pn, default false)"),
        ]
        # Section 3: Targeting (global convenience only -- protocol options stay in modules)
        target_rows = [
            ("TARGET",    self._get_global("target"),
             "IP / hostname - default target when module TARGET is empty"),
            ("PORT",      self._get_global("port") or "(module default)",
             "Port expression: 502 | 502,510 | 500-510 - applied on module load"),
            ("TRANSPORT", self._get_global("transport") or "(module default)",
             "tcp | udp | both - applied on module load when supported"),
            ("UNIT_ID",   self._get_global("unit_id") or "(module default)",
             "Modbus unit ID 0-255 - applied on module load"),
        ]

        print_table(["Option", "Current", "Description / Accepted Values"],
                    out_rows, title="Global: Output & Verbosity")
        print_table(["Option", "Current", "Description / Accepted Values"],
                    scan_rows, title="Global: Scan Behavior  (safe OT defaults)")
        print_table(["Option", "Current", "Description"],
                    target_rows, title="Global: Targeting")

        print_info("")
        print_info("  Usage:  setg TARGET 10.0.0.1    setg PORT 502,510    setg TRANSPORT tcp")
        print_info("          setg UNIT_ID 1          setg TIMING T2       setg THREADS 3")
        print_info("          unsetg PORT             unsetg TRANSPORT")
        print_info("  Help:   help port   help transport   help timing   help probe_level")

    def _help_safemode(self) -> None:
        safemode_current = self._get_global("safemode")
        print_info(f"""
Option: SAFEMODE  (global only -- setg)
----------------------------------------
Type    : bool (true/false)
Default : false
Current : {safemode_current}

SAFEMODE is a legacy global flag. It no longer overrides per-module
SIMULATE or DESTRUCTIVE options. Execution follows what you set on
each module:

  set SIMULATE true|false
  set DESTRUCTIVE true|false
  run

Use simulate=true when you want dry-run behavior on a specific module.
Use destructive=true when the module supports writes and you intend
to execute them.
""")

    def _help_simulate(self) -> None:
        print_info("""
Option: SIMULATE  (per-module)
-------------------------------
Type    : bool (true/false)
Default : false

  simulate=false  (default)
    - Module runs real protocol logic (reads/writes per module design).
    - Combine with DESTRUCTIVE for write-capable modules.

  simulate=true
    - Dry-run: module shows what it would do without sending payloads
      (when the module implements simulate handling).

Usage:
  set SIMULATE true           -- enable dry-run on this module
  set SIMULATE false          -- real execution (default)
  set DESTRUCTIVE true        -- enable write/destructive paths (module-dependent)
  help destructive            -- write/destructive option reference
""")

    def _help_loglevel(self) -> None:
        print_info("""
loglevel / verbose -- Output Verbosity
-------------------------------------
  Levels (setg loglevel <level>):
    debug     -- all internal messages, raw packets, socket events
    info      -- standard output (default)
    warning   -- only warnings and errors
    error     -- only fatal errors

  Shorthand:
    setg verbose true    -- equivalent to setg loglevel debug
    setg verbose false   -- equivalent to setg loglevel info

Usage:
  setg loglevel debug
  setg verbose true
""")

    def _help_search(self) -> None:
        print_info("""
search -- Module Discovery
-------------------------
  search <keyword>           -- keyword in module path or name
  search sector=<name>       -- all modules for an industry sector
  search type=<category>     -- filter by type: scanner, exploit, cve, assessment, creds
  search cve_2022            -- find modules for a CVE year
  search <vendor>            -- e.g. search siemens, search schneider, search abb

Sector examples:
  search sector=energy       search sector=oilgas     search sector=water
  search sector=manufacturing  search sector=building  search sector=maritime

Type examples:
  search type=scanner        search type=exploit      search type=assessment

Tip: 'modules' or 'modules <category>' browses the full tree.
""")

    # -- Per-option help -------------------------------------------------------

    # Map of option name -> help function
    _OPTION_HELP_MAP: dict = {}  # populated lazily below

    def _get_option_help_map(self) -> dict:
        return {
            "timing":      self._help_option_timing,
            "scan_timing": self._help_option_timing,
            "registers":   self._help_option_registers,
            "register":    self._help_option_registers,
            "coils":       self._help_option_coils,
            "coil":        self._help_option_coils,
            "port":        self._help_option_port,
            "ports":       self._help_option_port,
            "transport":   self._help_option_transport,
            "fc":          self._help_option_fc,
            "unit_id":     self._help_option_unit_id,
            "unitid":      self._help_option_unit_id,
            "timeout":     self._help_option_timeout,
            "target":      self._help_option_target,
            "safemode":    self._help_safemode,
            "simulate":    self._help_simulate,
            "destructive": self._help_option_destructive,
            "loglevel":    self._help_loglevel,
            "verbose":     self._help_loglevel,
            "threads":      self._help_option_threads,
            "host_timeout": self._help_option_host_timeout,
            "max_retries":  self._help_option_retries,
            "min_retries":  self._help_option_retries,
            "scan_delay":   self._help_option_scan_delay,
            "max_rate":     self._help_option_max_rate,
            "probe_level":  self._help_option_probe_level,
            "ping_first":   self._help_option_ping,
            "skip_ping":    self._help_option_ping,
            "output":       self._help_option_output,
            "report_fmt":   self._help_option_report_fmt,
        }

