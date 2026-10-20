    def _help_option_probe_level(self) -> None:
        print_info("""
Option: PROBE_LEVEL  (global only -- setg)
-----------------------------------------
Type     : integer 1-5
Default  : 2
Nmap eq. : --version-intensity 0-9 (mapped to 1-5 here)

Controls how deeply modules probe for service/version information.
Higher levels send more packets but extract richer fingerprints.

  1   Minimal   -- TCP banner only, no active FC probes
  2   Light     -- FC43/MEI + FC17, no coil/register reads   [default]
  3   Standard  -- FC43/MEI + FC17 + FC1/FC3 register reads
  4   Deep      -- All FCs, full object ID enumeration, unit_id sweep
  5   Exhaustive-- All of level 4 + brute-force FC codes, full MEI tree

OT guidance: keep at 1-2 for production environments.
Level 3+ may cause unexpected behavior on older PLCs.

Examples:
  setg PROBE_LEVEL 2         -- default (safe for OT)
  setg PROBE_LEVEL 1         -- read-banner-only (safest)
  setg PROBE_LEVEL 4         -- deep assessment (lab/authorized only)
""")

    def _help_option_ping(self) -> None:
        print_info("""
Options: PING_FIRST / SKIP_PING  (global only -- setg)
----------------------------------------------------
Type     : bool (true/false)
Defaults : PING_FIRST=true, SKIP_PING=false
Nmap eq. : -Pn (skip ping) | default (ping first)

PING_FIRST=true (default):
  IXF performs a lightweight TCP connection check on the target port
  before running any module. If the host doesn't respond, it is skipped.
  This avoids wasting time and sending probes to dead hosts.

SKIP_PING=true (like nmap -Pn):
  Skips the alive check and scans regardless. Use when:
  - The host filters ICMP/TCP but still runs Modbus
  - You are certain the host is up
  - Scanning through a NAT or jump host

Note: PING_FIRST and SKIP_PING are opposites. Setting SKIP_PING=true
overrides PING_FIRST regardless of its value.

Examples:
  setg PING_FIRST true       -- default (safer, avoids dead hosts)
  setg SKIP_PING true        -- scan even if host appears down
  setg PING_FIRST false      -- alias for skip_ping=true
""")

    def _help_option_output(self) -> None:
        print_info("""
Option: output (global)
-----------------------
Type     : file path string
Default  : (empty -- no file output)
Scope    : global (setg)

Save all module output to a file in addition to the terminal.
Format determined by 'report_fmt' option.

Examples:
  setg output /tmp/scan_results.txt
  setg output ./reports/modbus_scan.json
  unsetg output              -- disable file output
""")

    def _help_option_report_fmt(self) -> None:
        print_info("""
Option: report_fmt (global)
---------------------------
Type     : string
Default  : markdown
Scope    : global (setg)

Accepted values:
  markdown  -- human-readable Markdown report
  json      -- machine-readable JSON
  html      -- HTML report with styling
  csv       -- comma-separated values (for tabular results)

Examples:
  setg report_fmt json       -- JSON output
  setg report_fmt markdown   -- default Markdown
  report json                -- generate report in JSON format immediately
""")

    def _help_timing(self) -> None:
        self._help_option_timing()

    def _help_mitre(self) -> None:
        print_info("""
MITRE ATT&CK for ICS -- Commands
--------------------------------
  mitre <TID>                        -- load module(s) for technique T0843
  mitre-list [tactic]                -- list all ICS techniques
  mitre-scan <tactic|TID> <target>   -- run all modules for a tactic/technique
  mitre-coverage                     -- show coverage % per tactic
  use assessment/mitre_ics/full_mitre_sweep   -- run all 12 tactics against target

Tactics: initial_access, execution, persistence, privilege_escalation,
         evasion, discovery, lateral_movement, collection,
         command_and_control, inhibit_response, impair_process_control, impact

Example:
  ixf > mitre-scan discovery 192.168.1.100
  ixf > use assessment/mitre_ics/full_mitre_sweep
  ixf > set target 10.0.0.1
  ixf > set simulate false
  ixf > run
""")

    # Aliases for common typos / shortcuts
    def command_info(self, args: str = "", **kwargs) -> None:
        term = args.strip()
        if term:
            self.command_help(term)
            return
        if self.current_module:
            self.command_show("info")
        else:
            print_error("No module loaded. Use 'use <module_path>' first.")

    def command_options(self, args: str = "", **kwargs) -> None:
        if self.current_module:
            self.command_show("options")
        else:
            self._help_global()

    def command_global(self, args: str = "", **kwargs) -> None:
        """Show or manage global options (alias: show global)."""
        sub = args.strip().lower()
        if sub in ("", "show", "list"):
            self._help_global()
        else:
            # Treat as 'setg' shorthand: global loglevel debug
            parts = sub.split(None, 1)
            if len(parts) == 2:
                self.command_setg(f"{parts[0]} {parts[1]}")
            else:
                self._help_global()

    def command_update(self, args: str = "", **kwargs) -> None:
        """Check for IXF updates and optionally upgrade."""
        import json as _json
        import urllib.request

        current = VERSION
        print_status("Checking for updates…")
        print_info(f"  Installed version : {current}")

        # Fetch latest version from PyPI
        try:
            url = "https://pypi.org/pypi/industrialxpl/json"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": f"IXF/{current} update-check"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = _json.loads(resp.read().decode())
            latest = data["info"]["version"]
            release_url = data["info"]["project_urls"].get(
                "Changelog", "https://github.com/mrhenrike/IndustrialXPL-Forge/releases"
            )
        except Exception as exc:
            print_error(f"Could not reach PyPI: {exc}")
            print_info("  Manual check: https://pypi.org/project/industrialxpl/")
            return

        print_info(f"  Latest version    : {latest}")

        # Compare versions using tuple comparison
        def _v(s: str):
            try:
                return tuple(int(x) for x in s.split("."))
            except ValueError:
                return (0,)

        current_t = _v(current)
        latest_t  = _v(latest)

        if current_t >= latest_t:
            print_success(f"IXF is up to date (v{current}).")
            return

        # Update available
        print_warning(f"New version available: v{current} -> v{latest}")
        print_info(f"  Release notes: {release_url}")

        # Module count diff is not easily queryable from PyPI, skip for now
        print_info("")
        print_info("  What will be upgraded:")
        print_info("    - IndustrialXPL-Forge core CLI and interpreter")
        print_info("    - Module library (new CVEs, protocols, MITRE mappings)")
        print_info("    - Documentation and help system")
        print_info("")

        # Ask user
        try:
            answer = input("  Proceed with upgrade? [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            print_info("Upgrade cancelled.")
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

