"""IndustrialXPL-Forge interactive shell interpreter.

Shell hierarchy:
    BaseInterpreter   — readline loop, command dispatch, history
    IXFInterpreter    — ICS/OT-specific commands + module loading

Prompt: "ixf >" (global) / "ixf (Module Name) >" (module loaded)
"""

import os
import shlex

try:
    import readline  # Unix/Mac readline support
    _HAS_READLINE = True
except ModuleNotFoundError:
    try:
        import pyreadline3 as readline  # type: ignore[no-redef]
        _HAS_READLINE = True
    except ModuleNotFoundError:
        readline = None  # type: ignore[assignment]
        _HAS_READLINE = False
import subprocess
import sys
from pathlib import Path
from typing import Optional

from industrialxpl.core.exploit.exceptions import IXFException
from industrialxpl.core.exploit.printer import (
    print_error, print_info, print_status, print_success, print_table, print_warning,
    pprint_dict_in_order, printer_queue, set_log_level, get_log_level,
)
from industrialxpl.core.exploit.safety import DestructiveGate, IMPACT_LEVELS
from industrialxpl.core.exploit.utils import (
    index_modules, import_exploit, pythonize_path, humanize_path,
    module_required, MODULES_DIR,
)

VERSION = "1.0.18"

_BANNER = r"""
 ___           _           _        _       ___  ______  _          _____
|_ _|_ __   __| |_   _ ___| |_ _ __(_) __ _| \ \/ /  _ \| |        |  ___|__  _ __ __ _  ___
 | || '_ \ / _` | | | / __| __| '__| |/ _` | |\  /| |_) | |   _____| |_ / _ \| '__/ _` |/ _ \
 | || | | | (_| | |_| \__ \ |_| |  | | (_| | |/  \|  __/| |__|_____|  _| (_) | | | (_| |  __/
|___|_| |_|\__,_|\__,_|___/\__|_|  |_|\__,_|_/_/\_\_|   |_____|    |_|  \___/|_|  \__, |\___|
                                                                                     |___/
  IndustrialXPL-Forge v{version} — OT/ICS/SCADA Security Assessment Framework
  Author: Andre Henrique (@mrhenrike) | Uniao Geek | https://uniaogeek.com.br/
  Python-First. Pure Python — pip install industrialxpl
  Type 'help' for commands.  simulate=True by default (safe mode).
""".format(version=VERSION)

_GLOBAL_HELP = """
IndustrialXPL-Forge (IXF) v{version}

NAVIGATION:
  help                          This menu
  help <term|module>            Contextual help: help sector / help modbus / help simulate
  help sector                   List all industry sectors (search sector=...)
  help type                     List all module types (search type=...)
  help global                   List global options and current values
  use <module>                  Load a module  (e.g. use scanners/ics/modbus_detect)
  back                          Deselect current module
  update                        Check for updates and optionally upgrade
  upgrade                       Alias for update
  exit                          Exit IXF

DISCOVERY:
  search <keyword>              Search by keyword, vendor, CVE, protocol
  search type=<category>        Filter: scanner | exploit | cve | assessment | creds
  search sector=<name>          Industry filter: energy | oilgas | water | manufacturing ...
  modules                       Browse categories with module counts
  modules <category>            Drill-down: modules scanners / modules assessment / modules cve
  show sectors                  List sectors (alias: help sector)
  show types                    List module types (alias: help type)

MODULE COMMANDS (after 'use'):
  run                           Execute current module
  check                         Read-only fingerprint check
  set <option> <value>          Set module option (case-insensitive)
  show info                     Module details, CVE, CVSS, MITRE
  show options                  Current option values
  info                          Alias: show info
  options                       Alias: show options

GLOBAL OPTIONS:
  setg <option> <value>         Set for all modules (persists until unsetg)
  unsetg <option>               Clear a global option
  show global                   Show all global options and current values
  global                        Alias: show global

  setg loglevel debug           debug | info | warning | error
  setg verbose true             Alias for loglevel=debug
  setg threads 20               Parallel threads (default 10)
  setg timeout 10               Socket timeout in seconds (default 5)
  setg target 10.0.0.1          Default target for all modules

SIMULATE vs DESTRUCTIVE:
  simulate=true   (DEFAULT)     Print planned actions only — no packets sent
  simulate=false                Execute reads/scans — safe for INFO/assessment modules
  destructive=true              Enable exploits/writes — requires typed confirmation
  help simulate                 Full explanation of modes

CVE / MITRE / TTP:
  cve <CVE-ID>                  Load module for a CVE (e.g. cve CVE-2022-29953)
  mitre <TID>                   Modules covering technique (e.g. mitre T0843)
  mitre-list [tactic]           List all 79 ICS techniques
  mitre-scan <tactic> <target>  Run all modules for a tactic
  ttp <TID> <target>            Execute all modules for a TTP-ID
  help mitre                    Full MITRE command reference

EXAMPLES:
  ixf > search sector=energy
  ixf > search type=scanner
  ixf > modules assessment
  ixf > setg loglevel debug
  ixf > setg threads 20
  ixf > use scanners/ics/modbus_detect
  ixf > set TARGET 192.168.1.100
  ixf > set simulate false
  ixf > run
  ixf > help zone_conduit_audit
  ixf > help modbus
""".format(version=VERSION)

_MODULE_HELP = """
MODULE COMMANDS:
  run                                 Execute the current module
  back                                Deselect the current module
  set <option> <value>                Set a module option
  setg <option> <value>               Set a global option
  unsetg <option>                     Clear a global option
  show [info|options|advanced|devices] Print module details
  check                               Fingerprint / vulnerability check (read-only)
"""


class BaseInterpreter:
    """Readline-based interactive shell loop."""

    history_file: str = os.path.expanduser("~/.ixf_history")
    raw_prompt_template: str    = "\033[1;36m{host}\033[0m > "
    module_prompt_template: str = "\033[1;36m{host}\033[0m (\033[1;33m{module}\033[0m) > "

    def __init__(self) -> None:
        self.current_module: Optional[object] = None
        self._global_opts: dict = {}
        self._setup_readline()

    def _setup_readline(self) -> None:
        if not _HAS_READLINE or readline is None:
            return
        try:
            readline.read_history_file(self.history_file)
        except (FileNotFoundError, OSError):
            pass
        try:
            readline.set_history_length(1000)
            readline.parse_and_bind("tab: complete")
        except Exception:
            pass

    @property
    def prompt(self) -> str:
        if self.current_module:
            name = self.current_module.get_info().get("name", str(self.current_module))
            return self.module_prompt_template.format(
                host="ixf", module=name[:40]
            )
        return self.raw_prompt_template.format(host="ixf")

    def parse_line(self, line: str) -> tuple:
        line = line.strip()
        if not line:
            return "", "", {}
        command, _, args = line.partition(" ")
        return command.lower().replace("-", "_"), args.strip(), {}

    def get_command_handler(self, command: str):
        handler = getattr(self, "command_{}".format(command), None)
        if handler is None:
            raise IXFException("Unknown command: '{}'".format(command))
        return handler

    def start(self) -> None:
        print(_BANNER)
        printer_q_thread = None
        try:
            while True:
                try:
                    raw = input(self.prompt)
                except (EOFError, KeyboardInterrupt):
                    print()
                    break

                if not raw.strip():
                    continue

                if _HAS_READLINE and readline is not None:
                    try:
                        readline.write_history_file(self.history_file)
                    except OSError:
                        pass

                command, args, kwargs = self.parse_line(raw)
                if not command:
                    continue

                try:
                    handler = self.get_command_handler(command)
                    handler(args, **kwargs)
                except IXFException as exc:
                    print_error(str(exc))
                except Exception as exc:
                    print_error("Unexpected error: {}".format(exc))
        finally:
            if _HAS_READLINE and readline is not None:
                try:
                    readline.write_history_file(self.history_file)
                except OSError:
                    pass

    def nonInteractive(self, argv: list) -> None:
        """Execute a single command from command-line arguments."""
        if len(argv) < 2:
            return
        cmd = argv[1].lower().replace("-", "_")
        args = " ".join(argv[2:])
        try:
            handler = self.get_command_handler(cmd)
            handler(args)
        except IXFException as exc:
            print_error(str(exc))
            sys.exit(1)


class IXFInterpreter(BaseInterpreter):
    """IXF-specific interpreter with all OT/ICS commands."""

    history_file = os.path.expanduser("~/.ixf_history")

    def __init__(self) -> None:
        super().__init__()
        print_status("Indexing modules…")
        self.modules: list = index_modules()
        print_success("{} modules indexed.".format(len(self.modules)))

    # ── Global commands ────────────────────────────────────────────────────

    # Known terms that have dedicated help pages
    _HELP_TOPICS = {
        "sector", "sectors", "type", "types", "global", "globals",
        "simulate", "destructive", "loglevel", "verbose", "threads",
        "search", "modules", "mitre", "ttp", "cve", "assess", "assessment",
    }

    def command_help(self, args: str = "", **kwargs) -> None:
        term = args.strip().lower()

        # help <term> — topic-based help
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
            if term in ("simulate", "simulation"):
                self._help_simulate()
                return
            if term in ("loglevel", "verbose", "verbosity"):
                self._help_loglevel()
                return
            if term in ("search",):
                self._help_search()
                return
            if term in ("mitre", "ttp"):
                self._help_mitre()
                return
            # Try to load the module and print its options
            module_path = pythonize_path(term)
            full_path = "industrialxpl.modules.{}".format(module_path)
            try:
                cls = import_exploit(full_path)
                tmp = cls()
                info = tmp.get_info()
                pprint_dict_in_order(info, header="Module Information — {}".format(info.get("name", term)))
                rows = [
                    (k, str(v[0]), "yes" if not v[2] else "adv", v[1])
                    for k, v in tmp.exploit_attributes.items()
                    if not v[2]
                ]
                print_table(
                    ["Option", "Default", "Required", "Description"],
                    rows,
                    title="Options — {}".format(info.get("name", term)),
                )
                return
            except Exception:
                pass
            # Search for modules matching the term and show a mini help
            results = [m for m in self.modules if term in m.lower()]
            if results:
                print_success("{} module(s) match '{}':".format(len(results), term))
                for m in results[:20]:
                    print_info("  use {}".format(humanize_path(m)))
                if len(results) > 20:
                    print_info("  … and {} more. Use: search {}".format(len(results) - 20, term))
                print_info("\nTip: 'help <full/module/path>' shows that module's options.")
                return
            print_info("No help topic or module found for '{}'. Known topics:".format(term))
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
            title="Sectors — search sector=<name>",
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
            rows.append((cat, str(count), "search type={}".format(cat)))
        print_table(["Type", "Modules", "Usage"], rows, title="Module Types")
        print_info("\nUsage:  search type=scanner")
        print_info("        search type=exploit")
        print_info("        search type=assessment\n")

    def _help_global(self) -> None:
        rows = [
            ("loglevel",     str(self._global_opts.get("loglevel", "info")),
             "debug | info | warning | error   — verbosity of IXF output"),
            ("verbose",      str(self._global_opts.get("verbose", "false")),
             "true | false                      — alias for loglevel=debug"),
            ("threads",      str(self._global_opts.get("threads", "10")),
             "integer >= 1                      — parallel threads for multi-host ops"),
            ("timeout",      str(self._global_opts.get("timeout", "5")),
             "integer seconds                   — socket timeout for all modules"),
            ("target",       str(self._global_opts.get("target", "")),
             "IP / hostname / CIDR              — default target for all modules"),
            ("port",         str(self._global_opts.get("port", "")),
             "integer 1-65535                   — override default port"),
            ("output",       str(self._global_opts.get("output", "")),
             "filepath                          — save output to file"),
            ("report_fmt",   str(self._global_opts.get("report_fmt", "markdown")),
             "json | html | markdown            — report format for 'report' cmd"),
        ]
        print_table(
            ["Option", "Current", "Description"],
            rows,
            title="Global Options (setg / unsetg)",
        )
        print_info("\nUsage:  setg loglevel debug")
        print_info("        setg threads 20")
        print_info("        setg target 192.168.1.0/24")
        print_info("        unsetg target\n")
        print_info("Global options are applied to every module loaded after 'setg'.")

    def _help_simulate(self) -> None:
        print_info("""
simulate — Safe Execution Mode
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  simulate=true  (DEFAULT)
    - No packets are sent to the target.
    - The module prints what it WOULD do: payloads, expected responses,
      MITRE technique, CVE, CVSS, and rationale for the vulnerability.
    - 100% safe for any environment.

  simulate=false
    - Sends real probes / reads against the target.
    - For INFO/READ modules (scanners, assessments): runs immediately.
    - For LOW/MEDIUM risk modules: runs after brief warning.
    - For HIGH/CRITICAL/CATASTROPHIC modules: requires destructive=true
      AND typed confirmation with the target hostname.

  destructive=true
    - Enables write, exploit, DoS, or configuration-change operations.
    - Always prompts for explicit typed confirmation before execution.
    - Audit log written to .log/destructive_ops_YYYY-MM-DD.log

Usage:
  set simulate false          — probe target (safe reads)
  set simulate false          — then set destructive true for exploits
  setg simulate false         — apply to all subsequent modules
""")

    def _help_loglevel(self) -> None:
        print_info("""
loglevel / verbose — Output Verbosity
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Levels (setg loglevel <level>):
    debug     — all internal messages, raw packets, socket events
    info      — standard output (default)
    warning   — only warnings and errors
    error     — only fatal errors

  Shorthand:
    setg verbose true    — equivalent to setg loglevel debug
    setg verbose false   — equivalent to setg loglevel info

Usage:
  setg loglevel debug
  setg verbose true
""")

    def _help_search(self) -> None:
        print_info("""
search — Module Discovery
━━━━━━━━━━━━━━━━━━━━━━━━━
  search <keyword>           — keyword in module path or name
  search sector=<name>       — all modules for an industry sector
  search type=<category>     — filter by type: scanner, exploit, cve, assessment, creds
  search cve_2022            — find modules for a CVE year
  search <vendor>            — e.g. search siemens, search schneider, search abb

Sector examples:
  search sector=energy       search sector=oilgas     search sector=water
  search sector=manufacturing  search sector=building  search sector=maritime

Type examples:
  search type=scanner        search type=exploit      search type=assessment

Tip: 'modules' or 'modules <category>' browses the full tree.
""")

    def _help_mitre(self) -> None:
        print_info("""
MITRE ATT&CK for ICS — Commands
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  mitre <TID>                        — load module(s) for technique T0843
  mitre-list [tactic]                — list all ICS techniques
  mitre-scan <tactic|TID> <target>   — run all modules for a tactic/technique
  mitre-coverage                     — show coverage % per tactic
  use assessment/mitre_ics/full_mitre_sweep   — run all 12 tactics against target

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
                self.command_setg("{} {}".format(parts[0], parts[1]))
            else:
                self._help_global()

    def command_update(self, args: str = "", **kwargs) -> None:
        """Check for IXF updates and optionally upgrade."""
        import importlib.metadata
        import urllib.request
        import json as _json

        current = VERSION
        print_status("Checking for updates…")
        print_info("  Installed version : {}".format(current))

        # Fetch latest version from PyPI
        try:
            url = "https://pypi.org/pypi/industrialxpl/json"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "IXF/{} update-check".format(current)},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = _json.loads(resp.read().decode())
            latest = data["info"]["version"]
            release_url = data["info"]["project_urls"].get(
                "Changelog", "https://github.com/mrhenrike/IndustrialXPL-Forge/releases"
            )
        except Exception as exc:
            print_error("Could not reach PyPI: {}".format(exc))
            print_info("  Manual check: https://pypi.org/project/industrialxpl/")
            return

        print_info("  Latest version    : {}".format(latest))

        # Compare versions using tuple comparison
        def _v(s: str):
            try:
                return tuple(int(x) for x in s.split("."))
            except ValueError:
                return (0,)

        current_t = _v(current)
        latest_t  = _v(latest)

        if current_t >= latest_t:
            print_success("IXF is up to date (v{}).".format(current))
            return

        # Update available
        print_warning("New version available: v{} -> v{}".format(current, latest))
        print_info("  Release notes: {}".format(release_url))

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
                    print_success("Upgrade complete. Restart IXF to use v{}.".format(latest))
                else:
                    print_error("pip exited with code {}. Check the output above.".format(result.returncode))
            except Exception as exc:
                print_error("Upgrade failed: {}".format(exc))
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
        full_path = "industrialxpl.modules.{}".format(module_path)
        try:
            cls = import_exploit(full_path)
            self.current_module = cls()
            # Apply any global options
            for key, val in self._global_opts.items():
                if key in self.current_module.options:
                    try:
                        setattr(self.current_module, key, val)
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
                        "[opt] Runtime '{}' not found — Python fallback will be used.".format(poly_lang)
                    )
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
            print_error("Usage: set <option> <value>")
            return
        key_raw, value = parts[0], parts[1]
        # Case-insensitive option matching
        key = key_raw.lower()
        if key not in self.current_module.options:
            print_error("Unknown option: '{}'".format(key_raw))
            return
        try:
            setattr(self.current_module, key, value)
            self.current_module.exploit_attributes[key][0] = value
            print_success("{} => {}".format(key, value))
        except Exception as exc:
            print_error("Cannot set '{}': {}".format(key, exc))

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
            print_success("[global] loglevel => {}".format(value))
            return
        if key == "verbose":
            set_log_level("debug" if value.lower() in ("true", "1", "on", "yes") else "info")
            self._global_opts["loglevel"] = get_log_level()
            print_success("[global] verbose => {}  (loglevel={})".format(value, get_log_level()))
            return
        if key == "threads":
            try:
                t = int(value)
                if t < 1:
                    raise ValueError
                self._global_opts["threads"] = str(t)
            except ValueError:
                print_error("threads must be a positive integer, got: {}".format(value))
                return

        if self.current_module and key in self.current_module.options:
            try:
                setattr(self.current_module, key, value)
            except Exception:
                pass
        print_success("[global] {} => {}".format(key, value))

    def command_unsetg(self, args: str, **kwargs) -> None:
        key = args.strip()
        if key in self._global_opts:
            del self._global_opts[key]
            print_success("[global] {} cleared.".format(key))
        else:
            print_warning("'{}' was not set globally.".format(key))

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

        if not self.current_module:
            if sub in ("modules", "all", "options", ""):
                print_status("{} modules indexed. Use 'search <keyword>' to find modules.".format(len(self.modules)))
                print_info("  search modbus       — keyword search")
                print_info("  search sector=energy — sector filter")
                print_info("  search type=scanner — type filter")
                print_info("  modules             — browse categories")
                print_info("  show global         — global options")
                print_info("  show sectors        — available sectors")
                print_info("  show types          — module categories")
            else:
                print_error("No module loaded. Use 'use <module_path>' first.")
            return
        mod = self.current_module
        info = mod.get_info()

        if sub == "info":
            pprint_dict_in_order(info, header="Module Information")
        elif sub in ("options", "advanced"):
            rows = [
                (k, str(v[0]), "yes" if not v[2] else "adv", v[1])
                for k, v in mod.exploit_attributes.items()
                if sub == "advanced" or not v[2]
            ]
            print_table(["Option", "Value", "Required", "Description"], rows,
                        title="Options — {}".format(info.get("name", str(mod))))
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
        mod = self.current_module
        info = mod.get_info()
        impact = info.get("impact", "LOW")

        # Simulate mode (default)
        if mod.simulate:
            mod._simulate_mode = True
            print_status("Running {} in SIMULATE mode…".format(info.get("name", str(mod))))
            try:
                mod.run()
            except NotImplementedError:
                print_warning("Module run() not yet implemented.")
            return

        # Destructive mode — gate check
        if not mod.simulate and mod.destructive:
            if impact in ("HIGH", "CRITICAL", "CATASTROPHIC"):
                target = str(getattr(mod, "target", "unknown"))
                description = info.get(
                    "destructive_description",
                    "This operation may cause irreversible damage to the target system.",
                )
                confirmed = DestructiveGate.require_confirmation(
                    module_name=info.get("name", str(mod)),
                    target=target,
                    impact_level=impact,
                    description=description,
                )
                if not confirmed:
                    return
            mod._simulate_mode = False
            print_status("Running {} [DESTRUCTIVE MODE]…".format(info.get("name", str(mod))))
            try:
                mod.run()
            except NotImplementedError:
                print_warning("Module run() not yet implemented.")
            return

        # simulate=false + destructive=false → run for INFO/assessment modules, check() for risky ones
        impact = info.get("impact", "LOW").upper()
        if impact in ("INFO", "READ"):
            # Assessment/read-only modules: run directly without destructive gate
            mod._simulate_mode = False
            print_status("Running {}…".format(info.get("name", str(mod))))
            try:
                mod.run()
            except NotImplementedError:
                print_warning("Module run() not yet implemented.")
            return
        print_warning("simulate=false but destructive=false — running check() only.")
        self.command_check(args, **kwargs)

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
                print_success("VULNERABLE — {}".format(info.get("name", "")))
            else:
                print_info("NOT_VULNERABLE — {}".format(info.get("name", "")))
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
    }

    def command_search(self, args: str, **kwargs) -> None:
        term = args.strip().lower()
        if not term:
            print_error("Usage: search <keyword>")
            print_info("  search modbus          — keyword search")
            print_info("  search sector=energy   — modules for energy sector")
            print_info("  search type=scanner    — filter by category (scanner/exploit/cve/assessment/creds)")
            return

        # Sector filter: search sector=energy
        if term.startswith("sector="):
            sector = term[7:].strip()
            aliases = self._SECTOR_ALIASES.get(sector, [sector])
            results = set()
            for alias in aliases:
                for m in self.modules:
                    if alias in m.lower():
                        results.add(m)
            results = sorted(results)
            if not results:
                known = ", ".join(sorted(self._SECTOR_ALIASES.keys()))
                print_info("No modules for sector '{}'. Known sectors: {}".format(sector, known))
                return
            print_success("{} module(s) for sector '{}':".format(len(results), sector))
            for m in results[:50]:
                print_info("  use {}".format(humanize_path(m)))
            if len(results) > 50:
                print_info("  … and {} more. Refine your search.".format(len(results) - 50))
            return

        # Type/category filter: search type=scanner
        if term.startswith("type="):
            category = term[5:].strip()
            _CAT_MAP = {
                "scanner": "scanners/",
                "scanners": "scanners/",
                "exploit": "exploits/",
                "exploits": "exploits/",
                "cve": "cve/",
                "assessment": "assessment/",
                "creds": "creds/",
                "credentials": "creds/",
            }
            prefix = _CAT_MAP.get(category, category + "/")
            results = [m for m in self.modules if prefix in m.lower()]
            if not results:
                known = ", ".join(sorted(_CAT_MAP.keys()))
                print_info("No modules for type '{}'. Known types: {}".format(category, known))
                return
            print_success("{} module(s) of type '{}':".format(len(results), category))
            for m in results[:50]:
                print_info("  use {}".format(humanize_path(m)))
            if len(results) > 50:
                print_info("  … and {} more. Refine your search.".format(len(results) - 50))
            return

        # Standard keyword search
        results = [m for m in self.modules if term in m.lower()]
        if not results:
            # Suggest sector search if term looks like an industry
            if term in self._SECTOR_ALIASES:
                print_info("No modules matched keyword '{}'. Try: search sector={}".format(term, term))
            else:
                print_info("No modules found for '{}'.".format(term))
            return
        print_success("{} module(s) found:".format(len(results)))
        for m in results[:50]:
            print_info("  use {}".format(humanize_path(m)))
        if len(results) > 50:
            print_info("  … and {} more. Refine your search.".format(len(results) - 50))

    def command_modules(self, args: str = "", **kwargs) -> None:
        """Drill-down module browser by top-level category."""
        sub = args.strip().lower()
        from collections import defaultdict
        tree: dict = defaultdict(lambda: defaultdict(list))
        for m in self.modules:
            parts = m.split(".")
            # parts example: industrialxpl.modules.scanners.ics.modbus_scan
            if len(parts) >= 5:
                cat = parts[3]      # e.g. scanners
                subcat = parts[4]   # e.g. ics
                tree[cat][subcat].append(parts[-1])
            elif len(parts) >= 4:
                cat = parts[3]
                tree[cat][""].append(parts[-1])

        if not sub:
            print_success("Top-level categories ({} total):".format(len(tree)))
            for cat in sorted(tree.keys()):
                subcats = sorted(tree[cat].keys())
                total = sum(len(v) for v in tree[cat].values())
                print_info("  {:20s} {:4d} modules  subcats: {}".format(
                    cat, total, ", ".join(s for s in subcats if s)))
            print_info("\nDrill down: modules <category>  (e.g. modules scanners)")
            return

        if sub not in tree:
            print_error("Category '{}' not found. Run 'modules' to see categories.".format(sub))
            return

        print_success("Category: {} ({} subcategories)".format(sub, len(tree[sub])))
        for subcat in sorted(tree[sub].keys()):
            mods = tree[sub][subcat]
            label = "{}/{}".format(sub, subcat) if subcat else sub
            print_info("  [{:3d}] {}".format(len(mods), label))
            for modname in sorted(mods)[:8]:
                path = "{}/{}/{}".format(sub, subcat, modname).replace("//" , "/")
                print_info("          use {}".format(path))
            if len(mods) > 8:
                print_info("          … and {} more — search {} to list all".format(len(mods) - 8, subcat))

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
        print_status("Discovering OT/ICS assets on {}…".format(cidr))
        self.command_use("scanners/ics/modbus_detect")
        if self.current_module:
            print_warning("Set target to each host in {} and run check().".format(cidr))
            print_info("For automated CIDR sweep: ixf > ttp T0846.001 {}".format(cidr))

    # ── CVE commands ──────────────────────────────────────────────────────

    def command_cve(self, args: str, **kwargs) -> None:
        cve_id = args.strip().upper()
        if not cve_id.startswith("CVE-") and not cve_id.startswith("CNVD-"):
            print_error("Usage: cve <CVE-ID>  (e.g. cve CVE-2022-29953)")
            return
        # Search for a module matching this CVE
        matches = [
            m for m in self.modules
            if cve_id.lower().replace("-", "_") in m.lower()
        ]
        if not matches:
            print_error("No IXF module found for {}. Check resources/cve/ics_cve_database.json".format(cve_id))
            return
        if len(matches) == 1:
            self.command_use(humanize_path(matches[0]))
        else:
            print_success("{} module(s) for {}:".format(len(matches), cve_id))
            for m in matches:
                print_info("  use {}".format(humanize_path(m)))

    def command_cve_scan(self, args: str, **kwargs) -> None:
        cidr = args.strip()
        if not cidr:
            print_error("Usage: cve-scan <CIDR>")
            return
        print_status("[cve-scan] Discovery + CVE testing on {}…".format(cidr))
        print_info("Feature: auto-fingerprint each host then run applicable CVE modules.")
        print_info("Use mitre-scan discovery {} to start with passive scanning.".format(cidr))

    def command_report(self, args: str, **kwargs) -> None:
        fmt = args.strip().lower() or "json"
        from industrialxpl.core.reporting.reporter import IXFReporter
        reporter = IXFReporter()
        output = reporter.generate(fmt)
        print_success("Report generated: {}".format(output))

    # ── MITRE commands ─────────────────────────────────────────────────────

    def command_mitre(self, args: str, **kwargs) -> None:
        tid = args.strip().upper()
        if not tid:
            print_error("Usage: mitre <TID>  (e.g. mitre T0843)")
            return
        from industrialxpl.core.mitre.index import TECHNIQUE_INDEX, build_index
        build_index(self.modules)
        mods = TECHNIQUE_INDEX.get(tid, [])
        if not mods:
            print_error("No modules for {}. Try 'mitre-list' to see all.".format(tid))
            return
        print_success("{} module(s) cover {}:".format(len(mods), tid))
        for m in mods:
            print_info("  use {}".format(humanize_path(m)))

    def command_mitre_list(self, args: str, **kwargs) -> None:
        from industrialxpl.core.mitre.index import TECHNIQUE_INDEX, TACTIC_INDEX, build_index
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
            " — {}".format(tactic_filter) if tactic_filter else ""
        )
        print_table(["TID", "# Modules", "Primary Module"], rows, title=title)

    def command_mitre_scan(self, args: str, **kwargs) -> None:
        parts = args.strip().split()
        if len(parts) < 2:
            print_error("Usage: mitre-scan <tactic|TID> <target/CIDR> [--destructive]")
            return
        tactic_or_tid, target = parts[0], parts[1]
        destructive = "--destructive" in parts
        simulate = not destructive
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
        print_status("[mitre-all] Full MITRE ICS sweep on {} (simulate=True)".format(target))
        MitreTacticSweeper(target=target, simulate=True).sweep_all()

    def command_mitre_coverage(self, args: str, **kwargs) -> None:
        from industrialxpl.core.mitre.index import build_index, TACTIC_INDEX, TECHNIQUE_INDEX
        from industrialxpl.core.mitre.tactics import TACTICS, TACTIC_TIDS
        build_index(self.modules)
        rows = []
        total_cov = total_tids = 0
        for tid_id, tname in TACTICS.items():
            tids = TACTIC_TIDS.get(tid_id, [])
            covered = sum(1 for t in tids if t in TECHNIQUE_INDEX and TECHNIQUE_INDEX[t])
            pct = int(covered / len(tids) * 100) if tids else 0
            rows.append((tid_id, tname, str(len(tids)), str(covered), "{}%".format(pct)))
            total_tids += len(tids)
            total_cov += covered
        global_pct = int(total_cov / total_tids * 100) if total_tids else 0
        rows.append(("TOTAL", "—", str(total_tids), str(total_cov), "{}%".format(global_pct)))
        print_table(
            ["Tactic ID", "Tactic", "Total TIDs", "Covered", "%"],
            rows,
            title="IXF MITRE ATT&CK for ICS Coverage",
        )

    def command_mitre_report(self, args: str, **kwargs) -> None:
        fmt = args.strip().lower() or "layer"
        from industrialxpl.core.mitre.reporter import MitreSweepReporter
        output = MitreSweepReporter().generate_layer(fmt)
        print_success("MITRE report generated: {}".format(output))

    def command_mitre_tactic(self, args: str, **kwargs) -> None:
        self.command_mitre_scan(args, **kwargs)

    # ── TTP commands ───────────────────────────────────────────────────────

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
        stop_first = "--stop-on-first" in parts
        output_file = parts[parts.index("--output") + 1] if "--output" in parts else None
        rate_ms = int(parts[parts.index("--rate-limit") + 1]) if "--rate-limit" in parts else 500
        from industrialxpl.core.mitre.sweeper import MitreTacticSweeper
        sweeper = MitreTacticSweeper(
            target=target,
            simulate=not destructive,
            destructive=destructive,
            rate_limit_ms=rate_ms,
            stop_on_first_vuln=stop_first,
        )
        results = sweeper.sweep_technique(tid)
        if output_file:
            from industrialxpl.core.mitre.reporter import MitreSweepReporter
            MitreSweepReporter(results).save(output_file)
            print_success("Results saved to {}".format(output_file))

    def command_ttp_check(self, args: str, **kwargs) -> None:
        parts = args.strip().split()
        if len(parts) < 2:
            print_error("Usage: ttp-check <TID> <target>")
            return
        tid, target = parts[0].upper(), parts[1]
        from industrialxpl.core.mitre.sweeper import MitreTacticSweeper
        MitreTacticSweeper(target=target, simulate=True, check_only=True).sweep_technique(tid)

    def command_ttp_simulate(self, args: str, **kwargs) -> None:
        parts = args.strip().split()
        if len(parts) < 2:
            print_error("Usage: ttp-simulate <TID> <target>")
            return
        tid, target = parts[0].upper(), parts[1]
        from industrialxpl.core.mitre.sweeper import MitreTacticSweeper
        MitreTacticSweeper(target=target, simulate=True).sweep_technique(tid)

    def command_ttp_list(self, args: str, **kwargs) -> None:
        from industrialxpl.core.mitre.index import TECHNIQUE_INDEX, TACTIC_INDEX, build_index
        from industrialxpl.core.mitre.tactics import TACTIC_ALIASES, TACTICS
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
        title = "TTP-IDs{}".format(" — {}".format(tactic_filter) if tactic_filter else " (all)")
        print_table(["TTP-ID", "# Modules", "Primary Module"], rows, title=title)

    def command_assess(self, args: str, **kwargs) -> None:
        module_path = args.strip()
        if not module_path:
            print_error("Usage: assess <module_path>")
            return
        self.command_use("assessment/{}".format(module_path) if not module_path.startswith("assessment") else module_path)
        if self.current_module:
            self.command_run("")

    # ── NSE (Nmap Scripting Engine) commands ─────────────────────────────────

    def command_nse(self, args: str = "", **kwargs) -> None:
        """Manage IXF Nmap NSE scripts. Usage: nse [install|list|status] [--force]"""
        from industrialxpl.core.nse.nse_manager import NseManager, NSE_SCRIPTS_DIR

        parts = args.strip().split()
        subcmd = parts[0].lower() if parts else "status"
        force = "--force" in parts

        if subcmd in ("status", ""):
            NseManager.status_report()
            nmap_bin = NseManager.find_nmap()
            if not nmap_bin:
                print_warning(
                    "Nmap not installed. Install it first:\n"
                    "  Linux:   sudo apt install nmap\n"
                    "  macOS:   brew install nmap\n"
                    "  Windows: https://nmap.org/download\n"
                    f"IXF NSE scripts are at: {NSE_SCRIPTS_DIR}\n"
                    "After installing Nmap, run: nse install"
                )
            else:
                scripts_dir = NseManager.find_scripts_dir()
                if scripts_dir:
                    not_installed = [
                        s.name for s in NseManager.list_ixf_scripts()
                        if not (scripts_dir / s.name).exists()
                    ]
                    if not_installed:
                        print_info("Run 'nse install' to install {} script(s).".format(
                            len(not_installed)))

        elif subcmd == "list":
            scripts = NseManager.list_ixf_scripts()
            scripts_dir = NseManager.find_scripts_dir()
            rows = []
            for s in scripts:
                status = "installed" if (scripts_dir and (scripts_dir / s.name).exists()) else "not installed"
                rows.append((s.name, status, f"{s.stat().st_size:,} B"))
            if rows:
                print_table(
                    ["Script", "Status", "Size"],
                    rows,
                    title=f"IXF NSE Scripts ({len(scripts)} total) — {NSE_SCRIPTS_DIR}",
                )
            else:
                print_error("No IXF NSE scripts found.")

        elif subcmd == "install":
            nmap_bin = NseManager.find_nmap()
            if not nmap_bin:
                print_error("Nmap is NOT installed on this system.")
                print_warning(
                    "Install Nmap first:\n"
                    "  Linux:   sudo apt install nmap\n"
                    "  macOS:   brew install nmap\n"
                    "  Windows: https://nmap.org/download\n"
                    f"\nIXF NSE scripts stored at: {NSE_SCRIPTS_DIR}\n"
                    "Copy .nse files manually to your Nmap scripts dir,\n"
                    "then run: nmap --script-updatedb"
                )
                return

            scripts_dir = NseManager.find_scripts_dir()
            if not scripts_dir:
                print_error("Nmap scripts directory not found.")
                print_info("Provide manually: python tools/nse_install.py --install --scripts-dir /path")
                return

            print_status(f"[NSE] Installing to: {scripts_dir}")
            result = NseManager.install(scripts_dir=scripts_dir, force=force)

            if result["installed"]:
                for name in result["installed"]:
                    print_success(f"  Installed: {name}")
            if result["skipped"]:
                print_info(f"  Skipped (already installed): {len(result['skipped'])} — use 'nse install --force'")
            if result["errors"]:
                for err in result["errors"]:
                    print_error(f"  {err}")
                if any("Permission" in e for e in result["errors"]):
                    import sys as _sys
                    if _sys.platform == "win32":
                        print_warning("Run IXF as Administrator to install into Program Files.")
                    else:
                        print_warning("Run: sudo python tools/nse_install.py --install")

            if result["success"] and result["installed"]:
                print_success(f"\nInstalled {len(result['installed'])} IXF NSE script(s) to {scripts_dir}")
                print_info("Usage: nmap --script ics-sweep -p 20-65535 <target>")
                print_info("       nmap --script 'ics-*' <target>")
                print_info("       nmap --script ics-default-creds -p 80,8080 <target>")
            elif not result["installed"] and not result["errors"]:
                print_info("All IXF NSE scripts already installed.")

        else:
            print_error(f"Unknown nse subcommand: '{subcmd}'")
            print_info("Usage: nse [install|list|status] [--force]")

    # ── Stats / coverage commands ─────────────────────────────────────────────

    def command_stats(self, args: str = "", **kwargs) -> None:
        """Show IXF module statistics and coverage summary."""
        mods = index_modules()
        from collections import Counter
        top_cats = Counter(m.split(".")[0] for m in mods)
        print_info("IXF Module Statistics")
        print_table(
            ["Category", "Count", "%"],
            [(k, str(v), f"{v*100//len(mods)}%") for k, v in sorted(top_cats.items(), key=lambda x: -x[1])],
            title=f"Total: {len(mods)} modules"
        )
        vendors = set()
        for m in mods:
            parts = m.split(".")
            if parts[0] == "cve" and len(parts) >= 2 and not parts[1].startswith("cve_"):
                vendors.add(parts[1])
        malware = sum(1 for m in mods if "malware" in m or m.startswith("cve.apt."))
        print_info(f"Vendors covered: {len(vendors)} | Malware TTPs: {malware}")
        print_info(f"MITRE ATT&CK for ICS: 12 tactics, 103 techniques mapped")
        print_info("PyPI: pip install industrialxpl | GitHub: github.com/mrhenrike/IndustrialXPL-Forge")

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

    # ── Alias normalisation ────────────────────────────────────────────────

    # -- LLM / SAST commands --

    def command_llm_key(self, args, **kwargs):
        parts = args.strip().split(None, 1)
        if len(parts) < 2:
            print_error("Usage: llm-key openai|anthropic|gemini|deepseek|grok API_KEY")
            return
        provider, api_key = parts[0].lower(), parts[1].strip()
        try:
            from industrialxpl.modules.assessment.sast.plc_source_analyzer import _llm_manager
            _llm_manager.set_key(provider, api_key)
            print_success("LLM key configured: provider={} len={}".format(provider, len(api_key)))
        except ValueError as exc:
            print_error(str(exc))

    def command_llm_status(self, args="", **kwargs):
        try:
            from industrialxpl.modules.assessment.sast.plc_source_analyzer import _llm_manager
            status = _llm_manager.status()
            active = _llm_manager.get_active_provider() or "(none)"
            rows = [(p, s) for p, s in status.items()]
            print_table(["Provider", "Status"], rows, title="LLM Providers")
            print_info("Active: {}".format(active))
        except Exception as exc:
            print_error("Error: {}".format(exc))

    def command_sast(self, args, **kwargs):
        parts = args.strip().split()
        if not parts:
            print_error("Usage: sast PATH [--mode sast|reverse|diff|exploit-gen]")
            return
        target_path = parts[0]
        mode = "sast"
        diff_with = ""
        i = 1
        while i < len(parts):
            if parts[i] == "--mode" and i+1 < len(parts):
                mode = parts[i+1]; i += 2
            elif parts[i] == "--diff" and i+1 < len(parts):
                diff_with = parts[i+1]; i += 2
            else:
                i += 1
        self.command_use("assessment/sast/plc_source_analyzer")
        if self.current_module:
            self.command_set("target " + target_path)
            self.command_set("mode " + mode)
            self.command_set("simulate false")
            if diff_with:
                self.command_set("diff_with " + diff_with)
            self.command_run("")

    def parse_line(self, line: str) -> tuple:
        """Normalise hyphens in commands (mitre-list → mitre_list)."""
        line = line.strip()
        if not line:
            return "", "", {}
        parts = line.split(None, 1)
        command = parts[0].replace("-", "_").lower()
        args = parts[1] if len(parts) > 1 else ""
        return command, args, {}
