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
    pprint_dict_in_order, printer_queue,
)
from industrialxpl.core.exploit.safety import DestructiveGate, IMPACT_LEVELS
from industrialxpl.core.exploit.utils import (
    index_modules, import_exploit, pythonize_path, humanize_path,
    module_required, MODULES_DIR,
)

VERSION = "1.0.0"

_BANNER = r"""
  ___           _           _       _  __  ______  _       ______
 |_ _|_ __   __| |_   _ ___| |_ _ __(_) \ \/ / _ \| |     |  ___|__  _ __ __ _  ___
  | || '_ \ / _` | | | / __| __| '__| |  \  /|  __/| |     | |_ / _ \| '__/ _` |/ _ \
  | || | | | (_| | |_| \__ \ |_| |  | |  /  \| |   | |___  |  _| (_) | | | (_| |  __/
 |___|_| |_|\__,_|\__,_|___/\__|_|  |_| /_/\_\_|   |_____| |_|  \___/|_|  \__, |\___|
                                                                              |___/
  IndustrialXPL-Forge v{version} — OT/ICS/SCADA Security Assessment Framework
  Author: André Henrique (@mrhenrike) | União Geek | https://uniaogeek.com.br/
  Python-First: no Metasploit required. Pure Python implementation.
  Type 'help' for commands.  simulate=True by default (safe mode).
""".format(version=VERSION)

_GLOBAL_HELP = """
IndustrialXPL-Forge (IXF) v{version}

GLOBAL COMMANDS:
  help                          Show this help menu
  use <module>                  Load a module (e.g. use scanners/ics/modbus_detect)
  search <term>                 Search modules by keyword, vendor, CVE, or protocol
  exec <shell_cmd>              Execute a shell command
  discover <CIDR>               Discover OT/ICS assets on a network
  exit                          Exit IXF

MODULE COMMANDS (after 'use'):
  run                           Execute the current module
  check                         Run check() only — read-only fingerprint
  back                          Deselect current module
  set <option> <value>          Set a module option (e.g. set target 192.168.1.1)
  setg <option> <value>         Set a global option (applies to all modules)
  unsetg <option>               Clear a global option
  show [info|options|devices]   Show module information

CVE COMMANDS:
  cve <CVE-ID>                  Load module for a specific CVE
  cve-scan <CIDR>               Discover assets and test all applicable CVEs
  report [json|html|markdown]   Generate assessment report for current session

MITRE ATT&CK FOR ICS COMMANDS:
  mitre <TID>                   Show modules covering a technique (e.g. mitre T0843)
  mitre-list [tactic]           List all techniques [filtered by tactic]
  mitre-scan <tactic|TID> <target>  Execute all modules for a tactic/technique
  mitre-all <target>            Execute all 79 MITRE ICS techniques (simulate default)
  mitre-coverage                Show coverage percentage per tactic
  mitre-report [json|html|layer]Generate MITRE report / ATT&CK Navigator JSON layer

TTP COMMANDS:
  ttp <TID> <target>            Execute all modules for a TTP-ID against target/CIDR
  ttp T0843 192.168.1.100       Run Program Download modules against target
  ttp T0878 10.0.0.0/24         Run Alarm Suppression modules against subnet
  ttp-check <TID> <target>      Run only check() — read-only, always safe
  ttp-simulate <TID> <target>   Force simulate mode — print payloads only, no send
  ttp-list [--tactic <name>]    List all TTP-IDs with module counts

ASSESSMENT:
  assess <module_path>          Run an assessment module

SAFETY (applies to all modules):
  simulate  (default: true)     Print payload without sending — SAFE
  destructive (default: false)  Enable real execution — requires confirmation
  All destructive modules show an impact banner and require typed confirmation.
  Audit log: .log/destructive_ops_YYYY-MM-DD.log

EXAMPLES:
  ixf > use scanners/ics/modbus_detect
  ixf > set target 192.168.1.100
  ixf > check

  ixf > ttp T0843 192.168.1.100
  ixf > mitre-scan discovery 10.0.0.0/24
  ixf > cve CVE-2022-29953
  ixf > cve-scan 192.168.1.0/24
  ixf > report html
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

                readline.write_history_file(self.history_file)

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

    def command_help(self, args: str = "", **kwargs) -> None:
        if self.current_module:
            print(_MODULE_HELP)
        else:
            print(_GLOBAL_HELP)

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
        key, value = parts[0], parts[1]
        if key not in self.current_module.options:
            print_error("Unknown option: '{}'".format(key))
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
            return
        key, value = parts[0], parts[1]
        self._global_opts[key] = value
        if self.current_module and key in self.current_module.options:
            setattr(self.current_module, key, value)
        print_success("[global] {} => {}".format(key, value))

    def command_unsetg(self, args: str, **kwargs) -> None:
        key = args.strip()
        if key in self._global_opts:
            del self._global_opts[key]
            print_success("[global] {} cleared.".format(key))
        else:
            print_warning("'{}' was not set globally.".format(key))

    @module_required
    def command_show(self, args: str, **kwargs) -> None:
        sub = args.strip().lower() or "options"
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

        # simulate=false + destructive=false → safe check only
        print_warning("simulate=false but destructive=false — running check() only.")
        self.command_check(args, **kwargs)

    @module_required
    def command_check(self, args: str = "", **kwargs) -> None:
        mod = self.current_module
        info = mod.get_info()
        print_status("Checking {}…".format(info.get("name", str(mod))))
        try:
            result = mod.check()
            if result:
                print_success("VULNERABLE — {}".format(info.get("name", "")))
            else:
                print_info("NOT_VULNERABLE — {}".format(info.get("name", "")))
        except NotImplementedError:
            print_warning("Module check() not yet implemented.")

    def command_search(self, args: str, **kwargs) -> None:
        term = args.strip().lower()
        if not term:
            print_error("Usage: search <keyword>")
            return
        results = [m for m in self.modules if term in m.lower()]
        if not results:
            print_info("No modules found for '{}'.".format(term))
            return
        print_success("{} module(s) found:".format(len(results)))
        for m in results[:50]:
            print_info("  use {}".format(humanize_path(m)))
        if len(results) > 50:
            print_info("  … and {} more. Refine your search.".format(len(results) - 50))

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
