"""IndustrialXPL-Forge interactive shell interpreter.

Shell hierarchy:
    BaseInterpreter   -- readline loop, command dispatch, history
    IXFInterpreter    -- ICS/OT-specific commands + module loading

Prompt: "ixf >" (global) / "ixf (Module Name) >" (module loaded)
"""

import os
import sys

from industrialxpl.core.platform import require_linux

require_linux()

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

from industrialxpl.cli import (
    ICSCommandsMixin,
    MalwareCommandsMixin,
    MITRECommandsMixin,
    SASTCommandsMixin,
    StatsCommandsMixin,
)
from industrialxpl.core.exploit.exceptions import IXFException
from industrialxpl.core.exploit.printer import (
    get_log_level,
    pprint_dict_in_order,
    print_error,
    print_info,
    print_status,
    print_success,
    print_table,
    print_warning,
    set_log_level,
)
from industrialxpl.core.exploit.utils import (
    humanize_path,
    import_exploit,
    index_modules,
    module_required,
    pythonize_path,
)

VERSION = "1.5.0"

_BANNER = rf"""
 ___           _           _        _       ___  ______  _          _____
|_ _|_ __   __| |_   _ ___| |_ _ __(_) __ _| \ \/ /  _ \| |        |  ___|__  _ __ __ _  ___
 | || '_ \ / _` | | | / __| __| '__| |/ _` | |\  /| |_) | |   _____| |_ / _ \| '__/ _` |/ _ \
 | || | | | (_| | |_| \__ \ |_| |  | | (_| | |/  \|  __/| |__|_____|  _| (_) | | | (_| |  __/
|___|_| |_|\__,_|\__,_|___/\__|_|  |_|\__,_|_/_/\_\_|   |_____|    |_|  \___/|_|  \__, |\___|
                                                                                     |___/
  IndustrialXPL-Forge v{VERSION} -- OT/ICS/SCADA Security Assessment Framework
  Author: Andre Henrique (@mrhenrike) | Uniao Geek | https://uniaogeek.com.br/
  Python-First. Pure Python -- pip install industrialxpl-forge
  Type 'help' for commands.  simulate=false by default - set SIMULATE true for dry-run.
"""

_GLOBAL_HELP = f"""
IndustrialXPL-Forge (IXF) v{VERSION}

NAVIGATION:
  help                          This menu
  help <term|module>            Contextual help: help sector / help modbus / help timing
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
  show global                   Show all global options with current values
  global                        Alias: show global

  Output:    setg LOGLEVEL debug | info | warning | error
             setg VERBOSE true            (alias: loglevel=debug)
             setg OUTPUT /tmp/scan.txt    (tee to file)
             setg REPORT_FMT json | html | markdown | csv

  Scan:      setg TIMING T3               (T0-T5 or slug: normal, polite, aggressive...)
             setg THREADS 5               (parallel probes, default 5)
             setg HOST_TIMEOUT 30         (seconds per host, like nmap --host-timeout)
             setg MAX_RETRIES 2           (TCP retries, like nmap --max-retries)
             setg SCAN_DELAY 300          (ms between probes, like nmap --scan-delay)
             setg MAX_RATE 10             (probes/sec cap, like nmap --max-rate)
             setg PROBE_LEVEL 2           (1-5 detection depth, like nmap --version-intensity)
             setg PING_FIRST true         (TCP alive check before scan, default true)
             setg SKIP_PING false         (skip alive check, like nmap -Pn)

  Target:    setg TARGET 10.0.0.1         (default target applied when module TARGET is empty)

  NOTE: PORT and UNIT_ID are protocol-specific -- set them per module, not globally.
  Help:  help host_timeout | help max_retries | help scan_delay | help probe_level | help max_rate

EXECUTION MODES (see 'help simulate' and 'help destructive'):
  simulate=false  (module default)  Real protocol operations per module logic.
  simulate=true                     Dry-run / simulated output only.
  destructive=false (default)       Read-oriented behavior in modules that support it.
  destructive=true                  Enables write/destructive paths when module supports it.

  set SIMULATE true|false           -- per module
  set DESTRUCTIVE true|false        -- per module
  help simulate                     -- full explanation

CVE / MITRE / TTP:
  cve <CVE-ID>                  Load module for a CVE (e.g. cve CVE-2022-29953)
  mitre <TID>                   Modules covering technique (e.g. mitre T0843)
  mitre-list [tactic]           List all 79 ICS techniques
  mitre-scan <tactic> <target>  Run all modules for a tactic
  ttp <TID> <target>            Execute all modules for a TTP-ID
  help mitre                    Full MITRE command reference

MALWARE RESEARCH (lab only):
  malware list                  Incorporated families (Mirai, TRISIS, Akaja, ...)
  malware analyze <slug>        Vendor source deep-dive + attack vectors
  malware build <target>        Compile with setg LHOST/LPORT (C2 lab profile)
  malware compile list          Native + vendor compile targets
  malware compile <target>      Build to .tmp/malware_builds/
  malware exec <artifact>       Execute built artifact (destructive gate)
  malware deploy <artifact> <ip>  Deploy to lab target
  malware shell <ip>            One-shot lab shell/session probe
  malware firmware <image> <ip> Firmware replace plan / gated flash
  ics_tools list                Incorporated ICS tools (SCADAPASS, Redpoint, ...)
  ics_tools run <slug>          Run vendor entry (simulate default)
  use scanners/malware_research/malware_full_pipeline
  use scanners/ics_tools_research/ics_tools_ops

RESOURCE FILE MODE (like Metasploit -r):
  ixf -r scan.rc                Run resource file, then drop into interactive shell
  ixf -r scan.rc -x             Run resource file and exit (for CI/CD pipelines)
  ixf -r setup.rc -r scan.rc   Chain multiple resource files in order
  ixf -e "setg TARGET 10.0.0.1; use scanners/ics/modbus_scanner; run" -x
  ixf -q -r scan.rc -x         Quiet (no banner) + resource file + exit
  ixf --loglevel debug -r scan.rc
  ixf -o /tmp/scan.log -r scan.rc -x

Resource file format (plain text, one command per line):
  # Comments start with #
  setg TIMING T2
  setg TARGET 192.168.1.100
  use scanners/ics/modbus_scanner
  set PORT 502
  run
  back

Templates in resources/rc/:  modbus_scan.rc  ot_discovery.rc  mitre_ics_sweep.rc

EXAMPLES:
  ixf > search sector=energy
  ixf > search type=scanner
  ixf > modules assessment
  ixf > setg loglevel debug
  ixf > setg timing T2
  ixf > use scanners/ics/modbus_detect
  ixf > set TARGET 192.168.1.100
  ixf > set simulate false
  ixf > run
  ixf > help timing
  ixf > help modbus
"""

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


