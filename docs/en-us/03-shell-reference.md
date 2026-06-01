# Shell Reference

Complete reference for all 35 IXF interactive shell commands.

**Shell prompts:**
- `ixf >` — global context, no module loaded
- `ixf (Module Name) >` — module loaded

Commands with hyphens (e.g. `mitre-scan`) work with or without hyphens; they map internally to `command_mitre_scan`.

---

## Navigation

### `help`

Display the global help menu or module-specific help.

**Syntax:** `help`

**Context:** global or module

```
ixf > help

  IndustrialXPL-Forge v1.0.12 — IXF Shell Commands
  ─────────────────────────────────────────────────────────────
  use <module>          Load a module
  back                  Unload current module
  search <term>         Search modules by keyword/CVE/vendor
  set <option> <value>  Set module option
  setg <option> <value> Set global option (all modules)
  show [info|options]   Show module details
  run                   Execute loaded module
  check                 Connectivity/vulnerability check
  discover <CIDR>       OT device discovery sweep
  cve <CVE-ID>          Load module by CVE ID
  ttp <TID> <target>    Execute MITRE ATT&CK technique
  mitre-scan <t> <ip>   MITRE tactic/technique sweep
  mitre-coverage        Coverage % per tactic
  sast <path>           Offline PLC code analysis (LLM)
  stats                 Module statistics
  vendors [filter]      List covered vendors
  protocols             List covered protocols
  report [format]       Generate assessment report
  help                  This help
  exit                  Exit IXF
```

---

### `exit`

Exit the IXF shell.

**Syntax:** `exit`

**Context:** global or module

```
ixf > exit
[*] Exiting IndustrialXPL-Forge. Stay safe.
```

---

### `use <module_path>`

Load a module by its path. Accepts slash notation (`scanners/ics/modbus_detect`) or dot notation (`scanners.ics.modbus_detect`).

**Syntax:** `use <module_path>`

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| module_path | string | yes | Slash or dot notation module path (relative to `modules/`) |

```
ixf > use scanners/ics/modbus_detect
[*] Module loaded: Modbus TCP Device Detect
[*] CVE: N/A | CVSS: N/A | Impact: LOW

ixf (Modbus TCP Device Detect) >
```

```
ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
[*] Module loaded: CVE-2021-22681 Siemens S7-1200/1500 PLC
[*] CVE: CVE-2021-22681 | CVSS: 9.8 | Impact: CRITICAL
```

If a required Tier 3 runtime is absent, IXF warns but still loads the module:

```
[!] Module requires 'go' runtime. Python fallback available.
    Install Go: https://go.dev/dl/
```

---

### `back`

Unload the current module and return to the global context.

**Syntax:** `back`

**Context:** module only

```
ixf (Modbus TCP Device Detect) > back
ixf >
```

---

## Module Options

### `set <option> <value>`

Set an option on the currently loaded module.

**Syntax:** `set <option> <value>`

**Context:** module only (requires module loaded)

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| option | string | yes | Option name (case-insensitive) |
| value | varies | yes | Value appropriate for the option type (see [Module System](04-module-system.md)) |

```
ixf (Modbus TCP Device Detect) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (Modbus TCP Device Detect) > set port 5020
[*] port => 5020

ixf (Modbus TCP Device Detect) > set simulate false
[*] simulate => False

ixf (Modbus TCP Device Detect) > set timeout 10
[*] timeout => 10
```

**Setting a boolean option:**

```
ixf > set destructive true
ixf > set simulate false
ixf > set verbose yes    # also accepts: yes, no, on, off, 1, 0, true, false
```

**Validation error example:**

```
ixf (Modbus TCP Device Detect) > set port 99999
[-] Validation error for 'port': Port must be between 1 and 65535
```

---

### `setg <option> <value>`

Set a global option that persists across all modules in the current session.

**Syntax:** `setg <option> <value>`

**Context:** global or module

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| option | string | yes | Option name |
| value | varies | yes | Value (same types as `set`) |

```
ixf > setg target 10.0.0.100
[*] Global: target => 10.0.0.100

ixf > use scanners/ics/modbus_detect
[*] Module loaded: Modbus TCP Device Detect
[*] target already set from global: 10.0.0.100
```

Common globals: `target`, `timeout`, `simulate`, `destructive`.

---

### `unsetg <option>`

Remove a global option.

**Syntax:** `unsetg <option>`

**Context:** global or module

```
ixf > unsetg target
[*] Global 'target' cleared.
```

---

## Module Inspection

### `show [subcommand]`

Display module information.

**Syntax:** `show [info|options|advanced|devices|all]`

**Context:** module only

| Subcommand | Description |
|------------|-------------|
| `options` | Standard options (default if subcommand omitted) |
| `info` | Full module metadata (`__info__` dictionary) |
| `advanced` | Advanced options only |
| `devices` | Target device types |
| `all` | Both `info` and `options` |

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > show options

     Options — CVE-2021-22681 Siemens S7-1200/1500 PLC
+------------+-----------+----------+----------------------------------------------+
| Option     | Value     | Required | Description                                  |
|------------+-----------+----------+----------------------------------------------|
| target     |           | yes      | Target Siemens S7-1200 IP                    |
| port       | 102       | no       | Port                                         |
| simulate   | True      | no       | Simulate (default: True)                     |
| destructive| False     | no       | Live exploitation — may cause irreversible   |
+------------+-----------+----------+----------------------------------------------+
```

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > show info

  Module Information
  ─────────────────────────────────────────────────────
  name            : CVE-2021-22681 Siemens S7-1200/1500 PLC
  description     : Siemens S7-1200/1500 hardcoded TLS private key...
  authors         : ('Andre Henrique (mrhenrike)',)
  references      : ('https://cert-portal.siemens.com/...',)
  devices         : ('Siemens S7-1200/1500 PLC',)
  impact          : CRITICAL
  exploit_type    : Hardcoded Key — MitM/Decryption
  cve             : CVE-2021-22681
  cvss            : 9.8
  severity        : CRITICAL
  mitre_techniques: ['T0855', 'T0830']
  mitre_tactics   : ['Collection']
```

---

## Execution

### `run`

Execute the loaded module. Behavior depends on `simulate` and `destructive` options.

**Syntax:** `run`

**Context:** module only

| simulate | destructive | Behavior |
|----------|-------------|----------|
| `True` (default) | any | Print simulation output only; no packets sent |
| `False` | `False` | Run `check()` only (safe probe) |
| `False` | `True` | Full exploit with DestructiveGate confirmation for HIGH/CRITICAL/CATASTROPHIC impact |

```
# Simulate mode (default)
ixf (Modbus TCP Device Detect) > run
  [SIMULATE MODE — no packets sent]
  ...

# Live run (authorized lab only)
ixf > set simulate false
ixf > set destructive true
ixf > run
  [DESTRUCTIVE MODE — HIGH IMPACT]
  ...
  Confirmation> I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
```

See [SafeMode / DestructiveMode](05-safemode-destructivemode.md) for the full confirmation flow.

---

### `check`

Run a read-only connectivity and vulnerability probe. Does not send exploits.

**Syntax:** `check`

**Context:** module only

```
ixf (Modbus TCP Device Detect) > set target 192.168.1.100
ixf (Modbus TCP Device Detect) > check
[*] Checking 192.168.1.100:502...
[+] VULNERABLE — Modbus device detected

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set target 192.168.1.50
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > check
[*] Checking 192.168.1.50:102...
[-] NOT VULNERABLE — Port 102 not reachable or S7comm+ not detected
```

---

## Discovery

### `search <term>`

Search indexed modules by keyword, CVE ID, vendor name, or protocol.

**Syntax:** `search <term>`

**Context:** global

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| term | string | yes | Substring to match against module paths and names |

```
ixf > search CVE-2022-29965
[*] Search results for: CVE-2022-29965
    use cve/emerson/cve_2022_29965_roc800_hardcoded_creds

ixf > search default_creds
[*] Search results for: default_creds (showing 50 of 184)
    use creds/siemens/ssh_default_creds
    use creds/siemens/telnet_default_creds
    ...

ixf > search dnp3
[*] Search results for: dnp3
    use exploits/protocols/dnp3/dnp3_data_spoofing
    use exploits/protocols/dnp3/dnp3_replay_command
    use exploits/protocols/dnp3/dnp3_unauthorized_control
    use scanners/ics/dnp3_scanner
```

---

### `discover <CIDR>`

Launch an OT device discovery sweep on a subnet.

**Syntax:** `discover <CIDR>`

**Context:** global

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| CIDR | string | yes | Network range (e.g. `192.168.1.0/24`) |

```
ixf > discover 192.168.1.0/24
[*] Loading scanners/ics/modbus_detect for OT sweep...
[i] For full OT discovery, run: ttp T0846.001 192.168.1.0/24
[i] For protocol-specific scan: use scanners/ics/modbus_detect
```

---

## CVE Commands

### `cve <CVE-ID>`

Find and load a module by CVE identifier.

**Syntax:** `cve <CVE-ID>`

**Context:** global

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| CVE-ID | string | yes | CVE, CNVD, or other identifier (e.g. `CVE-2022-29965`) |

```
ixf > cve CVE-2021-22681
[*] Module loaded: CVE-2021-22681 Siemens S7-1200/1500 PLC

ixf > cve CVE-2023-6448
[*] Module loaded: CVE-2023-6448 Unitronics Unistream PLC

# Multiple matches — displays list
ixf > cve CVE-2022-3232
[*] Multiple modules found for CVE-2022-3232:
    1. use cve/ls_electric/cve_2022_3232_xgk_modbus_dos
    2. use cve/scanners/ls_electric/ls_electric_xgk_scanner
    Select module (number or path):
```

---

### `cve-scan <CIDR>`

Placeholder: discover assets and suggest CVE testing workflow.

**Syntax:** `cve-scan <CIDR>`

```
ixf > cve-scan 192.168.1.0/24
[i] CVE scan: discover assets first with mitre-scan discovery 192.168.1.0/24
[i] Then load specific CVE modules with: cve <CVE-ID>
```

---

## Reports

### `report [format]`

Generate an assessment report from the current session.

**Syntax:** `report [json|html|markdown]`

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| format | string | no | `json` | Output format |

```
ixf > report json
[*] Generating report...
[+] Report saved: ixf_report_20260601_153045.json

ixf > report html
[+] Report saved: ixf_report_20260601_153112.html

ixf > report markdown
[+] Report saved: ixf_report_20260601_153201.md
```

---

## MITRE ATT&CK for ICS

### `mitre <TID>`

List all modules that cover a specific MITRE technique.

**Syntax:** `mitre <TID>`

```
ixf > mitre T0843
[*] Modules for T0843 (Program Download):
    cve.siemens.cve_2022_1161_controllogix_modified_fw
    cve.rockwell.cve_2022_1161_controllogix_modified_fw
    exploits.protocols.s7comm.s7_unauthorized_cpu_control
    assessment.mitre_ics.t0843_program_upload
```

---

### `mitre-list [tactic]`

List all mapped MITRE techniques with module counts. Optional tactic filter.

**Syntax:** `mitre-list [tactic_name_or_alias]`

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| tactic | string | no | Tactic name, alias, or TA-ID (e.g. `discovery`, `initial-access`, `TA0108`) |

```
ixf > mitre-list
  MITRE ATT&CK for ICS — Technique Index
  ─────────────────────────────────────────────────────────────────
  T0817   Drive-by Compromise                  3 modules
  T0819   Exploit Public-Facing Application    47 modules
  T0822   External Remote Services             12 modules
  ...

ixf > mitre-list discovery
  MITRE ATT&CK for ICS — Discovery Techniques
  ─────────────────────────────────────────────────────────────────
  T0840   Network Connection Enumeration       2 modules
  T0842   Network Sniffing                     3 modules
  T0846   Remote System Discovery              8 modules
  ...
```

---

### `mitre-scan <tactic_or_TID> <target> [--destructive]`

Run a MITRE tactic sweep or single technique against a target.

**Syntax:** `mitre-scan <tactic|TID> <target> [--destructive]`

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| tactic or TID | string | yes | Tactic name/alias or technique ID (e.g. `discovery`, `T0843`) |
| target | string | yes | Target IP, hostname, or CIDR range |
| `--destructive` | flag | no | Disable simulate mode (authorized labs only) |

```
ixf > mitre-scan discovery 192.168.1.0/24
[*] Sweeping tactic: Initial Access (TA0108) on 192.168.1.0/24
[*] simulate=True (safe mode)
[*] Technique T0817 — Drive-by Compromise...
[*] Technique T0819 — Exploit Public-Facing Application...
...
[+] Tactic sweep complete: 9 techniques, 23 modules executed

ixf > mitre-scan T0843 192.168.1.100
[*] Sweeping T0843 (Program Download) on 192.168.1.100...
```

---

### `mitre-all <target>`

Sweep all 79+ mapped MITRE ATT&CK for ICS techniques (always in simulate mode).

**Syntax:** `mitre-all <target>`

```
ixf > mitre-all 192.168.1.100
[*] Full MITRE ATT&CK for ICS sweep on 192.168.1.100 (simulate=True)
[*] Running 74 techniques across 12 tactics...
```

---

### `mitre-coverage`

Display coverage percentage per tactic.

**Syntax:** `mitre-coverage`

```
ixf > mitre-coverage

  MITRE ATT&CK for ICS Coverage
  ──────────────────────────────────────────────────────────────
  Initial Access (TA0108)             :  9/9   (100%)
  Execution (TA0104)                  :  8/9   (88%)
  Persistence (TA0110)                :  6/8   (75%)
  Privilege Escalation (TA0111)       :  2/2   (100%)
  Evasion (TA0103)                    :  4/5   (80%)
  Discovery (TA0102)                  : 11/13  (84%)
  Lateral Movement (TA0109)           :  3/3   (100%)
  Collection (TA0100)                 :  8/9   (88%)
  Command and Control (TA0101)        :  3/3   (100%)
  Inhibit Response Function (TA0107)  : 14/18  (77%)
  Impair Process Control (TA0106)     :  9/11  (81%)
  Impact (TA0105)                     :  8/11  (72%)
  ──────────────────────────────────────────────────────────────
  TOTAL                               : 74/90  (82%)
```

---

### `mitre-report [format]`

Generate a MITRE ATT&CK Navigator-compatible layer or report.

**Syntax:** `mitre-report [json|html|layer]`

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| format | string | no | `layer` | `layer` = ATT&CK Navigator JSON; `json` = raw data; `html` = HTML report |

```
ixf > mitre-report layer
[+] ATT&CK Navigator layer saved: ixf_mitre_layer_20260601.json
[i] Open at: https://mitre-attack.github.io/attack-navigator/

ixf > mitre-report html
[+] MITRE ICS coverage report saved: ixf_mitre_report_20260601.html
```

---

### `mitre-tactic <tactic> <target>`

Alias for `mitre-scan`. See `mitre-scan` above.

---

## TTP Execution

### `ttp <TID> <target> [flags]`

Execute all modules mapped to a specific MITRE technique ID against a target.

**Syntax:** `ttp <TID> <target> [--destructive] [--stop-on-first] [--output <file>] [--rate-limit <ms>]`

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| TID | string | yes | MITRE technique ID (e.g. `T0843`, `T0843.001`) |
| target | string | yes | Target IP, hostname, or CIDR range |
| `--destructive` | flag | no | Disable simulate mode |
| `--stop-on-first` | flag | no | Stop after first confirmed hit |
| `--output <file>` | string | no | Save results to file |
| `--rate-limit <ms>` | int | no | Milliseconds between modules (default: 0) |

```
ixf > ttp T0843 192.168.1.100
[*] TTP T0843 (Program Download) — 12 modules — simulate=True
[*] Running cve/siemens/cve_2021_22681_s7_1200_hardcoded_key...
[*] Running cve/rockwell/cve_2022_1161_controllogix_modified_fw...
...
[+] T0843 sweep complete: 12 modules, 3 simulate matches

ixf > ttp T0878 10.0.0.0/24 --rate-limit 500
[*] TTP T0878 (Alarm Suppression) — subnet 10.0.0.0/24 — 500ms between modules

ixf > ttp T0859 192.168.1.1 --stop-on-first --output results.json
```

---

### `ttp-check <TID> <target>`

Run only the `check()` probe for all technique modules (read-only, no exploits).

**Syntax:** `ttp-check <TID> <target>`

```
ixf > ttp-check T0843 192.168.1.100
[*] T0843 check-only sweep on 192.168.1.100...
[+] POTENTIAL: cve/siemens/cve_2022_38465_s7_global_key — port 102 open
[-] NOT VULNERABLE: cve/rockwell/cve_2023_3595_controllogix_rce — port 44818 closed
```

---

### `ttp-simulate <TID> <target>`

Force simulate mode for all technique modules (safe, no packets beyond check).

**Syntax:** `ttp-simulate <TID> <target>`

```
ixf > ttp-simulate T0866 192.168.1.100
[*] T0866 simulation on 192.168.1.100 (simulate forced)
```

---

### `ttp-list [--tactic <name>]`

List all TTP-IDs with module counts. Optional tactic filter.

**Syntax:** `ttp-list [--tactic <tactic_name>]`

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `--tactic` | string | no | Filter by tactic name/alias |

```
ixf > ttp-list
  TTP Index — all techniques
  ─────────────────────────────────────────────────────────────
  T0801   Monitor Process State           2 modules   [Collection]
  T0802   Automated Collection            5 modules   [Collection]
  T0806   Brute Force I/O                 1 module    [Impair Process Control]
  ...

ixf > ttp-list --tactic evasion
  TTP Index — Evasion (TA0103)
  ─────────────────────────────────────────────────────────────
  T0820   Exploitation of Remote Services 3 modules
  T0849   Masquerading                    1 module
  T0856   Spoof Reporting Message         2 modules
  T0858   Change Credential               4 modules
  T0874   Hooking                         1 module
```

---

## Assessment

### `assess <module_path>`

Load and immediately execute an assessment module.

**Syntax:** `assess <module_path>`

**Context:** global

```
ixf > assess iec62443/zone_conduit_audit
[*] Loading assessment/iec62443/zone_conduit_audit...
[*] Running IEC 62443 Zone and Conduit Audit...

ixf > assess risk/ics_risk_scorer
ixf > assess nist_sp800_82/control_checklist
ixf > assess threat_intel/ics_kill_chain
```

---

## Statistics

### `stats`

Display module statistics and coverage summary.

**Syntax:** `stats`

```
ixf > stats
[i] IXF Module Statistics

  Total: 976 modules
  ──────────────────────────────────────
  Category        Count  %
  cve               486  49%
  exploits          159  16%
  creds              34   3%
  scanners           31   3%
  assessment         18   1%
  ──────────────────────────────────────

[i] Vendors covered: 150 | Malware TTPs: 26
[i] MITRE ATT&CK for ICS: 12 tactics, 103 techniques mapped
[i] PyPI: pip install industrialxpl-forge
```

---

### `vendors [filter]`

List all covered OT/ICS vendors with CVE module counts.

**Syntax:** `vendors [substring_filter]`

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| filter | string | no | Case-insensitive substring filter |

```
ixf > vendors
  Vendors (150 covered)
  ─────────────────────────────────────────
  Vendor                     Modules
  Schneider Electric            39
  Rockwell Automation           38
  Siemens                       27
  ...

ixf > vendors siemens
  Vendors (1 covered)
  ─────────────────────────────────────────
  Siemens                       27

ixf > vendors germany
  Vendors (12 covered)
  ─────────────────────────────────────────
  Siemens                       27
  Beckhoff                       5
  Belden/Hirschmann              2
  ...
```

---

### `protocols`

List all covered OT/ICS protocols with exploit module counts.

**Syntax:** `protocols`

```
ixf > protocols
  Protocol Coverage (26 protocols)
  ─────────────────────────────────────────
  Protocol               Exploit Modules
  MODBUS                       18
  DNP3                          4
  S7COMM                        2
  IEC61850                      3
  ENIP                          4
  BACNET                        2
  ...
```

---

### `coverage`

Alias for `mitre-coverage`. See [MITRE ATT&CK for ICS](06-mitre-attack-ics.md).

---

## LLM / SAST

### `llm-key <provider> <api_key>`

Configure an LLM provider API key for SAST analysis. Keys are stored in-session only (never written to disk by this command).

**Syntax:** `llm-key <provider> <api_key>`

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| provider | string | yes | `openai`, `anthropic`, `gemini`, `deepseek`, or `grok` |
| api_key | string | yes | API key string |

```
ixf > llm-key gemini AIzaSyBGaoio5aKf3rWNFjpqc8trP4EJPyABYH8
[+] LLM key configured: provider=gemini len=39

ixf > llm-key openai sk-svcacct-...
[+] LLM key configured: provider=openai len=82
```

Alternatively, set via environment variables before launching IXF:

```bash
export GOOGLE_AI_STUDIO_API_KEY=AIzaSy...
export OPENAI_API_KEY=sk-...
ixf
```

---

### `llm-status`

Display the status of all configured LLM providers.

**Syntax:** `llm-status`

```
ixf > llm-status

  LLM Providers
  ─────────────────────────────────────
  Provider    Status
  openai      not configured
  anthropic   not configured
  gemini      configured
  deepseek    not configured
  grok        not configured
  ─────────────────────────────────────
  Active: gemini
```

---

### `sast <path> [--mode <mode>] [--diff <other_path>]`

Run offline LLM-powered SAST analysis on a PLC/RTU source code file or directory.

**Syntax:** `sast <path> [--mode sast|reverse|diff|exploit-gen] [--diff <other_file>]`

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| path | string | yes | — | Path to PLC source file or project directory |
| `--mode` | string | no | `sast` | Analysis mode (see below) |
| `--diff` | string | no | — | Second file for diff mode |

**Modes:**

| Mode | Description |
|------|-------------|
| `sast` | Full vulnerability analysis (setpoints, safety, auth, network, logic) |
| `reverse` | Reverse engineer binary/compiled PLC firmware |
| `diff` | Compare two versions of PLC code for unauthorized changes |
| `exploit-gen` | Generate proof-of-concept exploit based on findings |

```
ixf > sast /opt/plc_projects/water_treatment/ --mode sast
[*] Analyzing: water_treatment/ (5 files, 245 lines)
[*] Provider: gemini | Sanitized: 2 credentials, 1 public IP
[*] Sending to LLM...

  SAST REPORT — water_treatment/
  ─────────────────────────────────────────────────────────────

  FINDING [SEVERITY: CRITICAL]: Unvalidated Chlorine Dosing Setpoint
    Location: water_treatment.st, line 48
    Description: SP_CHLORINE_HIGH := 4000.0 — 2000x WHO safe limit
    Attack Vector: Modbus FC16 write to HR[200] (DOSE_FACTOR)
    Physical Impact: 4000 mg/L chlorine — lethal dose for infants
    MITRE: T0836 (Modify Parameter), T0880 (Alarm Suppression)
    Remediation: Validate DOSE_FACTOR <= 2.0; add hardware interlock

  FINDING [SEVERITY: HIGH]: Race Condition in pH Dosing
    Location: water_treatment.st, lines 65-71
    ...
```

See [SAST / LLM Analysis](07-sast-llm.md) for the full guide.

---

## Other Commands

### `exec <shell_command>`

Execute an arbitrary shell command and display output. Timeout: 30 seconds.

**Syntax:** `exec <command>`

```
ixf > exec ping 192.168.1.1 -c 3
PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
...

ixf > exec python tools/env_doctor.py
```

---

*Previous: [Quick Start](02-quick-start.md) | Next: [Module System](04-module-system.md)*
