# CLI Non-Interactive Mode

IXF can be used without the interactive shell by passing commands directly on the command line. Commands are processed sequentially then the process exits. This enables scripting, automation, CI/CD integration, and repeatable one-liner penetration testing workflows.

---

## Table of Contents

1. [Basic Syntax](#basic-syntax)
2. [One-Liner Patterns with Full Output](#one-liner-patterns-with-full-output)
3. [Multiple Module Chaining](#multiple-module-chaining)
4. [setg in Non-Interactive Mode](#setg-in-non-interactive-mode)
5. [ALL ttp Command Variations](#all-ttp-command-variations)
6. [ALL mitre Commands](#all-mitre-commands)
7. [Shell Piping — 10 Examples](#shell-piping---10-examples)
8. [Bash Script for Full OT Assessment](#bash-script-for-full-ot-assessment)
9. [Python API — 10 Code Examples](#python-api---10-code-examples)
10. [CI/CD Integration](#cicd-integration)
11. [Exit Codes](#exit-codes)
12. [JSON Output Piping with jq](#json-output-piping-with-jq)
13. [Batch File Scanning with file:// Targets](#batch-file-scanning-with-file-targets)

---

## Basic Syntax

```bash
ixf <command> [args...]
```

Multiple commands are separated by spaces. The shell processes them left-to-right sequentially, then exits. Commands requiring options use `set <option> <value>` between `use` and `run`.

```bash
# Single command
ixf stats

# Chained commands (processed sequentially)
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run

# Multiple independent commands
ixf search siemens
ixf stats
ixf vendors siemens
```

---

## One-Liner Patterns with Full Output

### Search and exit

```bash
ixf search modbus
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.

Search results for: modbus
──────────────────────────────────────────────────────────────────────────────
  use scanners/ics/modbus_detect                       [INFO]   Modbus TCP Device Scanner
  use scanners/ics/modbus_range_scanner                [INFO]   Modbus Register Range Scanner
  use exploits/protocols/modbus/modbus_replay_attack   [HIGH]   Modbus TCP Replay Attack
  use exploits/protocols/modbus/modbus_write_coil      [HIGH]   Modbus Unauthorized Coil Write
  use exploits/protocols/modbus/modbus_flood_dos       [HIGH]   Modbus TCP Flood DoS
  use cve/malware/frostygoop_modbus_heating            [CRITICAL] FrostyGoop Modbus Heating Attack
  use cve/schneider/cve_2022_37300_modbus_auth_bypass  [CRITICAL] CVE-2022-37300 Modbus Auth Bypass
  use assessment/protocols/modbus_security_audit       [INFO]   Modbus Protocol Security Audit
──────────────────────────────────────────────────────────────────────────────
8 result(s) found.
```

---

```bash
ixf search CVE-2021-22681
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.

Search results for: CVE-2021-22681
──────────────────────────────────────────────────────────────────────────────
  use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key   [CRITICAL] CVE-2021-22681 Siemens S7-1200 Hardcoded Crypto Key
──────────────────────────────────────────────────────────────────────────────
1 result(s) found.
```

---

```bash
ixf search default_creds
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.

Search results for: default_creds
──────────────────────────────────────────────────────────────────────────────
  use creds/siemens/ssh_default_creds                 [HIGH]   Siemens SSH Default Credentials
  use creds/siemens/web_default_creds                 [HIGH]   Siemens Web Default Credentials
  use creds/rockwell/logix_default_creds              [HIGH]   Rockwell Logix Default Credentials
  use creds/schneider/web_default_creds               [HIGH]   Schneider Web Default Credentials
  use creds/ge/cimplicity_default_creds               [HIGH]   GE Cimplicity Default Credentials
  use creds/honeywell/experion_default_creds          [HIGH]   Honeywell Experion Default Credentials
  use creds/generic/web_default_creds                 [HIGH]   Generic Web Default Credentials
  use creds/generic/ftp_default_creds                 [MEDIUM] Generic FTP Default Credentials
  [... 26 more results ...]
──────────────────────────────────────────────────────────────────────────────
34 result(s) found.
```

---

### Load a module, set options, and run

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.
[*] Module loaded: Modbus TCP Device Scanner
[*] target => 192.168.1.100

  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────────────
  [i] What would happen:

      Modbus TCP Device Detection

      Step 1: TCP connect to 192.168.1.100:502
      Step 2: Send FC04 probe (Read Input Registers)
              Payload (hex): 000100000006010400000001
      Step 3: Validate Transaction ID echo in 6-byte MBAP response
      Step 4: If identify=True, send FC43/MEI (Object IDs 0x00-0x02)
              Extract: VendorName, ProductCode, MajorMinorRevision
      Impact: Device fingerprinted — vendor, model, firmware revision known

  [i] MITRE ATT&CK for ICS: T0888 (Remote System Information Discovery), T0802 (Automated Collection)
  ─────────────────────────────────────────────────────────────────────
  [i] Run with simulate=False and destructive=True to execute live
      (authorized lab environments only)
```

---

### Check only (no exploit, just connectivity probe)

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 check
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.
[*] Module loaded: Modbus TCP Device Scanner
[*] target => 192.168.1.100
[*] Running check()...
[+] check() => True
```

Or if unreachable:

```
[*] check() => False
```

---

### Show module info

```bash
ixf use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key info
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.
[*] Module loaded: CVE-2021-22681 Siemens S7-1200 Hardcoded Crypto Key

  Module Information
  ─────────────────────────────────────────────────────────────────────
  Name:              CVE-2021-22681 Siemens S7-1200 Hardcoded Crypto Key
  CVE:               CVE-2021-22681
  CVSS:              10.0
  Severity:          CRITICAL
  Impact:            CRITICAL
  Type:              Hardcoded Credentials
  Devices:           Siemens SIMATIC S7-1200, S7-1500
  Authors:           Andre Henrique (mrhenrike)
  MITRE Techniques:  T0859, T0813
  MITRE Tactics:     Credential Access, Impair Process Control
  References:
    https://www.cisa.gov/uscert/ics/advisories/icsa-21-194-07
    https://nvd.nist.gov/vuln/detail/CVE-2021-22681
  ─────────────────────────────────────────────────────────────────────

  Options
  ─────────────────────────────────────────────────────────────────────
  Name         Value       Description
  target                   Target Siemens S7-1200/1500 IP
  port         102         S7comm port (default: 102)
  rack         0           S7 CPU rack number
  slot         1           S7 CPU slot number
  simulate     True        Simulate mode (default: True)
  destructive  False       Enable live exploitation
  ─────────────────────────────────────────────────────────────────────
```

---

### Stats

```bash
ixf stats
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.

  IXF Statistics
  ─────────────────────────────────────────────────────────────────────
  Total modules:         976
    CVE exploits:        612
    Protocol exploits:   89
    PLC exploits:        44
    SCADA exploits:      38
    Scanners:            31
    Credential modules:  34
    Malware TTPs:        26
    APT TTPs:            14
    Assessment modules:  88

  Coverage by severity:
    CATASTROPHIC:  8
    CRITICAL:      287
    HIGH:          341
    MEDIUM:        198
    LOW:           87
    INFO:          55

  Vendors covered:       150+
  Protocols covered:     50
  MITRE ICS techniques:  82 of 85 (96.5%)
  ─────────────────────────────────────────────────────────────────────
```

---

### Vendors and protocols

```bash
ixf vendors siemens
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.

  Siemens ICS/OT Modules
  ─────────────────────────────────────────────────────────────────────
  Module                                              Severity   CVE
  cve/siemens/cve_2021_22681_s7_1200_hardcoded_key   CRITICAL   CVE-2021-22681
  cve/siemens/cve_2019_13945_scalance_auth_bypass     CRITICAL   CVE-2019-13945
  cve/siemens/cve_2018_4832_wincc_path_traversal      HIGH       CVE-2018-4832
  cve/siemens/cve_2019_19300_siprotec4_dos            HIGH       CVE-2019-19300
  cve/siemens/cve_2022_38465_tia_portal_priv_esc      HIGH       CVE-2022-38465
  cve/siemens/cve_2023_44317_scalance_rce             CRITICAL   CVE-2023-44317
  [... 61 more ...]
  ─────────────────────────────────────────────────────────────────────
  67 modules for Siemens
```

---

```bash
ixf protocols
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.

  Supported ICS/OT Protocols
  ─────────────────────────────────────────────────────────────────────
  Protocol         Port(s)           Modules   Category
  Modbus TCP       502               34        SCADA/PLC
  S7comm           102               28        Siemens PLC
  EtherNet/IP      44818, 2222       22        Rockwell/AB PLC
  DNP3             20000             18        RTU/SCADA
  IEC 60870-5-104  2404              16        RTU/SCADA (IEC)
  OPC UA           4840              14        SCADA middleware
  BACnet/IP        47808             12        Building automation
  IEC 61850        102, 61850        10        Substation automation
  PROFINET         34964             9         Siemens field bus
  MQTT             1883, 8883        8         IoT/SCADA messaging
  CODESYS          1217              7         Multi-vendor PLC runtime
  EtherCAT         —                 6         Field bus
  CC-Link          5006              5         Mitsubishi PLC
  HART             —                 5         Field instruments
  FOUNDATION FBus  —                 4         Field instruments
  [... 35 more protocols ...]
  ─────────────────────────────────────────────────────────────────────
  50 protocols covered
```

---

```bash
ixf coverage
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.

  IXF Coverage Summary
  ─────────────────────────────────────────────────────────────────────
  Vendors:    150+  (Siemens, Schneider, Rockwell, GE, Honeywell, ABB, Moxa, ...)
  Protocols:  50    (Modbus, S7comm, DNP3, IEC 104, OPC UA, BACnet, ...)
  CVEs:       612   (spanning 2005–2024)
  MITRE ICS:  82/85 techniques covered (96.5%)
  Malware:    26    (Stuxnet, Industroyer, TRITON, FrostyGoop, CosmicEnergy, ...)
  ─────────────────────────────────────────────────────────────────────
```

---

### Generate report

```bash
ixf report json
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.
[*] Generating JSON report...
[+] Report saved: .tmp/ixf_report_20240601_182500.json
[i] Report contains: 976 modules, 612 CVEs, 50 protocols, 150+ vendors
```

---

```bash
ixf report html
```

**Output:**

```
[*] Generating HTML report...
[+] Report saved: .tmp/ixf_report_20240601_182501.html
[i] Open in browser: file:///path/to/IndustrialXPL-Forge/.tmp/ixf_report_20240601_182501.html
```

---

## Multiple Module Chaining

Run multiple modules back-to-back against the same target in a single command:

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run \
    use scanners/ics/s7_comm_scanner set target 192.168.1.100 run \
    use scanners/ics/bacnet_scanner set target 192.168.1.100 run \
    use scanners/ics/dnp3_scanner set target 192.168.1.100 run
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.
[*] Module loaded: Modbus TCP Device Scanner
[*] target => 192.168.1.100
  [SIMULATE MODE — no packets sent]
  [i] What would happen: Send FC04 probe to 192.168.1.100:502...
  [i] MITRE ATT&CK for ICS: T0888

[*] Module loaded: Siemens S7comm Scanner
[*] target => 192.168.1.100
  [SIMULATE MODE — no packets sent]
  [i] What would happen: Send COTP+S7 Setup probe to 192.168.1.100:102...
  [i] MITRE ATT&CK for ICS: T0888

[*] Module loaded: BACnet/IP Scanner
[*] target => 192.168.1.100
  [SIMULATE MODE — no packets sent]
  [i] What would happen: Send Who-Is broadcast to 192.168.1.100:47808...
  [i] MITRE ATT&CK for ICS: T0888

[*] Module loaded: DNP3 Scanner
[*] target => 192.168.1.100
  [SIMULATE MODE — no packets sent]
  [i] What would happen: Send DNP3 Link Status probe to 192.168.1.100:20000...
  [i] MITRE ATT&CK for ICS: T0888
```

---

**Chain with different options per module:**

```bash
ixf \
  use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key set target 10.0.0.5 set port 102 run \
  use cve/schneider/cve_2022_37300_modbus_auth_bypass set target 10.0.0.6 set port 502 run \
  use creds/ge/cimplicity_default_creds set target 10.0.0.7 set port 80 run
```

---

## setg in Non-Interactive Mode

`setg` sets a global option that persists across all subsequent module loads in the session:

```bash
ixf setg target 192.168.1.100 \
    use scanners/ics/modbus_detect run \
    use scanners/ics/s7_comm_scanner run \
    use scanners/ics/bacnet_scanner run
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.
[*] Global option set: target = 192.168.1.100

[*] Module loaded: Modbus TCP Device Scanner
[*] target => 192.168.1.100 (global)
  [SIMULATE MODE — no packets sent]
  ...

[*] Module loaded: Siemens S7comm Scanner
[*] target => 192.168.1.100 (global)
  [SIMULATE MODE — no packets sent]
  ...

[*] Module loaded: BACnet/IP Scanner
[*] target => 192.168.1.100 (global)
  [SIMULATE MODE — no packets sent]
  ...
```

**Multiple global options:**

```bash
ixf setg target 192.168.1.100 setg simulate False setg destructive True \
    use scanners/ics/modbus_detect run
```

**Note:** `setg simulate False` and `setg destructive True` will enable live traffic. Only use in authorized, isolated lab environments.

---

## ALL ttp Command Variations

### Run a specific technique (simulate mode)

```bash
ixf ttp T0843 192.168.1.100
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.
[*] Running technique T0843 (Program Upload) against 192.168.1.100

  Technique: T0843 — Program Upload
  Tactic:    Collection
  ──────────────────────────────────────────────────────────────────
  Module 1/3: assessment/mitre_ics/t0843_program_upload
  [SIMULATE MODE]
    Stage 1: Discovery — enumerate S7comm/EIP/Modbus PLCs on network
    Stage 2: Access — connect to PLC programming interface
    Stage 3: Upload — request complete PLC ladder logic program
    Stage 4: Analysis — identify safety bypass and backdoor opportunities
  ──────────────────────────────────────────────────────────────────
  T0843 assessment complete. 1 modules executed.
```

---

### Run technique against specific port

```bash
ixf ttp T0855 192.168.1.100 --port 502
```

---

### List all techniques for a tactic

```bash
ixf ttp-list --tactic discovery
```

**Output:**

```
[*] MITRE ATT&CK for ICS — Discovery Techniques
  ──────────────────────────────────────────────────────────────────
  Technique   Name                                    IXF Modules
  T0802       Automated Collection                    3
  T0840       Network Connection Enumeration           4
  T0842       Network Sniffing                         2
  T0846       Remote System Discovery                  5
  T0888       Remote System Information Discovery      8
  T0887       Wireless Sniffing                        2
  ──────────────────────────────────────────────────────────────────
  6 techniques, 24 modules
```

---

### List all techniques for all tactics

```bash
ixf ttp-list
```

**Output (truncated):**

```
[*] MITRE ATT&CK for ICS — All Techniques
  Tactic                    Technique   Name
  Initial Access            T0817       Drive-by Compromise
  Initial Access            T0819       Exploit Public-Facing Application
  Initial Access            T0822       External Remote Services
  ...
  Execution                 T0807       Command-Line Interface
  Execution                 T0821       Modify Controller Tasking
  ...
  [82 techniques total]
```

---

### Run all techniques for a tactic

```bash
ixf ttp-sweep --tactic "Initial Access" --target 192.168.1.100
```

**Output:**

```
[*] Sweeping tactic: Initial Access (8 techniques)
[*] Running T0817 against 192.168.1.100...
  [SIMULATE] T0817: Drive-by Compromise — watering hole on ICS vendor portal
[*] Running T0819 against 192.168.1.100...
  [SIMULATE] T0819: Exploit Public-Facing Application — internet-exposed HMI
[*] Running T0822 against 192.168.1.100...
  [SIMULATE] T0822: External Remote Services — VPN/RDP without MFA
[... 5 more techniques ...]
[+] Tactic sweep complete: 8/8 techniques assessed.
```

---

### Check a specific technique (read-only probe)

```bash
ixf ttp-check T0843 192.168.1.100
```

**Output:**

```
[*] Checking T0843 (Program Upload) connectivity against 192.168.1.100
[*] Probing S7comm (TCP/102)... OPEN
[*] Probing EtherNet/IP (TCP/44818)... CLOSED
[*] Probing Modbus TCP (TCP/502)... CLOSED
[i] T0843: S7comm port accessible — PLC program upload may be possible
```

---

### Run full TTP coverage (all techniques, simulate)

```bash
ixf ttp-all --target 192.168.1.100 --simulate
```

**Output (truncated):**

```
[*] Running full MITRE ICS TTP coverage (82 techniques)
[*] T0800 Activate Firmware Update Mode...        [SIM] OK
[*] T0801 Monitor Process State...                [SIM] OK
[*] T0802 Automated Collection...                 [SIM] OK
[... 79 more ...]
[+] Full TTP sweep complete: 82/82 techniques simulated.
[+] Report: .tmp/ttp_all_20240601_182500.json
```

---

## ALL mitre Commands

### Show MITRE coverage

```bash
ixf mitre-coverage
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.

  MITRE ATT&CK for ICS Coverage
  ──────────────────────────────────────────────────────────────────
  Tactic                    Total  Covered  %
  Initial Access            9      9        100%
  Execution                 12     11       91.7%
  Persistence               8      8        100%
  Privilege Escalation      5      5        100%
  Evasion                   6      6        100%
  Discovery                 6      6        100%
  Lateral Movement          5      5        100%
  Collection                7      7        100%
  Command and Control       8      7        87.5%
  Inhibit Response Function 14     13       92.9%
  Impair Process Control    10     10       100%
  Impact                    14     13       92.9%
  ──────────────────────────────────────────────────────────────────
  Overall: 82/85 techniques (96.5%)

  Uncovered techniques:
    T0880.001  Modify Alarm Settings — Subtech 1
    T0863      User Execution (manual interaction required)
    T0865      Spearphishing Attachment (email delivery, not applicable)
```

---

### Export ATT&CK Navigator layer

```bash
ixf mitre-report layer
```

**Output:**

```
[*] Generating MITRE ATT&CK Navigator layer...
[+] Layer saved: .tmp/ixf_navigator_layer_20240601.json
[i] Import at: https://mitre-attack.github.io/attack-navigator/
[i] Select: Enterprise ATT&CK → ICS Matrix → Upload layer file
```

---

### Show all modules for a specific technique

```bash
ixf mitre-list T0836
```

**Output:**

```
[*] MITRE T0836 — Modify Parameter
  Tactic: Impair Process Control
  ──────────────────────────────────────────────────────────────────
  IXF Modules implementing T0836:
    cve/malware/frostygoop_modbus_heating          CRITICAL
    cve/malware/triton_safety_bypass               CATASTROPHIC
    exploits/protocols/modbus/modbus_write_coil    HIGH
    exploits/protocols/s7comm/s7_db_write          HIGH
    assessment/mitre_ics/t0836_modify_parameter    INFO
  ──────────────────────────────────────────────────────────────────
  5 modules cover T0836
```

---

### Run a specific technique module

```bash
ixf mitre run T0836 --target 192.168.1.100
```

**Output:**

```
[*] Running all T0836 modules against 192.168.1.100 (simulate mode)
[*] Module 1/5: frostygoop_modbus_heating
  [SIMULATE] FrostyGoop: FC16 writes to register 0x0000 → setpoint = 0
[*] Module 2/5: triton_safety_bypass
  [SIMULATE] TRITON: SIS setpoint override → shutdown threshold raised to 9999
[... 3 more ...]
```

---

### Show MITRE technique detail

```bash
ixf mitre-info T0843
```

**Output:**

```
  T0843 — Program Upload
  ──────────────────────────────────────────────────────────────────
  Tactic:       Collection
  Description:  Adversaries may attempt to upload a program from a PLC
                to gather information about configurations and programming.
  Platforms:    Field Controller/RTU/PLC/IED, Engineering Workstation
  CISA Ref:     https://attack.mitre.org/techniques/T0843/

  Real-world use:
    - TRITON/TRISIS: uploaded SIS program to understand Schneider safety logic
    - Industroyer: uploaded IEC 104 station programs to modify RTU logic
    - Dragonfly/Energetic Bear: uploaded HMI screens from historian

  IXF Modules: 3
    assessment/mitre_ics/t0843_program_upload
    cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
    exploits/protocols/s7comm/s7_program_download
  ──────────────────────────────────────────────────────────────────
```

---

## Shell Piping — 10 Examples

### 1. List all Siemens modules (grep use lines)

```bash
ixf search siemens | grep "use cve"
```

**Output:**

```
  use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key   [CRITICAL]
  use cve/siemens/cve_2019_13945_scalance_auth_bypass     [CRITICAL]
  use cve/siemens/cve_2022_38465_tia_portal_priv_esc      [HIGH]
  [... more ...]
```

---

### 2. Count total CVE modules

```bash
ixf search CVE | wc -l
```

**Output:**

```
614
```

(includes header/footer lines — subtract 4 for module count)

---

### 3. Save search results to file

```bash
ixf search modbus > /tmp/modbus_modules.txt
cat /tmp/modbus_modules.txt
```

---

### 4. Filter CRITICAL modules only

```bash
ixf search siemens | grep CRITICAL
```

**Output:**

```
  use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key   [CRITICAL]
  use cve/siemens/cve_2019_13945_scalance_auth_bypass     [CRITICAL]
  use cve/siemens/cve_2023_44317_scalance_rce             [CRITICAL]
```

---

### 5. Extract module paths for scripting

```bash
ixf search default_creds | grep "use creds" | awk '{print $2}'
```

**Output:**

```
creds/siemens/ssh_default_creds
creds/siemens/web_default_creds
creds/rockwell/logix_default_creds
creds/schneider/web_default_creds
[...]
```

---

### 6. Run all credential modules via xargs

```bash
ixf search default_creds | grep "use creds" | awk '{print $2}' | \
  while read mod; do
    ixf use "$mod" set target 192.168.1.100 run 2>&1 | grep -E "SIMULATE|SUCCESS|ERROR"
  done
```

---

### 7. JSON report piped to jq for severity filter

```bash
ixf report json 2>/dev/null
cat .tmp/ixf_report_*.json | jq '.modules[] | select(.severity == "CRITICAL") | .name'
```

**Output:**

```
"CVE-2021-22681 Siemens S7-1200 Hardcoded Crypto Key"
"CVE-2022-29965 Emerson ROC800 Hardcoded Credentials"
"CVE-2019-13945 Scalance Authentication Bypass"
[...]
```

---

### 8. Count modules per vendor

```bash
for vendor in siemens schneider rockwell ge honeywell abb moxa; do
  count=$(ixf search "$vendor" 2>/dev/null | grep -c "use cve")
  echo "$vendor: $count CVE modules"
done
```

**Output:**

```
siemens: 67
schneider: 48
rockwell: 39
ge: 28
honeywell: 22
abb: 18
moxa: 15
```

---

### 9. Pipe MITRE coverage to grep for gaps

```bash
ixf mitre-coverage | grep "0%\|uncovered\|Uncovered"
```

**Output:**

```
  Uncovered techniques:
    T0880.001  Modify Alarm Settings — Subtech 1
    T0863      User Execution
    T0865      Spearphishing Attachment
```

---

### 10. Chain with tee for live output + log file

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run 2>&1 | \
  tee .tmp/scan_$(date +%Y%m%d_%H%M%S).log
```

---

## Bash Script for Full OT Assessment

```bash
#!/usr/bin/env bash
# IXF Full OT Assessment Script
# Usage: ./ot_assessment.sh <TARGET_IP> [NETWORK_CIDR]
# Example: ./ot_assessment.sh 192.168.1.100 192.168.1.0/24
#
# Runs in simulate mode by default. All traffic is simulated.
# Set LIVE_MODE=1 only in authorized, isolated lab environments.

set -euo pipefail

TARGET="${1:?Usage: $0 <TARGET_IP> [NETWORK_CIDR]}"
NETWORK="${2:-${TARGET%.*}.0/24}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_DIR=".tmp/assessment_${TIMESTAMP}"
LIVE_MODE="${LIVE_MODE:-0}"

mkdir -p "$REPORT_DIR"

echo "════════════════════════════════════════════════════════════"
echo " IXF OT Security Assessment"
echo " Target:  $TARGET"
echo " Network: $NETWORK"
echo " Mode:    $([ "$LIVE_MODE" = "1" ] && echo "LIVE — AUTHORIZED LAB ONLY" || echo "SIMULATE")"
echo " Report:  $REPORT_DIR/"
echo "════════════════════════════════════════════════════════════"
echo ""

# Helper: run ixf command and log output
run_ixf() {
  local label="$1"; shift
  echo "━━━ $label ━━━"
  ixf "$@" 2>&1 | tee "$REPORT_DIR/${label// /_}.txt"
  echo ""
}

# ── Phase 1: Protocol Discovery ──────────────────────────────────
echo "▶ Phase 1: Protocol Discovery"
run_ixf "modbus_scan"    use scanners/ics/modbus_detect    set target "$TARGET" run
run_ixf "s7_scan"        use scanners/ics/s7_comm_scanner  set target "$TARGET" run
run_ixf "bacnet_scan"    use scanners/ics/bacnet_scanner   set target "$TARGET" run
run_ixf "dnp3_scan"      use scanners/ics/dnp3_scanner     set target "$TARGET" run
run_ixf "enip_scan"      use scanners/ics/enip_scanner     set target "$TARGET" run
run_ixf "opcua_scan"     use scanners/ics/opcua_scanner    set target "$TARGET" run
run_ixf "iec104_scan"    use scanners/ics/iec104_scanner   set target "$TARGET" run
run_ixf "codesys_scan"   use scanners/ics/codesys_scanner  set target "$TARGET" run

# ── Phase 2: Credential Assessment ───────────────────────────────
echo "▶ Phase 2: Default Credential Testing"
run_ixf "creds_web"      use creds/generic/web_default_creds  set target "$TARGET" run
run_ixf "creds_ftp"      use creds/generic/ftp_default_creds  set target "$TARGET" run
run_ixf "creds_telnet"   use creds/generic/telnet_default_creds set target "$TARGET" run
run_ixf "creds_ssh"      use creds/generic/ssh_default_creds  set target "$TARGET" run

# ── Phase 3: CVE Scanning ────────────────────────────────────────
echo "▶ Phase 3: CVE Vulnerability Checks (check() only)"
run_ixf "check_s7_key"   use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key \
                         set target "$TARGET" check
run_ixf "check_roc800"   use cve/emerson/cve_2022_29965_roc800_hardcoded \
                         set target "$TARGET" check
run_ixf "check_logix"    use cve/rockwell/cve_2021_27478_logix_hardcoded \
                         set target "$TARGET" check

# ── Phase 4: MITRE ATT&CK Assessment ─────────────────────────────
echo "▶ Phase 4: MITRE ATT&CK for ICS Assessment"
run_ixf "mitre_T0843"    ttp T0843 "$TARGET"
run_ixf "mitre_T0836"    ttp T0836 "$TARGET"
run_ixf "mitre_T0855"    ttp T0855 "$TARGET"
run_ixf "mitre_T0859"    ttp T0859 "$TARGET"
run_ixf "mitre_T0888"    ttp T0888 "$TARGET"

# ── Phase 5: Compliance Assessment ───────────────────────────────
echo "▶ Phase 5: Compliance Assessment"
run_ixf "iec62443"       assess iec62443/zone_conduit_audit
run_ixf "nist_800_82"    assess nist_sp800_82/control_checklist
run_ixf "risk_score"     assess risk/ics_risk_scorer
run_ixf "kill_chain"     assess threat_intel/ics_kill_chain
run_ixf "ir_playbook"    assess ir/iacs_ir_playbook

# ── Phase 6: Protocol Security Audits ────────────────────────────
echo "▶ Phase 6: Protocol Security Audits"
run_ixf "opcua_audit"    use assessment/protocols/opcua_security_audit \
                         set target "$TARGET" run
run_ixf "dnp3_audit"     assess protocols/dnp3_security_audit
run_ixf "iec61850_audit" assess protocols/iec61850_security_audit

# ── Phase 7: Network Assessment ──────────────────────────────────
echo "▶ Phase 7: Network Security Assessment"
run_ixf "fw_audit"       assess network/ics_firewall_audit
run_ixf "net_assess"     assess network/industrial_network_assessment

# ── Phase 8: MITRE Coverage ──────────────────────────────────────
echo "▶ Phase 8: MITRE Coverage Report"
run_ixf "mitre_coverage" mitre-coverage

# ── Phase 9: Generate Reports ────────────────────────────────────
echo "▶ Phase 9: Generating Reports"
ixf report json 2>&1 | tee "$REPORT_DIR/report_json.txt"
ixf report html 2>&1 | tee "$REPORT_DIR/report_html.txt"
run_ixf "navigator_layer" mitre-report layer

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Assessment Complete"
echo " Results: $REPORT_DIR/"
echo " Files:   $(ls "$REPORT_DIR" | wc -l) output files"
echo "════════════════════════════════════════════════════════════"
```

**Usage:**

```bash
chmod +x ot_assessment.sh
./ot_assessment.sh 192.168.1.100
./ot_assessment.sh 192.168.1.100 192.168.1.0/24
```

---

## Python API — 10 Code Examples

### Example 1: Load and run a module in simulate mode

```python
from industrialxpl.core.exploit.utils import import_exploit

cls = import_exploit("industrialxpl.modules.scanners.ics.modbus_detect")
mod = cls()
mod.target = "192.168.1.100"
mod.port = 502
mod.simulate = True  # Default — explicit for clarity

mod.run()  # Prints simulation block
```

---

### Example 2: Run check() (read-only probe)

```python
from industrialxpl.core.exploit.utils import import_exploit

cls = import_exploit("industrialxpl.modules.scanners.ics.modbus_detect")
mod = cls()
mod.target = "192.168.1.100"
mod.port = 502

is_modbus = mod.check()
print("Modbus detected:", is_modbus)  # True / False
```

---

### Example 3: Run live mode (authorized labs only)

```python
from industrialxpl.core.exploit.utils import import_exploit

cls = import_exploit("industrialxpl.modules.scanners.ics.modbus_detect")
mod = cls()
mod.target = "192.168.1.100"
mod.port = 502
mod.simulate = False     # Disable simulation
mod.destructive = True   # Enable live traffic

mod.run()
```

---

### Example 4: Enumerate all modules

```python
from industrialxpl.core.exploit.utils import index_modules, import_exploit

modules = index_modules()
print(f"Total: {len(modules)} modules")

for mod_path in modules[:10]:  # First 10
    cls = import_exploit("industrialxpl.modules." + mod_path)
    info = cls().get_info()
    print(f"  {info['name']} — {info['cve']} — {info['severity']}")
```

---

### Example 5: Filter modules by severity

```python
from industrialxpl.core.exploit.utils import index_modules, import_exploit

modules = index_modules()
critical = []

for mod_path in modules:
    try:
        cls = import_exploit("industrialxpl.modules." + mod_path)
        info = cls().get_info()
        if info.get("severity") in ("CRITICAL", "CATASTROPHIC"):
            critical.append(info)
    except Exception:
        continue

print(f"CRITICAL/CATASTROPHIC modules: {len(critical)}")
for info in critical[:5]:
    print(f"  {info['cve']}: {info['name']}")
```

---

### Example 6: Scan a list of targets

```python
from industrialxpl.core.exploit.utils import import_exploit

targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.5"]

cls = import_exploit("industrialxpl.modules.scanners.ics.modbus_detect")

results = []
for ip in targets:
    mod = cls()
    mod.target = ip
    mod.port = 502
    found = mod.check()
    results.append((ip, found))
    print(f"  {ip}: {'Modbus UP' if found else 'no response'}")

modbus_hosts = [ip for ip, found in results if found]
print(f"\nModbus devices: {modbus_hosts}")
```

---

### Example 7: Programmatic TTP sweep

```python
import sys
sys.path.insert(0, "/path/to/IndustrialXPL-Forge")

from industrialxpl.core.mitre.sweeper import MitreTacticSweeper

sweeper = MitreTacticSweeper()

# Sweep a single technique
results = sweeper.sweep_technique(
    technique_id="T0843",
    target="192.168.1.100",
    simulate=True,
    stop_on_first=False,
)
for r in results:
    print(f"  {r['module']}: {r['result']}")
```

---

### Example 8: Sweep a full tactic

```python
from industrialxpl.core.mitre.sweeper import MitreTacticSweeper

sweeper = MitreTacticSweeper()

# Sweep all Discovery techniques
results = sweeper.sweep_tactic(
    tactic="Discovery",
    target="192.168.1.100",
    simulate=True,
)

print(f"Techniques swept: {len(results)}")
for r in results:
    print(f"  [{r['technique']}] {r['module']}: {r['status']}")
```

---

### Example 9: Export JSON report programmatically

```python
import json
from industrialxpl.core.exploit.utils import index_modules, import_exploit

modules = index_modules()
report = {"modules": [], "stats": {}}

for mod_path in modules:
    try:
        cls = import_exploit("industrialxpl.modules." + mod_path)
        info = cls().get_info()
        report["modules"].append({
            "path":    mod_path,
            "name":    info.get("name"),
            "cve":     info.get("cve"),
            "cvss":    info.get("cvss"),
            "severity": info.get("severity"),
            "mitre":   info.get("mitre_techniques"),
        })
    except Exception:
        continue

report["stats"]["total"] = len(report["modules"])
report["stats"]["critical"] = sum(
    1 for m in report["modules"]
    if m["severity"] in ("CRITICAL", "CATASTROPHIC")
)

with open(".tmp/ixf_api_report.json", "w") as f:
    json.dump(report, f, indent=2)

print(f"Report: {len(report['modules'])} modules written to .tmp/ixf_api_report.json")
```

---

### Example 10: Concurrent multi-host scan

```python
import concurrent.futures
from industrialxpl.core.exploit.utils import import_exploit

def probe_host(ip: str, module_path: str, port: int) -> dict:
    """Probe one host with one module. Returns result dict."""
    try:
        cls = import_exploit("industrialxpl.modules." + module_path)
        mod = cls()
        mod.target = ip
        mod.port = port
        result = mod.check()
        return {"ip": ip, "module": module_path, "found": result}
    except Exception as e:
        return {"ip": ip, "module": module_path, "found": False, "error": str(e)}

# Build work items: (ip, module, port) tuples
targets = [f"192.168.1.{i}" for i in range(1, 50)]
work = [(ip, "scanners.ics.modbus_detect", 502) for ip in targets]

results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    futures = [executor.submit(probe_host, ip, mod, port) for ip, mod, port in work]
    for future in concurrent.futures.as_completed(futures):
        r = future.result()
        results.append(r)
        if r["found"]:
            print(f"[+] Modbus found: {r['ip']}")

found = [r for r in results if r["found"]]
print(f"\nScan complete: {len(found)}/{len(targets)} Modbus devices found")
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/ixf-validation.yml
name: IXF Module Validation

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  validate-modules:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install IXF
        run: pip install -e ".[dev]"

      - name: Validate all modules
        run: |
          python -c "
          from industrialxpl.core.exploit.utils import index_modules, import_exploit
          import sys

          mods = index_modules()
          print(f'Indexing {len(mods)} modules...')

          errs = []
          for m in mods:
              try:
                  cls = import_exploit('industrialxpl.modules.' + m)
                  obj = cls()
                  info = obj.get_info()
                  required = ['name','description','authors','references','devices',
                              'impact','exploit_type','source_poc','cve','cvss',
                              'severity','mitre_techniques','mitre_tactics']
                  missing = [k for k in required if k not in info]
                  if missing:
                      errs.append((m, 'Missing: ' + ', '.join(missing)))
              except Exception as e:
                  errs.append((m, str(e)))

          print(f'{len(mods)} modules | {len(errs)} errors')
          if errs:
              for m, e in errs:
                  print(f'  ERR {m}: {e}')
              sys.exit(1)
          else:
              print('All modules valid.')
          "

      - name: Run simulate mode on key modules
        run: |
          ixf use scanners/ics/modbus_detect set target 127.0.0.1 run
          ixf use assessment/iec62443/zone_conduit_audit run
          ixf mitre-coverage

      - name: Assert module count
        run: |
          python -c "
          from industrialxpl.core.exploit.utils import index_modules
          mods = index_modules()
          assert len(mods) >= 900, f'Expected 900+ modules, got {len(mods)}'
          print(f'Module count OK: {len(mods)}')
          "

      - name: Generate coverage report
        run: |
          ixf mitre-coverage
          ixf report json
          ixf mitre-report layer

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: ixf-reports
          path: .tmp/
```

---

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent { label 'linux' }

    environment {
        TARGET = '192.168.1.100'
        SIMULATE = 'true'
    }

    stages {
        stage('Setup') {
            steps {
                sh 'pip install -e .[dev]'
            }
        }

        stage('Module Validation') {
            steps {
                sh '''
                python -c "
                from industrialxpl.core.exploit.utils import index_modules, import_exploit
                mods = index_modules()
                errs = []
                for m in mods:
                    try: import_exploit('industrialxpl.modules.' + m)()
                    except Exception as e: errs.append((m, str(e)))
                print(f'{len(mods)} modules | {len(errs)} errors')
                if errs:
                    for m,e in errs: print(f'ERR {m}: {e}')
                    exit(1)
                "
                '''
            }
        }

        stage('Protocol Discovery') {
            steps {
                sh "ixf use scanners/ics/modbus_detect set target ${TARGET} run"
                sh "ixf use scanners/ics/s7_comm_scanner set target ${TARGET} run"
                sh "ixf use scanners/ics/bacnet_scanner set target ${TARGET} run"
            }
        }

        stage('MITRE Coverage') {
            steps {
                sh 'ixf mitre-coverage'
                sh 'ixf mitre-report layer'
            }
        }

        stage('Compliance Assessment') {
            steps {
                sh 'ixf assess iec62443/zone_conduit_audit'
                sh 'ixf assess nist_sp800_82/control_checklist'
                sh 'ixf assess risk/ics_risk_scorer'
            }
        }

        stage('Report') {
            steps {
                sh 'ixf report json'
                sh 'ixf report html'
                archiveArtifacts artifacts: '.tmp/*.json,.tmp/*.html', fingerprint: true
            }
        }
    }

    post {
        always {
            junit '.tmp/test_results.xml'
        }
        failure {
            mail to: 'security@company.com',
                 subject: "IXF Validation Failed: ${currentBuild.fullDisplayName}",
                 body: "Build failed. Check: ${env.BUILD_URL}"
        }
    }
}
```

---

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - validate
  - scan
  - report

variables:
  TARGET: "192.168.1.100"
  SIMULATE: "true"

default:
  image: python:3.11-slim
  before_script:
    - pip install -e ".[dev]" --quiet

validate-modules:
  stage: validate
  script:
    - |
      python -c "
      from industrialxpl.core.exploit.utils import index_modules, import_exploit
      import sys
      mods = index_modules()
      errs = []
      for m in mods:
          try: import_exploit('industrialxpl.modules.' + m)()
          except Exception as e: errs.append((m, str(e)))
      print(f'{len(mods)} modules | {len(errs)} errors')
      if errs:
          for m,e in errs: print(f'ERR {m}: {e}')
          sys.exit(1)
      "
  artifacts:
    reports:
      junit: .tmp/module_validation.xml

protocol-discovery:
  stage: scan
  script:
    - ixf use scanners/ics/modbus_detect set target $TARGET run
    - ixf use scanners/ics/s7_comm_scanner set target $TARGET run
    - ixf use scanners/ics/bacnet_scanner set target $TARGET run

mitre-assessment:
  stage: scan
  script:
    - ixf mitre-coverage
    - ixf ttp T0843 $TARGET
    - ixf ttp T0836 $TARGET
    - ixf assess iec62443/zone_conduit_audit
    - ixf assess nist_sp800_82/control_checklist

generate-report:
  stage: report
  script:
    - ixf report json
    - ixf report html
    - ixf mitre-report layer
  artifacts:
    paths:
      - .tmp/*.json
      - .tmp/*.html
    expire_in: 30 days
```

---

## Exit Codes

| Code | Name | When It Occurs | Example Trigger |
|------|------|---------------|-----------------|
| `0` | Success | All commands completed successfully | `ixf stats` |
| `1` | General error | Import failure, missing Python dependency | `pip` package not installed |
| `2` | Module validation error | `__info__` missing required keys, import syntax error | Broken module file |
| `3` | Target not reachable | `check()` returns False in non-simulate mode when strict | `ixf use mod check` with offline target |
| `4` | Configuration error | Invalid option value (bad IP format, port out of range) | `set port 99999` |
| `5` | Module not found | `use <path>` does not match any indexed module | Typo in module path |
| `10` | Simulate mode active | Live mode command rejected (simulate=True) | Attempting live run with `simulate=True` |
| `42` | Destructive gate | Live exploit requires `destructive=True` not set | `run` without `set destructive True` |
| `127` | ixf not found | `ixf` binary not in PATH | pip install not complete |
| `130` | User interrupt | Ctrl+C during execution | Manual keyboard interrupt |

**Using exit codes in scripts:**

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 check
EXIT_CODE=$?

case $EXIT_CODE in
  0)  echo "Check completed successfully" ;;
  3)  echo "Target not reachable — check network connectivity" ;;
  5)  echo "Module not found — check path" ;;
  *)  echo "Unexpected exit code: $EXIT_CODE" ;;
esac
```

---

## JSON Output Piping with jq

Generate a JSON report then query it with `jq`:

```bash
# Generate report
ixf report json

# Find the report file
REPORT=$(ls -t .tmp/ixf_report_*.json | head -1)

# List all CRITICAL modules
jq '.modules[] | select(.severity == "CRITICAL") | {name, cve, cvss}' "$REPORT"

# Count by severity
jq '.modules | group_by(.severity) | map({severity: .[0].severity, count: length})' "$REPORT"

# List all modules for a specific MITRE technique
jq '.modules[] | select(.mitre_techniques | contains(["T0836"])) | .name' "$REPORT"

# List all CVEs with CVSS >= 9.0
jq '.modules[] | select(.cvss != "N/A" and (.cvss | tonumber) >= 9.0) | {name, cve, cvss}' "$REPORT"

# Export vendor list
jq '.modules[].devices | .[]' "$REPORT" | sort -u

# Count by exploit_type
jq '[.modules[].exploit_type] | group_by(.) | map({type: .[0], count: length}) | sort_by(-.count)' "$REPORT"
```

**Sample jq output (severity count):**

```json
[
  {"severity": "HIGH",        "count": 341},
  {"severity": "CRITICAL",    "count": 287},
  {"severity": "MEDIUM",      "count": 198},
  {"severity": "LOW",         "count": 87},
  {"severity": "INFO",        "count": 55},
  {"severity": "CATASTROPHIC","count": 8}
]
```

---

## Batch File Scanning with file:// Targets

Run modules against a list of targets stored in a file:

```bash
# Create targets file (one IP per line)
cat > .tmp/targets.txt << 'EOF'
192.168.1.100
192.168.1.101
192.168.1.102
10.0.0.5
10.0.0.6
EOF

# Run a module against each target
while IFS= read -r ip; do
  echo "=== Testing $ip ==="
  ixf use scanners/ics/modbus_detect set target "$ip" check
done < .tmp/targets.txt
```

**Using file:// in Python API:**

```python
from pathlib import Path
from industrialxpl.core.exploit.utils import import_exploit

# Load targets
targets = Path(".tmp/targets.txt").read_text().strip().splitlines()
targets = [t.strip() for t in targets if t.strip() and not t.startswith("#")]

cls = import_exploit("industrialxpl.modules.scanners.ics.modbus_detect")

print(f"Scanning {len(targets)} targets...")
results = []
for ip in targets:
    mod = cls()
    mod.target = ip
    found = mod.check()
    results.append({"ip": ip, "modbus": found})
    status = "[+]" if found else "[-]"
    print(f"  {status} {ip}: {'Modbus UP' if found else 'no response'}")

# Save results
import json
Path(".tmp/batch_results.json").write_text(json.dumps(results, indent=2))
print(f"\nResults saved to .tmp/batch_results.json")
```

**Multi-protocol batch scan script:**

```bash
#!/usr/bin/env bash
# Multi-protocol batch scan from file
# Usage: ./batch_scan.sh targets.txt

TARGETS_FILE="${1:-.tmp/targets.txt}"
PROTOCOLS=("modbus_detect:502" "s7_comm_scanner:102" "bacnet_scanner:47808" "dnp3_scanner:20000")

while IFS= read -r ip; do
  [[ -z "$ip" || "$ip" == \#* ]] && continue
  echo ""
  echo "━━━ Target: $ip ━━━"
  for proto_port in "${PROTOCOLS[@]}"; do
    proto="${proto_port%%:*}"
    port="${proto_port##*:}"
    result=$(ixf use "scanners/ics/$proto" set target "$ip" check 2>&1)
    if echo "$result" | grep -q "True"; then
      echo "  [+] $proto (port $port): OPEN"
    else
      echo "  [-] $proto (port $port): closed"
    fi
  done
done < "$TARGETS_FILE"
```

---

*Previous: [Module Development](09-module-development.md) | Next: [PolyExploit Runner](11-poly-exploit-runner.md)*
