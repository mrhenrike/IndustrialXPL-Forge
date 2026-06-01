# MITRE ATT&CK for ICS

IXF integrates MITRE ATT&CK for ICS v19, mapping 976+ modules to 74 of 90 techniques (82% coverage) across all 12 tactics.

---

## Tactic Overview

| Tactic ID | Tactic Name | Techniques | IXF Coverage |
|-----------|-------------|-----------|--------------|
| TA0108 | Initial Access | 9 | 100% |
| TA0104 | Execution | 9 | 88% |
| TA0110 | Persistence | 8 | 75% |
| TA0111 | Privilege Escalation | 2 | 100% |
| TA0103 | Evasion | 5 | 80% |
| TA0102 | Discovery | 13 | 84% |
| TA0109 | Lateral Movement | 3 | 100% |
| TA0100 | Collection | 9 | 88% |
| TA0101 | Command and Control | 3 | 100% |
| TA0107 | Inhibit Response Function | 18 | 77% |
| TA0106 | Impair Process Control | 11 | 81% |
| TA0105 | Impact | 11 | 72% |

**Total: 74/90 (82%)**

---

## Tactic Aliases

The shell accepts multiple forms when specifying tactics:

| Canonical Name | Accepted Aliases |
|----------------|-----------------|
| Initial Access | `initial-access`, `initial_access`, `ia` |
| Execution | `execution`, `exec` |
| Persistence | `persistence` |
| Privilege Escalation | `privilege-escalation`, `privesc`, `pe` |
| Evasion | `evasion`, `defense-evasion` |
| Discovery | `discovery` |
| Lateral Movement | `lateral-movement`, `lateral`, `lm` |
| Collection | `collection` |
| Command and Control | `command-and-control`, `c2`, `c&c` |
| Inhibit Response Function | `inhibit`, `inhibit-response`, `irf` |
| Impair Process Control | `impair`, `impair-process`, `ipc` |
| Impact | `impact` |

---

## `ttp` — Execute a Technique

Run all modules mapped to a specific MITRE technique against a target.

```
ixf > ttp T0843 192.168.1.100
[*] TTP T0843 (Program Download) — 12 modules — target: 192.168.1.100 — simulate=True
[*] [1/12] cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
  [SIMULATE] CVE-2021-22681: S7comm+ TLS key extraction
[*] [2/12] cve/rockwell/cve_2022_1161_controllogix_modified_fw
  [SIMULATE] CVE-2022-1161: ControlLogix firmware modification
...
[+] T0843 sweep complete: 12 modules, 0 errors
```

**With flags:**

```
# Stop after first check() returns True
ixf > ttp T0859 192.168.1.100 --stop-on-first

# Rate limit to 500ms between modules
ixf > ttp T0836 10.0.0.0/24 --rate-limit 500

# Save results to file
ixf > ttp T0866 192.168.1.100 --output /tmp/t0866_results.json

# Live run (authorized labs only)
ixf > ttp T0839 192.168.1.100 --destructive
```

---

## `mitre-scan` — Tactic Sweep

Run all techniques of an entire tactic against a target or subnet.

```
ixf > mitre-scan discovery 192.168.1.0/24
[*] Sweeping tactic: Discovery (TA0102) on 192.168.1.0/24
[*] simulate=True (safe mode)
[*] T0840 Network Connection Enumeration — 2 modules...
[*] T0842 Network Sniffing — 3 modules...
[*] T0846 Remote System Discovery — 8 modules...
[*] T0861 Point and Tag Identification — 2 modules...
...
[+] Tactic sweep complete: 11 techniques, 34 modules — 3 potential matches
```

```
ixf > mitre-scan T0843 192.168.1.100
[*] Single technique T0843 (Program Download) on 192.168.1.100...
```

---

## `mitre-all` — Full Sweep

Run all 74+ mapped techniques in simulate mode only:

```
ixf > mitre-all 192.168.1.100
[*] Full MITRE ATT&CK for ICS sweep (simulate=True)
[*] Target: 192.168.1.100
[*] Running 74 techniques across 12 tactics...
[*] [TA0108] Initial Access...
[*]   T0817 Drive-by Compromise — 3 modules
[*]   T0819 Exploit Public-Facing Application — 47 modules
...
[+] Full sweep complete: 74 techniques, 850+ module runs
```

---

## `mitre-coverage` — Coverage Report

```
ixf > mitre-coverage

  MITRE ATT&CK for ICS Coverage
  ──────────────────────────────────────────────────────────────────
  Tactic                                   Covered  Total  Pct
  Initial Access (TA0108)                     9       9    100%
  Execution (TA0104)                          8       9     88%
  Persistence (TA0110)                        6       8     75%
  Privilege Escalation (TA0111)               2       2    100%
  Evasion (TA0103)                            4       5     80%
  Discovery (TA0102)                         11      13     84%
  Lateral Movement (TA0109)                   3       3    100%
  Collection (TA0100)                         8       9     88%
  Command and Control (TA0101)                3       3    100%
  Inhibit Response Function (TA0107)         14      18     77%
  Impair Process Control (TA0106)             9      11     81%
  Impact (TA0105)                             8      11     72%
  ──────────────────────────────────────────────────────────────────
  TOTAL                                      74      90     82%
```

---

## `mitre-report` — Export

### ATT&CK Navigator Layer (default)

```
ixf > mitre-report layer
[+] ATT&CK Navigator layer saved: ixf_mitre_layer_20260601.json
[i] Open at: https://mitre-attack.github.io/attack-navigator/
```

The JSON layer file can be loaded into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize coverage. Covered techniques are highlighted, color-coded by impact level.

### HTML Report

```
ixf > mitre-report html
[+] MITRE ICS coverage report: ixf_mitre_report_20260601.html
```

### JSON Data

```
ixf > mitre-report json
[+] MITRE coverage data: ixf_mitre_data_20260601.json
```

---

## `mitre-list` — Technique Index

```
ixf > mitre-list
  MITRE ATT&CK for ICS — Technique Index
  ─────────────────────────────────────────────────────────────────────
  T0801  Monitor Process State            2 modules  [Collection]
  T0802  Automated Collection             5 modules  [Collection]
  T0803  Block Command Message            3 modules  [Inhibit Response]
  T0806  Brute Force I/O                  1 module   [Impair Process]
  T0807  Remote Services                  8 modules  [Lateral Movement]
  T0809  Disk Wipe                        3 modules  [Impact]
  T0810  Data Destruction                 2 modules  [Impact]
  ...

ixf > mitre-list --tactic collection
  MITRE ATT&CK for ICS — Collection (TA0100)
  ─────────────────────────────────────────────────────────────────────
  T0801  Monitor Process State            2 modules
  T0802  Automated Collection             5 modules
  T0811  Data from Information Repos      4 modules
  T0832  Manipulation of View            3 modules
  ...
```

---

## `ttp-list` — TTP Browser

```
ixf > ttp-list
  TTP Index — all techniques
  ─────────────────────────────────────────────────────────────────────
  T0801  Monitor Process State           2 modules   [Collection]
  T0802  Automated Collection            5 modules   [Collection]
  ...

ixf > ttp-list --tactic evasion
  TTP Index — Evasion (TA0103)
  ─────────────────────────────────────────────────────────────────────
  T0820  Exploitation of Remote Services  3 modules
  T0849  Masquerading                     1 module
  T0856  Spoof Reporting Message          2 modules
  T0858  Change Credential               4 modules
  T0874  Hooking                         1 module
```

---

## Assessment Modules by Technique

Individual MITRE technique assessment modules are in `assessment/mitre_ics/`:

```
ixf > use assessment/mitre_ics/t0843_program_upload
ixf > set target 192.168.1.100
ixf > run

  [SIMULATE MODE — no packets sent]
  MITRE T0843: Program Upload
  Adversary uploads/extracts PLC programs from controllers to analyze logic.

  Step 1: Connect to PLC engineering port (S7:102, EtherNet/IP:44818)
  Step 2: Issue program upload command without authentication
  Step 3: Download full PLC program to local file
  Step 4: Analyze program for safety system logic and critical setpoints
```

---

## Selected Technique-to-Module Mapping

| Technique | ID | Example Modules |
|-----------|-----|-----------------|
| Exploit Public-Facing App | T0819 | 47 CVE modules (Siemens, Rockwell, Schneider...) |
| Drive-by Compromise | T0817 | `cve.malware.kamacite_spearphishing` |
| Default Credentials | T0859 | `creds/siemens/*`, `creds/schneider/*`, 37 vendors |
| Program Download | T0843 | `cve.siemens.cve_2022_1161_controllogix_modified_fw` |
| Modify Parameter | T0836 | `exploits.protocols.modbus.modbus_unauthorized_coil_set` |
| Denial of Control | T0813 | `exploits.protocols.modbus.modbus_broadcast_flood` |
| Alarm Suppression | T0880 | `assessment.mitre_ics.t0878_alarm_suppression` |
| Loss of Availability | T0826 | `cve.malware.notpetya_destructive_wiper` |
| Damage to Property | T0879 | `assessment.mitre_ics.t0879_damage_to_property` |
| Rootkit | T0851 | `assessment.mitre_ics.t0851_rootkit` |
| Firmware Modification | T0839 | `cve.rockwell.cve_2022_1161_controllogix_modified_fw` |
| Safety Instrumented System Compromise | T0816 | `cve.malware.triton_trisis_sis_attack` |

---

*Previous: [SafeMode / DestructiveMode](05-safemode-destructivemode.md) | Next: [SAST / LLM Analysis](07-sast-llm.md)*
