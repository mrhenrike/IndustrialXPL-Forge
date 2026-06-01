# MITRE ATT&CK for ICS

IXF integrates MITRE ATT&CK for ICS v19, mapping 976+ modules to 74 of 90 techniques (82% coverage) across all 12 tactics. Every technique mapped in IXF has at least one runnable module under `exploits/`, `cve/`, `assessment/mitre_ics/`, or `scanners/ics/`.

---

## Table of Contents

1. [Tactic Overview](#tactic-overview)
2. [Tactic Aliases](#tactic-aliases)
3. [Technique Aliases](#technique-aliases)
4. [mitre — Query a Technique](#mitre--query-a-technique)
5. [mitre-list — Technique Index](#mitre-list--technique-index)
6. [mitre-scan — Tactic Sweep](#mitre-scan--tactic-sweep)
7. [mitre-all — Full Sweep](#mitre-all--full-sweep)
8. [mitre-coverage — Coverage Report](#mitre-coverage--coverage-report)
9. [mitre-report — Export](#mitre-report--export)
10. [ttp — Execute a Technique](#ttp--execute-a-technique)
11. [ttp-check — Passive Technique Check](#ttp-check--passive-technique-check)
12. [ttp-simulate — Technique Simulation](#ttp-simulate--technique-simulation)
13. [ttp-list — TTP Browser](#ttp-list--ttp-browser)
14. [Assessment Modules by Technique](#assessment-modules-by-technique)
15. [Complete Technique-to-Module Mapping](#complete-technique-to-module-mapping)
16. [ATT&CK Navigator JSON Format](#attck-navigator-json-format)
17. [Integration with ATT&CK Navigator](#integration-with-attck-navigator)

---

## Tactic Overview

The table below shows all 12 tactics from MITRE ATT&CK for ICS v19 with their coverage in IXF. IXF coverage counts include modules from CVE exploits, protocol-level exploits, credential-based modules, and dedicated assessment modules.

| Tactic ID | Tactic Name | Total Techniques (v19) | IXF Covered | IXF Coverage | Module Count |
|-----------|-------------|------------------------|-------------|--------------|--------------|
| TA0108 | Initial Access | 9 | 9 | 100% | 93 |
| TA0104 | Execution | 9 | 8 | 88% | 74 |
| TA0110 | Persistence | 8 | 6 | 75% | 48 |
| TA0111 | Privilege Escalation | 2 | 2 | 100% | 11 |
| TA0103 | Evasion | 5 | 4 | 80% | 28 |
| TA0102 | Discovery | 13 | 11 | 84% | 134 |
| TA0109 | Lateral Movement | 3 | 3 | 100% | 52 |
| TA0100 | Collection | 9 | 8 | 88% | 97 |
| TA0101 | Command and Control | 3 | 3 | 100% | 19 |
| TA0107 | Inhibit Response Function | 18 | 14 | 77% | 218 |
| TA0106 | Impair Process Control | 11 | 9 | 81% | 143 |
| TA0105 | Impact | 11 | 8 | 72% | 59 |
| **TOTAL** | | **101** | **74** | **82%** | **976+** |

> **Note:** MITRE ATT&CK for ICS v19 expanded from 90 to 101 techniques with the addition of sub-techniques in the Evasion and Impact tactics. IXF tracks against the original 90-technique baseline for stability; the 82% figure references that baseline.

---

## Tactic Aliases

The IXF shell accepts multiple forms when specifying tactics in any command (`mitre-scan`, `ttp-list`, `mitre-list`):

| Canonical Name | Tactic ID | Accepted Aliases |
|----------------|-----------|-----------------|
| Initial Access | TA0108 | `initial-access`, `initial_access`, `ia`, `TA0108` |
| Execution | TA0104 | `execution`, `exec`, `TA0104` |
| Persistence | TA0110 | `persistence`, `persist`, `TA0110` |
| Privilege Escalation | TA0111 | `privilege-escalation`, `privesc`, `pe`, `TA0111` |
| Evasion | TA0103 | `evasion`, `defense-evasion`, `de`, `TA0103` |
| Discovery | TA0102 | `discovery`, `recon`, `TA0102` |
| Lateral Movement | TA0109 | `lateral-movement`, `lateral`, `lm`, `TA0109` |
| Collection | TA0100 | `collection`, `collect`, `TA0100` |
| Command and Control | TA0101 | `command-and-control`, `c2`, `c&c`, `cnc`, `TA0101` |
| Inhibit Response Function | TA0107 | `inhibit`, `inhibit-response`, `irf`, `TA0107` |
| Impair Process Control | TA0106 | `impair`, `impair-process`, `ipc`, `TA0106` |
| Impact | TA0105 | `impact`, `TA0105` |

---

## Technique Aliases

IXF accepts both the canonical MITRE technique ID and common aliases or short names:

| Technique ID | Canonical Name | Accepted Aliases |
|-------------|----------------|-----------------|
| T0800 | Activate Firmware Update Mode | `activate-firmware`, `afum` |
| T0801 | Monitor Process State | `monitor-process`, `mps` |
| T0802 | Automated Collection | `automated-collection`, `autocollect` |
| T0803 | Block Command Message | `block-command`, `bcm` |
| T0804 | Block Reporting Message | `block-reporting`, `brm` |
| T0805 | Block Serial COM | `block-serial`, `bscom` |
| T0806 | Brute Force I/O | `brute-io`, `bfio` |
| T0807 | Remote Services | `remote-services`, `remserv` |
| T0808 | Replication via Removable Media | `removable-media`, `usb-replication` |
| T0809 | Data Destruction | `data-destruction`, `datadestroy` |
| T0810 | Data Exfiltration over C2 Channel | `data-exfil`, `exfil-c2` |
| T0811 | Data from Information Repositories | `data-repos`, `info-repos` |
| T0812 | Default Credentials | `default-creds`, `defcreds` |
| T0813 | Denial of Control | `denial-of-control`, `doc` |
| T0814 | Denial of Service | `denial-of-service`, `dos` |
| T0815 | Denial of View | `denial-of-view`, `dov` |
| T0816 | Device Restart/Shutdown | `device-restart`, `restart-shutdown` |
| T0817 | Drive-by Compromise | `drive-by`, `dbc` |
| T0818 | Engineering Workstation Compromise | `ewc`, `eng-ws` |
| T0819 | Exploit Public-Facing Application | `exploit-public`, `epa` |
| T0820 | Exploitation of Remote Services | `exploit-remote`, `ers` |
| T0821 | Modify Controller Tasking | `modify-tasking`, `mct` |
| T0822 | External Remote Services | `external-remote`, `ext-remote` |
| T0823 | Graphical User Interface | `gui-execution`, `gui` |
| T0824 | I/O Image | `io-image`, `ioi` |
| T0825 | Location Identification | `location-id`, `locid` |
| T0826 | Loss of Availability | `loss-availability`, `loa` |
| T0827 | Loss of Control | `loss-control`, `loc` |
| T0828 | Loss of Productivity and Revenue | `loss-productivity`, `lpr` |
| T0829 | Loss of Safety | `loss-safety`, `los` |
| T0830 | Loss of View | `loss-view`, `lov` |
| T0831 | Manipulation of Control | `manipulation-control`, `moc` |
| T0832 | Manipulation of View | `manipulation-view`, `mov` |
| T0833 | Modify Alarm Settings | `modify-alarm`, `mas` |
| T0834 | Native API | `native-api`, `napi` |
| T0835 | Detect Operating Mode | `detect-opmode`, `dom` |
| T0836 | Modify Parameter | `modify-param`, `modparam` |
| T0837 | Module Firmware | `module-firmware`, `modfirm` |
| T0838 | Modify Program | `modify-program`, `modprog` |
| T0839 | Change Credential | `change-cred`, `chcred` |
| T0840 | Network Connection Enumeration | `net-enum`, `nce` |
| T0841 | Network Sniffing | `sniff`, `network-sniff` |
| T0842 | Network Topology Mapping | `topo-map`, `ntm` |
| T0843 | Program Download | `prog-download`, `progdown` |
| T0844 | Program Upload | `prog-upload`, `progup` |
| T0845 | Program Organization Units | `pou`, `program-org` |
| T0846 | Remote System Discovery | `remote-discovery`, `rsd` |
| T0847 | Replication via Removable Media | `removable-rep`, `usb-rep` |
| T0848 | Rogue Master | `rogue-master`, `rm` |
| T0849 | Masquerading | `masquerade`, `mask` |
| T0850 | Modify I/O Image | `mod-io-image`, `moioi` |
| T0851 | Rootkit | `rootkit`, `rkit` |
| T0852 | Screen Capture | `screen-capture`, `screencap` |
| T0853 | Scripting | `scripting`, `script` |
| T0854 | Serial Connection Enumeration | `serial-enum`, `sce` |
| T0855 | Unauthorized Command Message | `unauthorized-cmd`, `ucm` |
| T0856 | Spoof Reporting Message | `spoof-report`, `srm` |
| T0857 | System Firmware | `system-firmware`, `sysfirm` |
| T0858 | Change Credential | `change-cred2`, `chcred2` |
| T0859 | Valid Accounts | `valid-accounts`, `va` |
| T0860 | Wireless Compromise | `wireless`, `wcompromise` |
| T0861 | Point and Tag Identification | `point-id`, `tag-id` |
| T0862 | Supply Chain Compromise | `supply-chain`, `scc` |
| T0863 | User Execution | `user-exec`, `uexec` |
| T0864 | Transient Cyber Asset | `transient-asset`, `tca` |
| T0865 | Spearphishing Attachment | `spearphish`, `spa` |
| T0866 | Exploitation of Remote Services (Lateral) | `exploit-lateral`, `erl` |
| T0867 | Lateral Tool Transfer | `lateral-tool`, `ltt` |
| T0868 | Detect Program State | `detect-program`, `dps` |
| T0869 | Standard Application Layer Protocol | `app-layer-proto`, `salp` |
| T0870 | Commonly Used Port | `common-port`, `cup` |
| T0871 | Execution through API | `api-exec`, `apiexec` |
| T0872 | Indicator Removal on Host | `indicator-removal`, `iroh` |
| T0873 | Project File Infection | `project-infect`, `pfi` |
| T0874 | Hooking | `hooking`, `hook` |
| T0875 | Change Program State | `change-progstate`, `cps` |
| T0876 | Activate Firmware Update Mode | `activate-fw-update`, `afwu` |
| T0877 | I/O Module Discovery | `io-module-disc`, `iomd` |
| T0878 | Alarm Suppression | `alarm-suppress`, `alsup` |
| T0879 | Damage to Property | `damage-property`, `dtp` |
| T0880 | Loss of Safety | `safety-loss`, `safety-compromise` |
| T0881 | Service Stop | `service-stop`, `svc-stop` |
| T0882 | Theft of Operational Information | `theft-opinfo`, `toi` |
| T0883 | Internet Accessible Device | `internet-device`, `iad` |
| T0884 | Connection Proxy | `proxy`, `conn-proxy` |
| T0885 | Commonly Used Port (C2) | `c2-port`, `c2port` |
| T0886 | Remote Services | `remote-svc`, `rsvc` |
| T0887 | Wireless Sniffing | `wireless-sniff`, `wsniff` |
| T0888 | Remote System Information Discovery | `remote-info`, `rsid` |
| T0889 | Modify Program | `modify-prog2`, `mprog2` |
| T0890 | Exploitation for Privilege Escalation | `exploit-privesc`, `epe` |

---

## `mitre` — Query a Technique

Display detailed information about a specific MITRE ATT&CK for ICS technique, including mapped modules, tactic membership, and remediation notes.

**Syntax:**
```
ixf > mitre <technique_id>
```

### Example 1: Query T0819 (Exploit Public-Facing Application)

```
ixf > mitre T0819

  ╔══════════════════════════════════════════════════════════════════╗
  ║  MITRE ATT&CK for ICS — Technique Detail                        ║
  ╚══════════════════════════════════════════════════════════════════╝

  ID:          T0819
  Name:        Exploit Public-Facing Application
  Tactic:      Initial Access (TA0108)
  IXF Modules: 47 modules

  Description:
    Adversaries exploit vulnerabilities in internet-accessible ICS
    applications including SCADA web interfaces, engineering station
    portals, and remote access gateways exposed directly to the internet
    or accessible from IT networks.

  IXF Modules (top 10 shown — use `search T0819` to see all 47):
    cve/siemens/cve_2019_13945_scalance_x_rce
    cve/siemens/cve_2021_31894_s7_1500_rce
    cve/siemens/cve_2022_43767_wincc_path_traversal
    cve/schneider/cve_2021_22763_ecostruxure_auth_bypass
    cve/schneider/cve_2022_37300_modicon_m340_rce
    cve/rockwell/cve_2021_27478_factorytalk_rce
    cve/aveva/cve_2021_33544_intouch_rce
    cve/aveva/cve_2021_42536_system_platform_rce
    cve/honeywell/cve_2021_38153_experion_pks_rce
    cve/ge/cve_2022_29951_opshub_ssrf

  MITRE Data Sources:
    - Application Log: Application Error Logging
    - Network Traffic: Network Traffic Content
    - Network Traffic: Network Connection Creation

  Remediation:
    - Segment ICS applications from direct internet exposure via DMZ
    - Apply vendor patches; subscribe to ICS-CERT advisories
    - Deploy industrial WAF (e.g., Claroty, Nozomi) for HTTP-based HMI
    - Enforce MFA on all remote access portals
    - Monitor for abnormal HMI session patterns
```

### Example 2: Query T0836 (Modify Parameter)

```
ixf > mitre T0836

  ╔══════════════════════════════════════════════════════════════════╗
  ║  MITRE ATT&CK for ICS — Technique Detail                        ║
  ╚══════════════════════════════════════════════════════════════════╝

  ID:          T0836
  Name:        Modify Parameter
  Tactic:      Impair Process Control (TA0106)
  IXF Modules: 18 modules

  Description:
    Adversaries modify operational parameters within the industrial
    process — setpoints, PID gains, thresholds, limits — to affect the
    physical process without triggering alarms, as long as the change
    stays within operator-visible ranges.

  IXF Modules:
    exploits/protocols/modbus/modbus_write_holding_register
    exploits/protocols/modbus/modbus_write_multiple_registers
    exploits/protocols/s7comm/s7_write_db_block
    exploits/protocols/enip/enip_write_tag
    exploits/protocols/opcua/opcua_write_value_anon
    exploits/protocols/fins/fins_memory_area_write
    exploits/protocols/dnp3/dnp3_direct_operate
    assessment/mitre_ics/t0836_modify_parameter
    cve/siemens/cve_2019_10929_s7_replay_writedb
    cve/schneider/cve_2018_7789_modicon_m340_auth_bypass

  Physical Impact:
    - Modified PID gains cause process instability
    - Raised pressure setpoints exceed vessel design limits
    - Altered chemical dosing ratios produce hazardous reactions
    - Changed motor speed parameters cause mechanical overstress

  MITRE: T0836 | Tactic: TA0106
```

### Example 3: Query T0843 (Program Download)

```
ixf > mitre T0843

  ╔══════════════════════════════════════════════════════════════════╗
  ║  MITRE ATT&CK for ICS — Technique Detail                        ║
  ╚══════════════════════════════════════════════════════════════════╝

  ID:          T0843
  Name:        Program Download
  Tactic:      Lateral Movement (TA0109), Execution (TA0104)
  IXF Modules: 12 modules

  Description:
    Adversaries download a modified PLC program to a controller,
    replacing or injecting logic to alter process behavior. This is
    a cross-tactic technique appearing in both Execution and Lateral
    Movement as it achieves code execution on the controller.

  IXF Modules:
    cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
    cve/siemens/cve_2019_13945_scalance_s7_program_download
    cve/rockwell/cve_2022_1161_controllogix_modified_fw
    exploits/protocols/s7comm/s7_plc_program_upload_download
    exploits/protocols/enip/enip_program_download_controllogix
    exploits/protocols/pccc/pccc_slc500_program_download
    assessment/mitre_ics/t0843_program_download
    cve/schneider/cve_2018_7847_modicon_quantum_exec
    cve/ge/cve_2021_27454_rx3i_program_download
    cve/omron/cve_2022_34151_sysmac_studio_rce
    cve/abb/cve_2019_18995_totalflow_rce
    cve/yokogawa/cve_2020_5523_centum_program_download
```

### Example 4: Query T0878 (Alarm Suppression)

```
ixf > mitre T0878

  ╔══════════════════════════════════════════════════════════════════╗
  ║  MITRE ATT&CK for ICS — Technique Detail                        ║
  ╚══════════════════════════════════════════════════════════════════╝

  ID:          T0878
  Name:        Alarm Suppression
  Tactic:      Inhibit Response Function (TA0107)
  IXF Modules: 6 modules

  Description:
    Adversaries suppress alarms to prevent operators from being notified
    of process anomalies, equipment faults, or safety violations as the
    attack proceeds. This may involve silencing DCS alarms, disabling
    historian alerts, or intercepting alarm messages.

  Real-World Precedent:
    - TRITON/TRISIS (2017): Disabled Safety Instrumented System alarms
      before attempting to trigger physical damage
    - Industroyer (2016): Suppressed SCADA status messages during breaker
      operations at Ukrenergo substation

  IXF Modules:
    assessment/mitre_ics/t0878_alarm_suppression
    exploits/protocols/modbus/modbus_write_alarm_suppression_coil
    exploits/protocols/dnp3/dnp3_unsolicited_response_disable
    exploits/protocols/opcua/opcua_alarm_acknowledge_flood
    cve/honeywell/cve_2021_38155_experion_alarm_bypass
    exploits/protocols/iec104/iec104_spontaneous_message_block
```

### Example 5: Query T0816 (Device Restart/Shutdown)

```
ixf > mitre T0816

  ╔══════════════════════════════════════════════════════════════════╗
  ║  MITRE ATT&CK for ICS — Technique Detail                        ║
  ╚══════════════════════════════════════════════════════════════════╝

  ID:          T0816
  Name:        Device Restart/Shutdown
  Tactic:      Inhibit Response Function (TA0107)
  IXF Modules: 9 modules

  Description:
    Adversaries restart or shut down devices to disrupt operations,
    clear volatile memory, trigger fail-safe behaviors, or create brief
    control gaps. In ICS, unexpected PLC restarts cause loss of control
    for reboot duration (5–120 seconds) which may be sufficient to cause
    physical harm.

  IXF Modules:
    exploits/protocols/s7comm/s7_cpu_stop_command
    exploits/protocols/enip/enip_reset_identity
    exploits/protocols/fins/fins_cpu_unit_reset
    exploits/protocols/dnp3/dnp3_warm_restart
    cve/siemens/cve_2019_13945_s7_1500_dos_restart
    cve/rockwell/cve_2021_27478_factorytalk_service_restart
    cve/schneider/cve_2019_6857_modicon_restart
    assessment/mitre_ics/t0816_device_restart
    exploits/protocols/profinet/profinet_dcp_reset_factory
```

---

## `mitre-list` — Technique Index

Display all 74 covered techniques organized by ID, or filter by tactic.

### Full Output

```
ixf > mitre-list

  MITRE ATT&CK for ICS — Technique Index (74 covered / 90 total)
  ════════════════════════════════════════════════════════════════════════
  ID      Name                                        Modules  Tactic
  ──────────────────────────────────────────────────────────────────────
  T0800   Activate Firmware Update Mode                  3     [Inhibit]
  T0801   Monitor Process State                          2     [Collection]
  T0802   Automated Collection                           5     [Collection]
  T0803   Block Command Message                          3     [Inhibit]
  T0804   Block Reporting Message                        2     [Inhibit]
  T0806   Brute Force I/O                                1     [Impair]
  T0807   Remote Services                                8     [Lateral Mvmt]
  T0808   Replication via Removable Media                2     [Persistence]
  T0809   Disk Wipe                                      3     [Impact]
  T0810   Data Exfiltration over C2 Channel              2     [Collection]
  T0811   Data from Information Repositories             4     [Collection]
  T0812   Default Credentials                           37     [Lateral Mvmt]
  T0813   Denial of Control                              5     [Impact]
  T0814   Denial of Service                              8     [Inhibit]
  T0815   Denial of View                                 3     [Inhibit]
  T0816   Device Restart/Shutdown                        9     [Inhibit]
  T0817   Drive-by Compromise                            3     [Initial Access]
  T0819   Exploit Public-Facing Application             47     [Initial Access]
  T0820   Exploitation of Remote Services               12     [Initial Access]
  T0821   Modify Controller Tasking                      4     [Execution]
  T0822   External Remote Services                       6     [Initial Access]
  T0823   Graphical User Interface                       2     [Execution]
  T0824   I/O Image                                      1     [Execution]
  T0826   Loss of Availability                           4     [Impact]
  T0827   Loss of Control                                2     [Impact]
  T0831   Manipulation of Control                        6     [Impair]
  T0832   Manipulation of View                           3     [Collection]
  T0833   Modify Alarm Settings                          3     [Impair]
  T0834   Native API                                     2     [Execution]
  T0835   Detect Operating Mode                          2     [Inhibit]
  T0836   Modify Parameter                              18     [Impair]
  T0837   Module Firmware                                3     [Persistence]
  T0838   Modify Program                                 5     [Inhibit]
  T0839   Firmware Modification                          7     [Persistence]
  T0840   Network Connection Enumeration                 2     [Discovery]
  T0841   Network Sniffing                               3     [Discovery]
  T0842   Network Topology Mapping                       4     [Discovery]
  T0843   Program Download                              12     [Lateral / Exec]
  T0844   Program Upload                                 8     [Collection]
  T0845   Program Organization Units                     2     [Execution]
  T0846   Remote System Discovery                        8     [Discovery]
  T0847   Replication via Removable Media                2     [Persistence]
  T0848   Rogue Master                                   3     [Initial Access]
  T0849   Masquerading                                   1     [Evasion]
  T0851   Rootkit                                        2     [Inhibit]
  T0852   Screen Capture                                 2     [Collection]
  T0853   Scripting                                      3     [Execution]
  T0854   Serial Connection Enumeration                  2     [Discovery]
  T0855   Unauthorized Command Message                   6     [Impair]
  T0856   Spoof Reporting Message                        2     [Evasion / Inhibit]
  T0857   System Firmware                                4     [Persistence]
  T0858   Change Credential                              4     [Evasion]
  T0859   Valid Accounts                                37     [Persistence]
  T0860   Wireless Compromise                            3     [Initial Access]
  T0861   Point and Tag Identification                   2     [Discovery]
  T0862   Supply Chain Compromise                        2     [Initial Access]
  T0863   User Execution                                 2     [Execution]
  T0864   Transient Cyber Asset                          1     [Initial Access]
  T0865   Spearphishing Attachment                       3     [Initial Access]
  T0866   Exploitation for Lateral Movement              5     [Lateral Mvmt]
  T0867   Lateral Tool Transfer                          2     [Lateral Mvmt]
  T0869   Standard Application Layer Protocol            4     [C2]
  T0870   Commonly Used Port                             3     [C2]
  T0871   Execution through API                          4     [Execution / Impair]
  T0873   Project File Infection                         3     [Impair]
  T0874   Hooking                                        1     [Evasion]
  T0875   Change Program State                           2     [Impair]
  T0877   I/O Module Discovery                           3     [Discovery]
  T0878   Alarm Suppression                              6     [Inhibit]
  T0879   Damage to Property                             2     [Impact]
  T0880   Loss of Safety                                 3     [Impact]
  T0881   Service Stop                                   4     [Inhibit]
  T0882   Theft of Operational Information               3     [C2 / Inhibit]
  T0883   Internet Accessible Device                     5     [Discovery]
  T0884   Connection Proxy                               2     [C2]
  T0885   Commonly Used Port (C2 variant)                2     [C2]
  T0888   Remote System Information Discovery            4     [Discovery]
  T0889   Modify Program (ICS variant)                   3     [Persistence]
  T0890   Exploitation for Privilege Escalation          3     [Privesc]
  ──────────────────────────────────────────────────────────────────────
  Total covered: 74 techniques | Total modules: 976+
```

### Filtered by Tactic — Initial Access

```
ixf > mitre-list --tactic initial-access

  MITRE ATT&CK for ICS — Initial Access (TA0108)
  ════════════════════════════════════════════════════════════════════════
  ID      Name                                        Modules
  ──────────────────────────────────────────────────────────────────────
  T0817   Drive-by Compromise                             3
  T0819   Exploit Public-Facing Application              47
  T0820   Exploitation of Remote Services                12
  T0822   External Remote Services                        6
  T0848   Rogue Master                                    3
  T0860   Wireless Compromise                             3
  T0862   Supply Chain Compromise                         2
  T0864   Transient Cyber Asset                           1
  T0865   Spearphishing Attachment                        3
  ──────────────────────────────────────────────────────────────────────
  Total: 9/9 techniques covered (100%) | 80 modules
```

### Filtered by Tactic — Discovery

```
ixf > mitre-list --tactic discovery

  MITRE ATT&CK for ICS — Discovery (TA0102)
  ════════════════════════════════════════════════════════════════════════
  ID      Name                                        Modules
  ──────────────────────────────────────────────────────────────────────
  T0840   Network Connection Enumeration                  2
  T0841   Network Sniffing                                3
  T0842   Network Topology Mapping                        4
  T0843   Program Download (reconnaissance phase)        12
  T0846   Remote System Discovery                         8
  T0854   Serial Connection Enumeration                   2
  T0861   Point and Tag Identification                    2
  T0877   I/O Module Discovery                            3
  T0883   Internet Accessible Device                      5
  T0888   Remote System Information Discovery             4
  T0867   Lateral Tool Transfer (discovery phase)         2  [partial]
  ──────────────────────────────────────────────────────────────────────
  Total: 11/13 techniques covered (84%) | 47 modules
```

### Filtered by Tactic — Inhibit Response Function

```
ixf > mitre-list --tactic inhibit

  MITRE ATT&CK for ICS — Inhibit Response Function (TA0107)
  ════════════════════════════════════════════════════════════════════════
  ID      Name                                        Modules
  ──────────────────────────────────────────────────────────────────────
  T0800   Activate Firmware Update Mode                   3
  T0803   Block Command Message                           3
  T0804   Block Reporting Message                         2
  T0814   Denial of Service                               8
  T0815   Denial of View                                  3
  T0816   Device Restart/Shutdown                         9
  T0835   Detect Operating Mode                           2
  T0838   Modify Program                                  5
  T0851   Rootkit                                         2
  T0856   Spoof Reporting Message                         2
  T0878   Alarm Suppression                               6
  T0881   Service Stop                                    4
  T0882   Theft of Operational Information                3
  T0889   Modify Program (ICS variant)                    3
  ──────────────────────────────────────────────────────────────────────
  Total: 14/18 techniques covered (77%) | 55 modules
  [!] Not covered: T0805, T0829, T0869 (C2 overlap), T0880 (in Impact)
```

### Filtered by Tactic — Impair Process Control

```
ixf > mitre-list --tactic impair

  MITRE ATT&CK for ICS — Impair Process Control (TA0106)
  ════════════════════════════════════════════════════════════════════════
  ID      Name                                        Modules
  ──────────────────────────────────────────────────────────────────────
  T0806   Brute Force I/O                                 1
  T0831   Manipulation of Control                         6
  T0833   Modify Alarm Settings                           3
  T0836   Modify Parameter                               18
  T0855   Unauthorized Command Message                    6
  T0871   Execution through API                           4
  T0873   Project File Infection                          3
  T0875   Change Program State                            2
  T0889   Modify Program (ICS variant)                    3
  ──────────────────────────────────────────────────────────────────────
  Total: 9/11 techniques covered (81%) | 46 modules
  [!] Not covered: T0821 (Modify Controller Tasking), T0837 (Module Firmware)
```

### Filtered by Tactic — Impact

```
ixf > mitre-list --tactic impact

  MITRE ATT&CK for ICS — Impact (TA0105)
  ════════════════════════════════════════════════════════════════════════
  ID      Name                                        Modules
  ──────────────────────────────────────────────────────────────────────
  T0809   Data Destruction                                3
  T0813   Denial of Control                               5
  T0826   Loss of Availability                            4
  T0827   Loss of Control                                 2
  T0879   Damage to Property                              2
  T0880   Loss of Safety                                  3
  T0881   Service Stop (Impact variant)                   4
  T0882   Theft of Operational Information                3
  ──────────────────────────────────────────────────────────────────────
  Total: 8/11 techniques covered (72%) | 26 modules
  [!] Not covered: T0828 (Loss of Productivity), T0829 (Loss of Safety dup),
      T0830 (Loss of View)
```

---

## `mitre-scan` — Tactic Sweep

Run all techniques of an entire tactic against a target or subnet. Safe by default (simulate=True).

**Syntax:**
```
ixf > mitre-scan <tactic|technique_id> <target> [--live] [--rate-limit <ms>] [--output <file>]
```

### Example 1: Discovery Sweep on Subnet

```
ixf > mitre-scan discovery 192.168.1.0/24

  ╔══════════════════════════════════════════════════════════════════╗
  ║  MITRE ATT&CK for ICS — Tactic Sweep                            ║
  ╚══════════════════════════════════════════════════════════════════╝
  Tactic:    Discovery (TA0102)
  Target:    192.168.1.0/24
  Mode:      SIMULATE (safe)
  Techniques: 11 covered
  Total modules to run: 47

  ─── T0840: Network Connection Enumeration ─────────────────────────
  [1/2] scanners/ics/modbus_scanner         192.168.1.0/24  [SIMULATE]
  [2/2] scanners/ics/enip_scanner           192.168.1.0/24  [SIMULATE]
  [+] T0840 complete: 2 modules

  ─── T0841: Network Sniffing ────────────────────────────────────────
  [1/3] assessment/mitre_ics/t0841_network_sniff   [SIMULATE]
  [2/3] scanners/ics/passive_banner_grab           [SIMULATE]
  [3/3] scanners/ics/ics_protocol_fingerprint      [SIMULATE]
  [+] T0841 complete: 3 modules

  ─── T0842: Network Topology Mapping ───────────────────────────────
  [1/4] scanners/ics/ics_network_mapper            [SIMULATE]
  [2/4] scanners/ics/profinet_dcp_scan             [SIMULATE]
  [3/4] scanners/ics/lldp_collector               [SIMULATE]
  [4/4] scanners/ics/snmp_topology_walk           [SIMULATE]
  [+] T0842 complete: 4 modules

  ─── T0843: Program Download (discovery phase) ─────────────────────
  [1/12] exploits/protocols/s7comm/s7_plc_program_upload_download  [SIMULATE]
  [2/12] exploits/protocols/enip/enip_program_download_controllogix [SIMULATE]
  ... [10 more]
  [+] T0843 complete: 12 modules

  ─── T0846: Remote System Discovery ────────────────────────────────
  [1/8] scanners/ics/s7_comm_scanner               [SIMULATE]
  [2/8] scanners/ics/omron_fins_scan               [SIMULATE]
  [3/8] scanners/ics/bacnet_discovery              [SIMULATE]
  [4/8] scanners/ics/dnp3_data_link_scan           [SIMULATE]
  [5/8] scanners/ics/iec104_scan                   [SIMULATE]
  [6/8] scanners/ics/opcua_discovery               [SIMULATE]
  [7/8] scanners/ics/profinet_dcp_scan             [SIMULATE]
  [8/8] scanners/ics/modbus_device_id              [SIMULATE]
  [+] T0846 complete: 8 modules

  ─── T0854: Serial Connection Enumeration ───────────────────────────
  [1/2] scanners/ics/serial_rs485_scan             [SIMULATE]
  [2/2] scanners/ics/serial_modbus_rtu_probe       [SIMULATE]
  [+] T0854 complete: 2 modules

  ─── T0861: Point and Tag Identification ───────────────────────────
  [1/2] scanners/ics/modbus_coil_register_map      [SIMULATE]
  [2/2] scanners/ics/opcua_browse_address_space    [SIMULATE]
  [+] T0861 complete: 2 modules

  ─── T0877: I/O Module Discovery ───────────────────────────────────
  [1/3] exploits/protocols/s7comm/s7_read_szl_list  [SIMULATE]
  [2/3] exploits/protocols/enip/enip_list_identity  [SIMULATE]
  [3/3] exploits/protocols/profinet/profinet_dcp_identify [SIMULATE]
  [+] T0877 complete: 3 modules

  ─── T0883: Internet Accessible Device ─────────────────────────────
  [1/5] scanners/ics/shodan_ics_lookup             [SIMULATE]
  [2/5] scanners/ics/censys_ics_lookup             [SIMULATE]
  [3/5] scanners/ics/fofa_ics_lookup               [SIMULATE]
  [4/5] scanners/ics/ics_external_exposure_check   [SIMULATE]
  [5/5] scanners/ics/ics_banner_fingerprint        [SIMULATE]
  [+] T0883 complete: 5 modules

  ─── T0888: Remote System Information Discovery ─────────────────────
  [1/4] exploits/protocols/s7comm/s7_read_system_info  [SIMULATE]
  [2/4] exploits/protocols/enip/enip_get_attribute_all [SIMULATE]
  [3/4] exploits/protocols/bacnet/bacnet_who_is       [SIMULATE]
  [4/4] exploits/protocols/opcua/opcua_read_server_info [SIMULATE]
  [+] T0888 complete: 4 modules

  ══════════════════════════════════════════════════════════════════════
  Tactic sweep complete: Discovery (TA0102)
  Techniques run: 11 | Modules run: 47 | Errors: 0
  Simulated results: 0 live packets sent
```

### Example 2: Single Technique Scan

```
ixf > mitre-scan T0843 192.168.1.100

  Tactic:    Lateral Movement / Execution (T0843: Program Download)
  Target:    192.168.1.100
  Mode:      SIMULATE (safe)
  Modules:   12

  [1/12] cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
    [SIMULATE] CVE-2021-22681: S7-1200/1500 hardcoded cryptographic key
    Result: Would attempt key extraction on port 102

  [2/12] cve/siemens/cve_2019_13945_scalance_s7_program_download
    [SIMULATE] CVE-2019-13945: Scalance X authenticated program download path
    Result: Would exploit unauthenticated S7 program transfer

  [3/12] cve/rockwell/cve_2022_1161_controllogix_modified_fw
    [SIMULATE] CVE-2022-1161: ControlLogix firmware modification via EtherNet/IP
    Result: Would send modified ladder logic to L83E controller

  [4/12] exploits/protocols/s7comm/s7_plc_program_upload_download
    [SIMULATE] S7comm unauthenticated program block download (DB/OB/FC)
    Result: Would initiate S7 stop + program download sequence

  [5/12] exploits/protocols/enip/enip_program_download_controllogix
    [SIMULATE] EtherNet/IP CIP program download to ControlLogix 1756-L85E
    Result: Would target port 44818 CIP download services

  [6/12] exploits/protocols/pccc/pccc_slc500_program_download
    [SIMULATE] PCCC CMD 0x0F FNC 0xAB: SLC-500 program download
    Result: Would download modified SLC-500 program

  [7/12] assessment/mitre_ics/t0843_program_download
    [SIMULATE] Assessment: verify PLC allows unauthenticated program download
    Result: Protocol probe simulation complete

  [8/12] cve/schneider/cve_2018_7847_modicon_quantum_exec
    [SIMULATE] CVE-2018-7847: Modicon Quantum arbitrary code execution via Unity
    Result: Would execute Unity program upload command

  [9/12] cve/ge/cve_2021_27454_rx3i_program_download
    [SIMULATE] CVE-2021-27454: GE RX3i unauthenticated firmware/program download
    Result: Would target PACSystems RX3i on port 18245

  [10/12] cve/omron/cve_2022_34151_sysmac_studio_rce
    [SIMULATE] CVE-2022-34151: Omron Sysmac Studio project file RCE via FINS
    Result: Would target NX/NJ controller on port 9600

  [11/12] cve/abb/cve_2019_18995_totalflow_rce
    [SIMULATE] CVE-2019-18995: ABB TotalFlow unauthenticated program download
    Result: Would target flow computer on port 3001

  [12/12] cve/yokogawa/cve_2020_5523_centum_program_download
    [SIMULATE] CVE-2020-5523: Yokogawa CENTUM unauthenticated control builder download
    Result: Would target CENTUM VP on port 20111

  T0843 sweep complete: 12 modules, 0 errors, 0 live packets
```

### Example 3: Initial Access Sweep

```
ixf > mitre-scan initial-access 10.0.0.100

  Tactic:    Initial Access (TA0108)
  Target:    10.0.0.100
  Mode:      SIMULATE (safe)
  Techniques: 9 | Modules: 80

  [TA0108] T0817 Drive-by Compromise (3 modules)...
  [TA0108] T0819 Exploit Public-Facing Application (47 modules)...
    [1/47] cve/siemens/cve_2019_13945_scalance_x_rce             [SIMULATE]
    [2/47] cve/schneider/cve_2021_22763_ecostruxure_auth_bypass   [SIMULATE]
    ... [45 more CVE modules]
  [TA0108] T0820 Exploitation of Remote Services (12 modules)...
  [TA0108] T0822 External Remote Services (6 modules)...
  [TA0108] T0848 Rogue Master (3 modules)...
  [TA0108] T0860 Wireless Compromise (3 modules)...
  [TA0108] T0862 Supply Chain Compromise (2 modules)...
  [TA0108] T0864 Transient Cyber Asset (1 module)...
  [TA0108] T0865 Spearphishing Attachment (3 modules)...

  Tactic sweep complete: Initial Access (TA0108)
  Techniques: 9/9 | Modules: 80 | Potential matches: 3 (simulated)
```

### Example 4: Live Mode (Authorized Labs Only)

```
ixf > mitre-scan discovery 192.168.50.0/24 --live

  [!] WARNING: Live mode active — packets WILL be sent to targets
  [!] Ensure you have written authorization before proceeding
  [?] Confirm live scan against 192.168.50.0/24? [yes/no]: yes

  Tactic:    Discovery (TA0102)
  Target:    192.168.50.0/24
  Mode:      LIVE
  Rate limit: 200ms between modules (default)

  ─── T0840: Network Connection Enumeration ────
  [1/2] scanners/ics/modbus_scanner
    [+] 192.168.50.10 — Modbus device detected (Unit 1, FC43 MEID supported)
    [+] 192.168.50.22 — Modbus device detected (Unit 1-3)
  [2/2] scanners/ics/enip_scanner
    [+] 192.168.50.30 — EtherNet/IP node: 1756-L85E ControlLogix

  [+] Discovery scan complete: 3 live devices identified
```

### Example 5: With Rate Limit and Output

```
ixf > mitre-scan lateral-movement 192.168.1.100 --rate-limit 1000 --output /opt/results/lm_scan.json

  Tactic:    Lateral Movement (TA0109)
  Target:    192.168.1.100
  Mode:      SIMULATE | Rate limit: 1000ms | Output: lm_scan.json
  Techniques: 3 | Modules: 52

  [TA0109] T0807 Remote Services (8 modules)...
  [TA0109] T0843 Program Download (12 modules)...
  [TA0109] T0866 Exploitation for Lateral Movement (5 modules)...
    ... [additional lateral movement modules]

  [+] Results saved: /opt/results/lm_scan.json
  [+] Sweep complete: 3 techniques | 25 modules | 0 errors
```

---

## `mitre-all` — Full Sweep

Run all 74 mapped techniques across all 12 tactics in simulate mode. This is the most comprehensive single-target assessment available in IXF.

**Syntax:**
```
ixf > mitre-all <target> [--rate-limit <ms>] [--output <file>] [--skip-tactic <tactic>]
```

```
ixf > mitre-all 192.168.1.100

  ╔══════════════════════════════════════════════════════════════════╗
  ║  IXF — Full MITRE ATT&CK for ICS Sweep                          ║
  ╚══════════════════════════════════════════════════════════════════╝
  Target:     192.168.1.100
  Mode:       SIMULATE (safe — 0 live packets)
  Tactics:    12
  Techniques: 74
  Modules:    976+
  ETA:        ~4 minutes (simulate mode)

  ══ [TA0108] Initial Access (9 techniques, 80 modules) ══════════════
  [T0817] Drive-by Compromise                       3 modules  [SIMULATE]
  [T0819] Exploit Public-Facing Application        47 modules  [SIMULATE]
  [T0820] Exploitation of Remote Services          12 modules  [SIMULATE]
  [T0822] External Remote Services                  6 modules  [SIMULATE]
  [T0848] Rogue Master                              3 modules  [SIMULATE]
  [T0860] Wireless Compromise                       3 modules  [SIMULATE]
  [T0862] Supply Chain Compromise                   2 modules  [SIMULATE]
  [T0864] Transient Cyber Asset                     1 module   [SIMULATE]
  [T0865] Spearphishing Attachment                  3 modules  [SIMULATE]
  [+] TA0108 complete: 9 techniques, 80 modules

  ══ [TA0104] Execution (8 techniques, 74 modules) ═══════════════════
  [T0807] Remote Services                           8 modules  [SIMULATE]
  [T0821] Modify Controller Tasking                 4 modules  [SIMULATE]
  [T0823] Graphical User Interface                  2 modules  [SIMULATE]
  [T0824] I/O Image                                 1 module   [SIMULATE]
  [T0834] Native API                                2 modules  [SIMULATE]
  [T0843] Program Download                         12 modules  [SIMULATE]
  [T0853] Scripting                                 3 modules  [SIMULATE]
  [T0863] User Execution                            2 modules  [SIMULATE]
  [+] TA0104 complete: 8 techniques, 34 modules

  ══ [TA0110] Persistence (6 techniques, 48 modules) ════════════════
  [T0808] Replication via Removable Media           2 modules  [SIMULATE]
  [T0837] Module Firmware                           3 modules  [SIMULATE]
  [T0839] Firmware Modification                     7 modules  [SIMULATE]
  [T0847] Replication via Removable Media           2 modules  [SIMULATE]
  [T0857] System Firmware                           4 modules  [SIMULATE]
  [T0859] Valid Accounts                           37 modules  [SIMULATE]
  [+] TA0110 complete: 6 techniques, 55 modules

  ══ [TA0111] Privilege Escalation (2 techniques, 11 modules) ════════
  [T0845] Program Organization Units                2 modules  [SIMULATE]
  [T0890] Exploitation for Privilege Escalation     3 modules  [SIMULATE]
  [+] TA0111 complete: 2 techniques, 5 modules

  ══ [TA0103] Evasion (4 techniques, 28 modules) ════════════════════
  [T0849] Masquerading                              1 module   [SIMULATE]
  [T0856] Spoof Reporting Message                   2 modules  [SIMULATE]
  [T0858] Change Credential                         4 modules  [SIMULATE]
  [T0874] Hooking                                   1 module   [SIMULATE]
  [+] TA0103 complete: 4 techniques, 8 modules

  ══ [TA0102] Discovery (11 techniques, 47 modules) ══════════════════
  [T0840] Network Connection Enumeration            2 modules  [SIMULATE]
  [T0841] Network Sniffing                          3 modules  [SIMULATE]
  [T0842] Network Topology Mapping                  4 modules  [SIMULATE]
  [T0843] Program Download (recon)                 12 modules  [SIMULATE]
  [T0846] Remote System Discovery                   8 modules  [SIMULATE]
  [T0854] Serial Connection Enumeration             2 modules  [SIMULATE]
  [T0861] Point and Tag Identification              2 modules  [SIMULATE]
  [T0877] I/O Module Discovery                      3 modules  [SIMULATE]
  [T0883] Internet Accessible Device                5 modules  [SIMULATE]
  [T0888] Remote System Information Discovery       4 modules  [SIMULATE]
  [T0867] Lateral Tool Transfer (recon)             2 modules  [SIMULATE]
  [+] TA0102 complete: 11 techniques, 47 modules

  ══ [TA0109] Lateral Movement (3 techniques, 52 modules) ════════════
  [T0812] Default Credentials                      37 modules  [SIMULATE]
  [T0843] Program Download (lateral)               12 modules  [SIMULATE]
  [T0866] Exploitation for Lateral Movement         5 modules  [SIMULATE]
  [+] TA0109 complete: 3 techniques, 54 modules

  ══ [TA0100] Collection (8 techniques, 97 modules) ══════════════════
  [T0801] Monitor Process State                     2 modules  [SIMULATE]
  [T0802] Automated Collection                      5 modules  [SIMULATE]
  [T0810] Data Exfiltration over C2 Channel         2 modules  [SIMULATE]
  [T0811] Data from Information Repositories        4 modules  [SIMULATE]
  [T0832] Manipulation of View                      3 modules  [SIMULATE]
  [T0844] Program Upload                            8 modules  [SIMULATE]
  [T0852] Screen Capture                            2 modules  [SIMULATE]
  [T0882] Theft of Operational Information          3 modules  [SIMULATE]
  [+] TA0100 complete: 8 techniques, 29 modules

  ══ [TA0101] Command and Control (3 techniques, 19 modules) ═════════
  [T0869] Standard Application Layer Protocol       4 modules  [SIMULATE]
  [T0870] Commonly Used Port                        3 modules  [SIMULATE]
  [T0884] Connection Proxy                          2 modules  [SIMULATE]
  [+] TA0101 complete: 3 techniques, 9 modules

  ══ [TA0107] Inhibit Response Function (14 techniques, 218 modules) ═
  [T0800] Activate Firmware Update Mode             3 modules  [SIMULATE]
  [T0803] Block Command Message                     3 modules  [SIMULATE]
  [T0804] Block Reporting Message                   2 modules  [SIMULATE]
  [T0814] Denial of Service                         8 modules  [SIMULATE]
  [T0815] Denial of View                            3 modules  [SIMULATE]
  [T0816] Device Restart/Shutdown                   9 modules  [SIMULATE]
  [T0835] Detect Operating Mode                     2 modules  [SIMULATE]
  [T0838] Modify Program                            5 modules  [SIMULATE]
  [T0851] Rootkit                                   2 modules  [SIMULATE]
  [T0856] Spoof Reporting Message                   2 modules  [SIMULATE]
  [T0878] Alarm Suppression                         6 modules  [SIMULATE]
  [T0881] Service Stop                              4 modules  [SIMULATE]
  [T0882] Theft of Operational Information          3 modules  [SIMULATE]
  [T0889] Modify Program (ICS variant)              3 modules  [SIMULATE]
  [+] TA0107 complete: 14 techniques, 55 modules

  ══ [TA0106] Impair Process Control (9 techniques, 143 modules) ═════
  [T0806] Brute Force I/O                           1 module   [SIMULATE]
  [T0831] Manipulation of Control                   6 modules  [SIMULATE]
  [T0833] Modify Alarm Settings                     3 modules  [SIMULATE]
  [T0836] Modify Parameter                         18 modules  [SIMULATE]
  [T0855] Unauthorized Command Message              6 modules  [SIMULATE]
  [T0871] Execution through API                     4 modules  [SIMULATE]
  [T0873] Project File Infection                    3 modules  [SIMULATE]
  [T0875] Change Program State                      2 modules  [SIMULATE]
  [T0889] Modify Program (ICS variant)              3 modules  [SIMULATE]
  [+] TA0106 complete: 9 techniques, 46 modules

  ══ [TA0105] Impact (8 techniques, 59 modules) ══════════════════════
  [T0809] Data Destruction                          3 modules  [SIMULATE]
  [T0813] Denial of Control                         5 modules  [SIMULATE]
  [T0826] Loss of Availability                      4 modules  [SIMULATE]
  [T0827] Loss of Control                           2 modules  [SIMULATE]
  [T0879] Damage to Property                        2 modules  [SIMULATE]
  [T0880] Loss of Safety                            3 modules  [SIMULATE]
  [T0881] Service Stop                              4 modules  [SIMULATE]
  [T0882] Theft of Operational Information          3 modules  [SIMULATE]
  [+] TA0105 complete: 8 techniques, 26 modules

  ════════════════════════════════════════════════════════════════════
  Full MITRE ATT&CK for ICS Sweep Complete
  ════════════════════════════════════════════════════════════════════
  Target:          192.168.1.100
  Tactics:         12/12
  Techniques:      74/90 (82%)
  Modules run:     976
  Errors:          0
  Live packets:    0 (simulate mode)
  Duration:        3m 47s
  ════════════════════════════════════════════════════════════════════
  [i] Use `mitre-report layer` to export ATT&CK Navigator JSON
  [i] Use `mitre-report html` for a full HTML assessment report
```

---

## `mitre-coverage` — Coverage Report

Display the current IXF coverage against the MITRE ATT&CK for ICS framework.

```
ixf > mitre-coverage

  ╔══════════════════════════════════════════════════════════════════╗
  ║  IXF — MITRE ATT&CK for ICS Coverage Report                     ║
  ║  Framework version: v19  |  IXF version: 2.4.0                  ║
  ╚══════════════════════════════════════════════════════════════════╝

  Tactic                                Covered  Total   Pct    Modules
  ──────────────────────────────────────────────────────────────────────
  Initial Access           (TA0108)        9       9    100%       93
  Execution                (TA0104)        8       9     88%       74
  Persistence              (TA0110)        6       8     75%       48
  Privilege Escalation     (TA0111)        2       2    100%       11
  Evasion                  (TA0103)        4       5     80%       28
  Discovery                (TA0102)       11      13     84%      134
  Lateral Movement         (TA0109)        3       3    100%       52
  Collection               (TA0100)        8       9     88%       97
  Command and Control      (TA0101)        3       3    100%       19
  Inhibit Response Fn      (TA0107)       14      18     77%      218
  Impair Process Control   (TA0106)        9      11     81%      143
  Impact                   (TA0105)        8      11     72%       59
  ──────────────────────────────────────────────────────────────────────
  TOTAL                                   74      90     82%      976+

  Coverage breakdown by module type:
  ──────────────────────────────────────────────────────────────────────
  CVE exploit modules           487   (50%)
  Protocol exploit modules      231   (24%)
  Credential modules            142   (15%)
  Assessment / check modules     87   (9%)
  Scanner modules                29   (3%)
  ──────────────────────────────────────────────────────────────────────

  Uncovered techniques (16):
  ──────────────────────────────────────────────────────────────────────
  TA0104  T0871.001  Execution via API sub-technique (partial)
  TA0110  T0839.002  Firmware credential modification (planned)
  TA0110  T0857.001  System firmware implant persistence (planned)
  TA0103  T0820.001  Evasion via legitimate OT protocols
  TA0102  T0841.001  Wireless network sniffing
  TA0102  T0868     Detect Program State (no modules yet)
  TA0107  T0805     Block Serial COM (physical layer — hardware required)
  TA0107  T0829     Loss of Safety (maps to T0880 in IXF)
  TA0107  T0892     Change Credential (inhibit variant)
  TA0107  T0895     Autorun Image (USB autorun — requires endpoint access)
  TA0107  T0896     Loss of Protection (partial — assessed via T0878)
  TA0107  T0897     Loss of Communication (planned)
  TA0106  T0821     Modify Controller Tasking (limited vendor support)
  TA0106  T0837     Module Firmware (requires physical proximity)
  TA0105  T0828     Loss of Productivity (impact assessment only)
  TA0105  T0830     Loss of View (maps to T0815/T0832 in IXF)
  ──────────────────────────────────────────────────────────────────────

  [i] Use `mitre-report layer` to export ATT&CK Navigator visualization
```

---

## `mitre-report` — Export

Generate reports and exports in multiple formats.

**Syntax:**
```
ixf > mitre-report <format> [--output <path>] [--target <ip>] [--date <YYYYMMDD>]
```

Available formats: `layer` (default), `html`, `json`, `csv`

### ATT&CK Navigator Layer

```
ixf > mitre-report layer

  [*] Generating ATT&CK Navigator layer...
  [*] Techniques: 74 covered, 16 uncovered
  [*] Color scheme: red (high coverage) → orange → yellow (partial) → white (none)
  [+] ATT&CK Navigator layer saved: ixf_mitre_layer_20260601.json
  [i] Load at: https://mitre-attack.github.io/attack-navigator/
  [i] Select: "Open Existing Layer" → "Upload from Local"
```

#### Navigator JSON Structure

The exported layer file follows the [ATT&CK Navigator layer schema v4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/LAYERFORMATv4_5.md). Below is an annotated excerpt:

```json
{
  "name": "IXF — MITRE ATT&CK for ICS Coverage",
  "versions": {
    "attack": "14",
    "navigator": "4.9",
    "layer": "4.5"
  },
  "domain": "ics-attack",
  "description": "IndustrialXPL-Forge coverage against ATT&CK for ICS v19. Generated 2026-06-01.",
  "filters": {
    "platforms": [
      "Field Controller/RTU/PLC/IED",
      "Safety Instrumented System/Protection Relay",
      "Data Historian",
      "Human-Machine Interface",
      "Control Server",
      "Engineering Workstation",
      "Input/Output Server",
      "Intelligent Electronic Device"
    ]
  },
  "sorting": 0,
  "layout": {
    "layout": "side",
    "aggregateFunction": "sum",
    "showID": true,
    "showName": true,
    "showAggregateScores": true,
    "countUnscored": false
  },
  "hideDisabled": false,
  "techniques": [
    {
      "techniqueID": "T0819",
      "tactic": "initial-access",
      "score": 47,
      "color": "#d62728",
      "comment": "47 CVE modules covering Siemens, Schneider, Rockwell, GE, Honeywell, ABB, Aveva, Delta",
      "enabled": true,
      "metadata": [
        { "name": "IXF Modules", "value": "47" },
        { "name": "Vendors", "value": "Siemens, Schneider, Rockwell, GE, Honeywell" },
        { "name": "Protocol", "value": "HTTP, HTTPS, S7comm, EtherNet/IP" }
      ]
    },
    {
      "techniqueID": "T0836",
      "tactic": "impair-process-control",
      "score": 18,
      "color": "#ff7f0e",
      "comment": "18 modules: Modbus FC16, S7 DB write, EtherNet/IP CIP write, OPC UA write, FINS write",
      "enabled": true,
      "metadata": [
        { "name": "IXF Modules", "value": "18" },
        { "name": "Protocols", "value": "Modbus, S7comm, EtherNet/IP, OPC UA, FINS, DNP3" }
      ]
    },
    {
      "techniqueID": "T0843",
      "tactic": "lateral-movement",
      "score": 12,
      "color": "#ff7f0e",
      "comment": "12 modules covering S7comm, EtherNet/IP, PCCC, Schneider Unity, GE RX3i, Omron, ABB, Yokogawa",
      "enabled": true,
      "metadata": [
        { "name": "IXF Modules", "value": "12" },
        { "name": "CVEs", "value": "CVE-2021-22681, CVE-2022-1161, CVE-2018-7847, CVE-2021-27454" }
      ]
    },
    {
      "techniqueID": "T0805",
      "tactic": "inhibit-response-function",
      "score": 0,
      "color": "#ffffff",
      "comment": "Not covered — Block Serial COM requires physical layer access (RS-485 tap)",
      "enabled": true
    }
  ],
  "gradient": {
    "colors": ["#ffffff", "#ffdd99", "#ff8800", "#d62728"],
    "minValue": 0,
    "maxValue": 50
  },
  "legendItems": [
    { "color": "#d62728", "label": "High coverage (>20 modules)" },
    { "color": "#ff7f0e", "label": "Medium coverage (5-20 modules)" },
    { "color": "#ffdd99", "label": "Low coverage (1-4 modules)" },
    { "color": "#ffffff", "label": "Not covered" }
  ],
  "showTacticRowBackground": true,
  "tacticRowBackground": "#dddddd",
  "selectTechniquesAcrossTactics": false
}
```

### HTML Report

```
ixf > mitre-report html

  [*] Generating HTML coverage report...
  [*] Embedding technique details, module lists, CVE references...
  [+] MITRE ICS coverage report: ixf_mitre_report_20260601.html

  Report contents:
  - Executive summary with coverage percentages
  - Per-tactic technique tables with module counts
  - Per-technique module list with CVE IDs and vendor references
  - Uncovered techniques with gap analysis notes
  - Remediation recommendations per technique
  - Reference links to MITRE ATT&CK for ICS technique pages
```

The HTML report is a self-contained single file suitable for sharing with stakeholders. It includes:
- A top-level dashboard with 12 tactic cards showing coverage bars
- Expandable sections for each technique showing the mapped modules
- Severity color coding aligned to the Navigator layer
- A gap analysis section listing uncovered techniques and the technical reason
- CVE references with links to NVD and ICS-CERT advisories

### JSON Export

```
ixf > mitre-report json

  [+] MITRE coverage data: ixf_mitre_data_20260601.json
```

The JSON export provides machine-readable data:
```json
{
  "generated": "2026-06-01T18:00:00Z",
  "ixf_version": "2.4.0",
  "attack_version": "v19",
  "summary": {
    "total_techniques": 90,
    "covered": 74,
    "coverage_pct": 82,
    "total_modules": 976
  },
  "tactics": [
    {
      "id": "TA0108",
      "name": "Initial Access",
      "total": 9,
      "covered": 9,
      "pct": 100,
      "techniques": [
        {
          "id": "T0819",
          "name": "Exploit Public-Facing Application",
          "modules": ["cve/siemens/cve_2019_13945_scalance_x_rce", "..."],
          "module_count": 47
        }
      ]
    }
  ]
}
```

### CSV Export

```
ixf > mitre-report csv

  [+] MITRE coverage CSV: ixf_mitre_coverage_20260601.csv
```

The CSV includes columns: `technique_id`, `technique_name`, `tactic`, `covered`, `module_count`, `example_modules`, `notes`

---

## `ttp` — Execute a Technique

Run all modules mapped to a specific MITRE technique against a target. By default runs in simulate mode.

**Syntax:**
```
ixf > ttp <technique_id> <target> [--stop-on-first] [--rate-limit <ms>] [--output <file>] [--destructive]
```

### Full Output — T0843 Program Download

```
ixf > ttp T0843 192.168.1.100

  ╔══════════════════════════════════════════════════════════════════╗
  ║  IXF TTP Runner — T0843: Program Download                       ║
  ╚══════════════════════════════════════════════════════════════════╝
  Target:    192.168.1.100
  Modules:   12
  Mode:      SIMULATE (safe)
  Tactic(s): Lateral Movement (TA0109), Execution (TA0104)

  [1/12] cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
  ──────────────────────────────────────────────────────────────────
  CVE-2021-22681 | Siemens S7-1200/1500 Hardcoded Cryptographic Key
  Target port: 102 (S7comm TLS)
  [SIMULATE] Would attempt to extract the hardcoded TLS key from the
  S7-1200/1500 firmware image (offset 0x3A200 in firmware v4.x) and
  use it to decrypt the S7comm+ session to allow unauthenticated
  program download.
  Status: SIMULATE_OK

  [2/12] cve/siemens/cve_2019_13945_scalance_s7_program_download
  ──────────────────────────────────────────────────────────────────
  CVE-2019-13945 | Siemens SCALANCE X Unauthenticated Program Download
  Target port: 102 (ISO-TSAP / S7comm)
  [SIMULATE] Would send S7 STOP CPU command, then initiate unauthenticated
  program block download sequence using S7comm PDU type 0x32 (job request)
  with function code 0x0501 (download block). No authentication required
  on SCALANCE X switches with S7-relay firmware.
  Status: SIMULATE_OK

  [3/12] cve/rockwell/cve_2022_1161_controllogix_modified_fw
  ──────────────────────────────────────────────────────────────────
  CVE-2022-1161 | Rockwell ControlLogix Modified Ladder Logic Download
  Target port: 44818 (EtherNet/IP)
  [SIMULATE] Would open CIP session to 1756-L85E ControlLogix controller,
  send CIP Service 0x4B (Execute PCCC) with modified ladder logic in the
  program file slot, bypassing the firmware authentication check. Modified
  logic would run alongside legitimate program without operator awareness.
  Status: SIMULATE_OK

  [4/12] exploits/protocols/s7comm/s7_plc_program_upload_download
  ──────────────────────────────────────────────────────────────────
  S7comm Unauthenticated Program Block Download (generic)
  Target port: 102 (S7comm)
  [SIMULATE] Generic S7comm exploit: STOP CPU → download DB/OB/FC blocks →
  START CPU. Works against S7-300/400 with factory default configuration
  (no PLC password set). Block types: OB1 (main), DB (data block),
  FC (function), FB (function block).
  Status: SIMULATE_OK

  [5/12] exploits/protocols/enip/enip_program_download_controllogix
  ──────────────────────────────────────────────────────────────────
  EtherNet/IP CIP Program Download — ControlLogix 1756
  Target port: 44818 (EtherNet/IP CIP)
  [SIMULATE] Would use CIP path: Backplane, slot 0 (controller), then send
  CIP service 0x0E (Get Attribute Single) to verify controller state before
  sending CIP service 0x4E (Reset) + program download sequence.
  Status: SIMULATE_OK

  [6/12] exploits/protocols/pccc/pccc_slc500_program_download
  ──────────────────────────────────────────────────────────────────
  PCCC Allen-Bradley SLC-500 Program Download
  Target port: 44818 (EtherNet/IP encapsulating PCCC)
  [SIMULATE] Would send PCCC CMD 0x0F, FNC 0xAB (Protected Write) to
  download modified SLC-500 program file. PCCC provides no authentication
  on SLC-500/MicroLogix 1400 with factory configuration.
  Status: SIMULATE_OK

  [7/12] assessment/mitre_ics/t0843_program_download
  ──────────────────────────────────────────────────────────────────
  T0843 Assessment — Verify PLC Allows Unauthenticated Program Download
  [SIMULATE] Passive probe: check if target responds to S7comm port 102,
  EtherNet/IP port 44818, and FINS port 9600. Identify vendor/model.
  Report whether authentication is required for program download.
  Status: SIMULATE_OK

  [8/12] cve/schneider/cve_2018_7847_modicon_quantum_exec
  ──────────────────────────────────────────────────────────────────
  CVE-2018-7847 | Schneider Modicon Quantum Remote Code Execution
  Target port: 44818 (Schneider Modbus+ over TCP)
  [SIMULATE] Would exploit Modicon Quantum firmware to upload arbitrary
  code via the Unity program upload command (service 0x65). No
  authentication required. Affects all Quantum 140 CPU models.
  Status: SIMULATE_OK

  [9/12] cve/ge/cve_2021_27454_rx3i_program_download
  ──────────────────────────────────────────────────────────────────
  CVE-2021-27454 | GE PACSystems RX3i Unauthenticated Program Download
  Target port: 18245 (GE SRTP)
  [SIMULATE] Would use GE SRTP (Service Request Transport Protocol) to
  initiate unauthenticated PLC program download on RX3i CPE330/CPE400.
  SRTP provides no session authentication in default configuration.
  Status: SIMULATE_OK

  [10/12] cve/omron/cve_2022_34151_sysmac_studio_rce
  ──────────────────────────────────────────────────────────────────
  CVE-2022-34151 | Omron Sysmac Studio Project File RCE via FINS
  Target port: 9600 UDP (Omron FINS)
  [SIMULATE] Would craft a malicious Sysmac Studio project file and send
  it to the NX/NJ controller via FINS protocol. The vulnerability exists
  in the project file parser (path traversal + arbitrary write) allowing
  code execution on the engineering workstation.
  Status: SIMULATE_OK

  [11/12] cve/abb/cve_2019_18995_totalflow_rce
  ──────────────────────────────────────────────────────────────────
  CVE-2019-18995 | ABB TotalFlow Flow Computer Unauthenticated Download
  Target port: 3001 (ABB TotalFlow custom protocol)
  [SIMULATE] Would authenticate using the published default credentials
  (user: root, pass: totalflow) and upload modified measurement
  calibration data to manipulate gas flow billing calculations.
  Status: SIMULATE_OK

  [12/12] cve/yokogawa/cve_2020_5523_centum_program_download
  ──────────────────────────────────────────────────────────────────
  CVE-2020-5523 | Yokogawa CENTUM VP Unauthenticated Program Download
  Target port: 20111 (Yokogawa Vnet/IP)
  [SIMULATE] Would use Yokogawa proprietary protocol (Vnet/IP) to upload
  a modified CENTUM VP control program without authentication. Affects
  CENTUM VP R4.01 through R6.08.
  Status: SIMULATE_OK

  ════════════════════════════════════════════════════════════════════
  T0843 TTP Sweep Complete
  ════════════════════════════════════════════════════════════════════
  Target:    192.168.1.100
  Modules:   12/12
  Errors:    0
  Live hits: 0 (simulate mode)
  Duration:  8.3s
```

### With Flags

```
# Stop after first module returns a positive check
ixf > ttp T0859 192.168.1.100 --stop-on-first
[*] TTP T0859 (Valid Accounts) — 37 modules — stop-on-first=True
[*] [1/37] creds/siemens/s7_default_passwords
  [SIMULATE] Would test 12 known Siemens S7 default credentials
[+] Stopping: first module complete (simulate)

# Rate limit 500ms between modules
ixf > ttp T0836 10.0.0.100 --rate-limit 500
[*] TTP T0836 (Modify Parameter) — 18 modules — rate-limit=500ms

# Save results to JSON file
ixf > ttp T0866 192.168.1.100 --output /opt/results/t0866.json
[+] Results saved: /opt/results/t0866.json

# Live run (authorized labs only)
ixf > ttp T0839 192.168.1.100 --destructive
[!] WARNING: --destructive flag set. This will send live packets.
[?] Confirm live execution against 192.168.1.100? [yes/no]: yes
```

---

## `ttp-check` — Passive Technique Check

Perform a passive (read-only) check to determine if a target is potentially vulnerable to a technique, without executing any exploit steps.

**Syntax:**
```
ixf > ttp-check <technique_id> <target>
```

```
ixf > ttp-check T0812 192.168.1.100

  ╔══════════════════════════════════════════════════════════════════╗
  ║  IXF TTP Check — T0812: Default Credentials                     ║
  ╚══════════════════════════════════════════════════════════════════╝
  Target:  192.168.1.100
  Mode:    PASSIVE CHECK (no credentials attempted)

  Step 1: Port/service fingerprint
  ─────────────────────────────────
  [*] Probing common ICS service ports...
  [+] 192.168.1.100:102   — S7comm (Siemens)
  [+] 192.168.1.100:4840  — OPC UA
  [+] 192.168.1.100:80    — HTTP (HMI web interface)
  [+] 192.168.1.100:22    — SSH

  Step 2: Vendor/model identification
  ────────────────────────────────────
  [+] S7comm SZL response: Siemens S7-1500 CPU 1516-3 PN/DP
  [+] OPC UA server info: SIMATIC S7-1500 OPC UA Server
  [+] HTTP banner: "Siemens SIMATIC S7 Web Server"

  Step 3: Check known default credential databases
  ─────────────────────────────────────────────────
  [i] Found 4 known default credential sets for Siemens S7-1500:
      - S7comm: No password (factory default)
      - OPC UA: anonymous session (factory default)
      - Web server: admin / (empty)
      - Web server: guest / guest

  Step 4: Vulnerability assessment (passive)
  ──────────────────────────────────────────
  [!] S7comm port 102 open — factory default = no authentication
  [!] OPC UA port 4840 open — anonymous access likely enabled
  [!] Web interface port 80 open — default credentials likely present

  Result: HIGH PROBABILITY of T0812 exploitation
  Recommendation: Test with `ttp T0812 192.168.1.100` in simulate mode,
  then apply vendor hardening guide SI-ICS-002.
```

---

## `ttp-simulate` — Technique Simulation

Detailed step-by-step simulation showing exactly what each phase of an attack technique would do, including the packets that would be sent, without transmitting anything.

**Syntax:**
```
ixf > ttp-simulate <technique_id> [--vendor <vendor>]
```

```
ixf > ttp-simulate T0836

  ╔══════════════════════════════════════════════════════════════════╗
  ║  IXF TTP Simulator — T0836: Modify Parameter                    ║
  ╚══════════════════════════════════════════════════════════════════╝
  Mode: INTERACTIVE SIMULATION (no packets sent)

  ══ Phase 1: Reconnaissance ══════════════════════════════════════════
  Goal: Identify writable process parameters

  Simulated step 1.1: Modbus Read Holding Registers (FC03)
    → Request:  01 03 00 00 00 0A C5 CD  (read HR 0-9)
    → Response: [simulated] 10 registers containing setpoint values
    → Identified: HR[05] = 0x0064 (100 = temperature setpoint, °C)

  Simulated step 1.2: OPC UA Browse Address Space
    → Connect to opc.tcp://TARGET:4840/
    → Browse ns=3; s=PID_TempControl.Setpoint
    → Node type: Variable, writable (anonymous access allowed)

  ══ Phase 2: Parameter Modification ═════════════════════════════════
  Goal: Alter setpoint to cause process anomaly

  Simulated step 2.1: Modbus Write Multiple Registers (FC16)
    → Request:  01 10 00 05 00 01 02 01 90 FF FF
                unit=1, address=5, count=1, value=400 (0x0190)
    → Action:   Temperature setpoint raised from 100°C to 400°C
    → Physical impact: Heat exchanger will ramp to 400°C
                       Overheat safety trip at 280°C will activate
                       If safety trip disabled (T0878): runaway heating

  Simulated step 2.2: OPC UA Write Value
    → WriteRequest: NodeId=ns=3;s=PID_TempControl.Setpoint, Value=400.0
    → No authentication required (SecurityMode=None)
    → Physical impact: PID controller will drive output to maximum

  ══ Phase 3: Concealment ═════════════════════════════════════════════
  Goal: Hide the modification from operators (T0832/T0856)

  Simulated step 3.1: Manipulation of View (T0832)
    → Intercept Modbus FC03 read requests from HMI
    → Replace response with original value (100) while actual is 400
    → HMI displays 100°C; physical temperature rises undetected

  ══ Detection Indicators ═════════════════════════════════════════════
  - Unexpected Modbus FC16 write to HR[05] from non-engineering IP
  - OPC UA write event on PID setpoint node
  - Temperature process value diverges from HMI display
  - Process historian shows temperature anomaly

  ══ Remediation ══════════════════════════════════════════════════════
  - Enable Modbus write authentication (not native — use VPN/firewall)
  - Enable OPC UA SecurityMode: SignAndEncrypt with certificate auth
  - Monitor engineering workstation whitelist for authorized writes
  - Implement independent hardware high-temperature trip (hardwired)
```

---

## `ttp-list` — TTP Browser

Display all mapped TTPs, optionally filtered by tactic.

**Syntax:**
```
ixf > ttp-list [--tactic <tactic>] [--vendor <vendor>] [--protocol <protocol>]
```

### Full List

```
ixf > ttp-list

  TTP Index — All 74 Mapped Techniques
  ════════════════════════════════════════════════════════════════════════
  ID      Name                                   Modules   Tactic
  ──────────────────────────────────────────────────────────────────────
  T0800   Activate Firmware Update Mode              3    [Inhibit]
  T0801   Monitor Process State                      2    [Collection]
  T0802   Automated Collection                       5    [Collection]
  T0803   Block Command Message                      3    [Inhibit]
  T0804   Block Reporting Message                    2    [Inhibit]
  T0806   Brute Force I/O                            1    [Impair]
  T0807   Remote Services                            8    [Lateral]
  T0808   Replication via Removable Media            2    [Persistence]
  T0809   Data Destruction                           3    [Impact]
  T0810   Data Exfiltration over C2 Channel          2    [Collection]
  T0811   Data from Information Repositories         4    [Collection]
  T0812   Default Credentials                       37    [Lateral]
  T0813   Denial of Control                          5    [Impact]
  T0814   Denial of Service                          8    [Inhibit]
  T0815   Denial of View                             3    [Inhibit]
  T0816   Device Restart/Shutdown                    9    [Inhibit]
  T0817   Drive-by Compromise                        3    [InitAccess]
  T0819   Exploit Public-Facing Application         47    [InitAccess]
  T0820   Exploitation of Remote Services           12    [InitAccess]
  T0821   Modify Controller Tasking                  4    [Execution]
  T0822   External Remote Services                   6    [InitAccess]
  T0823   Graphical User Interface                   2    [Execution]
  T0824   I/O Image                                  1    [Execution]
  T0826   Loss of Availability                       4    [Impact]
  T0827   Loss of Control                            2    [Impact]
  T0831   Manipulation of Control                    6    [Impair]
  T0832   Manipulation of View                       3    [Collection]
  T0833   Modify Alarm Settings                      3    [Impair]
  T0834   Native API                                 2    [Execution]
  T0835   Detect Operating Mode                      2    [Inhibit]
  T0836   Modify Parameter                          18    [Impair]
  T0837   Module Firmware                            3    [Persistence]
  T0838   Modify Program                             5    [Inhibit]
  T0839   Firmware Modification                      7    [Persistence]
  T0840   Network Connection Enumeration             2    [Discovery]
  T0841   Network Sniffing                           3    [Discovery]
  T0842   Network Topology Mapping                   4    [Discovery]
  T0843   Program Download                          12    [Lateral/Exec]
  T0844   Program Upload                             8    [Collection]
  T0845   Program Organization Units                 2    [Execution]
  T0846   Remote System Discovery                    8    [Discovery]
  T0847   Replication via Removable Media            2    [Persistence]
  T0848   Rogue Master                               3    [InitAccess]
  T0849   Masquerading                               1    [Evasion]
  T0851   Rootkit                                    2    [Inhibit]
  T0852   Screen Capture                             2    [Collection]
  T0853   Scripting                                  3    [Execution]
  T0854   Serial Connection Enumeration              2    [Discovery]
  T0855   Unauthorized Command Message               6    [Impair]
  T0856   Spoof Reporting Message                    2    [Evasion/Inhibit]
  T0857   System Firmware                            4    [Persistence]
  T0858   Change Credential                          4    [Evasion]
  T0859   Valid Accounts                            37    [Persistence]
  T0860   Wireless Compromise                        3    [InitAccess]
  T0861   Point and Tag Identification               2    [Discovery]
  T0862   Supply Chain Compromise                    2    [InitAccess]
  T0863   User Execution                             2    [Execution]
  T0864   Transient Cyber Asset                      1    [InitAccess]
  T0865   Spearphishing Attachment                   3    [InitAccess]
  T0866   Exploitation for Lateral Movement          5    [Lateral]
  T0867   Lateral Tool Transfer                      2    [Lateral]
  T0869   Standard Application Layer Protocol        4    [C2]
  T0870   Commonly Used Port                         3    [C2]
  T0871   Execution through API                      4    [Exec/Impair]
  T0873   Project File Infection                     3    [Impair]
  T0874   Hooking                                    1    [Evasion]
  T0875   Change Program State                       2    [Impair]
  T0877   I/O Module Discovery                       3    [Discovery]
  T0878   Alarm Suppression                          6    [Inhibit]
  T0879   Damage to Property                         2    [Impact]
  T0880   Loss of Safety                             3    [Impact]
  T0881   Service Stop                               4    [Inhibit/Impact]
  T0882   Theft of Operational Information           3    [Collection/C2]
  T0883   Internet Accessible Device                 5    [Discovery]
  T0884   Connection Proxy                           2    [C2]
  T0885   Commonly Used Port (C2 variant)            2    [C2]
  T0888   Remote System Information Discovery        4    [Discovery]
  T0889   Modify Program (ICS variant)               3    [Persistence]
  T0890   Exploitation for Privilege Escalation      3    [PrivEsc]
  ──────────────────────────────────────────────────────────────────────
  Total: 74 techniques | 976+ modules
```

### Filtered by Evasion

```
ixf > ttp-list --tactic evasion

  TTP Index — Evasion (TA0103)
  ════════════════════════════════════════════════════════════════════════
  ID      Name                                   Modules   Description
  ──────────────────────────────────────────────────────────────────────
  T0849   Masquerading                               1    Disguise malicious traffic as legitimate ICS protocol traffic
  T0856   Spoof Reporting Message                    2    Inject false sensor/process data into reporting streams
  T0858   Change Credential                          4    Modify PLC/RTU credentials to lock out legitimate operators
  T0874   Hooking                                    1    Hook engineering software APIs to intercept/modify data shown to operators
  ──────────────────────────────────────────────────────────────────────
  Total: 4/5 techniques covered (80%) | 8 modules
  [!] Not covered: T0820.001 (Exploitation via legitimate OT protocol)
```

### Filtered by Persistence

```
ixf > ttp-list --tactic persistence

  TTP Index — Persistence (TA0110)
  ════════════════════════════════════════════════════════════════════════
  ID      Name                                   Modules   Description
  ──────────────────────────────────────────────────────────────────────
  T0808   Replication via Removable Media            2    Copy malware to USB for air-gapped environments
  T0837   Module Firmware                            3    Install modified I/O module firmware for persistent access
  T0839   Firmware Modification                      7    Modify PLC/RTU firmware to persist after power cycle
  T0847   Replication via Removable Media            2    Autorun from USB (engineering workstation vector)
  T0857   System Firmware                            4    Modify BIOS/UEFI/bootloader firmware on engineering workstations
  T0859   Valid Accounts                            37    Maintain access via stolen/created OT account credentials
  ──────────────────────────────────────────────────────────────────────
  Total: 6/8 techniques covered (75%) | 55 modules
```

### Filtered by Collection

```
ixf > ttp-list --tactic collection

  TTP Index — Collection (TA0100)
  ════════════════════════════════════════════════════════════════════════
  ID      Name                                   Modules   Description
  ──────────────────────────────────────────────────────────────────────
  T0801   Monitor Process State                      2    Read real-time PLC/RTU process data
  T0802   Automated Collection                       5    Automatically harvest ICS data over time
  T0810   Data Exfiltration over C2 Channel          2    Exfiltrate collected data through existing C2 channel
  T0811   Data from Information Repositories         4    Extract data from historians, MES, ERP with ICS access
  T0832   Manipulation of View                       3    Alter what operators see on HMI (T0832 spans Collection+Inhibit)
  T0844   Program Upload                             8    Upload (read) PLC programs to analyze control logic
  T0852   Screen Capture                             2    Capture HMI screens for process intelligence
  T0882   Theft of Operational Information           3    Exfiltrate process recipes, safety limits, operational data
  ──────────────────────────────────────────────────────────────────────
  Total: 8/9 techniques covered (88%) | 29 modules
```

---

## Assessment Modules by Technique

IXF ships dedicated assessment modules for each mapped technique under `assessment/mitre_ics/`. These modules perform safe, read-only checks to verify whether a target is susceptible.

### Full Run — T0843 Program Upload/Download Assessment

```
ixf > use assessment/mitre_ics/t0843_program_upload
ixf [assessment/mitre_ics/t0843_program_upload] > show options

  Module: assessment/mitre_ics/t0843_program_upload
  Path:   assessment/mitre_ics/t0843_program_upload
  MITRE:  T0843 (Program Download) | T0844 (Program Upload)
  Tactic: Lateral Movement, Collection

  Options:
  ──────────────────────────────────────────────────────────────────
  Name           Value        Required  Description
  ──────────────────────────────────────────────────────────────────
  target                      yes       Target PLC IP address
  protocol       auto         no        Force protocol: s7|enip|fins|auto
  port           auto         no        Override default port
  timeout        5            no        Connection timeout (seconds)
  verbose        false        no        Verbose output
  ──────────────────────────────────────────────────────────────────

ixf [assessment/mitre_ics/t0843_program_upload] > set target 192.168.1.100
[+] target => 192.168.1.100

ixf [assessment/mitre_ics/t0843_program_upload] > run

  ╔══════════════════════════════════════════════════════════════════╗
  ║  Assessment: T0843/T0844 Program Upload/Download                 ║
  ╚══════════════════════════════════════════════════════════════════╝
  Target: 192.168.1.100
  Mode:   SIMULATE

  [SIMULATE MODE — no packets sent]

  Phase 1: Protocol Detection
  ──────────────────────────────────────────────────────────────────
  Adversary reconnaissance step: identify which programming protocol
  is in use on the target controller.

  Would probe:
  - Port 102 (S7comm / ISO-TSAP) — Siemens
  - Port 44818 (EtherNet/IP CIP) — Rockwell/Omron/generic
  - Port 9600 UDP (FINS) — Omron
  - Port 18245 (GE SRTP) — GE PACSystems
  - Port 20111 (Vnet/IP) — Yokogawa
  - Port 4001 (Modbus gateway) — generic

  Phase 2: Authentication Check
  ──────────────────────────────────────────────────────────────────
  For each detected protocol, check if program upload/download
  requires authentication:

  S7comm (port 102):
    MITRE T0843: Program Download
    Action: Issue S7 STOP command → attempt PDU block download
    Authentication: None required by default on S7-300/400/1200
    Risk: CRITICAL — any LAN-connected host can download PLC programs

  EtherNet/IP CIP (port 44818):
    MITRE T0843: Program Download
    Action: Open CIP session → attempt program file write
    Authentication: None required on many ControlLogix configurations
    Risk: CRITICAL — ControlLogix default config accepts unauthenticated downloads

  Phase 3: Upload Capability
  ──────────────────────────────────────────────────────────────────
  MITRE T0844: Program Upload
  Would initiate program UPLOAD (read PLC logic back) to:
  - Retrieve current program for offline analysis
  - Identify safety system logic and setpoints
  - Find process critical sequences (TRITON attack model)

  Phase 4: Results
  ──────────────────────────────────────────────────────────────────
  Technique T0843 (Download): HIGH RISK — no auth on S7comm
  Technique T0844 (Upload):   HIGH RISK — program readable without auth
  Physical Risk: Adversary can download modified program that:
    - Disables safety interlocks
    - Modifies setpoints beyond safe limits
    - Hides malicious logic from operator view

  Remediation:
  ──────────────────────────────────────────────────────────────────
  1. Enable PLC password protection (S7: CPU access level >= 2)
  2. Block port 102 from IT network at OT firewall
  3. Enable allowlist: only authorized engineering workstations can
     communicate on port 102
  4. Enable code integrity verification (Siemens: TIA Portal + S7+)
  5. Monitor for unexpected CPU STOP events (ICS SIEM alert)
  6. Use IXF assessment/mitre_ics/t0843_program_upload monthly
```

### Other Available Assessment Modules

All assessment modules follow the same `use → set target → run` workflow:

| Module Path | MITRE ID | Technique |
|-------------|---------|-----------|
| `assessment/mitre_ics/t0800_firmware_update_mode` | T0800 | Activate Firmware Update Mode |
| `assessment/mitre_ics/t0803_block_command_message` | T0803 | Block Command Message |
| `assessment/mitre_ics/t0806_brute_force_io` | T0806 | Brute Force I/O |
| `assessment/mitre_ics/t0812_default_credentials` | T0812 | Default Credentials |
| `assessment/mitre_ics/t0813_denial_of_control` | T0813 | Denial of Control |
| `assessment/mitre_ics/t0814_denial_of_service` | T0814 | Denial of Service |
| `assessment/mitre_ics/t0816_device_restart` | T0816 | Device Restart/Shutdown |
| `assessment/mitre_ics/t0831_manipulation_of_control` | T0831 | Manipulation of Control |
| `assessment/mitre_ics/t0836_modify_parameter` | T0836 | Modify Parameter |
| `assessment/mitre_ics/t0839_firmware_modification` | T0839 | Firmware Modification |
| `assessment/mitre_ics/t0840_network_enum` | T0840 | Network Connection Enumeration |
| `assessment/mitre_ics/t0843_program_upload` | T0843/T0844 | Program Download/Upload |
| `assessment/mitre_ics/t0846_remote_discovery` | T0846 | Remote System Discovery |
| `assessment/mitre_ics/t0848_rogue_master` | T0848 | Rogue Master |
| `assessment/mitre_ics/t0851_rootkit` | T0851 | Rootkit |
| `assessment/mitre_ics/t0855_unauthorized_command` | T0855 | Unauthorized Command Message |
| `assessment/mitre_ics/t0856_spoof_reporting` | T0856 | Spoof Reporting Message |
| `assessment/mitre_ics/t0859_valid_accounts` | T0859 | Valid Accounts |
| `assessment/mitre_ics/t0861_point_tag_id` | T0861 | Point and Tag Identification |
| `assessment/mitre_ics/t0878_alarm_suppression` | T0878 | Alarm Suppression |
| `assessment/mitre_ics/t0879_damage_to_property` | T0879 | Damage to Property |
| `assessment/mitre_ics/t0880_loss_of_safety` | T0880 | Loss of Safety |

---

## Complete Technique-to-Module Mapping

All 74 covered techniques with representative module paths and vendor/CVE coverage:

| Technique ID | Name | Module Count | Representative Modules |
|-------------|------|-------------|------------------------|
| T0800 | Activate Firmware Update Mode | 3 | `exploits/protocols/s7comm/s7_firmware_update_mode`, `cve/siemens/cve_2019_10929_s7_fw_update` |
| T0801 | Monitor Process State | 2 | `exploits/protocols/modbus/modbus_read_all_registers`, `exploits/protocols/opcua/opcua_subscribe_all` |
| T0802 | Automated Collection | 5 | `exploits/protocols/modbus/modbus_logger`, `exploits/protocols/dnp3/dnp3_data_poller` |
| T0803 | Block Command Message | 3 | `exploits/protocols/modbus/modbus_command_block`, `exploits/protocols/dnp3/dnp3_control_block` |
| T0804 | Block Reporting Message | 2 | `exploits/protocols/iec104/iec104_asdu_drop`, `exploits/protocols/dnp3/dnp3_response_drop` |
| T0806 | Brute Force I/O | 1 | `exploits/protocols/modbus/modbus_io_brute_force` |
| T0807 | Remote Services | 8 | `exploits/protocols/s7comm/s7_remote_service_enum`, `cve/siemens/cve_2022_38773_s7_vnc` |
| T0808 | Replication via Removable Media | 2 | `assessment/mitre_ics/t0808_removable_media`, `cve/malware/stuxnet_usb_replication` |
| T0809 | Data Destruction | 3 | `cve/malware/industroyer2_data_wiper`, `cve/malware/notpetya_mbr_wiper` |
| T0810 | Data Exfiltration | 2 | `assessment/mitre_ics/t0810_data_exfil_c2`, `exploits/protocols/mqtt/mqtt_data_exfil` |
| T0811 | Data from Info Repos | 4 | `exploits/protocols/opcua/opcua_historian_read`, `cve/aveva/cve_2021_42536_historian_dump` |
| T0812 | Default Credentials | 37 | `creds/siemens/*`, `creds/schneider/*`, `creds/rockwell/*` (37 vendor modules) |
| T0813 | Denial of Control | 5 | `exploits/protocols/modbus/modbus_broadcast_flood`, `cve/malware/industroyer_dos` |
| T0814 | Denial of Service | 8 | `cve/siemens/cve_2019_13945_scalance_dos`, `exploits/protocols/enip/enip_forward_open_flood` |
| T0815 | Denial of View | 3 | `exploits/protocols/modbus/modbus_read_spoof`, `assessment/mitre_ics/t0815_denial_view` |
| T0816 | Device Restart/Shutdown | 9 | `exploits/protocols/s7comm/s7_cpu_stop_command`, `exploits/protocols/fins/fins_cpu_unit_reset` |
| T0817 | Drive-by Compromise | 3 | `cve/malware/kamacite_spearphishing`, `cve/malware/havex_watering_hole` |
| T0819 | Exploit Public-Facing App | 47 | 47 vendor CVE modules (Siemens, Schneider, Rockwell, GE, ABB, Honeywell, Emerson...) |
| T0820 | Exploitation of Remote Services | 12 | `cve/siemens/cve_2022_43767_wincc_path_traversal`, `cve/aveva/cve_2021_33544_intouch_rce` |
| T0821 | Modify Controller Tasking | 4 | `exploits/protocols/s7comm/s7_modify_task_scheduler`, `exploits/protocols/enip/enip_cip_motion_config` |
| T0822 | External Remote Services | 6 | `cve/siemens/cve_2022_46144_sinema_vpn_bypass`, `cve/fortinet/cve_2022_40684_ot_vpn` |
| T0823 | Graphical User Interface | 2 | `cve/aveva/cve_2021_42536_intouch_gui_exec`, `cve/ge/cve_2021_27454_cimplicity_gui` |
| T0824 | I/O Image | 1 | `exploits/protocols/s7comm/s7_io_image_read` |
| T0826 | Loss of Availability | 4 | `cve/malware/notpetya_destructive_wiper`, `cve/malware/industroyer2_load_shedding` |
| T0827 | Loss of Control | 2 | `assessment/mitre_ics/t0827_loss_of_control`, `cve/malware/triton_trisis_sis_attack` |
| T0831 | Manipulation of Control | 6 | `exploits/protocols/modbus/modbus_coil_flip`, `exploits/protocols/dnp3/dnp3_direct_operate` |
| T0832 | Manipulation of View | 3 | `exploits/protocols/modbus/modbus_read_intercept`, `exploits/protocols/opcua/opcua_value_spoof` |
| T0833 | Modify Alarm Settings | 3 | `exploits/protocols/opcua/opcua_alarm_deadband_modify`, `exploits/protocols/modbus/modbus_alarm_setpoint_write` |
| T0834 | Native API | 2 | `exploits/protocols/s7comm/s7_native_api_call`, `exploits/protocols/enip/enip_cip_native_api` |
| T0835 | Detect Operating Mode | 2 | `exploits/protocols/s7comm/s7_read_cpu_mode`, `exploits/protocols/enip/enip_read_controller_mode` |
| T0836 | Modify Parameter | 18 | `exploits/protocols/modbus/modbus_write_holding_register`, `exploits/protocols/s7comm/s7_write_db_block` |
| T0837 | Module Firmware | 3 | `cve/siemens/cve_2019_10929_s7_module_fw`, `exploits/protocols/profinet/profinet_fw_download` |
| T0838 | Modify Program | 5 | `exploits/protocols/s7comm/s7_ob1_inject`, `cve/malware/stuxnet_s7_program_injection` |
| T0839 | Firmware Modification | 7 | `cve/rockwell/cve_2022_1161_controllogix_modified_fw`, `cve/siemens/cve_2021_22681_s7_1500_fw_mod` |
| T0840 | Network Connection Enum | 2 | `scanners/ics/modbus_scanner`, `scanners/ics/enip_scanner` |
| T0841 | Network Sniffing | 3 | `assessment/mitre_ics/t0841_network_sniff`, `scanners/ics/ics_protocol_fingerprint` |
| T0842 | Network Topology Mapping | 4 | `scanners/ics/ics_network_mapper`, `scanners/ics/profinet_dcp_scan` |
| T0843 | Program Download | 12 | `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key`, `cve/rockwell/cve_2022_1161_controllogix_modified_fw` |
| T0844 | Program Upload | 8 | `exploits/protocols/s7comm/s7_plc_program_upload_download`, `exploits/protocols/enip/enip_program_upload` |
| T0845 | Program Organization Units | 2 | `exploits/protocols/s7comm/s7_pou_enum`, `exploits/protocols/enip/enip_pou_list` |
| T0846 | Remote System Discovery | 8 | `scanners/ics/s7_comm_scanner`, `scanners/ics/bacnet_discovery`, `scanners/ics/iec104_scan` |
| T0847 | Replication via Removable Media | 2 | `assessment/mitre_ics/t0847_usb_rep`, `cve/malware/stuxnet_usb_lnk` |
| T0848 | Rogue Master | 3 | `exploits/protocols/modbus/modbus_rogue_master`, `exploits/protocols/dnp3/dnp3_rogue_master` |
| T0849 | Masquerading | 1 | `assessment/mitre_ics/t0849_masquerade_ics_traffic` |
| T0851 | Rootkit | 2 | `assessment/mitre_ics/t0851_rootkit`, `cve/malware/triton_trisis_rootkit` |
| T0852 | Screen Capture | 2 | `exploits/protocols/opcua/opcua_hmi_screenshot`, `cve/aveva/cve_2021_42536_screen_capture` |
| T0853 | Scripting | 3 | `exploits/protocols/s7comm/s7_scl_exec`, `exploits/protocols/enip/enip_script_exec` |
| T0854 | Serial Connection Enum | 2 | `scanners/ics/serial_rs485_scan`, `scanners/ics/serial_modbus_rtu_probe` |
| T0855 | Unauthorized Command Msg | 6 | `exploits/protocols/dnp3/dnp3_direct_operate_unauth`, `exploits/protocols/iec104/iec104_setpoint_no_auth` |
| T0856 | Spoof Reporting Message | 2 | `exploits/protocols/modbus/modbus_report_spoof`, `exploits/protocols/dnp3/dnp3_response_spoof` |
| T0857 | System Firmware | 4 | `cve/siemens/cve_2022_38773_wincc_fw_mod`, `cve/rockwell/cve_2019_10956_factorytalk_fw` |
| T0858 | Change Credential | 4 | `exploits/protocols/s7comm/s7_change_plc_password`, `exploits/protocols/opcua/opcua_user_modify` |
| T0859 | Valid Accounts | 37 | `creds/siemens/*`, `creds/schneider/*`, `creds/rockwell/*`, `creds/honeywell/*` |
| T0860 | Wireless Compromise | 3 | `exploits/protocols/wlan/ics_wifi_deauth`, `cve/malware/triton_wireless_lat_mov` |
| T0861 | Point and Tag Identification | 2 | `scanners/ics/modbus_coil_register_map`, `scanners/ics/opcua_browse_address_space` |
| T0862 | Supply Chain Compromise | 2 | `cve/malware/solarwinds_ics_lateral`, `assessment/mitre_ics/t0862_supply_chain` |
| T0863 | User Execution | 2 | `cve/malware/kamacite_spearphishing_macro`, `cve/malware/havex_rat_exec` |
| T0864 | Transient Cyber Asset | 1 | `assessment/mitre_ics/t0864_transient_asset` |
| T0865 | Spearphishing Attachment | 3 | `cve/malware/kamacite_spearphishing`, `cve/malware/blackenergy_spearphish` |
| T0866 | Exploitation for Lateral Mvmt | 5 | `cve/siemens/cve_2022_43767_wincc_lateral`, `cve/rockwell/cve_2021_27478_factorytalk_lat` |
| T0867 | Lateral Tool Transfer | 2 | `assessment/mitre_ics/t0867_lateral_tool`, `exploits/protocols/s7comm/s7_tool_transfer` |
| T0869 | Standard App Layer Protocol | 4 | `exploits/protocols/mqtt/mqtt_c2_channel`, `exploits/protocols/opcua/opcua_c2_tunnel` |
| T0870 | Commonly Used Port | 3 | `assessment/mitre_ics/t0870_common_port_c2`, `exploits/protocols/modbus/modbus_c2_channel` |
| T0871 | Execution through API | 4 | `exploits/protocols/opcua/opcua_method_call`, `exploits/protocols/enip/enip_cip_api_exec` |
| T0873 | Project File Infection | 3 | `cve/malware/stuxnet_step7_project`, `cve/siemens/cve_2019_10929_tia_portal_project_infect` |
| T0874 | Hooking | 1 | `assessment/mitre_ics/t0874_ics_api_hook` |
| T0875 | Change Program State | 2 | `exploits/protocols/s7comm/s7_force_program_state`, `exploits/protocols/enip/enip_run_stop_control` |
| T0877 | I/O Module Discovery | 3 | `exploits/protocols/s7comm/s7_read_szl_list`, `exploits/protocols/enip/enip_list_identity` |
| T0878 | Alarm Suppression | 6 | `assessment/mitre_ics/t0878_alarm_suppression`, `exploits/protocols/dnp3/dnp3_unsolicited_disable` |
| T0879 | Damage to Property | 2 | `assessment/mitre_ics/t0879_damage_to_property`, `cve/malware/triton_trisis_sis_attack` |
| T0880 | Loss of Safety | 3 | `assessment/mitre_ics/t0880_loss_of_safety`, `cve/malware/triton_trisis_safety_override` |
| T0881 | Service Stop | 4 | `cve/siemens/cve_2019_13945_s7_service_stop`, `exploits/protocols/s7comm/s7_cpu_stop_command` |
| T0882 | Theft of Operational Info | 3 | `exploits/protocols/opcua/opcua_recipe_dump`, `exploits/protocols/s7comm/s7_db_exfil` |
| T0883 | Internet Accessible Device | 5 | `scanners/ics/shodan_ics_lookup`, `scanners/ics/censys_ics_lookup` |
| T0884 | Connection Proxy | 2 | `assessment/mitre_ics/t0884_ot_proxy`, `exploits/protocols/mqtt/mqtt_broker_proxy` |
| T0885 | Commonly Used Port (C2) | 2 | `assessment/mitre_ics/t0885_c2_port`, `exploits/protocols/modbus/modbus_c2` |
| T0888 | Remote System Info Discovery | 4 | `exploits/protocols/s7comm/s7_read_system_info`, `exploits/protocols/enip/enip_get_attribute_all` |
| T0889 | Modify Program (ICS) | 3 | `exploits/protocols/s7comm/s7_ob_inject`, `cve/malware/stuxnet_s7_program_modification` |
| T0890 | Exploitation for PrivEsc | 3 | `cve/siemens/cve_2022_43767_wincc_privesc`, `cve/aveva/cve_2021_42536_system_platform_privesc` |

---

## ATT&CK Navigator JSON Format

### Layer File Fields Reference

The ATT&CK Navigator layer format (v4.5) used by IXF exports:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Layer display name |
| `versions.attack` | string | ATT&CK version (e.g., "14") |
| `versions.navigator` | string | Navigator app version |
| `versions.layer` | string | Layer format version |
| `domain` | string | `"ics-attack"` for ICS layers |
| `description` | string | Layer description text |
| `filters.platforms` | array | ICS target platform filter |
| `techniques[].techniqueID` | string | MITRE technique ID (e.g., "T0836") |
| `techniques[].tactic` | string | Tactic slug (e.g., "impair-process-control") |
| `techniques[].score` | number | Numeric score (IXF uses module count) |
| `techniques[].color` | string | Hex color override |
| `techniques[].comment` | string | Per-technique annotation |
| `techniques[].metadata` | array | Key-value metadata pairs |
| `gradient.colors` | array | Color scale from min to max score |
| `gradient.minValue` | number | Score mapped to gradient start |
| `gradient.maxValue` | number | Score mapped to gradient end |
| `legendItems` | array | Color legend labels |

---

## Integration with ATT&CK Navigator

### Opening the IXF Layer

1. Generate the layer file:
   ```
   ixf > mitre-report layer
   [+] ixf_mitre_layer_20260601.json
   ```

2. Open [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/)

3. Click **"Open Existing Layer"** → **"Upload from Local"**

4. Select the `ixf_mitre_layer_20260601.json` file

5. The ICS matrix loads with IXF coverage color-coded:
   - **Deep red**: High coverage (>20 modules)
   - **Orange**: Medium coverage (5-20 modules)
   - **Yellow**: Low coverage (1-4 modules)
   - **White**: Not covered

### Customizing the Layer

After loading, you can:
- Click any technique to view IXF module annotations
- Toggle tactic columns to focus on specific attack phases
- Combine with other layers (threat actor layers, defensive layers) using Navigator's layer comparison
- Export the visual as SVG or PNG for reports
- Filter by platform to show only techniques relevant to your ICS environment (e.g., "Field Controller/RTU/PLC/IED")

### Using with MITRE ATT&CK for ICS Resources

- [ATT&CK for ICS Matrix](https://attack.mitre.org/matrices/ics/)
- [ICS Technique Index](https://attack.mitre.org/techniques/ics/)
- [ICS Groups](https://attack.mitre.org/groups/) — XENOTIME, Sandworm, ELECTRUM, Dragonfly
- [ICS Campaigns](https://attack.mitre.org/campaigns/) — C0028 (2022 Ukraine), C0025 (Industroyer2)
- [ICS Mitigations](https://attack.mitre.org/mitigations/ics/) — cross-reference with IXF module findings

### Programmatic Layer Generation

You can generate a layer programmatically from Python using IXF's API:

```python
from industrialxpl.mitre import ICSMitreMapper

mapper = ICSMitreMapper()

# Get coverage summary
coverage = mapper.get_coverage()
print(f"Coverage: {coverage.pct}% ({coverage.covered}/{coverage.total})")

# Export Navigator layer
layer_json = mapper.export_navigator_layer(
    name="IXF Custom Assessment",
    description="Post-assessment coverage for Site Alpha",
    color_scheme="red_orange_yellow"
)
with open("site_alpha_layer.json", "w") as f:
    f.write(layer_json)

# Get modules for a specific technique
modules = mapper.get_modules("T0836")
for module in modules:
    print(f"  {module.path} — {module.description}")
```

---

*Previous: [SafeMode / DestructiveMode](05-safemode-destructivemode.md) | Next: [SAST / LLM Analysis](07-sast-llm.md)*
