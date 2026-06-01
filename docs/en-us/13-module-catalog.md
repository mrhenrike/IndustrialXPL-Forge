# Module Catalog

IXF ships with 976 modules spanning CVE exploits, protocol abuse, scanners, credential testers, assessment tools, and malware TTP replicas. This catalog provides a complete, searchable reference for all available modules, organized by category.

---

## Table of Contents

1. [Introduction and Statistics](#introduction-and-statistics)
2. [CVE Modules by Vendor](#cve-modules-by-vendor)
3. [Protocol Exploit Modules](#protocol-exploit-modules)
4. [Scanner Modules](#scanner-modules)
5. [Credential Modules](#credential-modules)
6. [Assessment Modules](#assessment-modules)
7. [Malware TTP Modules](#malware-ttp-modules)
8. [Native Malware Artifacts](#native-malware-artifacts)
9. [How to Search](#how-to-search)
10. [How to Filter by MITRE Technique](#how-to-filter-by-mitre-technique)

---

## Introduction and Statistics

The IXF module catalog is indexed at startup from the `industrialxpl/modules/` directory tree. The framework automatically discovers all Python classes named `Exploit` that subclass the base `Exploit` class and contain a valid `__info__` dictionary.

**Module counts:**

| Category | Count | Description |
|----------|-------|-------------|
| CVE exploits | 612 | Vendor-specific CVE-based exploits |
| Protocol exploits | 89 | Protocol-level abuse and manipulation |
| PLC exploits | 44 | PLC-specific vulnerability modules |
| SCADA exploits | 38 | SCADA platform vulnerabilities |
| Scanners | 31 | Protocol detection and fingerprinting |
| Credential modules | 34 | Default and hardcoded credential testers |
| Malware TTP modules | 26 | Named malware behavior replicas |
| APT TTP modules | 14 | Nation-state group TTP replicas |
| Assessment modules | 88 | Compliance and MITRE assessment |
| **TOTAL** | **976** | All modules |

**Severity distribution:**

| Severity | Count | % |
|----------|-------|---|
| CATASTROPHIC | 8 | 0.8% |
| CRITICAL | 287 | 29.4% |
| HIGH | 341 | 35.0% |
| MEDIUM | 198 | 20.3% |
| LOW | 87 | 8.9% |
| INFO | 55 | 5.6% |

---

## CVE Modules by Vendor

CVE modules are organized under `industrialxpl/modules/cve/<vendor>/`. Each module targets a specific publicly disclosed vulnerability.

### Siemens — 67 modules

**Key CVEs:**

| Module Path | CVE | CVSS | Description |
|-------------|-----|------|-------------|
| `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key` | CVE-2021-22681 | 10.0 | S7-1200/1500 hardcoded crypto key |
| `cve/siemens/cve_2019_13945_scalance_auth_bypass` | CVE-2019-13945 | 9.8 | SCALANCE authentication bypass |
| `cve/siemens/cve_2022_38465_tia_portal_priv_esc` | CVE-2022-38465 | 8.1 | TIA Portal privilege escalation |
| `cve/siemens/cve_2023_44317_scalance_rce` | CVE-2023-44317 | 9.8 | SCALANCE W-700 RCE |
| `cve/siemens/cve_2019_19300_siprotec4_dos` | CVE-2019-19300 | 7.5 | SIPROTEC4 relay DoS |
| `cve/siemens/cve_2018_4832_wincc_path_traversal` | CVE-2018-4832 | 7.5 | WinCC path traversal |
| `cve/siemens/cve_2017_2681_logo_hardcoded_creds` | CVE-2017-2681 | 9.8 | LOGO! hardcoded credentials |
| `cve/siemens/cve_2016_9158_s7_1200_cpu_stop` | CVE-2016-9158 | 9.1 | S7-1200 unauthorized CPU stop |
| `cve/siemens/cve_2020_15782_s7_1500_rce` | CVE-2020-15782 | 9.8 | S7-1500 SIMATIC RCE |
| `cve/siemens/cve_2021_37185_wincc_oa_injection` | CVE-2021-37185 | 8.8 | WinCC OA injection |
| `cve/siemens/cve_2020_7580_simatic_net_dos` | CVE-2020-7580 | 7.5 | SIMATIC NET DoS |
| `cve/siemens/cve_2022_25622_scalance_hardcoded` | CVE-2022-25622 | 9.8 | SCALANCE hardcoded credentials |
| ... | ... | ... | ... |

Total Siemens CVEs: 67

---

### Schneider Electric — 48 modules

**Key CVEs:**

| Module Path | CVE | CVSS | Description |
|-------------|-----|------|-------------|
| `cve/schneider/cve_2022_37300_ecostruxure_rce` | CVE-2022-37300 | 9.8 | EcoStruxure Control Expert RCE |
| `cve/schneider/cve_2018_7760_ecostruxure_auth` | CVE-2018-7760 | 9.8 | EcoStruxure auth bypass |
| `cve/schneider/cve_2021_22719_citect_scada_rce` | CVE-2021-22719 | 9.8 | Citect SCADA RCE |
| `cve/schneider/cve_2020_28212_unity_pro_dos` | CVE-2020-28212 | 7.5 | Unity Pro DoS |
| `cve/schneider/cve_2019_6821_modicon_hardcoded` | CVE-2019-6821 | 9.8 | Modicon M340 hardcoded credentials |
| `cve/schneider/cve_2022_37301_ecostruxure_path` | CVE-2022-37301 | 7.5 | EcoStruxure path traversal |
| `cve/schneider/cve_2021_22717_powerlogic_bypass` | CVE-2021-22717 | 9.1 | PowerLogic auth bypass |
| `cve/schneider/cve_2020_7529_acti9_hardcoded` | CVE-2020-7529 | 9.8 | Acti9 PowerTag hardcoded creds |
| `cve/schneider/cve_2023_29412_ecostruxure_rce` | CVE-2023-29412 | 9.8 | EcoStruxure Operator Terminal Expert RCE |
| `cve/schneider/cve_2022_34751_modicon_bypass` | CVE-2022-34751 | 9.1 | Modicon authentication bypass |
| ... | ... | ... | ... |

Total Schneider CVEs: 48

---

### Rockwell Automation / Allen-Bradley — 39 modules

**Key CVEs:**

| Module Path | CVE | CVSS | Description |
|-------------|-----|------|-------------|
| `cve/rockwell/cve_2021_27478_logix_hardcoded` | CVE-2021-27478 | 10.0 | Logix 5000 hardcoded crypto |
| `cve/rockwell/cve_2022_1161_logix_firmware` | CVE-2022-1161 | 10.0 | Logix firmware manipulation |
| `cve/rockwell/cve_2020_12034_rslinx_dos` | CVE-2020-12034 | 7.5 | RSLinx Classic DoS |
| `cve/rockwell/cve_2021_22681_factorytalk_bypass` | CVE-2021-22681 | 9.8 | FactoryTalk auth bypass |
| `cve/rockwell/cve_2019_13510_rslinx_dos` | CVE-2019-13510 | 7.5 | RSLinx DoS via malformed EIP |
| `cve/rockwell/cve_2018_14829_panelview_rce` | CVE-2018-14829 | 9.8 | PanelView Plus RCE |
| `cve/rockwell/cve_2022_3156_stratix_auth_bypass` | CVE-2022-3156 | 9.8 | Stratix auth bypass |
| `cve/rockwell/cve_2021_33012_aol_dos` | CVE-2021-33012 | 8.6 | Arena simulation DoS |
| ... | ... | ... | ... |

Total Rockwell CVEs: 39

---

### GE / ABB / Hitachi Energy — 28 modules

**Key CVEs:**

| Module Path | CVE | CVSS | Description |
|-------------|-----|------|-------------|
| `cve/ge/cve_2018_10952_cimplicity_rce` | CVE-2018-10952 | 9.8 | GE Cimplicity RCE |
| `cve/ge/cve_2019_6553_rx3i_dos` | CVE-2019-6553 | 7.5 | RX3i controller DoS |
| `cve/ge/cve_2021_27430_ops_hub_sqli` | CVE-2021-27430 | 8.8 | Operations Hub SQLi |
| `cve/ge/cve_2020_25160_apex_web_rce` | CVE-2020-25160 | 9.8 | Apex Pro WebHMI RCE |
| `cve/abb/cve_2019_7232_pb610_hardcoded` | CVE-2019-7232 | 9.8 | PB610 Panel Builder hardcoded creds |
| `cve/abb/cve_2022_26057_ac500_dos` | CVE-2022-26057 | 7.5 | AC500 PLC DoS |
| `cve/hitachi/cve_2023_27116_wnnm_rce` | CVE-2023-27116 | 9.8 | WNNM RCE |
| ... | ... | ... | ... |

Total GE/ABB/Hitachi CVEs: 28

---

### Honeywell — 22 modules

**Key CVEs:**

| Module Path | CVE | CVSS | Description |
|-------------|-----|------|-------------|
| `cve/honeywell/cve_2021_37740_experion_dos` | CVE-2021-37740 | 7.5 | Experion PKS DoS |
| `cve/honeywell/cve_2020_12033_experion_hardcoded` | CVE-2020-12033 | 9.8 | Experion hardcoded credentials |
| `cve/honeywell/cve_2021_38397_mb_connect_rce` | CVE-2021-38397 | 9.8 | MB Connect RCE |
| `cve/honeywell/cve_2022_30314_fc_300_bypass` | CVE-2022-30314 | 9.1 | FC 300 auth bypass |
| `cve/honeywell/cve_2023_25078_ip_camera_rce` | CVE-2023-25078 | 9.8 | IP Camera RCE |
| ... | ... | ... | ... |

Total Honeywell CVEs: 22

---

### Emerson — 18 modules

**Key CVEs:**

| Module Path | CVE | CVSS | Description |
|-------------|-----|------|-------------|
| `cve/emerson/cve_2022_29965_roc800_hardcoded` | CVE-2022-29965 | 9.8 | ROC800 RTU hardcoded credentials |
| `cve/emerson/cve_2021_26264_deltav_rce` | CVE-2021-26264 | 9.8 | DeltaV DCS RCE |
| `cve/emerson/cve_2020_12025_ovation_dos` | CVE-2020-12025 | 7.5 | Ovation DCS DoS |
| `cve/emerson/cve_2022_30263_syncade_sqli` | CVE-2022-30263 | 8.8 | Syncade SQLi |
| ... | ... | ... | ... |

Total Emerson CVEs: 18

---

### Moxa — 15 modules

**Key CVEs:**

| Module Path | CVE | CVSS | Description |
|-------------|-----|------|-------------|
| `cve/moxa/cve_2020_25159_mgmt_auth_bypass` | CVE-2020-25159 | 9.8 | NPort Manager auth bypass |
| `cve/moxa/cve_2021_38427_nport_hardcoded` | CVE-2021-38427 | 9.8 | NPort hardcoded credentials |
| `cve/moxa/cve_2022_40225_iobank_bypass` | CVE-2022-40225 | 9.8 | ioBank auth bypass |
| `cve/moxa/cve_2019_9098_awk_3121_rce` | CVE-2019-9098 | 9.8 | AWK-3121 RCE |
| ... | ... | ... | ... |

Total Moxa CVEs: 15

---

### Additional Vendors (sample — 150+ vendors total)

| Vendor | Count | Sample CVEs |
|--------|-------|-------------|
| Omron | 12 | CVE-2022-31206 (FINS overflow), CVE-2023-27390 |
| Phoenix Contact | 11 | CVE-2022-3461 (EtherLine auth bypass) |
| Mitsubishi | 10 | CVE-2021-20587 (MELSEC bypass), CVE-2022-25157 |
| AVEVA | 14 | CVE-2023-34982 (InTouch RCE), CVE-2022-23853 |
| Inductive Automation | 8 | CVE-2023-39476 (Ignition RCE), CVE-2022-35869 |
| Yokogawa | 9 | CVE-2021-38390 (CENTUM RCE), CVE-2022-3261 |
| Wago | 7 | CVE-2022-45138 (e!COCKPIT RCE) |
| B&R | 6 | CVE-2022-43228 (Automation Studio bypass) |
| Advantech | 13 | CVE-2023-2976 (WebAccess RCE), CVE-2021-33920 |
| Beckhoff | 5 | CVE-2022-28357 (TwinCAT DoS) |
| Danfoss | 4 | CVE-2022-3204 (PLUS+1 bypass) |
| HMS Networks | 4 | CVE-2021-46389 (Anybus gateway RCE) |
| Kepware | 6 | CVE-2022-2848 (KEPServerEX RCE) |
| OPC Foundation | 3 | CVE-2023-27321 (.NET Classic overflow) |
| Codesys | 11 | CVE-2021-29240 (runtime RCE), CVE-2022-4048 |
| Triangle MicroWorks | 4 | CVE-2019-10979 (DNP3 master overflow) |
| DataCom | 3 | CVE-2023-31246 (SCADA bypass) |
| Sprecher Automation | 2 | CVE-2022-37785 (SPRECON bypass) |
| SAIA Burgess | 3 | CVE-2022-45137 (PG5 bypass) |
| Red Lion | 4 | CVE-2021-40885 (Crimson3 RCE) |
| AutomationDirect | 5 | CVE-2022-2589 (DirectSOFT bypass) |
| ProSoft | 3 | CVE-2022-3012 (EtherNet/IP bypass) |
| Pepperl+Fuchs | 2 | CVE-2022-27577 (WirelessHART gateway) |
| Belden/Hirschmann | 5 | CVE-2022-4897 (RSP bypass) |
| Cisco IoT | 8 | CVE-2023-20076 (IE series RCE) |
| ...and 125+ more vendors | ... | ... |

---

## Protocol Exploit Modules

Protocol modules are under `industrialxpl/modules/exploits/protocols/`. They exploit weaknesses in ICS communication protocols without requiring a specific vendor CVE.

### Modbus TCP — 34 modules

| Module Path | Severity | Description |
|-------------|----------|-------------|
| `exploits/protocols/modbus/modbus_detect` | INFO | FC04 device detection probe |
| `exploits/protocols/modbus/modbus_fc01_read_coils` | LOW | Read coils (discrete outputs) without auth |
| `exploits/protocols/modbus/modbus_fc03_read_holding` | LOW | Read holding registers without auth |
| `exploits/protocols/modbus/modbus_fc05_write_coil` | HIGH | Write single coil — unauthenticated |
| `exploits/protocols/modbus/modbus_fc06_write_register` | HIGH | Write single register — unauthenticated |
| `exploits/protocols/modbus/modbus_fc15_write_coils` | HIGH | Write multiple coils — unauthenticated |
| `exploits/protocols/modbus/modbus_fc16_write_registers` | HIGH | Write multiple registers — unauthenticated |
| `exploits/protocols/modbus/modbus_fc43_mei_device_id` | LOW | FC43 MEI device identification read |
| `exploits/protocols/modbus/modbus_replay_attack` | HIGH | Replay captured Modbus write frames |
| `exploits/protocols/modbus/modbus_flood_dos` | HIGH | FC03 flood DoS attack |
| `exploits/protocols/modbus/modbus_unit_id_scan` | LOW | Unit ID enumeration (1-247) |
| `exploits/protocols/modbus/modbus_register_scan` | LOW | Full register address range scan |
| `exploits/protocols/modbus/modbus_exception_probe` | LOW | Illegal function code response analysis |
| `exploits/protocols/modbus/modbus_set_listen_only` | MEDIUM | Force device to listen-only mode |

---

### Siemens S7comm — 28 modules

| Module Path | Severity | Description |
|-------------|----------|-------------|
| `exploits/protocols/s7comm/s7_connect_probe` | INFO | COTP/S7 connectivity probe |
| `exploits/protocols/s7comm/s7_info_gather` | LOW | CPU identification (SZL-SSL 0x001C) |
| `exploits/protocols/s7comm/s7_cpu_stop` | CRITICAL | Unauthorized CPU STOP command |
| `exploits/protocols/s7comm/s7_cpu_start` | HIGH | Unauthorized CPU START command |
| `exploits/protocols/s7comm/s7_db_read` | MEDIUM | Read data block without auth |
| `exploits/protocols/s7comm/s7_db_write` | HIGH | Write data block without auth |
| `exploits/protocols/s7comm/s7_program_download` | CRITICAL | PLC program upload/download (T0843) |
| `exploits/protocols/s7comm/s7_szl_read` | LOW | SZL system status list read |
| `exploits/protocols/s7comm/s7_block_list` | LOW | Enumerate all program blocks |
| `exploits/protocols/s7comm/s7_firmware_read` | MEDIUM | Read firmware version and order number |
| `exploits/protocols/s7comm/s7_watchdog_bypass` | HIGH | S7 watchdog bypass via keepalives |
| `exploits/protocols/s7comm/s7_cotp_connect` | INFO | COTP connection establishment |

---

### EtherNet/IP (CIP) — 22 modules

| Module Path | Severity | Description |
|-------------|----------|-------------|
| `exploits/protocols/ethernetip/enip_list_identity` | INFO | CIP List Identity broadcast |
| `exploits/protocols/ethernetip/enip_list_services` | INFO | CIP List Services request |
| `exploits/protocols/ethernetip/enip_session_open` | LOW | Open CIP session without auth |
| `exploits/protocols/ethernetip/enip_read_tag` | MEDIUM | Read PLC tag without auth |
| `exploits/protocols/ethernetip/enip_write_tag` | CRITICAL | Write PLC tag without auth |
| `exploits/protocols/ethernetip/enip_cpu_reset` | CRITICAL | Unauthorized CPU reset via CIP |
| `exploits/protocols/ethernetip/enip_scan_objects` | LOW | CIP object enumeration |
| `exploits/protocols/ethernetip/enip_pccc_read` | MEDIUM | Legacy PCCC data read |
| `exploits/protocols/ethernetip/enip_pccc_write` | HIGH | Legacy PCCC data write |
| `exploits/protocols/ethernetip/enip_flood_dos` | HIGH | CIP session flood DoS |

---

### DNP3 — 18 modules

| Module Path | Severity | Description |
|-------------|----------|-------------|
| `exploits/protocols/dnp3/dnp3_link_status` | INFO | DNP3 link status probe |
| `exploits/protocols/dnp3/dnp3_read_class0_data` | LOW | Read Class 0 (static) data |
| `exploits/protocols/dnp3/dnp3_read_class123_data` | LOW | Read Class 1/2/3 (event) data |
| `exploits/protocols/dnp3/dnp3_direct_operate` | CRITICAL | Direct operate without auth (CROB) |
| `exploits/protocols/dnp3/dnp3_select_before_operate` | HIGH | Select-before-operate sequence |
| `exploits/protocols/dnp3/dnp3_time_sync` | MEDIUM | Force time synchronization |
| `exploits/protocols/dnp3/dnp3_replay_attack` | HIGH | Replay DNP3 control frames |
| `exploits/protocols/dnp3/dnp3_unsolicited_flood` | HIGH | Unsolicited response flood DoS |
| `exploits/protocols/dnp3/dnp3_auth_bypass` | CRITICAL | SAv5 authentication bypass |
| `exploits/protocols/dnp3/dnp3_malformed_frame_dos` | MEDIUM | Malformed frame DoS |

---

### IEC 60870-5-104 — 16 modules

| Module Path | Severity | Description |
|-------------|----------|-------------|
| `exploits/protocols/iec104/iec104_startdt` | INFO | STARTDT session initiation |
| `exploits/protocols/iec104/iec104_interrogation` | LOW | General Interrogation command |
| `exploits/protocols/iec104/iec104_single_command` | CRITICAL | Single point command (TypeID 45) |
| `exploits/protocols/iec104/iec104_double_command` | CRITICAL | Double point command (TypeID 46) |
| `exploits/protocols/iec104/iec104_setpoint_float` | CRITICAL | Setpoint command normalized float |
| `exploits/protocols/iec104/iec104_time_sync` | MEDIUM | RTU time synchronization command |
| `exploits/protocols/iec104/iec104_startdt_flood` | HIGH | STARTDT flood DoS |
| `exploits/protocols/iec104/iec104_replay_attack` | HIGH | Command replay attack |
| `exploits/protocols/iec104/iec104_session_enum` | INFO | IEC 104 session enumeration |

---

### OPC UA — 14 modules

| Module Path | Severity | Description |
|-------------|----------|-------------|
| `exploits/protocols/opcua/opcua_anonymous_browse` | HIGH | Anonymous namespace browse |
| `exploits/protocols/opcua/opcua_unauth_read` | HIGH | Unauthenticated node read |
| `exploits/protocols/opcua/opcua_unauth_write` | CRITICAL | Unauthenticated node write |
| `exploits/protocols/opcua/opcua_session_hijack` | CRITICAL | Session token replay |
| `exploits/protocols/opcua/opcua_dos_flood` | HIGH | OPC UA session flood |
| `exploits/protocols/opcua/opcua_endpoint_enum` | INFO | Endpoint and security mode enumeration |
| `exploits/protocols/opcua/opcua_method_invoke` | HIGH | Unauthorized method invocation |
| `exploits/protocols/opcua/opcua_subscription_enum` | MEDIUM | Subscription and monitored item enum |

---

### BACnet/IP — 12 modules

| Module Path | Severity | Description |
|-------------|----------|-------------|
| `exploits/protocols/bacnet/bacnet_who_is` | INFO | Who-Is broadcast device discovery |
| `exploits/protocols/bacnet/bacnet_read_property` | LOW | Read property without auth |
| `exploits/protocols/bacnet/bacnet_write_property` | CRITICAL | Write property without auth |
| `exploits/protocols/bacnet/bacnet_reinitialize_device` | CRITICAL | Reinitialize (reboot) device |
| `exploits/protocols/bacnet/bacnet_who_has` | INFO | Who-Has object enumeration |
| `exploits/protocols/bacnet/bacnet_flood_dos` | HIGH | Who-Is flood DoS |
| `exploits/protocols/bacnet/bacnet_bbmd_scan` | INFO | BBMD router enumeration |

---

### IEC 61850 — 10 modules

| Module Path | Severity | Description |
|-------------|----------|-------------|
| `exploits/protocols/iec61850/goose_replay` | CRITICAL | GOOSE frame replay attack |
| `exploits/protocols/iec61850/goose_inject` | CRITICAL | Forged GOOSE multicast injection |
| `exploits/protocols/iec61850/mms_browse` | MEDIUM | MMS namespace anonymous browse |
| `exploits/protocols/iec61850/mms_read_dataset` | MEDIUM | Read MMS dataset without auth |
| `exploits/protocols/iec61850/mms_write_value` | CRITICAL | Write MMS control value |
| `exploits/protocols/iec61850/sv_replay` | CRITICAL | Sampled Values replay attack |

---

### Other Protocols (additional — 50 protocols total)

| Protocol | Port | Modules | Key Capabilities |
|----------|------|---------|-----------------|
| PROFINET | 34964 | 9 | DCP scan, I&M record read, parameter write |
| MQTT | 1883/8883 | 8 | Topic enumeration, unauthenticated publish |
| CODESYS | 1217 | 7 | Runtime RCE, PLC program access |
| EtherCAT | — | 6 | ECAT frame manipulation |
| CC-Link | 5006 | 5 | Mitsubishi PLC communication abuse |
| HART-IP | 5094 | 5 | HART device parameter read/write |
| Foundation Fieldbus | — | 4 | FF HSE block parameter manipulation |
| PROFIBUS | — | 4 | DP/PA master-slave frame injection |
| DeviceNet | — | 3 | CIP-over-DeviceNet object access |
| AS-i | — | 2 | Actuator-Sensor interface bus abuse |
| KNX/EIBnet | 3671 | 4 | Building automation group write |
| LonWorks | — | 3 | LON network management packet |
| CANopen | — | 3 | CAN frame injection |
| J1939 | — | 3 | Vehicle/industrial CAN abuse |
| IEC 61968/61970 | — | 4 | CIM-based energy management |
| ICCP/TASE.2 | — | 3 | Control center-to-center protocol |
| IEEE C37.118 | — | 3 | Phasor data concentration |
| MMS (IEC 9506) | — | 5 | Generic MMS client/server abuse |
| FTP (OT context) | 21 | 4 | PLC firmware download via FTP |
| Telnet (OT context) | 23 | 4 | Unauthenticated PLC Telnet access |
| HTTP (OT context) | 80 | 6 | HMI web interface exploitation |
| SNMP (OT context) | 161 | 5 | OT device SNMP community string abuse |
| SSH (OT context) | 22 | 4 | Default SSH credentials for OT |
| RDP (OT context) | 3389 | 4 | HMI RDP credential spray |
| WinRM (OT context) | 5985 | 3 | PowerShell OT lateral movement |
| Modbus RTU/ASCII | — | 6 | Serial Modbus protocol abuse |
| DNP3 Serial | — | 4 | Serial DNP3 protocol abuse |
| ICMP (OT sweep) | — | 3 | Ping sweep with OT fingerprinting |

---

## Scanner Modules

Scanner modules are under `industrialxpl/modules/scanners/`. They perform read-only protocol detection and device fingerprinting. All 31 scanner modules default to `simulate=True` and use `check()` for passive probing.

| # | Module Path | Protocol | Port | Description |
|---|------------|---------|------|-------------|
| 1 | `scanners/ics/modbus_detect` | Modbus TCP | 502 | FC04 probe + FC43 MEI identification |
| 2 | `scanners/ics/modbus_range_scanner` | Modbus TCP | 502 | Register range scan (0x0000–0xFFFF) |
| 3 | `scanners/ics/s7_comm_scanner` | S7comm | 102 | COTP+S7 Setup Communication probe |
| 4 | `scanners/ics/s7_info_gather` | S7comm | 102 | S7 SZL CPU identification dump |
| 5 | `scanners/ics/bacnet_scanner` | BACnet/IP | 47808 | Who-Is broadcast + I-Am parse |
| 6 | `scanners/ics/bacnet_property_scanner` | BACnet/IP | 47808 | Read all object properties |
| 7 | `scanners/ics/dnp3_scanner` | DNP3 | 20000 | DNP3 Link Status probe |
| 8 | `scanners/ics/dnp3_data_scanner` | DNP3 | 20000 | Class 0 data integrity poll |
| 9 | `scanners/ics/enip_scanner` | EtherNet/IP | 44818 | CIP List Identity broadcast |
| 10 | `scanners/ics/enip_tag_scanner` | EtherNet/IP | 44818 | CIP tag enumeration |
| 11 | `scanners/ics/iec104_scanner` | IEC 104 | 2404 | STARTDT + General Interrogation |
| 12 | `scanners/ics/opcua_scanner` | OPC UA | 4840 | GetEndpoints + security mode enum |
| 13 | `scanners/ics/opcua_browse_scanner` | OPC UA | 4840 | OPC UA namespace browser |
| 14 | `scanners/ics/profinet_scanner` | PROFINET | 34964 | DCP identify request |
| 15 | `scanners/ics/codesys_scanner` | CODESYS | 1217 | CODESYS runtime detection |
| 16 | `scanners/ics/mqtt_scanner` | MQTT | 1883 | CONNECT + SUBSCRIBE probe |
| 17 | `scanners/ics/goose_listener` | IEC 61850 | — | Passive GOOSE multicast listener |
| 18 | `scanners/ics/mms_scanner` | MMS | 102 | MMS Initiate probe |
| 19 | `scanners/ics/hart_ip_scanner` | HART-IP | 5094 | HART-IP session establishment |
| 20 | `scanners/ics/ff_hse_scanner` | Foundation Fieldbus | — | FF HSE discovery |
| 21 | `scanners/ics/profibus_scanner` | PROFIBUS | — | DP scan request |
| 22 | `scanners/ics/cc_link_scanner` | CC-Link | 5006 | Mitsubishi network scan |
| 23 | `scanners/ics/knx_scanner` | KNX | 3671 | KNX search request |
| 24 | `scanners/ics/lonworks_scanner` | LonWorks | — | LON Who-Is-Router |
| 25 | `scanners/network/ot_port_sweep` | Multi | Various | Scan all known OT ports (50+) |
| 26 | `scanners/network/ics_banner_grab` | Multi | Various | OT service banner collection |
| 27 | `scanners/network/shodan_ics_query` | N/A (API) | N/A | Shodan search for ICS assets |
| 28 | `scanners/network/cve_version_check` | HTTP/FTP | Various | Version banner → CVE lookup |
| 29 | `scanners/ics/snmp_ics_scanner` | SNMP | 161 | OT device SNMP community probe |
| 30 | `scanners/ics/telnet_ics_detect` | Telnet | 23 | Telnet banner fingerprint |
| 31 | `scanners/ics/multi_protocol_sweep` | Multi | Various | Concurrent multi-protocol OT scan |

---

## Credential Modules

Credential modules are under `industrialxpl/modules/creds/`. All 34 modules test hardcoded or factory-default credentials found in public advisories and vendor documentation.

| # | Module Path | Vendor/Service | Port | Severity |
|---|------------|---------------|------|----------|
| 1 | `creds/siemens/ssh_default_creds` | Siemens (SSH) | 22 | HIGH |
| 2 | `creds/siemens/web_default_creds` | Siemens (HTTP) | 80 | HIGH |
| 3 | `creds/siemens/s7_default_creds` | Siemens S7comm | 102 | CRITICAL |
| 4 | `creds/siemens/ftp_default_creds` | Siemens (FTP) | 21 | HIGH |
| 5 | `creds/schneider/web_default_creds` | Schneider (HTTP) | 80 | HIGH |
| 6 | `creds/schneider/ftp_default_creds` | Schneider (FTP) | 21 | HIGH |
| 7 | `creds/schneider/modicon_default_creds` | Modicon (HTTP) | 80 | CRITICAL |
| 8 | `creds/rockwell/logix_default_creds` | Logix (EtherNet/IP) | 44818 | HIGH |
| 9 | `creds/rockwell/web_default_creds` | Rockwell (HTTP) | 80 | HIGH |
| 10 | `creds/ge/cimplicity_default_creds` | GE Cimplicity (HTTP) | 80 | HIGH |
| 11 | `creds/ge/proficy_default_creds` | GE Proficy (HTTP) | 80 | HIGH |
| 12 | `creds/honeywell/experion_default_creds` | Honeywell Experion | 80 | HIGH |
| 13 | `creds/honeywell/phd_default_creds` | Honeywell PHD | 80 | MEDIUM |
| 14 | `creds/emerson/roc800_hardcoded` | Emerson ROC800 | 4000 | CRITICAL |
| 15 | `creds/emerson/deltav_web_creds` | Emerson DeltaV | 80 | HIGH |
| 16 | `creds/abb/800xa_web_creds` | ABB 800xA | 80 | HIGH |
| 17 | `creds/moxa/nport_default_creds` | Moxa NPort (HTTP) | 80 | HIGH |
| 18 | `creds/moxa/nport_telnet_creds` | Moxa NPort (Telnet) | 23 | HIGH |
| 19 | `creds/omron/fins_default_creds` | Omron FINS | 9600 | HIGH |
| 20 | `creds/mitsubishi/melsec_web_creds` | Mitsubishi MELSEC | 80 | HIGH |
| 21 | `creds/aveva/intouch_web_creds` | AVEVA InTouch | 80 | HIGH |
| 22 | `creds/kepware/kepserver_web_creds` | PTC Kepware | 57412 | HIGH |
| 23 | `creds/inductive/ignition_web_creds` | Inductive Automation | 8088 | HIGH |
| 24 | `creds/generic/web_default_creds` | Generic HMI/SCADA (HTTP) | 80 | HIGH |
| 25 | `creds/generic/ftp_default_creds` | Generic OT FTP | 21 | MEDIUM |
| 26 | `creds/generic/telnet_default_creds` | Generic OT Telnet | 23 | HIGH |
| 27 | `creds/generic/ssh_default_creds` | Generic OT SSH | 22 | HIGH |
| 28 | `creds/generic/snmp_default_creds` | Generic SNMP v1/v2c | 161 | HIGH |
| 29 | `creds/generic/mqtt_default_creds` | Generic MQTT broker | 1883 | MEDIUM |
| 30 | `creds/generic/rdp_default_creds` | Generic HMI RDP | 3389 | HIGH |
| 31 | `creds/generic/opcua_default_creds` | Generic OPC UA | 4840 | HIGH |
| 32 | `creds/codesys/runtime_default_creds` | CODESYS runtime | 1217 | HIGH |
| 33 | `creds/wago/plc_default_creds` | WAGO PLC (HTTP) | 80 | HIGH |
| 34 | `creds/phoenix/plcnext_web_creds` | Phoenix PLCnext | 443 | HIGH |

---

## Assessment Modules

Assessment modules are under `industrialxpl/modules/assessment/`. All 88 assessment modules run in simulate mode only and provide structured analysis outputs.

**Compliance Assessment (18 modules):**

| Module Path | Framework | Description |
|------------|----------|-------------|
| `assessment/iec62443/zone_conduit_audit` | IEC 62443 | Zone and conduit boundary audit |
| `assessment/iec62443/security_level_assessment` | IEC 62443 | SL1-SL4 determination |
| `assessment/iec62443/foundational_requirements` | IEC 62443-3-3 | FR1-FR7 checklist |
| `assessment/nist_sp800_82/control_checklist` | NIST 800-82r3 | Full control family checklist |
| `assessment/nist_sp800_82/network_architecture` | NIST 800-82r3 | Network architecture review |
| `assessment/risk/ics_risk_scorer` | CISA/IEC 62443 | Weighted risk scoring |
| `assessment/risk/consequence_analysis` | IEC 61511 (SIL) | Physical consequence analysis |
| `assessment/threat_intel/ics_kill_chain` | Dragos/CISA | ICS Cyber Kill Chain |
| `assessment/threat_intel/apt_ics_actors` | MITRE/CISA | APT group threat intelligence |
| `assessment/ir/iacs_ir_playbook` | NIST 800-61r2 | ICS/OT IR playbook |
| `assessment/ir/recovery_guidance` | NIST/Dragos | PLC/historian recovery |
| `assessment/protocols/opcua_security_audit` | OPC Foundation | OPC UA security assessment |
| `assessment/protocols/dnp3_security_audit` | IEEE 1815/IEC 62351 | DNP3 SAv5 assessment |
| `assessment/protocols/iec61850_security_audit` | IEC 61850/62351 | Substation security assessment |
| `assessment/protocols/modbus_security_audit` | Modbus Org | Modbus TCP security assessment |
| `assessment/protocols/ethernetip_security_audit` | ODVA CIP | EtherNet/IP CIP assessment |
| `assessment/network/ics_firewall_audit` | NIST/IEC 62443 | OT firewall and segmentation |
| `assessment/network/industrial_network_assessment` | NIST/ISA-99 | Network infrastructure review |

**MITRE ATT&CK for ICS Assessment (28 modules):** See [All 28 MITRE Technique Assessment Modules](12-assessment-compliance.md#all-28-mitre-technique-assessment-modules).

**Additional assessment modules (42 modules):**

Sector-specific assessments, vulnerability chain analysis modules, and architecture review helpers are available under:
- `assessment/sector/energy_ot_assessment`
- `assessment/sector/water_ics_assessment`
- `assessment/sector/oil_gas_ot_assessment`
- `assessment/sector/manufacturing_ot_assessment`
- `assessment/chain/supply_chain_analysis`
- `assessment/architecture/purdue_model_review`

---

## Malware TTP Modules

Malware TTP modules are under `industrialxpl/modules/cve/malware/` and `industrialxpl/modules/cve/apt/`. All 26 modules replicate behaviors of known ICS-targeting malware for defensive research and red team exercises.

| # | Module Path | Malware Name | Year | Attribution | MITRE | Impact |
|---|------------|-------------|------|-------------|-------|--------|
| 1 | `cve/malware/stuxnet_centrifuge` | Stuxnet | 2010 | NSA/Unit 8200 | T0839, T0857 | CATASTROPHIC |
| 2 | `cve/malware/havex_opc_enum` | Havex | 2014 | APT28/Sandworm | T0802, T0888 | HIGH |
| 3 | `cve/malware/blackenergy_killdisk` | BlackEnergy3 | 2015 | Sandworm | T0809, T0831 | CATASTROPHIC |
| 4 | `cve/malware/industroyer_iec104` | Industroyer | 2016 | Sandworm | T0855, T0816 | CATASTROPHIC |
| 5 | `cve/malware/triton_safety_bypass` | TRITON/TRISIS | 2017 | APT33/XENOTIME | T0836, T0878 | CATASTROPHIC |
| 6 | `cve/malware/notpetya_wiper` | NotPetya | 2017 | Sandworm | T0809, T0840 | CATASTROPHIC |
| 7 | `cve/malware/industroyer2_iec104_rtu` | Industroyer2 | 2022 | Sandworm | T0855, T0816 | CATASTROPHIC |
| 8 | `cve/malware/incontroller_pipedream` | INCONTROLLER | 2022 | Russia-linked | T0843, T0855 | CATASTROPHIC |
| 9 | `cve/malware/frostygoop_modbus_heating` | FrostyGoop | 2024 | Sandworm | T0836, T0855 | CRITICAL |
| 10 | `cve/malware/cosmicenergy_iec104` | CosmicEnergy | 2023 | Rostelecom-Solar | T0855, T0831 | CRITICAL |
| 11 | `cve/malware/ekans_process_killer` | EKANS/Snake | 2020 | CHRYSENE/Iran | T0827, T0828 | CRITICAL |
| 12 | `cve/malware/oldsmar_florida_hmi` | Oldsmar Water | 2021 | Unknown | T0836, T0855 | CRITICAL |
| 13 | `cve/malware/shamoon_wiper` | Shamoon | 2012 | APT33/Iran | T0809 | HIGH |
| 14 | `cve/malware/crashoverride_breaker` | Crashoverride | 2016 | Sandworm | T0855, T0816 | CATASTROPHIC |
| 15 | `cve/malware/hiddenpower_modbus` | HiddenPower | 2019 | Unknown | T0836, T0855 | HIGH |
| 16 | `cve/malware/conti_ics_process_kill` | Conti ICS | 2021 | Conti Group | T0827 | HIGH |
| 17 | `cve/malware/darkside_ics_process_kill` | DarkSide OT | 2021 | DarkSide | T0827, T0828 | HIGH |
| 18 | `cve/malware/revil_ics_process_kill` | REvil OT | 2021 | REvil | T0827 | HIGH |
| 19 | `cve/malware/blackcat_ics_process` | BlackCat/ALPHV | 2022 | ALPHV Group | T0827 | HIGH |
| 20 | `cve/malware/cl0p_ics_process_kill` | CL0P OT | 2023 | TA505 | T0827, T0828 | HIGH |
| 21 | `cve/apt/dragonfly_energetic_bear` | Dragonfly | 2014 | APT33 | T0802, T0888 | HIGH |
| 22 | `cve/apt/apt33_shamoon_ics` | APT33 SCADA | 2018 | APT33 | T0809, T0836 | CRITICAL |
| 23 | `cve/apt/lazarus_nuclear` | Lazarus ICS | 2022 | Lazarus/DPRK | T0843, T0836 | CRITICAL |
| 24 | `cve/apt/volt_typhoon_ot_living` | Volt Typhoon | 2023 | Volt Typhoon/China | T0817, T0822 | HIGH |
| 25 | `cve/apt/sandworm_wiper_campaign` | Sandworm Wipers | 2022 | Sandworm | T0809, T0831 | CATASTROPHIC |
| 26 | `cve/apt/lockbit_ot_healthcare` | LockBit OT | 2023 | LockBit | T0827, T0828 | HIGH |

**Attribution years and impact note:** All modules replicate techniques for authorized red team and defensive research only. Live mode requires explicit `simulate=False` and `destructive=True`. Never run in production environments.

---

## Native Malware Artifacts

IXF includes compiled (or compilable) artifacts under `industrialxpl/modules/cve/malware/_native/`:

| Artifact | Language | Source | Output | Description |
|----------|----------|--------|--------|-------------|
| `killdisk.c` | C | `src/killdisk.c` | `.tmp/malware_builds/killdisk[.exe]` | BlackEnergy3/Industroyer MBR wiper |
| `notpetya.cpp` | C++ | `src/notpetya.cpp` | `.tmp/malware_builds/notpetya[.exe]` | NotPetya MBR + fake ransom |
| `frostygoop/` | Go | `src/frostygoop/` | `.tmp/malware_builds/frostygoop[.exe]` | FrostyGoop Modbus heating attack |
| `modbus_flood.c` | C | `src/modbus_flood.c` | `.tmp/malware_builds/modbus_flood[.exe]` | Modbus TCP flood DoS |
| `s7_watchdog.cpp` | C++ | `src/s7_watchdog.cpp` | `.tmp/malware_builds/s7_watchdog[.exe]` | S7 watchdog bypass |
| `ekans_process_killer.py` | Python | (native) | — | EKANS ICS process kill list |
| `plc_logic_bomb_st.py` | Python | (native) | `.tmp/*.st` | IEC 61131-3 ST logic bomb generator |

**Build tools:**
- `malware_builder.py` — builds C/C++/Go artifacts
- `tools/env_doctor.py` — checks compiler availability

---

## How to Search

### Search by keyword

```bash
ixf search <keyword>
```

Examples:

```bash
ixf search modbus           # All Modbus-related modules
ixf search siemens          # All Siemens modules
ixf search CVE-2022         # All 2022 CVEs
ixf search default_creds    # All credential modules
ixf search CRITICAL         # All CRITICAL severity modules
ixf search FrostyGoop       # Specific malware modules
ixf search T0836            # Modules covering T0836
ixf search scanner          # All scanner modules
ixf search assessment       # All assessment modules
```

### Search from Python API

```python
from industrialxpl.core.exploit.utils import index_modules, import_exploit

# Search by keyword in module path or name
mods = index_modules()
results = [m for m in mods if "modbus" in m.lower()]
print(f"Found {len(results)} Modbus modules:")
for r in results[:10]:
    print(f"  {r}")
```

### Search by severity

```python
from industrialxpl.core.exploit.utils import index_modules, import_exploit

mods = index_modules()
critical = []
for m in mods:
    try:
        info = import_exploit("industrialxpl.modules." + m)().get_info()
        if info.get("severity") in ("CRITICAL", "CATASTROPHIC"):
            critical.append((info["name"], info["cve"], info["cvss"]))
    except Exception:
        continue

print(f"CRITICAL/CATASTROPHIC modules: {len(critical)}")
```

### Search by vendor

```bash
ixf vendors siemens
ixf vendors schneider
ixf vendors rockwell
```

### Search by protocol

```bash
ixf protocols
ixf search modbus
ixf search S7comm
ixf search DNP3
```

---

## How to Filter by MITRE Technique

### CLI: List modules for a technique

```bash
ixf mitre-list T0836
```

**Output:**

```
[*] MITRE T0836 — Modify Parameter
  Tactic: Impair Process Control
  IXF Modules implementing T0836:
    cve/malware/frostygoop_modbus_heating          CRITICAL
    cve/malware/triton_safety_bypass               CATASTROPHIC
    exploits/protocols/modbus/modbus_write_coil    HIGH
    exploits/protocols/s7comm/s7_db_write          HIGH
    assessment/mitre_ics/t0836_modify_parameter    INFO
  5 modules cover T0836
```

### CLI: Run all modules for a technique

```bash
ixf mitre run T0836 --target 192.168.1.100
```

### CLI: List all techniques and their modules

```bash
ixf ttp-list
ixf mitre-coverage
```

### Python API: Filter by MITRE technique

```python
from industrialxpl.core.exploit.utils import index_modules, import_exploit

TARGET_TECHNIQUE = "T0836"

mods = index_modules()
matching = []

for m in mods:
    try:
        info = import_exploit("industrialxpl.modules." + m)().get_info()
        techniques = info.get("mitre_techniques", [])
        if TARGET_TECHNIQUE in techniques:
            matching.append({
                "path":    m,
                "name":    info["name"],
                "severity": info["severity"],
            })
    except Exception:
        continue

print(f"Modules for {TARGET_TECHNIQUE}: {len(matching)}")
for m in matching:
    print(f"  [{m['severity']:12}] {m['path']}")
```

### Python API: Build MITRE technique → module mapping

```python
from industrialxpl.core.exploit.utils import index_modules, import_exploit
from collections import defaultdict

mods = index_modules()
technique_map = defaultdict(list)

for m in mods:
    try:
        info = import_exploit("industrialxpl.modules." + m)().get_info()
        for tech in info.get("mitre_techniques", []):
            technique_map[tech].append({
                "path": m,
                "severity": info.get("severity"),
                "name": info.get("name"),
            })
    except Exception:
        continue

# Print all techniques with module counts
for tech, modules in sorted(technique_map.items()):
    print(f"  {tech}: {len(modules)} modules")
    for mod in modules[:3]:
        print(f"    [{mod['severity']:10}] {mod['path']}")
```

**Sample output:**

```
  T0800: 2 modules
    [HIGH      ] cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
    [INFO      ] assessment/mitre_ics/t0800_activate_firmware_update_mode
  T0802: 5 modules
    [HIGH      ] scanners/ics/modbus_range_scanner
    [MEDIUM    ] exploits/protocols/modbus/modbus_fc03_read_holding
    [LOW       ] scanners/ics/bacnet_property_scanner
  T0836: 5 modules
    [CRITICAL  ] cve/malware/frostygoop_modbus_heating
    [CATASTROPHIC] cve/malware/triton_safety_bypass
    [HIGH      ] exploits/protocols/modbus/modbus_write_coil
  ...
```

---

*Previous: [Assessment & Compliance](12-assessment-compliance.md) | Next: [NSE Scripts](14-nse-scripts.md)*
