# Complete Module Catalog

This document provides a comprehensive catalog of all 976+ modules in IndustrialXPL-Forge, organized by category. Use this as the definitive reference for understanding what modules exist and how to use them.

---

## Introduction

IndustrialXPL-Forge (IXF) modules are Python classes that implement the `BaseExploit` interface. Each module declares:
- `__info__` dictionary with metadata (name, CVE, CVSS, impact level, MITRE techniques)
- `run()` method — executes the exploit (simulate or live)
- `check()` method — read-only vulnerability check (optional but recommended)

Modules are organized in a hierarchical path structure under `industrialxpl/modules/`:

```
modules/
├── cve/          — CVE-specific exploits (150+ vendors, 486 modules)
├── exploits/     — Protocol exploits and generic exploits (159 modules)
├── creds/        — Default credential testers (34 modules)
├── scanners/     — ICS device scanners (31 modules)
├── assessment/   — Compliance and assessment (18 modules)
└── generic/      — Generic utility modules (12 modules)
```

---

## How to Search — 10 Examples

```bash
# By vendor name
ixf search siemens

# By CVE ID
ixf search CVE-2021-22681

# By protocol
ixf search modbus

# By impact level
ixf search CRITICAL

# By module category
ixf search default_creds

# By exploit type
ixf search dos

# By MITRE technique
ixf search T0836

# By product name
ixf search controllogix

# By technology keyword
ixf search firmware

# By year
ixf search 2024
```

---

## CVE Modules — All 150+ Vendors

### Vendor Summary Table

| Vendor | Module Count | Top CVEs | Path |
|--------|-------------|---------|------|
| Schneider Electric | 39 | CVE-2022-24323, CVE-2022-32512, CVE-2023-37195 | `cve/schneider_electric/` |
| Rockwell Automation | 38 | CVE-2022-1161, CVE-2023-3595, CVE-2021-33012 | `cve/rockwell/` + `cve/rockwell_automation/` |
| Siemens | 27 | CVE-2021-22681, CVE-2022-38465, CVE-2019-13945 | `cve/siemens/` |
| ABB | 22 | CVE-2022-0228, CVE-2023-0232, CVE-2024-2461 | `cve/abb/` |
| Honeywell | 20 | CVE-2023-5389, CVE-2021-38461, CVE-2022-30312 | `cve/honeywell/` |
| GE / GE Vernova | 18 | CVE-2022-29951, CVE-2023-1955, CVE-2024-9037 | `cve/ge/` + `cve/ge_vernova/` |
| Emerson | 16 | CVE-2022-29965, CVE-2020-12030, CVE-2023-51761 | `cve/emerson/` |
| AVEVA / OSIsoft | 14 | CVE-2023-34982, CVE-2022-23854, CVE-2021-26382 | `cve/aveva/` + `cve/osisoft_aveva/` |
| Advantech | 15 | CVE-2022-3157, CVE-2023-2573, CVE-2021-22690 | `cve/advantech/` |
| Moxa | 12 | CVE-2019-9084, CVE-2021-45741, CVE-2022-40224 | `cve/moxa/` |
| Omron | 12 | CVE-2022-31206, CVE-2023-27396, CVE-2021-43985 | `cve/omron/` |
| Phoenix Contact | 9 | CVE-2021-33543, CVE-2022-31800, CVE-2023-46145 | `cve/phoenix_contact/` |
| Beckhoff | 8 | CVE-2022-25920, CVE-2019-5637, CVE-2020-27267 | `cve/beckhoff/` |
| Mitsubishi | 8 | CVE-2021-20608, CVE-2023-2726, CVE-2022-25151 | `cve/mitsubishi/` |
| Inductive Automation | 6 | CVE-2023-39476, CVE-2022-35876, CVE-2021-42615 | `cve/ignition/` + `cve/inductive_automation/` |
| Tridium | 7 | CVE-2021-33009, CVE-2019-15521, CVE-2022-29856 | `cve/tridium/` |
| Unitronics | 5 | CVE-2023-6448, CVE-2024-22178, CVE-2021-43466 | `cve/unitronics/` |
| WAGO | 4 | CVE-2022-45138, CVE-2021-34593, CVE-2019-5074 | `cve/wago/` |
| Pilz | 4 | CVE-2021-34596, CVE-2022-40206, CVE-2020-12516 | `cve/pilz/` |
| Codesys | 5 | CVE-2023-41706, CVE-2022-31802, CVE-2021-34595 | `cve/codesys/` |
| Delta Electronics | 5 | CVE-2023-1133, CVE-2022-2109, CVE-2021-38404 | `cve/delta_electronics/` |
| Eaton | 5 | CVE-2021-23276, CVE-2022-22805, CVE-2023-43772 | `cve/eaton/` |
| Johnson Controls | 5 | CVE-2023-4486, CVE-2022-21939, CVE-2021-36206 | `cve/johnson_controls/` |
| Yokogawa | 5 | CVE-2022-27192, CVE-2021-20248, CVE-2019-5911 | `cve/yokogawa/` |
| Dassault Systemes | 4 | CVE-2021-22177, CVE-2022-26527, CVE-2023-2456 | `cve/dassault_systemes/` |
| 7 Technologies | 1 | CVE-2011-3486 | `cve/7_technologies/` |
| Alstom | 2 | CVE-2019-14932, CVE-2021-31539 | `cve/alstom/` |
| Altus | 3 | CVE-2022-1701, CVE-2023-38578, CVE-2021-4107 | `cve/altus/` |
| Apache (ICS) | 2 | CVE-2021-44228 (Log4Shell ICS), CVE-2022-42889 | `cve/apache/` |
| APT Malware TTPs | 26 | FrostyGoop, Industroyer, NotPetya, EKANS, TRITON | `cve/malware/` |
| AspenTech | 3 | CVE-2021-26030, CVE-2022-1498, CVE-2020-12028 | `cve/aspentech/` |
| AutomationDirect | 3 | CVE-2022-2003, CVE-2021-33013, CVE-2023-0615 | `cve/automationdirect/` |
| Automated Logic | 2 | CVE-2021-24280, CVE-2022-38361 | `cve/automated_logic/` |
| Axiomtek | 2 | CVE-2022-26165, CVE-2023-2974 | `cve/axiomtek/` |
| Baker Hughes | 2 | CVE-2021-42834, CVE-2022-25257 | `cve/baker_hughes/` |
| Bedrock Automation | 2 | CVE-2021-31347, CVE-2022-12905 | `cve/bedrock_automation/` |
| Belden/Hirschmann | 2 | CVE-2022-35862, CVE-2021-20117 | `cve/belden_hirschmann/` |
| Bentley Systems | 2 | CVE-2021-32031, CVE-2022-29928 | `cve/bentley_systems/` |
| Bihl+Wiedemann | 1 | CVE-2023-45315 | `cve/bihl_wiedemann/` |
| Bosch Rexroth | 3 | CVE-2023-48255, CVE-2022-45139, CVE-2021-20127 | `cve/bosch_rexroth/` |
| B&R Automation | 2 | CVE-2022-37026, CVE-2021-22286 | `cve/br_automation/` |
| Broadwin | 2 | CVE-2020-17439, CVE-2021-31789 | `cve/broadwin/` |
| Burkert | 1 | CVE-2022-45866 | `cve/burkert/` |
| Carlo Gavazzi | 1 | CVE-2022-45444 | `cve/carlo_gavazzi/` |
| Chint | 2 | CVE-2022-45701, CVE-2023-41920 | `cve/chint/` |
| Cisco (OT) | 3 | CVE-2022-20695, CVE-2023-20198, CVE-2021-1135 | `cve/cisco/` |
| Compressor Controls | 2 | CVE-2021-27451, CVE-2022-30612 | `cve/compressor_controls/` |
| Comtrol | 1 | CVE-2020-25171 | `cve/comtrol/` |
| Critical Manufacturing | 1 | CVE-2023-4498 | `cve/critical_manufacturi/` |
| Danfoss | 2 | CVE-2021-34587, CVE-2022-22428 | `cve/danfoss/` |
| Delixi | 1 | CVE-2023-40542 | `cve/delixi/` |
| Delta Controls | 1 | CVE-2021-27902 | `cve/delta_controls/` |
| Digi International | 3 | CVE-2022-26210, CVE-2021-34552, CVE-2023-5558 | `cve/digi/` |
| Digicon | 2 | CVE-2022-39832, CVE-2023-28379 | `cve/digicon/` |
| Distech Controls | 1 | CVE-2022-26069 | `cve/distech_controls/` |
| Eaton | 5 | CVE-2021-23276, CVE-2022-22805, CVE-2023-43772 | `cve/eaton/` |
| ELIPSE | 2 | CVE-2023-28378, CVE-2022-40692 | `cve/elipse/` |
| Endress+Hauser | 2 | CVE-2022-27187, CVE-2021-34854 | `cve/endress_hauser/` |
| Exploits (generic) | — | Generic protocol exploits | `cve/exploits/` |
| FANUC | 2 | CVE-2021-22681, CVE-2022-25158 | `cve/fanuc/` |
| FATEK | 2 | CVE-2021-32998, CVE-2022-30269 | `cve/fatek/` |
| Festo | 3 | CVE-2022-30310, CVE-2021-34527, CVE-2023-0432 | `cve/festo/` |
| Flowserve | 1 | CVE-2021-33000 | `cve/flowserve/` |
| Framatome | 1 | CVE-2022-26162 | `cve/framatome/` |
| FrangoTeam | 1 | CVE-2022-29858 | `cve/frangoteam/` |
| Fuji Electric | 2 | CVE-2021-32992, CVE-2022-22452 | `cve/fuji_electric/` |
| Grundfos | 1 | CVE-2023-2877 | `cve/grundfos/` |
| Hach | 1 | CVE-2022-26078 | `cve/hach/` |
| Harting | 1 | CVE-2021-20121 | `cve/harting/` |
| Hilscher | 2 | CVE-2022-30612, CVE-2021-20120 | `cve/hilscher/` |
| HIMA | 2 | CVE-2020-12523, CVE-2022-27191 | `cve/hima/` |
| Hitachi | 2 | CVE-2022-41988, CVE-2021-20589 | `cve/hitachi/` |
| Hiwin | 1 | CVE-2023-28346 | `cve/hiwin/` |
| HMS Networks | 2 | CVE-2022-35862, CVE-2021-37163 | `cve/hms_networks/` |
| Hollysys | 1 | CVE-2022-34045 | `cve/hollysys/` |
| IEI Integration | 1 | CVE-2023-40543 | `cve/iei_integration/` |
| ifm electronic | 1 | CVE-2022-43556 | `cve/ifm_electronic/` |
| Iconics | 4 | CVE-2023-29474, CVE-2022-23127, CVE-2021-27992 | `cve/iconics/` |
| Inovance | 2 | CVE-2022-36131, CVE-2023-40541 | `cve/inovance/` |
| INVT | 1 | CVE-2022-43778 | `cve/invt/` |
| Itron | 2 | CVE-2022-29485, CVE-2021-36208 | `cve/itron/` |
| JTEKT | 2 | CVE-2022-21134, CVE-2021-20626 | `cve/jtekt/` |
| Kepware | 3 | CVE-2022-29825, CVE-2021-23297, CVE-2020-25158 | `cve/kepware/` |
| Keyence | 2 | CVE-2022-43552, CVE-2021-20603 | `cve/keyence/` |
| Kinco | 2 | CVE-2022-40202, CVE-2023-40540 | `cve/kinco/` |
| KMC Controls | 2 | CVE-2022-26167, CVE-2021-38458 | `cve/kmc_controls/` |
| Kongsberg | 3 | CVE-2022-31207, CVE-2021-32987, CVE-2023-2712 | `cve/kongsberg/` |
| Kontron | 2 | CVE-2022-45702, CVE-2023-28378 | `cve/kontron/` |
| Koyo | 1 | CVE-2020-25176 | `cve/koyo/` |
| Krohne | 1 | CVE-2022-27188 | `cve/krohne/` |
| Landis+Gyr | 2 | CVE-2022-27286, CVE-2021-21815 | `cve/landis_gyr/` |
| Lenze | 2 | CVE-2022-3225, CVE-2021-20131 | `cve/lenze/` |
| LS Electric | 4 | CVE-2022-3232, CVE-2021-26981, CVE-2023-2586 | `cve/ls_electric/` |
| Magnetrol | 1 | CVE-2022-22435 | `cve/magnetrol/` |
| Malware TTPs | 26 | See Malware TTP Modules section | `cve/malware/` |
| Measuresoft | 2 | CVE-2021-32955, CVE-2022-27187 | `cve/measuresoft/` |
| MES/ERP | 2 | CVE-2022-44512, CVE-2021-38374 | `cve/mes_erp/` |
| Metso | 1 | CVE-2022-29848 | `cve/metso/` |
| Mettler-Toledo | 1 | CVE-2022-44545 | `cve/mettler_toledo/` |
| MikroTik (ICS-adjacent) | 2 | CVE-2023-30799, CVE-2022-3617 | `cve/mikrotik/` |
| Moore Industries | 1 | CVE-2022-26168 | `cve/moore_industries/` |
| Motorola Solutions | 1 | CVE-2022-47896 | `cve/motorola_solutions/` |
| National Instruments | 3 | CVE-2023-1545, CVE-2022-23130, CVE-2021-23181 | `cve/national_instruments/` |
| Nidec | 2 | CVE-2022-45133, CVE-2021-20626 | `cve/nidec/` |
| Novus | 2 | CVE-2022-43553, CVE-2023-40539 | `cve/novus/` |
| Opto22 | 2 | CVE-2021-32963, CVE-2022-27192 | `cve/opto22/` |
| OSIsoft | 3 | CVE-2023-34982, CVE-2021-26382, CVE-2022-23854 | `cve/osisoft/` |
| OSIsoft/AVEVA | 3 | Combined modules | `cve/osisoft_aveva/` |
| Panasonic | 1 | CVE-2022-29958 | `cve/panasonic/` |
| Pepperl+Fuchs | 2 | CVE-2022-44544, CVE-2021-20127 | `cve/pepperl_fuchs/` |
| Prominent | 1 | CVE-2022-27193 | `cve/prominent/` |
| Prosoft | 2 | CVE-2022-29851, CVE-2021-33009 | `cve/prosoft/` |
| PTC | 2 | CVE-2022-25247, CVE-2021-23220 | `cve/ptc/` |
| R.Stahl | 1 | CVE-2021-33002 | `cve/r_stahl/` |
| Realflex | 1 | CVE-2020-25169 | `cve/realflex/` |
| Red Lion | 2 | CVE-2022-40222, CVE-2021-20127 | `cve/red_lion/` |
| Reliable Controls | 1 | CVE-2022-29854 | `cve/reliable_controls/` |
| Ruggedcom (Siemens) | 2 | CVE-2022-25751, CVE-2021-37204 | `cve/ruggedcom/` |
| S&C Electric | 1 | CVE-2022-30304 | `cve/s_and_c_electric/` |
| Saia-Burgess | 2 | CVE-2022-30312, CVE-2021-27453 | `cve/saia_burgess/` |
| Sauter AG | 1 | CVE-2022-22423 | `cve/sauter_ag/` |
| SEL (Schweitzer) | 3 | CVE-2023-31168, CVE-2022-29959, CVE-2021-20125 | `cve/sel/` |
| Sensata | 1 | CVE-2022-40203 | `cve/sensata/` |
| SEW-Eurodrive | 2 | CVE-2022-43783, CVE-2021-20130 | `cve/sew_eurodrive/` |
| Sick AG | 2 | CVE-2022-27188, CVE-2021-21816 | `cve/sick_ag/` |
| Sierra Wireless | 2 | CVE-2022-26168, CVE-2021-40513 | `cve/sierra_wireless/` |
| SMAR | 2 | CVE-2022-44540, CVE-2023-41921 | `cve/smar/` |
| Sofrel | 2 | CVE-2022-30612, CVE-2021-34856 | `cve/sofrel/` |
| Softing | 2 | CVE-2022-22519, CVE-2021-33009 | `cve/softing/` |
| Step Electric | 1 | CVE-2022-43784 | `cve/step_electric/` |
| Supcon | 1 | CVE-2022-27194 | `cve/supcon/` |
| Teltonika | 2 | CVE-2023-32348, CVE-2022-22427 | `cve/teltonika/` |
| Thales | 1 | CVE-2022-38458 | `cve/thales/` |
| Trench Group | 1 | CVE-2022-27195 | `cve/trench_group/` |
| Trend Control | 1 | CVE-2021-27466 | `cve/trend_control/` |
| Turck | 2 | CVE-2022-45135, CVE-2021-34858 | `cve/turck/` |
| VEGA | 1 | CVE-2022-44543 | `cve/vega/` |
| Vigor | 2 | CVE-2022-40224, CVE-2023-25380 | `cve/vigor/` |
| VMware/Spring (ICS) | 2 | CVE-2022-22965 (Spring4Shell), CVE-2022-22963 | `cve/vmware_spring/` |
| VxWorks/URGENT11 | 4 | CVE-2019-12255, CVE-2019-12258, CVE-2019-12262 | `cve/vxworks_urgent11/` |
| Wabtec | 1 | CVE-2022-30612 | `cve/wabtec/` |
| Wartsila | 2 | CVE-2022-29853, CVE-2021-34857 | `cve/wartsila/` |
| Weatherford | 1 | CVE-2022-29850 | `cve/weatherford/` |
| WEG | 3 | CVE-2023-38573, CVE-2022-44539, CVE-2024-1234 | `cve/weg/` |
| Weidmuller | 1 | CVE-2022-45137 | `cve/weidmuller/` |
| Weintek | 2 | CVE-2022-3361, CVE-2021-43982 | `cve/weintek/` |
| Westermo | 1 | CVE-2022-30612 | `cve/westermo/` |
| Westinghouse | 2 | CVE-2022-29852, CVE-2021-21813 | `cve/westinghouse/` |
| Wind River (VxWorks) | 3 | CVE-2019-12255, CVE-2020-25211, CVE-2021-31170 | `cve/wind_river/` |
| Xylem | 1 | CVE-2022-40207 | `cve/xylem/` |
| Yaskawa | 2 | CVE-2022-43780, CVE-2021-20620 | `cve/yaskawa/` |
| Zyxel | 2 | CVE-2023-28771, CVE-2022-26413 | `cve/zyxel/` |

---

## Protocol Exploit Modules — All 50 Protocols with Module Paths

| Protocol | Module Path | Modules | Example Exploit |
|----------|------------|---------|----------------|
| Modbus TCP | `exploits/protocols/modbus/` | 18 | `modbus_write_single_register`, `modbus_flood_dos`, `modbus_alarm_suppression` |
| Modbus RTU | `exploits/protocols/modbus/` | 3 | `modbus_rtu_coil_write`, `modbus_rtu_gateway_bypass` |
| S7comm | `exploits/protocols/s7comm/` | 8 | `s7_unauthorized_cpu_control`, `s7_memory_read`, `s7_password_bypass` |
| S7comm+ | `exploits/protocols/s7comm_plus/` | 5 | `s7plus_tls_mitm`, `s7plus_session_hijack` |
| EtherNet/IP | `exploits/protocols/enip/` | 7 | `enip_list_identity`, `enip_cip_read_tag`, `enip_session_hijack` |
| PROFINET DCP | `exploits/protocols/profinet/` | 3 | `profinet_dcp_identify`, `profinet_dcp_set_ip`, `profinet_dcp_factory_reset` |
| DNP3 | `exploits/protocols/dnp3/` | 4 | `dnp3_unauthorized_control`, `dnp3_data_spoofing`, `dnp3_replay_command` |
| BACnet/IP | `exploits/protocols/bacnet/` | 2 | `bacnet_device_scan`, `bacnet_property_write` |
| BACnet/MSTP | `exploits/protocols/bacnet_mstp/` | 1 | `bacnet_mstp_device_scan` |
| IEC 60870-5-104 | `exploits/protocols/iec104/` | 3 | `iec104_data_spoofing`, `iec104_unauthorized_command`, `iec104_dos` |
| IEC 61850 MMS | `exploits/protocols/iec61850/` | 2 | `iec61850_mms_read_write`, `iec61850_unauthorized_access` |
| IEC 61850 GOOSE | `exploits/protocols/iec61850/` | 1 | `iec61850_goose_injection` |
| OPC UA | `exploits/protocols/opcua/` | 4 | `opcua_no_auth_browse`, `opcua_write_variable`, `opcua_method_call` |
| OPC DA (DCOM) | `exploits/protocols/opc_da/` | 2 | `opc_da_dcom_enum`, `opc_da_write_item` |
| OPC HDA | `exploits/protocols/opc_hda/` | 1 | `opc_hda_read_history` |
| OPC A&E | `exploits/protocols/opc_ae/` | 1 | `opc_ae_acknowledge_alarm` |
| Omron FINS | `exploits/protocols/fins/` | 3 | `fins_memory_read`, `fins_memory_write`, `fins_cpu_control` |
| Unitronics PCOM | `exploits/protocols/pcom/` | 2 | `pcom_memory_read`, `pcom_cpu_stop` |
| Beckhoff ADS | `exploits/protocols/ads/` | 2 | `ads_symbol_read`, `ads_variable_write` |
| MQTT | `exploits/protocols/mqtt/` | 2 | `mqtt_subscribe_all`, `mqtt_publish_command` |
| SNMP | `exploits/protocols/snmp/` | 3 | `snmp_ot_community_sweep`, `snmp_v1_write`, `snmp_enumeration` |
| PROFIBUS DP | `exploits/protocols/profibus/` | 2 | `profibus_dp_device_scan`, `profibus_dp_diagnosis` |
| PROFIBUS PA | `exploits/protocols/profibus_pa/` | 1 | `profibus_pa_scan` |
| HART/HART-IP | `exploits/protocols/hart/` | 1 | `hart_ip_device_scan` |
| CANopen | `exploits/protocols/canopen/` | 1 | `canopen_sdo_read` |
| CC-Link | `exploits/protocols/cc_link/` | 2 | `cc_link_device_scan`, `cc_link_write` |
| CC-Link IE | `exploits/protocols/cc_link_ie_field/` | 1 | `cc_link_ie_scan` |
| EtherCAT | `exploits/protocols/ethercat/` | 1 | `ethercat_frame_injection` |
| EtherNet/POWERLINK | `exploits/protocols/powerlink/` | 1 | `powerlink_device_scan` |
| SERCOS III | `exploits/protocols/sercos/` | 1 | `sercos_iii_scan` |
| IO-Link | `exploits/protocols/iolink/` | 1 | `iolink_master_scan` |
| INTERBUS | `exploits/protocols/interbus/` | 1 | `interbus_gateway_scan` |
| ControlNet | `exploits/protocols/controlnet/` | 1 | `controlnet_device_scan` |
| DeviceNet | `exploits/protocols/devicenet/` | 1 | `devicenet_scan` |
| PCCC | `exploits/protocols/pccc/` | 1 | `pccc_data_table_read` |
| FL-NET | `exploits/protocols/fl_net/` | 1 | `fl_net_device_scan` |
| CompoNet | `exploits/protocols/componet/` | 1 | `componet_scan` |
| Yokogawa Vnet/IP | `exploits/protocols/vnetip/` | 1 | `vnetip_device_scan` |
| FOUNDATION Fieldbus | `exploits/protocols/foundation_fieldbus/` | 2 | `ff_hse_device_scan`, `ff_h1_gateway_scan` |
| LonWorks | `exploits/protocols/lonworks/` | 1 | `lonworks_device_scan` |
| KNX/EIB | `exploits/protocols/knx/` | 1 | `knx_ip_router_scan` |
| CIP Safety | `exploits/protocols/ethernet_ip_cip_safety/` | 1 | `cip_safety_disable` |
| PROFIsafe | `exploits/protocols/profisafe/` | 1 | `profisafe_status_read` |
| FSoE | `exploits/protocols/fsoe/` | 1 | `fsoe_status_read` |
| SECS/GEM | `exploits/protocols/hsms/` | 1 | `hsms_s1f1_device_id` |
| Serial-to-Ethernet | `exploits/protocols/serial/` | 2 | `moxa_nport_scan`, `lantronix_xport_scan` |
| DNP3 Security Auth v5 | `assessment/protocols/dnp3_security_audit` | 1 | Assessment module |
| OPC UA Security | `assessment/protocols/opcua_security_audit` | 1 | Assessment module |
| IEC 61850 Security | `assessment/protocols/iec61850_security_audit` | 1 | Assessment module |
| SNMP OT extended | `exploits/protocols/snmp/` | 1 | `snmp_ot_extended` |

---

## Scanner Modules — All 31 Scanners

| Scanner | Module Path | Port | Protocol | Usage |
|---------|------------|------|----------|-------|
| Modbus TCP Device Detect | `scanners/ics/modbus_detect` | 502 | Modbus TCP | Find Modbus devices; fingerprint vendor |
| Siemens S7 Scanner | `scanners/ics/s7_comm_scanner` | 102 | S7comm | Detect Siemens S7 PLCs |
| EtherNet/IP Scanner | `scanners/ics/enip_scanner` | 44818 | EtherNet/IP | Rockwell, Omron CIP discovery |
| DNP3 Scanner | `scanners/ics/dnp3_scanner` | 20000 | DNP3 | Power grid RTU detection |
| BACnet Scanner | `scanners/ics/bacnet_scanner` | 47808 | BACnet/IP | Building automation discovery |
| OPC UA Scanner | `scanners/ics/opcua_scanner` | 4840 | OPC UA | OPC UA endpoint discovery |
| PROFINET Scanner | `scanners/ics/profinet_scanner` | L2 | PROFINET DCP | Siemens, Beckhoff, WAGO discovery |
| IEC 104 Scanner | `scanners/ics/iec104_scanner` | 2404 | IEC 60870-5-104 | Power grid RTU discovery |
| Omron FINS Scanner | `scanners/ics/fins_scanner` | 9600 | FINS/UDP | Omron PLC discovery |
| Unitronics PCOM Scanner | `scanners/ics/pcom_scanner` | 20256 | PCOM | Unitronics PLC discovery |
| Beckhoff ADS Scanner | `scanners/ics/ads_scanner` | 48898 | ADS/AMS | TwinCAT runtime discovery |
| MQTT Scanner | `scanners/ics/mqtt_scanner` | 1883 | MQTT | IIoT broker discovery |
| SNMP OT Scanner | `scanners/ics/snmp_scanner` | 161 | SNMP | OT device SNMP enumeration |
| Niagara/Tridium Scanner | `scanners/ics/niagara_scanner` | 4911 | Niagara | Tridium Niagara/JACE discovery |
| Ignition Scanner | `scanners/ics/ignition_scanner` | 8088 | HTTP | Inductive Automation Ignition |
| WinCC/Siemens SCADA Scanner | `scanners/ics/wincc_scanner` | 4999 | HTTP | Siemens WinCC web detection |
| PI System Scanner | `scanners/ics/pi_scanner` | 5450 | PI-SDK | OSIsoft PI Server detection |
| ICS VPN/Remote Access Scanner | `scanners/ics/ics_remote_scanner` | Various | Various | OT remote access exposure |
| Modbus Serial GW Scanner | `scanners/ics/modbus_serial_gw` | 4001 | TCP | Serial-to-Ethernet gateway scan |
| CC-Link Scanner | `scanners/ics/cc_link_scanner` | 61450 | UDP | Mitsubishi CC-Link discovery |
| Vnet/IP Scanner | `scanners/ics/vnetip_scanner` | 20111 | TCP | Yokogawa CENTUM discovery |
| Fieldbus GW Scanner | `scanners/ics/fieldbus_gw_scanner` | 1962 | TCP | PROFIBUS gateway discovery |
| HART-IP Scanner | `scanners/ics/hart_ip_scanner` | 5094 | TCP | HART field device gateway |
| KNX/IP Scanner | `scanners/ics/knx_scanner` | 3671 | UDP | KNX building automation |
| SECS/GEM Scanner | `scanners/ics/secs_gem_scanner` | 5000 | TCP | Semiconductor equipment |
| ICS Historian Scanner | `scanners/ics/historian_scanner` | Various | Various | Historian DB port detection |
| HMI Web Scanner | `scanners/ics/hmi_web_scanner` | 80, 443 | HTTP | Web-based HMI detection |
| IEC 61850 MMS Scanner | `scanners/ics/iec61850_scanner` | 102 | MMS | Substation IED discovery |
| GOOSE/Sampled Values Monitor | `scanners/ics/goose_monitor` | L2 | GOOSE | Passive GOOSE frame capture |
| OPC DA Enumerator | `scanners/ics/opc_da_enum` | 135 | DCOM | Legacy OPC server discovery |
| Generic ICS Port Sweep | `scanners/ics/ics_port_sweep` | Various | Multiple | Multi-protocol port sweep |

---

## Credential Modules — All 34 Modules

| Vendor | Module Path | Port | Protocol | Default Creds Tested |
|--------|------------|------|----------|---------------------|
| ABB | `creds/abb/ssh_default_creds` | 22 | SSH | admin/admin, Admin/Admin |
| ABB | `creds/abb/webinterface_http_auth_default` | 80 | HTTP | admin/admin |
| Advantech | `creds/advantech/webaccess_default_creds` | 8080 | HTTP | admin/admin, guest/guest |
| Altus | `creds/altus/duo_default_creds` | 80 | HTTP | admin/altus |
| AVEVA | `creds/aveva/intouch_default_creds` | 1433 | MSSQL | sa/(blank), sa/wonderware |
| Beckhoff | `creds/beckhoff/twincat_default_creds` | 48898 | ADS | (no auth by default) |
| Bosch Rexroth | `creds/bosch_rexroth/ctrlx_default_creds` | 443 | HTTPS | admin/admin |
| Cisco | `creds/cisco/industrial_router_default_creds` | 22, 23 | SSH/Telnet | cisco/cisco, admin/(blank) |
| CODESYS | `creds/codesys/runtime_default_creds` | 1200 | CODESYS | (no auth) |
| Dassault | `creds/dassault_systemes/dscc_default_creds` | 8443 | HTTPS | admin/3ds |
| Delta Electronics | `creds/delta_electronics/web_default_creds` | 80 | HTTP | admin/admin |
| Emerson | `creds/emerson/deltav_default_creds` | 135 | DCOM | DeltaV/deltav |
| Fuji Electric | `creds/fuji_electric/spb_default_creds` | 80 | HTTP | admin/admin |
| GE | `creds/ge/cimplicity_default_creds` | 80, 1234 | HTTP | admin/(blank) |
| GE Vernova | `creds/ge_vernova/grid_solutions_default_creds` | 22, 80 | SSH/HTTP | admin/admin |
| Generic HTTP | `creds/generic/http_default` | 80, 443 | HTTP | admin/admin, admin/password |
| Generic HTTP Basic | `creds/generic/http_basic_digest_default` | 80 | HTTP | admin/admin |
| Generic SSH | `creds/generic/ssh_default` | 22 | SSH | root/root, admin/admin |
| Generic Telnet | `creds/generic/telnet_default` | 23 | Telnet | admin/admin |
| Honeywell | `creds/honeywell/experion_default_creds` | 80 | HTTP | admin/admin |
| Honeywell | `creds/honeywell/spyder_default_creds` | 80 | HTTP | admin/(blank) |
| Honeywell OT | `creds/honeywell_ot/ssh_default_creds` | 22 | SSH | admin/admin |
| Honeywell OT | `creds/honeywell_ot/webinterface_http_auth` | 443 | HTTPS | admin/Aut0maT3 |
| Iconics | `creds/iconics/genesis64_default_creds` | 80 | HTTP | admin/(blank) |
| Inductive Auto. | `creds/inductive_automation/ignition_default_creds` | 8088 | HTTP | admin/password |
| LS Electric | `creds/ls_electric/xgk_default_creds` | 502 | Modbus | (no auth — Modbus) |
| Mitsubishi | `creds/mitsubishi/melsec_default_creds` | 5007 | SLMP | (no auth default) |
| Moxa | `creds/moxa/ssh_default_creds` | 22 | SSH | admin/moxa |
| Moxa | `creds/moxa/telnet_default_creds` | 23 | Telnet | admin/moxa |
| Moxa | `creds/moxa/webinterface_http_auth_default` | 80 | HTTP | admin/moxa |
| Omron | `creds/omron/nx_nj_default_creds` | 44818 | EtherNet/IP | (no auth) |
| Omron | `creds/omron/ssh_default_creds` | 22 | SSH | root/root |
| Omron | `creds/omron/webinterface_http_auth_default` | 80 | HTTP | admin/admin |
| OSIsoft | `creds/osisoft/pi_server_default_creds` | 5450 | PI-SDK | piadmin/(blank) |
| Phoenix Contact | `creds/phoenix_contact/ssh_default_creds` | 22 | SSH | admin/admin |
| Phoenix Contact | `creds/phoenix_contact/telnet_default_creds` | 23 | Telnet | admin/private |
| Phoenix Contact | `creds/phoenix_contact/webinterface_http_auth` | 80 | HTTP | admin/admin |
| Pilz | `creds/pilz/pss4000_default_creds` | 80, 22 | HTTP/SSH | admin/12345 |
| Rockwell | `creds/rockwell/ssh_default_creds` | 22 | SSH | admin/1234 |
| Rockwell | `creds/rockwell/webinterface_http_auth_default` | 443 | HTTPS | admin/1234 |
| Rockwell Auto. | `creds/rockwell_automation/logix_default_creds` | 44818 | EtherNet/IP | (no auth) |
| Schneider | `creds/schneider/ssh_default_creds` | 22 | SSH | USER/USER |
| Schneider | `creds/schneider/telnet_default_creds` | 23 | Telnet | USER/USER |
| Schneider | `creds/schneider/webinterface_http_auth_default` | 80 | HTTP | USER/USER |
| Schneider Elec. | `creds/schneider_electric/modicon_default_creds` | 502 | Modbus | (no auth) |
| Siemens | `creds/siemens/ssh_default_creds` | 22 | SSH | admin/admin |
| Siemens | `creds/siemens/telnet_default_creds` | 23 | Telnet | admin/admin |
| Siemens | `creds/siemens/webinterface_http_auth_default` | 443 | HTTPS | admin/admin |
| Tridium | `creds/tridium/niagara_default_creds` | 4911 | Fox | admin/admin, guest/guest |
| Unitronics | `creds/unitronics/pcom_default_creds` | 20256 | PCOM | (no auth default) |
| WAGO | `creds/wago/pfc_default_creds` | 80 | HTTP | admin/wago |
| WEG | `creds/weg/motor_scan_default_creds` | 80 | HTTP | admin/admin |
| Wind River | `creds/wind_river/vxworks_default_creds` | Various | Various | target/(blank) |
| Yokogawa | `creds/yokogawa/modbus_default_creds` | 502 | Modbus | (no auth) |

---

## Assessment Modules — All 18

(See [Assessment & Compliance](12-assessment-compliance.md) for full details)

| Module | Description |
|--------|-------------|
| `assessment/iec62443/zone_conduit_audit` | IEC 62443 zone/conduit audit |
| `assessment/nist_sp800_82/control_checklist` | NIST SP 800-82r3 ICS checklist |
| `assessment/risk/ics_risk_scorer` | Composite ICS risk score |
| `assessment/threat_intel/ics_kill_chain` | ICS kill chain 8-stage analysis |
| `assessment/ir/iacs_ir_playbook` | 5-phase ICS incident response |
| `assessment/protocols/opcua_security_audit` | OPC UA IEC 62541 security audit |
| `assessment/protocols/dnp3_security_audit` | DNP3 SAv5 authentication audit |
| `assessment/protocols/iec61850_security_audit` | IEC 61850/IEC 62351 audit |
| `assessment/network/ics_firewall_audit` | ICS firewall rule audit |
| `assessment/network/industrial_network_assessment` | Full industrial network assessment |
| `assessment/mitre_ics/coverage_report` | MITRE ATT&CK ICS coverage |
| `assessment/mitre_ics/full_mitre_sweep` | Full technique simulation sweep |
| `assessment/mitre_ics/t0801_monitor_process_state` | T0801 simulation |
| `assessment/mitre_ics/t0806_brute_force_io` | T0806 simulation |
| `assessment/mitre_ics/t0830_aitm_modbus` | T0830 Adversary-in-the-Middle |
| `assessment/mitre_ics/t0836_modify_parameter` | T0836 parameter modification |
| `assessment/mitre_ics/t0878_alarm_suppression` | T0878 alarm suppression |
| `assessment/sast/plc_source_analyzer` | PLC SAST analysis wrapper |

---

## Malware TTP Modules — All 26

| Malware | Year | Attribution | Impact | MITRE Techniques |
|---------|------|------------|--------|-----------------|
| KillDisk | 2015-2016 | Sandworm (Russia) | CATASTROPHIC | T0810, T0879, T0881 |
| BlackEnergy3 | 2015 | Sandworm (Russia) | CATASTROPHIC | T0817, T0822, T0810 |
| Industroyer/CrashOverride | 2016 | Sandworm (Russia) | CATASTROPHIC | T0855, T0813, T0810 |
| TRITON/TRISIS | 2017 | TEMP.Veles (Russia/Iran) | CATASTROPHIC | T0838, T0836, T0829 |
| NotPetya | 2017 | Sandworm (Russia) | CATASTROPHIC | T0810, T0816, T0879 |
| EKANS/SNAKE | 2020 | Iran-nexus | HIGH | T0881, T0810, T0826 |
| Incontroller/Pipedream | 2022 | Chernovite (Russia likely) | CATASTROPHIC | T0855, T0836, T0813 |
| Industroyer2 | 2022 | Sandworm (Russia) | CATASTROPHIC | T0855, T0813, T0814 |
| FrostyGoop/BUSTLEBERM | 2024 | Sandworm (Russia) | CRITICAL | T0836, T0814, T0878 |
| CosmicEnergy | 2023 | Rostelecom-Solar (Russia) | CATASTROPHIC | T0855, T0813, T0837 |
| Stuxnet TTP | 2010 | NSA/Unit 8200 (US/Israel) | CATASTROPHIC | T0843, T0834, T0851 |
| Havex/Dragonfly | 2013-2014 | APT28 / Energetic Bear | HIGH | T0819, T0842, T0801 |
| Shamoon | 2012-2018 | APT33 (Iran) | HIGH | T0810, T0881, T0879 |
| BlackEnergy2 | 2014 | Sandworm (Russia) | HIGH | T0817, T0863 |
| OldRea/Energetic Bear | 2014 | APT28 (Russia) | HIGH | T0801, T0842 |
| Irongate | 2014-2016 | Unknown (S7 simulated) | HIGH | T0834, T0851, T0856 |
| PLC Logic Bomb (Time) | 2024 | IXF synthetic | CRITICAL | T0839, T0836 |
| PLC Logic Bomb (Counter) | 2024 | IXF synthetic | CRITICAL | T0839, T0836 |
| PLC Logic Bomb (Physical) | 2024 | IXF synthetic | CRITICAL | T0836, T0838 |
| Modbus Flood DoS | — | Generic TTP | HIGH | T0813, T0815 |
| S7 Watchdog Bypass | — | Generic TTP | HIGH | T0816, T0855 |
| ICS Ransomware Generic | 2019+ | Multiple | HIGH | T0881, T0810 |
| DNP3 Rogue Master | — | Generic TTP | HIGH | T0848, T0855 |
| GOOSE Injection | — | Generic TTP | CATASTROPHIC | T0855, T0836 |
| IEC 104 Replay Attack | — | Generic TTP | HIGH | T0855, T0813 |
| BACnet Property Attack | — | Generic TTP | MEDIUM | T0836, T0832 |

---

## Native Artifacts

IXF ships with these native source files compiled by the PolyExploit Runner:

| File | Language | Size | Module Using It | Impact |
|------|----------|------|----------------|--------|
| `killdisk.c` | C | 412 lines | `cve/malware/killdisk_ics_wiper` | CATASTROPHIC |
| `notpetya.cpp` | C++ | 687 lines | `cve/malware/notpetya_wiper` | CATASTROPHIC |
| `frostygoop.go` | Go | 318 lines | `cve/malware/frostygoop_modbus_heating` | CRITICAL |
| `modbus_flood.c` | C | 198 lines | `cve/malware/modbus_flood_dos` | HIGH |
| `s7_watchdog.cpp` | C++ | 245 lines | `cve/malware/s7_watchdog_bypass` | HIGH |

---

## NSE Scripts — All 8

(See [Nmap NSE Scripts](14-nse-scripts.md) for full reference)

| Script | Description |
|--------|-------------|
| `ics-sweep.nse` | Multi-protocol ICS port sweep |
| `ics-default-creds.nse` | ICS web interface default credentials |
| `ics-plc-program-access.nse` | Unauthenticated PLC programming port check |
| `ics-safety-systems.nse` | Safety system interface detection |
| `ics-firmware-version.nse` | OT device firmware version extraction |
| `ics-historian-discover.nse` | Industrial historian discovery |
| `ics-enumerate.nse` | ICS device metadata enumeration |
| `ics-honeypot-detect.nse` | ICS honeypot detection |

---

## Module Statistics

```
Total modules: 976
─────────────────────────────────────────────────────────
Category          Count    Percentage
─────────────────────────────────────────────────────────
cve               486      49.8%
exploits          159      16.3%
creds              34       3.5%  (note: some duplicates per vendor)
scanners           31       3.2%
assessment         18       1.8%
generic            12       1.2%
malware_ttps       26       2.7%
others/misc       210      21.5%
─────────────────────────────────────────────────────────
Total            976      100%

By Impact Level:
CATASTROPHIC      22       2.3%
CRITICAL         128      13.1%
HIGH             312      32.0%
MEDIUM           218      22.3%
LOW               98      10.0%
READ              86       8.8%
INFO              112      11.5%

By MITRE Coverage:
Techniques mapped: 74/90 (82%)
Tactics covered:   12/12 (100%)
```

---

## MITRE ATT&CK Coverage per Module Category

| Category | Primary MITRE Tactics | Key Techniques |
|----------|----------------------|----------------|
| CVE modules (cve/) | Initial Access, Execution, Privilege Escalation | T0819, T0820, T0890 |
| Protocol exploits (exploits/protocols/) | Impair Process Control, Inhibit Response | T0836, T0813, T0855 |
| Credential modules (creds/) | Initial Access | T0812 (Default Credentials), T0859 |
| Scanners (scanners/ics/) | Discovery | T0846, T0840, T0861, T0808 |
| Assessment modules (assessment/) | INFO — detection guidance | All tactics |
| Malware TTPs (malware/) | Impact, Inhibit Response | T0810, T0879, T0881, T0837 |

---

## Extended CVE Coverage by Vendor — Secondary Vendors

### Phoenix Contact (6 modules)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/phoenix_contact/cve_2019_12407_plcnext_rce` | CVE-2019-12407 | 9.8 | PLCnext AXC F 2152 | Remote code execution via web |
| `cve/phoenix_contact/cve_2020_12515_webvisit_auth` | CVE-2020-12515 | 9.8 | WebVisit HMI 6.0 | Authentication bypass |
| `cve/phoenix_contact/cve_2021_33544_fl_mguard_rce` | CVE-2021-33544 | 9.8 | FL mGuard firewall | Remote code execution |
| `cve/phoenix_contact/cve_2022_2989_plcnext_path` | CVE-2022-2989 | 8.8 | PLCnext Engineer | Path traversal |
| `cve/phoenix_contact/cve_2023_28650_radioline_auth` | CVE-2023-28650 | 9.8 | Radioline wireless | Authentication bypass |
| `cve/phoenix_contact/cve_2021_21005_iolinkmaster_rce` | CVE-2021-21005 | 9.8 | IOLinkMaster | Unauthenticated RCE |

### Yokogawa (5 modules)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/yokogawa/cve_2014_3888_centum_vp_rce` | CVE-2014-3888 | 9.8 | CENTUM VP R5 | Remote code execution |
| `cve/yokogawa/cve_2019_4462_stardom_dos` | CVE-2019-4462 | 7.5 | STARDOM FCN/FCJ | Denial of service |
| `cve/yokogawa/cve_2020_5524_fast_tools_auth` | CVE-2020-5524 | 9.8 | FAST/TOOLS | Authentication bypass |
| `cve/yokogawa/cve_2021_22736_centum_path` | CVE-2021-22736 | 8.8 | CENTUM VP | Path traversal |
| `cve/yokogawa/cve_2022_32480_vnet_ip_dos` | CVE-2022-32480 | 7.5 | Vnet/IP network | Denial of service |

### Fanuc (2 modules)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/fanuc/cve_2019_13411_focas2_rce` | CVE-2019-13411 | 9.8 | FOCAS2 Ethernet | CNC remote code execution |
| `cve/fanuc/cve_2021_22655_robot_auth` | CVE-2021-22655 | 9.8 | Robot Controller R-30iB | Auth bypass |

### Mitsubishi Electric (3 modules)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/mitsubishi/cve_2021_20594_melsec_dos` | CVE-2021-20594 | 7.5 | MELSEC iQ-R CPU | Denial of service |
| `cve/mitsubishi/cve_2021_20598_genesis64_sqli` | CVE-2021-20598 | 9.8 | GENESIS64 SCADA | SQL injection RCE |
| `cve/mitsubishi/cve_2023_51012_melsec_auth` | CVE-2023-51012 | 9.8 | MELSEC iQ-F FX5U | Auth bypass |

### LS Electric (1 module)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/ls_electric/cve_2021_26728_xgi_rce` | CVE-2021-26728 | 9.8 | XGI PLC series | Remote code execution |

### Delta Electronics — Detailed Breakdown (11 modules)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/delta_electronics/cve_2022_26857_diaenergie_sqli` | CVE-2022-26857 | 9.8 | DIAEnergie EMS | SQL injection → RCE |
| `cve/delta_electronics/cve_2021_38413_infrasuite_rce` | CVE-2021-38413 | 9.8 | InfraSuite Device Master | IOCTL command exec |
| `cve/delta_electronics/cve_2022_1366_diaenergie_auth` | CVE-2022-1366 | 9.8 | DIAEnergie | Auth bypass |
| `cve/delta_electronics/cve_2023_1148_diascreen_dos` | CVE-2023-1148 | 7.5 | DIAScreen | Stack overflow DoS |
| `cve/delta_electronics/cve_2021_32968_as_plc_rce` | CVE-2021-32968 | 9.8 | AS300/AS200 PLC | Remote code execution |
| `cve/delta_electronics/cve_2022_26836_cnc_overflow` | CVE-2022-26836 | 9.8 | DeltaLogic A8SOFT | Buffer overflow |
| `cve/delta_electronics/cve_2022_26839_diaenergie_path` | CVE-2022-26839 | 8.8 | DIAEnergie | Path traversal |
| `cve/delta_electronics/cve_2021_22677_dvp_auth` | CVE-2021-22677 | 9.8 | DVP-series PLC | Auth bypass via Modbus |
| `cve/delta_electronics/cve_2023_47207_diaenergie_xxe` | CVE-2023-47207 | 9.1 | DIAEnergie | XXE injection |
| `cve/delta_electronics/cve_2022_43775_infrasuite_heap` | CVE-2022-43775 | 9.8 | InfraSuite | Heap overflow |
| `cve/delta_electronics/cve_2023_39224_diaplc_rce` | CVE-2023-39224 | 9.8 | DIALink | Remote code execution |

### WAGO (2 modules)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/wago/cve_2021_20987_pfc200_rce` | CVE-2021-20987 | 9.8 | PFC200 controller | Remote code execution |
| `cve/wago/cve_2019_12261_codesys_rce` | CVE-2019-12261 | 9.8 | Codesys-based PLC | Stack overflow RCE |

### Endress+Hauser (2 modules)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/endress_hauser/cve_2023_30898_fieldgate_rce` | CVE-2023-30898 | 9.8 | Fieldgate FXA42 | Remote code execution |
| `cve/endress_hauser/cve_2021_28665_netilion_auth` | CVE-2021-28665 | 9.8 | Netilion cloud | Authentication bypass |

---

## Full Malware Module Reference

### Detailed Malware TTP Analysis

Each malware module simulates the specific attack techniques used by real ICS malware, allowing defenders to test their detection and response capabilities.

#### STUXNET Modules (2)

| Module | Technique | Simulation |
|--------|-----------|-----------|
| `malware/stuxnet/stuxnet_s7_rootkit` | T0857, T0851, T0836 | Simulates Stuxnet's approach: intercept S7comm reads (report fake values), modify frequency converter setpoints while hiding changes from SCADA |
| `malware/stuxnet/stuxnet_plc_intercept` | T0831, T0873 | Simulates Stuxnet OB35 injection pattern: add malicious code to existing PLC program organization blocks |

#### CRASHOVERRIDE / INDUSTROYER Modules (4)

| Module | Technique | Simulation |
|--------|-----------|-----------|
| `malware/industroyer/industroyer_iec104_exec` | T0855, T0803 | IEC 104 direct breaker trip (Ukraine 2016 attack pattern) |
| `malware/industroyer/industroyer_modbus_exec` | T0855, T0806 | Modbus output manipulation component |
| `malware/industroyer/industroyer_dos` | T0813, T0814 | SCADA denial-of-service (Industroyer DoS wiper component) |
| `malware/industroyer/industroyer2_iec104` | T0855, T0803 | INDUSTROYER2 IEC 104 attack (Ukraine April 2022) |

#### TRITON / TRISIS Modules (2)

| Module | Technique | Target | Simulation |
|--------|-----------|--------|-----------|
| `malware/triton/triton_sic_rewrite` | T0857, T0829 | Schneider Triconex SIS | Simulates TRITON firmware implant: rewrite SIS firmware to disable safety trips |
| `malware/triton/triton_safe_state_bypass` | T0829, T0876 | Safety PLC | Simulate bypass of SIS safe state — allow unsafe condition to persist |

#### INCONTROLLER / PIPEDREAM Modules (5)

| Module | Technique | Target Protocol | Simulation |
|--------|-----------|----------------|-----------|
| `malware/pipedream/pipedream_modbus_module` | T0855, T0806 | Modbus TCP | INCONTROLLER Modbus attack module |
| `malware/pipedream/pipedream_omron_fins` | T0855, T0866 | Omron FINS | INCONTROLLER Omron module |
| `malware/pipedream/pipedream_opcua_module` | T0855, T0802 | OPC UA | INCONTROLLER OPC UA data collector |
| `malware/pipedream/pipedream_plc_wiper` | T0809, T0843 | PLC memory | INCONTROLLER PLC wiper function |
| `malware/pipedream/pipedream_codesys` | T0843, T0857 | Codesys V3 | INCONTROLLER Codesys V3 exploit |

---

## Complete Module Usage Examples

### Loading any module from the catalog

```
# Protocol exploit example
ixf > use exploits/protocols/dnp3/dnp3_direct_operate
ixf > set target 10.0.0.101
ixf > set outstation_addr 10
ixf > set trip_close LATCH_ON
ixf > run

# Scanner example
ixf > use scanners/ics/bacnet_scanner
ixf > set target 192.168.100.0/24
ixf > set threads 10
ixf > run

# Malware TTP example
ixf > use malware/industroyer/industroyer_iec104_exec
ixf > show info
ixf > set target 10.0.0.20
ixf > run
```

### Batch module execution

```bash
# Run a list of modules non-interactively
for module in \
  "use scanners/ics/modbus_scanner set target 192.168.1.0/24 run" \
  "use scanners/ics/s7_comm_scanner set target 192.168.1.50 run" \
  "use scanners/ics/enip_scanner set target 192.168.1.0/24 run"; do
  ixf $module
done
```

### Using search to find modules by technique

```
ixf > search T0836
[*] Search results for: T0836
    use exploits/protocols/modbus/modbus_write_register
    use exploits/protocols/modbus/modbus_unauthorized_coil_set
    use exploits/protocols/s7comm/s7_write_memory
    use exploits/protocols/dnp3/dnp3_analog_output
    use exploits/protocols/iec104/iec104_command_injection
    use assessment/mitre_ics/t0836_modify_parameter
    use malware/stuxnet/stuxnet_s7_rootkit
    ... (18 results)
```

### Finding all CRITICAL modules

```
ixf > search CRITICAL
[*] Filtering by severity: CRITICAL (241 modules)
    use cve/schneider/cve_2018_7789_modicon_auth_bypass   CVSS 9.8
    use cve/rockwell/cve_2022_1161_controllogix_firmware  CVSS 9.8
    use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key  CVSS 9.8
    ... (238 more CRITICAL modules)
```

---

## Module Development Quick Reference

### Adding a new CVE module

```python
# File: industrialxpl/modules/cve/newvendor/cve_2024_XXXXX_product_vuln.py

from industrialxpl.core.exploit.base import BaseExploit
from industrialxpl.core.exploit.options import OptString, OptInt, OptBool

__info__ = {
    "name": "CVE-2024-XXXXX NewVendor Product Vulnerability",
    "description": "Description of the vulnerability and impact",
    "authors": ("Andre Henrique (mrhenrike)",),
    "impact": "CRITICAL",
    "exploit_type": "Remote Code Execution",
    "cve": "CVE-2024-XXXXX",
    "cvss": 9.8,
    "mitre_techniques": ["T0855", "T0866"],
    "mitre_tactics": ["Execution"],
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX"],
    "tags": ["newvendor", "rce", "critical"],
}

class Module(BaseExploit):
    def setup(self):
        self.add_option(OptString("target", required=True, description="Target IP"))
        self.add_option(OptInt("port", default=443, description="HTTPS port"))
        self.add_option(OptBool("simulate", default=True))
        self.add_option(OptBool("destructive", default=False))

    def run(self):
        target = self.get_option("target")
        if self.get_option("simulate"):
            self.print_simulate_header()
            print(f"  Step 1: Connect to https://{target}:{self.get_option('port')}")
            print(f"  Step 2: Send malformed request to /vulnerable/endpoint")
            print(f"  Step 3: Trigger RCE via [mechanism]")
            self.print_mitre()
        else:
            # live execution code
            pass
```

### Adding a new scanner module

```python
# File: industrialxpl/modules/scanners/ics/newprotocol_detect.py

from industrialxpl.core.exploit.base import BaseScanner
from industrialxpl.core.exploit.options import OptString, OptInt

__info__ = {
    "name": "NewProtocol Device Detect",
    "description": "Detect NewProtocol-speaking devices on the network",
    "authors": ("Andre Henrique (mrhenrike)",),
    "impact": "LOW",
    "exploit_type": "Service Detection",
    "cve": "N/A",
    "mitre_techniques": ["T0888"],
    "tags": ["scanner", "newprotocol", "discovery"],
}

class Module(BaseScanner):
    def setup(self):
        self.add_option(OptString("target", required=True))
        self.add_option(OptInt("port", default=9999))

    def run(self):
        target = self.get_option("target")
        port = self.get_option("port")
        # Detection logic
        pass
```

---

## Quick Reference: Searching the Catalog

### Search patterns

| Goal | Command |
|------|---------|
| Find all Siemens modules | `ixf > search siemens` |
| Find by CVE ID | `ixf > search CVE-2021-22681` |
| Find by protocol | `ixf > search modbus` |
| Find by MITRE technique | `ixf > search T0843` |
| Find all scanners | `ixf > search scanner` |
| Find credential modules | `ixf > search default_creds` |
| Find malware simulations | `ixf > search malware` |
| Find assessment modules | `ixf > search assessment` |
| Find by product name | `ixf > search controllogix` |
| Find by impact | `ixf > search CRITICAL` |
| Find by region | `ixf > vendors americas` |
| Find by country | `ixf > vendors japan` |

### Module info shortcuts

```
# View all options for loaded module
ixf (module) > show options

# View full metadata
ixf (module) > show info

# View MITRE mapping only
ixf (module) > show mitre

# View references and CVE details
ixf (module) > show refs

# Check connectivity without running exploit
ixf (module) > check
```

---

## Complete CVE ID Cross-Reference (Selected Highlights)

| CVE ID | Vendor | CVSS | Module Count | IXF Path |
|--------|--------|------|-------------|---------|
| CVE-2018-7789 | Schneider | 9.8 | 1 | `cve/schneider/cve_2018_7789_*` |
| CVE-2021-22681 | Siemens | 9.8 | 1 | `cve/siemens/cve_2021_22681_*` |
| CVE-2022-1161 | Rockwell | 9.8 | 1 | `cve/rockwell/cve_2022_1161_*` |
| CVE-2022-26857 | Delta | 9.8 | 1 | `cve/delta_electronics/cve_2022_26857_*` |
| CVE-2023-25078 | Honeywell | 9.8 | 1 | `cve/honeywell/cve_2023_25078_*` |
| CVE-2022-34151 | Omron | 9.8 | 1 | `cve/omron/cve_2022_34151_*` |
| CVE-2017-16744 | Tridium | 9.8 | 1 | `cve/tridium/cve_2017_16744_*` |
| CVE-2018-10952 | GE | 9.8 | 1 | `cve/ge/cve_2018_10952_*` |
| CVE-2023-34982 | AVEVA | 9.8 | 1 | `cve/aveva/cve_2023_34982_*` |
| CVE-2023-39468 | Inductive | 9.8 | 1 | `cve/inductive/cve_2023_39468_*` |
| CVE-2021-38413 | Delta | 9.8 | 1 | `cve/delta_electronics/cve_2021_38413_*` |
| CVE-2022-3323 | Advantech | 9.8 | 1 | `cve/advantech/cve_2022_3323_*` |
| CVE-2019-7232 | ABB | 9.8 | 1 | `cve/abb/cve_2019_7232_*` |
| CVE-2023-0364 | ABB | 9.8 | 1 | `cve/abb/cve_2023_0364_*` |
| CVE-2022-23854 | AVEVA | 9.8 | 1 | `cve/aveva/cve_2022_23854_*` |
| CVE-2020-10636 | Emerson | 9.8 | 1 | `cve/emerson/cve_2020_10636_*` |
| CVE-2021-22655 | FANUC | 9.8 | 1 | `cve/fanuc/cve_2021_22655_*` |
| CVE-2022-26376 | ABB | 9.8 | 1 | `cve/abb/cve_2022_26376_*` |
| CVE-2019-12407 | Phoenix | 9.8 | 1 | `cve/phoenix_contact/cve_2019_12407_*` |
| CVE-2020-7493 | Schneider | 9.8 | 1 | `cve/schneider/cve_2020_7493_*` |

---

## Module Index Verification

After installation, verify the full module index is intact:

```bash
# Quick count
python -c "
from industrialxpl.core.exploit.utils import index_modules
mods = index_modules()
print(f'Total: {len(mods)} modules')

# Count by category
from collections import Counter
cats = Counter(m.split('/')[0] for m in mods)
for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
    print(f'  {cat:30s} {count:4d}')
"
```

Expected output:
```
Total: 976 modules
  cve                              814
  exploits                         102
  scanners                          31
  creds                             34
  assessment                        18
  malware                           26
  nse                                8  (NSE wrappers)
```

If the count differs, reinstall:

```bash
pip install --force-reinstall industrialxpl-forge
python tools/env_doctor.py
```

---

## Vendor CVE Module Details — Additional Vendors

### Prosoft Technology (2 modules)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/prosoft/cve_2019_6807_radiolinx_rce` | CVE-2019-6807 | 9.8 | RadioLinx ControlScape | Remote code execution |
| `cve/prosoft/cve_2021_27491_icx35_auth` | CVE-2021-27491 | 9.8 | ICX35 cellular gateway | Authentication bypass |

### Red Lion Controls (1 module)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/red_lion/cve_2022_26519_crimson_rce` | CVE-2022-26519 | 9.8 | Crimson 3.2 HMI/SCADA | Remote code execution via crafted project |

### Opto22 (1 module)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/opto22/cve_2023_26597_groov_epic_auth` | CVE-2023-26597 | 9.8 | groov EPIC PR1 | Authentication bypass |

### Schweitzer Engineering (SEL) — 4 modules

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/schweitzer/cve_2023_34392_sel_3555_dos` | CVE-2023-34392 | 7.5 | SEL-3555 RTAC | Denial of service |
| `cve/schweitzer/cve_2022_30585_sel_5056_rce` | CVE-2022-30585 | 9.8 | SEL-5056 relay | Remote code execution |
| `cve/schweitzer/cve_2021_27500_sel_relay_auth` | CVE-2021-27500 | 9.8 | SEL-351 relay | Authentication bypass |
| `cve/schweitzer/cve_2023_31171_sel_acse_dos` | CVE-2023-31171 | 7.5 | SEL ACSE stack | Stack overflow DoS |

### Landis+Gyr (2 modules)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/landis_gyr/cve_2022_3085_e360_auth` | CVE-2022-3085 | 9.8 | E360 smart meter | Authentication bypass |
| `cve/landis_gyr/cve_2023_32283_gridstream_rce` | CVE-2023-32283 | 9.8 | Gridstream RF | Remote code execution |

### WEG Brazil (2 modules)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/weg/cve_2022_44620_cfw11_auth` | CVE-2022-44620 | 9.8 | CFW-11 VFD web | Authentication bypass |
| `cve/weg/cve_2021_38162_motor_scan_info` | CVE-2021-38162 | 5.3 | Motor Scan IIoT | Information disclosure |

### Elipse Software Brazil (2 modules)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/elipse/cve_2022_3207_e3_scada_sqli` | CVE-2022-3207 | 9.8 | E3 SCADA | SQL injection → RCE |
| `cve/elipse/cve_2021_43931_epics_rce` | CVE-2021-43931 | 9.8 | Epics SCADA | Remote code execution |

### Cisco Industrial (3 modules)

| Module Path | CVE | CVSS | Affected Product | Impact |
|-------------|-----|------|-----------------|--------|
| `cve/cisco_industrial/cve_2022_20695_ie3400_auth` | CVE-2022-20695 | 9.8 | IE3400 switch | Authentication bypass |
| `cve/cisco_industrial/cve_2023_20026_ir800_rce` | CVE-2023-20026 | 9.8 | IR800 industrial router | RCE |
| `cve/cisco_industrial/cve_2021_1257_ind_network_dir` | CVE-2021-1257 | 7.5 | Industrial Network Director | Privilege escalation |

---

## Protocol Exploit Modules — Remaining Catalog

### Additional Modbus Variants

| Module Path | Variant | Purpose |
|-------------|---------|---------|
| `exploits/protocols/modbus/modbus_read_all_coils` | Modbus TCP | Read all coils (FC1) — full discrete output state |
| `exploits/protocols/modbus/modbus_write_multiple_regs` | Modbus TCP | FC16 Write Multiple Registers — bulk analog output |
| `exploits/protocols/modbus/modbus_mask_write_register` | Modbus TCP | FC22 Mask Write Register — bitmask manipulation |
| `exploits/protocols/modbus/modbus_read_file_record` | Modbus TCP | FC20 File Record read — firmware/config file access |
| `exploits/protocols/modbus/modbus_encapsulated_transport` | Modbus TCP | FC43 Encapsulated Interface Transport |

### Additional DNP3 Variants

| Module Path | Purpose | Impact |
|-------------|---------|--------|
| `exploits/protocols/dnp3/dnp3_warm_restart` | DNP3 Warm Restart (FC 14) | RTU warm reboot — process disruption |
| `exploits/protocols/dnp3/dnp3_enable_spontaneous` | Enable unsolicited responses | Flood RTU with event data |
| `exploits/protocols/dnp3/dnp3_write_time` | Write time synchronization | Clock skew — event timestamp falsification |
| `exploits/protocols/dnp3/dnp3_assign_class` | Reassign data class assignments | Suppress critical events from polling |

### Additional OPC UA Variants

| Module Path | Purpose |
|-------------|---------|
| `exploits/protocols/opcua/opcua_create_subscription` | Create high-rate subscription to exhaust server |
| `exploits/protocols/opcua/opcua_session_hijack` | Test session token reuse vulnerability |
| `exploits/protocols/opcua/opcua_trusted_cert_bypass` | Test certificate trust store bypass |

### Additional IEC 61850 Variants

| Module Path | Purpose |
|-------------|---------|
| `exploits/protocols/iec61850/goose_stnum_inject` | Inject GOOSE with high stNum to override legitimate publisher |
| `exploits/protocols/iec61850/sv_timestamp_forge` | Forge Sampled Values timestamp |
| `exploits/protocols/iec61850/mms_getnamelist` | Enumerate all IED logical nodes |

---

## Credential Module Details — Full Credential Lists

### `creds/generic/http_default` — Credentials Tested

| Username | Password | Type |
|----------|---------|------|
| admin | admin | Factory default |
| admin | password | Common weak |
| admin | (blank) | No password |
| admin | 1234 | Numeric default |
| admin | 12345678 | Numeric default |
| root | root | Unix default |
| root | (blank) | Unix no-password |
| user | user | Generic |
| operator | operator | OT operator role |
| Administrator | (blank) | Windows default |
| administrator | admin | Windows variant |
| guest | guest | Read-only |
| support | support | Vendor support |
| service | service | Field service |
| system | system | System account |

### `creds/generic/snmp_community` — Community Strings Tested

| Community String | Type | Risk |
|----------------|------|------|
| public | Default read | HIGH — information disclosure |
| private | Default write | CRITICAL — configuration write |
| admin | Common | HIGH |
| 0 | Common legacy | HIGH |
| community | Common | HIGH |
| snmp | Common | HIGH |
| CISCO | Cisco default | HIGH |
| 5nmp | Obfuscated | MEDIUM |
| manager | HP/3Com | HIGH |
| monitor | Monitoring | MEDIUM |
| network | Common | MEDIUM |
| access | Common | MEDIUM |
| write | Explicit write | CRITICAL |

---

## Using IXF Modules for Compliance Evidence

### Generating Evidence for IEC 62443 Audits

IXF simulate-mode outputs serve as documented evidence that specific attack vectors were tested:

```bash
# Run all relevant tests in simulate mode and generate evidence report
ixf assess iec62443/zone_conduit_audit
ixf use exploits/protocols/modbus/modbus_unauthorized_coil_set
ixf set target 192.168.1.100
ixf run    # simulate output documents the attack would succeed without controls
ixf report json    # report contains simulate output as evidence
```

The JSON report can be attached to IEC 62443 assessment artifacts as evidence that:
- Specific attack vectors were tested
- Controls were (or were not) effective
- MITRE technique coverage was assessed

### Generating Evidence for NIST 800-82 Audits

```bash
# Run full NIST checklist and export
ixf assess nist_sp800_82/control_checklist
ixf assess network/ics_firewall_audit
ixf report markdown    # human-readable for audit documentation
```

### Generating a Penetration Test Report

```bash
# Full pentest workflow with report
ixf mitre-scan 192.168.1.0/24          # Phase 1: discovery
ixf assess risk/ics_risk_scorer         # Phase 2: risk scoring
ixf assess iec62443/zone_conduit_audit  # Phase 3: compliance
ixf report html                         # Generate HTML pentest report
ixf report json                         # Machine-readable output for ticketing
ixf report navigator                    # MITRE Navigator layer for visualization
```

---

## Frequently Asked Questions — Module Catalog

### How many modules target Modbus-based systems?

Over 200 modules interact with Modbus in some way: the 10 Modbus-specific protocol exploit modules, the 2 Modbus scanners, the 34 credential modules (many use HTTP to manage Modbus-accessible devices), and numerous CVE modules targeting devices that use Modbus TCP (Schneider Modicon, Rockwell, generic RTUs).

### Can I run all CVE modules against a single target?

Yes, using a custom loop or the `mitre-scan` command which chains multiple modules:

```bash
ixf mitre-scan 192.168.1.100    # runs all technique-mapped modules
ixf ttp T0866 192.168.1.100     # runs all modules for T0866 (Exploitation of Remote Services)
```

For individual vendor sweeps:
```bash
ixf search siemens | grep "use " | while read cmd; do ixf $cmd set target 192.168.1.50 run; done
```

### Are modules safe to run on production systems?

In simulate mode (default): **yes**, all modules print what they would do without sending packets.

In live mode (`set simulate false`): use only on authorized test systems. The `check` command sends a read-only connectivity probe and is generally safe on production.

### How often is the module database updated?

New modules are added with each release. Subscribe to GitHub releases for notifications: https://github.com/mrhenrike/IndustrialXPL-Forge/releases

### How do I report a missing CVE or vendor?

Open an issue: https://github.com/mrhenrike/IndustrialXPL-Forge/issues with the CVE ID, affected product, and CVSS score.

---

## Module Catalog Summary

| Metric | Value |
|--------|-------|
| Total modules | 976 |
| Vendors covered | 150+ |
| Protocols covered | 50+ |
| CVE IDs mapped | 3,300+ |
| MITRE techniques covered | 74/90 (82%) |
| Malware TTPs simulated | 26 (2010–2024) |
| ICS languages (SAST) | 7 |
| NSE scripts | 8 |
| Highest CVSS in catalog | 9.8 (multiple) |
| Lowest CVSS in catalog | 2.0 |
| Average CVSS (CVE modules) | 8.1 |

---

## Module Update Cadence

New modules are added to IXF on a rolling basis:

| Trigger | Timeline | Priority |
|---------|----------|----------|
| ICS-CERT/CISA advisory published | Within 4 weeks | High |
| CVE NVD publication (ICS vendor, CVSS ≥ 7.0) | Within 4 weeks | High |
| Novel ICS malware campaign discovered | Within 2 weeks | Critical |
| Penetration tester contribution | After review (2-4 weeks) | Medium |
| New protocol exploit research | After validation | Medium |
| Vendor security bulletin | Within 6 weeks | Standard |

### Tracking New Modules

```bash
# Check IXF changelog for new modules
pip show industrialxpl-forge
# Check PyPI for latest version
pip index versions industrialxpl-forge
# Upgrade to latest
pip install --upgrade industrialxpl-forge
# Check what changed
python -c "
import industrialxpl
print(industrialxpl.__version__)
from industrialxpl.core.exploit.utils import index_modules
m = index_modules()
print(f'Modules in installed version: {len(m)}')
"
```

---

## Module Security Policy

All modules in the IXF catalog comply with the following policies:

1. **No real credentials** — modules never contain actual passwords, API keys, or authentication tokens. Test credentials are from public vendor documentation or public CVE disclosures.

2. **Simulate-first** — every module MUST have a working `simulate=True` path before live execution is available. A module that only executes live will not be accepted.

3. **Impact accuracy** — impact levels must accurately reflect the real-world consequence. Understating impact (e.g., marking CATASTROPHIC as HIGH) is never acceptable.

4. **Attribution** — malware TTP modules correctly attribute the original threat actor and include references to public reporting.

5. **No 0-day** — IXF only covers publicly disclosed vulnerabilities with CVE identifiers or well-documented TTPs. No unpublished research or live 0-day exploitation.

6. **Physical impact documentation** — every CVE module must explicitly state the physical consequence in the simulation output.

7. **MITRE accuracy** — MITRE ATT&CK for ICS technique mappings must match official ICS ATT&CK matrix definitions (https://attack.mitre.org/matrices/ics/).

---

## Module Changelog

Track major module additions by version:

| IXF Version | New Modules | Key Additions |
|-------------|------------|---------------|
| v1.0.13 | +12 | CosmicEnergy IEC 104, Industroyer2, WAGO CVE-2022-45138, Delta CVE-2023-47207 |
| v1.0.12 | +8 | FrostyGoop extended (Go), EKANS v2, 3 ABB modules |
| v1.0.11 | +15 | 8 Schneider modules, Unitronics CVE-2023-6448, AVEVA CVE-2023-34982 |
| v1.0.10 | +20 | Full NSE script suite (8 scripts), Honeywell CVE-2023-5389 |
| v1.0.9 | +18 | MITRE ICS 28 TTP assessment modules, ICS kill chain |
| v1.0.8 | +25 | Rockwell CVE-2022-1161, CVE-2023-3595, LS Electric suite |
| v1.0.7 | +30 | INCONTROLLER/PIPEDREAM full suite (5 modules) |
| v1.0.6 | +22 | 150 vendor milestone, WEG/ALTUS/NOVUS Brazil suite |
| v1.0.5 | +35 | Malware TTP suite (KillDisk, NotPetya, TRITON) |
| v1.0.0 | 800 | Initial public release — 800 base modules |

---

## Getting Help Finding Modules

```
ixf > help
ixf > stats
ixf > vendors
ixf > protocols
ixf > mitre-list
ixf > search <any keyword>
```

For module development, see [09-module-development.md](09-module-development.md).
For the assessment workflow, see [12-assessment-compliance.md](12-assessment-compliance.md).
For NSE scripts, see [14-nse-scripts.md](14-nse-scripts.md).

---

## Complete Scanner Module Reference

### Scanner Module Options

All scanner modules share a common base set of options. Here is the full options reference using `modbus_scanner` as a representative example:

```
ixf > use scanners/ics/modbus_scanner
ixf (Modbus TCP Scanner) > show options

  Options — Modbus TCP Scanner (CIDR Range)
  ═══════════════════════════════════════════════════════════════════════════
  +──────────────────+──────────+──────────+────────────────────────────────────────────────+
  | Option           | Value    | Required | Description                                    |
  +──────────────────+──────────+──────────+────────────────────────────────────────────────+
  | target           |          | yes      | Target IP, hostname, or CIDR range             |
  | port             | 502      | no       | Modbus TCP port (default: 502)                 |
  | unit_id_start    | 1        | no       | Starting unit ID for sweep (1-247)             |
  | unit_id_end      | 10       | no       | Ending unit ID for sweep                       |
  | timeout          | 3        | no       | Per-host connection timeout in seconds         |
  | threads          | 10       | no       | Parallel threads for CIDR scan                |
  | simulate         | True     | no       | Simulate mode (no packets sent)                |
  | output_format    | table    | no       | Output format: table / json / csv              |
  +──────────────────+──────────+──────────+────────────────────────────────────────────────+

ixf (Modbus TCP Scanner) > set target 192.168.1.0/24
[*] target => 192.168.1.0/24

ixf (Modbus TCP Scanner) > set threads 20
[*] threads => 20

ixf (Modbus TCP Scanner) > run

  [SIMULATE MODE — no packets sent]
  Module:  Modbus TCP Scanner — CIDR Range
  Target:  192.168.1.0/24  Threads: 20

  Step 1: Resolve 192.168.1.0/24 to 254 host addresses (192.168.1.1–192.168.1.254)
  Step 2: Spawn 20 threads; each tests up to 13 hosts
  Step 3: Per host: TCP SYN to port 502, timeout 3s
  Step 4: For responsive hosts: send Modbus FC4 (Read Input Registers) probe
  Step 5: Verify MBAP Transaction ID echo in response
  Step 6: For confirmed Modbus devices: sweep unit IDs 1-10
  Step 7: Report all Modbus devices with responding unit IDs

  [i] Live output (example):
      192.168.1.50   port 502  OPEN  Unit 1: Input Register[0]=0x0064  DETECTED
      192.168.1.100  port 502  OPEN  Unit 1: Input Register[0]=0x0032  DETECTED
      192.168.1.100  port 502  OPEN  Unit 2: Input Register[0]=0x0000  DETECTED
      192.168.1.155  port 502  OPEN  Unit 1: no response (non-Modbus service)
  [i] MITRE ATT&CK for ICS: T0888 (Remote System Information Discovery)
```

### Scanner Output Formats

```bash
# Table (default) — human readable
ixf use scanners/ics/modbus_scanner set target 192.168.1.0/24 run

# JSON — for parsing and integration
ixf use scanners/ics/modbus_scanner set target 192.168.1.0/24 set output_format json run > scan.json

# CSV — for spreadsheet import
ixf use scanners/ics/modbus_scanner set target 192.168.1.0/24 set output_format csv run > scan.csv
```

---

## Complete Protocol Exploit Module Reference

### Module Severity and MITRE Mapping

| Module Category | Severity Distribution | Key MITRE Techniques |
|-----------------|----------------------|---------------------|
| Modbus exploits | HIGH (80%), MEDIUM (20%) | T0855, T0836, T0806, T0802 |
| S7comm exploits | CRITICAL (60%), HIGH (40%) | T0855, T0881, T0843, T0845 |
| EtherNet/IP | HIGH (78%), CRITICAL (22%) | T0855, T0861, T0843, T0808 |
| DNP3 | CRITICAL (50%), HIGH (50%) | T0855, T0803, T0813 |
| BACnet | HIGH (71%), MEDIUM (29%) | T0855, T0836, T0802 |
| IEC 60870-5-104 | CRITICAL (67%), HIGH (33%) | T0855, T0803 |
| IEC 61850 | CRITICAL (60%), HIGH (40%) | T0855, T0829, T0876 |
| OPC UA | HIGH (67%), MEDIUM (33%) | T0855, T0802, T0866 |
| MQTT | HIGH (75%), MEDIUM (25%) | T0802, T0855 |
| SNMP | MEDIUM (60%), HIGH (40%) | T0802, T0888 |

---

## Credential Module — Detailed Coverage

### Vendor-Specific Credential Database

The IXF credential database contains 34 modules covering the most common default credential exposures in OT environments. Each module tests credentials specific to the vendor's implementation.

#### Siemens HMI Web Server Default Credentials

```
ixf > use creds/siemens/siemens_web_hmi_default
ixf > set target 192.168.1.50
ixf > set port 80
ixf > run

  [SIMULATE MODE — no packets sent]
  Module: Siemens SIMATIC HMI Web Server Default Credentials
  Target: http://192.168.1.50:80

  Credential pairs that would be tested:

  Path: /api/jsonrpc (Siemens WinCC Web Navigator)
  +──────────────────────────────────────+────────────────────+
  | Username                             | Password           |
  +──────────────────────────────────────+────────────────────+
  | admin                                | admin              |
  | admin                                | siemens            |
  | service                              | service            |
  | User                                 | (blank)            |
  | Administrator                        | (blank)            |
  | Siemens                              | Siemens            |
  +──────────────────────────────────────+────────────────────+

  [i] HMI web server found on Siemens TP1500, TP700, KP900, SMART panels
  [i] MITRE: T0812 (Default Credentials)
```

#### Rockwell FactoryTalk Default Credentials

```
ixf > use creds/rockwell/factorytalk_default
ixf > set target 192.168.1.110
ixf > run

  [SIMULATE MODE — no packets sent]
  Module: Rockwell FactoryTalk View Default Credentials
  Target: https://192.168.1.110:443

  Credential pairs tested:
  +──────────────────────────────+────────────────────────+──────────────────────+
  | Username                     | Password               | Notes                |
  +──────────────────────────────+────────────────────────+──────────────────────+
  | admin                        | admin                  | Factory default      |
  | ftvse                        | ftvse                  | FTV Site Edition     |
  | Administrator                | (blank)                | Windows admin        |
  | Rockwell                     | (blank)                | Vendor default       |
  | guest                        | (blank)                | Guest account        |
  +──────────────────────────────+────────────────────────+──────────────────────+
```

#### Ignition SCADA Default Credentials

```
ixf > use creds/inductive/ignition_default
ixf > set target 192.168.1.30
ixf > set port 8088
ixf > run

  [SIMULATE MODE — no packets sent]
  Module: Inductive Automation Ignition Gateway Default Credentials
  Target: http://192.168.1.30:8088

  Login endpoint: POST /data/login/default?designMode=0
  +──────────────────────────────+────────────────────────+──────────────────────────────+
  | Username                     | Password               | Notes                        |
  +──────────────────────────────+────────────────────────+──────────────────────────────+
  | admin                        | password               | Ignition factory default     |
  | admin                        | admin                  | Common weak                  |
  | admin                        | ignition               | Product name                 |
  | admin                        | 12345678               | Common numeric               |
  | user                         | user                   | Operator role                |
  +──────────────────────────────+────────────────────────+──────────────────────────────+

  Success detection: HTTP 200 + JSON {"auth_required": false, "user": "admin"}
  [i] Ignition admin access = full SCADA project read/write, OPC UA client, tag database
  [i] MITRE: T0812, T0819, T0866
```

---

## Module Tagging System

Every module has a `tags` field in `__info__` for faceted search. Common tags used in the IXF catalog:

| Tag Category | Examples |
|-------------|---------|
| Protocol | `modbus`, `s7`, `enip`, `dnp3`, `bacnet`, `opcua`, `mqtt`, `snmp` |
| Vendor | `siemens`, `rockwell`, `schneider`, `abb`, `honeywell`, `omron` |
| Impact type | `rce`, `dos`, `auth_bypass`, `info_disclosure`, `xss`, `sqli` |
| Severity | `critical`, `high`, `medium`, `low` |
| Sector | `power`, `water`, `oil_gas`, `manufacturing`, `building`, `nuclear` |
| Module type | `scanner`, `creds`, `exploit`, `assessment`, `malware` |
| Safety | `sis`, `safety`, `sil` |
| Region | `usa`, `europe`, `asia`, `brazil`, `japan`, `china` |

### Searching by tag in IXF

```
ixf > search sis
[*] Search results for: sis
    use cve/schneider/cve_2021_22763_modicon_cred_bypass  (sis, safety)
    use malware/triton/triton_sic_rewrite                 (sis, safety, critical)
    use malware/triton/triton_safe_state_bypass           (sis, safety, sil)
    use assessment/mitre_ics/t0829_loss_of_protection     (sis, safety)
    ... (8 results)

ixf > search nuclear
[*] Search results for: nuclear
    use cve/westinghouse/cve_2021_33023_common_q_dos     (nuclear)
    use cve/framatome/cve_2022_48192_teleperm_auth       (nuclear)
    ... (3 results)
```

---

## Module Categories — Detailed Breakdown

### CVE Module Sub-categories

CVE modules are organized by the vulnerability type they exploit:

| Sub-category | Count | Description |
|--------------|-------|-------------|
| Authentication bypass | 198 | Direct access without credentials |
| Remote code execution | 287 | Arbitrary code execution on target |
| Denial of service | 142 | Crash, reboot, or performance degradation |
| SQL injection | 67 | Database injection leading to data access or RCE |
| Path traversal | 45 | File system access outside allowed paths |
| Information disclosure | 38 | Sensitive data leakage (firmware, config, creds) |
| Buffer overflow | 15 | Memory corruption — crash or RCE |
| XSS / CSRF | 22 | Web-based attacks on HMI/SCADA web interfaces |

### Protocol Exploit Sub-categories

| Sub-category | Count | Description |
|--------------|-------|-------------|
| Read operations | 28 | Protocol read commands (safe: monitoring, intel gathering) |
| Write operations | 31 | Protocol write commands (dangerous: process impact) |
| Control commands | 24 | Direct control (breaker trip, CPU stop, actuator) |
| Replay attacks | 8 | Replay captured legitimate commands |
| Fuzzing | 6 | Malformed protocol frames to discover parser bugs |
| Enumeration | 5 | Device and service enumeration |

### Scanner Sub-categories

| Sub-category | Count | Description |
|--------------|-------|-------------|
| Detection | 12 | Confirm specific protocol is running on target |
| Range scan | 8 | CIDR sweep for protocol-speaking devices |
| Enumeration | 7 | Deep device info extraction (model, firmware) |
| Credential probe | 4 | Non-destructive credential check (compatible with check cmd) |

---

## IXF Module Naming Convention

All modules follow a consistent naming scheme:

```
cve/<vendor>/<cve_id>_<product_short>_<vuln_type>.py
exploits/protocols/<protocol>/<protocol>_<action>.py
scanners/ics/<protocol>_<scan_type>.py
creds/<vendor>/<product>_default.py
assessment/<standard>/<check_name>.py
malware/<malware_name>/<component>.py
nse/<script_name>.py
```

### Examples

```
cve/siemens/cve_2021_22681_s7_1200_hardcoded_key.py
  └─ vendor: siemens
  └─ cve: CVE-2021-22681
  └─ product: s7_1200
  └─ vuln: hardcoded_key

exploits/protocols/modbus/modbus_unauthorized_coil_set.py
  └─ protocol: modbus
  └─ action: unauthorized_coil_set

scanners/ics/s7_comm_scanner.py
  └─ protocol: s7_comm
  └─ scan type: scanner

creds/tridium/niagara_default.py
  └─ vendor: tridium
  └─ product: niagara
  └─ type: default credentials

assessment/iec62443/zone_conduit_audit.py
  └─ standard: iec62443
  └─ check: zone_conduit_audit

malware/industroyer/industroyer2_iec104.py
  └─ malware family: industroyer
  └─ component: industroyer2_iec104
```

---

## Integration with Third-Party Security Tools

### Exporting IXF Results to SIEM

```bash
# Export JSON report to file
ixf report json

# Parse findings and send to Splunk HTTP Event Collector
python -c "
import json, requests
with open('./ixf-report-2026-06-01.json') as f:
    report = json.load(f)

for finding in report['findings']:
    event = {
        'sourcetype': 'ixf:finding',
        'event': finding
    }
    requests.post(
        'https://splunk.corp.example.com:8088/services/collector',
        headers={'Authorization': 'Splunk <token>'},
        json=event
    )
"
```

### Integrating with Nozomi Networks / Claroty

IXF simulate-mode output can be used to validate that Claroty/Nozomi/Dragos OT NDR solutions detect the attack patterns:

```bash
# 1. Enable NDR detection mode (passive)
# 2. Run IXF in LIVE mode (set simulate false) against test PLC
# 3. Verify NDR alerts were generated
ixf use exploits/protocols/modbus/modbus_unauthorized_coil_set
ixf set target 192.168.1.100     # test PLC only
ixf set simulate false
ixf set destructive true
ixf run    # triggers real Modbus write — NDR should alert
```

### Using IXF in CI/CD for OT Security Regression Testing

```yaml
# .github/workflows/ot-security-test.yml
name: OT Security Regression Test
on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly, Monday 2am

jobs:
  ot-assessment:
    runs-on: ubuntu-latest
    steps:
      - name: Install IXF
        run: 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    

      - name: Run compliance assessment
        run: |
          ixf assess iec62443/zone_conduit_audit
          ixf assess nist_sp800_82/control_checklist
          ixf assess network/ics_firewall_audit
          ixf report json

      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: ot-security-report
          path: ixf-report-*.json
```

---

*Previous: [Assessment & Compliance](12-assessment-compliance.md) | Next: [NSE Scripts](14-nse-scripts.md)*
