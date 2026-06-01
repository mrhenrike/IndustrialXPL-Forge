# Catálogo de Módulos

Catálogo completo de todos os módulos disponíveis no IndustrialXPL-Forge. Este documento lista todos os 976+ módulos organizados por categoria, com caminhos de uso, CVEs, scores CVSS e níveis de impacto.

---

## Índice

1. [Introdução](#introdução)
2. [Como Buscar Módulos](#como-buscar-módulos)
3. [Módulos CVE por Vendor (150+ vendors)](#módulos-cve-por-vendor)
4. [Módulos de Protocolo (50 protocolos)](#módulos-de-protocolo)
5. [Scanners (31 listados)](#scanners)
6. [Creds (34 listados)](#creds)
7. [Assessment (18 listados)](#assessment)
8. [Malware TTP (26 listados)](#malware-ttp)
9. [Estatísticas](#estatísticas)

---

## Introdução

O IXF é uma plataforma modular de pesquisa em segurança OT/ICS. Seus módulos cobrem:

- **486 módulos CVE** — exploits de vulnerabilidades documentadas em PLCs, RTUs, SCADA e HMIs
- **159 módulos de exploit de protocolo** — abuso de Modbus, S7comm, EtherNet/IP, DNP3 e mais
- **34 módulos de credenciais** — teste de credenciais padrão por vendor
- **31 módulos scanner** — descoberta e fingerprinting de dispositivos ICS
- **18 módulos de assessment** — conformidade IEC 62443, NIST SP 800-82, scoring de risco
- **26 módulos de malware TTP** — replay de ataques históricos (FrostyGoop, TRITON, Industroyer)

Todos os módulos têm `simulate=True` como padrão — nenhum payload é enviado sem opt-in explícito.

---

## Como Buscar Módulos

### Busca por palavra-chave
```
ixf > search modbus
ixf > search siemens
ixf > search CVE-2021
ixf > search hardcoded
```

### Busca por CVE
```
ixf > cve CVE-2021-22681
ixf > search CVE-2022-29965
```

### Busca por vendor
```
ixf > vendors siemens
ixf > search rockwell
```

### Busca por protocolo
```
ixf > search s7comm
ixf > search modbus
ixf > search enip
```

### Busca por categoria
```
ixf > search scanner
ixf > search creds
ixf > search assessment
ixf > search malware
```

### Listar por MITRE
```
ixf > mitre T0836
ixf > ttp-list --tactic impair
```

---

## Módulos CVE por Vendor

### Schneider Electric (39 módulos)

| Caminho do Módulo | CVE | CVSS | Impacto | Descrição Curta |
|-------------------|-----|------|---------|-----------------|
| `cve/schneider/cve_2018_7789_modicon_rce` | CVE-2018-7789 | 9.8 | CRITICAL | Modicon M340 RCE via HTTP |
| `cve/schneider/cve_2021_22763_ecostruxure_auth_bypass` | CVE-2021-22763 | 9.8 | CRITICAL | EcoStruxure Auth Bypass |
| `cve/schneider/cve_2022_45789_ecostruxure_rce` | CVE-2022-45789 | 9.8 | CRITICAL | EcoStruxure Expert RCE |
| `cve/schneider/cve_2019_6829_modicon_dos` | CVE-2019-6829 | 7.5 | HIGH | Modicon M340/Premium DoS |
| `cve/schneider/cve_2021_22797_easergy_t300` | CVE-2021-22797 | 9.8 | CRITICAL | Easergy T300 Auth Bypass |
| `cve/schneider/cve_2022_37300_netmaster` | CVE-2022-37300 | 9.8 | CRITICAL | NET Master Path Traversal |
| `cve/schneider/cve_2023_37195_conext_combox` | CVE-2023-37195 | 9.8 | CRITICAL | Conext ComBox RCE |
| `cve/schneider/cve_2021_22786_modicon_m580` | CVE-2021-22786 | 7.5 | HIGH | Modicon M580 DoS |
| `cve/schneider/cve_2022_34759_clearscada` | CVE-2022-34759 | 9.8 | CRITICAL | ClearSCADA Unauthenticated Access |
| `cve/schneider/cve_2022_24322_ecostruxure_sql` | CVE-2022-24322 | 9.8 | CRITICAL | EcoStruxure SQL Injection |
| `cve/schneider/cve_2022_24325_easergy_p3u30` | CVE-2022-24325 | 7.5 | HIGH | Easergy P3U30 Auth Bypass |
| `cve/schneider/cve_2021_22763_powermanager` | CVE-2021-22763 | 7.8 | HIGH | PowerManager Default Creds |
| `cve/apt/triton_triconex_safety_overwrite` | N/A | N/A | CATASTROPHIC | TRITON/TRISIS SIS Overwrite |
| ... (26 módulos adicionais) | | | | |

### Rockwell Automation / Allen-Bradley (38 módulos)

| Caminho do Módulo | CVE | CVSS | Impacto | Descrição Curta |
|-------------------|-----|------|---------|-----------------|
| `cve/rockwell/cve_2022_1161_controllogix_modified_fw` | CVE-2022-1161 | 8.8 | CRITICAL | ControlLogix Modified FW |
| `cve/rockwell/cve_2023_3595_controllogix_rce` | CVE-2023-3595 | 9.8 | CRITICAL | ControlLogix Remote Code Execution |
| `cve/rockwell/cve_2023_3596_logix_dos` | CVE-2023-3596 | 7.5 | HIGH | Logix 5000 Denial of Service |
| `cve/rockwell/cve_2022_1159_logix5000_heap_overflow` | CVE-2022-1159 | 9.8 | CRITICAL | Logix5000 Heap Overflow |
| `cve/rockwell/cve_2021_22681_logix_hardcoded` | CVE-2021-22681 | 9.8 | CRITICAL | Logix Hardcoded Key |
| `cve/rockwell/cve_2022_3752_compactlogix_dos` | CVE-2022-3752 | 7.5 | HIGH | CompactLogix 5380 DoS |
| `cve/rockwell/cve_2021_33012_micrologix_dos` | CVE-2021-33012 | 7.5 | HIGH | MicroLogix DoS |
| `cve/rockwell/cve_2012_6435_enip_dos` | CVE-2012-6435 | 7.8 | HIGH | EtherNet/IP Legacy DoS |
| `cve/rockwell/cve_2020_6998_factorytalk` | CVE-2020-6998 | 9.8 | CRITICAL | FactoryTalk View SE RCE |
| `cve/rockwell/cve_2022_46670_logix_path_traversal` | CVE-2022-46670 | 7.5 | HIGH | Logix Path Traversal |
| ... (28 módulos adicionais) | | | | |

### Siemens (27 módulos)

| Caminho do Módulo | CVE | CVSS | Impacto | Descrição Curta |
|-------------------|-----|------|---------|-----------------|
| `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key` | CVE-2021-22681 | 9.8 | CRITICAL | S7-1200/1500 Hardcoded Key |
| `cve/siemens/cve_2022_38465_s7_global_key` | CVE-2022-38465 | 9.3 | CRITICAL | S7 Global Private Key Bypass |
| `cve/siemens/cve_2019_13945_simatic_s7_dos` | CVE-2019-13945 | 7.5 | HIGH | SIMATIC S7-1200 DoS |
| `cve/siemens/cve_2017_2680_scalance_x_dos` | CVE-2017-2680 | 7.5 | HIGH | SCALANCE X Switch DoS |
| `cve/siemens/cve_2021_40365_simatic_hmi` | CVE-2021-40365 | 9.8 | CRITICAL | SIMATIC HMI Unauth. Access |
| `cve/siemens/cve_2020_15782_wincc_path_traversal` | CVE-2020-15782 | 9.1 | CRITICAL | WinCC Path Traversal |
| `cve/siemens/cve_2021_22698_simatic_wincc_oa` | CVE-2021-22698 | 7.8 | HIGH | WinCC OA DoS |
| `cve/siemens/cve_2021_37195_sinema_rc` | CVE-2021-37195 | 9.8 | CRITICAL | SINEMA Remote Connect RCE |
| `cve/siemens/cve_2023_38380_scalance_xm400` | CVE-2023-38380 | 7.5 | HIGH | SCALANCE XM400 DoS |
| `cve/siemens/cve_2022_32257_sinema_server` | CVE-2022-32257 | 9.8 | CRITICAL | SINEMA Server Auth Bypass |
| `cve/siemens/cve_2019_10929_simatic_s7_auth` | CVE-2019-10929 | 5.9 | MEDIUM | S7 Auth Bypass (Brute Force) |
| `cve/siemens/cve_2022_43513_simatic_ipc` | CVE-2022-43513 | 7.5 | HIGH | SIMATIC IPC Path Traversal |
| ... (15 módulos adicionais) | | | | |

### GE Digital / Emerson (24 módulos)

| Caminho do Módulo | CVE | CVSS | Impacto | Descrição Curta |
|-------------------|-----|------|---------|-----------------|
| `cve/ge/cve_2020_35952_ge_cimplicity_path_traversal` | CVE-2020-35952 | 9.8 | CRITICAL | Cimplicity Path Traversal RCE |
| `cve/ge/cve_2018_10952_ge_ifix_buffer_overflow` | CVE-2018-10952 | 9.8 | CRITICAL | iFIX Buffer Overflow |
| `cve/ge/cve_2022_29965_roc800_hardcoded_creds` | CVE-2022-29965 | 9.8 | CRITICAL | Emerson ROC800 Hardcoded Creds |
| `cve/ge/cve_2021_40877_pacsystems_rx3i` | CVE-2021-40877 | 7.5 | HIGH | PACSystems RX3i DoS |
| `cve/ge/cve_2020_25159_proficy_historian` | CVE-2020-25159 | 9.8 | CRITICAL | Proficy Historian Unauth Access |
| ... (19 módulos adicionais) | | | | |

### Honeywell (21 módulos)

| Caminho do Módulo | CVE | CVSS | Impacto | Descrição Curta |
|-------------------|-----|------|---------|-----------------|
| `cve/honeywell/cve_2021_38395_experion_pks` | CVE-2021-38395 | 10.0 | CRITICAL | Experion PKS RCE |
| `cve/honeywell/cve_2021_38397_experion_dos` | CVE-2021-38397 | 7.5 | HIGH | Experion PKS DoS |
| `cve/honeywell/cve_2023_25178_crane_pb` | CVE-2023-25178 | 9.8 | CRITICAL | Honeywell Safety Manager Auth Bypass |
| ... (18 módulos adicionais) | | | | |

### Mitsubishi Electric (18 módulos)

| Caminho do Módulo | CVE | CVSS | Impacto | Descrição Curta |
|-------------------|-----|------|---------|-----------------|
| `cve/mitsubishi/cve_2022_33139_melsec_fw` | CVE-2022-33139 | 7.5 | HIGH | MELSEC-F Series FW Update DoS |
| `cve/mitsubishi/cve_2021_20600_melsec_dos` | CVE-2021-20600 | 7.5 | HIGH | MELSEC iQ-R DoS |
| `cve/mitsubishi/cve_2023_47590_melsec_rce` | CVE-2023-47590 | 9.8 | CRITICAL | MELSEC-Q Series RCE |
| ... (15 módulos adicionais) | | | | |

### ABB (15 módulos)

| Caminho do Módulo | CVE | CVSS | Impacto | Descrição Curta |
|-------------------|-----|------|---------|-----------------|
| `cve/abb/cve_2021_22281_abb_800xa_auth_bypass` | CVE-2021-22281 | 9.8 | CRITICAL | 800xA Auth Bypass |
| `cve/abb/cve_2022_1573_abb_totalflow` | CVE-2022-1573 | 9.8 | CRITICAL | TotalFlow Auth Bypass |
| ... (13 módulos adicionais) | | | | |

### Omron (13 módulos)

| Caminho do Módulo | CVE | CVSS | Impacto | Descrição Curta |
|-------------------|-----|------|---------|-----------------|
| `cve/omron/cve_2022_34151_sysmac_studio` | CVE-2022-34151 | 8.8 | HIGH | Sysmac Studio Path Traversal |
| `cve/omron/cve_2021_27477_cj2m` | CVE-2021-27477 | 7.5 | HIGH | CJ2M Series DoS via FINS |
| ... (11 módulos adicionais) | | | | |

### Inductive Automation (7 módulos)

| Caminho do Módulo | CVE | CVSS | Impacto | Descrição Curta |
|-------------------|-----|------|---------|-----------------|
| `cve/inductive/cve_2023_39476_ignition_rce` | CVE-2023-39476 | 9.8 | CRITICAL | Ignition Gateway RCE via Deserial. |
| `cve/inductive/cve_2022_35871_ignition_path` | CVE-2022-35871 | 7.5 | HIGH | Ignition Path Traversal |
| ... (5 módulos adicionais) | | | | |

### Kepware Technologies (6 módulos)

| Caminho do Módulo | CVE | CVSS | Impacto | Descrição Curta |
|-------------------|-----|------|---------|-----------------|
| `cve/kepware/cve_2022_2848_kepserverex_bof` | CVE-2022-2848 | 9.1 | CRITICAL | KEPServerEX Buffer Overflow |
| `cve/kepware/cve_2021_33010_kepserverex_dos` | CVE-2021-33010 | 7.5 | HIGH | KEPServerEX DoS |
| ... (4 módulos adicionais) | | | | |

### Phoenix Contact (11 módulos)

| Caminho do Módulo | CVE | CVSS | Impacto | Descrição Curta |
|-------------------|-----|------|---------|-----------------|
| `cve/phoenix/cve_2022_36249_plcnext_auth_bypass` | CVE-2022-36249 | 9.8 | CRITICAL | PLCnext Auth Bypass |
| `cve/phoenix/cve_2021_34566_plcnext_bof` | CVE-2021-34566 | 9.8 | CRITICAL | PLCnext Buffer Overflow RCE |
| ... (9 módulos adicionais) | | | | |

### Beckhoff (10 módulos)

| Caminho do Módulo | CVE | CVSS | Impacto | Descrição Curta |
|-------------------|-----|------|---------|-----------------|
| `cve/beckhoff/cve_2020_12494_twincat_ads_dos` | CVE-2020-12494 | 7.5 | HIGH | TwinCAT ADS DoS |
| `cve/beckhoff/cve_2019_5637_twincat_path` | CVE-2019-5637 | 9.8 | CRITICAL | TwinCAT Path Traversal |
| ... (8 módulos adicionais) | | | | |

### Unitronics (4 módulos)

| Caminho do Módulo | CVE | CVSS | Impacto | Descrição Curta |
|-------------------|-----|------|---------|-----------------|
| `cve/unitronics/cve_2023_6448_unistream_rce` | CVE-2023-6448 | 9.8 | CRITICAL | UniStream RCE (sem autenticação) |
| `cve/unitronics/cve_2023_6448_vision_unauth` | CVE-2023-6448 | 9.8 | CRITICAL | Vision Series Unauth Access |
| ... (2 módulos adicionais) | | | | |

### Módulos APT / Campanha (9 módulos)

| Caminho do Módulo | Ator | Impacto | Descrição |
|-------------------|------|---------|-----------|
| `cve/apt/sandworm_industroyer_iec104` | Sandworm/GRU | CATASTROPHIC | Industroyer IEC 104 payload (Ucrânia 2016) |
| `cve/apt/triton_triconex_safety_overwrite` | XENOTIME | CATASTROPHIC | TRITON SIS overwrite (Arábia Saudita 2017) |
| `cve/apt/lazarus_ecipekac_plc` | Lazarus Group | CRITICAL | PLC implant TTP |
| `cve/apt/industroyer2` | Sandworm/GRU | CATASTROPHIC | Industroyer2 (Ucrânia 2022) |
| `cve/apt/apt_dragonfly_havex` | Energetic Bear | HIGH | HaVeX RAT OPC DA |
| `cve/apt/sandworm_blackenergy` | Sandworm | HIGH | BlackEnergy SCADA exfiltration |
| `cve/apt/apt_xenotime_triton` | XENOTIME | CATASTROPHIC | TRITON TTP simulation |
| `cve/apt/lazarus_elektronchnaya` | Lazarus | HIGH | Elektronchnaya campaign |
| `cve/apt/voodoo_bear_crashoverride` | Sandworm | CATASTROPHIC | Crashoverride full TTP |

---

## Módulos de Protocolo

### Modbus TCP (18 módulos)

| Caminho do Módulo | Impacto | Descrição |
|-------------------|---------|-----------|
| `exploits/protocols/modbus/modbus_fc90_dos` | MEDIUM | FC90 (Function Code 90) DoS — código inválido |
| `exploits/protocols/modbus/modbus_fc16_write_registers` | MEDIUM | FC16 Write Multiple Registers sem auth |
| `exploits/protocols/modbus/modbus_fc05_coil_write` | LOW | FC05 Write Single Coil |
| `exploits/protocols/modbus/modbus_fc06_register_write` | LOW | FC06 Write Single Register |
| `exploits/protocols/modbus/modbus_alarm_disable` | MEDIUM | Desabilitar alarmes via Modbus |
| `exploits/protocols/modbus/modbus_rogue_master` | HIGH | Injeção de mestre Modbus desonesto |
| `exploits/protocols/modbus/modbus_unit_id_flood` | MEDIUM | Flood de unit IDs inválidos |
| `exploits/protocols/modbus/modbus_broadcast_dos` | MEDIUM | DoS via broadcast de unit ID 0 |
| `exploits/protocols/modbus/modbus_read_coils_all` | READ | Lê todos os coils (0x0000-0xFFFF) |
| `exploits/protocols/modbus/modbus_read_holding_all` | READ | Lê todos os holding registers |
| ... (8 módulos adicionais) | | |

### EtherNet/IP (14 módulos)

| Caminho do Módulo | Impacto | Descrição |
|-------------------|---------|-----------|
| `exploits/protocols/enip/enip_list_identity` | READ | List Identity broadcast |
| `exploits/protocols/enip/enip_cip_forward_open_flood` | HIGH | CIP Forward Open flood — DoS |
| `exploits/protocols/enip/enip_pccc_execute` | MEDIUM | PCCC command execution |
| `exploits/protocols/enip/enip_cip_write_tag` | MEDIUM | CIP Write Tag sem autenticação |
| `exploits/protocols/enip/enip_session_hijack` | HIGH | Sequestro de sessão EtherNet/IP |
| ... (9 módulos adicionais) | | |

### S7comm (8 módulos)

| Caminho do Módulo | Impacto | Descrição |
|-------------------|---------|-----------|
| `exploits/protocols/s7comm/s7_stop_cpu` | HIGH | Para CPU PLC via PDU S7 |
| `exploits/protocols/s7comm/s7_start_cpu` | MEDIUM | Inicia CPU PLC via PDU S7 |
| `exploits/protocols/s7comm/s7_read_szl` | READ | Lê informações SZL (sem auth) |
| `exploits/protocols/s7comm/s7_unauthorized_cpu_control` | HIGH | Controle CPU não autenticado |
| `exploits/protocols/s7comm/s7_dos_malformed_pdu` | HIGH | PDU malformada provoca DoS |
| `exploits/protocols/s7comm/s7_cold_restart` | HIGH | Reinicialização a frio (cold restart) |
| ... (2 módulos adicionais) | | |

### DNP3 (4 módulos)

| Caminho do Módulo | Impacto | Descrição |
|-------------------|---------|-----------|
| `exploits/protocols/dnp3/dnp3_data_spoofing` | MEDIUM | Falsificação de dados de processo |
| `exploits/protocols/dnp3/dnp3_replay_command` | HIGH | Replay de comandos DNP3 capturados |
| `exploits/protocols/dnp3/dnp3_unauthorized_control` | HIGH | Controle não autorizado de outstation |
| `exploits/protocols/dnp3/dnp3_unsolicit_flood` | MEDIUM | Flood de respostas não solicitadas |

### IEC 60870-5-104 (6 módulos)

| Caminho do Módulo | Impacto | Descrição |
|-------------------|---------|-----------|
| `exploits/protocols/iec104/iec104_startdt_flood` | MEDIUM | STARTDT Flood — saturação de conexões |
| `exploits/protocols/iec104/iec104_command_inject` | HIGH | Injeção de comando ASDU |
| `exploits/protocols/iec104/iec104_data_spoof` | MEDIUM | Falsificação de dados ASDU |
| `exploits/protocols/iec104/iec104_dos_malformed` | HIGH | PDU malformada provoca crash |
| `exploits/protocols/iec104/iec104_rogue_master` | HIGH | Mestre IEC 104 não autorizado |
| `exploits/protocols/iec104/iec104_testfr_flood` | MEDIUM | TESTFR Flood — keepalive flood |

---

## Scanners

### Todos os 31 Módulos Scanner

| # | Caminho do Módulo | Protocolo | Impacto | Descrição |
|---|-------------------|-----------|---------|-----------|
| 1 | `scanners/ics/modbus_detect` | Modbus TCP | READ | Detecção de dispositivo Modbus |
| 2 | `scanners/ics/s7_enumerate` | S7comm | READ | Enumeração S7 CPU info |
| 3 | `scanners/ics/enip_list_identity` | EtherNet/IP | READ | EtherNet/IP List Identity |
| 4 | `scanners/ics/bacnet_device_id` | BACnet/IP | READ | BACnet Device ID e vendor |
| 5 | `scanners/ics/dnp3_link_status` | DNP3 | READ | DNP3 Link Status request |
| 6 | `scanners/ics/opcua_endpoints` | OPC UA | READ | Enumeração de endpoints OPC UA |
| 7 | `scanners/ics/profinet_dcp_identify` | PROFINET | READ | PROFINET DCP Device Identification |
| 8 | `scanners/ics/iec104_connect` | IEC 104 | READ | Teste de conexão IEC 104 |
| 9 | `scanners/ics/iec61850_mms_info` | IEC 61850 | READ | IEC 61850 MMS Information |
| 10 | `scanners/ics/altus_nexto_discover` | Modbus | READ | Descoberta Altus Nexto |
| 11 | `scanners/ics/ge_srtp_identify` | GE SRTP | READ | GE PACSystems SRTP info |
| 12 | `scanners/ics/melsec_identify` | MELSEC | READ | Mitsubishi MELSEC identify |
| 13 | `scanners/ics/omron_fins_info` | FINS | READ | Omron FINS CPU info |
| 14 | `scanners/ics/umas_register_read` | UMAS | READ | Schneider UMAS register read |
| 15 | `scanners/ics/hart_ip_identify` | HART-IP | READ | HART-IP device identification |
| 16 | `scanners/ics/cip_identity` | CIP | READ | CIP (Common Industrial Protocol) identity |
| 17 | `scanners/ics/ethercat_scan` | EtherCAT | READ | EtherCAT device discovery |
| 18 | `scanners/ics/modbus_unit_id_enum` | Modbus | READ | Enumeração de unit IDs Modbus |
| 19 | `scanners/ics/s7_protection_level` | S7comm | READ | Verificação de nível de proteção S7 |
| 20 | `scanners/ics/enip_get_attributes` | EtherNet/IP | READ | CIP Get_Attribute_Single scan |
| 21 | `scanners/osint/shodan_ics_dork` | OSINT | INFO | Shodan dorks para ICS/SCADA |
| 22 | `scanners/osint/censys_ics_hunt` | OSINT | INFO | Censys ICS device search |
| 23 | `scanners/osint/elitewolf_signatures` | OSINT | INFO | NSA ELITEWOLF ICS signatures |
| 24 | `scanners/osint/ot_cvss_feed` | OSINT | INFO | OT CVE feed e triagem |
| 25 | `scanners/ics/iec60870_scan` | IEC 870 | READ | IEC 60870-5-101/104 scan |
| 26 | `scanners/ics/codesys_v3_identify` | CODESYS | READ | CODESYS V3 runtime discovery |
| 27 | `scanners/ics/wincc_identify` | WinCC | READ | Siemens WinCC identification |
| 28 | `scanners/ics/ignition_gateway_info` | HTTP | READ | Ignition Gateway version info |
| 29 | `scanners/ics/kepserverex_identify` | OPC DA | READ | KEPServerEX identification |
| 30 | `scanners/ics/wonderware_identify` | Suitelink | READ | Wonderware InTouch identification |
| 31 | `scanners/ics/factorytalk_identify` | EtherNet/IP | READ | Rockwell FactoryTalk identification |

---

## Creds

### Todos os 34 Módulos de Credenciais

| # | Caminho do Módulo | Vendor | Protocolo | Impacto | Credenciais Testadas |
|---|-------------------|--------|-----------|---------|---------------------|
| 1 | `creds/siemens/s7_default_creds` | Siemens | S7comm | HIGH | Default S7 passwords |
| 2 | `creds/siemens/ssh_default_creds` | Siemens | SSH | HIGH | Siemens SSH defaults |
| 3 | `creds/siemens/telnet_default_creds` | Siemens | Telnet | HIGH | Siemens Telnet defaults |
| 4 | `creds/siemens/wincc_default_creds` | Siemens | HTTP | HIGH | WinCC Web Navigator |
| 5 | `creds/rockwell/logix_default_creds` | Rockwell | EtherNet/IP | HIGH | ControlLogix defaults |
| 6 | `creds/rockwell/factorytalk_default_creds` | Rockwell | HTTP | HIGH | FactoryTalk View SE |
| 7 | `creds/schneider/modicon_default_creds` | Schneider | Modbus | HIGH | Modicon defaults |
| 8 | `creds/schneider/ecostruxure_default_creds` | Schneider | HTTP | HIGH | EcoStruxure Expert |
| 9 | `creds/ge/ge_rx3i_default_creds` | GE | SRTP | HIGH | PACSystems RX3i defaults |
| 10 | `creds/ge/cimplicity_default_creds` | GE | HTTP | HIGH | GE Cimplicity |
| 11 | `creds/mitsubishi/melsec_default_creds` | Mitsubishi | MELSEC | HIGH | MELSEC default creds |
| 12 | `creds/abb/abb_800xa_default_creds` | ABB | HTTP | HIGH | 800xA DCS defaults |
| 13 | `creds/honeywell/experion_default_creds` | Honeywell | HTTP | HIGH | Experion PKS defaults |
| 14 | `creds/omron/sysmac_default_creds` | Omron | HTTP | HIGH | Sysmac Studio defaults |
| 15 | `creds/unitronics/unistream_default_creds` | Unitronics | HTTP | HIGH | UniStream defaults |
| 16 | `creds/inductive/ignition_default_creds` | Inductive | HTTP | HIGH | Ignition Gateway defaults |
| 17 | `creds/phoenix/plcnext_default_creds` | Phoenix | HTTP | HIGH | PLCnext defaults |
| 18 | `creds/beckhoff/twincat_default_creds` | Beckhoff | ADS | HIGH | TwinCAT defaults |
| 19 | `creds/yokogawa/centum_default_creds` | Yokogawa | HTTP | HIGH | CENTUM VP defaults |
| 20 | `creds/generic/modbus_coil_write_test` | Genérico | Modbus | LOW | Teste de escrita write-access |
| 21 | `creds/generic/http_basic_auth_brute` | Genérico | HTTP | HIGH | Brute-force HTTP Basic Auth |
| 22 | `creds/generic/snmp_community_brute` | Genérico | SNMP | MEDIUM | SNMP community strings padrão |
| 23 | `creds/generic/ssh_ics_default_creds` | Genérico | SSH | HIGH | SSH ICS device defaults |
| 24 | `creds/generic/telnet_ics_default_creds` | Genérico | Telnet | HIGH | Telnet ICS device defaults |
| 25 | `creds/emerson/roc800_default_creds` | Emerson | ROC | HIGH | ROC800 RTU defaults |
| 26 | `creds/emerson/deltav_default_creds` | Emerson | HTTP | HIGH | DeltaV DCS defaults |
| 27 | `creds/kepware/kepserver_default_creds` | Kepware | HTTP | HIGH | KEPServerEX defaults |
| 28 | `creds/wonderware/intouch_default_creds` | Wonderware | HTTP | HIGH | InTouch HMI defaults |
| 29 | `creds/moxa/iologik_default_creds` | Moxa | HTTP | HIGH | IOLogik RTU defaults |
| 30 | `creds/advantech/adam_default_creds` | Advantech | HTTP | HIGH | ADAM RTU defaults |
| 31 | `creds/delta/dvp_default_creds` | Delta | Modbus | HIGH | DVP PLC defaults |
| 32 | `creds/altus/nexto_default_creds` | Altus | HTTP | HIGH | Nexto PLC defaults |
| 33 | `creds/weg/weg_drive_default_creds` | WEG | Modbus | MEDIUM | WEG drive defaults |
| 34 | `creds/codesys/codesys_v3_default_creds` | CODESYS | ADS | HIGH | CODESYS V3 runtime defaults |

---

## Assessment

### Todos os 18 Módulos de Assessment

| # | Caminho do Módulo | Framework | Impacto | Tipo |
|---|-------------------|-----------|---------|------|
| 1 | `assessment/iec62443/zone_conduit_audit` | IEC 62443-3-2 | INFO | Auditoria de zona/conduto |
| 2 | `assessment/iec62443/sl_gap_analysis` | IEC 62443-2-1 | INFO | Análise de gap de SL |
| 3 | `assessment/iec62443/patch_management_check` | IEC 62443-2-3 | INFO | Patch management |
| 4 | `assessment/nist_sp800_82/control_checklist` | NIST SP 800-82r3 | INFO | Checklist de controles |
| 5 | `assessment/nist_sp800_82/network_segmentation` | NIST SP 800-82r3 | INFO | Segmentação de rede |
| 6 | `assessment/risk/ics_risk_scorer` | Proprietário IXF | INFO | Score de risco quantitativo |
| 7 | `assessment/risk/cvss_ot_adapter` | CVSS v3.1/v4.0 | INFO | CVSS adaptado para OT |
| 8 | `assessment/threat_intel/ics_kill_chain` | Dragos/SANS ICS | INFO | ICS Kill Chain |
| 9 | `assessment/ir/iacs_ir_playbook` | IEC 62443 / NIST 800-61 | INFO | Playbook de IR |
| 10 | `assessment/sast/plc_code_llm_review` | IXF/LLM | INFO | Revisão SAST com LLM |
| 11 | `assessment/sast/iec61131_lint` | IEC 61131-3 | INFO | Lint de código PLC |
| 12 | `assessment/mitre_ics/coverage_report` | MITRE ATT&CK ICS | INFO | Relatório de cobertura |
| 13 | `assessment/mitre_ics/full_mitre_sweep` | MITRE ATT&CK ICS | READ | Varredura MITRE completa |
| 14 | `assessment/mitre_ics/t0801_monitor_process_state` | T0801 | READ | Monitor de processo |
| 15 | `assessment/mitre_ics/t0836_modify_parameter` | T0836 | MEDIUM | Modificação de parâmetro |
| 16 | `assessment/mitre_ics/t0843_program_upload` | T0843 | CRITICAL | Upload de programa PLC |
| 17 | `assessment/mitre_ics/t0878_alarm_suppression` | T0878 | MEDIUM | Supressão de alarme |
| 18 | `assessment/mitre_ics/t0848_rogue_master` | T0848 | HIGH | Mestre Modbus desonesto |

---

## Malware TTP

### Todos os 26 Módulos de Malware TTP

| # | Caminho do Módulo | Ator Histórico | Ano | Impacto | Técnicas MITRE |
|---|-------------------|---------------|-----|---------|----------------|
| 1 | `cve/malware/crashoverride_industroyer` | Sandworm/GRU | 2016 | CATASTROPHIC | T0843, T0855, T0816 |
| 2 | `cve/malware/frostygoop_modbus_heating` | Sandworm/GRU | 2024 | CATASTROPHIC | T0836, T0814 |
| 3 | `cve/malware/pipedream_iocontrol` | CHERNOVITE | 2022 | CATASTROPHIC | T0843, T0855, T0836 |
| 4 | `cve/malware/blackenergy_datalogger` | Sandworm | 2015 | HIGH | T0802, T0882 |
| 5 | `cve/malware/triton_triconex_safety` | XENOTIME | 2017 | CATASTROPHIC | T0857, T0816, T0829 |
| 6 | `cve/malware/industroyer2` | Sandworm/GRU | 2022 | CATASTROPHIC | T0843, T0816 |
| 7 | `cve/malware/incontroller_codesys` | CHERNOVITE | 2022 | CRITICAL | T0843, T0836 |
| 8 | `cve/malware/incontroller_omron` | CHERNOVITE | 2022 | CRITICAL | T0843, T0855 |
| 9 | `cve/malware/cosmicenergy_iec104` | Unknown/GRU? | 2023 | CATASTROPHIC | T0843, T0816, T0855 |
| 10 | `cve/malware/havex_rat_opcda` | Energetic Bear | 2014 | HIGH | T0811, T0802 |
| 11 | `cve/malware/stuxnet_siemens_worm` | NSA/UNIT 8200 | 2010 | CATASTROPHIC | T0838, T0873 |
| 12 | `cve/malware/crashoverride_iec104` | Sandworm/GRU | 2016 | CATASTROPHIC | T0855, T0843 |
| 13 | `cve/malware/plc_logic_bomb_timer` | Genérico | N/A | HIGH | T0838, T0836 |
| 14 | `cve/malware/plc_logic_bomb_counter` | Genérico | N/A | HIGH | T0838, T0836 |
| 15 | `cve/malware/plc_logic_bomb_condition` | Genérico | N/A | HIGH | T0838, T0836 |
| 16 | `cve/malware/modbus_coil_bomb` | Genérico | N/A | HIGH | T0836, T0813 |
| 17 | `cve/malware/s7_logic_overwrite` | Siemens-based | N/A | CRITICAL | T0843, T0845 |
| 18 | `cve/malware/enip_cip_forward_open_flood` | Genérico | N/A | HIGH | T0814 |
| 19 | `cve/malware/dnp3_replay_attack` | Genérico | N/A | HIGH | T0855, T0836 |
| 20 | `cve/malware/iec104_rogue_master` | Genérico | N/A | HIGH | T0848, T0836 |
| 21 | `cve/malware/opcua_node_overwrite` | Genérico | N/A | MEDIUM | T0836 |
| 22 | `cve/malware/profinet_dcp_name_change` | Genérico | N/A | HIGH | T0814 |
| 23 | `cve/malware/bacnet_rpm_spoof` | Genérico | N/A | MEDIUM | T0856 |
| 24 | `cve/malware/wirelesshart_packet_inject` | Genérico | N/A | HIGH | T0862 |
| 25 | `cve/apt/sandworm_industroyer_iec104` | Sandworm/GRU | 2016 | CATASTROPHIC | T0843, T0856 |
| 26 | `cve/apt/lazarus_ecipekac_plc` | Lazarus Group | 2020 | CRITICAL | T0843, T0851 |

---

## Estatísticas

### Visão Geral

```
ixf > stats
[i] IndustrialXPL-Forge v1.0.13 — Estatísticas Completas

  ═══════════════════════════════════════════════════════════════
  Total de módulos: 976
  ═══════════════════════════════════════════════════════════════

  Por Categoria:
  ─────────────────────────────────────────────────────────────
  CVE (vendor-específicos)        486   49.8%
  Exploits de protocolo           159   16.3%
  Malware TTP                      26    2.7%
  Credenciais padrão               34    3.5%
  Scanners / Discovery             31    3.2%
  Assessment / Conformidade        18    1.8%
  Outros / Auxiliares             222   22.7%
  ─────────────────────────────────────────────────────────────

  Por Nível de Impacto:
  ─────────────────────────────────────────────────────────────
  CATASTROPHIC                     18    1.8%
  CRITICAL                        312   32.0%
  HIGH                            289   29.6%
  MEDIUM                          198   20.3%
  LOW                              47    4.8%
  READ                             67    6.9%
  INFO                             45    4.6%
  ─────────────────────────────────────────────────────────────

  Cobertura:
  ─────────────────────────────────────────────────────────────
  Vendors cobertos:               150
  Protocolos cobertos:             50
  CVEs únicos cobertos:           486
  MITRE ATT&CK ICS: 12 táticas / 74 técnicas (82%)
  Malware ICS histórico simulado:  26
  ─────────────────────────────────────────────────────────────

  Top 5 vendors por número de módulos:
  1. Schneider Electric            39
  2. Rockwell Automation           38
  3. Siemens                       27
  4. GE Digital / Emerson          24
  5. Honeywell Process Solutions   21
  ─────────────────────────────────────────────────────────────
```

---

*Anterior: [Assessment e Conformidade](12-assessment-conformidade.md) | Próximo: [Scripts NSE](14-scripts-nse.md)*
