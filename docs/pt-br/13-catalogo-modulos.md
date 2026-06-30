# Catálogo Completo de Módulos

Este documento é o catálogo de referência completo de todos os módulos do IXF organizados por categoria. Use-o para descobrir módulos disponíveis, entender o escopo de cobertura e planejar assessments.

---

## Sumário

1. [Introdução e Como Usar](#introdução-e-como-usar)
2. [Módulos CVE por Vendor](#módulos-cve-por-vendor)
3. [Módulos de Protocolo](#módulos-de-protocolo)
4. [Scanners](#scanners)
5. [Credentials (Creds)](#credentials-creds)
6. [Assessment](#assessment)
7. [Malware TTP](#malware-ttp)
8. [Scripts NSE](#scripts-nse)
9. [Estatísticas Completas](#estatísticas-completas)

---

## Introdução e Como Usar

### Navegando o Catálogo

```bash
# Listar todos os módulos
ixf list

# Buscar por keyword
ixf search <termo>

# Buscar por vendor
ixf vendors <vendor>

# Ver módulos de uma categoria
ixf search cve/siemens
ixf search exploits/protocols
ixf search assessment
ixf search cve/malware

# Ver informações de módulo específico
ixf use <caminho> info

# Carregar e executar em modo simulate
ixf use <caminho> set target <ip> run
```

### Convenções de Caminho

```
Formato slash (shell):   cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
Formato dot (Python):    cve.siemens.cve_2021_22681_s7_1200_hardcoded_key

Categorias:
  cve/<vendor>/         → CVEs específicos de vendor
  cve/malware/          → TTPs de malware ICS
  cve/apt/              → TTPs de grupos APT
  exploits/protocols/   → Abusos de protocolo ICS
  exploits/plc/         → Exploits específicos de PLC
  exploits/scada/       → Exploits SCADA/HMI
  scanners/ics/         → Scanners de protocolo ICS
  scanners/network/     → Scanners de rede
  scanners/osint/       → Ferramentas OSINT
  creds/<vendor>/       → Testes de credenciais por vendor
  creds/generic/        → Testes de credenciais genéricos
  assessment/           → Módulos de assessment e conformidade
```

---

## Módulos CVE por Vendor

### Siemens (27 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key` | CVE-2021-22681 | 10.0 | S7-1200/1500 | CRITICAL |
| `cve/siemens/cve_2019_13945_scalance_x_rce` | CVE-2019-13945 | 9.8 | SCALANCE X | CRITICAL |
| `cve/siemens/cve_2021_31894_s7_1500_rce` | CVE-2021-31894 | 9.8 | S7-1500 | CRITICAL |
| `cve/siemens/cve_2022_43767_wincc_path_traversal` | CVE-2022-43767 | 7.5 | WinCC OA | HIGH |
| `cve/siemens/cve_2019_13945_simatic_dos` | CVE-2019-13945 | 7.5 | SIMATIC | HIGH |
| `cve/siemens/cve_2022_38465_simatic_privesc` | CVE-2022-38465 | 7.8 | SIMATIC | HIGH |
| `cve/siemens/cve_2019_10929_s7_replay_writedb` | CVE-2019-10929 | 6.5 | S7-300/400 | MEDIUM |
| `cve/siemens/cve_2020_7581_pcs7_path_traversal` | CVE-2020-7581 | 7.5 | PCS 7 | HIGH |
| `cve/siemens/cve_2020_15782_s7_1500_rce` | CVE-2020-15782 | 9.1 | S7-1500 | CRITICAL |
| `cve/siemens/cve_2021_22771_s7_auth_bypass` | CVE-2021-22771 | 9.8 | S7-1200 | CRITICAL |
| `cve/siemens/cve_2022_29877_scalance_csrf` | CVE-2022-29877 | 8.8 | SCALANCE | HIGH |
| `cve/siemens/cve_2021_40365_sinema_rce` | CVE-2021-40365 | 9.8 | SINEMA RC | CRITICAL |
| `cve/siemens/cve_2020_26869_desigo_cc_rce` | CVE-2020-26869 | 9.8 | Desigo CC | CRITICAL |
| `cve/siemens/cve_2022_43518_logo_dos` | CVE-2022-43518 | 7.5 | SIMATIC LOGO! | HIGH |
| `cve/siemens/cve_2021_27382_scalance_fw_dos` | CVE-2021-27382 | 7.5 | SCALANCE W | HIGH |
| ... (12 módulos adicionais) | | | | |

### Schneider Electric (39 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/schneider/cve_2022_37300_modicon_m340_rce` | CVE-2022-37300 | 9.8 | Modicon M340 | CRITICAL |
| `cve/schneider/cve_2021_22763_ecostruxure_auth_bypass` | CVE-2021-22763 | 9.1 | EcoStruxure | CRITICAL |
| `cve/schneider/cve_2018_7789_modicon_rce` | CVE-2018-7789 | 9.8 | Modicon M221 | CATASTROPHIC |
| `cve/schneider/cve_2018_7847_modicon_quantum_exec` | CVE-2018-7847 | 10.0 | Modicon Quantum | CATASTROPHIC |
| `cve/schneider/cve_2019_6857_modicon_restart` | CVE-2019-6857 | 7.5 | Modicon M340 | HIGH |
| `cve/schneider/cve_2020_28212_modbus_ftp_dos` | CVE-2020-28212 | 9.8 | Modicon M340 | CRITICAL |
| `cve/schneider/cve_2021_22710_proface_rce` | CVE-2021-22710 | 9.8 | Pro-face GP | CRITICAL |
| `cve/schneider/cve_2022_30269_ecostruxure_path` | CVE-2022-30269 | 7.5 | EcoStruxure Expert | HIGH |
| `cve/schneider/cve_2021_22722_web_server_xss` | CVE-2021-22722 | 6.1 | BMX NOR | MEDIUM |
| `cve/schneider/cve_2020_7523_lacroix_firmware` | CVE-2020-7523 | 9.8 | LACROIX | CRITICAL |
| ... (29 módulos adicionais) | | | | |

### Rockwell Automation (38 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/rockwell/cve_2022_1159_logix5000_heap_overflow` | CVE-2022-1159 | 9.8 | ControlLogix | CRITICAL |
| `cve/rockwell/cve_2022_1161_controllogix_modified_fw` | CVE-2022-1161 | 10.0 | ControlLogix | CATASTROPHIC |
| `cve/rockwell/cve_2021_27478_factorytalk_rce` | CVE-2021-27478 | 10.0 | FactoryTalk | CRITICAL |
| `cve/rockwell/cve_2021_27478_logix_hardcoded` | CVE-2021-27478 | 10.0 | Logix | CRITICAL |
| `cve/rockwell/cve_2020_12025_factorytalk_dos` | CVE-2020-12025 | 7.5 | FactoryTalk | HIGH |
| `cve/rockwell/cve_2020_12033_studioview_rce` | CVE-2020-12033 | 9.8 | Studio 5000 | CRITICAL |
| `cve/rockwell/cve_2022_3156_arena_sim_rce` | CVE-2022-3156 | 7.8 | Arena Simulation | HIGH |
| `cve/rockwell/cve_2021_27492_powerflex_dos` | CVE-2021-27492 | 7.5 | PowerFlex 520 | HIGH |
| `cve/rockwell/cve_2022_3157_compact_logix_dos` | CVE-2022-3157 | 7.5 | CompactLogix | HIGH |
| ... (29 módulos adicionais) | | | | |

### Honeywell (20 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/honeywell/cve_2021_37740_experion_dos` | CVE-2021-37740 | 9.1 | Experion PKS | HIGH |
| `cve/honeywell/cve_2021_38153_experion_pks_rce` | CVE-2021-38153 | 9.8 | Experion PKS | CRITICAL |
| `cve/honeywell/cve_2021_38155_experion_alarm_bypass` | CVE-2021-38155 | 7.4 | Experion PKS | HIGH |
| `cve/honeywell/cve_2022_30316_enraf_dos` | CVE-2022-30316 | 9.1 | Enraf 854 | HIGH |
| `cve/honeywell/cve_2021_38156_spyder_rce` | CVE-2021-38156 | 9.8 | Spyder BAS | CRITICAL |
| ... (15 módulos adicionais) | | | | |

### ABB (22 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/abb/cve_2019_7232_pb610_hardcoded` | CVE-2019-7232 | 9.8 | PB610 Panel Builder | CRITICAL |
| `cve/abb/cve_2020_8474_symphony_rce` | CVE-2020-8474 | 9.8 | Symphony Plus | CRITICAL |
| `cve/abb/cve_2021_22282_symphony_xss` | CVE-2021-22282 | 6.1 | Symphony Plus | MEDIUM |
| `cve/abb/cve_2022_0842_ac500_dos` | CVE-2022-0842 | 7.5 | AC500 PLC | HIGH |
| ... (18 módulos adicionais) | | | | |

### GE / GE Vernova (18 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/ge/cve_2018_10952_cimplicity_rce` | CVE-2018-10952 | 9.8 | CIMPLICITY | CRITICAL |
| `cve/ge/cve_2022_29951_opshub_ssrf` | CVE-2022-29951 | 7.5 | OpsHub | HIGH |
| `cve/ge/cve_2021_27454_rx3i_program_download` | CVE-2021-27454 | 9.8 | PACSystems RX3i | CRITICAL |
| `cve/ge/cve_2020_25183_cimplicity_dos` | CVE-2020-25183 | 7.5 | CIMPLICITY | HIGH |
| ... (14 módulos adicionais) | | | | |

### Emerson (16 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/emerson/cve_2022_29965_roc800_hardcoded` | CVE-2022-29965 | 9.8 | ROC800 | CRITICAL |
| `cve/emerson/cve_2021_38457_deltav_rce` | CVE-2021-38457 | 9.8 | DeltaV | CRITICAL |
| `cve/emerson/cve_2022_30263_openenterprise_rce` | CVE-2022-30263 | 9.8 | OpenEnterprise | CRITICAL |
| ... (13 módulos adicionais) | | | | |

### AVEVA / OSIsoft (14 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/aveva/cve_2021_33544_intouch_rce` | CVE-2021-33544 | 9.8 | InTouch HMI | CRITICAL |
| `cve/aveva/cve_2021_42536_system_platform_rce` | CVE-2021-42536 | 9.8 | System Platform | CRITICAL |
| `cve/aveva/cve_2022_23854_pi_server_dos` | CVE-2022-23854 | 7.5 | PI Server | HIGH |
| `cve/aveva/cve_2021_33544_wonderware_rce` | CVE-2021-33544 | 9.8 | Wonderware | CRITICAL |
| ... (10 módulos adicionais) | | | | |

### Moxa (10 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/moxa/cve_2020_25159_mgmt_auth_bypass` | CVE-2020-25159 | 9.8 | NPort IA5000A | CRITICAL |
| `cve/moxa/cve_2021_40223_nport_dos` | CVE-2021-40223 | 7.5 | NPort 5110 | HIGH |
| `cve/moxa/cve_2022_3082_mxview_rce` | CVE-2022-3082 | 9.8 | MXView One | CRITICAL |
| ... (7 módulos adicionais) | | | | |

### Delta Electronics (11 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/delta/cve_2022_1426_diaenergie_sqli` | CVE-2022-1426 | 9.8 | DIAEnergie | CRITICAL |
| `cve/delta/cve_2022_26009_diascreen_rce` | CVE-2022-26009 | 9.8 | DIAScreen | CRITICAL |
| `cve/delta/cve_2021_26279_dvpsoft_dos` | CVE-2021-26279 | 7.5 | DVPSoft | HIGH |
| ... (8 módulos adicionais) | | | | |

### Omron (12 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/omron/cve_2022_31206_fins_overflow` | CVE-2022-31206 | 9.8 | FINS protocol | CRITICAL |
| `cve/omron/cve_2022_34151_sysmac_studio_rce` | CVE-2022-34151 | 9.8 | Sysmac Studio | CRITICAL |
| `cve/omron/cve_2021_33018_cj2_fins_auth_bypass` | CVE-2021-33018 | 9.1 | CJ2M | HIGH |
| ... (9 módulos adicionais) | | | | |

### Inductive Automation / Ignition (5 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/ignition/cve_2023_39476_ignition_rce` | CVE-2023-39476 | 9.8 | Ignition SCADA | CRITICAL |
| `cve/ignition/cve_2022_36940_ignition_gateway_rce` | CVE-2022-36940 | 9.8 | Ignition Gateway | CRITICAL |
| `cve/ignition/cve_2023_25717_ignition_path_traversal` | CVE-2023-25717 | 7.5 | Ignition 8.1.x | HIGH |
| ... (2 módulos adicionais) | | | | |

### Tridium Niagara (5 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/tridium/cve_2021_33016_niagara_auth_bypass` | CVE-2021-33016 | 9.1 | Niagara 4 | CRITICAL |
| `cve/tridium/cve_2022_23850_niagara_path_traversal` | CVE-2022-23850 | 7.5 | Niagara 4.9 | HIGH |
| ... (3 módulos adicionais) | | | | |

### Yokogawa (5 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/yokogawa/cve_2020_5523_centum_program_download` | CVE-2020-5523 | 9.8 | CENTUM VP | CRITICAL |
| `cve/yokogawa/cve_2021_32988_stardom_dos` | CVE-2021-32988 | 7.5 | STARDOM | HIGH |
| ... (3 módulos adicionais) | | | | |

### Advantech (15 módulos)

| Módulo | CVE | CVSS | Produto | Impacto |
|--------|-----|------|---------|---------|
| `cve/advantech/cve_2021_21801_webaccess_rce` | CVE-2021-21801 | 9.8 | WebAccess | CRITICAL |
| `cve/advantech/cve_2022_3398_iview_sql` | CVE-2022-3398 | 9.8 | iView | CRITICAL |
| `cve/advantech/cve_2021_32957_webaccess_xss` | CVE-2021-32957 | 6.1 | WebAccess | MEDIUM |
| ... (12 módulos adicionais) | | | | |

### Outros Vendors (CVEs variados)

| Vendor | Módulos | CVEs Principais |
|--------|---------|-----------------|
| Beckhoff | 5 | CVE-2019-5637 (TwinCAT), CVE-2022-1467 (ADS) |
| Phoenix Contact | 6 | CVE-2021-21001 (PLCnext), CVE-2022-45138 |
| WAGO | 2 | CVE-2022-45138 (PFC200), CVE-2019-12550 |
| Unitronics | 4 | CVE-2023-6448 (Vision), CVE-2021-38443 |
| Mitsubishi | 3 | CVE-2022-40267 (MELSEC), CVE-2023-5274 |
| Weintek | 2 | CVE-2021-27433 (cMT HMI), CVE-2022-2641 |
| Fatek | 2 | CVE-2021-22651 (FBS Series), CVE-2021-22657 |
| Hollysys | 2 | CVE-2018-17874 (MACS-S), CVE-2019-10952 |
| WEG | 2 | CVE-2022-3200 (CFW-11), CVE-2023-1132 |
| Elipse | 2 | CVE-2020-25166 (E3 SCADA), CVE-2021-33021 |
| Smar | 1 | CVE-2021-27419 (ProcessView) |

---

## Módulos de Protocolo

### Modbus TCP/RTU (31 módulos)

| Módulo | Tipo | Impacto | Descrição |
|--------|------|---------|-----------|
| `exploits/protocols/modbus/modbus_fc90_dos` | DoS | HIGH | Função code ilegal para DoS de dispositivo |
| `exploits/protocols/modbus/modbus_fc16_write_registers` | Exploit | MEDIUM | Escrita não autorizada em holding registers (FC16) |
| `exploits/protocols/modbus/modbus_write_coil` | Exploit | MEDIUM | Escrita não autorizada em bobina (FC05) |
| `exploits/protocols/modbus/modbus_replay_attack` | Exploit | HIGH | Replay de pacote Modbus capturado |
| `exploits/protocols/modbus/modbus_flood_dos` | DoS | HIGH | Flood TCP Modbus com alta taxa |
| `exploits/protocols/modbus/modbus_write_alarm_suppression_coil` | Exploit | HIGH | Supressão de alarme via coil Modbus |
| `exploits/protocols/modbus/modbus_write_holding_register` | Exploit | MEDIUM | Escrita em registro único (FC06) |
| `exploits/protocols/modbus/modbus_write_multiple_registers` | Exploit | MEDIUM | Escrita em múltiplos registros (FC16) |
| `exploits/protocols/modbus/modbus_rogue_master` | Exploit | HIGH | Emulação de mestre Modbus rogue |
| `exploits/protocols/modbus/modbus_spoof_response` | Exploit | HIGH | Spoofing de resposta Modbus |
| `exploits/protocols/modbus/modbus_c2_channel` | Exploit | HIGH | Canal C2 encoberto via Modbus |
| ... (20 módulos adicionais) | | | |

### Siemens S7comm / S7comm+ (27 módulos)

| Módulo | Tipo | Impacto | Descrição |
|--------|------|---------|-----------|
| `exploits/protocols/s7comm/s7_cpu_stop_command` | Exploit | HIGH | Comando STOP do CPU S7 |
| `exploits/protocols/s7comm/s7_plc_program_upload_download` | Exploit | CRITICAL | Upload/Download de lógica PLC via S7comm |
| `exploits/protocols/s7comm/s7_write_db_block` | Exploit | MEDIUM | Escrita em bloco de dados S7 |
| `exploits/protocols/s7comm/s7_activate_fw_update` | Exploit | CRITICAL | Ativar modo de atualização de firmware S7 |
| `exploits/protocols/s7comm/s7_program_upload` | Exploit | HIGH | Upload de programa S7 (leitura de lógica) |
| `exploits/protocols/s7comm/s7_szl_enumerate` | Scanner | READ | Enumeração SZL S7 (CPU info, proteção) |
| ... (21 módulos adicionais) | | | |

### EtherNet/IP / CIP (38 módulos)

| Módulo | Tipo | Impacto | Descrição |
|--------|------|---------|-----------|
| `exploits/protocols/enip/enip_list_identity` | Scanner | READ | Identidade de dispositivo EtherNet/IP |
| `exploits/protocols/enip/enip_reset_identity` | Exploit | HIGH | Reset de dispositivo via CIP (Class 1, Service 0x05) |
| `exploits/protocols/enip/enip_write_tag` | Exploit | MEDIUM | Escrita de tag CIP sem autenticação |
| `exploits/protocols/enip/enip_program_download_controllogix` | Exploit | CRITICAL | Download de programa ControlLogix |
| `exploits/protocols/enip/enip_set_attribute_anon` | Exploit | MEDIUM | Set_Attribute_Single sem autenticação |
| ... (33 módulos adicionais) | | | |

### DNP3 (18 módulos)

| Módulo | Tipo | Impacto | Descrição |
|--------|------|---------|-----------|
| `exploits/protocols/dnp3/dnp3_unsolicit_flood` | DoS | HIGH | Flood de resposta não solicitada DNP3 |
| `exploits/protocols/dnp3/dnp3_direct_operate` | Exploit | HIGH | Comando de operação direta DNP3 |
| `exploits/protocols/dnp3/dnp3_warm_restart` | Exploit | HIGH | Warm restart DNP3 |
| `exploits/protocols/dnp3/dnp3_unsolicited_response_disable` | Exploit | HIGH | Desabilitar respostas não solicitadas |
| ... (14 módulos adicionais) | | | |

### IEC 60870-5-104 (14 módulos)

| Módulo | Tipo | Impacto | Descrição |
|--------|------|---------|-----------|
| `exploits/protocols/iec104/iec104_startdt_flood` | DoS | HIGH | Flood STARTDT IEC 104 |
| `exploits/protocols/iec104/iec104_startdt_block` | Exploit | HIGH | Bloquear transmissão de dados via flood |
| `exploits/protocols/iec104/iec104_spontaneous_message_block` | Exploit | HIGH | Bloquear mensagens espontâneas |
| `exploits/protocols/iec104/iec104_gi_flood` | DoS | HIGH | Flood de General Interrogation |
| ... (10 módulos adicionais) | | | |

### IEC 61850 (11 módulos)

| Módulo | Tipo | Impacto | Descrição |
|--------|------|---------|-----------|
| `exploits/protocols/iec61850/iec61850_goose_spoof` | Exploit | CATASTROPHIC | Spoofing de frame GOOSE (trip de relé) |
| `exploits/protocols/iec61850/iec61850_mms_unauthenticated` | Exploit | HIGH | Acesso MMS sem autenticação |
| ... (9 módulos adicionais) | | | |

### OPC UA (22 módulos)

| Módulo | Tipo | Impacto | Descrição |
|--------|------|---------|-----------|
| `exploits/protocols/opcua/opcua_anonymous_browse` | Exploit | READ | Browse anônimo de namespace |
| `exploits/protocols/opcua/opcua_write_value_anon` | Exploit | MEDIUM | Escrita de valor sem autenticação |
| `exploits/protocols/opcua/opcua_alarm_acknowledge_flood` | DoS | HIGH | Flood de acknowledge de alarme |
| ... (19 módulos adicionais) | | | |

### BACnet/IP (12 módulos)

| Módulo | Tipo | Impacto | Descrição |
|--------|------|---------|-----------|
| `exploits/protocols/bacnet/bacnet_who_is_flood` | DoS | HIGH | Flood de Who-Is broadcast |
| `exploits/protocols/bacnet/bacnet_write_property_anon` | Exploit | MEDIUM | Escrita de propriedade sem autenticação |
| `exploits/protocols/bacnet/bacnet_device_communication_control` | Exploit | HIGH | Controle de comunicação de dispositivo |
| ... (9 módulos adicionais) | | | |

---

## Scanners

31 scanners organizados por protocolo/categoria:

| Módulo | Porta | Protocolo | Descrição |
|--------|-------|-----------|-----------|
| `scanners/ics/modbus_detect` | 502 | Modbus TCP | Detecção e fingerprint de dispositivo Modbus |
| `scanners/ics/modbus_range_scanner` | 502 | Modbus TCP | Varredura de intervalo de registros Modbus |
| `scanners/ics/modbus_device_id` | 502 | Modbus TCP | Identificação MEI de dispositivo Modbus |
| `scanners/ics/s7_enumerate` | 102 | S7comm | Enumeração de CPU e firmware Siemens S7 |
| `scanners/ics/s7_comm_scanner` | 102 | S7comm | Descoberta de PLCs Siemens S7 |
| `scanners/ics/enip_scanner` | 44818 | EtherNet/IP | Descoberta de dispositivos EtherNet/IP |
| `scanners/ics/bacnet_discovery` | 47808 | BACnet/IP | Descoberta de dispositivos BACnet |
| `scanners/ics/dnp3_data_link_scan` | 20000 | DNP3 | Descoberta de dispositivos DNP3 |
| `scanners/ics/iec104_scan` | 2404 | IEC 104 | Descoberta de RTUs IEC 60870-5-104 |
| `scanners/ics/opcua_discovery` | 4840 | OPC UA | Descoberta de servidores OPC UA |
| `scanners/ics/opcua_tag_browse` | 4840 | OPC UA | Enumeração de namespace/tags OPC UA |
| `scanners/ics/profinet_dcp_scan` | L2 | PROFINET | Descoberta de dispositivos PROFINET DCP |
| `scanners/ics/omron_fins_scan` | 9600 | FINS | Descoberta de PLCs Omron FINS |
| `scanners/ics/ads_scanner` | 48898 | ADS/AMS | Descoberta de runtimes TwinCAT Beckhoff |
| `scanners/ics/unitronics_pcom_scan` | 20256 | PCOM | Descoberta de PLCs Unitronics |
| `scanners/ics/mqtt_scanner` | 1883 | MQTT | Descoberta de brokers MQTT e tópicos |
| `scanners/ics/io_module_scanner` | Var. | Var. | Descoberta de módulos I/O |
| `scanners/ics/serial_scanner` | Var. | Serial | Enumeração de servidores serial-to-ethernet |
| `scanners/ics/historian_data_read` | Var. | OPC/ODBC | Leitura de dados de historian |
| `scanners/ics/ics_network_mapper` | Var. | Multi | Mapeamento de topologia de rede OT |
| `scanners/ics/ics_protocol_fingerprint` | Var. | Multi | Fingerprint de protocolo ICS multi-protocolo |
| `scanners/ics/passive_banner_grab` | Var. | Multi | Captura passiva de banner |
| `scanners/ics/lldp_collector` | L2 | LLDP | Coletor de informações LLDP |
| `scanners/ics/snmp_topology_walk` | 161 | SNMP | Mapeamento de topologia via SNMP |
| `scanners/network/ot_port_sweep` | Multi | TCP | Varredura de portas OT comuns |
| `scanners/network/wifi_ics_scanner` | 2.4/5G | Wi-Fi | Scanner de redes Wi-Fi ICS |
| `scanners/osint/shodan_ics_dork` | — | OSINT | Dorks Shodan para exposição de ICS |
| `scanners/ics/modbus_scanner` | 502 | Modbus | Scanner de sub-rede Modbus |
| `scanners/ics/vnetip_scan` | 20111 | Vnet/IP | Descoberta de DCS Yokogawa |
| `scanners/ics/cc_link_scan` | 61450 | CC-Link | Descoberta de redes CC-Link |
| `scanners/ics/ads_scanner` | 48898 | ADS | Descoberta de dispositivos Beckhoff ADS |

---

## Credentials (Creds)

34 módulos de credenciais organizados por vendor/protocolo:

| Módulo | Vendor | Protocolo | Porta | Descrição |
|--------|--------|-----------|-------|-----------|
| `creds/siemens/s7_default_creds` | Siemens | S7comm | 102 | Credenciais padrão S7 PLC |
| `creds/siemens/ssh_default_creds` | Siemens | SSH | 22 | SSH padrão SCALANCE/SINEMA |
| `creds/siemens/web_default_creds` | Siemens | HTTP/S | 443 | Interface web Siemens |
| `creds/rockwell/logix_default_creds` | Rockwell | EtherNet/IP | 44818 | ControlLogix padrão |
| `creds/rockwell/factorytalk_default_creds` | Rockwell | HTTP | 80 | FactoryTalk padrão |
| `creds/schneider/web_default_creds` | Schneider | HTTP/S | 443 | Interface web Modicon |
| `creds/schneider/modbus_default_creds` | Schneider | Modbus | 502 | Modbus com auth estendida |
| `creds/honeywell/experion_default_creds` | Honeywell | HTTP | 80 | Experion PKS Station |
| `creds/ge/cimplicity_default_creds` | GE | HTTP | 80 | GE CIMPLICITY HMI |
| `creds/omron/fins_default_creds` | Omron | FINS | 9600 | Omron CJ/NJ FINS |
| `creds/omron/web_default_creds` | Omron | HTTP | 80 | Interface web Omron |
| `creds/yokogawa/centum_default_creds` | Yokogawa | HTTP | 80 | CENTUM VP |
| `creds/aveva/intouch_default_creds` | AVEVA | HTTP | 80 | InTouch HMI |
| `creds/ignition/gateway_default_creds` | Ignition | HTTP | 8088 | Ignition Gateway |
| `creds/tridium/niagara_default_creds` | Tridium | HTTPS | 443 | Niagara 4 Station |
| `creds/beckhoff/ads_default_creds` | Beckhoff | ADS | 48898 | TwinCAT ADS |
| `creds/moxa/web_default_creds` | Moxa | HTTP | 80 | Interface web Moxa NPort |
| `creds/delta/diaenergie_default_creds` | Delta | HTTP | 80 | DIAEnergie portal |
| `creds/unitronics/pcom_default_creds` | Unitronics | PCOM | 20256 | Vision/Unistream |
| `creds/generic/ssh_default_creds` | Generic | SSH | 22 | SSH credenciais comuns |
| `creds/generic/ftp_default_creds` | Generic | FTP | 21 | FTP credenciais comuns |
| `creds/generic/web_default_creds` | Generic | HTTP | 80 | Web credenciais comuns |
| `creds/generic/telnet_default_creds` | Generic | Telnet | 23 | Telnet credenciais comuns |
| `creds/generic/snmp_community_scan` | Generic | SNMP | 161 | Strings de comunidade SNMP |
| `creds/generic/modbus_extended_auth` | Generic | Modbus | 502 | Auth estendida Modbus |
| `creds/generic/opcua_anonymous_test` | Generic | OPC UA | 4840 | Teste de acesso anônimo OPC UA |
| `creds/generic/http_default` | Generic | HTTP | 80 | HTTP credenciais genéricas |
| `creds/generic/vnc_default_creds` | Generic | VNC | 5900 | VNC padrão (HMIs Windows) |
| `creds/generic/rdp_default_creds` | Generic | RDP | 3389 | RDP Windows EWS/SCADA |
| `creds/generic/vpn_default_creds` | Generic | VPN | Var. | VPN credenciais padrão |
| `creds/generic/mqtt_anonymous_test` | Generic | MQTT | 1883 | Broker MQTT anônimo |
| `creds/generic/bacnet_bbmd_default` | Generic | BACnet | 47808 | BACnet BBMD padrão |
| `creds/schneider/proface_default_creds` | Schneider | HTTP | 80 | Pro-face GP-Pro HMI |
| `creds/abb/symphony_default_creds` | ABB | HTTP | 80 | Symphony Plus |

---

## Assessment

18 módulos de assessment principais:

| Módulo | Padrão | Tipo | Impacto | Descrição |
|--------|--------|------|---------|-----------|
| `assessment/iec62443/zone_conduit_audit` | IEC 62443 | Conformidade | INFO | Auditoria de zona e conduto |
| `assessment/nist_sp800_82/control_checklist` | NIST 800-82r3 | Conformidade | INFO | Checklist de controles ICS |
| `assessment/risk/ics_risk_scorer` | Customizado | Risco | INFO | Pontuação de risco ICS |
| `assessment/threat_intel/ics_kill_chain` | Dragos | Ameaça | INFO | Análise de ICS Kill Chain |
| `assessment/ir/iacs_ir_playbook` | CISA/SANS | IR | INFO | Playbook de IR ICS/OT |
| `assessment/network/ics_firewall_audit` | IEC 62443 | Rede | INFO | Auditoria de firewall OT |
| `assessment/network/industrial_network_assessment` | NIST | Rede | INFO | Assessment de rede industrial |
| `assessment/protocols/modbus_security_audit` | CISA | Protocolo | READ | Auditoria Modbus |
| `assessment/protocols/opcua_security_audit` | OPC Foundation | Protocolo | READ | Auditoria OPC UA |
| `assessment/protocols/dnp3_security_audit` | IEC 62351 | Protocolo | READ | Auditoria DNP3 SAv5 |
| `assessment/protocols/iec61850_security_audit` | IEC 62351 | Protocolo | READ | Auditoria IEC 61850 |
| `assessment/sast/plc_code_llm_review` | Customizado | SAST | INFO | Revisão SAST de código PLC |
| `assessment/mitre_ics/coverage_report` | MITRE | MITRE | INFO | Relatório de cobertura MITRE |
| `assessment/mitre_ics/full_mitre_sweep` | MITRE | MITRE | INFO | Varredura completa MITRE |
| `assessment/mitre_ics/t0836_modify_parameter` | MITRE T0836 | MITRE | INFO | Assessment T0836 |
| `assessment/mitre_ics/t0843_program_download` | MITRE T0843 | MITRE | INFO | Assessment T0843 |
| `assessment/mitre_ics/t0878_alarm_suppression` | MITRE T0878 | MITRE | INFO | Assessment T0878 |
| `assessment/mitre_ics/t0812_default_credentials` | MITRE T0812 | MITRE | INFO | Assessment T0812 |

---

## Malware TTP

26 módulos de TTP de malware e APT:

| Módulo | Malware/APT | Ano | Grupo APT | Impacto | Descrição |
|--------|-------------|-----|-----------|---------|-----------|
| `cve/malware/frostygoop_modbus_heating` | FrostyGoop | 2024 | Sandworm/GRU | CATASTROPHIC | Ataque de aquecimento Modbus (Ucrânia) |
| `cve/malware/crashoverride_industroyer` | Industroyer/Crashoverride | 2016 | Sandworm | CATASTROPHIC | Ataque à rede elétrica ucraniana |
| `cve/malware/industroyer2` | Industroyer2 | 2022 | Sandworm | CATASTROPHIC | Variante atualizada Industroyer |
| `cve/malware/pipedream_iocontrol` | PIPEDREAM/INCONTROLLER | 2022 | Desconhecido (Russia-nexus) | CATASTROPHIC | Framework OT modular |
| `cve/malware/cosmicenergy_iec104` | CosmicEnergy | 2023 | Rostelecom-Solar | CATASTROPHIC | Ataque IEC 104 à rede elétrica |
| `cve/malware/killdisk_industroyer` | KillDisk | 2015/2016 | Sandworm | CATASTROPHIC | Wiper MBR + arquivos |
| `cve/malware/notpetya` | NotPetya | 2017 | Sandworm | CATASTROPHIC | Wiper global + propagação SMB |
| `cve/malware/ekans_process_killer` | EKANS/Snake | 2020 | Desconhecido | HIGH | Ransomware que mata processos ICS |
| `cve/malware/blackenergy3_ics` | BlackEnergy3 | 2015 | Sandworm | CATASTROPHIC | Primeiro apagão cibernético documentado |
| `cve/apt/triton_triconex_safety_overwrite` | TRITON/TRISIS | 2017 | TEMP.Veles/Russia | CATASTROPHIC | Ataque ao SIS Schneider Triconex |
| `cve/apt/sandworm_industroyer_iec104` | Industroyer | 2016 | Sandworm | CATASTROPHIC | Módulo IEC 104 do Industroyer |
| `cve/apt/apt33_shamoon_ics` | Shamoon | 2012/2016 | APT33/Iran | CATASTROPHIC | Wiper com componente OT |
| `cve/apt/lazarus_electricfish` | ElectricFish | 2019 | Lazarus/DPRK | HIGH | Tunneling para exfiltração OT |
| `cve/apt/xenotime_triton` | XENOTIME/TRITON | 2017 | TEMP.Veles | CATASTROPHIC | Componente de safety bypass |
| `cve/malware/stuxnet_centrifuge` | Stuxnet | 2010 | Unit 8200/NSA | CATASTROPHIC | Sabotagem de centrífugas Siemens |
| `cve/malware/havex_opcda` | Havex | 2014 | APT28/Dragonfly | HIGH | Coleta de dados OPC DA |
| `cve/malware/blackenergy2_scada` | BlackEnergy2 | 2014 | Sandworm | HIGH | Plugin SCADA BlackEnergy |
| `cve/malware/industroyer_enip` | Industroyer | 2016 | Sandworm | CATASTROPHIC | Módulo EtherNet/IP do Industroyer |
| `cve/malware/industroyer_s7` | Industroyer | 2016 | Sandworm | CATASTROPHIC | Módulo S7comm do Industroyer |
| `cve/malware/industroyer_iec101` | Industroyer | 2016 | Sandworm | CATASTROPHIC | Módulo IEC 101 do Industroyer |
| `cve/malware/chernovite_pipedream` | CHERNOVITE/PIPEDREAM | 2022 | Desconhecido | CATASTROPHIC | Componente CHERNOVITE |
| `cve/malware/incontroller_codesys` | INCONTROLLER | 2022 | Desconhecido | CATASTROPHIC | Exploit Codesys INCONTROLLER |
| `cve/malware/incontroller_omron` | INCONTROLLER | 2022 | Desconhecido | CATASTROPHIC | Exploit Omron INCONTROLLER |
| `cve/malware/modpipe_pos_ics` | ModPipe | 2020 | Desconhecido | HIGH | Backdoor OT/POS |
| `cve/malware/fluxwire_apt_backdoor` | FluxWire | 2021 | APT28 | HIGH | Backdoor ICS FluxWire |
| `cve/malware/dragonfly_energetic_bear` | Dragonfly | 2014/2017 | Energetic Bear/Russia | HIGH | Campanha de reconhecimento ICS |

---

## Scripts NSE

15 scripts NSE para integração com Nmap:

| Script | Protocolo | Porta | Descrição |
|--------|-----------|-------|-----------|
| `scripts/nse/ixf-modbus-info.nse` | Modbus TCP | 502 | Enumeração de dispositivo Modbus via Nmap |
| `scripts/nse/ixf-s7-info.nse` | S7comm | 102 | Enumeração de CPU Siemens S7 via Nmap |
| `scripts/nse/ixf-enip-info.nse` | EtherNet/IP | 44818 | Identificação de dispositivo EtherNet/IP |
| `scripts/nse/ixf-bacnet-info.nse` | BACnet/IP | 47808 | Descoberta de dispositivos BACnet |
| `scripts/nse/ixf-dnp3-info.nse` | DNP3 | 20000 | Detecção de dispositivos DNP3 |
| `scripts/nse/ixf-opcua-info.nse` | OPC UA | 4840 | Enumeração de servidor OPC UA |
| `scripts/nse/ixf-iec104-info.nse` | IEC 104 | 2404 | Detecção de RTUs IEC 60870-5-104 |
| `scripts/nse/ixf-fins-info.nse` | FINS | 9600 | Enumeração de PLCs Omron FINS |

### Instalando Scripts NSE

```bash
# Via IXF
ixf > nse install

# Manualmente
sudo cp industrialxpl/scripts/nse/*.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
```

### Usando Scripts NSE

```bash
# Varredura completa com todos os scripts IXF
nmap -p 502,102,44818,47808,20000,2404,4840,9600 \
  --script ixf-modbus-info,ixf-s7-info,ixf-enip-info,ixf-bacnet-info \
  192.168.1.0/24
```

---

## Estatísticas Completas

```
  IXF — Estatísticas Completas da Base de Módulos v2.1.0
  ════════════════════════════════════════════════════════════════════════

  MÓDULOS POR CATEGORIA:
  ──────────────────────────────────────────────────────────────────────
  CVE (todos os vendors):          421
    Top vendors:
      Schneider Electric:           39
      Rockwell Automation:          38
      Siemens:                      27
      ABB:                          22
      Honeywell:                    20
      GE / GE Vernova:              18
      Emerson:                      16
      Advantech:                    15
      AVEVA / OSIsoft:              14
      Delta Electronics:            11
      Omron:                        12
      Moxa:                         10
      Outros (130+ vendors):       180

  CVE Malware/APT:                  26
    Grupos APT representados:       12
    (Sandworm, APT33, APT28, Lazarus, TEMP.Veles, ...)

  Exploits de Protocolo:           214
    Modbus TCP/RTU:                 31
    EtherNet/IP CIP:                38
    Siemens S7comm/S7+:             27
    IEC 60870-5-104:                14
    OPC UA:                         22
    BACnet/IP:                      12
    DNP3:                           18
    IEC 61850:                      11
    Outros protocolos:              41

  Scanners:                         31
    ICS Protocol:                   24
    Network:                         5
    OSINT:                           2

  Credentials:                      34
    Por vendor específico:          20
    Genéricos:                      14

  Assessment:                       48
    Conformidade (IEC62443/NIST):    8
    MITRE técnicas específicas:     30
    Protocolo-específicos:           6
    Outros:                          4

  Scripts NSE:                       8

  ──────────────────────────────────────────────────────────────────────
  TOTAL GERAL:                     1190+

  COBERTURA MITRE:
  ──────────────────────────────────────────────────────────────────────
  Técnicas MITRE ATT&CK for ICS v19 cobertas:  96/103 (93%)
  Táticas com 100% cobertura:                   4/12
  (Initial Access, Privilege Escalation, Lateral Movement, C2)

  COBERTURA DE PROTOCOLO:
  ──────────────────────────────────────────────────────────────────────
  Protocolos cobertos:              50
  Top 5 por módulo count:
    EtherNet/IP:                    38 módulos
    Modbus:                         31 módulos
    S7comm:                         27 módulos
    OPC UA:                         22 módulos
    DNP3:                           18 módulos

  COBERTURA DE VENDOR:
  ──────────────────────────────────────────────────────────────────────
  Vendors cobertos:                150
  Países representados:             25+
  Regiões:                          Europa, Américas, APAC, Brasil/LATAM

  DISTRIBUIÇÃO POR NÍVEL DE IMPACTO:
  ──────────────────────────────────────────────────────────────────────
  CATASTROPHIC:                     28 módulos
  CRITICAL:                        187 módulos
  HIGH:                            312 módulos
  MEDIUM:                           98 módulos
  LOW:                              12 módulos
  READ:                            198 módulos
  INFO:                            141 módulos
  ════════════════════════════════════════════════════════════════════════
```

---

*Anterior: [Assessment e Conformidade](12-assessment-conformidade.md) | Próximo: [Scripts NSE](14-scripts-nse.md)*

---

## Módulos por Nível de Impacto — Listagem Completa

### Módulos CATASTROPHIC (18 módulos)

Estes módulos podem causar dano físico irreversível a equipamentos, pessoal ou infraestrutura crítica. Requerem contagem regressiva obrigatória de 10 segundos + string de confirmação exata.

| Caminho do Módulo | Descrição | MITRE |
|-------------------|-----------|-------|
| cve/malware/frostygoop_modbus_heating | FrostyGoop — desabilita aquecimento (Ucrânia 2024) | T0836, T0814 |
| cve/malware/crashoverride_industroyer | Industroyer — apagão de energia (Ucrânia 2016) | T0843, T0816 |
| cve/apt/triton_triconex_safety_overwrite | TRITON — sobrescreve SIS Triconex | T0857, T0829 |
| cve/malware/industroyer2 | Industroyer2 (Ucrânia 2022) | T0843, T0816 |
| cve/malware/pipedream_iocontrol | PIPEDREAM/INCONTROLLER framework | T0843, T0836 |
| cve/malware/stuxnet_siemens_worm | Stuxnet — centrífugas Natanz (2010) | T0838, T0873 |
| cve/malware/cosmicenergy_iec104 | CosmicEnergy — IEC 104 payload | T0843, T0816 |
| cve/apt/sandworm_industroyer_iec104 | Sandworm — IEC 104 subestações | T0855, T0843 |
| cve/apt/voodoo_bear_crashoverride | Crashoverride TTP completo | T0855, T0816 |
| cve/honeywell/cve_2021_38395_experion_pks | Experion PKS RCE (CVSS 10.0) | T0819, T0866 |
| cve/schneider/cve_2022_45789_ecostruxure_rce | EcoStruxure RCE | T0819 |
| cve/schneider/cve_2018_7789_modicon_rce | Modicon M340 RCE | T0819, T0866 |
| cve/rockwell/cve_2023_3595_controllogix_rce | ControlLogix RCE | T0819, T0866 |
| cve/ge/cve_2020_35952_ge_cimplicity_path_traversal | Cimplicity Path Traversal RCE | T0819 |
| cve/inductive/cve_2023_39476_ignition_rce | Ignition Gateway RCE | T0819 |
| xploits/protocols/s7comm/s7_stop_cpu | S7comm CPU Stop (impacto de processo) | T0816 |
| cve/apt/lazarus_ecipekac_plc | Lazarus PLC Implant | T0843, T0851 |
| cve/malware/triton_triconex_safety | TRITON SIS overwrite simulation | T0857, T0829 |

### Módulos CRITICAL (312 módulos — amostra)

| Caminho do Módulo | CVE | CVSS | Vendor |
|-------------------|-----|------|--------|
| cve/siemens/cve_2021_22681_s7_1200_hardcoded_key | CVE-2021-22681 | 9.8 | Siemens |
| cve/siemens/cve_2022_38465_s7_global_key | CVE-2022-38465 | 9.3 | Siemens |
| cve/rockwell/cve_2022_1161_controllogix_modified_fw | CVE-2022-1161 | 8.8 | Rockwell |
| cve/rockwell/cve_2022_1159_logix5000_heap_overflow | CVE-2022-1159 | 9.8 | Rockwell |
| cve/schneider/cve_2021_22763_ecostruxure_auth_bypass | CVE-2021-22763 | 9.8 | Schneider |
| cve/ge/cve_2022_29965_roc800_hardcoded_creds | CVE-2022-29965 | 9.8 | GE/Emerson |
| cve/abb/cve_2021_22281_abb_800xa_auth_bypass | CVE-2021-22281 | 9.8 | ABB |
| cve/honeywell/cve_2021_38395_experion_pks | CVE-2021-38395 | 10.0 | Honeywell |
| cve/mitsubishi/cve_2023_47590_melsec_rce | CVE-2023-47590 | 9.8 | Mitsubishi |
| cve/phoenix/cve_2022_36249_plcnext_auth_bypass | CVE-2022-36249 | 9.8 | Phoenix |
| cve/beckhoff/cve_2019_5637_twincat_path | CVE-2019-5637 | 9.8 | Beckhoff |
| cve/unitronics/cve_2023_6448_unistream_rce | CVE-2023-6448 | 9.8 | Unitronics |
| cve/kepware/cve_2022_2848_kepserverex_bof | CVE-2022-2848 | 9.1 | Kepware |
| cve/siemens/cve_2021_40365_simatic_hmi | CVE-2021-40365 | 9.8 | Siemens |
| cve/siemens/cve_2020_15782_wincc_path_traversal | CVE-2020-15782 | 9.1 | Siemens |
| ... (297 módulos adicionais) | | | |

### Módulos HIGH (289 módulos — amostra)

| Caminho do Módulo | CVE | CVSS | Tipo |
|-------------------|-----|------|------|
| xploits/protocols/s7comm/s7_stop_cpu | N/A | N/A | Protocol Abuse |
| xploits/protocols/enip/enip_cip_forward_open_flood | N/A | N/A | DoS |
| xploits/protocols/iec104/iec104_command_inject | N/A | N/A | Protocol Abuse |
| cve/siemens/cve_2019_13945_simatic_s7_dos | CVE-2019-13945 | 7.5 | DoS |
| cve/rockwell/cve_2022_3752_compactlogix_dos | CVE-2022-3752 | 7.5 | DoS |
| cve/ge/cve_2021_40877_pacsystems_rx3i | CVE-2021-40877 | 7.5 | DoS |
| cve/omron/cve_2021_27477_cj2m | CVE-2021-27477 | 7.5 | DoS |
| ... (282 módulos adicionais) | | | |

---

## Módulos por Técnica MITRE — Top 20 Técnicas

### T0819 — Exploit Public-Facing Application (47 módulos)

A técnica mais coberta no IXF. Inclui exploits para interfaces web de SCADA, gateways de acesso remoto e aplicações ICS expostas à internet.

Módulos incluídos:
- xploits/scada/ignition/ignition_rce — Ignition SCADA Gateway RCE
- xploits/scada/wonderware/archestra_dcom_exec — Wonderware ArchestrA
- xploits/scada/ge_cimplicity/cimplicity_path_traversal — GE Cimplicity
- xploits/scada/kepware/kepserverex_buffer_overflow — KEPServerEX
- cve/siemens/cve_2021_37195_sinema_rc — SINEMA Remote Connect
- cve/rockwell/cve_2020_6998_factorytalk — FactoryTalk View SE
- cve/inductive/cve_2023_39476_ignition_rce — Ignition RCE (2023)
- ... (40 módulos adicionais)

### T0812 — Default Credentials (34 módulos)

Cobre teste de credenciais padrão em 34 vendors/produtos ICS. Todos estão na categoria creds/.

### T0836 — Modify Parameter (15 módulos)

Módulos que modificam parâmetros de processo ICS via protocolos sem autenticação.

### T0843 — Program Download (12 módulos)

Download de programas modificados para PLCs. Alta severidade — pode substituir toda a lógica de controle.

---

## Busca Avançada e Filtragem

### Filtrar por CVSS Score

`python
from industrialxpl.core.exploit.utils import index_modules, import_exploit

# Todos os módulos com CVSS >= 9.0
modules = index_modules()
critical = []
for m in modules:
    try:
        cls = import_exploit(f"industrialxpl.modules.{m}")
        obj = cls()
        info = obj.get_info()
        cvss = info.get("cvss", "N/A")
        if cvss != "N/A":
            try:
                if float(cvss) >= 9.0:
                    critical.append({
                        "module": m,
                        "cvss": float(cvss),
                        "name": info.get("name"),
                        "cve": info.get("cve"),
                    })
            except ValueError:
                pass
    except Exception:
        pass

# Ordenar por CVSS decrescente
critical.sort(key=lambda x: x["cvss"], reverse=True)
print(f"Módulos com CVSS >= 9.0: {len(critical)}")
for m in critical[:10]:
    print(f"  [{m['cvss']}] {m['cve']} — {m['name'][:50]}")
`

### Filtrar por Tática MITRE

`python
# Todos os módulos que cobrem "Inhibit Response Function"
inhibit_modules = []
for m in modules:
    try:
        obj = import_exploit(f"industrialxpl.modules.{m}")()
        info = obj.get_info()
        if "Inhibit Response Function" in info.get("mitre_tactics", []):
            inhibit_modules.append(m)
    except Exception:
        pass
print(f"Módulos cobrindo Inhibit Response Function: {len(inhibit_modules)}")
`

### Filtrar por Region/País

`python
# Módulos de vendors brasileiros
brazil_vendors = ["altus", "weg", "elipse", "contemp", "microsat"]
brazil_modules = [m for m in modules if any(v in m for v in brazil_vendors)]
print(f"Módulos de vendors brasileiros: {len(brazil_modules)}")
`

---

## Estatísticas por Ano de CVE

| Período | CVEs | Exemplos Notáveis |
|---------|------|-------------------|
| 2010-2015 | 23 | Stuxnet (2010), HaVeX (2014) |
| 2016-2018 | 41 | Industroyer (2016), CVE-2018-7789 Schneider |
| 2019-2020 | 67 | CVE-2019-13945 Siemens, CVE-2020-15782 WinCC |
| 2021 | 89 | CVE-2021-22681 S7, CVE-2021-38395 Honeywell |
| 2022 | 124 | CVE-2022-1161 Rockwell, CVE-2022-29965 Emerson |
| 2023 | 98 | CVE-2023-3595 ControlLogix, CVE-2023-6448 Unitronics |
| 2024+ | 44 | FrostyGoop (2024), CosmicEnergy |
| N/A (TTPs) | 26 | Malware ICS, técnicas MITRE, módulos de assessment |
| **Total** | **486** | |

---

## Como Contribuir com Novos Módulos

Para adicionar um módulo ao catálogo:

1. Verifique se o CVE ainda não está coberto: ixf > search CVE-AAAA-NNNNN
2. Siga o template em [Desenvolvimento de Módulos](09-desenvolvimento-modulos.md)
3. Coloque o arquivo no diretório correto:
   - industrialxpl/modules/cve/<vendor>/cve_AAAA_NNNNN_<descricao>.py
4. Execute validação:
   `ash
   python -c "from industrialxpl.core.exploit.utils import import_exploit; ..."
   `
5. Abra um PR com o template de contribuição

---

*Este catálogo é gerado automaticamente a partir do índice de módulos do IXF. Para o catálogo mais atualizado, execute ixf > stats na versão instalada.*

*Anterior: [Assessment e Conformidade](12-assessment-conformidade.md) | Próximo: [Scripts NSE](14-scripts-nse.md)*

---

## Módulos CVE Adicionais por Vendor

### Exploits SCADA e HMI

| Módulo | Vendor | CVE | Produto | Impacto |
|--------|--------|-----|---------|---------|
| `exploits/scada/schneider/citect_scada_odbc_rce` | Schneider | CVE-2018-7828 | Citect SCADA | CRITICAL |
| `exploits/scada/ge/cimplicity_web_server_rce` | GE | CVE-2018-10952 | CIMPLICITY | CRITICAL |
| `exploits/scada/ignition/ignition_rce` | Ignition | CVE-2023-39476 | Ignition 8.x | CRITICAL |
| `exploits/hmi/siemens/wincc_path_traversal` | Siemens | CVE-2022-43767 | WinCC OA | HIGH |
| `exploits/hmi/aveva/intouch_code_injection` | AVEVA | CVE-2021-33544 | InTouch | CRITICAL |
| `exploits/hmi/ge/ifix_web_rce` | GE | CVE-2021-27456 | iFIX | CRITICAL |
| `exploits/hmi/rockwell/factorytalk_view_rce` | Rockwell | CVE-2021-27478 | FactoryTalk View | CRITICAL |
| `exploits/hmi/honeywell/hscada_dos` | Honeywell | CVE-2021-37740 | HSCADA | HIGH |
| `exploits/mes/sap/sap_message_server_dos` | SAP | CVE-2020-6207 | SAP MII | HIGH |
| `exploits/mes/aveva/historian_sql_injection` | AVEVA | CVE-2022-23854 | PI Historian | CRITICAL |

### Módulos CVE por Categoria de Vulnerabilidade

**Buffer Overflow / Memory Corruption:**

| Módulo | CVE | Produto Afetado | CVSS |
|--------|-----|-----------------|------|
| `cve/rockwell/cve_2022_1159_logix5000_heap_overflow` | CVE-2022-1159 | ControlLogix 5570 | 9.8 |
| `cve/omron/cve_2022_31206_fins_overflow` | CVE-2022-31206 | FINS Protocol | 9.8 |
| `cve/siemens/cve_2020_15782_s7_1500_rce` | CVE-2020-15782 | S7-1500 V2.5 | 9.1 |
| `cve/delta/cve_2022_1426_diaenergie_sqli` | CVE-2022-1426 | DIAEnergie 1.7 | 9.8 |
| `cve/advantech/cve_2021_21801_webaccess_rce` | CVE-2021-21801 | WebAccess 8.4.5 | 9.8 |

**SQL Injection:**

| Módulo | CVE | Produto Afetado | CVSS |
|--------|-----|-----------------|------|
| `cve/delta/cve_2022_1426_diaenergie_sqli` | CVE-2022-1426 | DIAEnergie | 9.8 |
| `cve/aveva/cve_2021_42537_pi_sqli` | CVE-2021-42537 | PI Vision | 8.8 |
| `cve/ge/cve_2021_27459_cimplicity_sqli` | CVE-2021-27459 | CIMPLICITY | 9.8 |

**Authentication Bypass:**

| Módulo | CVE | Produto Afetado | CVSS |
|--------|-----|-----------------|------|
| `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key` | CVE-2021-22681 | S7-1200/1500 | 10.0 |
| `cve/moxa/cve_2020_25159_mgmt_auth_bypass` | CVE-2020-25159 | NPort IA5000A | 9.8 |
| `cve/schneider/cve_2021_22763_ecostruxure_auth_bypass` | CVE-2021-22763 | EcoStruxure | 9.1 |
| `cve/tridium/cve_2021_33016_niagara_auth_bypass` | CVE-2021-33016 | Niagara 4 | 9.1 |
| `cve/emerson/cve_2022_29965_roc800_hardcoded` | CVE-2022-29965 | ROC800 | 9.8 |

---

## Módulos de Protocolo Adicionais

### Protocolos de Safety (CIP Safety, PROFIsafe, FSoE)

| Módulo | Protocolo | Impacto | Descrição |
|--------|-----------|---------|-----------|
| `exploits/protocols/ethernet_ip_cip_safety/cip_safety_bypass` | CIP Safety | CATASTROPHIC | Bypass de camada de safety CIP |
| `exploits/protocols/profisafe/profisafe_crc_bypass` | PROFIsafe | CATASTROPHIC | Bypass de CRC PROFIsafe |
| `exploits/protocols/fsoe/fsoe_safety_override` | FSoE | CATASTROPHIC | Override de safety FSoE Beckhoff |
| `assessment/protocols/cip_safety_audit` | CIP Safety | INFO | Auditoria de configuração CIP Safety |
| `assessment/protocols/profisafe_audit` | PROFIsafe | INFO | Auditoria de parâmetros PROFIsafe |

### Protocolos de Semiconductor (SECS/GEM)

| Módulo | Protocolo | Porta | Impacto | Descrição |
|--------|-----------|-------|---------|-----------|
| `exploits/protocols/hsms/secs_gem_equipment_control` | SECS/GEM HSMS | 5000 | HIGH | Controle não autorizado de equipamento de fábrica de semicondutores |
| `exploits/protocols/hsms/secs_gem_process_job_abort` | SECS/GEM | 5000 | HIGH | Abortar processo SECS/GEM em fab de semicondutores |
| `scanners/ics/hsms_scanner` | SECS/GEM | 5000 | READ | Descoberta de equipamentos SECS/GEM |

### Protocolos de Automação Predial

| Módulo | Protocolo | Porta | Impacto | Descrição |
|--------|-----------|-------|---------|-----------|
| `exploits/protocols/lonworks/lonworks_node_override` | LonWorks | 1628 | MEDIUM | Override de nó LonWorks |
| `exploits/protocols/knx/knx_group_write` | KNX/EIB | 3671 | MEDIUM | Escrita de grupo KNX sem autenticação |
| `exploits/protocols/knx/knx_restart_broadcast` | KNX | 3671 | HIGH | Restart de dispositivos KNX via broadcast |
| `scanners/ics/knx_scanner` | KNX | 3671 | READ | Descoberta de dispositivos KNX |
| `scanners/ics/lonworks_scanner` | LonWorks | 1628 | READ | Descoberta de nós LonWorks |

---

## Ferramentas OSINT e Inteligência de Ameaças

### Módulos OSINT

| Módulo | Tipo | Descrição |
|--------|------|-----------|
| `scanners/osint/shodan_ics_dork` | OSINT | Dorks Shodan para exposição de ICS pela internet |
| `scanners/osint/censys_ics_search` | OSINT | Busca Censys para sistemas ICS expostos |
| `scanners/osint/zoomeye_ics` | OSINT | Busca ZoomEye para dispositivos ICS |
| `scanners/osint/onyphe_ics` | OSINT | Busca ONYPHE para exposição de protocolo ICS |

**Usando OSINT no IXF:**

```
ixf > use scanners/osint/shodan_ics_dork
ixf (Shodan ICS Dork) > set target schneider
ixf (Shodan ICS Dork) > run

[i] [SIMULATE] Dorks Shodan para Schneider Electric:
    port:502 "Schneider Electric"
    port:102 "Schneider"
    port:44818 "Schneider"
    modbus "Modicon"
    product:"Modicon M340"

[i] Usar: https://www.shodan.io/search?query=port%3A502+%22Schneider%22
[i] Para resultados completos: configure SHODAN_API_KEY no ambiente
[i] MITRE: T0883 (Internet Accessible Device)
```

---

## Módulos de Suporte a Regulamentações Setoriais

### Energia Elétrica (NERC CIP)

| Módulo | Padrão | Descrição |
|--------|--------|-----------|
| `assessment/nerc_cip/cip_002_asset_identification` | NERC CIP-002 | Identificação de ativos BES |
| `assessment/nerc_cip/cip_005_esp_assessment` | NERC CIP-005 | Assessment de Electronic Security Perimeter |
| `assessment/nerc_cip/cip_007_ports_services` | NERC CIP-007 | Verificação de portas e serviços |
| `assessment/nerc_cip/cip_010_config_management` | NERC CIP-010 | Gerenciamento de configuração |

### Petróleo e Gás (ISA/IEC 62443)

| Módulo | Padrão | Descrição |
|--------|--------|-----------|
| `assessment/oil_gas/pipeline_scada_audit` | IEC 62443 | Auditoria SCADA de gasodutos |
| `assessment/oil_gas/rtu_security_baseline` | NIST 800-82 | Baseline de segurança RTU O&G |

### Água e Saneamento (AWW / AWWA)

| Módulo | Padrão | Descrição |
|--------|--------|-----------|
| `assessment/water/awa_water_utility_assessment` | AWWA | Assessment de utilidade de água |
| `assessment/water/chemical_dosing_validation` | Customizado | Validação de controle de dosagem química |

---

## Referências e Recursos Externos

### Bases de Dados CVE / ICS

| Recurso | URL | Descrição |
|---------|-----|-----------|
| NVD NIST | https://nvd.nist.gov/ | National Vulnerability Database |
| CISA ICS-CERT | https://www.cisa.gov/ics | Advisories ICS-CERT |
| ICS-CERT CSAF | https://www.cisa.gov/resources-tools/resources/csaf | Formato CSAF |
| MITRE ATT&CK ICS | https://attack.mitre.org/matrices/ics/ | Framework MITRE |
| Dragos ICS | https://www.dragos.com/resources/ | Inteligência de ameaças OT |

### Padrões Relevantes

| Padrão | Título | Aplicação |
|--------|--------|-----------|
| IEC 62443 | Industrial Automation and Control Systems Security | OT/ICS geral |
| NIST SP 800-82r3 | Guide to ICS Security | ICS geral |
| IEC 61850 | Communication in Substations | Subestações elétricas |
| IEC 60870-5 | Telecontrol Equipment and Systems | RTUs/SCADA |
| ISA/IEC 61511 | Safety Instrumented Systems | SIS/SIL |
| NERC CIP | Critical Infrastructure Protection | Rede elétrica América do Norte |
| AWWA | Cybersecurity Guidance for Water Utilities | Utilidades de água |

---

## Índice de Consulta Rápida

### Por Técnica MITRE

| Técnica MITRE | Módulos Primários IXF |
|--------------|----------------------|
| T0812 | `creds/*/` (34 módulos de credenciais) |
| T0819 | `cve/siemens/`, `cve/schneider/`, `cve/rockwell/` (47 módulos) |
| T0836 | `exploits/protocols/modbus/modbus_fc16_*`, `exploits/protocols/s7comm/s7_write_*` |
| T0843 | `cve/siemens/cve_2021_22681_*`, `exploits/protocols/s7comm/s7_plc_program_*` |
| T0814 | `exploits/protocols/*/flood*`, `exploits/protocols/*/dos*` |
| T0816 | `exploits/protocols/s7comm/s7_cpu_stop*`, `exploits/protocols/enip/enip_reset_*` |
| T0846 | `scanners/ics/*` (todos os 31 scanners) |
| T0878 | `assessment/mitre_ics/t0878_*`, `exploits/protocols/*/alarm_*` |
| T0826 | `cve/malware/frostygoop_*`, `cve/malware/cosmicenergy_*` |
| T0829 | `cve/apt/triton_*`, `cve/malware/pipedream_*` |

### Por Setor Industrial

| Setor | Módulos Mais Relevantes |
|-------|------------------------|
| Energia Elétrica | `exploits/protocols/iec104/`, `exploits/protocols/iec61850/`, `cve/malware/industroyer*`, `cve/malware/crashoverride*` |
| Água e Saneamento | `exploits/protocols/modbus/`, `cve/malware/frostygoop_*`, `cve/unitronics/` |
| Petróleo e Gás | `cve/emerson/`, `cve/honeywell/`, `exploits/protocols/modbus/`, `exploits/protocols/dnp3/` |
| Manufatura | `cve/siemens/`, `cve/rockwell/`, `cve/schneider/`, `exploits/protocols/s7comm/`, `exploits/protocols/enip/` |
| Automação Predial | `exploits/protocols/bacnet/`, `exploits/protocols/knx/`, `exploits/protocols/lonworks/` |
| Semicondutores | `exploits/protocols/hsms/` |
| Químico | `cve/apt/triton_*`, `assessment/mitre_ics/t0836_*` |

---

*Versão: IXF v1.1.1 | Data: 2026-06-01 | Técnicas MITRE: v19*

---

## Modulos por Vendor -- Listagem Expandida

### Vendors Europeus Adicionais

| Vendor | Pais | Modulos | Produto Principal |
|--------|------|---------|------------------|
| Pilz | Alemanha | 2 | PSS 4000, safety controllers |
| SICK AG | Alemanha | 1 | Sensores de seguranca |
| Turck | Alemanha | 1 | Gateways de protocolo |
| Murrelektronik | Alemanha | 1 | Gateways Modbus |
| Lenze | Alemanha | 2 | Inversores de frequencia |
| SEW Eurodrive | Alemanha | 2 | MOVIFIT drives |
| IFM Electronic | Alemanha | 1 | Sensores IO-Link |
| Harting | Alemanha | 1 | Gateways industriais |
| Weidmuller | Alemanha | 1 | Reles de seguranca |
| Eaton RAMO | Republica Tcheca | 1 | PLCs serie EC4P |

### Vendors Asiaticos Adicionais

| Vendor | Pais | Modulos | Produto Principal |
|--------|------|---------|------------------|
| Chint | China | 1 | PLCs e inversores |
| Inovance | China | 1 | AM600 PLCs |
| HOLLYSYS | China | 2 | DCS MACS V |
| LS Electric | Coreia do Sul | 2 | XGK/XGB PLCs |
| Hyundai Robotics | Coreia do Sul | 1 | Controladores de robo |
| Rexroth Bosch | Japao/DE | 2 | IndraControl XM |
| SMC | Japao | 1 | Controladores pneumaticos |
| CKD | Japao | 1 | PLCs selecionados |
| Koyo | Japao/EUA | 2 | DirectLogix, série DL |
| Vigor Electric | Taiwan | 1 | VH Series PLCs |

---

## Consideracoes de Licenca e Uso Etico

### Licenca MIT

O IndustrialXPL-Forge esta licenciado sob a licenca MIT. Isso significa:

- **Permitido**: Uso para pesquisa, testes autorizados, educacao
- **Permitido**: Fork e modificacao do codigo
- **Exigido**: Manutencao do aviso de direitos autorais
- **Proibido**: Uso em sistemas sem autorizacao do proprietario

### Principios Eticos

1. **Consentimento explicito** -- sempre obtenha autorizacao escrita antes de testes
2. **Responsabilidade** -- documente todas as acoes em ambientes de producao
3. **Proporcionalidade** -- use o nivel minimo de acesso necessario
4. **Divulgacao responsavel** -- reporte vulnerabilidades encontradas ao fabricante
5. **Nao causar dano** -- priorize always simulate=True exceto em labs controlados

---

*Fim do Catalogo de Modulos*

*Anterior: [Assessment e Conformidade](12-assessment-conformidade.md) | Proximo: [Scripts NSE](14-scripts-nse.md)*

---

## Modulos Organizados por Protocolo de Comunicacao

### Modulos Modbus (43 modulos total)

| Categoria | Contagem | Exemplos |
|-----------|---------|---------|
| CVE Modbus | 8 | cve/schneider/cve_2018_7789_modicon_rce |
| Exploits Protocolo | 18 | exploits/protocols/modbus/modbus_fc16_write_registers |
| Scanners | 3 | scanners/ics/modbus_detect |
| Creds | 6 | creds/schneider/modicon_default_creds |
| Assessment | 4 | assessment/mitre_ics/t0836_modify_parameter |
| Malware TTP | 4 | cve/malware/frostygoop_modbus_heating |

### Modulos S7comm (27 modulos total)

| Categoria | Contagem | Exemplos |
|-----------|---------|---------|
| CVE Siemens S7 | 15 | cve/siemens/cve_2021_22681_s7_1200_hardcoded_key |
| Exploits Protocolo | 8 | exploits/protocols/s7comm/s7_stop_cpu |
| Scanners | 2 | scanners/ics/s7_enumerate |
| Creds | 2 | creds/siemens/s7_default_creds |

### Modulos EtherNet/IP (38 modulos total)

| Categoria | Contagem | Exemplos |
|-----------|---------|---------|
| CVE Rockwell | 24 | cve/rockwell/cve_2023_3595_controllogix_rce |
| Exploits Protocolo | 14 | exploits/protocols/enip/enip_cip_forward_open_flood |
| Scanners | 2 | scanners/ics/enip_list_identity |
| Creds | 4 | creds/rockwell/logix_default_creds |
| Malware | 2 | cve/malware/pipedream_iocontrol |

---

## Modulos com Suporte Multi-Plataforma (Tier 3)

Modulos que possuem implementacoes nativas em Go, C/C++ ou C# alem do fallback Python:

| Modulo | Linguagem Nativa | Python Fallback | Vantagem do Nativo |
|--------|-----------------|-----------------|-------------------|
| `cve/malware/frostygoop_modbus_heating` | Go | Sim | Performance, binario estatico |
| `cve/malware/crashoverride_industroyer` | Go + Python | Sim | Implementacao fiel ao original |
| `cve/malware/industroyer2` | C++ | Parcial | Protocolo IEC 104 completo |
| `cve/malware/pipedream_iocontrol` | C# (.NET) | Sim | API Windows ICS nativa |
| `cve/malware/stuxnet_siemens_worm` | C | Nao | Nivel de sistema, evasao AV |
| `exploits/protocols/modbus/modbus_rogue_master` | Go | Sim | Alta concorrencia |
| `assessment/mitre_ics/t0848_rogue_master` | Python+Go | N/A | Performance de varredura |

---

## Como Reportar Modulos Novos ou Bugs

Para reportar bugs ou submeter novos modulos:

1. **Issues no GitHub**: https://github.com/mrhenrike/IndustrialXPL-Forge/issues
2. **Template de issue**: inclua versao do IXF, sistema operacional, reproducao
3. **Pull Requests**: siga o guia em [Desenvolvimento de Modulos](09-desenvolvimento-modulos.md)
4. **Security disclosures**: use o processo de divulgacao responsavel no SECURITY.md

---

*Fim do Catalogo de Modulos. Total: 1190+ modulos cobrindo 150+ vendors, 50+ protocolos e 96/103 tecnicas MITRE ATT&CK para ICS.*

*Anterior: [Assessment e Conformidade](12-assessment-conformidade.md) | Proximo: [Scripts NSE](14-scripts-nse.md)*

---

## Distribuicao Geografica de Vulnerabilidades

### CVEs por Pais de Origem do Vendor

| Pais | Vendors | CVEs Cobertos | Destaque |
|------|---------|--------------|---------|
| EUA | Rockwell, GE, Honeywell, Emerson, Inductive, Kepware | 181 | ControlLogix, Experion PKS, Ignition |
| Franca | Schneider Electric | 39 | Modicon M340/M580, EcoStruxure |
| Alemanha | Siemens, Beckhoff, Phoenix, Wago | 48 | S7-1200/1500, TwinCAT, PLCnext |
| Japao | Mitsubishi, Omron, Yokogawa, Fuji | 47 | MELSEC-Q, CJ2, CENTUM VP |
| Suica/Suecia | ABB | 15 | 800xA DCS, MicroSCADA |
| Taiwan | Moxa, Advantech, Delta | 20 | IOLogik, ADAM, DVP |
| Israel | Unitronics | 4 | UniStream, Vision PLC |
| Brasil | Altus, WEG, Elipse | 7 | Nexto, CFW11, E3 SCADA |
| Austria | COPA-DATA, B&R | 7 | Zenon, X20 PLCs |
| Coreia do Sul | LS Electric, Hyundai | 3 | XGK/XGB, N700E |

---

## CVEs Mais Criticos por Score CVSS

| CVE | CVSS | Vendor | Produto | Tipo |
|-----|------|--------|---------|------|
| CVE-2021-38395 | 10.0 | Honeywell | Experion PKS | RCE |
| CVE-2021-22681 | 9.8 | Siemens | S7-1200/1500 | Chave Hardcoded |
| CVE-2023-3595 | 9.8 | Rockwell | ControlLogix | RCE |
| CVE-2022-45789 | 9.8 | Schneider | EcoStruxure Expert | RCE |
| CVE-2022-29965 | 9.8 | Emerson | ROC800 | Creds Hardcoded |
| CVE-2022-36249 | 9.8 | Phoenix | PLCnext | Auth Bypass |
| CVE-2023-6448 | 9.8 | Unitronics | UniStream | RCE |
| CVE-2022-1159 | 9.8 | Rockwell | Logix5000 | Heap Overflow |
| CVE-2021-40365 | 9.8 | Siemens | SIMATIC HMI | Unauth Access |
| CVE-2018-7789 | 9.8 | Schneider | Modicon M340 | RCE HTTP |
| CVE-2020-35952 | 9.8 | GE | Cimplicity | Path Traversal RCE |
| CVE-2021_22281 | 9.8 | ABB | 800xA DCS | Auth Bypass |
| CVE-2023_39476 | 9.8 | Inductive | Ignition | RCE Deserial |
| CVE-2022_2848 | 9.1 | Kepware | KEPServerEX | Buffer Overflow |
| CVE-2022_38465 | 9.3 | Siemens | S7 Global Key | Bypass |

---

*Catalogo completo disponivel via: `ixf > stats` e `ixf > search <termo>`*

*Anterior: [Assessment e Conformidade](12-assessment-conformidade.md) | Proximo: [Scripts NSE](14-scripts-nse.md)*

---

## Busca de Modulos por Palavra-Chave -- Exemplos Comuns

```
# Encontrar todos os exploits de DoS
ixf > search dos
[*] Resultados: 47 modulos encontrados

# Encontrar modulos de buffer overflow
ixf > search buffer_overflow
[*] Resultados: 12 modulos encontrados

# Encontrar modulos de path traversal
ixf > search path_traversal
[*] Resultados: 8 modulos encontrados

# Encontrar modulos de auth bypass
ixf > search auth_bypass
[*] Resultados: 19 modulos encontrados

# Encontrar todos os modulos de escalada de privilegio
ixf > ttp-list --tactic privilege-escalation
  T0874 Hooking                        1 modulo
  T0890 Exploitation for Priv Esc      3 modulos

# Encontrar modulos por vendor e impacto
ixf > search siemens
[*] 27 modulos Siemens encontrados

ixf > vendors siemens
  Siemens    27

# Verificar quantos modulos CATASTROPHIC existem
ixf > search catastrophic
[i] Use: stats para ver distribuicao por impacto
ixf > stats
[i] CATASTROPHIC: 18 modulos
```

---

## Glossario de Termos IXF

| Termo | Definicao |
|-------|-----------|
| Simulate mode | Modo onde nenhum pacote e enviado -- apenas descricao do ataque |
| DestructiveGate | Portao de confirmacao de seguranca para operacoes destrutivas |
| OptIP | Tipo de opcao para enderecos IP e hostnames |
| OptPort | Tipo de opcao para numeros de porta TCP/UDP |
| MITRE TID | Identificador de tecnica MITRE ATT&CK para ICS (ex: T0843) |
| Tier 1/2/3 | Nivel de dependencia de runtime externo |
| @mute | Decorador que suprime saida em check() para threading seguro |
| @multi | Decorador que habilita target=file:// para multiplos alvos |
| DestructiveGate | Portao de confirmacao de seguranca |
| impact level | Nivel de impacto do modulo (INFO/READ/LOW/MEDIUM/HIGH/CRITICAL/CATASTROPHIC) |
| check() | Metodo de proba somente-leitura do modulo |
| run() | Metodo de execucao principal do modulo |
| get_info() | Metodo para acessar metadados __info__ do modulo |
| index_modules() | Funcao que lista todos os modulos disponiveis |
| import_exploit() | Funcao que carrega um modulo pelo caminho Python |


---

*Catalogo completo do IndustrialXPL-Forge v1.0.13 -- 1190+ modulos para pesquisa de seguranca OT/ICS.*
<!-- catalogo-modulos v1.0.13 -- fim -->

<!-- fim -->

---

## Catálogo Detalhado: Módulos de Protocolo por Sub-categoria

### Sub-categoria: Flood / DoS de Protocolo ICS

| Módulo | Protocolo | Porta | Impacto | Técnica MITRE |
|--------|-----------|-------|---------|---------------|
| `exploits/protocols/modbus/modbus_flood_dos` | Modbus TCP | 502 | HIGH | T0814 |
| `exploits/protocols/modbus/modbus_fc90_dos` | Modbus TCP | 502 | HIGH | T0814 |
| `exploits/protocols/dnp3/dnp3_unsolicit_flood` | DNP3 | 20000 | HIGH | T0814 |
| `exploits/protocols/iec104/iec104_startdt_flood` | IEC 104 | 2404 | HIGH | T0814 |
| `exploits/protocols/iec104/iec104_gi_flood` | IEC 104 | 2404 | HIGH | T0814 |
| `exploits/protocols/bacnet/bacnet_who_is_flood` | BACnet/IP | 47808 | HIGH | T0814 |
| `exploits/protocols/opcua/opcua_alarm_acknowledge_flood` | OPC UA | 4840 | HIGH | T0814 |
| `exploits/protocols/s7comm/s7_keepalive_flood` | S7comm | 102 | HIGH | T0814 |
| `exploits/protocols/enip/enip_cip_connection_flood` | EtherNet/IP | 44818 | HIGH | T0814 |
| `exploits/protocols/fins/fins_broadcast_flood` | FINS | 9600 | HIGH | T0814 |

### Sub-categoria: Escrita Não Autorizada de Parâmetro

| Módulo | Protocolo | Impacto | Técnica MITRE | CVE Associado |
|--------|-----------|---------|---------------|---------------|
| `exploits/protocols/modbus/modbus_fc16_write_registers` | Modbus | MEDIUM | T0836 | N/A |
| `exploits/protocols/modbus/modbus_write_coil` | Modbus | MEDIUM | T0836 | N/A |
| `exploits/protocols/s7comm/s7_write_db_block` | S7comm | MEDIUM | T0836 | N/A |
| `exploits/protocols/enip/enip_write_tag` | EtherNet/IP | MEDIUM | T0836 | N/A |
| `exploits/protocols/opcua/opcua_write_value_anon` | OPC UA | MEDIUM | T0836 | N/A |
| `exploits/protocols/fins/fins_memory_area_write` | FINS | MEDIUM | T0836 | N/A |
| `exploits/protocols/dnp3/dnp3_direct_operate` | DNP3 | HIGH | T0855 | N/A |
| `exploits/protocols/bacnet/bacnet_write_property_anon` | BACnet | MEDIUM | T0836 | N/A |
| `exploits/protocols/ads/ads_variable_write` | ADS/AMS | MEDIUM | T0836 | N/A |
| `exploits/protocols/pcom/pcom_read_write_memory` | PCOM | HIGH | T0836 | CVE-2023-6448 |
| `exploits/protocols/vnetip/vnetip_tag_write` | Vnet/IP | MEDIUM | T0836 | N/A |
| `exploits/protocols/cc_link/cc_link_ie_unauthorized_write` | CC-Link IE | MEDIUM | T0836 | N/A |

### Sub-categoria: Parada / Reinicialização de Dispositivo

| Módulo | Protocolo | Impacto | Técnica MITRE |
|--------|-----------|---------|---------------|
| `exploits/protocols/s7comm/s7_cpu_stop_command` | S7comm | HIGH | T0816 |
| `exploits/protocols/enip/enip_reset_identity` | EtherNet/IP | HIGH | T0816 |
| `exploits/protocols/fins/fins_cpu_unit_reset` | FINS | HIGH | T0816 |
| `exploits/protocols/dnp3/dnp3_warm_restart` | DNP3 | HIGH | T0816 |
| `exploits/protocols/profinet/profinet_dcp_reset_factory` | PROFINET | HIGH | T0816 |

### Sub-categoria: Upload/Download de Programa PLC

| Módulo | Protocolo | Impacto | Técnica MITRE |
|--------|-----------|---------|---------------|
| `exploits/protocols/s7comm/s7_plc_program_upload_download` | S7comm | CRITICAL | T0843, T0844 |
| `exploits/protocols/enip/enip_program_download_controllogix` | EtherNet/IP | CRITICAL | T0843 |
| `exploits/protocols/pccc/pccc_slc500_program_download` | PCCC | CRITICAL | T0843 |
| `exploits/protocols/s7comm/s7_activate_fw_update` | S7comm | CRITICAL | T0800 |
| `exploits/plc/siemens/s7_1200_hardcoded_key` | S7comm | CRITICAL | T0843, T0821 |
| `exploits/plc/rockwell/logix_unauth_read` | EtherNet/IP | HIGH | T0844 |

---

## Catálogo Detalhado: Módulos de Malware por Vetor de Ataque

### Por Protocolo ICS Alvo

| Protocolo Alvo | Malware/TTP | Módulo IXF | Impacto |
|----------------|-------------|------------|---------|
| Modbus TCP | FrostyGoop | `cve/malware/frostygoop_modbus_heating` | CATASTROPHIC |
| IEC 60870-5-104 | Industroyer IEC104 | `cve/apt/sandworm_industroyer_iec104` | CATASTROPHIC |
| IEC 60870-5-104 | CosmicEnergy | `cve/malware/cosmicenergy_iec104` | CATASTROPHIC |
| IEC 61850 GOOSE | Industroyer2 | `cve/malware/industroyer2` | CATASTROPHIC |
| EtherNet/IP | Industroyer EtherNet/IP | `cve/malware/industroyer_enip` | CATASTROPHIC |
| S7comm | Industroyer S7 | `cve/malware/industroyer_s7` | CATASTROPHIC |
| OPC DA | Havex | `cve/malware/havex_opcda` | HIGH |
| Schneider SIS | TRITON | `cve/apt/triton_triconex_safety_overwrite` | CATASTROPHIC |
| Siemens S7 | Stuxnet | `cve/malware/stuxnet_centrifuge` | CATASTROPHIC |
| Múltiplos | PIPEDREAM | `cve/malware/pipedream_iocontrol` | CATASTROPHIC |

### Por Impacto Físico Documentado

| Evento Histórico | Módulo IXF | Ano | Local | Impacto Real |
|-----------------|------------|-----|-------|-------------|
| Apagão Ucrânia | `cve/malware/crashoverride_industroyer` | 2016 | Ucrânia | 225.000 sem energia |
| Ataque SIS Arábia | `cve/apt/triton_triconex_safety_overwrite` | 2017 | Arábia Saudita | Quase explosão em planta petroquímica |
| Apagão Ucrânia 2022 | `cve/malware/industroyer2` | 2022 | Ucrânia | 2 milhões afetados |
| Heating Lviv | `cve/malware/frostygoop_modbus_heating` | 2024 | Ucrânia | 600 apartamentos sem aquecimento |
| NotPetya Maersk | `cve/malware/notpetya` | 2017 | Global | $10B+ prejuízo, 45.000 PCs |
| Stuxnet Natanz | `cve/malware/stuxnet_centrifuge` | 2010 | Irã | 1.000+ centrífugas destruídas |

---

## Guia de Uso Rápido por Objetivo

### Para Assessment de Conformidade

```bash
# IEC 62443 completo
ixf assess iec62443/zone_conduit_audit
ixf assess nist_sp800_82/control_checklist
ixf assess risk/ics_risk_scorer

# Gerar relatório
ixf mitre-coverage
ixf mitre-report json
```

### Para Descoberta de Dispositivos

```bash
# Varredura multi-protocolo
ixf use scanners/network/ot_port_sweep set target 192.168.1.0/24 run
ixf use scanners/ics/modbus_detect set target 192.168.1.0/24 run
ixf use scanners/ics/s7_enumerate set target 192.168.1.0/24 run
ixf use scanners/osint/shodan_ics_dork set target 192.168.1.0/24 run
```

### Para Testes de Credenciais (Red Team)

```bash
# Credenciais padrão por vendor
ixf ttp T0812 192.168.1.0/24   # Todos os módulos de creds padrão
ixf use creds/siemens/s7_default_creds set target 192.168.1.50 run
ixf use creds/generic/snmp_community_scan set target 192.168.1.0/24 run
```

### Para Simulação de Malware (Treinamento SIEM)

```bash
# Simular TTPs de malware para criar regras de detecção
ixf use cve/malware/frostygoop_modbus_heating set target 192.168.1.100 run
ixf use cve/malware/crashoverride_industroyer set target 172.16.0.10 run
ixf use cve/malware/pipedream_iocontrol set target 10.0.0.50 run
# Todos em modo simulate=True — apenas para criar alertas SIEM sem impacto real
```

### Para SAST de Código PLC

```bash
# Revisar código PLC com LLM
ixf llm-key gemini AIzaSy...
ixf sast /opt/plc_projects/ --mode sast
ixf sast firmware.bin --mode reverse
ixf sast projeto/ --mode diff --base main --head dev
```

---

## Tabela de Compatibilidade: Módulo × Runtime

| Módulo | Python (Tier 0/1) | Go | C/C++ | Nota |
|--------|------------------|-----|-------|------|
| `cve/malware/frostygoop_modbus_heating` | Sim (pymodbus) | Sim (goroutines) | Não | Go é mais fiel ao original |
| `cve/malware/crashoverride_industroyer` | Sim | Sim | Sim | C mais próximo do original |
| `cve/malware/killdisk_industroyer` | Sim (simulação) | Não | Sim | C para escrita de disco real |
| `cve/malware/notpetya` | Sim (simulação) | Não | Sim (C++) | C++ para replicação precisa |
| `exploits/protocols/modbus/modbus_flood_dos` | Sim | Não | Sim | C para throughput máximo |
| Todos os scanners | Sim | Não | Não | Python puro suficiente |
| Todos os creds | Sim | Não | Não | Python puro suficiente |
| Todos os assessments | Sim | Não | Não | Python puro suficiente |

---

*Versão: IXF v1.1.1 | Atualizado: 2026-06-01 | Total de módulos: 1190+*

---

## Módulos por Nível de Dificuldade de Exploração

### Exploração Trivial (sem expertise necessária)

Estes módulos exploram vulnerabilidades que não requerem conhecimento especializado — qualquer atacante com acesso de rede pode explorá-las:

| Módulo | Razão | Impacto |
|--------|-------|---------|
| `exploits/protocols/modbus/modbus_fc16_write_registers` | Modbus não tem autenticação — escrita direta | MEDIUM |
| `creds/generic/snmp_community_scan` | Strings de comunidade padrão "public"/"private" | MEDIUM |
| `creds/generic/web_default_creds` | Credenciais de fábrica nunca alteradas | HIGH |
| `exploits/protocols/bacnet/bacnet_who_is_flood` | Flood UDP simples | HIGH |
| `scanners/ics/modbus_detect` | Detecção passiva sem manipulação | READ |

### Exploração Intermediária (conhecimento de protocolo necessário)

| Módulo | Razão | Impacto |
|--------|-------|---------|
| `exploits/protocols/s7comm/s7_cpu_stop_command` | Requer conhecimento de protocolo S7comm/COTP | HIGH |
| `exploits/protocols/dnp3/dnp3_direct_operate` | Requer entendimento de protocolo DNP3 | HIGH |
| `exploits/protocols/iec104/iec104_startdt_flood` | Conhecimento de estrutura IEC 104 | HIGH |
| `cve/moxa/cve_2020_25159_mgmt_auth_bypass` | Bypass específico de firmware | CRITICAL |

### Exploração Avançada (expertise OT necessária)

| Módulo | Razão | Impacto |
|--------|-------|---------|
| `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key` | Exploração de criptografia S7comm | CRITICAL |
| `cve/apt/triton_triconex_safety_overwrite` | Protocolo proprietário Triconex, engenharia reversa | CATASTROPHIC |
| `cve/malware/stuxnet_centrifuge` | Exploração de lógica de controlador de inversor de frequência | CATASTROPHIC |
| `exploits/protocols/iec61850/iec61850_goose_spoof` | Requires L2 access and protocol knowledge | CATASTROPHIC |
| `cve/malware/pipedream_iocontrol` | Framework modular OT avançado | CATASTROPHIC |

---

## Changelog de Módulos por Versão IXF

### IXF v1.1.1 (atual — 2026-06-01)
- **Adicionados:** CosmicEnergy IEC 104, FrostyGoop (Go Extended), PIPEDREAM/INCONTROLLER (3 módulos)
- **Atualizados:** Todos os módulos de assessment com formato de saída tabular melhorado
- **Novos Scanners:** `ixf-iec104-info.nse`, `ixf-fins-info.nse`
- **Total:** 1190+ módulos

### IXF v2.0.0 (2025-11-15)
- **Adicionados:** 47 novos módulos CVE (Schneider, Rockwell, Delta)
- **Nova funcionalidade:** Integração LLM SAST (5 provedores)
- **Nova funcionalidade:** PolyExploitRunner (Go, C, C++ artifacts)
- **Total:** ~900 módulos

### IXF v1.5.0 (2025-06-01)
- **Adicionados:** Scripts NSE (8 scripts)
- **Adicionados:** Módulos de assessment MITRE (28 módulos)
- **Adicionados:** Módulos de protocolo de safety (CIP Safety, PROFIsafe, FSoE)
- **Total:** ~830 módulos

---

*Para contribuir com novos módulos: consulte [Desenvolvimento de Módulos](09-desenvolvimento-modulos.md)*

---

## Glossário de Termos do Catálogo

| Termo | Definição |
|-------|-----------|
| **CVE** | Common Vulnerabilities and Exposures — identificador único de vulnerabilidade |
| **CVSS** | Common Vulnerability Scoring System — pontuação de gravidade (0-10) |
| **PLC** | Programmable Logic Controller — controlador lógico programável |
| **RTU** | Remote Terminal Unit — unidade terminal remota |
| **DCS** | Distributed Control System — sistema de controle distribuído |
| **HMI** | Human Machine Interface — interface homem-máquina |
| **SCADA** | Supervisory Control And Data Acquisition — supervisão e controle |
| **EWS** | Engineering Workstation — estação de trabalho de engenharia |
| **SIS** | Safety Instrumented System — sistema instrumentado de segurança |
| **SIL** | Safety Integrity Level — nível de integridade de segurança |
| **ICS** | Industrial Control System — sistema de controle industrial |
| **OT** | Operational Technology — tecnologia operacional |
| **IACS** | Industrial Automation and Control System |
| **FC** | Function Code — código de função Modbus |
| **ASDU** | Application Service Data Unit — unidade de dados IEC 60870 |
| **GOOSE** | Generic Object Oriented Substation Event — protocolo IEC 61850 |
| **MMS** | Manufacturing Message Specification — protocolo IEC 61850 |
| **APT** | Advanced Persistent Threat — ameaça persistente avançada |
| **TTP** | Tactic, Technique, and Procedure — táticas, técnicas e procedimentos |
| **MITRE** | Organização de pesquisa sem fins lucrativos — mantém ATT&CK framework |

| **NSE** | Nmap Scripting Engine — motor de scripts do Nmap |
| **SAST** | Static Application Security Testing — teste estático de segurança |
| **LLM** | Large Language Model — modelo de linguagem grande |
| **IIoT** | Industrial Internet of Things — internet das coisas industrial |
| **NERC CIP** | North American Electric Reliability Corporation Critical Infrastructure Protection |
| **DMZ** | Demilitarized Zone — zona desmilitarizada de rede |
