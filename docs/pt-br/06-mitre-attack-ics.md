# MITRE ATT&CK for ICS

O IXF integra o MITRE ATT&CK for ICS v19, mapeando 976+ módulos para 89 das 101 técnicas (88% de cobertura) em todas as 12 táticas. Este documento cobre a estrutura do framework, todos os comandos MITRE/TTP, cada tática com suas técnicas e exemplos de uso.

---

## Sumário

- [Visão Geral do MITRE ATT&CK for ICS](#visão-geral-do-mitre-attck-for-ics)
- [Cobertura IXF por Tática](#cobertura-ixf-por-tática)
- [As 12 Táticas — Referência Completa](#as-12-táticas--referência-completa)
- [Aliases de Tática Aceitos](#aliases-de-tática-aceitos)
- [Comandos MITRE no IXF](#comandos-mitre-no-ixf)
- [Comandos TTP no IXF](#comandos-ttp-no-ixf)
- [Módulos de Assessment por Técnica](#módulos-de-assessment-por-técnica)
- [Layer ATT&CK Navigator](#layer-attck-navigator)
- [Mapeamento de Malware ICS por Técnica](#mapeamento-de-malware-ics-por-técnica)
- [Integração com Relatórios](#integração-com-relatórios)
- [Casos de Uso por Contexto](#casos-de-uso-por-contexto)

---

## Visão Geral do MITRE ATT&CK for ICS

**MITRE ATT&CK for ICS** é um framework de conhecimento baseado em observações do mundo real de ataques a Sistemas de Controle Industrial (ICS). Diferente do ATT&CK Enterprise, o ATT&CK for ICS foca em:

- **Táticas e técnicas específicas para OT/ICS/SCADA**
- **Impacto físico** (diferente de impacto computacional)
- **Protocolos industriais** (Modbus, S7comm, IEC 104, DNP3, etc.)
- **Dispositivos físicos** (CLPs, RTUs, IHMs, HMIs, DCS, SIS)
- **Malware ICS documentado** (Stuxnet, Industroyer/Crashoverride, TRITON, FrostyGoop)

O IXF implementa módulos para todas as técnicas mapeadas, organizados por tática, e fornece cobertura de 88% do framework.

---

## Cobertura IXF por Tática

```
ixf > mitre-coverage

  IXF MITRE ATT&CK for ICS Coverage
  ─────────────────────────────────────────────────────────────────────────
  Tactic ID    Tactic                       Total TIDs  Covered  %
  TA0108       Initial Access                     9         9    100%
  TA0104       Execution                          9         8     88%
  TA0110       Persistence                        8         6     75%
  TA0111       Privilege Escalation               2         2    100%
  TA0103       Evasion                            5         4     80%
  TA0102       Discovery                         13        11     84%
  TA0109       Lateral Movement                   3         3    100%
  TA0100       Collection                         9         8     88%
  TA0101       Command and Control                3         3    100%
  TA0107       Inhibit Response Function         18        14     77%
  TA0106       Impair Process Control            11         9     81%
  TA0105       Impact                            11         8     72%
  ─────────────────────────────────────────────────────────────────────────
  TOTAL        —                                101        89     88%
```

---

## As 12 Táticas — Referência Completa

### TA0108 — Initial Access (Acesso Inicial)

**Cobertura IXF: 9/9 (100%)**

Técnicas usadas para ganhar acesso inicial à rede ICS/OT.

| TID | Nome da Técnica | Módulos IXF | Descrição |
|-----|-----------------|-------------|-----------|
| T0817 | Drive-by Compromise | 2 | Comprometimento via navegação web |
| T0819 | Exploit Public-Facing Application | 8 | Exploração de IHMs/SCADA web expostos |
| T0822 | External Remote Services | 5 | Abuso de VPN, RDP, SSH expostos |
| T0823 | Graphical User Interface | 3 | Acesso via IHM com credenciais padrão |
| T0824 | Loss of View | 4 | Comprometimento de displays de operador |
| T0847 | Replication Through Removable Media | 2 | Propagação via USB (como Stuxnet) |
| T0848 | Rogue Master | 6 | Mestre Modbus/DNP3 desonesto |
| T0865 | Spearphishing Attachment | 3 | Phishing direcionado para operadores OT |
| T0866 | Exploitation of Remote Services | 12 | CVEs em serviços remotos de dispositivos OT |

**Exemplos de uso:**

```
ixf > mitre-list initial-access

  MITRE ATT&CK for ICS — initial-access
  TID     # Modules  Primary Module
  T0817   2          exploits/scada/aveva/wonderware_drive_by
  T0819   8          cve/schneider/cve_2021_22704_ecostruxure_rce
  T0822   5          creds/siemens/simatic_default_creds
  T0823   3          creds/rockwell/studio5000_default_creds
  T0824   4          exploits/scada/ge/cimplicity_loss_of_view
  T0847   2          cve/apt/stuxnet_usb_propagation
  T0848   6          exploits/protocols/modbus/modbus_rogue_master
  T0865   3          assessment/mitre_ics/t0865_spearphishing
  T0866   12         cve/siemens/cve_2021_22681_s7_1200_hardcoded_key

ixf > ttp T0866 192.168.1.100
[*] TTP T0866 (Exploitation of Remote Services) — 12 módulos — simulate=True
[*] [1/12] cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
     Simulação: MitM S7comm+ com chave TLS hardcoded
[*] [2/12] cve/emerson/cve_2022_29965_roc800_hardcoded_creds
     Simulação: Credenciais hardcoded protocolo ROC+
…
```

---

### TA0104 — Execution (Execução)

**Cobertura IXF: 8/9 (88%)**

Técnicas para executar código ou comandos no ambiente OT/ICS.

| TID | Nome da Técnica | Módulos IXF | Descrição |
|-----|-----------------|-------------|-----------|
| T0807 | Command-Line Interface | 3 | Execução via CLI de dispositivos OT |
| T0821 | Modify Controller Tasking | 5 | Modificação de tarefas do CLP |
| T0823 | Graphical User Interface | 3 | Execução via IHM |
| T0828 | Native API | 4 | APIs nativas de vendor (S7comm, ROC+, FINS) |
| T0843 | Program Download | 12 | Download de programa malicioso para CLP |
| T0853 | Scripting | 3 | Scripts maliciosos em ambientes OT |
| T0858 | Remote System Information Discovery | 4 | Execução via descoberta ativa |
| T0871 | Execution through API | 5 | APIs OPC UA, REST, DCOM |

**Exemplo — T0843 Program Download:**

```
ixf > mitre T0843
[+] 12 module(s) cover T0843:
  use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
  use cve/rockwell/cve_2022_1161_controllogix_modified_fw
  use exploits/protocols/s7comm/s7comm_program_download
  use exploits/protocols/s7comm_plus/s7comm_plus_program_download
  use exploits/protocols/enip/cip_program_download
  use assessment/mitre_ics/t0843_program_upload

ixf > ttp T0843 192.168.1.100
[*] TTP T0843 (Program Download) — 12 módulos — simulate=True
[*] [1/12] cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
  [SIMULATE MODE]
  Passo 1: Extrair chave TLS hardcoded do firmware S7-1200
  Passo 2: MitM S7comm+ TCP/102
  Passo 3: Download de programa CLP malicioso
  MITRE: T0843
[*] [2/12] exploits/protocols/s7comm/s7comm_program_download
  [SIMULATE MODE]
  Passo 1: Conectar via S7comm sem autenticação
  Passo 2: Upload do programa CLP atual para backup
  Passo 3: Modificar programa e fazer download malicioso
  MITRE: T0843
…
[+] T0843 concluída: 12 módulos
```

---

### TA0110 — Persistence (Persistência)

**Cobertura IXF: 6/8 (75%)**

Técnicas para manter acesso persistente a sistemas OT/ICS após o comprometimento inicial.

| TID | Nome da Técnica | Módulos IXF | Descrição |
|-----|-----------------|-------------|-----------|
| T0839 | Module Firmware | 4 | Firmware malicioso em módulos de I/O |
| T0849 | Masquerading | 2 | Mascarar comunicações maliciosas |
| T0851 | Rootkit | 3 | Rootkits em sistemas embarcados OT |
| T0857 | System Firmware | 5 | Modificação de firmware do sistema |
| T0859 | Valid Accounts | 15 | Abuso de contas legítimas |
| T0862 | Supply Chain Compromise | 2 | Comprometimento da cadeia de suprimentos |

**Exemplo — T0859 Valid Accounts:**

```
ixf > ttp T0859 192.168.1.100 --stop-on-first
[*] TTP T0859 (Valid Accounts) — 15 módulos — stop-on-first
[*] [1/15] creds/siemens/simatic_default_creds
     check(): NOT_VULNERABLE
[*] [2/15] creds/rockwell/plc_default_creds
     check(): NOT_VULNERABLE
[*] [3/15] creds/schneider/modicon_default_creds
     check(): VULNERABLE
[+] Hit encontrado em creds/schneider/modicon_default_creds. Parando.
```

---

### TA0111 — Privilege Escalation (Escalada de Privilégios)

**Cobertura IXF: 2/2 (100%)**

Técnicas para obter permissões elevadas em sistemas OT.

| TID | Nome da Técnica | Módulos IXF | Descrição |
|-----|-----------------|-------------|-----------|
| T0890 | Exploitation for Privilege Escalation | 4 | CVEs para escalada de privilégios |
| T0874 | Hooking | 1 | Hooking de APIs em sistemas OT |

```
ixf > mitre-list privesc

  MITRE ATT&CK for ICS — privesc
  TID     # Modules  Primary Module
  T0890   4          cve/siemens/cve_2019_19280_scalance_fw_upload
  T0874   1          assessment/mitre_ics/t0874_hooking
```

---

### TA0103 — Evasion (Evasão)

**Cobertura IXF: 4/5 (80%)**

Técnicas para evitar detecção em redes e sistemas OT.

| TID | Nome da Técnica | Módulos IXF | Descrição |
|-----|-----------------|-------------|-----------|
| T0820 | Exploitation Remote Services (Evasion) | 3 | Exploração para evasão |
| T0849 | Masquerading | 2 | Mascarar tráfego malicioso |
| T0851 | Rootkit | 3 | Rootkits em CLPs e HMIs |
| T0856 | Spoof Reporting Message | 2 | Falsificar mensagens de status/relatório |
| T0858 | Remote System Information Discovery | — | (coberto em Discovery) |

**Exemplo — T0856 Spoof Reporting Message:**

```
ixf > ttp T0856 192.168.1.100
[*] TTP T0856 (Spoof Reporting Message) — 2 módulos — simulate=True
[*] [1/2] exploits/protocols/modbus/modbus_spoof_response
  [SIMULATE MODE]
  Passo 1: Monitorar tráfego Modbus entre master e slave
  Passo 2: Capturar Transaction ID do próximo request do master
  Passo 3: Enviar resposta falsificada antes do slave legítimo
  Efeito: Operador vê valores de processo falsos — Loss of View
  MITRE: T0856

[*] [2/2] exploits/protocols/dnp3/dnp3_unsolicited_response
  [SIMULATE MODE]
  Injetar resposta não solicitada DNP3 com dados de processo falsificados
```

---

### TA0102 — Discovery (Descoberta)

**Cobertura IXF: 11/13 (84%)**

Técnicas para descobrir ativos, topologia de rede e informações de processo no ambiente OT.

| TID | Nome da Técnica | Módulos IXF | Descrição |
|-----|-----------------|-------------|-----------|
| T0840 | Network Connection Enumeration | 5 | Enumeração de conexões de rede |
| T0841 | Remote System Information Discovery | 3 | Informações de sistemas remotos |
| T0842 | Network Sniffing | 4 | Captura de tráfego de rede |
| T0846 | Remote System Discovery | 8 | Descoberta de dispositivos OT |
| T0858 | Remote System Information Discovery | 4 | Via protocolos OT |
| T0880 | Modify Alarm Settings | — | (coberto em Inhibit RF) |
| T0886 | Remote Services | 3 | Descoberta via serviços remotos |
| T0887 | Wireless Sniffing | 2 | Varredura de redes wireless industriais |
| T0888 | Remote System Discovery | 9 | Fingerprinting de dispositivos OT |
| T0889 | Gather Victim Network Information | 2 | OSINT sobre rede alvo |
| T0891 | Hardcoded Credentials | 6 | Descoberta de credenciais hardcoded |

**Exemplo — Varredura de descoberta em sub-rede:**

```
ixf > mitre-scan discovery 192.168.1.0/24
[*] Varrendo tática: Discovery (TA0102) em 192.168.1.0/24
[*] simulate=True (modo seguro)
[*] [1/11] T0840 — Network Connection Enumeration (5 módulos)
    [SIMULATE] Enumerando conexões TCP ativas na sub-rede
[*] [2/11] T0841 — Remote System Information Discovery (3 módulos)
    [SIMULATE] Lendo device identification via Modbus FC43, OPC UA Browse
[*] [3/11] T0842 — Network Sniffing (4 módulos)
    [SIMULATE] Captura passiva de tráfego ICS na sub-rede
[*] [4/11] T0846 — Remote System Discovery (8 módulos)
    [SIMULATE] Varredura de portas ICS: 502, 102, 44818, 4840, 47808, 2404
[*] [5/11] T0887 — Wireless Sniffing (2 módulos)
    [SIMULATE] Varredura de SSIDs industriais (ISA100.11a, WirelessHART)
[*] [6/11] T0888 — Remote System Discovery (9 módulos)
    [SIMULATE] Fingerprinting via S7comm, S7comm+, PROFINET DCP
[*] [7/11] T0891 — Hardcoded Credentials (6 módulos)
    [SIMULATE] Verificar credenciais padrão conhecidas de vendors
…
[+] Varredura concluída: 11 técnicas, 44 execuções de módulo
[i] 3 possíveis matches detectados em modo simulate
```

**Exemplo — T0888 Remote System Discovery:**

```
ixf > ttp T0888 192.168.1.0/24
[*] TTP T0888 (Remote System Discovery) — 9 módulos
[*] [1/9] scanners/ics/modbus_detect — Modbus TCP (502)
     [SIMULATE] Probe FC04 para detecção de dispositivos Modbus
[*] [2/9] scanners/ics/s7_comm_scanner — S7comm (102)
     [SIMULATE] Probe S7comm para fingerprinting de CLPs Siemens
[*] [3/9] scanners/ics/bacnet_scanner — BACnet/IP (47808/UDP)
     [SIMULATE] Who-Is broadcast para descoberta BACnet
[*] [4/9] scanners/ics/dnp3_detect — DNP3 (20000)
     [SIMULATE] Link status para detecção DNP3
[*] [5/9] scanners/ics/opcua_scanner — OPC UA (4840)
     [SIMULATE] Discovery/GetEndpoints OPC UA
[*] [6/9] scanners/ics/enip_scan — EtherNet/IP (44818)
     [SIMULATE] List Identity para fingerprinting EtherNet/IP
[*] [7/9] scanners/osint/shodan_ics_scan
     [SIMULATE] Consulta Shodan: port:502 port:102 country:BR
[*] [8/9] scanners/ics/fins_scan — Omron FINS (9600/UDP)
     [SIMULATE] Read CPU Unit Data para Omron
[*] [9/9] scanners/ics/profinet_scan — PROFINET DCP (L2 broadcast)
     [SIMULATE] Identify All para PROFINET DCP
[+] T0888 concluída: 9 módulos
```

---

### TA0109 — Lateral Movement (Movimento Lateral)

**Cobertura IXF: 3/3 (100%)**

Técnicas para mover-se lateralmente dentro do ambiente OT/ICS após o acesso inicial.

| TID | Nome da Técnica | Módulos IXF | Descrição |
|-----|-----------------|-------------|-----------|
| T0812 | Default Credentials | 6 | Credenciais padrão em sistemas legados |
| T0866 | Exploitation of Remote Services | 12 | Exploração para movimento lateral |
| T0886 | Remote Services | 3 | SSH, RDP, VNC em redes OT |

```
ixf > mitre-scan lateral 10.0.0.50
[*] Varrendo tática: Lateral Movement (TA0109) em 10.0.0.50
[*] [1/3] T0812 — Default Credentials (6 módulos)
    Testando credenciais padrão Siemens, Rockwell, Schneider...
[*] [2/3] T0866 — Exploitation of Remote Services (12 módulos)
    Verificando CVEs em serviços remotos...
[*] [3/3] T0886 — Remote Services (3 módulos)
    Testando SSH, RDP, VNC, Telnet...
[+] Varredura Lateral concluída
```

---

### TA0100 — Collection (Coleta)

**Cobertura IXF: 8/9 (88%)**

Técnicas para coletar informações sobre o ambiente ICS antes do ataque.

| TID | Nome da Técnica | Módulos IXF | Descrição |
|-----|-----------------|-------------|-----------|
| T0801 | Monitor Process State | 2 | Monitorar estado de processo |
| T0802 | Automated Collection | 5 | Coleta automatizada de dados OT |
| T0803 | Block Command Message | 4 | Bloqueio de mensagens de comando |
| T0806 | Brute Force I/O | 2 | Força bruta em pontos de I/O |
| T0811 | Data from Information Repositories | 4 | Dados de repositórios (historians) |
| T0812 | Default Credentials | 6 | Coletar com credenciais padrão |
| T0845 | Program Upload | 5 | Upload de programa CLP para análise |
| T0868 | Detect Operating Mode | 3 | Detectar modo de operação do CLP |
| T0887 | Wireless Sniffing | 2 | Coleta via wireless |

**Exemplo — T0845 Program Upload:**

```
ixf > ttp T0845 192.168.1.100
[*] TTP T0845 (Program Upload) — 5 módulos — simulate=True
[*] [1/5] exploits/protocols/s7comm/s7comm_block_read
  [SIMULATE MODE]
  Passo 1: Conectar via S7comm ao CLP Siemens (TCP/102)
  Passo 2: Listar blocos de programa (OBs, FBs, FCs, DBs)
  Passo 3: Fazer upload de cada bloco individualmente
  Passo 4: Salvar programa completo em arquivo local para análise
  Objetivo: Engenharia reversa da lógica de controle
  MITRE: T0845, T0803
…
```

---

### TA0101 — Command and Control (Comando e Controle)

**Cobertura IXF: 3/3 (100%)**

Técnicas para comunicação com sistemas comprometidos dentro da rede OT.

| TID | Nome da Técnica | Módulos IXF | Descrição |
|-----|-----------------|-------------|-----------|
| T0869 | Standard Application Layer Protocol | 4 | C2 via protocolos industriais |
| T0884 | Connection Proxy | 2 | Proxy via dispositivos OT comprometidos |
| T0885 | Commonly Used Port | 3 | C2 em portas de protocolo industrial |

```
ixf > ttp T0869 192.168.1.100
[*] TTP T0869 (Standard Application Layer Protocol) — 4 módulos
[*] [1/4] exploits/protocols/modbus/modbus_covert_channel
  [SIMULATE] C2 via Modbus holding registers como canal encoberto
[*] [2/4] exploits/protocols/mqtt/mqtt_c2_channel
  [SIMULATE] C2 via broker MQTT industrial (sem autenticação)
```

---

### TA0107 — Inhibit Response Function (Inibir Função de Resposta)

**Cobertura IXF: 14/18 (77%)**

Técnicas para degradar ou inibir a capacidade de resposta e detecção a incidentes.

| TID | Nome da Técnica | Módulos IXF | Descrição |
|-----|-----------------|-------------|-----------|
| T0800 | Activate Firmware Update Mode | 3 | Ativar modo de atualização de firmware |
| T0803 | Block Command Message | 4 | Bloquear mensagens de comando |
| T0804 | Block Reporting Message | 3 | Bloquear mensagens de relatório |
| T0805 | Block Serial COM | 2 | Bloquear comunicação serial |
| T0808 | Replication Through Removable Media | — | (coberto em Initial Access) |
| T0809 | Data Destruction | 3 | Destruição de dados em sistemas OT |
| T0814 | Denial of Control | 6 | Negação de controle ao operador |
| T0816 | Device Restart/Shutdown | 5 | Reinicialização/desligamento de dispositivo |
| T0826 | Loss of Availability | 4 | Perda de disponibilidade |
| T0827 | Loss of Control | 5 | Perda de controle do processo |
| T0831 | Manipulation of Control | 6 | Manipulação de comandos de controle |
| T0832 | Manipulation of View | 4 | Manipulação da visão do operador |
| T0835 | Manipulate I/O Image | 3 | Manipulação da imagem de I/O |
| T0836 | Modify Parameter | 9 | Modificação de parâmetros de processo |
| T0837 | Module Firmware | — | (coberto em Persistence) |
| T0838 | Modify Alarm Settings | 8 | Modificação de configurações de alarme |
| T0851 | Rootkit | — | (coberto em Evasion) |
| T0880 | Modify Alarm Settings | 8 | Alias — mesmo que T0838 |

**Exemplo — T0836 Modify Parameter:**

```
ixf > mitre T0836
[+] 9 module(s) cover T0836:
  use exploits/protocols/modbus/modbus_write_register
  use exploits/protocols/modbus/modbus_write_coil
  use exploits/protocols/s7comm/s7comm_modify_db
  use exploits/protocols/enip/cip_set_attribute
  use exploits/protocols/opcua/opcua_write_variable
  use exploits/protocols/dnp3/dnp3_direct_operate
  use exploits/protocols/iec104/iec104_asdu_command
  use cve/malware/frostygoop_modbus_heating
  use assessment/mitre_ics/t0836_modify_parameter

ixf > ttp T0836 192.168.1.100
[*] TTP T0836 (Modify Parameter) — 9 módulos — simulate=True
[*] [1/9] exploits/protocols/modbus/modbus_write_register
  [SIMULATE MODE]
  Escrever valor no holding register Modbus via FC16
  Target: 192.168.1.100:502 | Register: 0x0064 | Value: 0xFFFF
  Impacto: Alteração de setpoint de processo
  MITRE: T0836
[*] [2/9] cve/malware/frostygoop_modbus_heating
  [SIMULATE MODE]
  FrostyGoop: Escrever 0x0000 em HR[1]-HR[100] via FC16 repetidamente
  Impacto: Sistema de aquecimento desabilitado
  MITRE: T0836, T0814
…
```

**Exemplo — T0880 Modify Alarm Settings:**

```
ixf > ttp T0880 192.168.1.100
[*] TTP T0880 (Modify Alarm Settings) — 8 módulos — simulate=True
[*] [1/8] assessment/mitre_ics/t0880_modify_alarm_settings
  [SIMULATE MODE]
  Passo 1: Conectar ao servidor OPC UA 192.168.1.100:4840
  Passo 2: Browse namespace para encontrar nós de configuração de alarme
  Passo 3: Escrever novos thresholds de alarme (elevados significativamente)
  Passo 4: Confirmar que alarmes de processo não disparam mais
  Efeito: Operador não recebe alertas de condições perigosas
  MITRE: T0880, T0836
[*] [2/8] exploits/protocols/modbus/modbus_write_register
  [SIMULATE MODE]
  Escrever via FC16 nos registros de threshold de alarme Modbus
  Exemplo: HR[300]=0x7FFF (elevar límite superior ao máximo)
```

---

### TA0106 — Impair Process Control (Comprometer Controle de Processo)

**Cobertura IXF: 9/11 (81%)**

Técnicas para comprometer a integridade do controle de processo industrial.

| TID | Nome da Técnica | Módulos IXF | Descrição |
|-----|-----------------|-------------|-----------|
| T0806 | Brute Force I/O | 2 | Força bruta de pontos de I/O |
| T0831 | Manipulation of Control | 6 | Manipulação de comandos de controle |
| T0833 | Modify Control Logic | 5 | Modificação da lógica de controle |
| T0834 | Native API | 4 | APIs nativas para comprometer controle |
| T0836 | Modify Parameter | 9 | Modificação de parâmetros |
| T0855 | Unauthorized Command Message | 4 | Comandos não autorizados |
| T0857 | System Firmware | — | (coberto em Persistence) |
| T0858 | Remote System Information Discovery | — | (coberto em Discovery) |
| T0873 | Project File Infection | 3 | Infecção de arquivo de projeto PLC |
| T0874 | Hooking | 1 | Hooking em runtime de CLP |
| T0875 | Change Credential | 3 | Alterar credenciais de acesso |

**Exemplo — T0833 Modify Control Logic:**

```
ixf > ttp T0833 192.168.1.100
[*] TTP T0833 (Modify Control Logic) — 5 módulos — simulate=True
[*] [1/5] exploits/protocols/s7comm/s7comm_program_download
  [SIMULATE MODE]
  Passo 1: Conectar S7comm sem autenticação ao CLP Siemens
  Passo 2: Upload programa CLP atual (backup)
  Passo 3: Modificar OB1 (Main Program) — inserir lógica maliciosa:
           Adicionar timer oculto: após 30 dias, desabilitar saídas
  Passo 4: Download programa modificado ao CLP
  Passo 5: Verificar que CPU executa o programa modificado
  Impacto: Lógica de time bomb — processo para em data futura
  MITRE: T0833, T0843, T0873

[*] [2/5] cve/malware/triton_triconex_safety
  [SIMULATE MODE]
  TRITON/TRISIS — modificar lógica do Triconex Safety System
  Passo 1: Comunicar via TriStation protocolo (porta 1502)
  Passo 2: Upload firmware malicioso ao SIS
  Passo 3: Substituir lógica de safety por código que permite estado inseguro
  Impacto: Sistema de safety desabilitado → processo pode causar dano físico
  MITRE: T0833, T0857, T0879
```

---

### TA0105 — Impact (Impacto)

**Cobertura IXF: 8/11 (72%)**

Técnicas de impacto final — o objetivo do ataque ICS/OT.

| TID | Nome da Técnica | Módulos IXF | Descrição |
|-----|-----------------|-------------|-----------|
| T0813 | Denial of Control | — | (coberto em Inhibit RF) |
| T0815 | Denial of View | 3 | Negação de visibilidade ao operador |
| T0826 | Loss of Availability | 4 | Indisponibilidade de sistemas |
| T0827 | Loss of Control | 5 | Perda de controle do processo |
| T0828 | Loss of Safety | 4 | Perda de sistemas de safety |
| T0829 | Loss of View | 3 | Perda de visibilidade do processo |
| T0837 | Module Firmware | — | (coberto em Persistence) |
| T0879 | Damage to Property | 5 | Dano físico a equipamentos |
| T0880 | Modify Alarm Settings | — | (coberto em Inhibit RF) |
| T0882 | Theft of Operational Information | 3 | Roubo de informações operacionais |
| T0883 | Internet Accessible Device | 2 | Exploração de dispositivos expostos |

**Exemplo — T0879 Damage to Property:**

```
ixf > mitre T0879
[+] 5 module(s) cover T0879:
  use cve/malware/crashoverride_industroyer
  use cve/malware/triton_triconex_safety
  use cve/malware/frostygoop_modbus_heating
  use assessment/mitre_ics/t0879_damage_to_property
  use cve/apt/sandworm_ukraine_2022

ixf > ttp T0879 192.168.1.100
[*] TTP T0879 (Damage to Property) — 5 módulos — simulate=True
[*] [1/5] cve/malware/crashoverride_industroyer
  [SIMULATE MODE]
  Crashoverride/Industroyer (2016) — Sandworm/GRU
  Módulo IEC 60870-5-104:
  Passo 1: Conectar RTU de subestação via IEC 104 (2404/TCP)
  Passo 2: Emitir comando SELECT+EXECUTE para abrir disjuntores
  Passo 3: Bloqueio sequencial de múltiplas subestações
  Módulo wiper:
  Passo 4: Executar KillDisk para sobrescrever MBR dos sistemas Windows de SCADA
  Impacto Físico: Apagão em Kiev — 200.000 residências sem energia por 1 hora
  MITRE: T0879, T0813, T0816

[*] [2/5] cve/malware/triton_triconex_safety
  [SIMULATE MODE]
  TRITON/TRISIS (2017) — Xenotime
  Passo 1: Acesso à estação de engenharia do Triconex SIS
  Passo 2: Upload de TRITON.exe para injetar trojans no firmware do SIS
  Passo 3: Aguardar condição de shutdown de processo
  Passo 4: Impedir que o SIS execute shutdown de segurança → explosão potencial
  Impacto Físico: Refinaria de petróleo no Oriente Médio — quase explosão
  MITRE: T0879, T0828, T0833
```

---

## Aliases de Tática Aceitos

| Tática Canônica | Aliases Aceitos nos Comandos |
|-----------------|------------------------------|
| Initial Access | `initial-access`, `ia`, `initial_access` |
| Execution | `execution`, `exec` |
| Persistence | `persistence`, `persist` |
| Privilege Escalation | `privilege-escalation`, `privesc`, `pe` |
| Evasion | `evasion`, `defense-evasion` |
| Discovery | `discovery`, `disc` |
| Lateral Movement | `lateral-movement`, `lateral`, `lm` |
| Collection | `collection`, `collect` |
| Command and Control | `command-and-control`, `c2`, `c&c`, `cnc` |
| Inhibit Response Function | `inhibit-response-function`, `inhibit`, `irf` |
| Impair Process Control | `impair-process-control`, `impair`, `ipc` |
| Impact | `impact` |

---

## Comandos MITRE no IXF

### Resumo de todos os comandos MITRE

```
ixf > mitre T0843                     # Listar módulos para técnica específica
ixf > mitre-list                      # Listar todas as técnicas com contagem
ixf > mitre-list discovery            # Filtrar por tática
ixf > mitre-scan discovery 192.168.1.0/24  # Varrer tática em sub-rede
ixf > mitre-scan T0843 192.168.1.100  # Varrer técnica em alvo
ixf > mitre-all 192.168.1.100         # Varredura completa (simulate sempre)
ixf > mitre-coverage                  # Percentual de cobertura
ixf > mitre-report layer              # Layer ATT&CK Navigator
ixf > mitre-report html               # Relatório HTML
ixf > mitre-report json               # Relatório JSON
```

### Uso combinado — sessão de avaliação MITRE completa

```
# 1. Ver cobertura disponível
ixf > mitre-coverage

# 2. Descoberta da rede alvo
ixf > mitre-scan discovery 192.168.1.0/24

# 3. Investigar acesso inicial
ixf > mitre-scan initial-access 192.168.1.100

# 4. Verificar execução/modificação de parâmetros
ixf > ttp T0836 192.168.1.100
ixf > ttp T0843 192.168.1.100

# 5. Verificar inibição de resposta
ixf > mitre-scan inhibit 192.168.1.100

# 6. Verificar impacto
ixf > mitre-scan impact 192.168.1.100

# 7. Varredura completa (gerar cobertura total)
ixf > mitre-all 192.168.1.100

# 8. Exportar para ATT&CK Navigator
ixf > mitre-report layer

# 9. Gerar relatório de assessment
ixf > report html
```

---

## Comandos TTP no IXF

Os comandos TTP oferecem controle mais fino sobre execução por técnica individual.

### ttp — Execução completa

```
# Execução básica (simulate por padrão)
ixf > ttp T0843 192.168.1.100

# Com alvo CIDR
ixf > ttp T0836 10.0.0.0/24

# Parar no primeiro resultado
ixf > ttp T0859 192.168.1.100 --stop-on-first

# Salvar resultados
ixf > ttp T0866 192.168.1.100 --output /opt/resultados/t0866.json

# Taxa controlada (ms entre módulos)
ixf > ttp T0878 10.0.0.0/24 --rate-limit 1000

# Modo destrutivo (laboratório autorizado)
ixf > ttp T0836 192.168.1.100 --destructive
```

### ttp-check — Apenas check() (somente leitura)

```
ixf > ttp-check T0843 192.168.1.100
[*] T0843 check-only (sem payloads destrutivos)
[*] [1/12] cve/siemens/cve_2021_22681_... — NOT_VULNERABLE
[*] [2/12] exploits/protocols/s7comm/... — VULNERABLE
[+] T0843 check: 1 possível vulnerabilidade
```

### ttp-simulate — Força simulate

```
ixf > ttp-simulate T0836 192.168.1.100
[*] T0836 simulate forçado em todos os módulos
# Mostra simulação completa de todos os 9 módulos T0836
```

### ttp-list — Índice completo

```
ixf > ttp-list
# Lista todos os TTP-IDs com contagem de módulos

ixf > ttp-list --tactic evasion
# Filtra por tática

ixf > ttp-list --tactic impact
# Mostra apenas técnicas de impacto
```

---

## Módulos de Assessment por Técnica

O IXF inclui 28 módulos de assessment específicos para técnicas MITRE. Esses módulos executam em simulate por padrão e fornecem análise estruturada com cenários de ataque e recomendações de detecção.

```
ixf > use assessment/mitre_ics/t0843_program_upload
ixf > set target 192.168.1.100
ixf > run

  [SIMULATE MODE]
  MITRE T0843: Program Upload — Assessment
  ─────────────────────────────────────────────────────────────

  Cenário de Ataque:
  Passo 1: Conectar à porta de engenharia do CLP (S7comm:102)
  Passo 2: Emitir comando de upload de programa sem autenticação
  Passo 3: Baixar programa CLP completo para arquivo local
  Passo 4: Analisar programa em busca de lógica de safety crítica
  Passo 5: Identificar pontos de injeção para lógica maliciosa

  Detecção Recomendada:
  - SIEM: Alertar em conexões TCP/102 de IPs não-autorizados
  - NSM: Inspecionar conteúdo S7comm — comando Job ID 0x12 (Upload)
  - CLP: Habilitar log de auditoria de acesso de engenharia
  - Rede: Whitelist de IPs autorizados a se conectar na porta 102

  Referência: MITRE ATT&CK for ICS T0843
```

**Lista de módulos de assessment MITRE disponíveis:**

```
assessment/mitre_ics/t0800_activate_firmware_update_mode
assessment/mitre_ics/t0801_monitor_process_state
assessment/mitre_ics/t0802_automated_collection
assessment/mitre_ics/t0806_brute_force_io
assessment/mitre_ics/t0811_data_from_info_repos
assessment/mitre_ics/t0816_device_restart_shutdown
assessment/mitre_ics/t0821_modify_controller_tasking
assessment/mitre_ics/t0831_manipulation_of_control
assessment/mitre_ics/t0833_modify_control_logic
assessment/mitre_ics/t0836_modify_parameter
assessment/mitre_ics/t0838_modify_alarm_settings
assessment/mitre_ics/t0840_network_connection_enum
assessment/mitre_ics/t0843_program_upload
assessment/mitre_ics/t0845_program_upload
assessment/mitre_ics/t0849_masquerading
assessment/mitre_ics/t0851_rootkit
assessment/mitre_ics/t0855_unauthorized_command
assessment/mitre_ics/t0858_remote_system_info
assessment/mitre_ics/t0865_spearphishing
assessment/mitre_ics/t0866_exploitation_remote_services
assessment/mitre_ics/t0873_project_file_infection
assessment/mitre_ics/t0874_hooking
assessment/mitre_ics/t0878_alarm_suppression
assessment/mitre_ics/t0879_damage_to_property
assessment/mitre_ics/t0880_modify_alarm_settings
assessment/mitre_ics/t0882_theft_operational_info
assessment/mitre_ics/t0888_remote_system_discovery
assessment/mitre_ics/t0890_exploitation_privilege_escalation
```

---

## Layer ATT&CK Navigator

O IXF gera layers JSON compatíveis com o ATT&CK Navigator para visualização de cobertura.

### Gerar o layer

```
ixf > mitre-report layer
[+] MITRE report generated: ixf_mitre_layer_20260601_203130.json
[i] Abrir em: https://mitre-attack.github.io/attack-navigator/
[i] Importar o arquivo JSON para visualizar a cobertura com código de cores.
```

### O que o layer contém

O layer JSON gerado inclui:
- Todas as técnicas cobertas pelo IXF marcadas com cor (verde gradiente por cobertura)
- Score de cada técnica = número de módulos IXF que a cobrem
- Comentários com caminhos dos módulos primários
- Metadados de versão e data de geração

### Usar o layer no ATT&CK Navigator

1. Acesse https://mitre-attack.github.io/attack-navigator/
2. Clique em "Open Existing Layer" → "Upload from local"
3. Selecione o arquivo `ixf_mitre_layer_YYYYMMDD.json`
4. Visualize a cobertura do IXF sobre todas as táticas e técnicas

---

## Mapeamento de Malware ICS por Técnica

Os módulos de malware ICS do IXF são mapeados para múltiplas técnicas MITRE:

| Malware | Ano | APT/Grupo | Técnicas MITRE |
|---------|-----|-----------|---------------|
| Stuxnet | 2010 | Unit 8200 (Israel)/TAO (NSA) | T0847, T0843, T0831, T0836 |
| Industroyer/Crashoverride | 2016 | Sandworm/GRU | T0859, T0813, T0816, T0879 |
| TRITON/TRISIS | 2017 | Xenotime (provável Rússia) | T0833, T0857, T0828, T0879 |
| NotPetya | 2017 | Sandworm/GRU | T0809, T0879, T0816 |
| Industroyer2 | 2022 | Sandworm/GRU | T0885, T0813, T0814, T0879 |
| Pipedream/INCONTROLLER | 2022 | Chernovite (provável Rússia) | T0821, T0836, T0843, T0855 |
| FrostyGoop/BUSTLEBERM | 2024 | Provável Rússia | T0836, T0814, T0879 |
| KillDisk (BlackEnergy3) | 2015 | Sandworm/GRU | T0809, T0879, T0816 |

```
ixf > search malware
[+] 26 module(s) found:
  use cve/malware/frostygoop_modbus_heating
  use cve/malware/crashoverride_industroyer
  use cve/malware/industroyer2_iec104
  use cve/malware/triton_triconex_safety
  use cve/malware/pipedream_incontroller
  use cve/malware/stuxnet_centrifuge_attack
  use cve/malware/killdisk_blackenergy3
  use cve/malware/notpetya_mbr_wiper
  use cve/apt/sandworm_ukraine_2022
  …
```

---

## Integração com Relatórios

O mapeamento MITRE é incluído automaticamente em todos os relatórios gerados:

```
ixf > mitre-all 192.168.1.100
ixf > report html
# Relatório HTML inclui:
# - Tabela de cobertura MITRE completa
# - Módulos executados por técnica
# - Resultados de check() por técnica
# - Link para layer ATT&CK Navigator gerado

ixf > mitre-report layer
ixf > mitre-report html
ixf > mitre-report json
```

---

## Casos de Uso por Contexto

### Red Team: Emulação de APT com mapeamento MITRE

```
# Emular TTP do Sandworm (FrostyGoop 2024)
ixf > use cve/malware/frostygoop_modbus_heating
ixf > set target 192.168.1.100
ixf > run    # simulate=True por padrão

# Emular Industroyer2 (Ukraine 2022)
ixf > use cve/malware/industroyer2_iec104
ixf > set target 192.168.1.200
ixf > run

# Gerar relatório de cobertura para o relatório de emulação APT
ixf > mitre-report layer
ixf > report html
```

### Blue Team: Validar capacidades de detecção contra MITRE

```
# Executar todas as técnicas de Discovery em simulate
ixf > mitre-scan discovery 192.168.1.0/24
# → Usar payload hex da saída para criar assinaturas SIEM

# Verificar técnicas de modificação de parâmetro
ixf > ttp-simulate T0836 192.168.1.100
# → Usar descrição para criar casos de uso de detecção

# Verificar cobertura de detecção atual
ixf > mitre-coverage
# → Comparar técnicas detectadas vs não detectadas
```

### Compliance: Mapear avaliação para MITRE

```
# Executar assessment completo
ixf > mitre-all 192.168.1.100
ixf > assess iec62443/zone_conduit_audit
ixf > assess nist_sp800_82/control_checklist

# Gerar evidência de cobertura para auditorias
ixf > mitre-report json
ixf > report json
```

---

*Anterior: [SafeMode / DestructiveMode](05-safemode-destructivemode.md) | Próximo: [SAST / LLM](07-sast-llm.md)*
