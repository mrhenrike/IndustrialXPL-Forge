# Protocolos e Vendors

O IXF cobre 50+ protocolos industriais e 150+ vendors OT/ICS em todo o mundo com módulos de scan, verificação, assessment de segurança e exploração.

---

## Cobertura de Protocolos

| Protocolo | Porta Padrão | Caminho do Módulo | Região / Uso |
|-----------|-------------|-------------------|--------------|
| **Modbus TCP** | 502 | `exploits/protocols/modbus/` | Global — SCADA, CLPs |
| **Siemens S7comm** | 102 | `exploits/protocols/s7comm/` | Siemens S7-200/300/400 |
| **Siemens S7comm+** | 102 | `exploits/protocols/s7comm_plus/` | S7-1200/1500 TLS |
| **EtherNet/IP (CIP)** | 44818 | `exploits/protocols/enip/` | Rockwell, Omron |
| **PROFINET DCP** | Broadcast L2 | `exploits/protocols/profinet/` | Siemens, Beckhoff, WAGO |
| **DNP3** | 20000 | `exploits/protocols/dnp3/` | Redes elétricas, água, petróleo |
| **BACnet/IP** | 47808 UDP | `exploits/protocols/bacnet/` | Automação predial |
| **BACnet/MSTP** | — | `exploits/protocols/bacnet_mstp/` | Redes seriais prediais |
| **IEC 60870-5-104** | 2404 | `exploits/protocols/iec104/` | RTUs de rede elétrica |
| **IEC 61850 MMS** | 102 | `exploits/protocols/iec61850/` | Subestações, relés de proteção |
| **IEC 61850 GOOSE** | L2 multicast | `exploits/protocols/iec61850/` | Intertravamento de relés |
| **OPC UA** | 4840 | `exploits/protocols/opcua/` | Industrial IoT multiplataforma |
| **OPC DA (DCOM)** | 135 | `exploits/protocols/opc_da/` | SCADA Windows legado |
| **OPC HDA** | 135 | `exploits/protocols/opc_hda/` | Acesso a dados históricos |
| **OPC A&E** | 135 | `exploits/protocols/opc_ae/` | Alarmes e eventos |
| **Omron FINS** | 9600 UDP | `exploits/protocols/fins/` | Série Omron CS/CJ/NJ |
| **Unitronics PCOM** | 20256 | `exploits/protocols/pcom/` | CLPs Vision/Unistream |
| **Beckhoff ADS/AMS** | 48898 | `exploits/protocols/ads/` | Runtime TwinCAT |
| **MQTT** | 1883 | `exploits/protocols/mqtt/` | Brokers de mensagens IIoT |
| **SNMP** | 161 UDP | `exploits/protocols/snmp/` | Gerenciamento de rede |
| **PROFIBUS DP** | 1962 (gateway) | `exploits/protocols/profibus/` | Siemens, Beckhoff |
| **PROFIBUS PA** | 1962 (gateway) | `exploits/protocols/profibus_pa/` | Instrumentação de processo |
| **HART** | 5094 (HART-IP) | `exploits/protocols/hart/` | Instrumentos de campo |
| **CANopen** | 4001 (gateway) | `exploits/protocols/canopen/` | Controle de máquina |
| **CC-Link** | 61450 UDP | `exploits/protocols/cc_link/` | Redes Mitsubishi |
| **CC-Link IE Field** | 61450 UDP | `exploits/protocols/cc_link_ie_field/` | Mitsubishi avançado |
| **EtherCAT** | L2 | `exploits/protocols/ethercat/` | Beckhoff, Omron |
| **EtherNet/POWERLINK** | L2 | `exploits/protocols/powerlink/` | B&R, Keba |
| **SERCOS III** | 8008 | `exploits/protocols/sercos/` | CNC/robótica |
| **IO-Link** | — | `exploits/protocols/iolink/` | Sensores/atuadores inteligentes |
| **INTERBUS** | 1962 (gateway) | `exploits/protocols/interbus/` | Phoenix Contact |
| **ControlNet** | 44818 | `exploits/protocols/controlnet/` | Rockwell legado |
| **DeviceNet** | 44818 | `exploits/protocols/devicenet/` | Rockwell baseado em CAN |
| **PCCC** | 44818 | `exploits/protocols/pccc/` | Allen-Bradley SLC-500 |
| **FL-NET (OPCN-2)** | 7000 UDP | `exploits/protocols/fl_net/` | Fuji Electric/JTEKT |
| **CompoNet** | 9600 (gateway) | `exploits/protocols/componet/` | Omron |
| **Yokogawa Vnet/IP** | 20111 | `exploits/protocols/vnetip/` | Yokogawa CENTUM DCS |
| **FOUNDATION Fieldbus H1** | 1089 (HSE) | `exploits/protocols/foundation_fieldbus/` | Emerson, ABB |
| **FOUNDATION Fieldbus HSE** | 1089 | `exploits/protocols/foundation_fieldbus/` | Rede FF high-speed |
| **LonWorks/LonTalk** | 1628 | `exploits/protocols/lonworks/` | Automação predial |
| **KNX/EIB** | 3671 UDP | `exploits/protocols/knx/` | Automação predial |
| **CIP Safety** | 44818 | `exploits/protocols/ethernet_ip_cip_safety/` | Rockwell GuardLogix |
| **PROFIsafe** | 502 | `exploits/protocols/profisafe/` | Camada de safety PROFIBUS |
| **FSoE** | L2 | `exploits/protocols/fsoe/` | Beckhoff TwinSAFE |
| **SECS/GEM (HSMS)** | 5000 | `exploits/protocols/hsms/` | Fábricas de semicondutores |
| **Serial-to-Ethernet** | 4001 | `exploits/protocols/serial/` | Moxa NPort, Lantronix |
| **Auditoria OPC UA** | 4840 | Módulo assessment | Verificação SecurityMode |
| **Auditoria DNP3** | 20000 | Módulo assessment | Verificação SAv5 |
| **Auditoria IEC 61850** | 102 | Módulo assessment | Auditoria GOOSE/MMS |

---

## Cobertura de Vendors

### Usando o Comando `vendors`

```
ixf > vendors
  Vendors (150 cobertos)
  ───────────────────────────────────────────────────
  Vendor                       Módulos CVE
  schneider_electric                39
  rockwell_automation               38
  siemens                           27
  honeywell                         20
  ...

ixf > vendors brasil
  Vendors (7 cobertos)
  WEG                               2
  ALTUS                             1
  Novus                             1
  Elipse Software                   2
  Smar                              1
  Digicon                           1
  Coel                              1
```

### Cobertura por Região

**Europa** — Siemens, Schneider, ABB, Beckhoff, Phoenix Contact, WAGO, Pilz, B&R, Festo, Endress+Hauser, Pepperl+Fuchs, SICK AG, HMS Networks, Belden/Hirschmann, Westermo, Ruggedcom, Metso, Danfoss, Krohne, Lenze, Hilscher, Softing, Saia-Burgess, Sauter AG, Distech Controls, Sofrel

**Américas** — Rockwell Automation, Honeywell, Emerson, GE/GE Vernova, Inductive Automation, Tridium, AVEVA/OSIsoft, AspenTech, AutomationDirect, Red Lion, Opto 22, ProSoft, Bedrock Automation, S&C Electric, Compressor Controls, Flowserve, Weatherford, Sierra Wireless, Delta Controls, Automated Logic, KMC Controls, Grundfos, Westinghouse, WEG, ALTUS, Novus, Elipse, Smar, Digicon

**Ásia-Pacífico** — Yokogawa, Omron, Mitsubishi Electric, FANUC, Yaskawa, Keyence, Panasonic, Fuji Electric, Weintek, Delta Electronics, Fatek, Vigor, LS Electric, Hollysys, Supcon, Inovance, INVT, CHINT, Kinco, Delixi, STEP Electric, HIWIN

**Energia/Rede Elétrica** — Schweitzer Engineering (SEL), Alstom/GE Power, Hitachi Energy, GE Multilin, Landis+Gyr, Itron

**Especialidades** — PTC/ThingWorx, Cisco (IR/IE), Teltonika, Framatome, Wabtec, Thales

---

## Brasil e América Latina — Destaque

O IXF possui cobertura específica para os principais vendors OT/SCADA do Brasil:

| Vendor | Produtos | CVEs |
|--------|---------|------|
| **WEG** | CFW-11 VFD, Motor Scan IIoT | 2 |
| **ALTUS** | Série Duo PLC | 1 |
| **Novus** | Controladores de temperatura | 1 |
| **Elipse Software** | E3 SCADA, Epics Historian | 2 |
| **Smar** | ProcessView SCADA, Fieldbus | 1 |
| **Digicon** | Concentradores de dados RTU | 1 |
| **Coel** | Controladores industriais | 1 |

---

*Anterior: [SAST / LLM](07-sast-llm.md) | Próximo: [Desenvolvimento de Módulos](09-desenvolvimento-modulos.md)*
