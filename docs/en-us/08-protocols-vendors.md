# Protocols & Vendors

IXF covers 50+ industrial protocols and 150+ OT/ICS vendors worldwide with scan, check, security assessment, and exploit modules.

---

## Protocol Coverage

All 50 protocols have at least one module under `exploits/protocols/` or `scanners/ics/`.

| Protocol | Default Port | Module Path | Region / Usage |
|----------|-------------|-------------|----------------|
| **Modbus TCP** | 502 | `exploits/protocols/modbus/` | Global — SCADA, PLCs |
| **Modbus RTU** | — | `exploits/protocols/modbus/` | Serial devices via gateways |
| **Siemens S7comm** | 102 | `exploits/protocols/s7comm/` | Siemens S7-200/300/400 |
| **Siemens S7comm+** | 102 | `exploits/protocols/s7comm_plus/` | S7-1200/1500 TLS variant |
| **EtherNet/IP (CIP)** | 44818 | `exploits/protocols/enip/` | Rockwell, Omron, generic |
| **PROFINET DCP** | Broadcast L2 | `exploits/protocols/profinet/` | Siemens, Beckhoff, WAGO |
| **DNP3** | 20000 | `exploits/protocols/dnp3/` | Power grids, water, oil & gas |
| **BACnet/IP** | 47808 UDP | `exploits/protocols/bacnet/` | Building automation |
| **BACnet/MSTP** | — | `exploits/protocols/bacnet_mstp/` | Building serial networks |
| **IEC 60870-5-104** | 2404 | `exploits/protocols/iec104/` | Power grid RTUs |
| **IEC 61850 MMS** | 102 | `exploits/protocols/iec61850/` | Substations, protection relays |
| **IEC 61850 GOOSE** | L2 multicast | `exploits/protocols/iec61850/` | Protection relay interlocking |
| **OPC UA** | 4840 | `exploits/protocols/opcua/` | Cross-platform industrial IoT |
| **OPC DA (DCOM)** | 135 | `exploits/protocols/opc_da/` | Legacy Windows SCADA |
| **OPC HDA** | 135 | `exploits/protocols/opc_hda/` | Historical data access |
| **OPC A&E** | 135 | `exploits/protocols/opc_ae/` | Alarms & events |
| **Omron FINS** | 9600 UDP | `exploits/protocols/fins/` | Omron CS/CJ/NJ series |
| **Unitronics PCOM** | 20256 | `exploits/protocols/pcom/` | Vision/Unistream PLCs |
| **Beckhoff ADS/AMS** | 48898 | `exploits/protocols/ads/` | TwinCAT runtime |
| **MQTT** | 1883 | `exploits/protocols/mqtt/` | IIoT messaging brokers |
| **SNMP** | 161 UDP | `exploits/protocols/snmp/` | Network management |
| **PROFIBUS DP** | 1962 (gateway) | `exploits/protocols/profibus/` | Siemens, Beckhoff |
| **PROFIBUS PA** | 1962 (gateway) | `exploits/protocols/profibus_pa/` | Process instrumentation |
| **HART** | 5094 (HART-IP) | `exploits/protocols/hart/` | Field instruments |
| **CANopen** | 4001 (gateway) | `exploits/protocols/canopen/` | Machine control |
| **CC-Link** | 61450 UDP | `exploits/protocols/cc_link/` | Mitsubishi networks |
| **CC-Link IE Field** | 61450 UDP | `exploits/protocols/cc_link_ie_field/` | Mitsubishi advanced |
| **EtherCAT** | L2 | `exploits/protocols/ethercat/` | Beckhoff, Omron |
| **EtherNet/POWERLINK** | L2 | `exploits/protocols/powerlink/` | B&R, Keba |
| **SERCOS III** | 8008 | `exploits/protocols/sercos/` | CNC/robotics motion |
| **IO-Link** | — | `exploits/protocols/iolink/` | Smart sensors/actuators |
| **INTERBUS** | 1962 (gateway) | `exploits/protocols/interbus/` | Phoenix Contact |
| **ControlNet** | 44818 | `exploits/protocols/controlnet/` | Rockwell legacy |
| **DeviceNet** | 44818 | `exploits/protocols/devicenet/` | Rockwell CAN-based |
| **PCCC** | 44818 | `exploits/protocols/pccc/` | Allen-Bradley SLC-500 |
| **FL-NET (OPCN-2)** | 7000 UDP | `exploits/protocols/fl_net/` | Fuji Electric/JTEKT |
| **CompoNet** | 9600 (gateway) | `exploits/protocols/componet/` | Omron |
| **Yokogawa Vnet/IP** | 20111 | `exploits/protocols/vnetip/` | Yokogawa CENTUM DCS |
| **FOUNDATION Fieldbus H1** | 1089 (HSE) | `exploits/protocols/foundation_fieldbus/` | Emerson, ABB |
| **FOUNDATION Fieldbus HSE** | 1089 | `exploits/protocols/foundation_fieldbus/` | FF high-speed network |
| **LonWorks/LonTalk** | 1628 | `exploits/protocols/lonworks/` | Building automation |
| **KNX/EIB** | 3671 UDP | `exploits/protocols/knx/` | Building automation |
| **CIP Safety** | 44818 | `exploits/protocols/ethernet_ip_cip_safety/` | Rockwell GuardLogix |
| **PROFIsafe** | 502 | `exploits/protocols/profisafe/` | PROFIBUS safety layer |
| **FSoE** | L2 | `exploits/protocols/fsoe/` | Beckhoff TwinSAFE |
| **SECS/GEM (HSMS)** | 5000 | `exploits/protocols/hsms/` | Semiconductor fabs |
| **Serial-to-Ethernet** | 4001 | `exploits/protocols/serial/` | Moxa NPort, Lantronix |
| **SNMP OT** | 161 UDP | `exploits/protocols/snmp/` | OT device management |
| **DNP3 Security Auth** | 20000 | Assessment module | SAv5 implementation check |
| **OPC UA Security** | 4840 | Assessment module | SecurityMode audit |
| **IEC 61850 Security** | 102 | Assessment module | GOOSE/MMS auth audit |

---

## Vendor Coverage

### Using the `vendors` Command

```
ixf > vendors
  Vendors (150 covered)
  ───────────────────────────────────────────────────
  Vendor                       CVE Modules
  schneider_electric                39
  rockwell_automation               38
  siemens                           27
  honeywell                         20
  emerson                           16
  ge / ge_vernova                   18
  abb                               22
  aveva / osisoft                   14
  advantech                         15
  ...

ixf > vendors japan
  Vendors (7 covered)
  ───────────────────────────────────────────────────
  Yokogawa                           5
  Mitsubishi Electric                3
  Omron                             12
  Keyence                            2
  FANUC                              2
  Panasonic                          1
  Fuji Electric                      2
```

### Vendor Coverage by Region

**Europe**

| Vendor | Country | Key Products | CVEs |
|--------|---------|--------------|------|
| Siemens | Germany | S7-1200/1500, WinCC, PCS 7, SCALANCE, Desigo CC | 27 |
| Schneider Electric | France | Modicon M340/M580, EcoStruxure | 39 |
| ABB | Switzerland | System 800xA, AC500, Relion relays | 22 |
| Beckhoff | Germany | TwinCAT, EtherCAT | 5 |
| Phoenix Contact | Germany | PLCnext, WebVisit HMI | 6 |
| WAGO | Germany | PFC100/PFC200 | 2 |
| Pilz | Germany | PNOZmulti, PSS4000 Safety | 1 |
| B&R Automation | Austria | APROL DCS, X20, ctrlX | 2 |
| Festo | Germany | CPX-AP-I, AX | 1 |
| Endress+Hauser | Switzerland | Fieldgate, VEGAPULS | 2 |
| Pepperl+Fuchs | Germany | IO-Link Masters | 1 |
| SICK AG | Germany | S3000 safety scanners | 2 |
| HMS Networks | Sweden | Anybus X-Gateway, eWON Flexy | 2 |
| Belden/Hirschmann | Germany | Eagle One firewall, RSPE switches | 2 |
| Westermo | Sweden | Lynx industrial switches | 1 |
| Ruggedcom (Siemens) | Germany | ROS/ROX II routers | 2 |
| Metso/Valmet | Finland | DNA DCS | 1 |
| Danfoss | Denmark | VLT/VACON drives | 1 |
| Krohne | Germany | SUMMIT flow computers | 2 |
| Lenze | Germany | i550 drives | 1 |
| Hilscher | Germany | netX/cifX fieldbus | 1 |
| Softing | Germany | DataFEED OPC, OT Security Box | 2 |
| Saia-Burgess | Switzerland | PCD Series PLC | 1 |
| Sauter AG | Switzerland | moduWeb Vision BAS | 1 |
| Distech Controls | France | ECLYPSE BACnet | 1 |
| Sofrel | France | LS-4x water RTU | 1 |

**Americas**

| Vendor | Country | Key Products | CVEs |
|--------|---------|--------------|------|
| Rockwell Automation | USA | ControlLogix, FactoryTalk, Studio 5000 | 38 |
| Honeywell | USA | Experion PKS, Spyder BAS, Enraf | 20 |
| Emerson | USA | DeltaV DCS, ROC800, Fisher valves | 16 |
| GE / GE Vernova | USA | CIMPLICITY, iFIX, Grid Solutions | 18 |
| Inductive Automation | USA | Ignition SCADA | 5 |
| Tridium | USA | Niagara 4 Framework | 5 |
| AVEVA / OSIsoft | USA | System Platform, PI Historian | 14 |
| AspenTech | USA | Aspen InfoPlus.21 historian | 1 |
| AutomationDirect | USA | CLICK PLCs, DirectLogix | 1 |
| Red Lion Controls | USA | Crimson 3.x HMI/SCADA | 1 |
| Opto 22 | USA | groov EPIC, groov RIO | 1 |
| ProSoft Technology | USA | RadioLinx, ICX35 | 2 |
| Bedrock Automation | USA | Open Secure PLC | 1 |
| Moore Industries | USA | SPC signal processors | 1 |
| Sensata | USA | Beacon RTU | 1 |
| S&C Electric | USA | PureWave/GeoScale power switching | 1 |
| Compressor Controls | USA | TurboControl MkV gas turbine | 1 |
| Flowserve | USA | PumpWorks controllers | 1 |
| Weatherford | USA | CygNet SCADA | 1 |
| Sierra Wireless | Canada | AirLink industrial routers | 1 |
| Delta Controls | Canada | ORCAview BAS | 1 |
| Automated Logic | USA | WebCTRL BAS | 1 |
| KMC Controls | USA | Commander BACnet | 1 |
| Grundfos | Denmark/USA | CUE pump drives | 2 |
| Westinghouse | USA | Common Q Nuclear I&C | 1 |
| WEG | Brazil | CFW-11 VFD, Motor Scan | 2 |
| ALTUS | Brazil | Duo PLC series | 1 |
| Novus | Brazil | Temperature controllers | 1 |
| Elipse Software | Brazil | E3 SCADA, Epics | 2 |
| Smar | Brazil | ProcessView SCADA | 1 |
| Digicon | Brazil | RTU data concentrators | 1 |

**Asia-Pacific**

| Vendor | Country | Key Products | CVEs |
|--------|---------|--------------|------|
| Yokogawa | Japan | CENTUM VP, FAST/TOOLS, STARDOM | 5 |
| Omron | Japan | NX/NJ controllers, CJ2M, CP2E | 12 |
| Mitsubishi Electric | Japan | MELSEC iQ-R/Q, GENESIS64, MELSOFT | 3 |
| FANUC | Japan | CNC, Robot Controllers | 2 |
| Yaskawa | Japan | Sigma-7 servo, MP3300 controller | 2 |
| Keyence | Japan | KV Series PLCs | 2 |
| Panasonic | Japan | FP7 PLCs | 1 |
| Fuji Electric | Japan | MICREX-SX, Monitouch HMI | 2 |
| JTEKT | Japan | TOYOPUC PLCs | 2 |
| HIWIN | Taiwan | MC Series motion controllers | 1 |
| Weintek | Taiwan | cMT HMI, EasyBuilder Pro | 2 |
| Delta Electronics | Taiwan | DIAEnergie, AS-series, DVP | 11 |
| Fatek Automation | Taiwan | FBS Series PLCs | 2 |
| Vigor | Taiwan | VH Series PLCs | 1 |
| LS Electric | Korea | XGK/XGI Series PLCs | 1 |
| Hollysys | China | MACS-S DCS, HolliField | 2 |
| Supcon | China | JX-300XP DCS | 1 |
| Inovance | China | AM600 PLCs | 1 |
| INVT | China | Goodrive VFD | 1 |
| CHINT | China | NTCP smart circuit breakers | 1 |
| Kinco | China | K5 Series PLCs | 1 |
| Delixi | China | CDN PLC series | 1 |
| STEP Electric | China | AC301E VFD | 1 |
| Kongsberg | Norway | K-Pos dynamic positioning | 1 |

**Energy / Power Grid**

| Vendor | Key Products |
|--------|--------------|
| Schweitzer Engineering (SEL) | Protection relays, SEL-5037, SEL-5056 |
| Alstom / GE Power | P40 Agile protection relays |
| Hitachi Energy (ABB) | RTU500, Relion 670 protection |
| GE Multilin | 850F protection relay |
| Landis+Gyr | E360 smart meters |
| Itron | Riva C smart meters |

**Specialized / Other**

| Vendor | Category |
|--------|---------|
| PTC / ThingWorx | IIoT platform |
| Cisco (IR800/IE3400) | Industrial networking |
| Teltonika | Industrial cellular routers |
| Framatome | Nuclear I&C (TELEPERM XP) |
| Wabtec | Railway SCADA |
| Thales | Critical infrastructure SCADA |

---

## Adding Coverage for a New Vendor

To scan a new vendor's devices:

```
# Use the generic modbus scanner
ixf > use scanners/ics/modbus_scanner
ixf > set target 192.168.1.0/24
ixf > run

# Or use a protocol-specific scanner
ixf > use scanners/ics/s7_comm_scanner
ixf > set target 192.168.1.100

# Check for default credentials
ixf > search default_creds
ixf > use creds/generic/http_default
```

---

*Previous: [SAST / LLM Analysis](07-sast-llm.md) | Next: [Module Development](09-module-development.md)*
