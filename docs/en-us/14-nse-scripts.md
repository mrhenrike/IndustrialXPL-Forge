# NSE Scripts Reference

IXF ships 8 custom Nmap Scripting Engine (NSE) scripts for ICS/OT protocol detection, device fingerprinting, and vulnerability scanning. These scripts extend standard Nmap with deep OT protocol knowledge and integrate with the IXF module ecosystem.

---

## Table of Contents

1. [Overview and Installation Requirements](#overview-and-installation-requirements)
2. [nse status — Full Terminal Output](#nse-status--full-terminal-output)
3. [nse list — Full Terminal Output](#nse-list--full-terminal-output)
4. [nse install — Full Terminal Output](#nse-install--full-terminal-output)
5. [nse install --force — When to Use](#nse-install---force--when-to-use)
6. [NSE Script Reference](#nse-script-reference)
   - [ixf-modbus-detect](#1-ixf-modbus-detect)
   - [ixf-s7comm-info](#2-ixf-s7comm-info)
   - [ixf-enip-list-identity](#3-ixf-enip-list-identity)
   - [ixf-bacnet-discover](#4-ixf-bacnet-discover)
   - [ixf-dnp3-detect](#5-ixf-dnp3-detect)
   - [ixf-iec104-detect](#6-ixf-iec104-detect)
   - [ixf-opcua-info](#7-ixf-opcua-info)
   - [ixf-ics-cve-check](#8-ixf-ics-cve-check)
7. [Combined Scan Examples](#combined-scan-examples)
8. [Integration with IXF Workflow](#integration-with-ixf-workflow)
9. [Writing Custom NSE Scripts](#writing-custom-nse-scripts)
10. [Troubleshooting](#troubleshooting)

---

## Overview and Installation Requirements

IXF NSE scripts are Lua files stored in `nse/scripts/`. They follow the standard NSE API and are installed into Nmap's script directory for use with `nmap --script`.

**Requirements:**

| Requirement | Version | Check Command |
|-------------|---------|--------------|
| Nmap | 7.80+ | `nmap --version` |
| Nmap NSE scripting engine | Included with Nmap | `nmap --script-help` |
| Root/Administrator | Required for raw socket operations | `sudo` on Linux |
| Python 3.9+ (for IXF integration) | Optional | `python --version` |

**Script files location (after install):**

| OS | Nmap Scripts Directory |
|----|----------------------|
| Linux | `/usr/share/nmap/scripts/` |
| macOS (Homebrew) | `/usr/local/share/nmap/scripts/` |
| Windows | `C:\Program Files (x86)\Nmap\scripts\` |

**Important:** NSE scripts send real network packets. Run only against authorized targets. Use `--simulate` flag in IXF modules (not Nmap) for simulation. Nmap NSE has no simulation mode.

---

## nse status — Full Terminal Output

```bash
ixf nse status
```

**Full output:**

```
[IXF NSE Scripts Status]
════════════════════════════════════════════════════════════

[Nmap availability]
  nmap        OK         Nmap 7.94 ( https://nmap.org ) — 2023-05-19

[Script directory]
  Linux:      /usr/share/nmap/scripts/
  Status:     WRITABLE (install will succeed)

[IXF NSE Scripts]
  Script                     Version  Status      Location
  ──────────────────────────────────────────────────────────────
  ixf-modbus-detect.nse      1.3.0    NOT INSTALLED  nse/scripts/
  ixf-s7comm-info.nse        1.2.1    NOT INSTALLED  nse/scripts/
  ixf-enip-list-identity.nse 1.1.0    NOT INSTALLED  nse/scripts/
  ixf-bacnet-discover.nse    1.0.5    NOT INSTALLED  nse/scripts/
  ixf-dnp3-detect.nse        1.1.2    NOT INSTALLED  nse/scripts/
  ixf-iec104-detect.nse      1.0.3    NOT INSTALLED  nse/scripts/
  ixf-opcua-info.nse         1.2.0    NOT INSTALLED  nse/scripts/
  ixf-ics-cve-check.nse      2.0.1    NOT INSTALLED  nse/scripts/
  ──────────────────────────────────────────────────────────────

[Action required]
  Run: ixf nse install
  Or with sudo: sudo ixf nse install

════════════════════════════════════════════════════════════
```

After installation:

```
[IXF NSE Scripts]
  Script                     Version  Status      Location
  ──────────────────────────────────────────────────────────────
  ixf-modbus-detect.nse      1.3.0    INSTALLED   /usr/share/nmap/scripts/
  ixf-s7comm-info.nse        1.2.1    INSTALLED   /usr/share/nmap/scripts/
  ixf-enip-list-identity.nse 1.1.0    INSTALLED   /usr/share/nmap/scripts/
  ixf-bacnet-discover.nse    1.0.5    INSTALLED   /usr/share/nmap/scripts/
  ixf-dnp3-detect.nse        1.1.2    INSTALLED   /usr/share/nmap/scripts/
  ixf-iec104-detect.nse      1.0.3    INSTALLED   /usr/share/nmap/scripts/
  ixf-opcua-info.nse         1.2.0    INSTALLED   /usr/share/nmap/scripts/
  ixf-ics-cve-check.nse      2.0.1    INSTALLED   /usr/share/nmap/scripts/
  ──────────────────────────────────────────────────────────────
  All 8 scripts installed and up to date.
  script-updatedb: DONE

[Test command]
  nmap --script ixf-modbus-detect -p 502 <target>
════════════════════════════════════════════════════════════
```

---

## nse list — Full Terminal Output

```bash
ixf nse list
```

**Full output:**

```
[IXF NSE Script Catalog]
════════════════════════════════════════════════════════════
  #   Script Name                Protocol    Port(s)   Category
  ────────────────────────────────────────────────────────────────────
  1   ixf-modbus-detect          Modbus TCP  502       discovery
      Detect Modbus TCP devices, read device ID, enumerate unit IDs.

  2   ixf-s7comm-info            S7comm      102       discovery
      Fingerprint Siemens S7 PLCs: CPU type, firmware, serial number.

  3   ixf-enip-list-identity     EtherNet/IP 44818     discovery
      Send CIP List Identity request, parse vendor, product, revision.

  4   ixf-bacnet-discover        BACnet/IP   47808     discovery
      Who-Is broadcast, parse I-Am responses, read device object name.

  5   ixf-dnp3-detect            DNP3        20000     discovery
      DNP3 Link Status probe, detect master/outstation response.

  6   ixf-iec104-detect          IEC 104     2404      discovery
      STARTDT + General Interrogation, parse RTU data object count.

  7   ixf-opcua-info             OPC UA      4840      discovery
      GetEndpoints, list security modes, detect anonymous access.

  8   ixf-ics-cve-check          Multi       Various   vuln
      Banner fingerprint and version → IXF CVE database lookup.
  ────────────────────────────────────────────────────────────────────

[Usage]
  nmap --script <name> [script-args] -p <port> <target>
  nmap --script ixf-modbus-detect -p 502 192.168.1.100
  nmap --script ixf-s7comm-info --script-args s7.rack=0,s7.slot=1 -p 102 192.168.1.100

[Documentation]
  nmap --script-help ixf-modbus-detect
  nmap --script-help all | grep ixf-

════════════════════════════════════════════════════════════
```

---

## nse install — Full Terminal Output

```bash
sudo ixf nse install
```

**Full output (success case):**

```
[IXF NSE Scripts — Installation]
════════════════════════════════════════════════════════════

[Nmap detection]
  [OK] nmap found: /usr/bin/nmap (Nmap 7.94)
  [OK] Script directory: /usr/share/nmap/scripts/
  [OK] Directory writable

[Copying scripts]
  [OK] ixf-modbus-detect.nse      → /usr/share/nmap/scripts/ixf-modbus-detect.nse
  [OK] ixf-s7comm-info.nse        → /usr/share/nmap/scripts/ixf-s7comm-info.nse
  [OK] ixf-enip-list-identity.nse → /usr/share/nmap/scripts/ixf-enip-list-identity.nse
  [OK] ixf-bacnet-discover.nse    → /usr/share/nmap/scripts/ixf-bacnet-discover.nse
  [OK] ixf-dnp3-detect.nse        → /usr/share/nmap/scripts/ixf-dnp3-detect.nse
  [OK] ixf-iec104-detect.nse      → /usr/share/nmap/scripts/ixf-iec104-detect.nse
  [OK] ixf-opcua-info.nse         → /usr/share/nmap/scripts/ixf-opcua-info.nse
  [OK] ixf-ics-cve-check.nse      → /usr/share/nmap/scripts/ixf-ics-cve-check.nse

[Updating script database]
  [OK] nmap --script-updatedb (script.db updated)

[Verification]
  [OK] All 8 scripts registered in Nmap script database
  [OK] Test: nmap --script-help ixf-modbus-detect

════════════════════════════════════════════════════════════
[+] IXF NSE installation complete.

[Quick test commands]
  nmap --script ixf-modbus-detect -p 502 192.168.1.100
  nmap --script ixf-s7comm-info -p 102 192.168.1.100
  nmap --script ixf-enip-list-identity -p 44818 192.168.1.100
  nmap --script ixf-bacnet-discover -p U:47808 192.168.1.255
  nmap --script ixf-ics-cve-check -p 80,102,502,4840,44818 192.168.1.100

[Run all IXF scripts on a target]
  nmap --script "ixf-*" -p 21,22,23,80,102,502,1217,2404,4840,20000,44818,47808 \
       192.168.1.100
════════════════════════════════════════════════════════════
```

---

## nse install --force — When to Use

```bash
sudo ixf nse install --force
```

Use `--force` when:

- Scripts are already installed but you want to overwrite with newer versions
- A previous install was incomplete (partial copy)
- The script database (`script.db`) is out of sync
- You reinstalled Nmap and the scripts were removed
- `nmap --script ixf-modbus-detect` reports "No such script"

**Output (force mode):**

```
[IXF NSE Scripts — Force Reinstall]
  [FORCE] Overwriting existing scripts even if up to date.
  [OK] ixf-modbus-detect.nse      → /usr/share/nmap/scripts/ (overwritten)
  [OK] ixf-s7comm-info.nse        → /usr/share/nmap/scripts/ (overwritten)
  [OK] ixf-enip-list-identity.nse → /usr/share/nmap/scripts/ (overwritten)
  [OK] ixf-bacnet-discover.nse    → /usr/share/nmap/scripts/ (overwritten)
  [OK] ixf-dnp3-detect.nse        → /usr/share/nmap/scripts/ (overwritten)
  [OK] ixf-iec104-detect.nse      → /usr/share/nmap/scripts/ (overwritten)
  [OK] ixf-opcua-info.nse         → /usr/share/nmap/scripts/ (overwritten)
  [OK] ixf-ics-cve-check.nse      → /usr/share/nmap/scripts/ (overwritten)
  [OK] nmap --script-updatedb
[+] Force reinstall complete.
```

---

## NSE Script Reference

### 1. ixf-modbus-detect

**Description:** Detects Modbus TCP devices by sending a Function Code 04 (Read Input Registers) probe and validating the Transaction ID echo in the MBAP response header. Optionally queries FC43/MEI (Read Device Identification) to extract vendor name, product code, and firmware revision from devices that support the MEI extension (IEC 61158-6).

**Syntax:**

```
nmap --script ixf-modbus-detect [--script-args modbus.unit=<id>,modbus.identify=true] -p 502 <target>
```

**Arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| `modbus.unit` | `1` | Modbus unit ID to probe (1–247) |
| `modbus.identify` | `false` | Send FC43 MEI device identification request |
| `modbus.timeout` | `5` | Socket timeout in seconds |
| `modbus.registers` | `1` | Number of input registers to read in FC04 probe |

**Example with full Nmap output:**

```bash
nmap --script ixf-modbus-detect --script-args modbus.identify=true -p 502 192.168.1.100
```

**Output:**

```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-01 18:25 UTC
Nmap scan report for 192.168.1.100
Host is up (0.00042s latency).

PORT    STATE SERVICE
502/tcp open  modbus

Host script results:
| ixf-modbus-detect:
|   Modbus TCP device detected
|   Unit ID:      1
|   Protocol:     Modbus TCP (MBAP header validated)
|   FC04 probe:   OK (Transaction ID echo: 0x0001)
|   Device Identification (FC43 MEI):
|     VendorName:         Schneider Electric
|     ProductCode:        TSXP574634M
|     MajorMinorRevision: V4.3
|   IXF module:  use scanners/ics/modbus_detect
|_  MITRE:       T0888 (Remote System Information Discovery)

Nmap done: 1 IP address (1 host up) scanned in 1.23 seconds
```

---

### 2. ixf-s7comm-info

**Description:** Fingerprints Siemens SIMATIC S7 PLCs by establishing a COTP (ISO 8073) connection followed by an S7comm Setup Communication PDU. On success, sends SZL-SSL read requests to extract CPU identification, module identification, firmware version, serial number, order number, and plant identification. Works against S7-300, S7-400, S7-1200, and S7-1500 series.

**Syntax:**

```
nmap --script ixf-s7comm-info [--script-args s7.rack=<n>,s7.slot=<n>] -p 102 <target>
```

**Arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| `s7.rack` | `0` | CPU rack number (0–7) |
| `s7.slot` | `1` | CPU slot number (0–31) |
| `s7.pdu_size` | `240` | PDU size for Setup Communication negotiation |
| `s7.timeout` | `5` | Socket timeout in seconds |
| `s7.get_szl` | `true` | Read SZL-SSL system status lists |

**Example with full Nmap output:**

```bash
nmap --script ixf-s7comm-info --script-args s7.rack=0,s7.slot=1 -p 102 192.168.1.50
```

**Output:**

```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-01 18:26 UTC
Nmap scan report for 192.168.1.50
Host is up (0.00031s latency).

PORT    STATE SERVICE
102/tcp open  iso-tsap

Host script results:
| ixf-s7comm-info:
|   Siemens S7 PLC detected
|   COTP Connection:  OK (CC TPDU received)
|   S7 Setup Comm:    OK (PDU size negotiated: 240 bytes)
|   SZL-SSL Results:
|     Module Identification:
|       Order number:     6ES7 215-1AG40-0XB0
|       Hardware version: V03
|       Firmware version: V4.4.0
|     CPU Identification:
|       Module type name: CPU 1215C DC/DC/DC
|       Serial number:    S C-X6BH70523
|       CPU type:         SIMATIC S7-1200
|     Plant Identification:
|       Plant ID:         (not set)
|       Module name:      PLC_1
|     Rack/Slot:          0 / 1
|   IXF module:  use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
|_  MITRE:       T0888, T0843

Nmap done: 1 IP address (1 host up) scanned in 2.14 seconds
```

---

### 3. ixf-enip-list-identity

**Description:** Sends a CIP (Common Industrial Protocol) List Identity request as a UDP broadcast or directed TCP packet to discover EtherNet/IP compatible devices. Parses the List Identity response to extract vendor ID, device type, product code, revision, serial number, product name, and current device state. Vendor IDs are mapped to the ODVA vendor registry for human-readable names.

**Syntax:**

```
nmap --script ixf-enip-list-identity [--script-args enip.broadcast=false] -p 44818 <target>
```

**Arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| `enip.broadcast` | `false` | Send to broadcast address (useful for subnet discovery) |
| `enip.timeout` | `3` | Response timeout in seconds |
| `enip.list_services` | `false` | Also send List Services request |

**Example with full Nmap output:**

```bash
nmap --script ixf-enip-list-identity -p 44818 192.168.1.200
```

**Output:**

```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-01 18:27 UTC
Nmap scan report for 192.168.1.200
Host is up (0.00051s latency).

PORT      STATE SERVICE
44818/tcp open  EtherNet/IP-2

Host script results:
| ixf-enip-list-identity:
|   EtherNet/IP CIP device detected
|   Vendor:       Rockwell Automation/Allen-Bradley (Vendor ID: 0x0001)
|   Device Type:  Programmable Logic Controller
|   Product Code: 0x006E (Logix 5340)
|   Revision:     32.011
|   Serial Number: 0x64A3F821
|   Product Name: "1756-L81ES/B LOGIX5381S"
|   State:        Running (0x03)
|   CIP Services: Connected Messaging, Unconnected Messaging
|   IXF module:  use cve/rockwell/cve_2021_27478_logix_hardcoded
|_  MITRE:       T0888

Nmap done: 1 IP address (1 host up) scanned in 0.89 seconds
```

---

### 4. ixf-bacnet-discover

**Description:** Sends BACnet Who-Is broadcast requests and parses I-Am responses to discover BACnet/IP devices on the network. For each discovered device, optionally reads the Device object properties: Object_Name, Vendor_Name, Model_Name, Firmware_Revision, Application_Software_Version, and Description. Supports directed broadcast for subnet scanning and unicast for directed probes.

**Syntax:**

```
nmap --script ixf-bacnet-discover [--script-args bacnet.read_properties=true] -p U:47808 <target>
```

**Arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| `bacnet.read_properties` | `false` | Read device object properties after discovery |
| `bacnet.low_limit` | `0` | Instance range low limit for Who-Is |
| `bacnet.high_limit` | `4194302` | Instance range high limit for Who-Is |
| `bacnet.timeout` | `3` | Response collection timeout in seconds |

**Example with full Nmap output:**

```bash
nmap --script ixf-bacnet-discover --script-args bacnet.read_properties=true -p U:47808 192.168.1.255
```

**Output:**

```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-01 18:28 UTC

Host script results:
| ixf-bacnet-discover:
|   BACnet/IP devices discovered: 3
|
|   Device 1 — 192.168.1.150:47808
|     Object Identifier: Device 12345
|     Object Name:        "AHU-01-Controller"
|     Vendor Name:        "Johnson Controls"
|     Model Name:         "Metasys NCE25-3001-0"
|     Firmware Revision:  "9.0.2"
|     Application Version: "9.0"
|     Description:        "Air Handling Unit 01"
|
|   Device 2 — 192.168.1.151:47808
|     Object Identifier: Device 22100
|     Object Name:        "VAV-Box-Floor-3"
|     Vendor Name:        "Siemens Building Technologies"
|     Model Name:         "PXC36-E.D"
|     Firmware Revision:  "4.5.1"
|     Application Version: "4.5"
|
|   Device 3 — 192.168.1.152:47808
|     Object Identifier: Device 54321
|     Object Name:        "Chiller-Plant-Controller"
|     Vendor Name:        "Schneider Electric"
|     Model Name:         "SmartX AS-P"
|     Firmware Revision:  "2.3.0"
|
|   IXF module:  use scanners/ics/bacnet_scanner
|_  MITRE:       T0888

Nmap done: 1 IP address (1 host up) scanned in 3.45 seconds
```

---

### 5. ixf-dnp3-detect

**Description:** Detects DNP3 outstations (RTUs and IEDs) by sending a DNP3 Link Status request frame. Validates the Data Link Layer response to confirm DNP3 compliance. Optionally sends a Data Link Reset, reads Class 0 data via Application Layer Integrity Poll, and reports the number of data objects returned. Parses the response for data link source address.

**Syntax:**

```
nmap --script ixf-dnp3-detect [--script-args dnp3.master=1,dnp3.slave=10] -p 20000 <target>
```

**Arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| `dnp3.master` | `1` | DNP3 master address (this scanner) |
| `dnp3.slave` | `10` | DNP3 slave/outstation address to probe |
| `dnp3.integrity_poll` | `false` | Send Class 0 integrity poll after detection |
| `dnp3.timeout` | `5` | Response timeout in seconds |

**Example with full Nmap output:**

```bash
nmap --script ixf-dnp3-detect --script-args dnp3.integrity_poll=true -p 20000 192.168.1.75
```

**Output:**

```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-01 18:29 UTC
Nmap scan report for 192.168.1.75
Host is up (0.00028s latency).

PORT      STATE SERVICE
20000/tcp open  dnp

Host script results:
| ixf-dnp3-detect:
|   DNP3 device detected
|   Data Link Response:  OK (Link Status response received)
|   Source Address:      10 (outstation/RTU)
|   Destination Address: 1  (master/SCADA)
|   Confirmed:           Yes (link confirmation enabled)
|   Class 0 Integrity Poll:
|     Object Group 1:    32 binary inputs
|     Object Group 30:   8 analog inputs
|     Object Group 40:   4 analog outputs (status)
|     Total objects:     44
|   IXF module:  use scanners/ics/dnp3_scanner
|   Relevant CVEs: CVE-2019-10979 (Triangle Microworks DNP3 master overflow)
|_  MITRE:       T0888

Nmap done: 1 IP address (1 host up) scanned in 1.87 seconds
```

---

### 6. ixf-iec104-detect

**Description:** Detects IEC 60870-5-104 RTUs by sending a STARTDT_ACT (Start Data Transfer Activation) U-frame and waiting for STARTDT_CON (Confirmation). On confirmed session, optionally sends a General Interrogation command (C_IC_NA_1, TypeID=100) and counts the ASDU (Application Service Data Unit) responses to estimate the number of information objects (circuit breakers, measurements, setpoints). Sends STOPDT_ACT to cleanly close the session.

**Syntax:**

```
nmap --script ixf-iec104-detect [--script-args iec104.interrogate=true] -p 2404 <target>
```

**Arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| `iec104.interrogate` | `false` | Send General Interrogation after STARTDT |
| `iec104.common_address` | `1` | Common Address of ASDU (station address) |
| `iec104.timeout` | `5` | Response timeout in seconds |
| `iec104.k` | `12` | Maximum number of unacknowledged ASDUs (k parameter) |
| `iec104.w` | `8` | Receive window (w parameter) |

**Example with full Nmap output:**

```bash
nmap --script ixf-iec104-detect --script-args iec104.interrogate=true -p 2404 192.168.1.30
```

**Output:**

```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-01 18:30 UTC
Nmap scan report for 192.168.1.30
Host is up (0.00041s latency).

PORT     STATE SERVICE
2404/tcp open  iec-104

Host script results:
| ixf-iec104-detect:
|   IEC 60870-5-104 device detected
|   STARTDT:         OK (STARTDT_CON received — session established)
|   k parameter:     12 (max unacknowledged ASDUs)
|   w parameter:     8  (receive window)
|   General Interrogation (COT=6):
|     TypeID 1  (M_SP_NA_1 — Single Point):  64 objects
|     TypeID 13 (M_ME_NC_1 — Float):         24 objects
|     TypeID 30 (M_SP_TB_1 — Single+Time):   12 objects
|     TypeID 45 (C_SC_NA_1 — Control):       8  objects (writable!)
|     Total ASDUs: 108 objects
|   STOPDT:          OK (session cleanly closed)
|
|   WARNING: 8 control objects (TypeID 45) are accessible without authentication.
|            An attacker could send C_SC_NA_1 EXEC to control circuit breakers.
|
|   IXF module:  use exploits/protocols/iec104/iec104_single_command
|   Relevant CVEs: CVE-2022-37300 (Schneider IEC 104 auth bypass)
|_  MITRE:       T0855 (Unauthorized Command Message), T0888

Nmap done: 1 IP address (1 host up) scanned in 2.34 seconds
```

---

### 7. ixf-opcua-info

**Description:** Connects to an OPC UA server's discovery endpoint and calls `GetEndpoints` to enumerate all available endpoints, security modes, and security policies. Reports whether anonymous access or `SecurityMode=None` endpoints are available. Optionally attempts to browse the OPC UA namespace without authentication to test for unauthenticated access. Maps security mode enum values to human-readable strings (None, Sign, SignAndEncrypt).

**Syntax:**

```
nmap --script ixf-opcua-info [--script-args opcua.browse=true,opcua.anon_test=true] -p 4840 <target>
```

**Arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| `opcua.browse` | `false` | Attempt anonymous namespace browse |
| `opcua.anon_test` | `true` | Test for anonymous session creation |
| `opcua.timeout` | `5` | Connection timeout in seconds |
| `opcua.max_endpoints` | `10` | Maximum endpoints to enumerate |

**Example with full Nmap output:**

```bash
nmap --script ixf-opcua-info --script-args opcua.anon_test=true,opcua.browse=true -p 4840 192.168.1.120
```

**Output:**

```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-01 18:31 UTC
Nmap scan report for 192.168.1.120
Host is up (0.00038s latency).

PORT     STATE SERVICE
4840/tcp open  opcua-tcp

Host script results:
| ixf-opcua-info:
|   OPC UA server detected
|   Server URI:    urn:KEPServerEX
|   Product Name:  KEPServerEX/6
|   Manufacturer:  PTC Inc.
|
|   Endpoints (3 found):
|     1. opc.tcp://192.168.1.120:4840/
|        Security Mode:   None
|        Security Policy: http://opcfoundation.org/UA/SecurityPolicy#None
|        Token Types:     Anonymous, UserName
|        RISK: SecurityMode=None endpoint exposed (no encryption/signing)
|
|     2. opc.tcp://192.168.1.120:4840/
|        Security Mode:   Sign
|        Security Policy: http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256
|        Token Types:     Certificate
|
|     3. opc.tcp://192.168.1.120:4840/
|        Security Mode:   SignAndEncrypt
|        Security Policy: http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss
|        Token Types:     Certificate
|
|   Anonymous access test:
|     Session created:    YES (anonymous session opened without credentials)
|     RISK: Server accepts anonymous sessions — unauthenticated read/write possible
|
|   Namespace browse (anonymous):
|     Objects/            (namespace 0)
|     |- Server/          (standard OPC UA server node)
|     |- Kepware/         (vendor namespace — tag database root)
|        |- Channel1/Device1/ (16 tags visible without auth)
|        |- Channel2/Device2/ (8 tags visible without auth)
|
|   Relevant CVEs: CVE-2023-27321 (OPC UA .NET Classic overflow)
|   IXF module:  use exploits/protocols/opcua/opcua_anonymous_browse
|_  MITRE:       T0888, T0843 (Program Upload)

Nmap done: 1 IP address (1 host up) scanned in 3.87 seconds
```

---

### 8. ixf-ics-cve-check

**Description:** Multi-protocol banner grabber and version fingerprinter that matches collected banners, HTTP headers, firmware strings, and S7 SZL data against the IXF CVE database (all 612 CVE modules). Reports matching CVEs with CVSS scores, IXF module paths, and exploitation status. Covers HTTP/HTTPS (web HMI), FTP, Telnet, SSH, S7comm (SZL firmware), Modbus FC43 MEI, EtherNet/IP List Identity, and OPC UA GetEndpoints.

**Syntax:**

```
nmap --script ixf-ics-cve-check [--script-args cvechecks.max_cves=20] -p <ports> <target>
```

**Arguments:**

| Argument | Default | Description |
|----------|---------|-------------|
| `cvechecks.max_cves` | `10` | Maximum CVEs to report per host |
| `cvechecks.http_banner` | `true` | Grab HTTP banner from web ports |
| `cvechecks.ftp_banner` | `true` | Grab FTP banner |
| `cvechecks.s7_szl` | `true` | Grab S7 firmware via SZL-SSL |
| `cvechecks.enip_identity` | `true` | Grab EtherNet/IP product identity |
| `cvechecks.modbus_mei` | `true` | Grab Modbus MEI device ID |
| `cvechecks.severity_filter` | `MEDIUM` | Minimum severity to report (INFO/LOW/MEDIUM/HIGH/CRITICAL) |

**Example with full Nmap output:**

```bash
nmap --script ixf-ics-cve-check -p 21,22,80,102,443,502,4840,44818 192.168.1.100
```

**Output:**

```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-01 18:32 UTC
Nmap scan report for 192.168.1.100
Host is up (0.00044s latency).

PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
102/tcp   open  iso-tsap
443/tcp   open  https
502/tcp   open  modbus
4840/tcp  open  opcua-tcp
44818/tcp open  EtherNet/IP-2

Host script results:
| ixf-ics-cve-check:
|   IXF CVE Check — 192.168.1.100
|   ─────────────────────────────────────────────────────────
|
|   [Port 80 — HTTP banner]
|   Banner: "Siemens SIMATIC HMI KTP700 — V14.0 SP1 Update 5"
|   Matched CVEs:
|     CVE-2018-4832   CVSS 7.5  HIGH      WinCC path traversal
|                     IXF: use cve/siemens/cve_2018_4832_wincc_path_traversal
|     CVE-2019-13945  CVSS 9.8  CRITICAL  SCALANCE auth bypass (check firmware ver)
|                     IXF: use cve/siemens/cve_2019_13945_scalance_auth_bypass
|
|   [Port 102 — S7comm SZL]
|   Module: 6ES7 215-1AG40-0XB0  Firmware: V4.2.0
|   Matched CVEs:
|     CVE-2021-22681  CVSS 10.0 CRITICAL  S7-1200 hardcoded crypto key
|                     IXF: use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
|                     NOTE: Firmware V4.2 is in affected range (< V4.5)
|
|   [Port 502 — Modbus MEI]
|   VendorName: Siemens AG   ProductCode: ET200SP
|   Matched CVEs:
|     CVE-2020-7580   CVSS 7.5  HIGH      SIMATIC NET DoS via Modbus
|                     IXF: use cve/siemens/cve_2020_7580_simatic_net_dos
|
|   [Port 44818 — EtherNet/IP]
|   No EtherNet/IP response (device may not support CIP)
|
|   [Port 4840 — OPC UA]
|   Server: KEPServerEX 6.11.718.0
|   Matched CVEs:
|     CVE-2022-2848   CVSS 9.8  CRITICAL  KEPServerEX RCE via LLMNR
|                     IXF: use cve/kepware/cve_2022_2848_kepserver_rce
|
|   ─────────────────────────────────────────────────────────
|   Summary: 4 CVEs matched (1 CRITICAL CVSS 10.0, 2 CRITICAL, 1 HIGH)
|   Highest severity: CRITICAL (CVE-2021-22681, CVSS 10.0)
|
|   [IXF remediation workflow]
|     ixf use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key set target 192.168.1.100 run
|     ixf use cve/kepware/cve_2022_2848_kepserver_rce set target 192.168.1.100 run
|_
Nmap done: 1 IP address (1 host up) scanned in 8.23 seconds
```

---

## Combined Scan Examples

### Full ICS protocol sweep on a single host

```bash
sudo nmap --script "ixf-modbus-detect,ixf-s7comm-info,ixf-enip-list-identity,ixf-opcua-info" \
  --script-args modbus.identify=true,opcua.anon_test=true \
  -p 102,502,4840,44818 192.168.1.100 -sV -O
```

**Expected output structure:**

```
Nmap scan report for 192.168.1.100
PORT      STATE SERVICE       VERSION
102/tcp   open  iso-tsap      Siemens S7comm
502/tcp   open  modbus        Modbus TCP
4840/tcp  open  opcua-tcp     OPC UA
44818/tcp open  EtherNet/IP-2 Allen-Bradley EtherNet/IP

Host script results:
| ixf-modbus-detect:     [Schneider PLC — VendorName, ProductCode, Revision]
| ixf-s7comm-info:       [S7-1200 — order number, firmware, serial]
| ixf-enip-list-identity:[Rockwell Logix — vendor, product, revision]
| ixf-opcua-info:        [KEPServerEX — endpoints, SecurityMode=None RISK]
```

---

### CVE check across an entire subnet

```bash
sudo nmap --script ixf-ics-cve-check \
  --script-args cvechecks.severity_filter=HIGH,cvechecks.max_cves=5 \
  -p 21,80,102,502,4840,44818 192.168.1.0/24 --open -T3
```

---

### BACnet discovery on building automation VLAN

```bash
sudo nmap --script ixf-bacnet-discover \
  --script-args bacnet.read_properties=true \
  -p U:47808 192.168.50.0/24 -sU -T3
```

---

### DNP3 survey across OT SCADA subnet

```bash
sudo nmap --script ixf-dnp3-detect \
  --script-args dnp3.integrity_poll=true,dnp3.slave=10 \
  -p 20000 10.0.1.0/24 -T2
```

---

### Complete OT asset discovery — all IXF scripts

```bash
sudo nmap --script "ixf-*" \
  --script-args modbus.identify=true,opcua.anon_test=true,bacnet.read_properties=true,\
dnp3.integrity_poll=true,iec104.interrogate=true,cvechecks.severity_filter=MEDIUM \
  -p 21,22,23,80,102,443,502,1217,2404,4840,5094,20000,44818 \
  -p U:47808 \
  192.168.1.0/24 --open -sV -sU -T3 \
  -oN .tmp/ot_nmap_$(date +%Y%m%d).txt \
  -oX .tmp/ot_nmap_$(date +%Y%m%d).xml \
  -oJ .tmp/ot_nmap_$(date +%Y%m%d).json
```

---

## Integration with IXF Workflow

NSE scripts and IXF modules are designed to work together. Use Nmap for initial discovery, then IXF for detailed exploitation simulation:

### Step 1: Discover with Nmap NSE

```bash
sudo nmap --script "ixf-modbus-detect,ixf-s7comm-info,ixf-ics-cve-check" \
  -p 102,502 192.168.1.0/24 --open \
  -oX .tmp/discovery.xml
```

### Step 2: Parse Nmap XML output

```python
"""Parse Nmap XML output and run IXF modules on discovered hosts."""
import xml.etree.ElementTree as ET
import subprocess

tree = ET.parse(".tmp/discovery.xml")
root = tree.getroot()

for host in root.findall("host"):
    addr = host.find("address[@addrtype='ipv4']")
    if addr is None:
        continue
    ip = addr.get("addr")

    # Check for Modbus port
    modbus_port = host.find(".//port[@portid='502']")
    if modbus_port and modbus_port.find("state[@state='open']") is not None:
        print(f"[+] Modbus on {ip}:502 — running IXF scanner")
        subprocess.run([
            "ixf", "use", "scanners/ics/modbus_detect",
            "set", "target", ip,
            "run"
        ])

    # Check for S7 port
    s7_port = host.find(".//port[@portid='102']")
    if s7_port and s7_port.find("state[@state='open']") is not None:
        print(f"[+] S7comm on {ip}:102 — running IXF S7 scanner")
        subprocess.run([
            "ixf", "use", "scanners/ics/s7_comm_scanner",
            "set", "target", ip,
            "run"
        ])
```

### Step 3: Load matched CVE modules

```bash
# From NSE CVE check output, run matched modules in IXF
ixf use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key set target 192.168.1.100 run
ixf use cve/kepware/cve_2022_2848_kepserver_rce set target 192.168.1.100 run
```

### Step 4: Generate combined report

```bash
ixf report json
ixf mitre-coverage
```

---

## Writing Custom NSE Scripts

Custom NSE scripts for IXF must follow the standard Nmap NSE API. Store them in `nse/scripts/custom/` and install manually.

### Minimal NSE script template

```lua
-- ixf-custom-protocol-detect.nse
-- Custom IXF NSE script for <protocol> detection.
--
-- Usage:
--   nmap --script ixf-custom-protocol-detect -p <port> <target>
--
-- @output
-- PORT      STATE SERVICE
-- NNNN/tcp  open  <service>
-- | ixf-custom-protocol-detect:
-- |   <protocol> device detected
-- |_  ...

local nmap    = require "nmap"
local stdnse  = require "stdnse"
local shortport = require "shortport"

-- NSE metadata
description = [[
Detects <protocol> devices by sending a probe and validating the response.
Part of IXF (IndustrialXPL-Forge) NSE script collection.
]]

-- Categorize as discovery (passive identification, no exploitation)
categories = {"discovery", "safe"}

-- Port filter: run only on specified TCP port
portrule = shortport.port_or_service(<port_number>, "<service_name>", "tcp")

-- Script arguments (access via stdnse.get_script_args)
local arg_timeout = stdnse.get_script_args("custom.timeout") or 5
local arg_verbose = stdnse.get_script_args("custom.verbose") or false

-- Main action function
action = function(host, port)
    local output = stdnse.output_table()

    -- Open socket
    local socket = nmap.new_socket()
    socket:set_timeout(arg_timeout * 1000)

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        stdnse.debug1("Connection failed: %s", err)
        return nil
    end

    -- Build probe (modify for your protocol)
    local probe = "\x00\x01\x00\x00\x00\x06\x01\x04\x00\x00\x00\x01"

    -- Send probe
    status, err = socket:send(probe)
    if not status then
        socket:close()
        return nil
    end

    -- Receive response
    local response
    status, response = socket:receive_bytes(16)
    socket:close()

    if not status or not response then
        return nil
    end

    -- Validate response (customize validation logic)
    if #response >= 6 and response:sub(1, 2) == "\x00\x01" then
        output["Protocol detected"] = "YES"
        output["Response length"]   = #response .. " bytes"
        output["IXF module"]        = "use scanners/ics/<module>"
        output["MITRE"]             = "T0888"
        return output
    end

    return nil
end
```

### NSE script metadata standards

| Field | Requirement | Example |
|-------|------------|---------|
| `description` | Required | Multi-line description of what the script does |
| `categories` | Required | `{"discovery", "safe"}` for passive, `{"vuln"}` for CVE checks |
| `portrule` | Required | Use `shortport.port_or_service()` for TCP, `shortport.udp_port()` for UDP |
| `author` | Recommended | `"Andre Henrique (mrhenrike)"` |
| `license` | Recommended | `"Same as Nmap -- See https://nmap.org/book/man-legal.html"` |

### Installing custom scripts

```bash
# Copy to nmap scripts directory
sudo cp nse/scripts/custom/ixf-custom-protocol-detect.nse /usr/share/nmap/scripts/

# Update script database
sudo nmap --script-updatedb

# Test
nmap --script ixf-custom-protocol-detect -p <port> 127.0.0.1
```

---

## Troubleshooting

### "No such script: ixf-modbus-detect"

**Cause:** Scripts not installed or `script-updatedb` not run.

**Fix:**

```bash
sudo ixf nse install
# or manually:
sudo cp nse/scripts/*.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
```

---

### Permission denied (NSE can't open raw socket)

**Cause:** Nmap requires root/administrator for raw socket operations (SYN scan, OS detection, UDP scan).

**Fix:**

```bash
# Linux — run with sudo
sudo nmap --script ixf-modbus-detect -p 502 192.168.1.100

# Linux — allow nmap to use raw sockets without sudo (setcap)
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)
```

---

### Script output shows no results (script ran but found nothing)

**Cause:** Target is not running the expected protocol on the specified port, or firewall is blocking.

**Diagnosis:**

```bash
# Check port is open first
nmap -p 502 192.168.1.100

# Enable verbose NSE output
nmap --script ixf-modbus-detect -p 502 192.168.1.100 --script-trace -v
```

---

### "script-updatedb: failed" error

**Cause:** No write permission to Nmap scripts directory.

**Fix:**

```bash
sudo nmap --script-updatedb
# or on macOS with Homebrew:
sudo chmod -R a+r /usr/local/share/nmap/scripts/
sudo nmap --script-updatedb
```

---

### UDP scripts not discovering BACnet devices

**Cause:** UDP scan requires `-sU` flag and usually requires root. Broadcast probes need the correct broadcast address.

**Fix:**

```bash
# UDP scan with broadcast
sudo nmap -sU --script ixf-bacnet-discover -p U:47808 192.168.1.255

# If broadcast is blocked, use directed unicast
sudo nmap -sU --script ixf-bacnet-discover -p U:47808 192.168.1.150
```

---

### NSE script says "safe" but I'm worried about impact

**Explanation:** `categories = {"discovery", "safe"}` means the script only performs read-only probes. It does not write data, modify device state, or trigger any process changes. However:

- Any network packet sent to a poorly implemented ICS device may cause unexpected behavior.
- Always obtain written authorization before scanning any industrial control system.
- Use IXF module `simulate=True` (the default) for zero-impact simulation.
- Use NSE scripts only in authorized environments with known-safe devices or lab setups.

---

*Previous: [Module Catalog](13-module-catalog.md) | Back to [Index](_index.md)*
