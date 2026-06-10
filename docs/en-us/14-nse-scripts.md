# Nmap NSE Scripts

IXF bundles 8 custom Nmap Scripting Engine (NSE) scripts for OT/ICS network reconnaissance and security assessment. These scripts extend Nmap's capabilities to understand industrial protocols and device types that standard Nmap scripts do not cover.

---

## Overview — Why IXF Provides NSE Scripts

Nmap's standard NSE library includes general-purpose network discovery scripts, but has limited coverage for industrial protocols such as Modbus TCP, Siemens S7comm, EtherNet/IP, DNP3, BACnet, and OPC UA. IXF's NSE scripts fill this gap by:

1. **Protocol-aware scanning** — understanding ICS protocol handshakes and responses
2. **Vendor fingerprinting** — identifying specific PLC/RTU models from response characteristics
3. **Security check integration** — flagging insecure configurations (default credentials, unauthenticated access, exposed programming ports)
4. **IXF workflow integration** — generating output that feeds directly into IXF module selection
5. **Honeypot detection** — identifying fake ICS targets to avoid misleading assessment results

NSE scripts run within Nmap's sandboxed Lua environment, making them safe to deploy and easy to customize. All 8 IXF scripts are passive/read-only — they send only valid protocol queries, never exploit payloads.

---

## Requirements

- **Nmap 7.80 or later** (7.95+ recommended for full NSE library compatibility)
- **Root/Administrator privileges** for raw socket scans (`-sS`) and Layer 2 scripts
- **IXF installed** (`pip install industrialxpl`) — provides the NSE scripts
- Scripts work on Linux, macOS, and Windows

**Verify Nmap version:**
```bash
nmap --version
# Nmap version 7.95 ( https://nmap.org )
```

---

## Installation

### Method 1: IXF Shell (`nse install`)

The recommended method — IXF auto-detects the Nmap scripts directory and installs all 8 scripts:

```
ixf > nse install
[*] Installing IXF NSE scripts into /usr/share/nmap/scripts/...
[+] ics-sweep.nse                   → installed
[+] ics-default-creds.nse           → installed
[+] ics-plc-program-access.nse      → installed
[+] ics-safety-systems.nse          → installed
[+] ics-firmware-version.nse        → installed
[+] ics-historian-discover.nse      → installed
[+] ics-enumerate.nse               → installed
[+] ics-honeypot-detect.nse         → installed
[*] Running: nmap --script-updatedb
[+] NSE script database updated.
[+] All 8 IXF NSE scripts installed successfully.
[i] Usage: nmap --script ics-sweep -p 102,502,47808 <target>
[i] For all ICS scripts: nmap --script "ics-*" -p 102,502,47808,4840,20000 <target>
```

**On Linux/macOS, you may need sudo:**
```bash
sudo ixf nse install
# or:
sudo python -m industrialxpl nse install
```

**Force reinstall (overwrite existing):**
```
ixf > nse install --force
```

### Method 2: Python Tool (`nse_install.py`)

```bash
python tools/nse_install.py --install
```

```
[IXF NSE Installer]
Nmap found: /usr/bin/nmap (7.95)
Scripts directory: /usr/share/nmap/scripts/
Installing 8 NSE scripts:
  [+] ics-sweep.nse
  [+] ics-default-creds.nse
  [+] ics-plc-program-access.nse
  [+] ics-safety-systems.nse
  [+] ics-firmware-version.nse
  [+] ics-historian-discover.nse
  [+] ics-enumerate.nse
  [+] ics-honeypot-detect.nse
Running: nmap --script-updatedb
Done. All 8 scripts installed.
```

**Full options:**
```bash
python tools/nse_install.py --help
# --install     Install all IXF NSE scripts
# --uninstall   Remove all IXF NSE scripts
# --force       Overwrite existing scripts
# --list        List installed status
# --scripts-dir Custom Nmap scripts directory
```

### Post-Install: Update Script Database

Always run after installation to register scripts with Nmap's database:
```bash
nmap --script-updatedb
```

---

## Script 1: `ics-sweep.nse`

### Description

Multi-protocol ICS port sweep. Probes the most common ICS/OT ports in a single scan and identifies which industrial protocols are listening. The sweep covers Modbus TCP, Siemens S7comm, EtherNet/IP, DNP3, BACnet/IP, OPC UA, PROFINET, FINS, and PCOM.

### Categories

`discovery`, `safe`, `ics`

### Syntax

```bash
nmap --script ics-sweep -p 102,502,44818,47808,2404,4840,9600,20000,20256 <target>
```

### Arguments Table

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `ics-sweep.timeout` | number | `5` | Per-protocol connection timeout in seconds |
| `ics-sweep.verbose` | boolean | `false` | Show raw response bytes |
| `ics-sweep.unit_id` | number | `1` | Modbus unit ID to probe |

### Example with Full Nmap Output

```bash
nmap --script ics-sweep -p 102,502,44818,47808,2404,4840,9600,20000,20256 192.168.1.100
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-01 20:15 UTC
Nmap scan report for ics-workstation (192.168.1.100)
Host is up (0.0042s latency).

PORT      STATE SERVICE    VERSION
102/tcp   open  iso-tsap
| ics-sweep:
|   S7comm: OPEN
|   S7comm+ (TLS): DETECTED — S7-1200/1500 series
|   Vendor: Siemens (inferred)
|   Model: S7-1500 CPU (from COTP connection response)
|_  IXF: use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key

502/tcp   open  mbnet
| ics-sweep:
|   Modbus TCP: OPEN
|   Function Code 04 response: Unit ID 1 responding
|   Register count: 0-999 accessible
|   Vendor: Schneider Electric (inferred from register layout)
|   Model: Modicon M340 (probable)
|_  IXF: use scanners/ics/modbus_detect

44818/tcp open  EtherNet/IP
| ics-sweep:
|   EtherNet/IP: OPEN
|   ListIdentity response:
|     Vendor ID: 1 (Rockwell Automation)
|     Device Type: 14 (Programmable Logic Controller)
|     Product Name: "1756-L75/B LOGIX5575"
|     Serial: 0x12345678
|_  IXF: search rockwell

47808/udp open  bacnet
| ics-sweep:
|   BACnet/IP: OPEN
|   WhoIs response: 1 device(s)
|   Device ID: 1001 | Vendor: Johnson Controls
|   Max APDU: 1476 | APDU timeout: 3000ms
|_  IXF: use scanners/ics/bacnet_scanner

2404/tcp  closed iec104
4840/tcp  closed opc-ua
9600/udp  closed fins
20000/tcp closed dnp3
20256/tcp closed pcom

Host script results:
| ics-sweep: ICS devices found:
|   Siemens S7-1500 (102/tcp)
|   Schneider Modicon M340 (502/tcp)
|   Rockwell ControlLogix L75 (44818/tcp)
|_  Johnson Controls BACnet device (47808/udp)

Nmap done: 1 IP address (1 host up) scanned in 5.27 seconds
```

---

## Script 2: `ics-default-creds.nse`

### Description

Tests a curated list of default credentials against ICS web interfaces, management panels, and SSH/Telnet endpoints. Covers 35+ vendors with their known factory defaults. All tests are performed against HTTP/HTTPS/SSH/Telnet — no Modbus or ICS protocol authentication is tested by this script.

### Categories

`auth`, `brute`, `default`, `ics`

### Syntax

```bash
nmap --script ics-default-creds -p 22,23,80,443,8080,8443 <target>
```

### Arguments Table

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `ics-default-creds.vendor` | string | `"auto"` | Target vendor for focused cred list (e.g. `siemens`, `rockwell`) |
| `ics-default-creds.timeout` | number | `10` | Connection timeout |
| `ics-default-creds.stop_on_first` | boolean | `true` | Stop testing after first successful credential pair |

### Example with Full Nmap Output

```bash
nmap --script ics-default-creds -p 22,80,443 192.168.1.101
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-01 20:17 UTC
Nmap scan report for 192.168.1.101
Host is up (0.0031s latency).

PORT    STATE SERVICE
22/tcp  open  ssh
| ics-default-creds:
|   SSH (port 22):
|     Testing vendor: Moxa (detected from banner: "MoxaDevice NPort 5150")
|     Testing 8 default credential pairs...
|     [+] SUCCESS: admin/moxa
|     Username: admin
|     Password: moxa
|     Access level: Administrator
|_    IXF: creds/moxa/ssh_default_creds

80/tcp  open  http
| ics-default-creds:
|   HTTP (port 80):
|     Banner: "NPort 5150 Web Console"
|     Testing 8 default credential pairs...
|     [+] SUCCESS: admin/moxa
|     Path: /login.html
|_    Login successful — full admin access confirmed

443/tcp closed https

Host script results:
| ics-default-creds:
|   CRITICAL: Default credentials valid on 192.168.1.101
|   Service: Moxa NPort 5150 (SSH + Web)
|   Credentials: admin/moxa (factory default)
|_  Recommendation: Change password immediately. IXF: creds/moxa/ssh_default_creds

Nmap done: 1 IP address (1 host up) scanned in 8.43 seconds
```

---

## Script 3: `ics-plc-program-access.nse`

### Description

Checks if PLC programming ports are accessible without authentication. Tests Siemens S7comm (port 102), Rockwell EtherNet/IP (port 44818), Unitronics PCOM (port 20256), Beckhoff ADS (port 48898), and generic Modbus TCP. An unauthenticated programming port means any host on the network can upload a modified PLC program.

### Categories

`vuln`, `discovery`, `ics`

### Syntax

```bash
nmap --script ics-plc-program-access -p 102,44818,20256,48898,502 <target>
```

### Arguments Table

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `ics-plc-program-access.timeout` | number | `10` | Connection timeout |
| `ics-plc-program-access.test_write` | boolean | `false` | Attempt a harmless write test (increases accuracy, may generate alarms) |

### Example with Full Nmap Output

```bash
nmap --script ics-plc-program-access -p 102,44818,20256,502 192.168.1.50
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-01 20:19 UTC
Nmap scan report for 192.168.1.50
Host is up (0.0027s latency).

PORT      STATE SERVICE
102/tcp   open  iso-tsap
| ics-plc-program-access:
|   S7comm: OPEN and UNAUTHENTICATED
|   Connection: COTP + S7comm handshake succeeded without credentials
|   CPU State: RUN (via SZL read — S7 System Status List access)
|   PLC Program: Downloadable without authentication
|   Block count: 47 OB/FB/FC/DB blocks accessible
|   VULNERABILITY: T0843 (Program Download) — any host can overwrite PLC program
|_  CVE: CVE-2021-22681 (if S7-1200/1500) | Severity: CRITICAL

44818/tcp open  EtherNet/IP
| ics-plc-program-access:
|   EtherNet/IP: OPEN
|   CIP GetAttributeAll succeeded without authentication
|   Programming: Requires FactoryTalk credentials (auth enforced)
|_  Status: PROTECTED (authentication required for program download)

20256/tcp closed pcom
502/tcp   open  mbnet
| ics-plc-program-access:
|   Modbus TCP: OPEN — NO AUTHENTICATION (by protocol design)
|   All holding registers accessible: FC01/02/03/04 (read) + FC05/06/15/16 (write)
|   NOTE: Modbus TCP has no authentication mechanism — any host can read/write
|_  IXF: exploits/protocols/modbus/modbus_write_single_register

Host script results:
| ics-plc-program-access:
|   CRITICAL: S7comm unauthenticated program access on port 102
|   HIGH: Modbus TCP unauthenticated register access on port 502
|_  Run: ixf ttp T0843 192.168.1.50

Nmap done: 1 IP address (1 host up) scanned in 6.18 seconds
```

---

## Script 4: `ics-safety-systems.nse`

### Description

Detects Safety Instrumented System (SIS) interfaces on the network. Identifies Triconex, HIMA, Pilz, and other safety PLC endpoints. Reports potential exposure — safety systems should typically be air-gapped or at minimum on separate isolated networks.

### Categories

`discovery`, `vuln`, `ics`

### Syntax

```bash
nmap --script ics-safety-systems -p 1502,7700,7701,2404,44818,1962 <target_range>
```

### Arguments Table

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `ics-safety-systems.timeout` | number | `8` | Connection timeout |
| `ics-safety-systems.strict` | boolean | `false` | Require confirmed safety system (default: flag likely candidates) |

### Example with Full Nmap Output

```bash
nmap --script ics-safety-systems -p 1502,7700,44818,2404 192.168.1.0/24
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-01 20:22 UTC
Nmap scan report for 192.168.1.75
Host is up (0.0022s latency).

PORT      STATE SERVICE
1502/tcp  open  unknown
| ics-safety-systems:
|   Port 1502 (Triconex TriStation): OPEN
|   Banner: Triconex TSAA protocol response detected
|   Vendor: Schneider Electric (Triconex)
|   Product: Triconex Safety System (likely model 3008)
|   CRITICAL: Safety system interface network-accessible
|   NOTE: TRITON/TRISIS malware targeted this exact interface (2017)
|   MITRE: T0838 (Modify Alarm Settings), T0829 (Loss of Protection)
|_  IXF: cve/malware/triton_trisis_safety_bypass (simulate only)

44818/tcp open  EtherNet/IP
| ics-safety-systems:
|   EtherNet/IP: CIP Safety device detected
|   Product: "GuardLogix 5570" (Rockwell Safety PLC)
|   Safety level: PLe/SIL3 (per device datasheet)
|   MEDIUM: Safety PLC EtherNet/IP accessible — verify network isolation
|_  IXF: exploits/protocols/ethernet_ip_cip_safety/

Host script results:
| ics-safety-systems:
|   CRITICAL: Triconex safety system exposed on network (192.168.1.75:1502)
|   MEDIUM: Rockwell GuardLogix safety PLC exposed (192.168.1.75:44818)
|_  Recommendation: Safety systems should be isolated (see IEC 61511, IEC 62443)

Nmap done: 256 IP addresses scanned in 23.14 seconds (7 hosts up)
```

---

## Script 5: `ics-firmware-version.nse`

### Description

Extracts firmware version information from OT devices using protocol-specific queries. Supports Modbus FC43 (Device Identification), S7comm SZL System Status List, EtherNet/IP GetAttributeAll, BACnet ReadProperty, and OPC UA GetServerInfo. Firmware version is used to determine patch status and applicable CVEs.

### Categories

`discovery`, `safe`, `ics`

### Syntax

```bash
nmap --script ics-firmware-version -p 102,502,44818,47808,4840 <target>
```

### Arguments Table

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `ics-firmware-version.timeout` | number | `10` | Connection timeout |
| `ics-firmware-version.check_cve` | boolean | `true` | Map firmware version to known CVEs |

### Example with Full Nmap Output

```bash
nmap --script ics-firmware-version -p 102,502,44818 192.168.1.100
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-01 20:25 UTC
Nmap scan report for 192.168.1.100
Host is up (0.0029s latency).

PORT      STATE SERVICE
102/tcp   open  iso-tsap
| ics-firmware-version:
|   Protocol: Siemens S7comm
|   SZL Query: CPU Identification (0x001C)
|   Manufacturer: Siemens AG
|   Product Name: CPU 1516-3 PN/DP
|   Copyright: Siemens AG
|   Module Type: CPU 1516-3 PN/DP
|   Firmware Version: V2.8.3
|   Hardware Version: 1
|   CPUType: CPU 1516-3 PN/DP
|   Known CVEs for this firmware version:
|     CVE-2021-22681 (CVSS 9.8): Hardcoded TLS key — ALL firmware versions affected
|     CVE-2022-38465 (CVSS 9.8): S7comm global private key — ALL firmware versions
|     Status: No patch available for CVE-2021-22681 (requires hardware replacement)
|_  IXF: cve CVE-2021-22681

502/tcp   open  mbnet
| ics-firmware-version:
|   Protocol: Modbus TCP FC43 MEI (Device Identification)
|   Object ID 0x01 (Vendor Name): Schneider Electric
|   Object ID 0x02 (Product Code): BMXP342020H
|   Object ID 0x03 (Major/Minor Rev): V3.30 / V3.30
|   Object ID 0x04 (Vendor URL): www.schneider-electric.com
|   Object ID 0x05 (Product Name): Modicon M340 CPU
|   Object ID 0x06 (Model Name): BMXP342020H
|   Firmware: V3.30
|   Known CVEs:
|     CVE-2022-24323 (CVSS 7.5): Malformed Modbus request DoS — V3.20 and below
|     Status: V3.30 — check patch bulletin SEVD-2022-116-01
|_  IXF: cve CVE-2022-24323

44818/tcp open  EtherNet/IP
| ics-firmware-version:
|   Protocol: EtherNet/IP / CIP GetAttributeAll
|   Vendor: Rockwell Automation / Allen-Bradley
|   Product: 1756-L75/B LOGIX5575
|   Revision: 33.011
|   Firmware: 33.011
|   Serial: 0x12AB34CD
|   Known CVEs:
|     CVE-2022-1161 (CVSS 10.0): Modified firmware upload — V33 and below
|     CVE-2023-3595 (CVSS 9.8): RCE via EtherNet/IP — V33 and below
|_  IXF: cve CVE-2022-1161

Nmap done: 1 IP address (1 host up) scanned in 7.91 seconds
```

---

## Script 6: `ics-historian-discover.nse`

### Description

Discovers industrial historian databases on the network. Checks for OSIsoft PI Server, AVEVA Historian, GE Proficy Historian, Honeywell PHD, and generic SQL-based historians. Historians contain time-series production data and are high-value targets for industrial espionage.

### Categories

`discovery`, `safe`, `ics`

### Syntax

```bash
nmap --script ics-historian-discover -p 5450,5457,5461,5480,1433,5432 <target>
```

### Arguments Table

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `ics-historian-discover.timeout` | number | `10` | Connection timeout |
| `ics-historian-discover.try_auth` | boolean | `false` | Attempt anonymous/default authentication |

### Example with Full Nmap Output

```bash
nmap --script ics-historian-discover -p 5450,5457,1433 192.168.1.0/24
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-01 20:28 UTC

Nmap scan report for historian01.plant.local (192.168.1.200)
Host is up (0.0018s latency).

PORT     STATE SERVICE
5450/tcp open  unknown
| ics-historian-discover:
|   OSIsoft PI Server detected (port 5450)
|   PI Data Archive version: 2023 (3.4.430.462)
|   PI Server name: HISTORIAN01
|   Server ID: {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
|   Authentication: Mapped/Explicit (Windows + PI user)
|   Default user 'piadmin': Attempting login...
|   [!] piadmin login allowed (default configuration)
|   Tag count: 47,832 process tags accessible
|   Oldest data: 2019-01-01 (7+ years of process data)
|   CRITICAL: piadmin with default/blank password provides full PI access
|_  IXF: creds/osisoft/pi_server_default_creds | CVE: CVE-2021-26382

1433/tcp open  ms-sql-s
| ics-historian-discover:
|   Microsoft SQL Server: Proficy Historian (GE Digital)
|   Version: SQL Server 2019 (15.00.4198.2)
|   Instance: HISTORIAN
|   Databases: [proficy_historian, proficy_system, master, model]
|   Authentication: SQL + Windows
|   [i] No anonymous access; default SA account not tested
|_  IXF: cve/ge/cimplicity_default_creds

Nmap done: 256 IP addresses scanned in 31.22 seconds (3 historians found)
```

---

## Script 7: `ics-enumerate.nse`

### Description

Comprehensive ICS device metadata enumeration. For each open ICS port, extracts all available device information including vendor, model, firmware version, serial number, station name, configured IP settings, and installed modules. Combines multiple protocol queries into a single rich output.

### Categories

`discovery`, `safe`, `ics`

### Syntax

```bash
nmap --script ics-enumerate -p 102,502,44818,47808,4840,9600 <target>
```

### Arguments Table

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `ics-enumerate.timeout` | number | `15` | Connection timeout (longer for full enumeration) |
| `ics-enumerate.deep` | boolean | `false` | Perform deeper enumeration (may generate more network traffic) |
| `ics-enumerate.save` | string | `""` | Save output to file path |

### Example with Full Nmap Output

```bash
nmap --script ics-enumerate -p 102,502,44818 192.168.1.100
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-01 20:31 UTC
Nmap scan report for 192.168.1.100
Host is up (0.0031s latency).

PORT      STATE SERVICE
102/tcp   open  iso-tsap
| ics-enumerate:
|   Siemens S7comm Enumeration
|   ─────────────────────────────────────────────────────────────
|   COTP Connection: Success (Slot 1, Rack 0)
|   S7comm Session: Established (PDU Type 1, max PDU 480 bytes)
|   SZL 0x001C: CPU Identification
|     Manufacturer:     Siemens AG
|     Product Name:     CPU 1516-3 PN/DP
|     Module Type:      CPU 1516-3 PN/DP
|     Firmware:         V2.8.3
|     Hardware Version: 1
|   SZL 0x0011: Module Identification
|     Order Number:     6ES7 516-3AN01-0AB0
|     Serial Number:    S C-C7UP57512014
|     Hardware Version: 1
|   SZL 0x0131: Communication
|     Max sessions:     128
|     Max PDU:          65536
|     Max tags:         8192
|   CPU Mode: RUN
|   CPU State: 0x08 (RUN)
|   System time: 2026-06-01 20:31:44 (UTC)
|   Station Name: "SIEMENS-S7-1516"
|   Project Name: "PlantControl_v3.2"
|   Plant designation: "Building A, Level 2"
|_  Security: S7comm+ TLS detected — check CVE-2021-22681

502/tcp   open  mbnet
| ics-enumerate:
|   Modbus TCP Enumeration
|   ─────────────────────────────────────────────────────────────
|   FC04 Read Input Registers (Unit 1):
|     Registers 0-19: [1842, 2731, 0, 4095, 1023, 512, 0, 0, ...]
|   FC43 MEI Device Identification:
|     Vendor:       Schneider Electric
|     Product Code: BMXP342020H
|     Revision:     V3.30
|     Vendor URL:   www.schneider-electric.com
|     Product Name: Modicon M340 CPU
|   FC01 Coil Read (Unit 1): 32 coils, 8 active
|   Unit IDs responding: 1 (primary)
|   Station Name: (not available via Modbus)
|_  IP Config: Target=192.168.1.100 Port=502 UnitID=1

44818/tcp open  EtherNet/IP
| ics-enumerate:
|   EtherNet/IP / CIP Enumeration
|   ─────────────────────────────────────────────────────────────
|   ListIdentity response:
|     Vendor ID:      1 (Rockwell Automation / Allen-Bradley)
|     Device Type:    14 (Programmable Logic Controller)
|     Product Code:   65 (ControlLogix)
|     Revision:       33.11
|     Status:         0x0030 (Owned, Configured, RUN mode)
|     Serial Number:  0x12AB34CD
|     Product Name:   "1756-L75/B LOGIX5575"
|   GetAttributeAll (Class 0x01, Instance 0x01):
|     Revision:       33.011
|     Max instance:   1
|     Number of instances: 1
|   Chassis Information (UCMM):
|     Slots:  10
|     Slot 0: 1756-L75/B (ControlLogix CPU)
|     Slot 1: 1756-ENBT/A (EtherNet/IP scanner)
|     Slot 2: 1756-IB32/A (32-point discrete input)
|     Slot 3: 1756-OB32/A (32-point discrete output)
|_  Tags: 156 controller tags accessible (no authentication required)

Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
```

---

## Script 8: `ics-honeypot-detect.nse`

### Description

Analyzes ICS protocol responses to detect honeypots and deception technologies. Real OT devices have consistent timing characteristics, specific quirks in protocol responses, and expected error behaviors. Honeypots often have slightly wrong behaviors that this script flags.

The detection is heuristic and not 100% reliable, but significantly reduces false positive results in ICS security assessments.

### Categories

`discovery`, `safe`, `ics`

### Syntax

```bash
nmap --script ics-honeypot-detect -p 102,502,44818,47808,4840 <target>
```

### Arguments Table

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `ics-honeypot-detect.timeout` | number | `10` | Connection timeout |
| `ics-honeypot-detect.iterations` | number | `3` | Number of timing test iterations |
| `ics-honeypot-detect.threshold` | number | `80` | Confidence threshold (0-100) for honeypot determination |

### Example with Full Nmap Output

```bash
nmap --script ics-honeypot-detect -p 102,502 192.168.1.100
```

**Real device (not a honeypot):**

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-01 20:34 UTC
Nmap scan report for 192.168.1.100

PORT    STATE SERVICE
102/tcp open  iso-tsap
| ics-honeypot-detect:
|   S7comm analysis:
|   Timing consistency (3 iterations):
|     Response 1: 4.2ms
|     Response 2: 4.1ms
|     Response 3: 4.3ms
|     Variance: 0.1ms (LOW — consistent with real hardware)
|   Protocol behavior:
|     COTP error codes: Correct (per RFC 905)
|     PDU length: Correct (480 bytes max — S7-1516 spec)
|     SZL response: Authentic hardware fingerprint
|     Unknown function handling: Correct error code returned
|   Conclusion: REAL DEVICE (confidence 92%)
|_  IXF: Target appears genuine — proceed with assessment

502/tcp open  mbnet
| ics-honeypot-detect:
|   Modbus TCP analysis:
|   Timing: 2.1ms ± 0.2ms (LOW variance — real hardware)
|   Function code 0x41 (invalid): Correct error 0x01 (ILLEGAL FUNCTION)
|   Exception code: 0x04 (correct behavior for undefined FC)
|_  Conclusion: REAL DEVICE (confidence 88%)

Nmap done: 1 IP address (1 host up) scanned in 9.82 seconds
```

**Honeypot detection:**

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-01 20:35 UTC
Nmap scan report for 192.168.1.250  <-- suspected honeypot

PORT    STATE SERVICE
502/tcp open  mbnet
| ics-honeypot-detect:
|   Modbus TCP analysis:
|   Timing (3 iterations):
|     Response 1: 2.1ms
|     Response 2: 145.3ms   <-- ANOMALY: latency spike suggests software emulation
|     Response 3: 3.0ms
|     Variance: 70+ ms (HIGH — inconsistent with real hardware)
|   Protocol behavior:
|     Function code 0x42 (invalid): ACCEPTED with generic response (WRONG)
|       Real Modbus devices return exception 0x01 for invalid FC
|       This response suggests incomplete protocol emulation
|     Unit ID 255 (broadcast): Full response received (UNUSUAL)
|       Real devices typically ignore broadcast unit ID
|     FC43 MEI response: Generic vendor string "Modbus Device" (SUSPICIOUS)
|       Real devices return specific vendor names
|   Indicators:
|     [!] High timing variance (software emulation signature)
|     [!] Invalid FC accepted without error (incomplete emulation)
|     [!] Generic vendor name in MEI response
|   Conclusion: PROBABLE HONEYPOT (confidence 91%)
|   [!] Verify before proceeding — results may not reflect real infrastructure
|_  Honeypot frameworks: Conpot, GridPot, S4x Industrial Honeypot

Nmap done: 1 IP address (1 host up) scanned in 12.41 seconds
```

---

## Combined Scan Examples

### 1. Full OT Reconnaissance

```bash
nmap --script "ics-sweep,ics-enumerate,ics-firmware-version" \
     -p 102,502,44818,47808,2404,4840,9600,20000,20256 \
     -sV --open \
     192.168.1.0/24
```

### 2. Vulnerability-Focused Scan

```bash
nmap --script "ics-default-creds,ics-plc-program-access,ics-safety-systems" \
     -p 22,23,80,443,102,44818,20256,1502 \
     192.168.1.0/24
```

### 3. Historian Discovery Sweep

```bash
nmap --script "ics-historian-discover" \
     -p 5450,5457,5461,1433,5432,3306,5480 \
     192.168.0.0/16
```

### 4. Safety System Alert Scan

```bash
nmap --script "ics-safety-systems" \
     -p 1502,7700,7701,44818,2404 \
     192.168.1.0/24
```

### 5. Pre-Assessment Honeypot Filter

```bash
# Always run this first to filter honeypots from the target list
nmap --script "ics-honeypot-detect,ics-sweep" \
     -p 102,502,44818,4840 \
     192.168.1.0/24 \
     | grep -E "REAL DEVICE|PROBABLE HONEYPOT|HOST:" > honeypot_check.txt
```

---

## Integration with IXF Workflow

NSE scripts and IXF work together as a complete assessment pipeline:

```bash
# Step 1: Run NSE scripts to discover ICS devices
nmap --script "ics-sweep,ics-firmware-version,ics-enumerate" \
     -p 102,502,44818,47808 \
     192.168.1.0/24 \
     -oX ics_scan.xml

# Step 2: Open IXF and use findings to target modules
ixf

# Step 3: Load modules based on discovered vendors
ixf > cve CVE-2021-22681    # Siemens S7 found by ics-enumerate
ixf > set target 192.168.1.100
ixf > check

# Step 4: Run TTP sweep for discovered protocols
ixf > ttp T0812 192.168.1.0/24   # Default credentials (from ics-default-creds)
ixf > ttp T0843 192.168.1.100    # Program download (from ics-plc-program-access)

# Step 5: Generate combined report
ixf > report html
ixf > mitre-report layer
```

---

## Writing Custom ICS NSE Scripts

### Minimal Template

```lua
-- ics-custom-example.nse
-- Custom ICS NSE script template
-- Author: Your Name

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Custom ICS protocol scanner. Example template.
]]

---
-- @usage
-- nmap --script ics-custom-example -p 502 <target>
-- @output
-- PORT    STATE SERVICE
-- 502/tcp open  mbnet
-- | ics-custom-example:
-- |   Found: Modbus device
-- |_  Vendor: Generic

author = "Your Name"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "ics"}

-- Only run against port 502 when it's open
portrule = shortport.port_or_service(502, "mbnet", "tcp")

action = function(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(stdnse.get_script_args(SCRIPT_NAME..".timeout", 5000))

    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return "Connection failed: " .. (err or "unknown")
    end

    -- Send Modbus FC04 Read Input Registers
    local request = "\x00\x01\x00\x00\x00\x06\x01\x04\x00\x00\x00\x0A"
    local send_ok, send_err = socket:send(request)
    if not send_ok then
        socket:close()
        return "Send failed"
    end

    local recv_ok, response = socket:receive()
    socket:close()

    if recv_ok and #response >= 3 then
        return "Modbus device responded (FC04): " .. #response .. " bytes"
    else
        return "No Modbus response"
    end
end
```

### Install and Test Custom Script

```bash
cp ics-custom-example.nse /usr/share/nmap/scripts/
nmap --script-updatedb
nmap --script ics-custom-example -p 502 192.168.1.100
```

---

## Troubleshooting Permissions

### Linux — Permission Denied for Raw Sockets

```bash
# Scripts requiring raw sockets (Layer 2, PROFINET) need root:
sudo nmap --script ics-sweep 192.168.1.0/24

# Or run as root (less recommended):
su -
nmap --script ics-sweep 192.168.1.0/24
```

### Windows — Administrator Required

```cmd
# Run as Administrator in elevated Command Prompt or PowerShell
nmap --script ics-sweep 192.168.1.0/24
```

### Script Database Not Updated

If scripts are not found after installation:
```bash
# Manually update the NSE database
nmap --script-updatedb
# Should show: NSE: Loaded X scripts for scanning.
```

### Scripts Directory Not Found

```bash
# Find nmap scripts directory
nmap --script ics-sweep --datadir /path/to/nmap/data 192.168.1.1

# Or find manually
find / -name "*.nse" -maxdepth 10 2>/dev/null | head -5
# /usr/share/nmap/scripts/http-title.nse
# → Scripts dir: /usr/share/nmap/scripts/
```

### Script Syntax Errors

```bash
# Debug a script with verbose output
nmap --script ics-sweep --script-trace -p 502 192.168.1.100

# Lint a custom script
nmap --script-help ics-sweep
```

---

## After Install: Running `nmap --script-updatedb`

Always run after adding new scripts:

```bash
nmap --script-updatedb
```

Expected output:
```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-01 20:45 UTC
NSE: Updating rule database.
NSE: Script Database updated successfully.
```

Verify IXF scripts are registered:
```bash
nmap --script-help ics-sweep
nmap --script-help ics-default-creds
nmap --script-help ics-plc-program-access
nmap --script-help ics-safety-systems
nmap --script-help ics-firmware-version
nmap --script-help ics-historian-discover
nmap --script-help ics-enumerate
nmap --script-help ics-honeypot-detect
```

Each should show the script's description and usage. If any returns an error, re-run `nse install` or check the scripts directory permissions.

---

*Previous: [Module Catalog](13-module-catalog.md)*
