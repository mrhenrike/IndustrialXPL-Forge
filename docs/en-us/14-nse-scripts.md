# Nmap NSE Scripts

IXF ships 8 specialized Nmap Scripting Engine (NSE) scripts for OT/ICS discovery and assessment. These complement the built-in Nmap ICS scripts (`bacnet-info.nse`, `modbus-discover.nse`, `s7-info.nse`) with deeper assessment capabilities.

---

## Prerequisites

1. **Nmap installed** — `nmap --version` should work
2. **IXF installed** — `pip install industrialxpl-forge`
3. **Administrator/root access** — needed to write to Nmap's scripts directory on most systems

---

## Installation

### Via IXF Shell (Recommended)

```
ixf > nse status

[*] [NSE] IndustrialXPL-Forge Nmap Script Status
[i] IXF NSE scripts available : 8
[i] IXF NSE scripts path      : /usr/lib/python3/dist-packages/industrialxpl/resources/nse_scripts
[i]
[+] Nmap binary : /usr/bin/nmap
[+] Version     : Nmap version 7.94 ( https://nmap.org )
[+] Scripts dir : /usr/share/nmap/scripts
[i] IXF scripts installed : 0/8

         IXF NSE Scripts for OT/ICS
┌────────────────────────────┬───────────────┐
│ Script                     │ Status        │
├────────────────────────────┼───────────────┤
│ ics-default-creds.nse      │ not installed │
│ ics-enumerate.nse          │ not installed │
│ ics-firmware-version.nse   │ not installed │
│ ics-historian-discover.nse │ not installed │
│ ics-honeypot-detect.nse    │ not installed │
│ ics-plc-program-access.nse │ not installed │
│ ics-safety-systems.nse     │ not installed │
│ ics-sweep.nse              │ not installed │
└────────────────────────────┴───────────────┘

[!] 8 scripts not yet installed. Run: nse install

ixf > nse install

[*] [NSE] Installing to: /usr/share/nmap/scripts
[+] Installed: ics-default-creds.nse
[+] Installed: ics-enumerate.nse
[+] Installed: ics-firmware-version.nse
[+] Installed: ics-historian-discover.nse
[+] Installed: ics-honeypot-detect.nse
[+] Installed: ics-plc-program-access.nse
[+] Installed: ics-safety-systems.nse
[+] Installed: ics-sweep.nse
[+] Installed 8 IXF NSE script(s) to /usr/share/nmap/scripts
[i] Usage: nmap --script ics-sweep -p 20-65535 <target>
```

### Via Standalone Tool

```bash
# Status check
python tools/nse_install.py --status

# List available scripts
python tools/nse_install.py --list

# Install
python tools/nse_install.py --install

# Linux may need sudo for /usr/share/nmap/scripts/
sudo python tools/nse_install.py --install

# Windows: run as Administrator, then
python tools/nse_install.py --install

# Reinstall (force overwrite)
python tools/nse_install.py --install --force

# Custom scripts directory
python tools/nse_install.py --install --scripts-dir /custom/path
```

### Via pip entry point

```bash
ixf-nse-install --install
ixf-nse-install --status
```

### Manual Installation

If the automated installer fails, copy scripts manually:

```bash
# Linux
sudo cp $(pip show industrialxpl-forge | grep Location | awk '{print $2}')/industrialxpl/resources/nse_scripts/*.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb

# macOS (Homebrew)
cp ~/.../nse_scripts/*.nse /opt/homebrew/share/nmap/scripts/
nmap --script-updatedb

# Windows (PowerShell as Administrator)
$ixf = python -c "import industrialxpl; print(industrialxpl.__file__)"
$scripts_src = (Split-Path $ixf) + "\resources\nse_scripts"
Copy-Item "$scripts_src\*.nse" "C:\Program Files (x86)\Nmap\scripts\"
nmap --script-updatedb
```

---

## Script 1: `ics-sweep.nse`

**Purpose:** Rapid multi-protocol ICS service identification. Identifies any ICS service on open ports across 50+ industrial protocols. The fastest way to get an OT surface overview.

**Categories:** `discovery`, `safe`, `ics`

**Ports detected:** 102, 135, 161, 502, 1502, 2004, 2404, 4840, 5007, 5450, 5413, 9600, 10014, 20000, 20256, 22350, 44818, 47808, 48898, and more.

### Syntax

```bash
nmap --script ics-sweep [--script-args ics-sweep.timeout=N] <target>
nmap --script ics-sweep -p <ports> <target>
nmap --script ics-sweep -sV <target>    # combine with version detection
```

### Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `ics-sweep.timeout` | int | 1500 | TCP connection timeout in ms |

### Example 1: Full port scan

```bash
$ nmap --script ics-sweep -p 20-65535 192.168.1.100

Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.100
Host is up (0.001s latency).

PORT      STATE SERVICE
102/tcp   open  iso-tsap
| ics-sweep:
|   service: Siemens S7comm (ISO-TSAP)
|   type: PLC Engineering
|   risk: CRITICAL
|   address: 192.168.1.100:102
|   banner_hex: 0300001611d00000000100c0010a
|   action_required: Verify this service is not accessible from untrusted networks
|_
502/tcp   open  modbus
| ics-sweep:
|   service: Modbus TCP
|   type: PLC/RTU Process
|   risk: HIGH
|_  address: 192.168.1.100:502
4840/tcp  open  opcua
| ics-sweep:
|   service: OPC UA
|   type: SCADA/DCS/ICS
|_  risk: HIGH

Nmap done: 1 IP address (1 host up) scanned in 45.23 seconds
```

### Example 2: Targeted ICS ports

```bash
$ nmap --script ics-sweep -p 102,502,2404,4840,44818,47808,9600,20000 192.168.1.0/24

Starting Nmap 7.94
Nmap scan report for 192.168.1.50
PORT      STATE  SERVICE
2404/tcp  open   iec-104
| ics-sweep:
|   service: IEC 60870-5-104
|   type: Power Grid RTU
|   risk: CATASTROPHIC
|   action_required: Verify this service is not accessible from untrusted networks
|_

Nmap scan report for 192.168.1.100
PORT     STATE SERVICE
502/tcp  open  modbus
| ics-sweep:
|   service: Modbus TCP
|   type: PLC/RTU Process
|_  risk: HIGH

Nmap done: 254 IP addresses scanned in 12.45 seconds
```

---

## Script 2: `ics-default-creds.nse`

**Purpose:** Tests 32 common default credential pairs against HTTP, HTTPS, and other management interfaces of ICS/OT devices. Covers 20+ vendor-specific credentials (Siemens, Schneider, Rockwell, Beckhoff, Honeywell, GE, Emerson, Yokogawa, Moxa, WEG, and more).

**Categories:** `auth`, `default`, `intrusive`, `ics`

**Ports:** 80, 443, 8080, 8443, 23 (Telnet), 21 (FTP)

> **Note:** This script sends authentication requests. Use only in authorized tests.

### Syntax

```bash
nmap --script ics-default-creds -p 80,443,8080 <target>
nmap --script ics-default-creds --script-args ics-default-creds.timeout=3000 <target>
```

### Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `ics-default-creds.timeout` | int | 3000 | HTTP timeout in ms |

### Example 1: Web interface scan

```bash
$ nmap --script ics-default-creds -p 80 192.168.1.100

Nmap scan report for 192.168.1.100
PORT   STATE SERVICE
80/tcp open  http
| ics-default-creds:
|   target: 192.168.1.100:80
|   tested: 32
|   valid_credentials:
|     user='admin' pass='admin'
|     user='operator' pass=''
|   WARNING: Default ICS credentials accepted -- device may be compromised
|_
```

### Example 2: No default creds found

```bash
$ nmap --script ics-default-creds -p 443 192.168.1.200

PORT    STATE SERVICE
443/tcp open  https
ics-default-creds: No default credentials accepted
```

---

## Script 3: `ics-plc-program-access.nse`

**Purpose:** Checks if PLC engineering ports are accessible without authentication. An accessible engineering port allows unauthorized program upload/download (MITRE T0845/T0843). Does NOT attempt to upload or download programs — only verifies reachability via protocol handshake.

**Categories:** `discovery`, `safe`, `ics`

**Ports checked:** 102 (Siemens S7), 44818 (EtherNet/IP), 11740 (CODESYS), 20256 (Unitronics), 48898 (Beckhoff ADS), 9600 (Omron FINS)

### Syntax

```bash
nmap --script ics-plc-program-access -p 102,44818,11740,20256,48898,9600 <target>
nmap --script ics-plc-program-access <target>   # auto-detects open ports
```

### Example 1: Engineering access confirmed

```bash
$ nmap --script ics-plc-program-access -p 102,44818 192.168.1.100

Nmap scan report for 192.168.1.100
PORT      STATE SERVICE
102/tcp   open  iso-tsap
| ics-plc-program-access:
|   service: Siemens S7 Engineering (ISO-TSAP)
|   vendor: Siemens
|   reachable: true
|   mitre: T0845 (Program Upload), T0843 (Program Download)
|   related_cve: CVE-2021-22681 (S7 hardcoded TLS key), CVE-2022-38465 (global RSA key)
|   banner_hex: 03000016d0000000010000
|   WARNING: Engineering port ACCESSIBLE from network -- program upload/download may be possible
|_  risk: CRITICAL -- unauthorized PLC logic modification

44818/tcp open  EtherNet/IP
| ics-plc-program-access:
|   service: Rockwell EtherNet/IP CIP Engineering
|   vendor: Rockwell Automation
|   reachable: true
|   mitre: T0845 (Program Upload), T0839 (Modify Program)
|_  WARNING: Engineering port ACCESSIBLE from network
```

### Example 2: Port not responding

```bash
$ nmap --script ics-plc-program-access -p 11740 192.168.1.100

PORT      STATE    SERVICE
11740/tcp filtered unknown
ics-plc-program-access: Engineering port not responding to probe
```

---

## Script 4: `ics-safety-systems.nse`

**Purpose:** Detects Safety Instrumented Systems (SIS) exposed on the network. SIS devices are the last line of defense before physical disasters — their compromise can lead to explosions, toxic releases, or loss of life. Historical context: TRITON/TRISIS malware (2017) specifically targeted Triconex SIS at a Saudi petrochemical facility.

**Categories:** `discovery`, `safe`, `ics`

**Ports:** 1502 (Triconex TriStation), 4840 (OPC UA Safety devices)

### Syntax

```bash
nmap --script ics-safety-systems -p 1502,4840 <target>
nmap --script ics-safety-systems <target>
```

### Example 1: Triconex found

```bash
$ nmap --script ics-safety-systems -p 1502 192.168.1.50

Nmap scan report for 192.168.1.50
PORT     STATE SERVICE
1502/tcp open  unknown
| ics-safety-systems:
|   service: Triconex TriStation Protocol
|   vendor: Schneider Electric
|   type: Safety PLC (SIS)
|   reachable: true
|   mitre: T0816 (Compromise Safety Instrumented System), T0880 (Modify Alarm Settings)
|   cve: CVE-2019-6829 (Triconex integrity violation), CVE-2023-5402 (Model 3009 bypass)
|   threat: TRITON/TRISIS malware vector (2017 Saudi petrochemical attack)
|   banner: 1f0200000000000000
|   CRITICAL_WARNING: SAFETY SYSTEM accessible from network -- compromise could cause physical harm
|_  immediate_action: Isolate from all non-SIS networks. Verify no unauthorized changes to safety logic.
```

---

## Script 5: `ics-firmware-version.nse`

**Purpose:** Extracts firmware version and hardware info from ICS devices via protocol-specific read operations. Essential for CVE matching and vulnerability assessment.

**Categories:** `discovery`, `version`, `safe`, `ics`

**Ports:** 502 (Modbus FC43), 44818 (EtherNet/IP List Identity), 102 (Siemens S7 COTP)

### Syntax

```bash
nmap --script ics-firmware-version -p 502,44818,102 <target>
nmap -sV --script ics-firmware-version <target>   # combine with service version
```

### Example 1: Modbus device identification

```bash
$ nmap --script ics-firmware-version -p 502 192.168.1.100

Nmap scan report for 192.168.1.100
PORT    STATE SERVICE
502/tcp open  modbus
| ics-firmware-version:
|   target: 192.168.1.100:502
|   protocol: Modbus TC (FC43 Device Identification)
|   VendorName: Schneider Electric
|   ProductCode: Modicon M340
|   RevisionLevel: V3.20
|   VendorURL: www.schneider-electric.com
|   ProductName: BMXP342020H
|_  note: Use CVE database to match version against known vulnerabilities
```

### Example 2: Siemens S7 identification

```bash
$ nmap --script ics-firmware-version -p 102 192.168.1.50

PORT    STATE SERVICE
102/tcp open  iso-tsap
| ics-firmware-version:
|   target: 192.168.1.50:102
|   protocol: Siemens S7 ISO-TSAP
|   response_hex: 0300001611d00000000100
|_  cotp_type: CC (Connect Confirm) -- S7 accessible
```

---

## Script 6: `ics-historian-discover.nse`

**Purpose:** Discovers process historian servers used in industrial environments. Historians store years of plant data and are high-value targets.

**Categories:** `discovery`, `safe`, `ics`

**Ports:** 5450 (OSIsoft PI), 5413 (AVEVA), 10014 (AspenTech), 1433 (SQL Server historians), 49320 (Kepware OPC), 57412 (ThingWorx), 4840 (OPC UA historians), 22350 (GE Proficy), 55555 (Honeywell Experion)

### Syntax

```bash
nmap --script ics-historian-discover -p 5450,5413,10014,1433 <target>
nmap --script ics-historian-discover <target>
```

### Example 1: OSIsoft PI found

```bash
$ nmap --script ics-historian-discover -p 5450 192.168.1.200

PORT     STATE SERVICE
5450/tcp open  unknown
| ics-historian-discover:
|   service: OSIsoft PI Data Archive
|   vendor: OSIsoft/AVEVA
|   address: 192.168.1.200:5450
|   risk: Historian servers store all process data -- high-value target
|_  mitigation: Ensure historian is in DMZ; restrict access to engineering VLANs
```

---

## Script 7: `ics-enumerate.nse`

**Purpose:** Comprehensive ICS device enumeration by probing multiple industrial protocols simultaneously. Provides vendor fingerprinting and protocol identification in a single pass.

**Categories:** `discovery`, `safe`, `ics`

### Syntax

```bash
nmap --script ics-enumerate -p 102,502,2404,4840,44818,20256,48898 <target>
nmap -sV --script ics-enumerate <target>
```

### Example 1: Multi-protocol detection

```bash
$ nmap --script ics-enumerate 192.168.1.100

Nmap scan report for 192.168.1.100
PORT      STATE SERVICE
102/tcp   open  iso-tsap
| ics-enumerate:
|   ics_protocols:
|     - protocol: Siemens S7comm COTP Connect
|       vendor: Siemens (S7 COTP)
|       banner: 0300001611d00000000100
|       bytes: 22
|   target: 192.168.1.100:102
|_
44818/tcp open  EtherNet/IP
| ics-enumerate:
|   ics_protocols:
|     - protocol: EtherNet/IP List Identity
|       vendor: ICS device (vendor unidentified)
|_    banner_hex: 6500380000000000
```

---

## Script 8: `ics-honeypot-detect.nse`

**Purpose:** Detects ICS honeypots (Conpot, GasPot, GridPot, HoneyD with ICS modules) by probing for behavioral inconsistencies that real devices would not exhibit.

**Categories:** `discovery`, `safe`, `ics`

**Ports:** 502 (Modbus)

### Syntax

```bash
nmap --script ics-honeypot-detect -p 502 <target>
```

### Example 1: Honeypot detected

```bash
$ nmap --script ics-honeypot-detect -p 502 192.168.1.55

PORT    STATE SERVICE
502/tcp open  modbus
| ics-honeypot-detect:
|   target: 192.168.1.55:502
|   indicators_found: 2
|   honeypot_likely: YES -- 2 indicator(s) detected
|   indicators:
|     IDENTICAL responses to unit ID 1 and invalid unit ID 255 (Conpot pattern)
|     Responds to unit ID 0 broadcast (unusual for real Modbus device)
|_  note: Target may be a honeypot. False positives possible.
```

### Example 2: Real device

```bash
PORT    STATE SERVICE
502/tcp open  modbus
ics-honeypot-detect:
  honeypot_likely: NO -- no common honeypot patterns detected
  note: Absence of indicators does not guarantee real device
```

---

## Combined Scan Examples

### Full OT assessment with all IXF scripts

```bash
# Scan all common ICS ports with all IXF scripts
nmap --script 'ics-*' \
  -p 80,102,135,161,443,502,1502,2404,4840,5413,5450,9600,10014,20000,20256,44818,47808,48898 \
  192.168.1.0/24

# With script arguments
nmap --script 'ics-*' \
  --script-args 'ics-default-creds.timeout=3000,ics-sweep.timeout=2000' \
  192.168.1.0/24
```

### Engineering port check only

```bash
nmap --script ics-plc-program-access,ics-safety-systems \
  -p 102,1502,4840,9600,11740,20256,44818,48898 \
  192.168.1.0/24
```

### Historian discovery subnet sweep

```bash
nmap --script ics-historian-discover \
  -p 5450,5413,10014,1433,4840 \
  --open \
  192.168.1.0/24
```

### Combine with built-in Nmap ICS scripts

```bash
nmap --script 'ics-*,bacnet-info,modbus-discover,s7-info' \
  -p 102,502,44818,47808 \
  192.168.1.0/24
```

### Save output for integration with IXF

```bash
nmap --script 'ics-*' -oX ot_scan.xml 192.168.1.0/24
nmap --script 'ics-*' -oJ ot_scan.json 192.168.1.0/24
```

---

## Integration with IXF Workflow

### 1. Nmap discovers → IXF exploits

```bash
# Step 1: Discover with Nmap
nmap --script ics-sweep -p 20-65535 192.168.1.100 > targets.txt

# Step 2: Load specific CVE module in IXF based on findings
ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
ixf > set target 192.168.1.100
ixf > run
```

### 2. IXF + Nmap parallel assessment

```bash
# Terminal 1: Nmap network sweep
nmap --script 'ics-*' -p 102,502,2404,4840 192.168.1.0/24

# Terminal 2: IXF MITRE sweep simultaneously
ixf > mitre-scan discovery 192.168.1.0/24
```

---

## Troubleshooting

### Scripts not found after install

```bash
# Run updatedb manually
sudo nmap --script-updatedb

# Verify scripts exist
ls /usr/share/nmap/scripts/ics-*.nse

# Re-install
ixf > nse install --force
```

### Permission denied

```bash
# Linux
sudo python tools/nse_install.py --install

# Windows: Run as Administrator, then
python tools/nse_install.py --install
```

### `nse install` shows nmap not found

```bash
# Check nmap is in PATH
nmap --version
which nmap       # Linux/macOS
where nmap       # Windows

# Install nmap
sudo apt install nmap      # Debian/Ubuntu
brew install nmap           # macOS
# Windows: https://nmap.org/download
```

---

*Previous: [Module Catalog](13-module-catalog.md) | Back to [Index](_index.md)*
