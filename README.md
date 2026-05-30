# IndustrialXPL-Forge (IXF)

> **The World's Largest OT/ICS/SCADA Security Assessment & Exploitation Framework**
> Part of the XPL-Forge suite | Author: André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://uniaogeek.com.br/)

**Python-First — no Metasploit required. No msfconsole. No Ruby. Just Python.**

---

## Quick Start

```bash
pip install industrialxpl
ixf
```

Or from source:

```bash
git clone https://github.com/mrhenrike/IndustrialXPL-Forge
cd IndustrialXPL-Forge
pip install -r requirements.txt
python ixf.py
```

---

## What is IXF?

IndustrialXPL-Forge is a modular, Python-native security assessment and exploitation framework for **Operational Technology (OT)**, **Industrial Control Systems (ICS)**, **SCADA**, **HMI**, **PLC**, **RTU**, **DCS**, and **IIoT** environments.

It covers the **complete attack lifecycle**:

```
OSINT → Discovery → Fingerprint → Vulnerability Check → Exploit → Report
```

**Key features:**
- **Python-First**: all core functionality works with `pip install industrialxpl` — no Metasploit, no msfconsole, no Java, no Ruby required
- **SafeMode by default**: every module runs in simulate mode — prints payload without sending
- **MITRE ATT&CK for ICS v19**: 79 techniques mapped, `ttp T0843 192.168.1.100` syntax
- **CVE coverage**: 3,300+ ICS/OT CVEs from CVSS 0.1 to 10.0
- **50 vendors**: Siemens, Schneider, Rockwell, ABB, Honeywell, Emerson, WEG, and more
- **50 protocols**: Modbus, S7comm, EtherNet/IP, DNP3, BACnet, IEC-104, OPC UA, PROFINET, and more

---

## Module Catalog

| Category | Modules | Description |
|----------|---------|-------------|
| `exploits/protocols/` | ~50 | Modbus, S7, ENIP, DNP3, BACnet, Profinet, IEC104, OPC UA |
| `exploits/plc/` | ~80 | Siemens, Schneider, Rockwell, GE, Beckhoff, Unitronics, ABB |
| `exploits/scada/` | ~60 | IGSS, RealWin, Genesis32, CoDeSys, FUXA, CitectSCADA |
| `exploits/mes/` | ~25 | Ignition, ThinManager, SIMATIC Historian, DELMIA Apriso |
| `scanners/ics/` | ~50 | Protocol-specific discovery (Modbus, S7, BACnet, DNP3...) |
| `scanners/osint/` | ~8 | Shodan queries, ELITEWOLF web dorks, OT Hunt |
| `creds/` | ~55 | Default credentials for 50+ OT/ICS vendors |
| `cve/` | 3,300+ | All CVE severity levels (CVSS 0.1-10.0), 3 implementation tiers |
| `cve/apt/` | ~10 | APT malware TTPs: FrostyGoop, Industroyer2, TRITON, INCONTROLLER |
| `assessment/` | ~25 | IEC 62443, NIST 800-82r3, MITRE ICS, risk scoring, IR playbook |

---

## Usage Examples

```
# Open the IXF interactive shell
ixf

# Load and run a module (simulate mode by default — safe)
ixf > use scanners/ics/modbus_detect
ixf > set target 192.168.1.100
ixf > check

# Search for modules
ixf > search siemens
ixf > search CVE-2015-5374
ixf > search modbus

# Execute a TTP-ID against a target
ixf > ttp T0843 192.168.1.100          # Program Download — all modules
ixf > ttp T0878 10.0.0.0/24            # Alarm Suppression — subnet sweep
ixf > ttp-list --tactic evasion        # List all Evasion TTP-IDs

# MITRE ATT&CK for ICS sweep
ixf > mitre-scan discovery 192.168.1.0/24
ixf > mitre-scan evasion 192.168.1.100
ixf > mitre-all 192.168.1.100          # All 79 techniques (simulate by default)
ixf > mitre-coverage                   # Show coverage % per tactic

# CVE-specific modules
ixf > cve CVE-2026-25895               # FUXA SCADA pre-auth RCE
ixf > cve CVE-2015-5374               # Siemens SIPROTEC4 DoS
ixf > cve-scan 192.168.1.0/24         # Discover assets + test all CVEs

# Generate reports
ixf > report json
ixf > mitre-report layer               # ATT&CK Navigator JSON layer
```

---

## SafeMode / DestructiveMode

**Every module defaults to simulate mode** — it prints what it WOULD do without sending any packets.

```
ixf (FrostyGoop) > run                 # SIMULATE: prints payload, no send
ixf (FrostyGoop) > set simulate false
ixf (FrostyGoop) > set destructive true
ixf (FrostyGoop) > run                 # LIVE: shows banner + requires confirmation
```

Impact levels require proportional confirmation:
- `INFO/READ`: automatic
- `LOW`: simple warning
- `MEDIUM`: press Enter
- `HIGH`: type `yes`
- `CRITICAL`: type the full confirmation string
- `CATASTROPHIC`: type string + wait 10 seconds

All destructive operations are logged to `.log/destructive_ops_YYYY-MM-DD.log`.

---

## Python-First Policy

| Tier | Type | Examples | Required? |
|------|------|----------|-----------|
| **0** | Python stdlib | socket, struct, select | Always |
| **1** | pip install | pymodbus, scapy, rich, requests | Yes |
| **2** | pip extras | asyncua, cpppo, python-can | Optional |
| **3** | External runtimes | ruby, node, java, gcc, go | **Optional — Python fallback always available** |

No Metasploit installation required. All 64 MSF SCADA modules are ported to Python native.

---

## Legal Disclaimer

This tool is intended for **authorized security testing, research, and educational purposes only**.

Using IndustrialXPL-Forge against systems you do not own or do not have **explicit written authorization** to test is **illegal** and may violate computer fraud laws in your jurisdiction.

OT/ICS systems control critical physical infrastructure. Unauthorized use may cause:
- Physical damage to industrial equipment
- Disruption of essential services (power, water, gas, manufacturing)
- Personal injury or death
- Significant legal penalties

**The authors and União Geek assume no liability for misuse. Users bear full legal and ethical responsibility for all actions performed with this tool.**

---

## Author & Credits

**Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://uniaogeek.com.br/)

Module sources: EmbedXPL-Forge (suite sibling), ISF/ICSSploit, ModBusSploit, Metasploit SCADA modules (ported to Python), n-days-poc-benchmark, InduGuard, ZeronTek OT Hunt research, CISA ICS-CERT advisories, Vedere Labs OT:ICEFALL.
