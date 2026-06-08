![IndustrialXPL-Forge](docs/img/industrialxpl_forge-banner_16x9-en_us.png)

# IndustrialXPL-Forge (IXF)

> **The World's Largest OT/ICS/SCADA Security Assessment & Exploitation Framework**
> Part of the XPL-Forge suite | Author: André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://uniaogeek.com.br/)

[![PyPI version](https://img.shields.io/pypi/v/industrialxpl-forge?color=red&label=PyPI)](https://pypi.org/project/industrialxpl-forge/)
[![Python](https://img.shields.io/pypi/pyversions/industrialxpl-forge?color=blue&label=Python)](https://pypi.org/project/industrialxpl-forge/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://img.shields.io/github/actions/workflow/status/mrhenrike/IndustrialXPL-Forge/ci.yml?branch=master&label=CI)](https://github.com/mrhenrike/IndustrialXPL-Forge/actions)
[![Modules](https://img.shields.io/badge/Modules-972%2B-brightgreen)](https://github.com/mrhenrike/IndustrialXPL-Forge)
[![Vendors](https://img.shields.io/badge/Vendors-150%2B-orange)](https://github.com/mrhenrike/IndustrialXPL-Forge)
[![Protocols](https://img.shields.io/badge/Protocols-50%2B-blue)](https://github.com/mrhenrike/IndustrialXPL-Forge)
[![MITRE ATT&CK ICS](https://img.shields.io/badge/MITRE%20ATT%26CK%20ICS-v19-red)](https://attack.mitre.org/matrices/ics/)
[![Platform](https://img.shields.io/badge/Platform-OT%20%7C%20ICS%20%7C%20SCADA%20%7C%20IIoT-darkred)](https://github.com/mrhenrike/IndustrialXPL-Forge)

**Python-First. Pure Python implementation — install and run with a single `pip install`.**

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
- **Python-First**: all core functionality works with `pip install industrialxpl` — external runtimes (C, Go, Java) are optional accelerators with Python fallbacks built in
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

All SCADA framework modules are implemented natively in Python — no additional tools required.

---

## Documentation

Full documentation is available in both English and Brazilian Portuguese:

| Language | Link |
|----------|------|
| English (en-US) | [docs/en-us/](docs/en-us/_index.md) |
| Português (pt-BR) | [docs/pt-br/](docs/pt-br/_index.md) |

**Quick links:**

| Topic | en-US | pt-BR |
|-------|-------|-------|
| Installation | [01-installation](docs/en-us/01-installation.md) | [01-instalacao](docs/pt-br/01-instalacao.md) |
| Quick Start | [02-quick-start](docs/en-us/02-quick-start.md) | [02-inicio-rapido](docs/pt-br/02-inicio-rapido.md) |
| Shell Reference (35 commands) | [03-shell-reference](docs/en-us/03-shell-reference.md) | [03-referencia-shell](docs/pt-br/03-referencia-shell.md) |
| Module System & Option Types | [04-module-system](docs/en-us/04-module-system.md) | [04-sistema-modulos](docs/pt-br/04-sistema-modulos.md) |
| SafeMode / DestructiveMode | [05-safemode](docs/en-us/05-safemode-destructivemode.md) | [05-safemode](docs/pt-br/05-safemode-destructivemode.md) |
| MITRE ATT&CK for ICS | [06-mitre](docs/en-us/06-mitre-attack-ics.md) | [06-mitre](docs/pt-br/06-mitre-attack-ics.md) |
| SAST / LLM Analysis | [07-sast](docs/en-us/07-sast-llm.md) | [07-sast](docs/pt-br/07-sast-llm.md) |
| Protocols & Vendors | [08-protocols](docs/en-us/08-protocols-vendors.md) | [08-protocolos](docs/pt-br/08-protocolos-vendors.md) |
| Module Development | [09-dev](docs/en-us/09-module-development.md) | [09-desenvolvimento](docs/pt-br/09-desenvolvimento-modulos.md) |
| CLI Non-Interactive | [10-cli](docs/en-us/10-cli-noninteractive.md) | [10-cli](docs/pt-br/10-cli-nao-interativo.md) |
| PolyExploit Runner | [11-poly](docs/en-us/11-poly-exploit-runner.md) | [11-poly](docs/pt-br/11-poly-exploit-runner.md) |
| Assessment & Compliance | [12-assessment](docs/en-us/12-assessment-compliance.md) | [12-assessment](docs/pt-br/12-assessment-conformidade.md) |

---

## Security Modules (BLOCO J)

New attack category modules added in BLOCO J expansion:

### Ransomware / Impact Simulation

| Module | Path | Impact | Description |
|--------|------|--------|-------------|
| `plc_project_locker` | `exploits/ransomware/` | CATASTROPHIC | Zeros all Modbus holding registers (FC16). Simulates CISA AA26-097A Iranian APT PLC manipulation. Triple gate required. |
| `hmi_display_ransomware` | `exploits/ransomware/` | CATASTROPHIC | Overwrites SCADA display string tags with ransom note via Modbus FC16. Triple gate required. |

### Persistence

| Module | Path | Impact | Description |
|--------|------|--------|-------------|
| `plc_logic_bomb_inject` | `exploits/persistence/` | HIGH | Writes a trigger value to a designated holding register to activate a pre-planted logic bomb. Based on INCONTROLLER/PIPEDREAM TTPs. |

### Routing Attacks (RTP)

| Module | Path | Impact | Description |
|--------|------|--------|-------------|
| `ospf_lsa_inject` | `exploits/routing/` | HIGH | Injects forged OSPF Router LSA to poison routing tables. Based on DCmal-2025 OSPF spoofing (MDPI 2025). Requires Scapy. |
| `bgp_vortex_dos` | `exploits/routing/` | HIGH | Sends 3 crafted BGP UPDATE messages triggering persistent route oscillation. Based on USENIX Security 2025 "BGP Vortex" (Stoeger et al.). |

### Credential Attacks

| Module | Path | Impact | Description |
|--------|------|--------|-------------|
| `ics_mqtt_bruteforce` | `creds/generic/` | MEDIUM | MQTT broker credential bruteforce using native Python socket (no external MQTT library). Checks CONNACK return codes. |

### MiTM / Lateral Movement

| Module | Path | Impact | Description |
|--------|------|--------|-------------|
| `modbus_mitm_inline` | `assessment/lateral/` | HIGH | Inline Modbus TCP proxy. Logs all function codes with decoded register info. Optional value injection in FC03/FC04 responses. |

### CVE 2025

| Module | Path | CVE | Description |
|--------|------|-----|-------------|
| `siemens_telecontrol_cve_2025` | `cve/siemens/` | CVE-2025-28390 | Siemens TeleControl Server Basic authentication bypass + path traversal. CVSS 9.8. |

### Capability Table Update

| Category | Modules |
|----------|---------|
| Ransomware / Impact | `plc_project_locker`, `hmi_display_ransomware`, `ekans_snake_ics_ransomware` |
| Persistence | `plc_logic_bomb_inject` |
| Routing (RTP) | `ospf_lsa_inject`, `bgp_vortex_dos` |
| MiTM | `modbus_arp_mitm`, `modbus_mitm_inline` |
| Credentials | `ics_mqtt_bruteforce`, + 30+ vendor-specific modules |
| CVE 2025 | `siemens_telecontrol_cve_2025` |

All destructive modules default to `simulate=True`. Ransomware/wiper modules require triple gate confirmation (`simulate=False` + `destructive=True` + `explicit_confirm="I_UNDERSTAND_THIS_IS_DESTRUCTIVE"`).

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

Module sources: EmbedXPL-Forge (suite sibling), ISF/ICSSploit, ModBusSploit, n-days-poc-benchmark, InduGuard, ZeronTek OT Hunt research, CISA ICS-CERT advisories, Vedere Labs OT:ICEFALL, ExploitDB ICS catalog, GitHub public PoCs.
