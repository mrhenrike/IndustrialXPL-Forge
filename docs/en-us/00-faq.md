# Frequently Asked Questions (FAQ)

## General

### What is IndustrialXPL-Forge?

IndustrialXPL-Forge (IXF) is a Python-native security assessment and exploitation framework for Operational Technology (OT), Industrial Control Systems (ICS), SCADA, HMI, PLC, RTU, DCS, and IIoT environments. It provides 1190+ modules covering CVE exploits, protocol abuse, default credential testing, MITRE ATT&CK for ICS sweeps, and offline SAST analysis of PLC code.

### Is IXF a replacement for Metasploit?

No. IXF is purpose-built for OT/ICS environments. Where Metasploit covers general IT exploitation, IXF specializes in industrial protocols (Modbus, S7comm, DNP3, IEC 104, OPC UA, EtherNet/IP), ICS-specific CVEs, and OT-specific assessment frameworks (IEC 62443, NIST 800-82r3, MITRE ATT&CK for ICS). All core modules are native Python — no Metasploit installation required.

### Is IXF legal to use?

IXF is intended **exclusively for authorized security testing, research, and education**. Using it against systems you do not own or have explicit written permission to test is illegal in most jurisdictions. OT/ICS systems control critical physical infrastructure — unauthorized access can cause physical harm, equipment damage, and service disruption.

### Does IXF require root/administrator privileges?

Most modules work without elevated privileges. Some require elevated access:
- Installing NSE scripts to `/usr/share/nmap/scripts/` (Linux: `sudo`, Windows: Run as Administrator)
- Sending raw Layer 2 frames (e.g. `ethercat_master_spoof`, `goose_spoofing_injection`) requires raw socket access
- Creating log files in protected directories

### What Python version is required?

Python 3.9 or later. Tested on 3.9, 3.10, 3.11, 3.12, 3.13. Python 3.14 support pending when stable.

---

## Installation

### `ixf` command not found after pip install

```bash
# Check PATH includes pip scripts directory
python -m pip show industrialxpl-forge | grep Location

# Run directly
python -m industrialxpl
```

On Windows, ensure `%LOCALAPPDATA%\Programs\Python\PythonXX\Scripts\` is in PATH.

### `AttributeError: 'NoneType' object has no attribute 'write_history_file'` (Windows)

Upgrade to v1.0.12 or later:

```bash
pip install --upgrade industrialxpl-forge
```

This was a Windows readline bug fixed in v1.0.12.

### `ModuleNotFoundError: No module named 'scapy'`

Scapy is a Tier 1 dependency and should install automatically. If missing:

```bash
pip install scapy
```

On Windows, Scapy may also require [Npcap](https://npcap.com/).

### `ModuleNotFoundError: No module named 'pymodbus'`

pymodbus is a Tier 2 optional dependency for live Modbus modules:

```bash

        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
```

### How do I install ALL optional dependencies?

```bash

        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
```

---

## Usage

### How do I find modules for a specific vendor?

```
ixf > vendors siemens
ixf > search siemens
ixf > search CVE-2021-22681
```

### How do I run in simulate mode (safe, no packets sent)?

`simulate=True` is the **default** for every module. Just `run` without changing anything:

```
ixf > use scanners/ics/modbus_detect
ixf > set target 192.168.1.100
ixf > run
  [SIMULATE MODE — no packets sent]
  ...
```

### How do I enable live execution?

```
ixf > set simulate false
ixf > set destructive true
ixf > run
  [DESTRUCTIVE MODE — requires confirmation]
  ...
```

### My target is at a non-standard port. How do I set it?

```
ixf > set port 5020
```

### How do I test multiple targets?

Create a file with one IP per line and use `file://`:

```
ixf > set target file:///opt/targets.txt
ixf > run
[multi] Target: 192.168.1.1
[multi] Target: 192.168.1.2
```

Or use MITRE tactic sweeps with CIDR:

```
ixf > ttp T0843 192.168.1.0/24
```

### How do I save results?

```
ixf > report json
[+] Report saved: ixf_report_20260601_153045.json

ixf > ttp T0866 192.168.1.100 --output results.json
```

### Where are session logs stored?

- `./industrialxpl.log` — rotating session log (500 KB max)
- `./.log/destructive_ops_YYYY-MM-DD.log` — destructive operation audit log
- `~/.ixf_history` — command history

---

## Modules

### How many modules does IXF have?

1190+ modules as of v1.0.13:
- 486 CVE modules
- 159 exploit modules (protocol, PLC, SCADA, MES)
- 34 credential modules
- 31 scanner modules
- 18 assessment modules
- 26 malware TTP modules

### How do I write a new module?

See [Module Development](09-module-development.md). The minimal template is:

```python
from industrialxpl.core.exploit import Exploit, OptBool, OptIP, OptPort, mute, DestructiveGate

class Exploit(Exploit):
    __info__ = { "name": "...", "cve": "N/A", "impact": "HIGH", ... }
    target = OptIP("", "Target IP")
    simulate = OptBool(True, "Simulate")
    @mute
    def check(self): ...
    def run(self): ...
```

### How do I validate my module loads correctly?

```bash
python -c "
from industrialxpl.core.exploit.utils import import_exploit
obj = import_exploit('industrialxpl.modules.cve.myvendor.my_module')()
print(obj.get_info()['name'])
obj.run()  # runs in simulate mode
"
```

### What is the difference between Level A and Level B modules?

- **Level A**: Full end-to-end PoC — exploits the vulnerability and demonstrates impact
- **Level B**: Version check/fingerprint — identifies if the target is likely vulnerable based on service version

---

## MITRE ATT&CK for ICS

### What is the current MITRE ATT&CK for ICS coverage?

96 out of 103 techniques = **93%** as of v1.0.13.

```
ixf > mitre-coverage
  TOTAL: 96/103 (93%)
```

### How do I run a complete MITRE sweep?

```
ixf > mitre-all 192.168.1.100
```

This runs all 74 mapped techniques in simulate mode only.

### How do I export for ATT&CK Navigator?

```
ixf > mitre-report layer
[+] Layer saved: ixf_mitre_layer_20260601.json
```

Open at: https://mitre-attack.github.io/attack-navigator/

---

## SAST / LLM

### Which LLM providers are supported?

OpenAI (gpt-4o), Anthropic (claude-3-5-sonnet), Google Gemini (gemini-2.5-flash), DeepSeek (deepseek-chat), Grok (grok-2-latest).

### How do I set my API key?

```bash
export GOOGLE_AI_STUDIO_API_KEY=AIzaSy...
ixf
```

Or inside the shell:

```
ixf > llm-key gemini AIzaSyBGaoio...
```

### Does SAST send my source code to external servers?

IXF applies sanitization before sending: credentials, public IPs, hostnames, and binary blobs are redacted. Only sanitized content is sent to the LLM. See [SAST / LLM Analysis](07-sast-llm.md#sanitization-before-llm-submission) for details.

### What PLC languages does SAST support?

Structured Text (ST), Ladder Diagram (LD), Function Block Diagram (FBD), Instruction List (IL), Sequential Function Chart (SFC), Siemens SCL/AWL/STL, Rockwell L5X, ABB AP1, CODESYS project files.

---

## NSE Scripts

### How do I install IXF Nmap scripts?

```bash
# Linux (may need sudo)
python tools/nse_install.py --install

# Windows (may need Administrator)
python tools/nse_install.py --install

# Or inside IXF shell
ixf > nse install
```

### Nmap is not installed. Can I still use the NSE scripts?

Yes — the .nse files are stored in `industrialxpl/resources/nse_scripts/`. Copy them manually to your Nmap scripts directory after installing Nmap.

### Where is the Nmap scripts directory on different platforms?

| Platform | Path |
|----------|------|
| Linux (apt) | `/usr/share/nmap/scripts/` |
| Linux (source) | `/usr/local/share/nmap/scripts/` |
| macOS (Homebrew) | `/opt/homebrew/share/nmap/scripts/` |
| Windows | `C:\Program Files (x86)\Nmap\scripts\` |

---

## Troubleshooting

### `ixf` starts but shows 0 modules indexed

```bash
python -c "from industrialxpl.core.exploit.utils import index_modules; print(len(index_modules()))"
```

If 0, the package data may not have been installed correctly:
```bash
pip install --force-reinstall industrialxpl-forge
```

### Modules load but `run` gives no output

Check that `target` is set:
```
ixf > show options
ixf > set target 192.168.1.100
```

### `Permission denied` when installing NSE scripts

Linux: `sudo python tools/nse_install.py --install`
Windows: Run terminal as Administrator

### `ImportError` for pysnmp or scapy

```bash
pip install pysnmp>=6.1 scapy>=2.5
```

Note: pysnmp v4.x is incompatible with Python 3.12+. Use pysnmp 6.1+.

### The shell history doesn't work (Windows)

`pyreadline3` should be installed automatically on Windows. If not:
```bash
pip install pyreadline3>=3.4
```

---

*Back to [Index](_index.md)*
