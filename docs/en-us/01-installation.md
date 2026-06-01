# Installation

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.9 | 3.11 or 3.12 |
| OS | Windows 10, Linux, macOS 11 | Ubuntu 22.04 / Windows 11 |
| RAM | 256 MB | 512 MB |
| Disk | 150 MB | 500 MB (with native malware artifacts) |

Python versions tested: **3.9, 3.10, 3.11, 3.12, 3.13**.

---

## Install from PyPI (Recommended)

```bash
pip install industrialxpl-forge
```

After installation the `ixf` CLI command is available globally:

```bash
ixf
```

Expected output:

```
[*] Indexing modules…
[+] 976 modules indexed.

  ___           _           _       _  __  ______  _       ______
 |_ _|_ __   __| |_   _ ___| |_ _ __(_) \ \/ / _ \| |     |  ___|__  _ __ __ _  ___
  | || '_ \ / _` | | | / __| __| '__| |  \  /|  __/| |     | |_ / _ \| '__/ _` |/ _ \
  | || | | | (_| | |_| \__ \ |_| |  | |  /  \| |   | |___  |  _| (_) | | | (_| |  __/
 |___|_| |_|\__,_|\__,_|___/\__|_|  |_| /_/\_\_|   |_____| |_|  \___/|_|  \__, |\___|
                                                                              |___/
  IndustrialXPL-Forge v1.0.12 — OT/ICS/SCADA Security Assessment Framework
  Author: André Henrique (@mrhenrike) | União Geek | https://uniaogeek.com.br/
  Python-First. Pure Python — install with pip install industrialxpl-forge.
  Type 'help' for commands.  simulate=True by default (safe mode).

ixf >
```

---

## Install from Source

```bash
git clone https://github.com/mrhenrike/IndustrialXPL-Forge.git
cd IndustrialXPL-Forge
pip install -r requirements.txt
python ixf.py
```

For development (includes testing and linting tools):

```bash
pip install -e ".[dev]"
```

---

## Optional Dependency Extras

IXF follows a **tiered dependency model**. The core installation covers Tier 0 and Tier 1.

### Tier 0 — Python Standard Library (always available)

`socket`, `struct`, `select`, `subprocess`, `threading`, `pathlib`, `json`, `re`, `os`

No installation needed.

### Tier 1 — Core pip dependencies (installed automatically)

| Package | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.31.0,<3.0 | HTTP/REST exploitation modules |
| `urllib3` | >=1.26.0,<3.0 | HTTP transport (requests dependency) |
| `paramiko` | >=3.0 | SSH default credential testing |
| `pysnmp` | >=6.1 | SNMP scanner and enumeration modules |
| `scapy` | >=2.5 | Packet crafting (Layer 2/3 attacks) |
| `rich` | >=13.0 | Terminal tables, colors, banners |
| `psutil` | >=5.9 | Process and system info |
| `pyreadline3` | >=3.4 | **Windows only** — readline history and tab completion |

### Tier 2 — Optional pip extras

Install these for specific protocol or SAST functionality:

```bash
# OT/ICS protocol libraries
pip install industrialxpl-forge[ot]
# Installs: pymodbus (Modbus TCP/RTU), asyncua (OPC UA), cpppo (EtherNet/IP/CIP)

# Industrial fieldbus
pip install industrialxpl-forge[fieldbus]
# Installs: python-can (CAN bus / CANopen)

# SAST / LLM analysis
pip install industrialxpl-forge[sast]
# Installs: openai, anthropic

# Everything
pip install industrialxpl-forge[full]
```

### Tier 3 — External runtimes (fully optional)

These runtimes enable native malware artifact compilation and multi-language exploit execution. IXF always has a **Python fallback** when they are absent.

| Runtime | Purpose | Install |
|---------|---------|---------|
| `gcc` / `g++` | Compile C/C++ native exploits (KillDisk, NotPetya replica) | System package manager |
| `go` | Compile Go malware (FrostyGoop extended) | https://go.dev/dl/ |
| `node` | JavaScript/TypeScript exploit modules | https://nodejs.org/ |
| `java` / `javac` | Java deserialization exploits | https://adoptium.net/ |
| `ruby` | Ruby exploit modules | https://www.ruby-lang.org/ |
| `pwsh` | PowerShell OT modules | https://github.com/PowerShell/PowerShell |
| `perl` | Legacy ICS scripts | System package manager |

Check runtime availability:

```bash
python tools/env_doctor.py
```

---

## Platform Notes

### Windows

`pyreadline3` is automatically installed on Windows (`sys_platform == 'win32'`). This provides command history (Up/Down arrows) and Tab completion in the IXF shell.

If you encounter `AttributeError: 'NoneType' object has no attribute 'write_history_file'`, upgrade to v1.0.12 or later:

```bash
pip install --upgrade industrialxpl-forge
```

### Linux / macOS

`readline` is part of the standard library. No additional configuration needed.

### Running inside Docker or CI

```bash
# Minimal Docker image
pip install industrialxpl-forge
python -c "from industrialxpl.core.exploit.utils import index_modules; print(len(index_modules()), 'modules')"
```

---

## Verifying the Installation

```bash
ixf
```

The banner should display the version and module count. To confirm all core dependencies:

```bash
python tools/env_doctor.py
```

Sample output:

```
[Python]
  Python 3.11.9  OK

[Tier 1 — Required pip]
  requests  2.32.4   OK
  paramiko  3.5.1    OK
  scapy     2.5.0    OK
  rich      13.9.4   OK
  psutil    6.1.0    OK
  pysnmp    6.2.1    OK

[Tier 2 — Optional pip extras]
  pymodbus  OPTIONAL   pip install industrialxpl[ot]
  asyncua   OPTIONAL   pip install industrialxpl[ot]
  cpppo     OPTIONAL   pip install industrialxpl[ot]
  python-can OPTIONAL  pip install industrialxpl[fieldbus]

[Tier 3 — External runtimes]
  ruby      not found  OPTIONAL
  node      OPTIONAL   https://nodejs.org/
  java      OPTIONAL   https://adoptium.net/
  gcc       OPTIONAL   apt install gcc / brew install gcc
  g++       OPTIONAL   apt install g++ / brew install g++
  go        OPTIONAL   https://go.dev/dl/
  pwsh      OPTIONAL   github.com/PowerShell/PowerShell

[IXF Module Index]
  976 modules indexed.

  Python-First: core functionality works without Tier 3
  pip install industrialxpl[ot] for Tier 2 (OT protocols)
  pip install industrialxpl[full] for everything
```

---

## Uninstall

```bash
pip uninstall industrialxpl-forge
```

Logs and history are stored locally and are not removed by pip:
- `~/.ixf_history` — command history
- `./industrialxpl.log` — rotating session log
- `./.log/destructive_ops_*.log` — destructive operation audit logs

---

*Next: [Quick Start](02-quick-start.md)*
