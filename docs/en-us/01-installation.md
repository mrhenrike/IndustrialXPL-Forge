# Installation

IndustrialXPL-Forge (IXF) is a pure Python framework published on PyPI. The recommended installation method is `pip`. All core functionality is available immediately after install — no compilers, containers, or external tools are required for the base install.

---

## System Requirements

### Minimum and Recommended Platform Requirements

| Requirement | Minimum | Recommended | Notes |
|-------------|---------|-------------|-------|
| Python | 3.9 | 3.11 or 3.12 | 3.13 tested; 3.8 not supported (walrus operator, `tomllib`) |
| Operating System | Windows 10, Ubuntu 20.04, macOS 11 | Ubuntu 22.04 LTS / Windows 11 | See per-OS notes below |
| RAM | 256 MB free | 512 MB free | Native malware artifact compilation requires 1+ GB |
| Disk | 150 MB | 500 MB | Extra space for compiled artifacts, LLM responses cached locally |
| Network | None (offline use) | Gigabit LAN access to OT segment | For live module execution |
| pip | 21.0 | 24.x | `pip install --upgrade pip` before installing IXF |
| Shell | Any | bash / PowerShell 7 | Interactive shell history via readline/pyreadline3 |

### Python Version Matrix

| Python Version | Status | Notes |
|----------------|--------|-------|
| 3.9 | Supported | Minimum; some type hints use `X \| Y` which requires 3.10+ in annotations |
| 3.10 | Supported | Full feature set |
| 3.11 | **Recommended** | Best performance; used for official releases |
| 3.12 | Supported | Tested in CI pipeline |
| 3.13 | Tested | Experimental; report issues on GitHub |
| 3.8 and below | Not supported | Missing walrus operator and stdlib modules |

### Per-OS Platform Notes

| OS | Support Level | Notes |
|----|---------------|-------|
| Ubuntu 22.04 LTS | Primary | Official test environment; all features supported |
| Ubuntu 20.04 LTS | Supported | Requires Python 3.9+ from deadsnakes PPA |
| Debian 11/12 | Supported | Same as Ubuntu; use `python3-pip` from apt |
| Fedora 38+ | Supported | Python 3.11+ available in default repos |
| CentOS Stream 9 | Supported | Install python3.11 via DNF |
| RHEL 8/9 | Supported | Use SCL or compile Python; `scapy` needs libpcap-devel |
| Kali Linux | Supported | Ideal for security assessments; all Tier 3 runtimes available |
| Parrot OS | Supported | Same as Kali |
| Windows 10 (21H2+) | Supported | `pyreadline3` auto-installed; Windows Firewall may block raw sockets |
| Windows 11 | Supported | Best Windows experience; WSL2 recommended for Scapy raw sockets |
| Windows Server 2019/2022 | Supported | For CI/CD runners and lab VMs |
| macOS 12 Monterey | Supported | Homebrew Python recommended over system Python |
| macOS 13/14 | Supported | Apple Silicon (M-series) fully supported |
| Docker (any OS) | Supported | See Docker section below |
| WSL2 (Ubuntu 22.04) | Supported | Full raw socket access; best of both worlds on Windows hosts |
| Raspberry Pi OS (64-bit) | Supported | Useful for lab gateway simulation |

---

## Install from PyPI (Recommended)

The simplest and most reliable installation method:

```bash

        ```

### Full Terminal Output (pip install)

The following is a complete representative terminal session showing the full install output, including the progress bars pip displays when downloading and installing packages:

```
$ 
        Collecting industrialxpl-forge
  Downloading industrialxpl_forge-1.0.31-py3-none-any.whl.metadata (8.4 kB)
Collecting requests>=2.31.0 (from industrialxpl-forge)
  Downloading requests-2.32.4-py3-none-any.whl.metadata (4.9 kB)
Collecting urllib3>=1.26.0 (from industrialxpl-forge)
  Downloading urllib3-2.3.0-py3-none-any.whl.metadata (6.5 kB)
Collecting paramiko>=3.0 (from industrialxpl-forge)
  Downloading paramiko-3.5.1-py3-none-any.whl.metadata (4.4 kB)
Collecting pysnmp>=6.1 (from industrialxpl-forge)
  Downloading pysnmp-6.2.6-py3-none-any.whl.metadata (6.2 kB)
Collecting scapy>=2.5 (from industrialxpl-forge)
  Downloading scapy-2.6.1-py3-none-any.whl.metadata (12.9 kB)
Collecting rich>=13.0 (from industrialxpl-forge)
  Downloading rich-13.9.4-py3-none-any.whl.metadata (18.8 kB)
Collecting psutil>=5.9 (from industrialxpl-forge)
  Downloading psutil-6.1.1-cp311-cp311-linux_x86_64.whl.metadata (22.5 kB)
Collecting pyreadline3>=3.4 ; sys_platform == 'win32' (from industrialxpl-forge)
  NOTE: Platform is linux; pyreadline3 not required.
Collecting cryptography>=41.0 (from paramiko>=3.0->industrialxpl-forge)
  Downloading cryptography-44.0.3-cp311-cp311-linux_x86_64.whl.metadata (5.5 kB)
Collecting bcrypt>=3.2 (from paramiko>=3.0->industrialxpl-forge)
  Downloading bcrypt-4.3.0-cp311-cp311-linux_x86_64.whl.metadata (9.7 kB)
Collecting pynacl>=1.5 (from paramiko>=3.0->industrialxpl-forge)
  Downloading PyNaCl-1.5.0-cp39-abi3-linux_x86_64.whl.metadata (8.9 kB)
Collecting pyasn1>=0.4.6 (from pysnmp>=6.1->industrialxpl-forge)
  Downloading pyasn1-0.6.1-py3-none-any.whl.metadata (8.4 kB)
Collecting pyasn1-modules>=0.3.0 (from pysnmp>=6.1->industrialxpl-forge)
  Downloading pyasn1_modules-0.4.1-py3-none-any.whl.metadata (3.5 kB)
Collecting markdown-it-py>=2.2.0 (from rich>=13.0->industrialxpl-forge)
  Downloading markdown_it_py-3.0.0-py3-none-any.whl.metadata (6.9 kB)
Collecting pygments<3.0.0,>=2.13.0 (from rich>=13.0->industrialxpl-forge)
  Downloading pygments-2.19.1-py3-none-any.whl.metadata (2.5 kB)
Collecting charset-normalizer<4,>=2 (from requests>=2.31.0->industrialxpl-forge)
  Downloading charset_normalizer-3.4.2-cp311-cp311-linux_x86_64.whl.metadata (35 kB)
Collecting idna<4,>=2.5 (from requests>=2.31.0->industrialxpl-forge)
  Downloading idna-3.10-py3-none-any.whl.metadata (10 kB)
Collecting certifi>=2017.4.17 (from requests>=2.31.0->industrialxpl-forge)
  Downloading certifi-2025.4.26-py3-none-any.whl.metadata (2.2 kB)
Collecting cffi>=1.12 (from cryptography>=41.0->paramiko>=3.0->industrialxpl-forge)
  Downloading cffi-1.17.1-cp311-cp311-linux_x86_64.whl.metadata (1.5 kB)
Collecting mdurl~=0.1 (from markdown-it-py>=2.2.0->rich>=13.0->industrialxpl-forge)
  Downloading mdurl-0.1.2-py3-none-any.whl.metadata (1.6 kB)
Collecting pycparser (from cffi>=1.12->cryptography>=41.0->paramiko>=3.0->industrialxpl-forge)
  Downloading pycparser-2.22-py3-none-any.whl.metadata (943 bytes)

Downloading industrialxpl_forge-1.0.31-py3-none-any.whl (2.4 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.4/2.4 MB 8.2 MB/s eta 0:00:00
Downloading requests-2.32.4-py3-none-any.whl (64 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 64.5/64.5 kB 5.1 MB/s eta 0:00:00
Downloading urllib3-2.3.0-py3-none-any.whl (128 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 128.5/128.5 kB 9.3 MB/s eta 0:00:00
Downloading paramiko-3.5.1-py3-none-any.whl (228 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 228.1/228.1 kB 11.4 MB/s eta 0:00:00
Downloading pysnmp-6.2.6-py3-none-any.whl (349 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 349.2/349.2 kB 14.7 MB/s eta 0:00:00
Downloading scapy-2.6.1-py3-none-any.whl (1.5 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1.5/1.5 MB 10.8 MB/s eta 0:00:00
Downloading rich-13.9.4-py3-none-any.whl (242 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 242.8/242.8 kB 13.1 MB/s eta 0:00:00
Downloading psutil-6.1.1-cp311-cp311-linux_x86_64.whl (431 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 431.6/431.6 kB 16.2 MB/s eta 0:00:00
Downloading cryptography-44.0.3-cp311-cp311-linux_x86_64.whl (4.2 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 4.2/4.2 MB 12.4 MB/s eta 0:00:00
Downloading bcrypt-4.3.0-cp311-cp311-linux_x86_64.whl (157 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 157.5/157.5 kB 12.0 MB/s eta 0:00:00
Downloading PyNaCl-1.5.0-cp39-abi3-linux_x86_64.whl (1.1 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1.1/1.1 MB 13.9 MB/s eta 0:00:00
Downloading pyasn1-0.6.1-py3-none-any.whl (83 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 83.7/83.7 kB 8.8 MB/s eta 0:00:00
Downloading pyasn1_modules-0.4.1-py3-none-any.whl (181 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 181.4/181.4 kB 11.5 MB/s eta 0:00:00
Downloading markdown_it_py-3.0.0-py3-none-any.whl (87 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 87.5/87.5 kB 9.2 MB/s eta 0:00:00
Downloading pygments-2.19.1-py3-none-any.whl (1.2 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1.2/1.2 MB 11.7 MB/s eta 0:00:00
Downloading charset_normalizer-3.4.2-cp311-cp311-linux_x86_64.whl (148 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 148.6/148.6 kB 10.4 MB/s eta 0:00:00
Downloading idna-3.10-py3-none-any.whl (70 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 70.0/70.0 kB 7.6 MB/s eta 0:00:00
Downloading certifi-2025.4.26-py3-none-any.whl (159 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 159.8/159.8 kB 10.9 MB/s eta 0:00:00
Downloading cffi-1.17.1-cp311-cp311-linux_x86_64.whl (470 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 471.3/471.3 kB 14.3 MB/s eta 0:00:00
Downloading mdurl-0.1.2-py3-none-any.whl (10 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 10.3/10.3 kB 1.8 MB/s eta 0:00:00
Downloading pycparser-2.22-py3-none-any.whl (117 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 117.1/117.1 kB 9.0 MB/s eta 0:00:00

Installing collected packages: pycparser, pyasn1, pygments, mdurl, idna, charset-normalizer,
  certifi, urllib3, scapy, psutil, pyasn1-modules, pynacl, mdurl, markdown-it-py, cffi,
  rich, requests, pysnmp, cryptography, bcrypt, paramiko, industrialxpl-forge
Successfully installed bcrypt-4.3.0 certifi-2025.4.26 cffi-1.17.1 charset-normalizer-3.4.2
  cryptography-44.0.3 idna-3.10 industrialxpl-forge-1.0.12 markdown-it-py-3.0.0
  mdurl-0.1.2 paramiko-3.5.1 psutil-6.1.1 pyasn1-0.6.1 pyasn1-modules-0.4.1
  pycparser-2.22 pygments-2.19.1 pynacl-1.5.0 pysnmp-6.2.6 requests-2.32.4
  rich-13.9.4 scapy-2.6.1 urllib3-2.3.0
```

After installation, launch the IXF shell:

```bash
$ ixf
[*] Indexing modules…
[+] 976 modules indexed.

  ___           _           _       _  __  ______  _       ______
 |_ _|_ __   __| |_   _ ___| |_ _ __(_) \ \/ / _ \| |     |  ___|__  _ __ __ _  ___
  | || '_ \ / _` | | | / __| __| '__| |  \  /|  __/| |     | |_ / _ \| '__/ _` |/ _ \
  | || | | | (_| | |_| \__ \ |_| |  | |  /  \| |   | |___  |  _| (_) | | | (_| |  __/
 |___|_| |_|\__,_|\__,_|___/\__|_|  |_| /_/\_\_|   |_____| |_|  \___/|_|  \__, |\___|
                                                                              |___/
  IndustrialXPL-Forge v1.0.31 — OT/ICS/SCADA Security Assessment Framework
  Author: André Henrique (@mrhenrike) | União Geek | https://uniaogeek.com.br/
  Python-First. Pure Python — install with 
        .
  Type 'help' for commands.  simulate=True by default (safe mode).

ixf >
```

---

## Virtual Environment Setup (Recommended)

Always install IXF inside a virtual environment to avoid conflicts with system Python packages. This is especially important on macOS and Kali Linux where system Python is managed by the OS.

### Creating and activating a virtual environment

**Linux / macOS:**

```bash
# Create the virtual environment
python3 -m venv ~/.venvs/ixf

# Activate it
source ~/.venvs/ixf/bin/activate

# Verify activation (prompt changes to show env name)
(ixf) $ which python
/home/user/.venvs/ixf/bin/python

# Install IXF into the venv
(ixf) $ 
        ```

**Windows (PowerShell):**

```powershell
# Create the virtual environment
python -m venv $HOME\.venvs\ixf

# Activate it (PowerShell)
& $HOME\.venvs\ixf\Scripts\Activate.ps1

# Verify activation
(ixf) PS> where.exe python
C:\Users\mrhen\.venvs\ixf\Scripts\python.exe

# Install IXF
(ixf) PS> 
        ```

**Windows (cmd.exe):**

```cmd
python -m venv %USERPROFILE%\.venvs\ixf
%USERPROFILE%\.venvs\ixf\Scripts\activate.bat

        ```

### Making the `ixf` command persistent

After activation, `ixf` is available as a command. To make it permanent without needing to activate the venv each time, add an alias or wrapper:

**Linux / macOS (~/.bashrc or ~/.zshrc):**

```bash
alias ixf="~/.venvs/ixf/bin/ixf"
```

**Windows (PowerShell profile):**

```powershell
function ixf { & "$HOME\.venvs\ixf\Scripts\ixf.exe" @args }
```

---

## Install from Source

For development, contribution, or running the latest unreleased commit:

```bash
# Step 1: Clone the repository
git clone https://github.com/mrhenrike/IndustrialXPL-Forge.git
cd IndustrialXPL-Forge

# Step 2: (Optional but recommended) Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows PowerShell

# Step 3: Upgrade pip
pip install --upgrade pip

# Step 4: Install core requirements
pip install -r requirements.txt

# Step 5: Launch
ixf
```

### Source Install: Development Mode

Install in editable mode for active development. Changes to source files are immediately reflected without reinstalling:

```bash
# Editable install with dev extras (includes pytest, mypy, ruff, coverage)
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Type check
mypy industrialxpl/

# Lint
ruff check industrialxpl/
```

### Source Install: Full Extras

```bash
# Install everything: ot, fieldbus, sast, dev
pip install -e ".[full,dev]"
```

### Source Directory Structure

```
IndustrialXPL-Forge/
├── industrialxpl/                  # Main package
│   ├── core/
│   │   ├── exploit/               # Module loading, option system, SafeMode gate
│   │   └── shell/                 # Interactive shell, completer, history
│   ├── modules/
│   │   ├── cve/                   # CVE exploit modules (by vendor)
│   │   ├── scanners/ics/          # Protocol scanner modules
│   │   ├── exploits/protocols/    # Protocol exploit modules
│   │   ├── creds/                 # Default credential modules
│   │   ├── assessment/            # Compliance/assessment modules
│   │   ├── malware/               # Malware TTP simulation
│   │   └── nse/                   # NSE script wrappers
│   └── tools/
│       └── env_doctor.py          # Dependency checker
├── tools/
│   ├── env_doctor.py              # Also accessible here
│   └── nse/                       # Nmap NSE scripts
├── requirements.txt               # Tier 1 dependencies
├── pyproject.toml                 # Build system and extras configuration
├── ixf.py                         # CLI entry point (source mode)
└── docs/                          # Documentation
```

---

## Optional Dependency Extras

IXF follows a **tiered dependency model**. The base `
        ` covers Tier 0 and Tier 1. Tiers 2 and 3 unlock additional protocol libraries, AI-powered SAST, and native multi-language execution.

### Tier 0 — Python Standard Library (Always Available)

No installation required. These modules ship with every Python 3.9+ interpreter.

| Module | Purpose in IXF |
|--------|----------------|
| `socket` | Raw TCP/UDP connections to OT devices |
| `struct` | Binary protocol packet packing/unpacking (Modbus, S7, DNP3) |
| `select` | Async I/O multiplexing for multi-target scanners |
| `subprocess` | Launching Tier 3 runtimes (gcc, go, node) |
| `threading` | Parallel module execution in `mitre-scan` sweeps |
| `pathlib` | Cross-platform file path handling |
| `json` | Module metadata, option serialization, report output |
| `re` | Pattern matching in `search`, CVE ID parsing |
| `os` | Environment variable access, process management |
| `logging` | Structured log output to `industrialxpl.log` |
| `hashlib` | Module integrity verification |
| `hmac` | Constant-time comparison for auth tokens |
| `ssl` | TLS connections (OPC UA, S7comm+) |
| `tomllib` | Parsing `pyproject.toml` extras (Python 3.11+) |
| `importlib` | Dynamic module loading from module paths |
| `readline` | Shell history and completion (Linux/macOS) |
| `cmd` | Base class for the IXF interactive shell |
| `shlex` | Safe tokenization of user shell input |
| `datetime` | Timestamp formatting in reports and audit logs |
| `csv` | CSV report export |
| `base64` | Payload encoding in simulate output |
| `ipaddress` | CIDR range validation for target options |

### Tier 1 — Core pip Dependencies (Installed Automatically)

These packages are declared in `install_requires` and installed automatically by pip.

| Package | Pinned Version | Purpose | Why Required |
|---------|----------------|---------|--------------|
| `requests` | >=2.31.0,<3.0 | HTTP/REST exploitation modules | HTTPS connections to HMIs, web APIs, Niagara, WebCTRL |
| `urllib3` | >=1.26.0,<3.0 | HTTP transport layer | Dependency of requests; also used directly for connection pooling |
| `paramiko` | >=3.0 | SSH default credential testing | Credential modules for network devices and Linux-based RTUs |
| `pysnmp` | >=6.1 | SNMP v1/v2c/v3 operations | OT device enumeration, community string brute force |
| `scapy` | >=2.5 | Raw packet crafting | Layer 2/3 protocol attacks, GOOSE injection, DNP3 raw frames |
| `rich` | >=13.0 | Terminal UI | Tables, progress bars, colored banners, panels |
| `psutil` | >=5.9 | Process/system information | Detect running engineering software, runtime availability checks |
| `cryptography` | >=41.0 | TLS, crypto primitives | S7comm+ TLS key extraction, JWT handling, credential hashing |
| `pyreadline3` | >=3.4 | **Windows only** — readline | Command history (Up/Down arrows), Tab completion on Windows |

### Tier 2 — Optional pip Extras

Install these extras to unlock specific protocol libraries and AI-powered SAST analysis.

#### `[ot]` — OT/ICS Protocol Libraries

```bash

        ```

**Installs:** `pymodbus>=3.0`, `asyncua>=1.0`, `cpppo>=4.3`

| Package | What It Enables |
|---------|----------------|
| `pymodbus` | Full Modbus TCP/RTU client: function codes 1–24, write coil flood, register manipulation, firmware interrogation via FC43 (Read Device Identification). Without this package, IXF falls back to raw socket Modbus using Tier 0 `socket` + `struct`. |
| `asyncua` | Native OPC UA client: endpoint enumeration, namespace browsing, unauthenticated write testing, SecurityMode=None detection, certificate validation bypass testing. Replaces the raw TCP fallback. |
| `cpppo` | EtherNet/IP / CIP client: tag enumeration on ControlLogix/CompactLogix PLCs, PCCC forward open, identity object read. Required for the `exploits/protocols/enip/` family of modules. |

Without `[ot]`, the Modbus, OPC UA, and EtherNet/IP modules still run using raw socket implementations from Tier 0. The raw fallback covers the most common attack surfaces but does not support advanced function codes or session management.

#### `[fieldbus]` — Industrial Fieldbus

```bash

        ```

**Installs:** `python-can>=4.0`

| Package | What It Enables |
|---------|----------------|
| `python-can` | CAN bus interface for CANopen protocol modules. Required for modules under `exploits/protocols/canopen/` and any module interacting with CAN-attached safety controllers. Requires a physical or virtual CAN adapter (SocketCAN on Linux, PCAN on Windows). |

#### `[sast]` — SAST / LLM Analysis

```bash

        ```

**Installs:** `openai>=1.0`, `anthropic>=0.25`

| Package | What It Enables |
|---------|----------------|
| `openai` | OpenAI GPT-4o / GPT-4 analysis for `sast` command. Sends sanitized PLC source code to OpenAI API for vulnerability identification in Ladder Logic, Structured Text, and FBD. |
| `anthropic` | Anthropic Claude 3 Opus/Sonnet analysis for `sast` command. Alternative LLM provider with strong context window for large IEC 61131-3 programs. |

Both providers require an API key set via `set llm-key <key>` inside IXF. Keys are never written to disk or log files. The SAST module sanitizes all code before sending: removes hostnames, IP addresses, engineering-specific identifiers, and any string matching credential patterns.

#### `[full]` — Everything

```bash

        ```

Equivalent to `
        `. Installs all optional extras at once.

### Tier 3 — External Runtimes (Fully Optional)

Tier 3 runtimes are external programs that must be installed separately via the OS package manager or official installers. IXF always has a **Python fallback** for all affected modules when Tier 3 runtimes are absent. The fallback uses subprocess-safe in-process Python emulation.

| Runtime | Version | Purpose in IXF | Install (Ubuntu/Debian) | Install (Windows) |
|---------|---------|----------------|------------------------|-------------------|
| `gcc` / `g++` | Any | Compile C/C++ native exploits: KillDisk replication, NotPetya disk wiper replica, INDUSTROYER C component | `sudo apt install gcc g++` | MinGW-w64 or MSYS2 |
| `go` | 1.21+ | Compile Go malware modules: FrostyGoop extended, PIPEDREAM Go components | `sudo apt install golang-go` | https://go.dev/dl/ |
| `node` | 18+ | JavaScript/TypeScript exploit modules: web HMI exploitation, WebSocket attacks | `sudo apt install nodejs npm` | https://nodejs.org/ |
| `java` / `javac` | 11+ | Java deserialization exploits: Ignition SCADA RCE, WildFly deserialization | `sudo apt install default-jdk` | https://adoptium.net/ |
| `ruby` | 3.0+ | Ruby exploit modules: Metasploit-style auxiliary modules ported to IXF | `sudo apt install ruby` | https://www.ruby-lang.org/ |
| `pwsh` | 7.0+ | PowerShell OT modules: Windows DCOM OPC DA attacks, WMI enumeration, Active Directory pivot | `sudo snap install powershell` | https://github.com/PowerShell/PowerShell |
| `perl` | 5.26+ | Legacy ICS scripts: older SCADA exploit PoCs in Perl | `sudo apt install perl` | Strawberry Perl |
| `nmap` | 7.80+ | NSE script execution via `nse` command family | `sudo apt install nmap` | https://nmap.org/download/ |

Check which runtimes are present:

```bash
python tools/env_doctor.py
```

---

## Platform-Specific Notes

### Windows

`pyreadline3` is declared with `sys_platform == 'win32'` in `pyproject.toml` and is automatically installed when running `
        ` on Windows. It provides:
- Up/Down arrow history navigation in the IXF interactive shell
- Tab completion for commands, module paths, and option names
- Ctrl-R reverse history search

#### pyreadline3 Troubleshooting

**Problem:** `AttributeError: 'NoneType' object has no attribute 'write_history_file'`

This error occurs with pyreadline3 versions older than 3.4 or when the history file path is unwritable.

**Solution 1** — Upgrade IXF (includes the fix):

```bash
pip install --upgrade industrialxpl-forge
```

**Solution 2** — Upgrade pyreadline3 directly:

```bash
pip install --upgrade pyreadline3
```

**Solution 3** — If the history directory is not writable, set a custom path:

```powershell
# In PowerShell, before launching ixf:
$env:IXF_HISTORY_FILE = "C:\Users\mrhen\.ixf_history"
ixf
```

**Problem:** `ModuleNotFoundError: No module named 'pyreadline3'` on Windows

This can occur if IXF was installed into a different Python environment. Verify:

```powershell
# Check which Python is active
where.exe python
where.exe ixf

# Reinstall into the correct env
python -m pip install --upgrade industrialxpl-forge
```

**Problem:** Tab completion produces garbled output in Windows Terminal

This is a known interaction between pyreadline3 and some Windows Terminal versions. Use PowerShell 7 (pwsh) instead of the legacy cmd.exe terminal for the best experience.

#### Windows Firewall and Raw Sockets

Some IXF modules use Scapy to craft raw Layer 2/3 packets. On Windows, this requires:
- Running as Administrator, OR
- Npcap installed (https://npcap.com/)

Modules that require raw sockets will display a warning if run without the necessary privileges:

```
[!] WARNING: Raw socket requires Administrator or Npcap on Windows.
[!] Falling back to TCP/UDP socket mode.
[!] Some packet-level features will be unavailable.
```

For a full raw socket experience on Windows without Administrator rights, use WSL2.

### Linux / macOS

`readline` is part of the Python standard library on Linux and macOS. No additional packages are needed for shell history and completion.

**Linux — Scapy raw sockets:**

```bash
# Option 1: Run as root (not recommended for general use)
sudo ixf

# Option 2: Set capabilities on the Python binary (recommended for lab setups)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Option 3: Use the virtual environment's python
sudo setcap cap_net_raw,cap_net_admin=eip ~/.venvs/ixf/bin/python
```

**macOS — Homebrew Python:**

```bash
# Install Homebrew Python (avoids system Python conflicts)
brew install python@3.11

# Verify
python3.11 --version

# Create venv and install
python3.11 -m venv ~/.venvs/ixf
source ~/.venvs/ixf/bin/activate

        ```

### Running inside Docker or CI/CD

See the dedicated Docker section below. For CI/CD pipelines without interactive shell access, use the non-interactive mode:

```bash
# CI one-liner: scan and exit
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run

# CI report generation
ixf assess iec62443/zone_conduit_audit
ixf report json
```

---

## Docker Installation

### Pre-built Usage (Quick)

```bash
docker pull mrhenrike/industrialxpl-forge:latest
docker run --rm -it mrhenrike/industrialxpl-forge:latest
```

### Dockerfile (Build from Source)

The following Dockerfile builds a minimal IXF container from the published PyPI package:

```dockerfile
FROM python:3.11-slim

LABEL maintainer="Andre Henrique (@mrhenrike) | Uniao Geek"
LABEL description="IndustrialXPL-Forge OT/ICS Security Framework"
LABEL version="1.0.12"

# Install system dependencies for Scapy raw socket support
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    net-tools \
    nmap \
    gcc \
    g++ \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for non-destructive operations
RUN useradd -m -s /bin/bash ixfuser

# Set working directory
WORKDIR /opt/ixf

# Upgrade pip
RUN pip install --upgrade pip

# Install IXF with all optional extras
RUN 
        # Create log directory
RUN mkdir -p /opt/ixf/.log /opt/ixf/.tmp && \
    chown -R ixfuser:ixfuser /opt/ixf

# Switch to non-root (use root for raw socket modules when needed)
USER ixfuser

# Default: launch interactive shell
ENTRYPOINT ["ixf"]
CMD []
```

**Build and run:**

```bash
# Build
docker build -t ixf:latest .

# Interactive shell
docker run --rm -it ixf:latest

# Non-interactive scan
docker run --rm ixf:latest use scanners/ics/modbus_detect set target 192.168.1.100 run

# With network access to OT lab
docker run --rm -it --network host ixf:latest

# Raw socket support (requires host network + privileged)
docker run --rm -it --network host --privileged ixf:latest
```

### Docker Compose (Lab Environment)

```yaml
version: "3.9"
services:
  ixf:
    image: mrhenrike/industrialxpl-forge:latest
    container_name: ixf_shell
    stdin_open: true
    tty: true
    network_mode: host        # Required for OT network access
    volumes:
      - ./reports:/opt/ixf/reports    # Persist generated reports
      - ./logs:/opt/ixf/.log          # Persist audit logs
    environment:
      - IXF_LOG_LEVEL=INFO
      - IXF_SIMULATE=true
```

```bash
docker-compose run ixf
```

### Docker: Module Indexing Verification

After running the container, verify modules are indexed correctly:

```bash
docker run --rm mrhenrike/industrialxpl-forge:latest python -c "
from industrialxpl.core.exploit.utils import index_modules
mods = index_modules()
print(f'[+] {len(mods)} modules indexed.')
"
```

Expected output:
```
[+] 976 modules indexed.
```

---

## Offline Installation

For air-gapped networks and OT lab environments without internet access, pre-download all packages on an internet-connected machine and transfer them to the offline host.

### Step 1: Download all packages (on internet-connected machine)

```bash
# Create a download directory
mkdir ixf-offline-packages
cd ixf-offline-packages

# Download IXF and all dependencies (core only)
pip download industrialxpl-forge -d .

# Download with all optional extras
pip download "industrialxpl-forge[full]" -d .

# Verify downloaded files
ls -la
# Should show .whl and .tar.gz files for all dependencies
```

### Step 2: Transfer to offline host

```bash
# Option A: USB drive
cp -r ixf-offline-packages/ /media/usb/

# Option B: SCP to lab VM
scp -r ixf-offline-packages/ labuser@192.168.100.10:~/

# Option C: Archive and transfer
tar -czf ixf-offline-packages.tar.gz ixf-offline-packages/
```

### Step 3: Install without internet (on offline host)

```bash
# Navigate to the transferred directory
cd ~/ixf-offline-packages

# Install from local directory, no index lookup
pip install --no-index --find-links . industrialxpl-forge

# With extras
pip install --no-index --find-links . "industrialxpl-forge[full]"
```

### Step 4: Verify

```bash
ixf
```

### Offline Upgrade

```bash
# On internet-connected machine:
pip download "industrialxpl-forge>=1.0.12" -d ./ixf-upgrade/

# Transfer and install:
pip install --no-index --find-links ./ixf-upgrade/ --upgrade industrialxpl-forge
```

---

## Upgrading Between Versions

### Check current version

```bash
pip show industrialxpl-forge
```

Output:
```
Name: industrialxpl-forge
Version: 1.0.12
Summary: OT/ICS/SCADA Security Assessment & Exploitation Framework
Home-page: https://github.com/mrhenrike/IndustrialXPL-Forge
Author: Andre Henrique
Author-email: mrhenrike@gmail.com
License: MIT
Location: /home/user/.venvs/ixf/lib/python3.11/site-packages
Requires: cryptography, paramiko, psutil, pysnmp, requests, rich, scapy, urllib3
```

### Upgrade to latest release

```bash
pip install --upgrade industrialxpl-forge
```

### Upgrade with extras preserved

```bash
pip install --upgrade "industrialxpl-forge[full]"
```

### Upgrade from source (development)

```bash
cd IndustrialXPL-Forge
git pull origin main
pip install -e ".[full,dev]"
```

### Breaking changes between versions

IXF uses semantic versioning. Check the [CHANGELOG](https://github.com/mrhenrike/IndustrialXPL-Forge/releases) for breaking changes before upgrading in production lab environments.

| From Version | To Version | Notes |
|--------------|------------|-------|
| <1.0 | 1.0.x | Module path format changed; update any saved command histories |
| 1.0.x | 1.0.12 | pyreadline3 `write_history_file` fix; safe to upgrade |

---

## Verifying the Installation

Use any of the following five methods to confirm IXF is installed correctly:

### Method 1: Launch the shell and check the banner

```bash
ixf
```

Expected: Banner with version `v1.0.12` and `976 modules indexed.`

### Method 2: env_doctor.py — full dependency check

```bash
python tools/env_doctor.py
```

Complete expected output:

```
============================================================
  IndustrialXPL-Forge — Environment Doctor
  Checking all dependency tiers
============================================================

[Python]
  Python 3.11.9  ........................................  OK
  pip 24.2  .............................................  OK

[Tier 0 — Python Standard Library]
  socket  ...............................................  OK
  struct  ...............................................  OK
  select  ...............................................  OK
  subprocess  ...........................................  OK
  threading  ............................................  OK
  pathlib  ..............................................  OK
  json  .................................................  OK
  re  ...................................................  OK
  os  ...................................................  OK
  logging  ..............................................  OK
  hashlib  ..............................................  OK
  ssl  ..................................................  OK
  importlib  ............................................  OK
  readline  .............................................  OK (Linux/macOS)
  cmd  ..................................................  OK

[Tier 1 — Required pip packages]
  requests  2.32.4  .....................................  OK
  urllib3  2.3.0  .......................................  OK
  paramiko  3.5.1  ......................................  OK
  pysnmp  6.2.6  ........................................  OK
  scapy  2.6.1  .........................................  OK
  rich  13.9.4  .........................................  OK
  psutil  6.1.1  ........................................  OK
  cryptography  44.0.3  .................................  OK

[Tier 1 — Windows only]
  pyreadline3  NOT REQUIRED  ............................  OK (Linux/macOS platform)

[Tier 2 — Optional pip extras]
  pymodbus  3.7.4  ......................................  OK  [ot]
  asyncua  1.1.5  .......................................  OK  [ot]
  cpppo  4.3.11  ........................................  OK  [ot]
  python-can  4.4.2  ....................................  OK  [fieldbus]
  openai  1.58.1  .......................................  OK  [sast]
  anthropic  0.40.0  ....................................  OK  [sast]

[Tier 3 — External runtimes]
  gcc  13.2.0  ..........................................  OK  (C/C++ native exploits)
  g++  13.2.0  ..........................................  OK  (C++ native exploits)
  go  1.22.4  ...........................................  OK  (Go malware modules)
  node  20.18.0  ........................................  OK  (JavaScript modules)
  npm  10.8.2  ..........................................  OK  (Node.js packages)
  java  21.0.3  .........................................  OK  (Java deserialization)
  javac  21.0.3  ........................................  OK  (Java compilation)
  ruby  3.2.3  ..........................................  OK  (Ruby exploit modules)
  pwsh  7.4.6  ..........................................  OK  (PowerShell OT modules)
  perl  5.36.0  .........................................  OK  (Legacy ICS scripts)
  nmap  7.95  ...........................................  OK  (NSE script execution)

[IXF Module Index]
  Scanning module paths...
  cve/                      814 modules
  exploits/protocols/       102 modules
  scanners/ics/              31 modules
  creds/                     34 modules
  assessment/                18 modules
  malware/                   26 modules
  nse/                        8 modules  (NSE wrappers)
  ─────────────────────────────────────
  TOTAL                     976 modules  ...................  OK

[Log Paths]
  ~/.ixf_history  ..............................................  OK  (exists)
  ./industrialxpl.log  .........................................  OK  (writable)
  ./.log/  .....................................................  OK  (exists)

[Summary]
  All Tier 0 checks  PASS
  All Tier 1 checks  PASS
  All Tier 2 checks  PASS (full extras installed)
  All Tier 3 checks  PASS (all runtimes present)
  976 modules indexed.

  Status: FULLY OPERATIONAL
  Python-First: all features available.
  
        for Tier 2 (OT protocols + SAST)
============================================================
```

**Partial output (Tier 2 and 3 not installed):**

```
[Tier 2 — Optional pip extras]
  pymodbus  MISSING  .......................................  OPTIONAL  
        asyncua  MISSING  ........................................  OPTIONAL  
        cpppo  MISSING  .........................................  OPTIONAL  
        python-can  MISSING  .....................................  OPTIONAL  
        openai  MISSING  .........................................  OPTIONAL  
        anthropic  MISSING  ......................................  OPTIONAL  
        [Tier 3 — External runtimes]
  gcc  NOT FOUND  ..........................................  OPTIONAL  apt install gcc / brew install gcc
  g++  NOT FOUND  ..........................................  OPTIONAL  apt install g++ / brew install g++
  go  NOT FOUND  ...........................................  OPTIONAL  https://go.dev/dl/
  node  NOT FOUND  .........................................  OPTIONAL  https://nodejs.org/
  java  NOT FOUND  .........................................  OPTIONAL  https://adoptium.net/
  ruby  NOT FOUND  .........................................  OPTIONAL  https://www.ruby-lang.org/
  pwsh  NOT FOUND  .........................................  OPTIONAL  github.com/PowerShell/PowerShell
  perl  NOT FOUND  .........................................  OPTIONAL  apt install perl
  nmap  NOT FOUND  .........................................  OPTIONAL  apt install nmap

[Summary]
  Status: CORE OPERATIONAL
  Python-First: core functionality works without Tier 2/3.
  Tier 2 packages expand protocol coverage.
  Tier 3 runtimes enable native malware artifact compilation.
```

### Method 3: Module count check (one-liner)

```bash
python -c "from industrialxpl.core.exploit.utils import index_modules; print(len(index_modules()), 'modules indexed')"
```

Expected output:
```
976 modules indexed
```

### Method 4: Version and help check

```bash
# Version
ixf --version
# IndustrialXPL-Forge v1.0.31

# Help text
ixf --help
```

### Method 5: Non-interactive search (confirms module index)

```bash
ixf search modbus
```

Expected output (truncated):
```
[*] Search results for: modbus
    use exploits/protocols/modbus/modbus_client
    use exploits/protocols/modbus/modbus_replay_attack
    use exploits/protocols/modbus/modbus_unauthorized_coil_set
    use exploits/protocols/modbus/modbus_write_coil_flood
    use scanners/ics/modbus_detect
    use scanners/ics/modbus_scanner
    ... (50 results)
```

---

## Uninstall and Cleanup

### Uninstall the package

```bash
pip uninstall industrialxpl-forge
```

Confirm the prompt:
```
Found existing installation: industrialxpl-forge 1.0.31
Uninstalling industrialxpl-forge-1.0.12:
  Would remove:
    /home/user/.venvs/ixf/bin/ixf
    /home/user/.venvs/ixf/lib/python3.11/site-packages/industrialxpl/
    /home/user/.venvs/ixf/lib/python3.11/site-packages/industrialxpl_forge-1.0.12.dist-info/
Proceed (Y/n)? Y
Successfully uninstalled industrialxpl-forge-1.0.12
```

### Removing local data files

Pip does not remove the following local files. Delete them manually if desired:

```bash
# Command history
rm ~/.ixf_history

# Session log
rm ./industrialxpl.log

# Destructive operation audit logs
rm -rf ./.log/destructive_ops_*.log

# Module-level temp files
rm -rf ./.tmp/

# IXF local config (if created)
rm ~/.ixf.conf
```

**Windows equivalents:**

```powershell
Remove-Item $HOME\.ixf_history -ErrorAction SilentlyContinue
Remove-Item .\industrialxpl.log -ErrorAction SilentlyContinue
Remove-Item .\.log\destructive_ops_*.log -ErrorAction SilentlyContinue
Remove-Item .\.tmp\ -Recurse -ErrorAction SilentlyContinue
```

### Removing the virtual environment

```bash
# Linux/macOS
deactivate
rm -rf ~/.venvs/ixf

# Windows
deactivate
Remove-Item -Recurse -Force $HOME\.venvs\ixf
```

### Removing all dependencies (nuclear option)

If IXF was installed into a virtual environment, simply delete the venv. All packages installed into it are removed automatically.

```bash
rm -rf ~/.venvs/ixf
```

---

## Kali Linux / Parrot OS — PEP 668 and Externally Managed Environments

Kali Linux 2024+ (and Parrot OS 6+) enforce **PEP 668**: the system `pip` is locked to prevent conflicts with `apt`-managed packages. Running `pip install industrialxpl-forge` directly will fail:

```
error: externally-managed-environment
x This environment is externally managed
```

There are three correct approaches. Choose the one that fits your workflow:

---

### Option 1 — pipx (Recommended for daily CLI use)

`pipx` creates an isolated virtualenv automatically and exposes `ixf` in your PATH without any manual activation.

```bash
# Install pipx if not present
sudo apt install pipx -y
pipx ensurepath
source ~/.bashrc          # or: exec $SHELL

# Install IXF
pipx install industrialxpl-forge

# Verify
ixf --version
```

**Expected output:**
```
  installed package industrialxpl-forge 1.0.31, installed using Python 3.12
  These apps are now globally available: ixf
Done!

IndustrialXPL-Forge v1.0.31
```

**Update later:**
```bash
pipx upgrade industrialxpl-forge

# Or from within IXF:
ixf > update
```

---

### Option 2 — Manual virtualenv (Recommended for development and labs)

Creates an isolated environment. You need to activate it each session.

```bash
# Create the virtualenv
python3 -m venv ~/venvs/ixf

# Activate
source ~/venvs/ixf/bin/activate

# Install
pip install industrialxpl-forge

# Verify
ixf --version
```

**Tip — add a permanent alias so you never need to activate manually:**

```bash
echo 'alias ixf="source ~/venvs/ixf/bin/activate && ixf"' >> ~/.bashrc
source ~/.bashrc
```

**Deactivate when done:**
```bash
deactivate
```

**Update:**
```bash
source ~/venvs/ixf/bin/activate
pip install --upgrade industrialxpl-forge
```

---

### Option 3 — Clone the repository with integrated venv (bleeding-edge modules)

Use this to get the very latest modules before they are published to PyPI.

```bash
# Clone
git clone https://github.com/mrhenrike/IndustrialXPL-Forge.git
cd IndustrialXPL-Forge

# Create and activate venv inside the project
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode (changes in source apply immediately)
pip install -e .

# Run
ixf
```

**Update to latest commit:**
```bash
cd IndustrialXPL-Forge
git pull
source .venv/bin/activate
pip install -e . --upgrade
ixf --version
```

---

### Option Comparison

| Criterion | pipx | Manual venv | Clone + venv |
|-----------|------|-------------|--------------|
| Module freshness | PyPI releases | PyPI releases | Git bleeding edge |
| Auto-activation | Yes | No (needs `source`) | No (needs `source`) |
| Best for | Daily CLI use | Development, labs | Contributing, latest modules |
| Update command | `pipx upgrade` | `pip install --upgrade` | `git pull` |
| Disk usage | ~50 MB | ~50 MB | ~200 MB (full repo) |
| Multiple IXF versions | Yes (pipx supports it) | Yes (separate venvs) | One per clone |

---

### Kali-Specific Troubleshooting

**Problem:** `ixf: command not found` after `pipx install`

```bash
# Reload PATH
pipx ensurepath && exec $SHELL
which ixf     # should now show ~/.local/bin/ixf
```

**Problem:** `SyntaxError` or `ImportError` on startup

The installed version may be outdated. Upgrade:
```bash
pipx upgrade industrialxpl-forge
# or
source ~/venvs/ixf/bin/activate && pip install --upgrade industrialxpl-forge
```

**Problem:** Scapy modules fail (`No libpcap provider`)

```bash
sudo apt install -y libpcap-dev
# For raw socket access without root:
sudo setcap cap_net_raw+eip $(which python3)
```

**Problem:** `pip install --upgrade industrialxpl-forge` downloads old version

pip may have cached metadata. Clear it:
```bash
pip install --upgrade --no-cache-dir industrialxpl-forge
# Or force a specific version:
pip install industrialxpl-forge==1.0.31
```

**Problem:** Auto-update notification on every startup (version mismatch between venv and PyPI)

```bash
# Inside the activated venv, upgrade:
pip install --upgrade industrialxpl-forge
# Then inside IXF confirm:
ixf > update
```

---

## Troubleshooting Installation

### `ixf: command not found` after install

**Cause:** The pip script directory is not in `$PATH`.

**Fix (Linux/macOS):**

```bash
# Check where pip installs scripts
python -m site --user-base
# Example: /home/user/.local

# Add to PATH in ~/.bashrc or ~/.zshrc:
export PATH="$HOME/.local/bin:$PATH"

# Reload
source ~/.bashrc

# Verify
which ixf
```

**Fix (Windows):** Find the Scripts directory:

```powershell
python -c "import site; print(site.getusersitepackages())"
# Example output: C:\Users\mrhen\AppData\Roaming\Python\Python311\site-packages
# Scripts are at: C:\Users\mrhen\AppData\Roaming\Python\Python311\Scripts
```

Add that Scripts path to the Windows PATH environment variable via System Properties > Environment Variables.

### `ImportError: cannot import name 'index_modules'`

**Cause:** Corrupted install or outdated cached `.pyc` files.

**Fix:**

```bash
pip install --force-reinstall industrialxpl-forge
python -c "from industrialxpl.core.exploit.utils import index_modules; print('OK')"
```

### `scapy: WARNING: No libpcap provider available`

**Cause:** libpcap not installed on the system.

**Fix:**

```bash
# Ubuntu/Debian
sudo apt install libpcap-dev

# macOS
brew install libpcap

# Windows
# Install Npcap from https://npcap.com/
```

### `976 modules indexed` but `search` returns no results

**Cause:** Module path mismatch after a source-mode install.

**Fix:** Ensure you are running the installed package, not a stale source directory:

```bash
which ixf
# Should point to your venv or user site, not the source directory

pip install --force-reinstall industrialxpl-forge
```

### pip SSL certificate errors (behind corporate proxy)

```bash
# Bypass SSL verification (not recommended for production)
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org industrialxpl-forge

# Preferred: configure proxy

pip install industrialxpl-forge --proxy http://proxy.corp.example.com:8080
```

---

*Next: [Quick Start](02-quick-start.md)*
