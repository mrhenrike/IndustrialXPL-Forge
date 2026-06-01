# IndustrialXPL-Forge — Documentation

> **The World's Largest OT/ICS/SCADA Security Assessment & Exploitation Framework**

[![PyPI](https://img.shields.io/pypi/v/industrialxpl-forge?color=red&label=PyPI)](https://pypi.org/project/industrialxpl-forge/)
[![Python](https://img.shields.io/pypi/pyversions/industrialxpl-forge?color=blue&label=Python)](https://pypi.org/project/industrialxpl-forge/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Modules](https://img.shields.io/badge/Modules-976%2B-brightgreen)](https://github.com/mrhenrike/IndustrialXPL-Forge)

---

## Table of Contents

| # | Document | Description |
|---|----------|-------------|
| 1 | [Installation](01-installation.md) | Requirements, pip install, source install, dependency tiers |
| 2 | [Quick Start](02-quick-start.md) | Full annotated terminal session from launch to first exploit |
| 3 | [Shell Reference](03-shell-reference.md) | All 35 commands with syntax, argument types, and terminal I/O samples |
| 4 | [Module System](04-module-system.md) | Module anatomy, `__info__` keys, all 10 `OptXxx` option types |
| 5 | [SafeMode / DestructiveMode](05-safemode-destructivemode.md) | Impact levels, confirmation flow, audit logging |
| 6 | [MITRE ATT&CK for ICS](06-mitre-attack-ics.md) | `ttp`, `mitre-scan`, `mitre-coverage`, Navigator layer export |
| 7 | [SAST / LLM Analysis](07-sast-llm.md) | Offline PLC code analysis, providers, sanitization, modes |
| 8 | [Protocols & Vendors](08-protocols-vendors.md) | 50 protocols with ports, 150+ vendor coverage by region |
| 9 | [Module Development](09-module-development.md) | Writing new modules: template, conventions, validation |
| 10 | [CLI Non-Interactive](10-cli-noninteractive.md) | One-liner usage, piping, CI/CD integration |
| 11 | [PolyExploit Runner](11-poly-exploit-runner.md) | C/C++/Go/Ruby runtimes, compile flow, malware builder |
| 12 | [Assessment & Compliance](12-assessment-compliance.md) | IEC 62443, NIST 800-82r3, MITRE ICS, risk scoring, IR playbook |

---

## pt-BR Version

Portuguese (Brazilian) documentation is available in [../pt-br/](_index.md).

---

## About IXF

IndustrialXPL-Forge (IXF) is a modular Python framework for security assessment and exploitation of **Operational Technology (OT)**, **Industrial Control Systems (ICS)**, **SCADA**, **HMI**, **PLC**, **RTU**, **DCS**, and **IIoT** environments.

**Core design principles:**

- **Python-First** — all core functionality runs with `pip install industrialxpl-forge`; no external tools required
- **SafeMode by default** — every module defaults to `simulate=True`; no packets are sent until explicitly enabled
- **Authorize before you act** — designed exclusively for authorized testing, research, and education

**Key numbers:**

| Metric | Value |
|--------|-------|
| Total modules | 976+ |
| CVE modules | 3,300+ |
| Vendors covered | 150+ |
| Protocols covered | 50+ |
| MITRE ATT&CK for ICS techniques | 74/90 (82%) |
| Malware TTPs | 26 (2010–2024) |
| ICS languages supported (SAST) | 7 |

---

*Author: André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://uniaogeek.com.br/)*
