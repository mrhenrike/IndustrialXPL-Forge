# Contributing to IndustrialXPL-Forge

Thank you for your interest in contributing. This project is an offensive and defensive security research tool for OT/ICS/SCADA/HMI/IIoT environments.

## Legal Notice

By contributing you confirm that:
- You have authorization to submit the code
- The exploit or module targets systems you own or have explicit written permission to test
- You understand and accept the [project disclaimer](README.md#disclaimer)
- You will not submit modules designed to cause unauthorized harm

## Development Setup

```bash
git clone https://github.com/mrhenrike/IndustrialXPL-Forge.git
cd IndustrialXPL-Forge
pip install -e ".[dev]"
python ixf.py
```

## Module Structure

Each module lives under `industrialxpl/modules/<category>/` and must:

1. Inherit from `Exploit` (imported from `industrialxpl.core.exploit`)
2. Define `__info__` with all required metadata fields
3. Set `simulate = OptBool(True, ...)` — **simulate mode is default**
4. Implement `check()` decorated with `@mute`
5. Implement `run()` with `DestructiveGate` before any live payload

Minimal module template:

```python
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, mute,
    print_status, DestructiveGate,
)

class Exploit(Exploit):
    __info__ = {
        "name":         "Module Name",
        "description":  "What this module does.",
        "authors":      ("Your Name",),
        "references":   ("https://...",),
        "devices":      ("Vendor Product",),
        "impact":       "HIGH",
        "exploit_type": "Type",
        "cve":          "CVE-YYYY-NNNNN",
        "cvss":         "9.8",
        "severity":     "CRITICAL",
        "mitre_techniques": ["T0866"],
        "mitre_tactics": ["Initial Access"],
    }

    target      = OptIP("",    "Target IP")
    port        = OptPort(502, "Target port")
    simulate    = OptBool(True,  "Simulate (default: True)")
    destructive = OptBool(False, "Enable live exploitation")

    @mute
    def check(self): ...

    def run(self):
        if self.simulate:
            DestructiveGate.print_simulation(description="...", mitre_techniques=["T0866"])
            return
        # Live payload here
```

## Contribution Checklist

- [ ] `simulate=True` default
- [ ] `check()` with `@mute`, returns `bool`
- [ ] `__info__` complete with CVSS, MITRE, CVE
- [ ] No secrets in code
- [ ] Impact level accurate
- [ ] Tested locally

## Submitting a Pull Request

1. Fork the repository
2. `git checkout -b add-cve-YYYY-NNNNN`
3. Add your module(s)
4. Validate with `python -c "from industrialxpl.core.exploit.utils import index_modules; print(len(index_modules()), 'modules')"`
5. Submit PR with clear description

## Module Categories

| Path | Description |
|------|-------------|
| `modules/exploits/` | Direct exploitation |
| `modules/scanners/` | Discovery and fingerprinting |
| `modules/creds/` | Credential testing |
| `modules/assessment/` | Security assessment |
| `modules/cve/` | CVE-specific PoCs (by vendor) |
| `modules/cve/malware/` | ICS malware TTP replicas |
| `modules/cve/malware/_native/` | C/C++/Go/Python malware builders |

## Contact

Andre Henrique (@mrhenrike) — henrique.santos@uniaogeek.com.br
