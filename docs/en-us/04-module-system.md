# Module System

This document explains the IXF module architecture, the `__info__` metadata format, all 10 option types, and the core `check()` / `run()` patterns.

---

## Module Path Conventions

Modules live under `industrialxpl/modules/` and are referenced by their path relative to that directory.

**Slash notation** (used in the shell):
```
scanners/ics/modbus_detect
cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
cve/malware/crashoverride_industroyer
assessment/mitre_ics/t0843_program_upload
```

**Dot notation** (Python import path):
```
scanners.ics.modbus_detect
cve.siemens.cve_2021_22681_s7_1200_hardcoded_key
cve.malware.crashoverride_industroyer
assessment.mitre_ics.t0843_program_upload
```

Both notations are interchangeable in the shell. `use` normalizes slashes to dots internally.

---

## Module Categories

| Directory | Contents |
|-----------|---------|
| `exploits/protocols/` | Protocol design abuse (Modbus, S7, DNP3, BACnet, IEC 104, OPC UA, ...) |
| `exploits/plc/` | Vendor-specific PLC exploits |
| `exploits/scada/` | SCADA/HMI software exploits |
| `exploits/mes/` | MES/ERP exploits (Ignition, SAP, ActiveMQ, ...) |
| `scanners/ics/` | Protocol-specific discovery and fingerprinting |
| `scanners/osint/` | Shodan dorks, ELITEWOLF, OT Hunt |
| `creds/` | Default credential testing by vendor |
| `cve/` | CVE-specific PoC exploits by vendor |
| `cve/apt/` | APT malware TTP replicas |
| `cve/malware/` | ICS malware TTP simulation modules |
| `cve/malware/_native/` | C/C++/Go/Python native malware code |
| `assessment/mitre_ics/` | MITRE ATT&CK for ICS technique modules |
| `assessment/iec62443/` | IEC 62443 compliance checks |
| `assessment/sast/` | SAST/LLM PLC code analysis |
| `assessment/risk/` | Risk scoring |
| `assessment/ir/` | Incident response playbooks |

---

## Module Anatomy

Every module is a Python file with a class named `Exploit` (shadowing the imported base). Here is the minimal structure:

```python
"""Brief description."""
import socket

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, mute,
    print_error, print_status, print_success,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "My Module Name",
        "description":      "What this module does in one sentence.",
        "authors":          ("Your Name",),
        "references":       ("https://example.com/advisory",),
        "devices":          ("Vendor Product Model",),
        "impact":           "HIGH",
        "exploit_type":     "Buffer Overflow",
        "source_poc":       "https://github.com/example/poc",
        "cve":              "CVE-YYYY-NNNNN",
        "cvss":             "9.8",
        "severity":         "CRITICAL",
        "mitre_techniques": ["T0866"],
        "mitre_tactics":    ["Initial Access"],
    }

    target      = OptIP("",    "Target device IP")
    port        = OptPort(502, "Protocol port")
    simulate    = OptBool(True,  "Simulate (default: True)")
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
        """Execute the exploit or print simulation."""
        if not self.target:
            print_error("Set 'target' option first.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-YYYY-NNNNN Vendor Product\n"
                    "Step 1: Connect to target\n"
                    "Step 2: Send crafted payload\n"
                    "Step 3: Achieve remote code execution"
                ),
                mitre_techniques=["T0866"],
            )
            return

        print_status("[CVE-YYYY] Exploiting {}:{}...".format(self.target, self.port))
        # Live exploit code here
```

---

## `__info__` Keys Reference

Every module must define a `__info__` dictionary. All keys are required unless marked optional.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | string | yes | Human-readable module name |
| `description` | string | yes | One to three sentence description |
| `authors` | tuple[str] | yes | Author(s) |
| `references` | tuple[str] | yes | CVE advisories, PoC URLs, papers |
| `devices` | tuple[str] | yes | Target device(s) or software |
| `impact` | string | yes | One of: `INFO`, `READ`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `CATASTROPHIC` |
| `exploit_type` | string | yes | Short exploit category (e.g. `Stack Buffer Overflow`, `Default Credentials`) |
| `source_poc` | string | no | Original PoC reference URL |
| `cve` | string | yes | CVE ID or `N/A` |
| `cvss` | string | yes | CVSS score string or `N/A` |
| `severity` | string | yes | Mirrors `impact` or CVSS severity label |
| `mitre_techniques` | list[str] | yes | MITRE ATT&CK for ICS technique IDs |
| `mitre_tactics` | list[str] | yes | Tactic names (must match ATT&CK taxonomy) |
| `destructive_description` | string | no | Human text shown in DestructiveGate banner |

**Impact values and their meaning:**

| Value | Meaning |
|-------|---------|
| `INFO` | Passive observation, no state change |
| `READ` | Read-only query |
| `LOW` | Non-destructive write, reversible |
| `MEDIUM` | Parameter change, may affect operation |
| `HIGH` | Device restart, process stop |
| `CRITICAL` | Firmware/logic modification, possibly irreversible |
| `CATASTROPHIC` | Physical damage, safety system disabling |

---

## Option Types

Modules declare options as class-level descriptors. The shell uses these to validate `set` inputs and display the `show options` table.

### `OptIP`

Accepts an IPv4 address or hostname.

| Value | Valid? |
|-------|--------|
| `"192.168.1.100"` | Yes |
| `"10.0.0.1"` | Yes |
| `"target.local"` | Yes (alphanumeric, `-`, `_`, `.`) |
| `""` | Yes (empty = unset) |
| `"999.999.999.999"` | No — invalid IPv4 |

```python
target = OptIP("", "Target device IP")
```

```
ixf > set target 192.168.1.100
[*] target => 192.168.1.100

ixf > set target not_a_hostname!
[-] Validation error for 'target': invalid IP or hostname
```

---

### `OptPort`

Accepts an integer between 1 and 65535.

| Value | Valid? |
|-------|--------|
| `502` | Yes |
| `44818` | Yes |
| `65535` | Yes |
| `0` | No |
| `65536` | No |
| `"80"` | Yes (auto-converted) |

```python
port = OptPort(502, "Modbus TCP port")
```

---

### `OptInteger`

Accepts any integer. Optional `min_value` and `max_value` constraints.

```python
unit_id  = OptInteger(1,  "Modbus unit ID (1–247)", min_value=1, max_value=247)
timeout  = OptInteger(5,  "Timeout in seconds", min_value=1)
threads  = OptInteger(10, "Thread count")
```

| Value | Valid? (no constraints) |
|-------|------------------------|
| `0` | Yes |
| `-1` | Yes |
| `1000` | Yes |
| `"abc"` | No |

---

### `OptFloat`

Accepts any floating-point number.

```python
rate_limit = OptFloat(0.5, "Request rate limit (seconds)")
```

| Value | Valid? |
|-------|--------|
| `1.5` | Yes |
| `0.0` | Yes |
| `-0.3` | Yes |
| `"abc"` | No |

---

### `OptString`

Accepts any string value.

```python
username = OptString("admin", "Username")
payload  = OptString("",      "Custom payload string")
```

---

### `OptBool`

Accepts boolean values. Case-insensitive string forms are also accepted.

| Input | Interpreted as |
|-------|----------------|
| `True`, `False` | Direct bool |
| `"true"`, `"yes"`, `"1"`, `"on"` | `True` |
| `"false"`, `"no"`, `"0"`, `"off"` | `False` |

```python
simulate    = OptBool(True,  "Simulate (default: True)")
destructive = OptBool(False, "Enable live execution")
verbose     = OptBool(False, "Verbose output", advanced=True)
```

```
ixf > set simulate false
ixf > set verbose yes
ixf > set destructive on
```

---

### `OptMAC`

Accepts a MAC address in standard notation. Both `:` and `-` separators accepted; always normalized to lowercase colon notation.

| Value | Valid? | Normalized |
|-------|--------|-----------|
| `"00:11:22:33:44:55"` | Yes | `00:11:22:33:44:55` |
| `"00-11-22-33-44-55"` | Yes | `00:11:22:33:44:55` |
| `"AA:BB:CC:DD:EE:FF"` | Yes | `aa:bb:cc:dd:ee:ff` |
| `"00:11:22:33:44"` | No | — |
| `"not-a-mac"` | No | — |

```python
target_mac = OptMAC("", "Target device MAC address")
```

---

### `OptWordlist`

Accepts a wordlist path. Supports:
- Absolute path: `/tmp/passwords.txt`
- `file://` prefix: `file:///opt/lists/default_creds.txt`
- Relative path from `industrialxpl/resources/wordlists/`: `ics_common_passwords.txt`

The file must exist and be readable.

```python
wordlist = OptWordlist("", "Password wordlist")
```

```
ixf > set wordlist file:///opt/wordlists/rockyou.txt
ixf > set wordlist ics_common_passwords.txt
```

---

### `OptEncoder`

Accepts an encoder name string (no format validation — passed to encoding pipeline).

```python
encoder = OptEncoder("", "Output encoder (e.g. base64, hex, raw)")
```

---

## Advanced Options

Some options are marked `advanced=True`. They are not shown by `show options` but appear in `show advanced`:

```
ixf (module) > show advanced

  Advanced Options
  ────────────────────────────────────
  verbose    False   Enable verbose output
  timeout    5       Override connection timeout
```

---

## Decorators

### `@mute`

Suppresses standard output during execution (useful in multi-threaded scans where `check()` is called concurrently).

```python
@mute
def check(self) -> bool:
    # stdout is suppressed here
    ...
```

Output generated inside a `@mute`-decorated function goes to an internal buffer. The overall scan result is printed by the thread coordinator.

---

### `@multi`

Enables a module to accept a file of targets via `target=file:///path/to/targets.txt`. Each line in the file is treated as a separate target.

```python
@multi
def run(self) -> None:
    # self.target is set to each line in the file
    ...
```

Usage:

```
ixf > set target file:///opt/targets.txt
ixf > run
[multi] Target: 192.168.1.1
[multi] Target: 192.168.1.2
[multi] Target: 192.168.1.3
```

---

## `check()` Pattern

`check()` must:
- Decorate with `@mute`
- Return `True` if the target appears vulnerable/present
- Return `False` if not reachable or not vulnerable
- Never send exploits — only passive probes (TCP connect, banner grab)
- Handle all exceptions gracefully

```python
@mute
def check(self) -> bool:
    if not self.target:
        return False
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((self.target, self.port))
        # optionally send a probe and inspect the response
        s.send(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01")
        banner = s.recv(64)
        s.close()
        return len(banner) >= 6  # Modbus response has at least 6 bytes
    except Exception:
        return False
```

---

## `run()` Pattern

`run()` must:
- Validate `self.target` first
- If `self.simulate` is `True`: call `DestructiveGate.print_simulation()` and return
- If live: implement the actual exploit logic

```python
def run(self) -> None:
    if not self.target:
        print_error("Set 'target' option.")
        return

    if self.simulate:
        DestructiveGate.print_simulation(
            description=(
                "Step 1: ...\n"
                "Step 2: ...\n"
                "Step 3: ..."
            ),
            mitre_techniques=["T0866"],
        )
        return

    # Live code
    print_status("[CVE-YYYY] Exploiting {}:{}...".format(self.target, self.port))
    # ...
```

---

## `get_info()`

The `get_info()` method traverses the class MRO to retrieve the `__info__` dictionary. It handles Python name mangling correctly (the metaclass stores `__info__` as `_{ClassName}__info__`).

```python
obj = import_exploit("industrialxpl.modules.cve.siemens.cve_2021_22681_s7_1200_hardcoded_key")()
info = obj.get_info()
print(info["name"])    # CVE-2021-22681 Siemens S7-1200/1500 PLC
print(info["impact"])  # CRITICAL
```

---

## Module Validation

After adding a new module, verify it loads without errors:

```bash
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
```

---

*Previous: [Shell Reference](03-shell-reference.md) | Next: [SafeMode / DestructiveMode](05-safemode-destructivemode.md)*
