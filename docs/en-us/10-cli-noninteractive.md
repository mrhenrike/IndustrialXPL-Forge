# CLI Non-Interactive Mode

IXF can be used without the interactive shell, passing commands directly on the command line. This is useful for scripting, automation, CI/CD pipelines, and one-liner penetration testing workflows.

---

## Basic Syntax

```bash
ixf <command> [args...]
```

Multiple commands are separated by spaces. The shell processes them sequentially then exits.

---

## One-Liner Examples

### Search and exit

```bash
ixf search modbus
ixf search CVE-2021-22681
ixf search default_creds
```

### Load a module, set options, and run

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run
```

**Output:**

```
[*] Indexing modules…
[+] 976 modules indexed.
[*] Module loaded: Modbus TCP Device Detect
[*] target => 192.168.1.100
  [SIMULATE MODE — no packets sent]
  [i] What would happen:
      Send Modbus FC04 probe to 192.168.1.100:502
      ...
```

### Check only (no exploit, just probe)

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 check
```

### Stats

```bash
ixf stats
```

### Vendors and protocols

```bash
ixf vendors siemens
ixf protocols
ixf coverage
```

### Generate report

```bash
ixf report json
ixf report html
```

---

## Setting Global Options

Use `setg` to apply options that persist across all module loads in the session:

```bash
ixf setg target 192.168.1.100 use scanners/ics/modbus_detect run use scanners/ics/s7_comm_scanner run
```

---

## TTP Execution

```bash
# Run T0843 technique in simulate mode
ixf ttp T0843 192.168.1.100

# List techniques for a tactic
ixf ttp-list --tactic discovery

# MITRE coverage report
ixf mitre-coverage

# Export ATT&CK Navigator layer
ixf mitre-report layer
```

---

## Shell Piping

Pipe `search` output through standard Unix tools:

```bash
# List all Siemens modules
ixf search siemens | grep "use cve"

# Count CVE modules
ixf search CVE | wc -l

# Save search results
ixf search modbus > modbus_modules.txt
```

---

## Scripting

Use IXF in a Bash script:

```bash
#!/bin/bash
TARGET="192.168.1.100"

echo "[*] Running IXF OT Discovery on $TARGET"

# Modbus scan
ixf use scanners/ics/modbus_detect set target "$TARGET" check

# S7 scan
ixf use scanners/ics/s7_comm_scanner set target "$TARGET" check

# BACnet scan
ixf use scanners/ics/bacnet_scanner set target "$TARGET" check

# MITRE technique check
ixf ttp-check T0843 "$TARGET"

echo "[*] Done. Review results."
```

---

## Python API

IXF modules can be used programmatically from Python:

```python
from industrialxpl.core.exploit.utils import import_exploit

# Load and run a module
cls = import_exploit("industrialxpl.modules.scanners.ics.modbus_detect")
mod = cls()
mod.target = "192.168.1.100"
mod.port = 502

# Check (read-only probe)
is_vulnerable = mod.check()
print("Modbus detected:", is_vulnerable)

# Run in simulate mode (default)
mod.run()

# Run live (authorized labs only)
mod.simulate = False
mod.destructive = True
mod.run()
```

### Programmatic TTP sweep

```python
import sys
sys.path.insert(0, "/path/to/IndustrialXPL-Forge")

from industrialxpl.core.mitre.sweeper import MitreTacticSweeper

sweeper = MitreTacticSweeper()
results = sweeper.sweep_technique(
    technique_id="T0843",
    target="192.168.1.100",
    simulate=True,
    stop_on_first=False,
)
for r in results:
    print(r["module"], r["result"])
```

---

## CI/CD Integration

Use IXF in a GitHub Actions workflow or Jenkins pipeline:

```yaml
# .github/workflows/ot-scan.yml
name: OT Security Scan
on: [push]

jobs:
  ot-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install industrialxpl-forge
      - name: Module integrity check
        run: |
          python -c "
          from industrialxpl.core.exploit.utils import index_modules
          mods = index_modules()
          print(f'{len(mods)} modules indexed')
          assert len(mods) > 900, 'Expected 900+ modules'
          "
      - name: MITRE coverage check
        run: ixf mitre-coverage
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (import failure, missing dependency) |
| `2` | Module validation error |

---

*Previous: [Module Development](09-module-development.md) | Next: [PolyExploit Runner](11-poly-exploit-runner.md)*
