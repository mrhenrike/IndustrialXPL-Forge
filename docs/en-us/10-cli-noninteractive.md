# CLI Non-Interactive Mode

IXF can be used without the interactive shell, passing commands directly on the command line. This enables scripting, CI/CD pipelines, automation, scheduled security scans, and one-liner penetration testing workflows — all without requiring a human to drive the interactive shell.

---

## Basic Syntax

```bash
ixf <command> [args...]
ixf <command1> <arg1> <command2> <arg2> ...
```

Commands are separated by spaces and processed sequentially. The IXF shell initializes, runs all commands in order, and exits. Module context is preserved across commands in the same invocation (i.e., after `use`, subsequent `set` and `run` commands target that module).

**Installation check:**
```bash
ixf --version
# IndustrialXPL-Forge v1.0.13

ixf --help
# Shows non-interactive syntax help
```

---

## 20 One-Liner Examples with Full Output

### 1. Module Statistics

```bash
ixf stats
```

```
[*] Indexing modules...
[+] 976 modules indexed.
[i] IXF Module Statistics — IndustrialXPL-Forge v1.0.13
  Total: 976 | Vendors: 150 | Protocols: 50 | MITRE: 74/90 (82%)
  cve: 486 | exploits: 159 | creds: 34 | scanners: 31 | assessment: 18
```

### 2. Search by CVE

```bash
ixf search CVE-2021-22681
```

```
[*] Indexing modules...
[+] 976 modules indexed.
[*] Search results for: CVE-2021-22681
  use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key  CRITICAL
[*] 1 result(s) found.
```

### 3. Load and Simulate a Module

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run
```

```
[*] Indexing modules...
[+] 976 modules indexed.
[*] Module loaded: Modbus TCP Device Detect
[*] target => 192.168.1.100

  [SIMULATE MODE — no packets sent]
  [i] What would happen:
      Phase 1 [TCP Connect]: TCP to 192.168.1.100:502
      Phase 2 [FC04 Probe]:  Modbus FC04 Read Input Registers (Unit=1)
      Phase 3 [Fingerprint]: Analyze response for device type
  [i] Payload (hex): 00 01 00 00 00 06 01 04 00 00 00 0A
  [i] MITRE: T0846 (Remote System Discovery)
```

### 4. Check Only (Read-Only Probe)

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 check
```

```
[*] Module loaded: Modbus TCP Device Detect
[*] target => 192.168.1.100
[*] Checking 192.168.1.100:502...
[+] VULNERABLE — Modbus device detected
[+] Device: Schneider Electric Modicon M340 (inferred)
```

### 5. MITRE Coverage Report

```bash
ixf mitre-coverage
```

```
[*] Indexing modules...
  MITRE ATT&CK for ICS Coverage
  Initial Access (TA0108):           9/9   (100%)
  Execution (TA0104):                8/9   (88%)
  ...
  TOTAL: 74/90 (82%)
```

### 6. List MITRE Techniques for a Tactic

```bash
ixf mitre-list discovery
```

```
  MITRE ATT&CK for ICS — Discovery Techniques (TA0102)
  T0840  Network Connection Enumeration   2 modules
  T0842  Network Sniffing                 3 modules
  T0846  Remote System Discovery          8 modules
  ...
```

### 7. TTP Sweep in Simulate Mode

```bash
ixf ttp T0843 192.168.1.100
```

```
[*] TTP T0843 (Program Download) — 5 modules — simulate=True
[*] Running module 1/5: cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
  [SIMULATE] CVE-2021-22681 ...
[*] Running module 2/5: cve/siemens/cve_2022_38465_s7_global_key
  [SIMULATE] CVE-2022-38465 ...
[+] T0843 sweep complete: 5 modules (simulate)
```

### 8. Vendors List Filtered

```bash
ixf vendors japan
```

```
  Vendors (7 results — japan)
  Omron             12 CVE | 3 Cred
  Mitsubishi         8 CVE | 1 Cred
  Yokogawa           5 CVE | 1 Cred
  ...
```

### 9. Protocols List

```bash
ixf protocols
```

```
  Protocol Coverage (50 protocols)
  MODBUS TCP         502/TCP    18 modules
  Siemens S7comm     102/TCP     8 modules
  ...
```

### 10. Generate JSON Report

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run report json
```

```
[*] Module loaded, target set, run complete
[+] Report saved: ixf_report_20260601_153045.json
```

### 11. CVE Load and Show Info

```bash
ixf cve CVE-2023-6448 show info
```

```
[*] Module loaded: CVE-2023-6448 Unitronics UniStream PLC
  name         : CVE-2023-6448 Unitronics UniStream PLC
  cvss         : 9.8
  impact       : CRITICAL
  mitre        : T0812, T0859
```

### 12. Assessment Module Run

```bash
ixf assess risk/ics_risk_scorer
```

```
[*] Loading assessment/risk/ics_risk_scorer...
  ICS Risk Score Methodology
  Network exposure:    30%    Internet-facing: CRITICAL
  Authentication:      25%    No Modbus auth: HIGH
  ...
  Composite Score: 8.7/10 (CRITICAL)
```

### 13. TTP List for a Tactic

```bash
ixf ttp-list --tactic evasion
```

```
  TTP Index — Evasion (TA0103)
  T0838  Modify Alarm Settings    2 modules
  T0844  Program Organization     1 module
  T0849  Masquerading             1 module
  T0851  Rootkit                  2 modules
  T0856  Spoof Reporting          2 modules
  T0858  Change Credential        4 modules
  T0872  Indicator Removal        1 module
  T0874  Hooking                  1 module
```

### 14. MITRE Navigator Layer Export

```bash
ixf mitre-report layer
```

```
[+] ATT&CK Navigator layer saved: ixf_mitre_layer_20260601_154200.json
[i] Open at: https://mitre-attack.github.io/attack-navigator/
```

### 15. NSE Install

```bash
ixf nse install
```

```
[*] Installing IXF NSE scripts...
[+] ics-sweep.nse → installed
[+] ics-default-creds.nse → installed
...
[+] All 8 IXF NSE scripts installed.
```

### 16. LLM Status Check

```bash
ixf llm-status
```

```
  LLM Provider Status
  gemini     configured    gemini-2.5-flash
  openai     not configured
  ...
  Active: gemini
```

### 17. SAST Analysis One-Liner

```bash
ixf sast /opt/plc_projects/water_treatment/ --mode sast
```

```
[*] Analyzing water_treatment/ (5 files, 245 lines)...
[*] Provider: gemini | Sanitized: 2 credentials, 1 IP
[*] Sending to LLM...
  SAST REPORT: 1 CRITICAL | 2 HIGH | 1 MEDIUM | 1 LOW
  FINDING [CRITICAL]: Unvalidated Chlorine Dosing Setpoint (line 48)
  ...
[+] Report saved: .tmp/sast_results/water_treatment_20260601.md
```

### 18. Multiple Modules with Global Target

```bash
ixf setg target 10.0.0.100 use scanners/ics/modbus_detect run use scanners/ics/s7_comm_scanner run
```

```
[*] Global: target => 10.0.0.100
[*] Module loaded: Modbus TCP Device Detect
  [SIMULATE] Modbus scan on 10.0.0.100:502...
[*] Module loaded: Siemens S7 Scanner
  [SIMULATE] S7comm scan on 10.0.0.100:102...
```

### 19. TTP Check (Read-Only Sweep)

```bash
ixf ttp-check T0859 192.168.1.100
```

```
[*] T0859 (Valid Accounts) check-only on 192.168.1.100...
  creds/siemens/ssh_default_creds     → POTENTIAL (port 22 open)
  creds/siemens/telnet_default_creds  → NOT VULNERABLE (port 23 closed)
  ...
```

### 20. Full MITRE HTML Report After Sweep

```bash
ixf mitre-all 192.168.1.100 report html mitre-report layer
```

```
[*] Full MITRE sweep on 192.168.1.100 (simulate)...
[+] MITRE sweep complete: 74 techniques
[+] Report saved: ixf_report_20260601_161200.html
[+] Navigator layer saved: ixf_mitre_layer_20260601_161215.json
```

---

## Multiple Module Chaining in One Command

Chain as many commands as needed. Each `use` loads a new module; `set`, `check`, and `run` operate on the currently loaded module:

```bash
# Three modules, all in sequence, single invocation
ixf \
  use scanners/ics/modbus_detect \
  set target 192.168.1.100 \
  run \
  use scanners/ics/s7_comm_scanner \
  set target 192.168.1.100 \
  run \
  use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key \
  set target 192.168.1.100 \
  run \
  report json
```

```
[*] Indexing 976 modules...
[*] Module loaded: Modbus TCP Device Detect
[*] target => 192.168.1.100
  [SIMULATE] Modbus scan...
[*] Module loaded: Siemens S7 Scanner
[*] target => 192.168.1.100
  [SIMULATE] S7comm scan...
[*] Module loaded: CVE-2021-22681 Siemens S7-1200/1500 PLC
[*] target => 192.168.1.100
  [SIMULATE] CVE-2021-22681 exploit chain...
[+] Report saved: ixf_report_20260601_154500.json
```

---

## All TTP and MITRE Command Variations

```bash
# Execute a single technique
ixf ttp T0843 192.168.1.100

# Execute with rate limiting (500ms between modules)
ixf ttp T0843 192.168.1.100 --rate-limit 500

# Stop on first confirmed hit
ixf ttp T0843 192.168.1.100 --stop-on-first

# Save output to file
ixf ttp T0843 192.168.1.100 --output /tmp/t0843_results.json

# Read-only check (no exploit)
ixf ttp-check T0843 192.168.1.100

# Force simulate for a technique
ixf ttp-simulate T0843 192.168.1.100

# List all TTPs
ixf ttp-list

# List TTPs by tactic
ixf ttp-list --tactic discovery
ixf ttp-list --tactic impact
ixf ttp-list --tactic "initial-access"

# MITRE scan — tactic sweep
ixf mitre-scan discovery 192.168.1.0/24
ixf mitre-scan initial-access 192.168.1.100
ixf mitre-scan impact 192.168.1.100
ixf mitre-scan collection 192.168.1.100

# MITRE scan — single technique
ixf mitre-scan T0843 192.168.1.100
ixf mitre-scan T0836 192.168.1.100

# MITRE scan — TA-ID
ixf mitre-scan TA0102 192.168.1.0/24

# Full MITRE sweep
ixf mitre-all 192.168.1.100

# Coverage
ixf mitre-coverage
ixf coverage

# Reports
ixf mitre-report layer
ixf mitre-report json
ixf mitre-report html

# Specific technique module list
ixf mitre T0843
ixf mitre T0836
ixf mitre T0819

# Technique list by tactic
ixf mitre-list
ixf mitre-list discovery
ixf mitre-list evasion
ixf mitre-list "impair-process-control"
```

---

## Shell Piping — 15 Examples with grep, jq, awk

IXF output can be piped to standard shell tools for filtering, parsing, and integration with other tooling.

### 1. Filter for CRITICAL findings

```bash
ixf search siemens | grep CRITICAL
```

```
│ use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key   CRITICAL CVE-2021-22681  │
│ use cve/siemens/cve_2022_38465_s7_global_key            CRITICAL CVE-2022-38465  │
│ use cve/siemens/cve_2023_44317_simatic_pcs_rce          CRITICAL CVE-2023-44317  │
```

### 2. Count modules for a vendor

```bash
ixf vendors siemens | grep -c "CVE\|N/A"
# 27
```

### 3. Extract module paths from search results

```bash
ixf search modbus | grep "^    use " | awk '{print $2}'
```

```
exploits/protocols/modbus/modbus_write_single_register
exploits/protocols/modbus/modbus_flood_dos
exploits/protocols/modbus/modbus_read_coils
...
```

### 4. Save JSON report and parse with jq

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 run report json
cat ixf_report_*.json | jq '.events[] | select(.result == "VULNERABLE")'
```

```json
{
  "module": "scanners/ics/modbus_detect",
  "target": "192.168.1.100",
  "result": "VULNERABLE",
  "impact": "READ",
  "timestamp": "2026-06-01T20:15:43Z"
}
```

### 5. Extract CVE IDs from stats

```bash
ixf search CVE-2021 | grep "CVE-2021" | awk '{print $NF}'
```

### 6. Filter protocols by port

```bash
ixf protocols | grep "502"
```

```
MODBUS TCP         502/TCP    18 modules
PROFIsafe          502/TCP     1 module
```

### 7. Monitor MITRE coverage changes

```bash
ixf mitre-coverage | grep "TOTAL"
# TOTAL: 74/90 (82%)
```

### 8. Extract all vendor names

```bash
ixf vendors | awk '/^  [A-Z]/{print $1, $2}'
```

### 9. Parse SAST report for critical findings

```bash
ixf sast /opt/plc.st 2>&1 | grep "SEVERITY: CRITICAL"
# FINDING [SEVERITY: CRITICAL]: Unvalidated Chlorine Dosing Setpoint
```

### 10. Save MITRE layer and check size

```bash
ixf mitre-report layer
ls -la ixf_mitre_layer_*.json
wc -l ixf_mitre_layer_*.json
```

### 11. JSON report findings count with jq

```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.0/24 run report json
jq '.events | length' ixf_report_*.json
# 14
```

### 12. Filter TTP list by module count

```bash
ixf ttp-list | awk '$3 >= 5 {print $0}'
# Shows techniques with 5+ modules
```

### 13. Combine multiple subnet scans

```bash
for subnet in 192.168.1.0/24 10.0.0.0/24 172.16.0.0/24; do
    echo "=== Scanning $subnet ===" 
    ixf use scanners/ics/modbus_detect set target $subnet check 2>&1
done | grep -E "VULNERABLE|NOT VULNERABLE"
```

### 14. Extract module paths from ttp output

```bash
ixf ttp T0843 192.168.1.100 2>&1 | grep "Running module" | sed 's/.*: //'
```

```
cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
cve/siemens/cve_2022_38465_s7_global_key
cve/rockwell/cve_2022_1161_controllogix_modified_fw
exploits/protocols/s7comm/s7_unauthorized_cpu_control
assessment/mitre_ics/t0843_program_upload
```

### 15. Automated vendor check with filtered output

```bash
ixf vendors | grep -E "(Siemens|Rockwell|Schneider|Honeywell)" | awk '{print $1, $2, $NF}'
```

---

## Bash Assessment Script (Complete, 100+ Lines)

A complete ICS security assessment script using IXF in non-interactive mode:

```bash
#!/usr/bin/env bash
# ixf_assessment.sh — Automated ICS Security Assessment
# Usage: ./ixf_assessment.sh <target_ip> [output_dir]
# Requires: ixf installed (
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    )
# Author: Andre Henrique (@mrhenrike) | União Geek

set -euo pipefail

TARGET="${1:?Usage: $0 <target_ip> [output_dir]}"
OUTPUT_DIR="${2:-.tmp/assessment_$(date +%Y%m%d_%H%M%S)}"
LOGFILE="$OUTPUT_DIR/assessment.log"

# Setup
mkdir -p "$OUTPUT_DIR"
echo "=== IXF ICS Security Assessment ===" | tee "$LOGFILE"
echo "Target: $TARGET" | tee -a "$LOGFILE"
echo "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

# Check IXF is available
if ! command -v ixf &>/dev/null; then
    echo "ERROR: ixf not found. Install: 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    " >&2
    exit 1
fi

echo "[Phase 1] Module Index" | tee -a "$LOGFILE"
ixf stats 2>&1 | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

echo "[Phase 2] Protocol Discovery (Modbus)" | tee -a "$LOGFILE"
ixf use scanners/ics/modbus_detect \
    set target "$TARGET" \
    check 2>&1 | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

echo "[Phase 3] Protocol Discovery (S7comm)" | tee -a "$LOGFILE"
ixf use scanners/ics/s7_comm_scanner \
    set target "$TARGET" \
    check 2>&1 | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

echo "[Phase 4] MITRE Discovery Sweep (Simulate)" | tee -a "$LOGFILE"
ixf mitre-scan discovery "$TARGET" 2>&1 | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

echo "[Phase 5] TTP T0846 — Remote System Discovery" | tee -a "$LOGFILE"
ixf ttp T0846 "$TARGET" 2>&1 | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

echo "[Phase 6] TTP T0812 — Default Credentials Check" | tee -a "$LOGFILE"
ixf ttp-check T0812 "$TARGET" 2>&1 | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

echo "[Phase 7] TTP T0819 — Exploit Public-Facing Application (Simulate)" | tee -a "$LOGFILE"
ixf ttp T0819 "$TARGET" 2>&1 | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

echo "[Phase 8] IEC 62443 Zone/Conduit Assessment" | tee -a "$LOGFILE"
ixf assess iec62443/zone_conduit_audit 2>&1 | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

echo "[Phase 9] NIST SP 800-82r3 Checklist" | tee -a "$LOGFILE"
ixf assess nist_sp800_82/control_checklist 2>&1 | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

echo "[Phase 10] MITRE Coverage" | tee -a "$LOGFILE"
ixf mitre-coverage 2>&1 | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

echo "[Phase 11] Generate Reports" | tee -a "$LOGFILE"
ixf report json 2>&1 | tee -a "$LOGFILE"
ixf report html 2>&1 | tee -a "$LOGFILE"
ixf mitre-report layer 2>&1 | tee -a "$LOGFILE"

# Move generated reports to output dir
mv ixf_report_*.json "$OUTPUT_DIR/" 2>/dev/null || true
mv ixf_report_*.html "$OUTPUT_DIR/" 2>/dev/null || true
mv ixf_mitre_*.json "$OUTPUT_DIR/" 2>/dev/null || true

echo "" | tee -a "$LOGFILE"
echo "=== Assessment Complete ===" | tee -a "$LOGFILE"
echo "Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$LOGFILE"
echo "Output directory: $OUTPUT_DIR" | tee -a "$LOGFILE"
echo "Files:" | tee -a "$LOGFILE"
ls -la "$OUTPUT_DIR/" | tee -a "$LOGFILE"

# Summary: count findings
VULNERABLE_COUNT=$(grep -c "VULNERABLE\|POTENTIAL\|CRITICAL\|HIGH" "$LOGFILE" || true)
echo "" | tee -a "$LOGFILE"
echo "Findings requiring attention: $VULNERABLE_COUNT" | tee -a "$LOGFILE"
```

**Usage:**
```bash
chmod +x ixf_assessment.sh
./ixf_assessment.sh 192.168.1.100
./ixf_assessment.sh 192.168.1.100 /reports/q2-2026/
```

---

## Python API — 15 Code Examples

### 1. Run a module programmatically

```python
import subprocess
import sys

def run_ixf(*args: str) -> str:
    """Run IXF with given arguments and return output."""
    result = subprocess.run(
        ["ixf"] + list(args),
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result.stdout + result.stderr

# Simulate a module
output = run_ixf(
    "use", "scanners/ics/modbus_detect",
    "set", "target", "192.168.1.100",
    "run",
)
print(output)
```

### 2. Parse MITRE coverage

```python
import re

output = run_ixf("mitre-coverage")
total_match = re.search(r"TOTAL\s+(\d+)/(\d+)\s+\((\d+)%\)", output)
if total_match:
    covered, total, pct = total_match.groups()
    print(f"MITRE coverage: {covered}/{total} ({pct}%)")
```

### 3. Search modules by keyword

```python
def search_modules(keyword: str) -> list[str]:
    output = run_ixf("search", keyword)
    paths = []
    for line in output.splitlines():
        if "use " in line:
            match = re.search(r"use\s+(\S+)", line)
            if match:
                paths.append(match.group(1))
    return paths

siemens_modules = search_modules("siemens")
print(f"Found {len(siemens_modules)} Siemens modules")
```

### 4. Run TTP sweep and parse results

```python
def run_ttp(tid: str, target: str) -> dict:
    output = run_ixf("ttp", tid, target)
    return {
        "technique": tid,
        "target": target,
        "output": output,
        "simulated": "[SIMULATE" in output,
        "modules_run": output.count("Running module"),
    }

result = run_ttp("T0843", "192.168.1.100")
print(f"Ran {result['modules_run']} modules for {result['technique']}")
```

### 5. Generate report and read JSON

```python
import json
import glob

# Run assessment
run_ixf(
    "use", "scanners/ics/modbus_detect",
    "set", "target", "192.168.1.0/24",
    "run",
    "report", "json",
)

# Parse most recent report
reports = sorted(glob.glob("ixf_report_*.json"))
if reports:
    with open(reports[-1]) as f:
        report = json.load(f)
    print(f"Session events: {len(report.get('events', []))}")
```

### 6. Multi-target scan

```python
targets = ["192.168.1.100", "192.168.1.101", "10.0.0.50"]

for target in targets:
    output = run_ixf(
        "use", "scanners/ics/modbus_detect",
        "set", "target", target,
        "check",
    )
    status = "VULNERABLE" if "VULNERABLE" in output else "NOT VULNERABLE"
    print(f"{target}: {status}")
```

### 7. SAST analysis with LLM

```python
import os

# Configure API key via environment (never hardcode)
env = os.environ.copy()
env["GOOGLE_AI_STUDIO_API_KEY"] = os.environ["GEMINI_KEY"]

result = subprocess.run(
    ["ixf", "sast", "/opt/plc_projects/", "--mode", "sast"],
    capture_output=True, text=True, env=env, timeout=300,
)
print(result.stdout)
```

### 8. Automated daily scan with scheduling

```python
import schedule
import time

def daily_scan():
    """Run daily ICS reconnaissance scan."""
    output = run_ixf("mitre-scan", "discovery", "192.168.1.0/24")
    # Parse and alert on new findings
    if "VULNERABLE" in output or "POTENTIAL" in output:
        alert_security_team(output)
    # Generate report
    run_ixf("report", "json")

schedule.every().day.at("02:00").do(daily_scan)
while True:
    schedule.run_pending()
    time.sleep(60)
```

### 9. Load module and get options as dict

```python
def get_module_options(module_path: str) -> dict:
    output = run_ixf("use", module_path, "show", "options")
    options = {}
    for line in output.splitlines():
        # Parse table rows: | option | value | required | description |
        parts = [p.strip() for p in line.split("|") if p.strip()]
        if len(parts) >= 3 and parts[0] not in ("Option", "-"):
            options[parts[0]] = {
                "value": parts[1],
                "required": parts[2].lower() == "yes",
            }
    return options

opts = get_module_options("scanners/ics/modbus_detect")
print(opts)
# {"target": {"value": "", "required": True}, "port": {"value": "502", ...}}
```

### 10. Vendor enumeration

```python
def get_vendor_list() -> list[str]:
    output = run_ixf("vendors")
    vendors = []
    for line in output.splitlines():
        # Lines starting with vendor names
        match = re.match(r"\s{2}(\w[\w\s\/]+?)\s{2,}", line)
        if match:
            vendors.append(match.group(1).strip())
    return vendors

vendors = get_vendor_list()
print(f"Total vendors: {len(vendors)}")
```

### 11. Check if target has Modbus and return bool

```python
def has_modbus(target: str) -> bool:
    output = run_ixf(
        "use", "scanners/ics/modbus_detect",
        "set", "target", target,
        "check",
    )
    return "[+] VULNERABLE" in output or "Modbus device detected" in output

if has_modbus("192.168.1.100"):
    print("Target has Modbus — checking for CVEs...")
    print(run_ixf("search", "modbus"))
```

### 12. TTP coverage report as dict

```python
def get_ttp_coverage() -> dict:
    output = run_ixf("mitre-coverage")
    tactics = {}
    pattern = re.compile(r"(\w[\w\s]+\(TA\d+\))\s+:\s+(\d+)/(\d+)\s+\((\d+)%\)")
    for match in pattern.finditer(output):
        name, covered, total, pct = match.groups()
        tactics[name] = {"covered": int(covered), "total": int(total), "pct": int(pct)}
    return tactics

coverage = get_ttp_coverage()
for tactic, data in coverage.items():
    if data["pct"] < 80:
        print(f"LOW COVERAGE: {tactic} ({data['pct']}%)")
```

### 13. Batch CVE check

```python
cve_list = [
    "CVE-2021-22681",
    "CVE-2022-38465",
    "CVE-2023-6448",
    "CVE-2022-29965",
]

for cve in cve_list:
    output = run_ixf("search", cve)
    found = cve in output
    print(f"{cve}: {'COVERED' if found else 'NOT COVERED'}")
```

### 14. Assessment module execution

```python
assessments = [
    "iec62443/zone_conduit_audit",
    "nist_sp800_82/control_checklist",
    "risk/ics_risk_scorer",
    "threat_intel/ics_kill_chain",
]

for assess_module in assessments:
    print(f"\n=== {assess_module} ===")
    output = run_ixf("assess", assess_module)
    print(output)
```

### 15. Full assessment pipeline with output

```python
from pathlib import Path
from datetime import datetime

def full_assessment(target: str, output_dir: str = ".tmp/assessment") -> Path:
    """Run full ICS assessment and save results."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    phases = [
        # (phase_name, ixf_args)
        ("discovery_modbus", ["use", "scanners/ics/modbus_detect", "set", "target", target, "check"]),
        ("discovery_s7", ["use", "scanners/ics/s7_comm_scanner", "set", "target", target, "check"]),
        ("mitre_discovery", ["mitre-scan", "discovery", target]),
        ("ttp_t0846", ["ttp", "T0846", target]),
        ("ttp_t0812", ["ttp-check", "T0812", target]),
        ("assess_iec62443", ["assess", "iec62443/zone_conduit_audit"]),
        ("assess_nist", ["assess", "nist_sp800_82/control_checklist"]),
        ("coverage", ["mitre-coverage"]),
    ]

    all_output = []
    for phase_name, args in phases:
        print(f"[*] Running: {phase_name}")
        out_text = run_ixf(*args)
        all_output.append(f"=== {phase_name} ===\n{out_text}\n")

    # Write full log
    log_path = out / f"assessment_{target.replace('.', '_')}_{timestamp}.log"
    log_path.write_text("\n".join(all_output))

    # Generate reports
    run_ixf("report", "json")
    run_ixf("mitre-report", "layer")

    print(f"[+] Assessment complete. Output: {log_path}")
    return log_path

full_assessment("192.168.1.100", "/reports/assessment_q2/")
```

---

## GitHub Actions Workflow (Complete)

```yaml
# .github/workflows/ics_security_scan.yml
name: ICS Security Assessment

on:
  schedule:
    - cron: "0 2 * * 1"  # Every Monday at 02:00 UTC
  workflow_dispatch:
    inputs:
      target:
        description: "Target IP or CIDR"
        required: true
        default: "192.168.1.100"

jobs:
  ics-scan:
    name: ICS Security Scan
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.13"

      - name: Install IXF
        run: 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    

      - name: Verify IXF Installation
        run: |
          ixf stats
          ixf mitre-coverage

      - name: Run MITRE Coverage Check
        run: |
          ixf mitre-coverage > coverage_report.txt
          cat coverage_report.txt

      - name: Run Discovery Sweep (Simulate)
        env:
          TARGET: ${{ github.event.inputs.target || '192.168.1.100' }}
        run: |
          ixf use scanners/ics/modbus_detect set target "$TARGET" run > modbus_scan.txt || true
          ixf mitre-scan discovery "$TARGET" > discovery_scan.txt || true

      - name: Run Assessment Modules
        run: |
          ixf assess iec62443/zone_conduit_audit > iec62443_report.txt
          ixf assess nist_sp800_82/control_checklist > nist_report.txt
          ixf assess risk/ics_risk_scorer > risk_report.txt

      - name: Generate Reports
        env:
          TARGET: ${{ github.event.inputs.target || '192.168.1.100' }}
        run: |
          ixf use scanners/ics/modbus_detect set target "$TARGET" run report json
          ixf mitre-report layer
          ixf mitre-report html

      - name: Upload Assessment Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: ics-assessment-${{ github.run_number }}
          path: |
            ixf_report_*.json
            ixf_report_*.html
            ixf_mitre_*.json
            coverage_report.txt
            *_report.txt
          retention-days: 30

      - name: Check for Critical Findings
        run: |
          if grep -q "CRITICAL\|CATASTROPHIC" modbus_scan.txt discovery_scan.txt 2>/dev/null; then
            echo "::warning::Critical findings detected in ICS scan"
          fi
          echo "ICS assessment complete."
```

---

## Jenkins Pipeline (Complete)

```groovy
// Jenkinsfile — ICS Security Assessment Pipeline
pipeline {
    agent {
        docker {
            image 'python:3.13-slim'
            args '-u root'
        }
    }

    parameters {
        string(name: 'TARGET', defaultValue: '192.168.1.100', description: 'Target IP or CIDR')
        choice(name: 'SCAN_DEPTH', choices: ['simulate', 'check', 'full'], description: 'Scan depth')
    }

    environment {
        GOOGLE_AI_STUDIO_API_KEY = credentials('gemini-api-key')
    }

    stages {
        stage('Install IXF') {
            steps {
                sh '
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    '
                sh 'ixf stats'
            }
        }

        stage('Protocol Discovery') {
            steps {
                sh """
                    ixf use scanners/ics/modbus_detect \
                        set target ${params.TARGET} \
                        check > modbus_check.txt || true
                    cat modbus_check.txt
                """
            }
        }

        stage('MITRE Sweep') {
            steps {
                sh "ixf mitre-scan discovery ${params.TARGET} > mitre_discovery.txt"
                sh "ixf mitre-coverage"
            }
        }

        stage('TTP Analysis') {
            parallel {
                stage('T0843 - Program Download') {
                    steps { sh "ixf ttp T0843 ${params.TARGET}" }
                }
                stage('T0812 - Default Credentials') {
                    steps { sh "ixf ttp-check T0812 ${params.TARGET}" }
                }
                stage('T0846 - Remote Discovery') {
                    steps { sh "ixf ttp T0846 ${params.TARGET}" }
                }
            }
        }

        stage('Compliance Assessment') {
            steps {
                sh 'ixf assess iec62443/zone_conduit_audit'
                sh 'ixf assess nist_sp800_82/control_checklist'
                sh 'ixf assess risk/ics_risk_scorer'
            }
        }

        stage('Generate Reports') {
            steps {
                sh 'ixf report json'
                sh 'ixf report html'
                sh 'ixf mitre-report layer'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'ixf_report_*.json, ixf_report_*.html, ixf_mitre_*.json, *.txt'
        }
        failure {
            echo 'ICS assessment pipeline failed'
        }
        success {
            echo 'ICS assessment complete'
        }
    }
}
```

---

## GitLab CI (Complete)

```yaml
# .gitlab-ci.yml — ICS Security Assessment
stages:
  - setup
  - scan
  - assess
  - report

variables:
  TARGET: "192.168.1.100"
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  key: ixf-pip
  paths:
    - .cache/pip

install-ixf:
  stage: setup
  image: python:3.13-slim
  script:
    - 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
    - ixf stats
    - ixf mitre-coverage
  artifacts:
    paths:
      - coverage_output.txt

protocol-scan:
  stage: scan
  image: python:3.13-slim
  script:
    - 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
    - ixf use scanners/ics/modbus_detect set target $TARGET check || true
    - ixf use scanners/ics/s7_comm_scanner set target $TARGET check || true
    - ixf mitre-scan discovery $TARGET > discovery_report.txt
  artifacts:
    paths:
      - discovery_report.txt
    expire_in: 1 week

ttp-analysis:
  stage: scan
  image: python:3.13-slim
  parallel:
    matrix:
      - TTP_ID: T0843
      - TTP_ID: T0812
      - TTP_ID: T0846
      - TTP_ID: T0819
  script:
    - 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
    - ixf ttp $TTP_ID $TARGET > ttp_${TTP_ID}_results.txt
  artifacts:
    paths:
      - ttp_*.txt

compliance-assess:
  stage: assess
  image: python:3.13-slim
  script:
    - 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
    - ixf assess iec62443/zone_conduit_audit > iec62443.txt
    - ixf assess nist_sp800_82/control_checklist > nist_report.txt
    - ixf assess risk/ics_risk_scorer > risk_score.txt
  artifacts:
    paths:
      - iec62443.txt
      - nist_report.txt
      - risk_score.txt

generate-reports:
  stage: report
  image: python:3.13-slim
  script:
    - 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
    - ixf report json
    - ixf report html
    - ixf mitre-report layer
    - ixf mitre-report html
  artifacts:
    paths:
      - ixf_report_*.json
      - ixf_report_*.html
      - ixf_mitre_*.json
    expire_in: 4 weeks
```

---

## Docker Usage

```bash
# Run IXF in Docker
docker run --rm python:3.13-slim bash -c \
    "
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
     -q && ixf stats"

# With target network access
docker run --rm --network host python:3.13-slim bash -c \
    "
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
     -q && \
     ixf use scanners/ics/modbus_detect set target 192.168.1.100 run"

# Dockerfile for custom IXF image
cat > Dockerfile << 'EOF'
FROM python:3.13-slim
RUN 
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    
WORKDIR /assessment
ENTRYPOINT ["ixf"]
EOF

docker build -t ixf:latest .

# Run assessment
docker run --rm -v $(pwd)/reports:/assessment ixf:latest \
    use scanners/ics/modbus_detect \
    set target 192.168.1.100 \
    run \
    report json

# Interactive shell
docker run -it --rm ixf:latest
```

---

## Exit Codes

| Exit Code | Meaning | When |
|-----------|---------|------|
| `0` | Success | All commands executed without error |
| `1` | General error | Unhandled exception, invalid command |
| `2` | Module not found | `use` or `cve` command with unknown module |
| `3` | Validation error | Required option not set, invalid value |
| `4` | Connection error | check/run failed due to network unreachable |
| `5` | LLM error | SAST command with no configured provider |
| `6` | Permission error | NSE install without sudo/admin |
| `10` | Aborted | DestructiveGate confirmation rejected |

**Check exit code in bash:**
```bash
ixf use scanners/ics/modbus_detect set target 192.168.1.100 check
EXIT_CODE=$?

case $EXIT_CODE in
    0) echo "Success" ;;
    2) echo "Module not found" ;;
    4) echo "Connection failed — target unreachable" ;;
    *) echo "Error: $EXIT_CODE" ;;
esac
```

---

## JSON Output Parsing Examples

```python
import json
import glob

# Find latest JSON report
reports = sorted(glob.glob("ixf_report_*.json"))
if not reports:
    print("No reports found. Run: ixf report json")
    exit(1)

with open(reports[-1]) as f:
    report = json.load(f)

# Top-level structure
print(f"Session ID: {report.get('session_id')}")
print(f"Started: {report.get('started_at')}")
print(f"Target: {report.get('target')}")
print(f"Events: {len(report.get('events', []))}")

# Filter events by type
vulnerable = [e for e in report.get("events", []) if e.get("result") == "VULNERABLE"]
simulated = [e for e in report.get("events", []) if e.get("simulated", True)]

print(f"Vulnerable: {len(vulnerable)}")
print(f"Simulated: {len(simulated)}")

# Most severe findings
for event in sorted(report.get("events", []), key=lambda e: e.get("cvss", 0), reverse=True)[:5]:
    print(f"{event.get('module')} — CVSS: {event.get('cvss', 'N/A')} — {event.get('result')}")
```

---

*Previous: [Module Development](09-module-development.md) | Next: [PolyExploit Runner](11-poly-exploit-runner.md)*
