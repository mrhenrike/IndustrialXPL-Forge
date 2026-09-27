# IXF Resource Files (.rc)

Resource files allow you to automate IXF sessions — set global options, load modules, configure them, and run — all from a plain text file. Similar to Metasploit's `-r` option.

## Usage

```bash
# Execute file and drop into interactive shell
ixf -r resources/rc/modbus_scan.rc

# Execute file and exit (non-interactive, for CI/CD)
ixf -r resources/rc/modbus_scan.rc -x

# Chain multiple resource files
ixf -r setup.rc -r scan.rc -r report.rc -x

# Inline commands (semicolons separate)
ixf -e "setg TARGET 10.0.0.1; setg TIMING T2" -r scan.rc -x

# Quiet mode (no banner) + resource file
ixf -q -r scan.rc -x

# Set loglevel from CLI
ixf --loglevel debug -r scan.rc

# Save output to file
ixf -o /tmp/ixf_scan.log -r scan.rc -x
```

## File Format

```
# Lines starting with # are comments — ignored
# Blank lines are ignored

# Set global options first
setg TIMING T2
setg SCAN_DELAY 500
setg TARGET 192.168.1.100

# Load and configure a module
use scanners/ics/modbus_scanner
set PORT 502
set REGISTERS 40001-40020
run

# Load another module
use scanners/ics/modbus_banner_grabbing
run

back
```

## Available Templates

| File | Description |
|------|-------------|
| `modbus_scan.rc` | Full Modbus TCP assessment (identify + scan + banner) |
| `ot_discovery.rc` | Multi-protocol OT discovery (Modbus, S7, ENIP, DNP3) |
| `mitre_ics_sweep.rc` | Full MITRE ATT&CK for ICS sweep (simulate mode) |
| `iec62443_audit.rc` | Interactive IEC 62443-3-2 zone and conduit audit |

## CI/CD Integration Example

```yaml
# GitHub Actions
- name: OT Assessment
  run: |
    pip install industrialxpl-forge
    ixf -q -e "setg TARGET ${{ env.OT_TARGET }}" -r ot_discovery.rc -x
```

## Tips

- Use `setg` for options that apply across all modules
- Comments (`#`) help document assessment intent for the report
- `-x` (exit after) is recommended for automated pipelines
- Chain `-r` files to separate setup from scan from reporting
- `exit` in a `.rc` file terminates execution even with `-r` chaining
