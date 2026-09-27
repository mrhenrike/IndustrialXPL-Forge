# SafeMode / DestructiveMode

IXF is designed to be **safe by default**. Every module starts in simulate mode and requires explicit multi-step opt-in before any live exploit payload is transmitted. This design prevents accidental disruption of production OT systems and creates an auditable trail for authorized testing.

---

## The Two Fundamental Modes

### SafeMode (Default — Always Active Unless Explicitly Disabled)

Every module defaults to `simulate=True`. In this mode:

- No network packets are sent to the target (no TCP connections beyond check() if explicitly called)
- `run()` calls `DestructiveGate.print_simulation()` which prints what *would* happen
- The output shows the exact payload bytes, MITRE techniques mapped, and step-by-step attack flow
- All simulation output is clearly labeled `[SIMULATE MODE — no packets sent]`
- Safe for use in SIEM/IDS detection testing, red team exercise planning, and training
- Safe to run against production IP ranges for planning — no impact whatsoever

**SafeMode is the factory default. It cannot be accidentally turned off.**

To disable SafeMode you must explicitly run two commands:
```
set simulate false
set destructive true
```

Forgetting either command keeps the module in a safe state.

### DestructiveMode (Requires Explicit Opt-In)

Requires both conditions simultaneously:
1. `set simulate false` — removes the simulation-only gate
2. `set destructive true` — signals intent to execute a real payload

Then `run` triggers the `DestructiveGate` confirmation flow, which varies by impact level.

---

## Impact Levels

Every module declares an impact level in `__info__["impact"]`. The level determines what confirmation is required before live execution and what banner is shown.

| Level | Color | Description | Example Modules | Required Action |
|-------|-------|-------------|-----------------|-----------------|
| `INFO` | — | Passive observation only. No packets sent by design. Assessment output only. | assessment/iec62443/zone_conduit_audit, assessment/mitre_ics/coverage_report | Automatic — no confirmation needed |
| `READ` | — | Read-only queries to target. No state change. Fingerprinting and detection only. | scanners/ics/modbus_detect, scanners/ics/s7_comm_scanner, scanners/ics/opcua_scanner | Automatic — warning displayed only |
| `LOW` | green | Non-destructive write. Reversible. Minor parameter change with no operational impact. | exploits/protocols/modbus/modbus_read_coils, creds/generic/http_default | Simple warning displayed; proceeds after acknowledgment |
| `MEDIUM` | yellow | Process parameter modification. May affect operation. Generally reversible. Operator may notice. | exploits/protocols/bacnet/bacnet_property_write, creds/siemens/ssh_default_creds | Press Enter to confirm |
| `HIGH` | orange | Device restart / process stop / service disruption. Requires operator intervention to recover. | cve/schneider_electric/cve_2022_24323_modicon_m340_dos, exploits/protocols/dnp3/dnp3_unauthorized_control | Type exact confirmation string |
| `CRITICAL` | red | Firmware modification / safety bypass / PLC logic overwrite. **MAY BE IRREVERSIBLE.** | cve/siemens/cve_2021_22681_s7_1200_hardcoded_key, cve/rockwell/cve_2022_1161_controllogix_modified_fw | Type exact confirmation string |
| `CATASTROPHIC` | dark red | Physical equipment damage / safety system disabling / mass casualty potential. **IRREVERSIBLE.** | cve/malware/killdisk_ics_wiper, cve/malware/frostygoop_modbus_heating, cve/malware/triton_trisis_safety_bypass | Type exact confirmation string + mandatory 10-second countdown wait |

---

## Impact Level Detail

### INFO

**Description:** The module performs no network activity. It outputs analysis, checklists, methodology guidance, or pre-computed data. Risk: zero.

**Example modules:**
- `assessment/iec62443/zone_conduit_audit` — IEC 62443 zone/conduit checklist
- `assessment/nist_sp800_82/control_checklist` — NIST 800-82r3 control checklist
- `assessment/mitre_ics/coverage_report` — MITRE ATT&CK coverage report
- `assessment/threat_intel/ics_kill_chain` — ICS kill chain analysis

**Behavior:** Runs immediately without any gate. No confirmation required.

```
ixf > assess iec62443/zone_conduit_audit
[*] Running IEC 62443 Zone and Conduit Audit...

  IEC 62443 Zone and Conduit Audit
  ──────────────────────────────────────────────────────────────────
  [i] Impact: INFO — no network activity
  Check                               Result    Notes
  IT/OT zone separation               MANUAL    Verify Level 3→2 firewall rules
  ...
```

---

### READ

**Description:** Sends read-only queries to the target. Does not modify any state on the device. Examples: Modbus FC04 probe, S7comm identification request, OPC UA GetEndpoints call. Risk: minimal — device may log connection; no operational impact.

**Example modules:**
- `scanners/ics/modbus_detect` — Modbus TCP fingerprinting
- `scanners/ics/s7_comm_scanner` — Siemens S7 detection
- `scanners/ics/opcua_scanner` — OPC UA endpoint discovery
- `scanners/ics/dnp3_scanner` — DNP3 outstation detection
- `scanners/ics/bacnet_scanner` — BACnet/IP device discovery

**Behavior with destructive=true and simulate=false:** Proceeds with a brief warning.

```
ixf (Modbus TCP Device Detect) > set simulate false
[*] simulate => False
ixf (Modbus TCP Device Detect) > set destructive true
[*] destructive => True
ixf (Modbus TCP Device Detect) > run

  [i] Impact: READ — read-only probes (no exploit, no state change)
  [i] Target: 192.168.1.100:502
  [!] Sending live packets. READ impact only — no modification to target.
[*] Connecting to 192.168.1.100:502...
[*] Sending Modbus FC04 Read Input Registers...
[+] Response: Device identified as Schneider Electric Modicon M340
[+] Unit IDs found: 1
```

---

### LOW

**Description:** Non-destructive write. Makes a change that is easily reversed by the operator. No production impact in most circumstances. Example: write a non-critical holding register to a test value.

**Example modules:**
- `exploits/protocols/modbus/modbus_read_coils` — Coil read (technically READ but classified LOW for safety margin)
- `creds/generic/http_default` — HTTP default credential test (read-only but involves authentication attempt)
- `creds/generic/telnet_default` — Telnet default credential test

**Behavior:** Banner shows impact level with warning. Proceeds without string confirmation.

```
ixf (creds/generic/http_default) > set simulate false
ixf (creds/generic/http_default) > set destructive true
ixf (creds/generic/http_default) > run

  ┌──────────────────────────────────────────────────────┐
  │  LIVE MODE — LOW IMPACT                              │
  │  Non-destructive. Reversible. Proceed? [Enter/Ctrl+C]│
  └──────────────────────────────────────────────────────┘

  Target: 192.168.1.100:80
  Action: Test HTTP default credentials (no state change on failure)
  Impact: LOW

  Press Enter to continue or Ctrl+C to abort...
[*] Testing 47 default credential pairs against 192.168.1.100:80...
```

---

### MEDIUM

**Description:** Modifies a process parameter or device configuration that may be visible to operators. Change is generally reversible but may require operator action. Impact: operational parameter change, not shutdown.

**Example modules:**
- `exploits/protocols/bacnet/bacnet_property_write` — Write BACnet property value
- `exploits/protocols/modbus/modbus_write_single_register` — Write single Modbus holding register
- `creds/siemens/ssh_default_creds` — Test SSH credentials (authenticated session attempt)

**Behavior:** Shows MEDIUM banner. Press Enter to confirm.

```
ixf (exploits/protocols/modbus/modbus_write_single_register) > run

  ┌──────────────────────────────────────────────────────────────┐
  │  LIVE MODE — MEDIUM IMPACT                                   │
  │  Process parameter modification. May affect operation.       │
  │  Reversible — operator can restore original value.           │
  └──────────────────────────────────────────────────────────────┘

  Module:  Modbus Write Single Register
  Target:  192.168.1.100:502
  Action:  Write value 0x0001 to Holding Register 0 (Unit 1)
  Impact:  MEDIUM — setpoint change visible in SCADA HMI

  Press Enter to continue or Ctrl+C to abort...

[*] Connecting to 192.168.1.100:502...
[+] FC06 Write Single Register: HR[0] = 0x0001 — success
[!] Restore original value after testing
```

---

### HIGH

**Description:** Device restart, process stop, service disruption, or denial of control. Requires operator intervention to recover. May cause process downtime. Example: trigger PLC stop mode, force device reboot.

**Example modules:**
- `cve/schneider_electric/cve_2022_24323_modicon_m340_dos` — Modicon M340 forced stop
- `exploits/protocols/dnp3/dnp3_unauthorized_control` — DNP3 unauthorized outstation control
- `exploits/protocols/s7comm/s7_unauthorized_cpu_control` — Siemens S7 CPU STOP command
- `cve/moxa/cve_2019_9084_nport_telnet_rce` — Moxa NPort telnet RCE (service restart)

**Behavior:** Shows HIGH banner (orange). Requires typing the exact confirmation string.

---

## Complete Terminal Walkthrough — HIGH Impact

```
ixf > use cve/schneider_electric/cve_2022_24323_modicon_m340_dos
[*] Module loaded: CVE-2022-24323 Modicon M340 Malformed Modbus DoS
[*] CVE: CVE-2022-24323 | CVSS: 7.5 | Impact: HIGH
[*] Author: Andre Henrique (mrhenrike)

ixf (CVE-2022-24323 Modicon M340 Malformed Modbus DoS) > show options
     Options — CVE-2022-24323 Modicon M340 Malformed Modbus DoS
+-------------+-------+----------+----------------------------------------------+
| Option      | Value | Required | Description                                  |
|-------------+-------+----------+----------------------------------------------|
| target      |       | yes      | Target Modicon M340 IP address               |
| port        | 502   | no       | Modbus TCP port                              |
| simulate    | True  | no       | Simulate — no packets sent (default)         |
| destructive | False | no       | Enable real exploitation                     |
| timeout     | 10    | no       | Connection timeout (seconds)                 |
+-------------+-------+----------+----------------------------------------------+

ixf (CVE-2022-24323 Modicon M340 Malformed Modbus DoS) > set target 10.0.1.20
[*] target => 10.0.1.20

ixf (CVE-2022-24323 Modicon M340 Malformed Modbus DoS) > set simulate false
[*] simulate => False

ixf (CVE-2022-24323 Modicon M340 Malformed Modbus DoS) > set destructive true
[*] destructive => True

ixf (CVE-2022-24323 Modicon M340 Malformed Modbus DoS) > run

  ██████████████████████████████████████████████████████████████
  ██  DESTRUCTIVE MODE — HIGH IMPACT                          ██
  ██  Device restart / process stop.                          ██
  ██  Requires operator intervention to recover.              ██
  ██████████████████████████████████████████████████████████████

  Module:  CVE-2022-24323 Modicon M340 Malformed Modbus DoS
  Target:  10.0.1.20:502
  Impact:  HIGH — Schneider Electric Modicon M340 forced stop via malformed
           Modbus function code. Device enters STOP mode. Process halts.
           Recovery: power cycle or engineering station STOP→RUN command.

  Type the following string EXACTLY to confirm (case-sensitive):
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmation> I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
[*] Confirmed. Audit entry written: .log/destructive_ops_2026-06-01.log
[*] Connecting to 10.0.1.20:502...
[+] TCP connection established.
[*] Sending malformed Modbus PDU (Function Code 0x5A, oversized length field)...
[+] Target stopped responding after 1.2 seconds — DoS successful
[+] PLC appears to be in STOP mode (verified by follow-up FC01 timeout)
[i] Restore device: power cycle or connect TIA Portal and issue CPU START command
[i] Audit entry: CONFIRMED | module=cve.schneider_electric.cve_2022_24323 | target=10.0.1.20:502 | impact=HIGH
```

---

### CRITICAL

**Description:** Firmware modification, safety system bypass, PLC logic overwrite. **May be irreversible.** Permanently changes device state. Examples: upload modified firmware, overwrite PLC program, extract and abuse hardcoded TLS keys.

**Example modules:**
- `cve/siemens/cve_2021_22681_s7_1200_hardcoded_key` — S7-1200/1500 TLS key exploit
- `cve/siemens/cve_2022_38465_s7_global_key` — S7comm global private key
- `cve/rockwell/cve_2022_1161_controllogix_modified_fw` — ControlLogix modified firmware upload
- `cve/emerson/cve_2022_29965_roc800_hardcoded_creds` — Emerson ROC800 hardcoded creds + admin access
- `exploits/protocols/s7comm/s7_unauthorized_cpu_control` — S7 unauthorized CPU control

**Behavior:** Shows CRITICAL banner (red). Requires typing exact confirmation string.

---

## Complete Terminal Walkthrough — CRITICAL Impact

```
ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
[*] Module loaded: CVE-2021-22681 Siemens S7-1200/1500 PLC
[*] CVE: CVE-2021-22681 | CVSS: 9.8 | Impact: CRITICAL

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set target 192.168.10.5
[*] target => 192.168.10.5

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set simulate false
[*] simulate => False

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set destructive true
[*] destructive => True

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > run

  ██████████████████████████████████████████████████████████████████████
  ██  DESTRUCTIVE MODE — CRITICAL IMPACT                              ██
  ██  Firmware modification / safety bypass / PLC logic overwrite.   ██
  ██  MAY BE IRREVERSIBLE. Verify you have authorization.            ██
  ██████████████████████████████████████████████████████████████████████

  Module:  CVE-2021-22681 Siemens S7-1200/1500 Hardcoded TLS Key
  Target:  192.168.10.5:102
  Impact:  CRITICAL — Uses hardcoded private TLS key to establish MitM position.
           Intercepts engineering traffic, decrypts PLC program.
           Optionally allows modified program upload to PLC.
           Affected: ALL S7-1200 and S7-1500 firmware versions (no patch available
           without hardware replacement).

  CVE:     CVE-2021-22681 | CVSS: 9.8 (Critical)
  Ref:     https://cert-portal.siemens.com/productcert/pdf/ssa-568428.pdf

  Type the following string EXACTLY to confirm (case-sensitive):
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmation> I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
[*] Confirmed. Audit entry written.
[*] Connecting to 192.168.10.5:102 (S7comm+ TLS)...
[*] Using hardcoded private key (extracted from S7-1200 firmware image)...
[+] TLS session established — MitM position achieved
[*] Intercepting engineering traffic...
[+] Captured: 1 engineering session (TIA Portal → PLC)
[+] Decrypted 14.2 KB of ladder logic from traffic
[i] Decrypted program saved: .tmp/s7_captured_program_20260601.bin
[i] To upload modified program: use exploit option --inject-program <file>
[i] Audit: CONFIRMED | CVE-2021-22681 | target=192.168.10.5:102 | impact=CRITICAL
```

---

### CATASTROPHIC

**Description:** Physical equipment damage, safety system disabling, mass casualty potential. Irreversible physical impact. Examples: MBR wiper on historian, Modbus attack disabling heating in winter, Triton/TRISIS safety system override.

**Example modules:**
- `cve/malware/killdisk_ics_wiper` — KillDisk MBR wiper (BlackEnergy3 / Industroyer)
- `cve/malware/frostygoop_modbus_heating` — FrostyGoop (Sandworm, Ukraine 2024)
- `cve/malware/triton_trisis_safety_bypass` — Triton/TRISIS SIS override (Schneider Triconex)
- `cve/malware/crashoverride_industroyer` — CrashOverride / Industroyer (Ukraine 2016)
- `cve/malware/notpetya_wiper` — NotPetya MBRS wiper
- `cve/malware/industroyer2_iec104` — Industroyer2 (Ukraine 2022)

**Behavior:** Shows CATASTROPHIC banner (dark red). 10-second mandatory wait (cannot be skipped). Then requires exact confirmation string.

---

## Complete Terminal Walkthrough — CATASTROPHIC Impact (Full 10-Second Countdown)

```
ixf > use cve/malware/frostygoop_modbus_heating
[*] Module loaded: FrostyGoop Modbus Heating Attack (Go) — Extended
[*] CVE: N/A | CVSS: N/A | Impact: CATASTROPHIC
[*] Attribution: Sandworm / GRU (Russia) | Campaign: Ukraine 2024
[!] Module requires Go runtime. Python fallback available (reduced functionality).

ixf (FrostyGoop Modbus Heating Attack) > show info

  Module Information
  ─────────────────────────────────────────────────────────────────
  name            : FrostyGoop Modbus Heating Attack (Go) — Extended
  description     : Replicate the FrostyGoop (BUSTLEBERM) TTP used by Sandworm
                    in January 2024 against Lviv, Ukraine district heating.
                    Sends Modbus FC16 write commands to Modbus TCP controllers
                    to set temperature setpoints to minimum, disabling heating.
                    Extended version runs continuously (goroutines) to prevent
                    operator recovery. 600 apartments lost heat for 2 days.
  attribution     : Sandworm / GRU (Russia) — CERT-UA #6444
  year            : 2024
  impact          : CATASTROPHIC — Physical: heating offline in winter; hypothermia risk
  mitre_techniques: T0836 (Modify Parameter), T0814 (Denial of Control),
                    T0813 (Denial of View), T0878 (Alarm Suppression)
  references      : https://www.mandiant.com/resources/blog/frostygoop-ics-attack
                    https://cert.gov.ua/article/6276921

ixf (FrostyGoop Modbus Heating Attack) > set target 192.168.1.100
[*] target => 192.168.1.100

ixf (FrostyGoop Modbus Heating Attack) > set simulate false
[*] simulate => False

ixf (FrostyGoop Modbus Heating Attack) > set destructive true
[*] destructive => True

ixf (FrostyGoop Modbus Heating Attack) > run

  ██████████████████████████████████████████████████████████████████████
  ██  DESTRUCTIVE MODE — CATASTROPHIC IMPACT                          ██
  ██  THIS ACTION IS IRREVERSIBLE                                      ██
  ██  Physical equipment damage / safety system disabling              ██
  ██  VERIFY AUTHORIZATION BEFORE PROCEEDING                          ██
  ██████████████████████████████████████████████████████████████████████

  Module:  FrostyGoop Modbus Heating Attack (Go) — Extended
  Target:  192.168.1.100:502
  Impact:  CATASTROPHIC — Sends Modbus FC16 write commands to disable heating
           controllers. Sets temperature setpoints to minimum (0°C).
           Runs continuously every 30 seconds to prevent operator recovery.
           Historical impact (Lviv, Ukraine, January 2024):
             600 apartments lost heat for 2 days in sub-zero winter conditions.
             Hypothermia risk. Civilian infrastructure attack.

  CVE:     N/A (TTP module — FrostyGoop malware replica)
  MITRE:   T0836, T0814, T0813, T0878

  [!] WAITING 10 SECONDS BEFORE PROMPT — press Ctrl+C to abort

  10... [pause]
   9... [pause]
   8... [pause]
   7... [pause]
   6... [pause]
   5... [pause]
   4... [pause]
   3... [pause]
   2... [pause]
   1... [pause]

  Type the following string EXACTLY to confirm (case-sensitive):
  I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION

  Confirmation> I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
[*] Confirmed. Audit entry written.
[*] [FrostyGoop] Connecting to 192.168.1.100:502 (Modbus TCP)...
[+] Connection established. Unit ID: 1
[*] [FrostyGoop] Phase 1: Writing temperature setpoint to 0x0000 (minimum)...
[*] FC16 Write Multiple Registers: Unit=1, Address=0x0000, Count=2, Values=[0,0]
[+] Heating controller: setpoint set to 0°C
[*] [FrostyGoop] Phase 2: Starting continuous loop (every 30s to prevent recovery)...
[*] [Loop iteration 1] Wrote 0x0000 to registers [0..1] — OK
[*] [Loop iteration 2] Wrote 0x0000 to registers [0..1] — OK
[*] [Loop] Awaiting 30s before next write... (Ctrl+C to abort loop)
^C
[-] Loop aborted by user.
[i] Restore device: manually write original setpoint via SCADA/HMI
[i] Audit: CONFIRMED | module=frostygoop_modbus_heating | target=192.168.1.100:502 | impact=CATASTROPHIC
```

---

## The Exact Confirmation String

The exact string required for `HIGH`, `CRITICAL`, and `CATASTROPHIC` impacts:

```
I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
```

**Rules:**
- Must be typed exactly as shown (case-sensitive)
- All spaces must be single spaces — no extra spaces
- No leading or trailing whitespace
- Any variation (wrong case, missing word, extra word, abbreviation) will abort

**Accepted:**
```
I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION
```

**Rejected (all of these abort):**
```
i accept full responsibility for this destructive operation   ← lowercase
I ACCEPT FULL RESPONSIBILITY                                  ← incomplete
I ACCEPT FULL RESPONSIBILITY FOR THIS DESTRUCTIVE OPERATION.  ← trailing period
yes                                                           ← wrong string
y                                                             ← wrong string
confirm                                                       ← wrong string
```

**On rejection:**
```
Confirmation> yes
[-] ABORTED. Audit entry written (ABORTED).
    Type the exact confirmation string to proceed, or Ctrl+C to cancel.
```

**On Ctrl+C:**
```
Confirmation> ^C
[-] ABORTED by user.
[i] Audit: ABORTED | target=192.168.1.100 | impact=CATASTROPHIC
```

---

## `print_simulation()` Output Explained

When `simulate=True` (the default), `run()` calls `DestructiveGate.print_simulation()`. This method displays a detailed, human-readable simulation of what the module *would* do.

### Function Signature

```python
DestructiveGate.print_simulation(
    description: str,           # required — what would happen (multi-line)
    payload_hex: str = None,    # optional — hex dump of the exploit payload
    payload_human: str = None,  # optional — human-readable payload description
    mitre_techniques: list = None,  # optional — list of MITRE TIDs
)
```

### Parameter Reference

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `description` | string | yes | Multi-line description of attack phases and actions |
| `payload_hex` | string | no | Hex dump of exploit payload (auto-truncated to 120 chars) |
| `payload_human` | string | no | Human-readable payload description |
| `mitre_techniques` | list[str] | no | MITRE ATT&CK for ICS technique IDs |

### Example 1 — Scanner Module (READ impact)

```python
# In module run() method:
DestructiveGate.print_simulation(
    description=(
        "Modbus TCP Device Detect on {target}:{port}\n\n"
        "Phase 1 [TCP Connect]: Would attempt TCP connection to {target}:{port}\n"
        "Phase 2 [FC04 Probe]:  Would send Modbus Function Code 04 (Read Input Registers)\n"
        "                       Unit ID: {unit_id} | Registers: 0-9\n"
        "Phase 3 [Fingerprint]: Would analyze response for device type and firmware version\n"
        "Phase 4 [FC43 ID]:     Would send Modbus FC43 (MEI) device identification request"
    ),
    payload_hex="00 01 00 00 00 06 01 04 00 00 00 0A",
    payload_human="Modbus FC04 Read Input Registers: Unit=1, Start=0, Count=10",
    mitre_techniques=["T0846"],
)
```

**Terminal output:**

```
  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────────────
  [i] What would happen:
      Modbus TCP Device Detect on 192.168.1.100:502

      Phase 1 [TCP Connect]: Would attempt TCP connection to 192.168.1.100:502
      Phase 2 [FC04 Probe]:  Would send Modbus Function Code 04 (Read Input Registers)
                             Unit ID: 1 | Registers: 0-9
      Phase 3 [Fingerprint]: Would analyze response for device type and firmware version
      Phase 4 [FC43 ID]:     Would send Modbus FC43 (MEI) device identification request

  [i] Payload (human):  Modbus FC04 Read Input Registers: Unit=1, Start=0, Count=10
  [i] Payload (hex):    00 01 00 00 00 06 01 04 00 00 00 0A
  [i] MITRE ATT&CK for ICS: T0846 (Remote System Discovery)
  [i] To run live: set simulate false (READ impact — no destructive flag needed)
```

### Example 2 — CRITICAL CVE Module

```python
# In cve_2021_22681 run() method:
DestructiveGate.print_simulation(
    description=(
        "CVE-2021-22681 — Siemens S7-1200/1500 Hardcoded TLS Key\n\n"
        "Phase 1 [S7comm+ Connect]:  TCP to {target}:102, negotiate S7comm+ TLS handshake\n"
        "Phase 2 [Key Injection]:    Load hardcoded RSA private key extracted from firmware\n"
        "Phase 3 [MitM Position]:    Intercept STEP7/TIA Portal engineering traffic\n"
        "Phase 4 [Decrypt Payload]:  Decrypt PLC program transfer and engineering session\n"
        "Phase 5 [Modify Logic]:     Inject modified PLC ladder logic block\n"
        "Phase 6 [Upload]:           Download modified program via authenticated TLS session\n"
        "Phase 7 [Persistence]:      Modified program persists across PLC power cycles"
    ),
    payload_hex="03 00 00 1F 02 F0 80 32 01 00 00 00 01 00 0E 00 00 04 01 12 04 11 44 01 00 FF",
    payload_human="S7comm+ TLS ClientHello with hardcoded private key material",
    mitre_techniques=["T0830", "T0855", "T0843"],
)
```

**Terminal output:**

```
  [SIMULATE MODE — no packets sent]
  ─────────────────────────────────────────────────────────────────────
  [i] What would happen:
      CVE-2021-22681 — Siemens S7-1200/1500 Hardcoded TLS Key

      Phase 1 [S7comm+ Connect]:  TCP to 10.0.0.50:102, negotiate S7comm+ TLS handshake
      Phase 2 [Key Injection]:    Load hardcoded RSA private key extracted from firmware
      Phase 3 [MitM Position]:    Intercept STEP7/TIA Portal engineering traffic
      Phase 4 [Decrypt Payload]:  Decrypt PLC program transfer and engineering session
      Phase 5 [Modify Logic]:     Inject modified PLC ladder logic block
      Phase 6 [Upload]:           Download modified program via authenticated TLS session
      Phase 7 [Persistence]:      Modified program persists across PLC power cycles

  [i] Payload (human):  S7comm+ TLS ClientHello with hardcoded private key material
  [i] Payload (hex):    03 00 00 1F 02 F0 80 32 01 00 00 00 01 00 0E 00 00 04 01 12 04...
  [i] MITRE ATT&CK for ICS: T0830 (Adversary-in-the-Middle), T0855 (Unauthorized Command Message), T0843 (Program Download)
  [i] To run live: set simulate false + set destructive true
  [!] This is a CRITICAL impact module — DestructiveGate confirmation required
```

### Example 3 — Malware TTP Module (CATASTROPHIC)

```python
# In killdisk_ics_wiper run() method:
DestructiveGate.print_simulation(
    description=(
        "KillDisk ICS Wiper — BlackEnergy3/Industroyer TTP (Ukraine 2015-2016)\n\n"
        "Phase 1 [Spread]:          Enumerate network shares and SCADA workstations\n"
        "Phase 2 [Credential Theft]: Extract cached Windows credentials (Mimikatz-style)\n"
        "Phase 3 [Deploy Wiper]:     Copy killdisk binary to discovered systems via SMB\n"
        "Phase 4 [MBR Overwrite]:    Overwrite Master Boot Record of all target disks\n"
        "         Target disks:      All fixed drives (PhysicalDrive0 through PhysicalDrive9)\n"
        "         Write pattern:     0xFFFFA (random sector fill), then MBR zeroed\n"
        "Phase 5 [Forced Reboot]:    Force system reboot — system unable to boot\n"
        "Phase 6 [HMI Deletion]:     Delete SCADA HMI projects and historian databases\n"
        "Phase 7 [Serial Comm Kill]: Terminate all serial communication processes\n\n"
        "Historical impact: 80,000 Ukrainian customers lost power for 6 hours (Dec 2015)\n"
        "                   HMI systems required complete OS reinstallation"
    ),
    payload_hex="FF FF A0 FF FF FF FF FF FF FF A0 FF FF FF",
    payload_human="MBR overwrite pattern (random sectors + zero MBR at sector 0)",
    mitre_techniques=["T0810", "T0816", "T0879", "T0813", "T0881"],
)
```

---

## Audit Log Format and Location

Every destructive operation attempt (whether confirmed or aborted) is recorded to:

```
.log/destructive_ops_YYYY-MM-DD.log
```

The log file is created in the current working directory where IXF is launched.

### Log Entry Format

```
TIMESTAMP | STATUS | module=<module_path> | target=<ip>:<port> | impact=<LEVEL> | user=<whoami>
```

### Real Log Examples

```
2026-06-01T20:15:43Z | CONFIRMED | module=cve.malware.frostygoop_modbus_heating | target=192.168.1.100:502 | impact=CATASTROPHIC | user=analyst1
2026-06-01T20:16:01Z | ABORTED   | module=cve.malware.crashoverride_industroyer  | target=192.168.1.200:2404 | impact=CATASTROPHIC | user=analyst1
2026-06-01T20:18:22Z | CONFIRMED | module=cve.siemens.cve_2021_22681_s7_1200     | target=10.0.0.5:102       | impact=CRITICAL    | user=analyst1
2026-06-01T20:19:55Z | ABORTED   | module=cve.schneider.cve_2022_24323_modicon    | target=10.0.1.20:502      | impact=HIGH        | user=analyst1
2026-06-01T20:22:14Z | CONFIRMED | module=cve.schneider.cve_2022_24323_modicon    | target=10.0.1.20:502      | impact=HIGH        | user=analyst1
```

### Log Location by Platform

| Platform | Default Path | Notes |
|----------|-------------|-------|
| Linux/macOS | `./.log/destructive_ops_YYYY-MM-DD.log` | Relative to `ixf` launch directory |
| Windows | `.\.log\destructive_ops_YYYY-MM-DD.log` | Relative to `ixf` launch directory |
| Custom | Configurable in `safety.py` `LOG_DIR` constant | For custom deployments |

### Viewing Logs

```bash
# View today's log
cat .log/destructive_ops_$(date +%Y-%m-%d).log

# View all logs
ls .log/
cat .log/destructive_ops_*.log

# Count confirmed operations
grep CONFIRMED .log/destructive_ops_2026-06-01.log | wc -l

# View CATASTROPHIC operations only
grep CATASTROPHIC .log/destructive_ops_2026-06-01.log
```

---

## simulate/destructive Combination Matrix

| simulate | destructive | impact | Behavior |
|----------|-------------|--------|----------|
| `True` | `False` | any | `print_simulation()` only — no packets. Always safe. |
| `True` | `True` | any | `print_simulation()` only — `destructive=true` is irrelevant when simulate=True. Always safe. |
| `False` | `False` | INFO | `run()` directly — outputs analysis (no network) |
| `False` | `False` | READ | `check()` only — read-only fingerprint probes |
| `False` | `False` | LOW | `check()` + brief warning banner — minor write attempted |
| `False` | `False` | MEDIUM | `check()` only — no modify without destructive=True |
| `False` | `False` | HIGH | `check()` only — no modify without destructive=True |
| `False` | `False` | CRITICAL | `check()` only — CRITICAL requires destructive=True |
| `False` | `False` | CATASTROPHIC | `check()` only — CATASTROPHIC requires destructive=True |
| `False` | `True` | INFO | `run()` directly — assessment output |
| `False` | `True` | READ | Live read-only probes — warning banner |
| `False` | `True` | LOW | Live write — LOW banner — press Enter |
| `False` | `True` | MEDIUM | Live write — MEDIUM banner — press Enter |
| `False` | `True` | HIGH | Live exploit — HIGH banner — confirmation string |
| `False` | `True` | CRITICAL | Live exploit — CRITICAL banner — confirmation string |
| `False` | `True` | CATASTROPHIC | Live exploit — CATASTROPHIC banner — 10s wait + confirmation string |

---

## setg simulate true — Global Session Lock

Use `setg simulate true` at session start to enforce simulate mode globally for all modules in the session, regardless of individual `set simulate` commands:

```
ixf > setg simulate true
[*] Global: simulate => True
[!] Simulate mode is globally locked. All modules will simulate.
[i] Individual 'set simulate false' commands will be overridden by global.

ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
[*] Module loaded: CVE-2021-22681 Siemens S7-1200/1500 PLC

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > set simulate false
[*] simulate => False
[!] Global 'simulate=True' overrides this setting. Module will still simulate.

ixf (CVE-2021-22681 Siemens S7-1200/1500 PLC) > run
  [SIMULATE MODE — no packets sent]    ← always simulates despite local set simulate false
  ...
```

This is recommended for:
- Training and education sessions
- Lab environments shared with multiple users
- Any session where you want a hard guarantee of no live packets

To release the global lock:
```
ixf > unsetg simulate
[*] Global 'simulate' cleared.
[i] Modules now use their own default (simulate=True per-module).
```

---

## Python API Usage

Access the safety system directly in Python scripts and automation:

```python
from industrialxpl.core.exploit.safety import DestructiveGate, IMPACT_LEVELS

# Check impact level requirements
print(IMPACT_LEVELS)
# {
#   "INFO": {"requires_confirmation": False, "countdown": 0},
#   "READ": {"requires_confirmation": False, "countdown": 0},
#   "LOW":  {"requires_confirmation": False, "countdown": 0},
#   "MEDIUM": {"requires_confirmation": False, "countdown": 0},
#   "HIGH": {"requires_confirmation": True, "confirmation_string": "I ACCEPT...", "countdown": 0},
#   "CRITICAL": {"requires_confirmation": True, "confirmation_string": "I ACCEPT...", "countdown": 0},
#   "CATASTROPHIC": {"requires_confirmation": True, "confirmation_string": "I ACCEPT...", "countdown": 10},
# }

# Print simulation output programmatically
DestructiveGate.print_simulation(
    description="Phase 1: Connect to {target}:502\nPhase 2: Send exploit payload",
    payload_hex="00 01 00 00 00 06 01 10 00 00 00 01 02 FF FF",
    payload_human="Modbus FC16 Write Multiple Registers",
    mitre_techniques=["T0836", "T0814"],
)

# Check if a gate confirmation is needed
gate = DestructiveGate(
    module_name="CVE-2021-22681",
    target="192.168.1.100:102",
    impact="CRITICAL",
    action="S7comm+ MitM and program download",
)
# In non-interactive scripts, confirmation_required=True means you must handle it
# For automated testing, use simulate=True always
```

### Automated testing (always simulate):

```python
import subprocess
import json

# Run IXF non-interactively in simulate mode (always safe)
result = subprocess.run(
    ["ixf", "use", "scanners/ics/modbus_detect",
     "set", "target", "192.168.1.100",
     "run"],
    capture_output=True,
    text=True,
)
print(result.stdout)
# Output will always show [SIMULATE MODE — no packets sent]
# because simulate=True is the default
```

---

## Full ASCII Workflow Diagram

```
ixf > use <module>
ixf > set target <ip>
ixf > run
       │
       ├─► simulate=True (DEFAULT)
       │          │
       │          └──► DestructiveGate.print_simulation()
       │                    │
       │                    └──► [no packets sent — always safe]
       │
       └─► simulate=False
                  │
                  ├─► destructive=False
                  │          │
                  │          ├─► impact=INFO/READ ──► run() directly (read-only)
                  │          ├─► impact=LOW       ──► check() only
                  │          ├─► impact=MEDIUM    ──► check() only
                  │          ├─► impact=HIGH      ──► check() only
                  │          ├─► impact=CRITICAL  ──► check() only
                  │          └─► impact=CATASTROPHIC ──► check() only
                  │
                  └─► destructive=True
                             │
                             ├─► impact=INFO        ──► run() (no network — assessment)
                             ├─► impact=READ        ──► run() (live read probes) + warning
                             ├─► impact=LOW         ──► DestructiveGate LOW banner → Enter → run()
                             ├─► impact=MEDIUM      ──► DestructiveGate MEDIUM banner → Enter → run()
                             ├─► impact=HIGH
                             │         │
                             │         ├─► Show HIGH banner (orange)
                             │         ├─► Write audit entry (pending)
                             │         ├─► Prompt: "I ACCEPT FULL RESPONSIBILITY..."
                             │         ├─► If exact match → CONFIRMED + audit → run()
                             │         └─► If mismatch → ABORTED + audit
                             │
                             ├─► impact=CRITICAL
                             │         │
                             │         ├─► Show CRITICAL banner (red)
                             │         ├─► Write audit entry (pending)
                             │         ├─► Prompt: "I ACCEPT FULL RESPONSIBILITY..."
                             │         ├─► If exact match → CONFIRMED + audit → run()
                             │         └─► If mismatch → ABORTED + audit
                             │
                             └─► impact=CATASTROPHIC
                                       │
                                       ├─► Show CATASTROPHIC banner (dark red)
                                       ├─► Write audit entry (pending)
                                       ├─► sleep(10) countdown [1..10] — Ctrl+C aborts
                                       ├─► Prompt: "I ACCEPT FULL RESPONSIBILITY..."
                                       ├─► If exact match → CONFIRMED + audit → run()
                                       └─► If mismatch/Ctrl+C → ABORTED + audit
```

---

## 10 Best Practices

### 1. Always Start Sessions with `setg simulate true`

Lock simulate mode globally at the start of any session to prevent accidental live execution:

```
ixf > setg simulate true
```

This is especially important in shared lab environments, training sessions, and any scenario where multiple users may be running IXF.

### 2. Use `check` Before `run` in Live Mode

Before running a full exploit in authorized environments, always run `check` first to verify the target is reachable and potentially vulnerable:

```
ixf > check   # Verify target before committing to exploit
ixf > run     # Only after check confirms vulnerability
```

This prevents wasting time on unreachable targets and reduces unnecessary network traffic.

### 3. Never Test on Production Without Written Authorization

Impact levels are defined for good reason. Even READ-level modules generate network traffic visible to IDS and may cause unexpected behavior on sensitive OT devices. Always obtain written authorization before any live testing.

### 4. Review Simulation Output Before Live Execution

The `print_simulation()` output shows exactly what the module will do. Read it carefully before enabling live mode. Pay special attention to:
- All phases listed
- The exact payload bytes
- Which MITRE techniques are invoked
- The impact level and recovery procedure

### 5. Keep Audit Logs and Review Them After Sessions

The `.log/destructive_ops_YYYY-MM-DD.log` file is your legal protection. After every authorized test session:

```bash
cat .log/destructive_ops_$(date +%Y-%m-%d).log | tee session_audit.txt
```

Keep these logs as part of your test report. They prove which operations were attempted and which were confirmed vs. aborted.

### 6. Use `ttp-check` for Initial Reconnaissance

Before running full TTP sweeps with `ttp`, use `ttp-check` to safely fingerprint which modules are applicable to a target:

```
ixf > ttp-check T0843 192.168.1.100
```

This runs only `check()` probes (read-only) across all technique modules.

### 7. Test CATASTROPHIC Modules Only in Isolated Lab Networks

CATASTROPHIC modules (`killdisk`, `frostygoop`, `triton/trisis`) should only ever be executed in isolated lab networks with no connection to production systems. Even a VLAN mistake could cause real-world impact.

Recommended lab setup:
- Air-gapped network segment
- No routing to production OT
- Physical isolation where possible
- Documented authorization signed by facility owner

### 8. Use `simulate=True` for SIEM/IDS Detection Tuning

The simulate mode output contains the exact payload bytes and MITRE techniques. Use this to tune SIEM detection rules without sending actual exploit traffic:

```
ixf > run   # simulate=True (default) — outputs exact payload hex for detection rules
```

This is one of the core use cases for IXF — improving detection posture without operational risk.

### 9. Pair Every Live Session with Report Generation

After any authorized live session, generate a full report:

```
ixf > report html
ixf > mitre-report layer
```

Include the generated files in your pentest or assessment report.

### 10. Understand Recovery Procedures Before Executing HIGH+ Modules

For every HIGH, CRITICAL, or CATASTROPHIC module, know the recovery procedure before executing:
- HIGH: Know how to restart the device (power cycle, engineering station command)
- CRITICAL: Know how to restore firmware/PLC program from backup
- CATASTROPHIC: Know the physical recovery procedure (may require vendor support)

The simulation output for each module includes recovery guidance -- read it in simulate mode before going live.

---

## Noise Level Comparison: IXF vs Nmap

IXF is designed to be the **least aggressive** active scanner for OT/ICS environments. Unlike Nmap, which sends SYN packets, OS detection probes, and multiple script PDUs per port, IXF sends a single well-formed protocol PDU -- identical to what a legitimate engineering workstation sends during normal operations.

```
Tool / Mode              Noise    OT risk
---------------------------------------------------------
tcpdump (passive)        1/5  ||||                Zero -- listen only, no packets sent
Wireshark (passive)      1/5  ||||                Zero -- listen only, no packets sent
IXF check()              2/5  ||||||||            1 TCP connection, 1 valid PDU, 1 response
IXF run() simulate=true  2/5  ||||||||            Identical to check() -- no writes
nmap -sS -T1             3/5  ||||||||||||        SYN scan (slow), half-open TCP
IXF run() simulate=false 3/5  ||||||||||||        1 conn, 1 read PDU (FC03/FC43)
nmap -sS -T2 (OT-safe)   3/5  ||||||||||||        Acceptable with conservative timing
nmap -sV -T3             4/5  ||||||||||||||||    Version probes per open port
nmap --script modbus-*   4/5  ||||||||||||||||    Multiple PDUs per port
nmap -A (aggressive)     5/5  ||||||||||||||||||||  OS detect + scripts -- AVOID in OT
nmap -T4 / -T5           5/5  ||||||||||||||||||||  NEVER in OT -- may crash PLCs/RTUs
```

### IXF Timing vs Nmap -T

| Nmap flag | IXF equivalent | Timeout | Delay | Retries | Use case |
|-----------|---------------|---------|-------|---------|----------|
| `-T0` | `setg TIMING paranoid` | 5.0s | 10s | 1 | Maximum stealth |
| `-T1` | `setg TIMING sneaky` | 3.0s | 5s | 1 | Very slow ICS |
| `-T2` | `setg TIMING polite` | 2.0s | 1s | 2 | **Recommended for OT** |
| `-T3` | `setg TIMING normal` | 1.0s | 300ms | 3 | Default -- safe for most OT |
| `-T4` | `setg TIMING aggressive` | 0.5s | 50ms | 2 | Lab / fast networks only |
| `-T5` | `setg TIMING insane` | 0.2s | 0ms | 1 | Never in production OT |

### Nmap Flags as IXF Global Options

```bash
# nmap -T2 --max-retries 1 --host-timeout 30s --max-rate 10 --scan-delay 500ms
setg TIMING T2
setg MAX_RETRIES 1
setg HOST_TIMEOUT 30
setg MAX_RATE 10
setg SCAN_DELAY 500

# nmap --version-intensity 2
setg PROBE_LEVEL 2

# nmap -Pn
setg SKIP_PING true

# nmap -oN output.txt
setg OUTPUT output.txt

# nmap -v
setg VERBOSE true
```

### Why IXF is Safer than Nmap for OT

| Aspect | Nmap | IXF |
|--------|------|-----|
| TCP handshake | SYN-only (half-open) | Full connect (complete handshake) |
| Payload | Generic probes + banner grab | Protocol-correct PDU (Modbus/S7/ENIP) |
| PDUs per port | 1-20+ (scripts, version probes) | 1 per check, 1-3 with PROBE_LEVEL 1-2 |
| OT-awareness | None | Designed for OT protocols |
| Rate limiting | Manual flags | Built-in defaults (MAX_RATE=10, DELAY=300ms) |
| Write protection | None | Requires `destructive=true` + confirmation |

---

*Previous: [Module System](04-module-system.md) | Next: [MITRE ATT&CK for ICS](06-mitre-attack-ics.md)*
