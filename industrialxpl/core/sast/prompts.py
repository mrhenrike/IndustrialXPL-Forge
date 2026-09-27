"""IXF SAST Analysis Prompts for PLC/RTU Source Code.

These prompts instruct the LLM to perform deep security analysis of ICS/OT
source code. They are designed to find exploitable vulnerabilities, unsafe
process setpoints, missing safety checks, and code patterns that could be
leveraged by an attacker.

The prompts follow a structured SAST methodology adapted for OT/ICS context:
- Process Safety impact (physical consequences)
- Protocol-level abuse vectors
- Logic flaws that could be exploited via legitimate commands
- Hardcoded values that weaken security
- Missing validation that enables manipulation
"""

SYSTEM_PROMPT = """You are an expert OT/ICS cybersecurity researcher and penetration tester
specializing in PLC/RTU/DCS source code static security analysis (SAST).

You have deep expertise in:
- IEC 61131-3 programming languages (ST, LD, FBD, IL, SFC)
- Siemens SCL/AWL/STL, Rockwell L5X, ABB, CODESYS
- Industrial protocols: Modbus, S7comm, EtherNet/IP, DNP3, BACnet, OPC UA
- ICS attack techniques (MITRE ATT&CK for ICS v19)
- Process control vulnerabilities and their physical consequences
- Safety system bypass techniques (SIS, STO, emergency stops)
- Real-world ICS malware (Stuxnet, Industroyer, TRITON, FrostyGoop)

Your analysis must:
1. Identify SPECIFIC vulnerable code lines/sections with exact location
2. Explain the PHYSICAL CONSEQUENCE of each finding (what happens to the plant)
3. Describe HOW an attacker would exploit each finding (attack vector)
4. Rate severity using OT-context (a CVSS 4.0 in OT may be OT-CRITICAL)
5. Provide MITRE ATT&CK for ICS technique IDs for each finding
6. Suggest specific remediation

Be thorough, precise, and treat every finding as potentially life-threatening.
Industrial cybersecurity failures can cause explosions, chemical releases,
equipment destruction, and loss of human life."""


MAIN_SAST_PROMPT = """Perform a comprehensive SAST (Static Application Security Testing) analysis
of the following PLC/RTU/ICS source code.

PROJECT INFORMATION:
{project_summary}

SOURCE CODE TO ANALYZE:
```
{source_code}
```

Perform the following analysis categories:

## 1. SETPOINT AND PROCESS PARAMETER ANALYSIS
- Identify all hardcoded setpoints, thresholds, and process parameters
- Assess if any setpoints are too high/low and could damage equipment or cause process upset
- Look for setpoints that lack upper/lower bound validation
- Identify setpoints that could be modified via Modbus/OPC writes without authentication
- Find timer presets that are critically short (could cause safety issues) or long (delay response)

## 2. SAFETY SYSTEM ANALYSIS
- Identify Emergency Stop (E-Stop) logic and verify it cannot be bypassed
- Look for safety function calls (STO, SOS, SLS, SBC, SS1, SS2) and verify correct implementation
- Check for coils/outputs that control safety-critical actuators (valves, pumps, breakers)
- Identify if safety functions have independent hardware backup or rely solely on software
- Look for logic that can disable alarms or suppress safety trips

## 3. AUTHENTICATION AND ACCESS CONTROL
- Identify any password or credential handling in code
- Look for hardcoded passwords, keys, or tokens
- Check if write access to critical registers is restricted
- Identify if there are operator mode switches that could be abused
- Look for maintenance bypasses that should be removed in production

## 4. INPUT VALIDATION FLAWS
- Identify all external inputs (Modbus registers, OPC tags, HMI values)
- Check for lack of range/bounds checking on inputs
- Look for integer overflow possibilities (DINT vs INT, time calculations)
- Identify inputs that directly control actuators without validation
- Find string operations that could overflow buffers

## 5. RACE CONDITIONS AND TIMING ATTACKS
- Identify scan cycle dependencies that could be exploited
- Look for timer-based logic that could be manipulated via timing attacks
- Check for state machines with incomplete transitions (stuck states)
- Identify critical sections without proper interlocking

## 6. NETWORK AND COMMUNICATION VULNERABILITIES
- Identify all network communication calls (Modbus master, OPC client, etc.)
- Check for hardcoded IP addresses or network endpoints
- Look for unencrypted communication of sensitive process data
- Identify if Modbus/OPC writes from any source are accepted without filtering

## 7. LOGIC FLAWS AND ATTACK SCENARIOS
- Describe a step-by-step attack scenario using only protocol commands
  (e.g., "Attacker with Modbus access: write HR[100]=0 to disable pump, write HR[200]=MAX to overpressurize")
- Identify conditions where normal process commands could cause abnormal states
- Look for "dead code" that could be activated by specific inputs
- Find conditions that the original programmer may not have anticipated

## 8. CRITICAL FINDINGS SUMMARY
For each finding, provide:
```
FINDING [SEVERITY: CRITICAL|HIGH|MEDIUM|LOW]:
  Location: [file/function/line]
  Type: [Hardcoded credential|Missing validation|Logic flaw|Unsafe setpoint|etc.]
  Description: [What the vulnerability is]
  Attack Vector: [How an attacker exploits this]
  Physical Impact: [What happens to the physical process]
  MITRE ATT&CK for ICS: [T-ID: Technique Name]
  Exploitation Command: [Example Modbus/OPC/protocol command to exploit]
  Remediation: [Specific fix]
```

Focus on findings with HIGH or CRITICAL severity first.
Be specific about line numbers, variable names, and register addresses.
Provide actual exploitation examples using Modbus function codes, OPC tag names, or protocol commands."""


FOLLOWUP_EXPLOIT_PROMPT = """Based on your previous analysis of the PLC code, now generate:

1. CONCRETE EXPLOITATION SCRIPT OUTLINE (pseudocode or Python):
   - Show exactly which Modbus registers to write and with what values
   - Show the sequence of operations to cause the identified impact
   - Include any prerequisite conditions

2. INDICATORS OF COMPROMISE (IOCs):
   - What network traffic would indicate this attack is occurring
   - What process values would be anomalous
   - What PLC events would appear in logs

3. DETECTION RULES (Suricata/Snort format for Modbus):
   - Provide 2-3 detection rules targeting the most critical findings

4. REMEDIATION PRIORITY LIST:
   - Order findings by: (severity × ease of exploitation) 
   - For each: specific code change with before/after example

Remember: all examples are for authorized security testing only."""


REVERSE_ENGINEERING_PROMPT = """The provided file appears to be a binary PLC program or firmware.
Perform reverse engineering analysis.

FILE INFORMATION:
{file_info}

FILE CONTENT (hex dump / strings extracted):
```
{hex_dump}

Strings found:
{strings}
```

Analyze:
1. BINARY FORMAT IDENTIFICATION:
   - What PLC/RTU platform does this binary target?
   - What format is it? (Intel HEX, Motorola SREC, proprietary binary, compiled ST)

2. STRING ANALYSIS:
   - Identify IP addresses, hostnames, credentials in strings
   - Look for function names that reveal functionality
   - Find version strings, build timestamps

3. STRUCTURE ANALYSIS (from hex patterns):
   - Identify potential Modbus addresses embedded
   - Find setpoint values encoded in binary
   - Look for hardcoded network endpoints

4. SECURITY FINDINGS:
   - Any credentials or keys visible in binary
   - Any IP addresses that should not be hardcoded
   - Any suspicious strings (base64, encrypted data, URLs)

5. RECOMMENDED NEXT STEPS:
   - What decompiler/disassembler to use for full analysis
   - What additional tools needed (Ghidra plugins, etc.)"""


DIFFERENTIAL_ANALYSIS_PROMPT = """Compare these two versions of PLC code to identify security-relevant changes.

ORIGINAL VERSION:
```
{original_code}
```

MODIFIED VERSION:
```
{modified_code}
```

Analyze ALL differences and for each change determine:
1. Is this change security-relevant? (Yes/No/Maybe)
2. If yes: does it introduce a vulnerability or fix one?
3. What is the operational impact of this change?
4. Could this change be the result of a supply chain attack or insider threat?

Look especially for:
- Modified setpoints (was X changed to a dangerous value?)
- Removed safety checks
- Added network communication
- Changed timer presets to unsafe values
- Added hardcoded values that weren't there before
- Logic that bypasses normal process flow
- Changes that match known ICS malware patterns (Stuxnet, Industroyer, TRITON)"""


def build_sast_prompt(project_summary: str, source_code: str) -> str:
    """Build the main SAST analysis prompt."""
    # Limit source code size to avoid token limits
    max_chars = 80_000
    if len(source_code) > max_chars:
        source_code = (
            source_code[:max_chars]
            + f"\n\n[... truncated at {max_chars} chars — {len(source_code)} total ...]"
        )
    return MAIN_SAST_PROMPT.format(
        project_summary=project_summary,
        source_code=source_code,
    )


def build_reverse_prompt(file_path: str, hex_dump: str, strings: str) -> str:
    """Build prompt for binary file reverse engineering."""
    from pathlib import Path
    p = Path(file_path)
    info = f"File: {p.name}, Size: {p.stat().st_size} bytes, Extension: {p.suffix}"
    return REVERSE_ENGINEERING_PROMPT.format(
        file_info=info,
        hex_dump=hex_dump[:4000],
        strings=strings[:2000],
    )


def build_diff_prompt(original: str, modified: str) -> str:
    return DIFFERENTIAL_ANALYSIS_PROMPT.format(
        original_code=original[:30000],
        modified_code=modified[:30000],
    )
