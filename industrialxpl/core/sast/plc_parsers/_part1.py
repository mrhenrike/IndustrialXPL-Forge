"""IXF PLC/RTU Source Code Parser with LLM-safe Sanitization.

Supports the 5 IEC 61131-3 languages plus vendor-specific formats:
  ST  - Structured Text (.st, .iecst, .scl)
  LD  - Ladder Diagram (.lad, .ld)
  FBD - Function Block Diagram (.fbd)
  IL  - Instruction List (.il, .awl, .stl)
  SFC - Sequential Function Chart (.sfc)
  + Siemens SCL/STL/AWL, CODESYS .project, ABB .ap1, L5X, etc.

Sanitization before LLM submission:
  - IP addresses replaced with [IP_REDACTED]
  - Passwords/secrets replaced with [CREDENTIAL_REDACTED]
  - Hostnames/domains replaced with [HOST_REDACTED]
  - Long binary data replaced with [BINARY_REDACTED]
  - Comments with PII/company info flagged only, not sent
  - Token budget enforced (max ~8000 tokens = ~32KB)

Design principle: send only security-relevant structural information to LLM,
not entire source code. This minimizes token cost and protects sensitive data.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── File extension → language mapping ────────────────────────────────────────

EXTENSION_MAP: dict[str, str] = {
    ".st":      "Structured Text (ST)",
    ".iecst":   "Structured Text (ST)",
    ".scl":     "Structured Text / Siemens SCL",
    ".lad":     "Ladder Diagram (LD)",
    ".ld":      "Ladder Diagram (LD)",
    ".ldr":     "Ladder Diagram (LD)",
    ".il":      "Instruction List (IL)",
    ".awl":     "Instruction List / Siemens AWL",
    ".stl":     "Instruction List / Siemens STL",
    ".fbd":     "Function Block Diagram (FBD)",
    ".sfc":     "Sequential Function Chart (SFC)",
    ".pro":     "CODESYS Project",
    ".project": "CODESYS Project",
    ".gvl":     "CODESYS Global Variable List",
    ".pou":     "CODESYS Program Organization Unit",
    ".tsp":     "CODESYS Task Configuration",
    ".library": "CODESYS Library",
    ".db":      "Siemens Data Block",
    ".fb":      "Siemens Function Block",
    ".fc":      "Siemens Function",
    ".ob":      "Siemens Organization Block",
    ".l5x":     "Rockwell Studio 5000 (XML/L5X)",
    ".acd":     "Rockwell Studio 5000 Project",
    ".rss":     "Rockwell RSLogix 500",
    ".ap1":     "ABB Automation Builder Project",
    ".ap15":    "ABB Automation Builder Project",
    ".xml":     "XML-based PLC project",
    ".json":    "JSON-based PLC config",
    ".txt":     "Unknown PLC (check content)",
    ".bin":     "Binary PLC firmware/program",
    ".hex":     "Intel HEX PLC firmware",
    ".s19":     "Motorola SREC PLC firmware",
}

_BINARY_EXTS = {".bin", ".hex", ".s19", ".acd", ".rss"}

# ── Sanitization patterns ─────────────────────────────────────────────────────

# IPv4 addresses (preserve private range structure but not exact values)
_RE_PUBLIC_IP = re.compile(
    r'\b(?:(?!(?:10|127|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.)(?:\d{1,3}\.){3}\d{1,3})\b'
)
# Passwords, secrets, API keys
_RE_CREDENTIAL = re.compile(
    r'(?:password|passwd|pwd|secret|api[_\-]?key|token|auth|credential|pin)\s*'
    r'(?::=|=|:)\s*["\']([^"\']{3,})["\']',
    re.I
)
# Connection strings with creds
_RE_CONN_STRING = re.compile(
    r'(?:jdbc:|mongodb:|postgresql:|mysql:|Server=)[^\s;\"\']{10,}',
    re.I
)
# Hardcoded passwords in code (not just string assignments)
_RE_PASS_INLINE = re.compile(
    r'(?:password|passwd|pwd|secret)\s*:=\s*["\']([^"\']{3,})["\']',
    re.I
)
# Domain names and hostnames
_RE_HOSTNAME = re.compile(
    r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|local|internal|corp|lan|gov|mil|edu)\b',
    re.I
)
# Long hex strings (binary data, keys)
_RE_HEX_BLOB = re.compile(r'\b[0-9a-fA-F]{32,}\b')
# Base64-like blobs
_RE_B64_BLOB = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')

# ── Security extraction patterns ──────────────────────────────────────────────

_RE_FUNCTION       = re.compile(r'^\s*FUNCTION\s+(\w+)\s*:', re.M | re.I)
_RE_FUNCTION_BLOCK = re.compile(r'^\s*FUNCTION_BLOCK\s+(\w+)', re.M | re.I)
_RE_PROGRAM        = re.compile(r'^\s*PROGRAM\s+(\w+)', re.M | re.I)

_RE_VAR = re.compile(
    r'(\w+)\s*:\s*(BOOL|INT|UINT|DINT|UDINT|REAL|LREAL|TIME|STRING|BYTE|WORD|DWORD|LWORD|ARRAY|STRUCT)'
    r'\s*(?::=\s*([^;]+))?;',
    re.I
)
# Setpoints: safety-relevant numeric assignments
_RE_SETPOINT = re.compile(
    r'(\w*(?:SET|LIMIT|THRESHOLD|MAX|MIN|SP|PV|SV|HIGH|LOW|ALARM|TRIP|SHUTDOWN|SETPOINT|DEADBAND)\w*)'
    r'\s*:=\s*([0-9.E+\-]+)',
    re.I
)
# Timer presets
_RE_TON_PRESET = re.compile(r'(\w+)\s*\(\s*IN\s*:=.*?PT\s*:=\s*(T#\w+)', re.I)

# Safety-critical patterns
_RE_SAFETY = re.compile(
    r'(?:STO|SOS|SLS|SBC|SLA|SS1|SS2|SCA|Emergency|EStop|Safety|SIL|SIS|SafeOp|SFB_Safety)\w*',
    re.I
)
# Watchdog patterns
_RE_WATCHDOG = re.compile(r'(?:Watchdog|WD_|Heartbeat|KeepAlive|WDT)\w*', re.I)
# Authentication bypasses / direct auth checks
_RE_AUTH_CHECK = re.compile(
    r'(?:IF\s+NOT\s+Authenticated|bypass.*auth|auth.*skip|UserLevel\s*=\s*0|access\s*:=\s*TRUE)',
    re.I
)
# Input validation (or lack thereof)
_RE_NO_VALIDATION = re.compile(
    r'(?:\(\*\s*no\s*(?:validation|check|limit)|without\s*check|unchecked\s*input'
    r'|TODO.*validat|FIXME.*bound|HACK.*sanitiz)',
    re.I
)
# Network access patterns
_RE_MODBUS = re.compile(r'(?:Modbus|ModbusTCP|MB_MASTER|MB_CLIENT|MODBUS_READ|MODBUS_WRITE)\s*\(', re.I)
_RE_OPC    = re.compile(r'(?:OPC|UA_Connect|UA_Write|UA_Read|UA_Browse)\s*\(', re.I)
_RE_DNSP3  = re.compile(r'(?:DNP3|dnp3_|DNPSend|DNPReceive)', re.I)
_RE_HTTP   = re.compile(r'(?:HTTP_Request|HTTPS_Get|HTTP_POST|WebClient)\s*\(', re.I)
_RE_MQTT   = re.compile(r'(?:MQTT_Publish|MQTT_Subscribe|MqttConnect)\s*\(', re.I)
# Critical comments
_RE_CRITICAL_CMT = re.compile(
    r'(?://|/\*|\(\*)\s*'
    r'(?:TODO|FIXME|HACK|UNSAFE|DANGER|CRITICAL|WARNING|INSECURE|BACKDOOR|BYPASS|HARDCODED)'
    r'[^\n]*',
    re.I
)
# Race conditions
_RE_RACE = re.compile(
    r'(?:GLOBAL\s+VAR|VAR_GLOBAL).*?(?:shared|concurrent|async)',
    re.I | re.S
)
# Hardcoded credential detection
_RE_HARDCODED_PASS = re.compile(
    r'(?:password|passwd|pwd|secret|key)\s*:?=\s*[\'"]([^\'"]{3,})[\'"]',
    re.I
)
# Private IP range (preserved for context, not redacted)
_RE_PRIVATE_IP = re.compile(
    r'\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}\b'
)
# Nesting depth estimator
_RE_NESTING = re.compile(r'\b(?:IF|FOR|WHILE|CASE|REPEAT)\b', re.I)


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
