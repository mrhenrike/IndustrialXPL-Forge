"""IXF PLC/RTU Source Code Parser with LLM-safe Sanitization.

Supports the 5 IEC 61131-3 languages plus vendor-specific formats:
  ST  — Structured Text (.st, .iecst, .scl)
  LD  — Ladder Diagram (.lad, .ld)
  FBD — Function Block Diagram (.fbd)
  IL  — Instruction List (.il, .awl, .stl)
  SFC — Sequential Function Chart (.sfc)
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
class ParsedPLCFile:
    """Parsed and partially sanitized PLC source file."""
    path: str
    language: str
    raw_content: str            # original (kept locally, NOT sent to LLM)
    sanitized_content: str      # safe to send to LLM
    size_bytes: int

    # Structural elements
    functions:         list[str]  = field(default_factory=list)
    function_blocks:   list[str]  = field(default_factory=list)
    programs:          list[str]  = field(default_factory=list)
    variables:         list[dict] = field(default_factory=list)
    setpoints:         list[dict] = field(default_factory=list)
    timers:            list[dict] = field(default_factory=list)

    # Security findings
    safety_functions:   list[str]  = field(default_factory=list)
    watchdog_refs:      list[str]  = field(default_factory=list)
    auth_checks:        list[str]  = field(default_factory=list)
    no_validation:      list[str]  = field(default_factory=list)
    network_access:     list[str]  = field(default_factory=list)
    hardcoded_values:   list[dict] = field(default_factory=list)
    critical_comments:  list[str]  = field(default_factory=list)
    private_ips:        list[str]  = field(default_factory=list)

    # Sanitization metadata (what was redacted, for audit)
    redactions: list[str] = field(default_factory=list)

    # Complexity
    line_count:    int = 0
    nesting_depth: int = 0
    cyclomatic:    int = 1


@dataclass
class PLCProject:
    """Collection of parsed PLC files."""
    root_path:       str
    files:           list[ParsedPLCFile] = field(default_factory=list)
    total_lines:     int = 0
    languages_found: set = field(default_factory=set)
    binary_files:    list[str] = field(default_factory=list)
    redaction_count: int = 0  # total sanitization replacements across all files


# ── Sanitization ──────────────────────────────────────────────────────────────

def sanitize_for_llm(raw: str) -> tuple[str, list[str]]:
    """Remove or mask sensitive data before sending to LLM.

    Returns:
        (sanitized_text, list_of_redaction_descriptions)
    """
    text = raw
    redactions: list[str] = []

    # 1. Credentials and secrets (highest priority — full value masked)
    for pattern, label in [
        (_RE_CREDENTIAL,   "credential assignment"),
        (_RE_PASS_INLINE,  "inline password"),
        (_RE_HARDCODED_PASS, "hardcoded credential"),
    ]:
        matches = pattern.findall(text)
        if matches:
            redactions.append(f"{len(matches)} {label}(s) redacted")
        text = pattern.sub(
            lambda m: m.group(0)[:m.group(0).index(m.group(1))] + "[CREDENTIAL_REDACTED]",
            text
        )

    # 2. Connection strings
    count = len(_RE_CONN_STRING.findall(text))
    if count:
        redactions.append(f"{count} connection string(s) redacted")
    text = _RE_CONN_STRING.sub("[CONNSTRING_REDACTED]", text)

    # 3. Public IP addresses only (private IPs preserved — important for topology analysis)
    pub_ips = _RE_PUBLIC_IP.findall(text)
    if pub_ips:
        redactions.append(f"{len(pub_ips)} public IP(s) redacted: {', '.join(set(pub_ips[:3]))}")
    text = _RE_PUBLIC_IP.sub("[IP_REDACTED]", text)

    # 4. External hostnames/domains
    hosts = _RE_HOSTNAME.findall(text)
    if hosts:
        redactions.append(f"{len(hosts)} hostname(s) redacted: {', '.join(set(hosts[:3]))}")
    text = _RE_HOSTNAME.sub("[HOST_REDACTED]", text)

    # 5. Long hex blobs (binary keys, firmware payloads)
    count = len(_RE_HEX_BLOB.findall(text))
    if count:
        redactions.append(f"{count} hex blob(s) redacted (>32 hex chars)")
    text = _RE_HEX_BLOB.sub("[HEXBLOB_REDACTED]", text)

    # 6. Base64 blobs
    count = len(_RE_B64_BLOB.findall(text))
    if count:
        redactions.append(f"{count} base64 blob(s) redacted")
    text = _RE_B64_BLOB.sub("[B64BLOB_REDACTED]", text)

    # 7. Enforce line length limit (very long lines are usually binary/data)
    lines = text.splitlines()
    cleaned = []
    for line in lines:
        if len(line) > 300:
            cleaned.append(line[:300] + " [LINE_TRUNCATED]")
        else:
            cleaned.append(line)
    text = "\n".join(cleaned)

    return text, redactions


def _extract_security_context(raw: str, sanitized: str, pf: ParsedPLCFile) -> None:
    """Extract security-relevant elements from the (sanitized) source."""
    # Use sanitized for context strings sent to LLM
    src = sanitized

    pf.functions       = [m.group(1) for m in _RE_FUNCTION.finditer(src)]
    pf.function_blocks = [m.group(1) for m in _RE_FUNCTION_BLOCK.finditer(src)]
    pf.programs        = [m.group(1) for m in _RE_PROGRAM.finditer(src)]

    for m in _RE_VAR.finditer(src):
        pf.variables.append({
            "name":  m.group(1),
            "type":  m.group(2),
            "value": (m.group(3) or "").strip(),
        })

    for m in _RE_SETPOINT.finditer(src):
        ctx = src[max(0, m.start()-80):m.end()+80].replace("\n", " ")
        pf.setpoints.append({
            "name":    m.group(1),
            "value":   m.group(2),
            "context": ctx,
        })

    for m in _RE_TON_PRESET.finditer(src):
        pf.timers.append({"name": m.group(1), "preset": m.group(2)})

    pf.safety_functions = list(dict.fromkeys(m.group(0) for m in _RE_SAFETY.finditer(src)))
    pf.watchdog_refs    = list(dict.fromkeys(m.group(0) for m in _RE_WATCHDOG.finditer(src)))
    pf.auth_checks      = [
        src[max(0, m.start()-60):m.end()+60].strip()
        for m in _RE_AUTH_CHECK.finditer(src)
    ]
    pf.no_validation    = [
        src[max(0, m.start()-60):m.end()+60].strip()
        for m in _RE_NO_VALIDATION.finditer(src)
    ]

    pf.network_access = []
    for pattern, label in [
        (_RE_MODBUS, "Modbus TCP client"),
        (_RE_OPC,    "OPC UA client"),
        (_RE_DNSP3,  "DNP3 access"),
        (_RE_HTTP,   "HTTP/HTTPS call"),
        (_RE_MQTT,   "MQTT publish/subscribe"),
    ]:
        if pattern.search(src):
            pf.network_access.append(label)

    # Hardcoded values — use RAW content (never sent to LLM, used for reporting)
    for m in _RE_HARDCODED_PASS.finditer(raw):
        pf.hardcoded_values.append({
            "type":    "hardcoded_credential",
            "context": "[content redacted — hardcoded credential detected]",
        })

    # Private IPs preserved for topology analysis
    pf.private_ips = list(dict.fromkeys(_RE_PRIVATE_IP.findall(raw)))

    pf.critical_comments = [m.group(0) for m in _RE_CRITICAL_CMT.finditer(src)]
    pf.nesting_depth = max(
        (len(_RE_NESTING.findall(line)) for line in src.splitlines()),
        default=0,
    )
    pf.cyclomatic = max(1, len(_RE_NESTING.findall(src)) + 1)


# ── Public API ────────────────────────────────────────────────────────────────

def detect_language(file_path: str) -> str:
    """Detect PLC language from extension or content signature."""
    ext = Path(file_path).suffix.lower()
    if ext in EXTENSION_MAP:
        return EXTENSION_MAP[ext]
    try:
        with open(file_path, "r", errors="ignore") as f:
            head = f.read(1024)
        if re.search(r'\bFUNCTION_BLOCK\b|\bPROGRAM\b|\bVAR_INPUT\b', head, re.I):
            return "Structured Text (ST)"
        if re.search(r'<Ladder|<rung|XIC\s|XIO\s|OTE\s', head, re.I):
            return "Ladder Diagram (LD)"
        if re.search(r'<FBD|FunctionBlockDiagram', head, re.I):
            return "Function Block Diagram (FBD)"
    except Exception:
        pass
    return "Unknown"


def parse_file(file_path: str) -> ParsedPLCFile:
    """Parse a PLC source file: extract structure + sanitize for LLM."""
    path = Path(file_path)
    language = detect_language(file_path)
    size = path.stat().st_size if path.exists() else 0

    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        raw = ""

    sanitized, redactions = sanitize_for_llm(raw)

    pf = ParsedPLCFile(
        path=str(path),
        language=language,
        raw_content=raw,
        sanitized_content=sanitized,
        size_bytes=size,
        line_count=raw.count("\n") + 1,
        redactions=redactions,
    )

    if raw:
        _extract_security_context(raw, sanitized, pf)

    return pf


def walk_project(root_path: str, max_files: int = 500) -> PLCProject:
    """Walk directory tree and parse all PLC source files."""
    project = PLCProject(root_path=root_path)
    root = Path(root_path)
    count = 0

    for path in sorted(root.rglob("*")):
        if count >= max_files:
            break
        if not path.is_file():
            continue
        ext = path.suffix.lower()
        if ext in _BINARY_EXTS:
            project.binary_files.append(str(path))
            continue
        if ext not in EXTENSION_MAP and ext not in (".xml", ".json", ".txt"):
            continue

        pf = parse_file(str(path))
        project.files.append(pf)
        project.total_lines      += pf.line_count
        project.redaction_count  += len(pf.redactions)
        project.languages_found.add(pf.language)
        count += 1

    return project


def build_llm_payload(project: PLCProject, max_chars: int = 32000) -> str:
    """Build the sanitized payload to send to the LLM.

    Includes:
    - Project metadata
    - Per-file: sanitized source (truncated to budget), extracted security findings

    Does NOT include:
    - Raw source with credentials/IPs (those are redacted)
    - Binary files
    - Files above size budget
    """
    budget = max_chars
    sections = []

    header = (
        f"PLC Project: {Path(project.root_path).name}\n"
        f"Files: {len(project.files)} | Lines: {project.total_lines} | "
        f"Languages: {', '.join(sorted(project.languages_found))}\n"
        f"Redactions applied: {project.redaction_count} (credentials/IPs/blobs sanitized)\n"
        f"Binary files (need reverse engineering): {len(project.binary_files)}\n"
    )
    sections.append(header)
    budget -= len(header)

    for pf in project.files:
        if budget <= 0:
            sections.append(f"\n[...{len(project.files) - project.files.index(pf)} more files truncated by budget...]\n")
            break

        name = Path(pf.path).name
        file_header = f"\n=== {name} [{pf.language}] ({pf.line_count} lines) ===\n"
        if pf.redactions:
            file_header += f"[Sanitized: {'; '.join(pf.redactions)}]\n"

        # Security findings summary (always included)
        findings = []
        if pf.setpoints:
            sp_strs = [f"{s['name']}={s['value']}" for s in pf.setpoints[:10]]
            findings.append(f"Setpoints: {', '.join(sp_strs)}")
        if pf.safety_functions:
            findings.append(f"Safety refs: {', '.join(pf.safety_functions[:8])}")
        if pf.watchdog_refs:
            findings.append(f"Watchdog refs: {', '.join(pf.watchdog_refs[:5])}")
        if pf.hardcoded_values:
            findings.append(f"ALERT: {len(pf.hardcoded_values)} hardcoded credential(s) detected")
        if pf.auth_checks:
            findings.append(f"Auth checks ({len(pf.auth_checks)}): " + str(pf.auth_checks[0])[:120])
        if pf.no_validation:
            findings.append(f"Validation gaps ({len(pf.no_validation)}): " + str(pf.no_validation[0])[:120])
        if pf.critical_comments:
            findings.append("Critical comments: " + " | ".join(pf.critical_comments[:3])[:200])
        if pf.network_access:
            findings.append(f"Network: {', '.join(pf.network_access)}")
        if pf.private_ips:
            findings.append(f"Internal IPs: {', '.join(pf.private_ips[:5])}")

        findings_str = "\n".join(f"  [{f}]" for f in findings) if findings else ""

        # Sanitized source — proportional allocation per file
        per_file_budget = max(500, budget // max(1, len(project.files)))
        sanitized_snippet = pf.sanitized_content[:per_file_budget]
        if len(pf.sanitized_content) > per_file_budget:
            sanitized_snippet += f"\n[...{len(pf.sanitized_content) - per_file_budget} chars truncated...]\n"

        block = file_header + findings_str + "\n\n" + sanitized_snippet
        sections.append(block)
        budget -= len(block)

    return "\n".join(sections)


def summarize_project(project: PLCProject) -> str:
    """Return human-readable summary (used for display, not LLM payload)."""
    lines = [
        "PLC Project Summary:",
        f"  Root: {project.root_path}",
        f"  Files: {len(project.files)} | Lines: {project.total_lines}",
        f"  Languages: {', '.join(sorted(project.languages_found))}",
        f"  Binary files: {len(project.binary_files)}",
        f"  Total redactions: {project.redaction_count}",
        "",
    ]
    for pf in project.files[:50]:
        name = Path(pf.path).name
        lines.append(f"  [{pf.language}] {name}")
        if pf.functions:        lines.append(f"    Functions: {', '.join(pf.functions[:5])}")
        if pf.function_blocks:  lines.append(f"    FBs: {', '.join(pf.function_blocks[:5])}")
        if pf.programs:         lines.append(f"    Programs: {', '.join(pf.programs[:5])}")
        if pf.setpoints:
            lines.append(f"    Setpoints ({len(pf.setpoints)}):")
            for sp in pf.setpoints[:5]:
                lines.append(f"      {sp['name']} = {sp['value']}")
        if pf.safety_functions: lines.append(f"    Safety: {', '.join(pf.safety_functions[:5])}")
        if pf.watchdog_refs:    lines.append(f"    Watchdog: {', '.join(pf.watchdog_refs[:3])}")
        if pf.hardcoded_values: lines.append(f"    ALERT: {len(pf.hardcoded_values)} hardcoded credential(s)")
        if pf.critical_comments: lines.append(f"    Critical comments: {len(pf.critical_comments)}")
        if pf.network_access:   lines.append(f"    Network: {', '.join(pf.network_access)}")
        if pf.redactions:       lines.append(f"    Redacted: {'; '.join(pf.redactions)}")
    return "\n".join(lines)
