"""IXF PLC/RTU Source Code Parser.

Supports the 5 IEC 61131-3 languages plus vendor-specific formats:
  ST  — Structured Text (.st, .iecst, .scl)
  LD  — Ladder Diagram (.lad, .ld)
  FBD — Function Block Diagram (.fbd)
  IL  — Instruction List (.il, .awl, .stl)
  SFC — Sequential Function Chart (.sfc)
  +  Siemens SCL/STL/AWL, CODESYS .project, ABB .ap1, etc.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


# ── File extension → language mapping ─────────────────────────────────────────

EXTENSION_MAP: dict[str, str] = {
    # Structured Text
    ".st":    "Structured Text (ST)",
    ".iecst": "Structured Text (ST)",
    ".scl":   "Structured Text / Siemens SCL",
    ".txt":   "Unknown PLC (check content)",
    # Ladder Diagram
    ".lad":   "Ladder Diagram (LD)",
    ".ld":    "Ladder Diagram (LD)",
    ".ldr":   "Ladder Diagram (LD)",
    # Instruction List
    ".il":    "Instruction List (IL)",
    ".awl":   "Instruction List / Siemens AWL",
    ".stl":   "Instruction List / Siemens STL",
    # Function Block Diagram
    ".fbd":   "Function Block Diagram (FBD)",
    # Sequential Function Chart
    ".sfc":   "Sequential Function Chart (SFC)",
    # CODESYS / 3S
    ".pro":   "CODESYS Project",
    ".project": "CODESYS Project",
    ".gvl":   "CODESYS Global Variable List",
    ".pou":   "CODESYS Program Organization Unit",
    ".tsp":   "CODESYS Task Configuration",
    ".library": "CODESYS Library",
    # Siemens TIA Portal / STEP 7
    ".db":    "Siemens Data Block",
    ".fb":    "Siemens Function Block",
    ".fc":    "Siemens Function",
    ".ob":    "Siemens Organization Block",
    # Rockwell / Studio 5000
    ".l5x":   "Rockwell Studio 5000 (XML/L5X)",
    ".acd":   "Rockwell Studio 5000 Project",
    ".rss":   "Rockwell RSLogix 500",
    # ABB
    ".ap1":   "ABB Automation Builder Project",
    ".ap15":  "ABB Automation Builder Project",
    # Generic XML/JSON PLC formats
    ".xml":   "XML-based PLC project",
    ".json":  "JSON-based PLC config",
    # Binary / compiled
    ".bin":   "Binary PLC firmware/program",
    ".hex":   "Intel HEX PLC firmware",
    ".s19":   "Motorola SREC PLC firmware",
}


@dataclass
class ParsedPLCFile:
    """Parsed representation of a PLC source file."""
    path: str
    language: str
    raw_content: str
    size_bytes: int

    # Extracted structural elements
    functions:       list[str] = field(default_factory=list)
    function_blocks: list[str] = field(default_factory=list)
    programs:        list[str] = field(default_factory=list)
    variables:       list[dict] = field(default_factory=list)   # {name, type, value}
    setpoints:       list[dict] = field(default_factory=list)   # {name, value, context}
    timers:          list[dict] = field(default_factory=list)   # {name, preset}
    safety_functions:list[str] = field(default_factory=list)
    network_access:  list[str] = field(default_factory=list)    # Modbus/OPC calls
    hardcoded_values:list[dict] = field(default_factory=list)   # potentially hardcoded creds/keys
    critical_comments:list[str] = field(default_factory=list)   # TODO/FIXME/HACK/UNSAFE

    # Complexity metrics
    line_count:      int = 0
    nesting_depth:   int = 0
    cyclomatic:      int = 1


@dataclass
class PLCProject:
    """Collection of parsed PLC files forming a project."""
    root_path: str
    files: list[ParsedPLCFile] = field(default_factory=list)
    total_lines: int = 0
    languages_found: set = field(default_factory=set)
    binary_files: list[str] = field(default_factory=list)


# ── Regex patterns for ST/SCL/AWL parsing ──────────────────────────────────────

_RE_FUNCTION      = re.compile(r'^\s*FUNCTION\s+(\w+)\s*:', re.M | re.I)
_RE_FUNCTION_BLOCK= re.compile(r'^\s*FUNCTION_BLOCK\s+(\w+)', re.M | re.I)
_RE_PROGRAM       = re.compile(r'^\s*PROGRAM\s+(\w+)', re.M | re.I)
_RE_VAR           = re.compile(
    r'(\w+)\s*:\s*(BOOL|INT|UINT|DINT|UDINT|REAL|LREAL|TIME|STRING|BYTE|WORD|DWORD|LWORD|ARRAY|STRUCT)\s*(?::=\s*([^;]+))?;',
    re.I
)
_RE_SETPOINT      = re.compile(
    r'(\w*(?:SET|LIMIT|THRESHOLD|MAX|MIN|SP|PV|SV|HIGH|LOW|ALARM|TRIP)\w*)\s*:=\s*([0-9.E+\-]+)',
    re.I
)
_RE_TIMER         = re.compile(r'(\w+)\s*:\s*TON|TOF|TP\s*;', re.I)
_RE_TON_PRESET    = re.compile(r'(\w+)\s*\(\s*IN\s*:=.*?PT\s*:=\s*(T#\w+)', re.I)
_RE_MODBUS        = re.compile(r'(?:Modbus|ModbusTCP|MB_MASTER|MB_CLIENT)\s*\(', re.I)
_RE_OPC           = re.compile(r'(?:OPC|UA_Connect|UA_Write|UA_Read)', re.I)
_RE_HARDCODED_IP  = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_HARDCODED_PASS= re.compile(r'(?:password|passwd|pwd|secret|key)\s*:?=\s*[\'"]([^\'"]{3,})[\'"]', re.I)
_RE_SAFETY        = re.compile(r'(?:STO|SOS|SLS|SBC|SLA|SS1|SS2|SCA|Emergency|EStop|Safety)\w*', re.I)
_RE_CRITICAL_CMT  = re.compile(r'(?://|/\*|\(\*)\s*(?:TODO|FIXME|HACK|UNSAFE|DANGER|CRITICAL|WARNING)[^\n]*', re.I)
_RE_NESTING       = re.compile(r'\b(?:IF|FOR|WHILE|CASE|REPEAT)\b', re.I)


def detect_language(file_path: str) -> str:
    """Detect PLC language from file extension or content."""
    ext = Path(file_path).suffix.lower()
    if ext in EXTENSION_MAP:
        return EXTENSION_MAP[ext]
    # Try content-based detection
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
    """Parse a single PLC source file and extract structural elements."""
    path = Path(file_path)
    language = detect_language(file_path)
    size = path.stat().st_size

    # Read content (text mode, skip binary files)
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        raw = ""

    pf = ParsedPLCFile(
        path=str(path),
        language=language,
        raw_content=raw,
        size_bytes=size,
        line_count=raw.count("\n") + 1,
    )

    if not raw:
        return pf

    # Extract structural elements
    pf.functions       = [m.group(1) for m in _RE_FUNCTION.finditer(raw)]
    pf.function_blocks = [m.group(1) for m in _RE_FUNCTION_BLOCK.finditer(raw)]
    pf.programs        = [m.group(1) for m in _RE_PROGRAM.finditer(raw)]

    for m in _RE_VAR.finditer(raw):
        pf.variables.append({
            "name":  m.group(1),
            "type":  m.group(2),
            "value": (m.group(3) or "").strip(),
        })

    for m in _RE_SETPOINT.finditer(raw):
        pf.setpoints.append({
            "name":    m.group(1),
            "value":   m.group(2),
            "context": raw[max(0,m.start()-60):m.end()+60].replace("\n", " "),
        })

    for m in _RE_TON_PRESET.finditer(raw):
        pf.timers.append({"name": m.group(1), "preset": m.group(2)})

    pf.safety_functions = list(set(m.group(0) for m in _RE_SAFETY.finditer(raw)))
    pf.network_access   = (
        ["Modbus client call detected"] if _RE_MODBUS.search(raw) else []
    ) + (
        ["OPC UA call detected"] if _RE_OPC.search(raw) else []
    )

    for m in _RE_HARDCODED_PASS.finditer(raw):
        pf.hardcoded_values.append({
            "type":    "hardcoded_credential",
            "context": raw[max(0,m.start()-40):m.end()+40].replace("\n"," "),
        })
    for ip in _RE_HARDCODED_IP.findall(raw):
        if not ip.startswith(("192.168.", "10.", "172.", "127.", "0.0.0.", "255.")):
            pf.hardcoded_values.append({"type": "external_ip", "value": ip})

    pf.critical_comments = [m.group(0) for m in _RE_CRITICAL_CMT.finditer(raw)]
    pf.nesting_depth = max(
        (len([m for m in _RE_NESTING.finditer(line)]) for line in raw.splitlines()),
        default=0,
    )
    pf.cyclomatic = max(1, len(_RE_NESTING.findall(raw)) + 1)

    return pf


def walk_project(root_path: str, max_files: int = 500) -> PLCProject:
    """Walk a directory tree and parse all PLC source files."""
    project = PLCProject(root_path=root_path)
    root = Path(root_path)

    supported_exts = set(EXTENSION_MAP.keys())
    binary_exts    = {".bin", ".hex", ".s19", ".acd", ".rss"}

    count = 0
    for path in sorted(root.rglob("*")):
        if count >= max_files:
            break
        if not path.is_file():
            continue
        ext = path.suffix.lower()
        if ext in binary_exts:
            project.binary_files.append(str(path))
            continue
        if ext not in supported_exts and ext not in (".xml", ".json", ".txt"):
            continue

        pf = parse_file(str(path))
        project.files.append(pf)
        project.total_lines  += pf.line_count
        project.languages_found.add(pf.language)
        count += 1

    return project


def summarize_project(project: PLCProject) -> str:
    """Return a human-readable summary of the parsed project for LLM context."""
    lines = [
        "PLC Project Summary:",
        f"  Root: {project.root_path}",
        f"  Files parsed: {len(project.files)}",
        f"  Total lines: {project.total_lines}",
        f"  Languages: {', '.join(sorted(project.languages_found))}",
        f"  Binary files (need reverse engineering): {len(project.binary_files)}",
        "",
    ]
    for pf in project.files[:50]:  # Limit to 50 files in summary
        lines.append(f"  [{pf.language}] {Path(pf.path).name}")
        if pf.functions:       lines.append(f"    Functions: {', '.join(pf.functions[:5])}")
        if pf.function_blocks: lines.append(f"    FBs: {', '.join(pf.function_blocks[:5])}")
        if pf.programs:        lines.append(f"    Programs: {', '.join(pf.programs[:5])}")
        if pf.setpoints:
            lines.append(f"    Setpoints ({len(pf.setpoints)}):")
            for sp in pf.setpoints[:5]:
                lines.append(f"      {sp['name']} = {sp['value']}")
        if pf.safety_functions: lines.append(f"    Safety: {', '.join(pf.safety_functions[:5])}")
        if pf.hardcoded_values: lines.append(f"    ⚠ Hardcoded values: {len(pf.hardcoded_values)}")
        if pf.critical_comments: lines.append(f"    ⚠ Critical comments: {len(pf.critical_comments)}")
        if pf.network_access:  lines.append(f"    Network calls: {', '.join(pf.network_access)}")
    return "\n".join(lines)
