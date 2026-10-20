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

    # 1. Credentials and secrets (highest priority - full value masked)
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

    # 3. Public IP addresses only (private IPs preserved - important for topology analysis)
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


