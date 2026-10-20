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

    # Hardcoded values - use RAW content (never sent to LLM, used for reporting)
    for m in _RE_HARDCODED_PASS.finditer(raw):
        pf.hardcoded_values.append({
            "type":    "hardcoded_credential",
            "context": "[content redacted - hardcoded credential detected]",
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

