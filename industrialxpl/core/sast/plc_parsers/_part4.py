def detect_language(file_path: str) -> str:
    """Detect PLC language from extension or content signature."""
    ext = Path(file_path).suffix.lower()
    if ext in EXTENSION_MAP:
        return EXTENSION_MAP[ext]
    try:
        with open(file_path, errors="ignore") as f:
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


