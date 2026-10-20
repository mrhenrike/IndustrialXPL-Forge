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

        # Sanitized source - proportional allocation per file
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
