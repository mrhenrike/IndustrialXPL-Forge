"""S7comm native payload manifest -- GitHub clone only."""

PAYLOAD_META = {
    "name":        "S7comm Native CPU Control (C implementation)",
    "language":    "c",
    "entry_point": "s7_stop",
    "impact":      "CATASTROPHIC",
    "description": (
        "C implementation of S7comm TPKT/COTP/S7comm framing for CPU Stop, "
        "DB write, and SZL read operations. More reliable timing than Python "
        "for multi-session and parallel connection attacks against S7-300/400. "
        "Compiles in-memory via gcc at runtime."
    ),
    "mitre":     ["T0855", "T0816", "T0843"],
    "cve":       "N/A (design vulnerability -- S7comm classic has no auth)",
    "cvss":      "10.0",
    "requires_destructive": True,
    "requires_repo_clone":  True,
}
