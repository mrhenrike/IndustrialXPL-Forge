"""Modbus native payload manifest -- GitHub clone only."""

PAYLOAD_META = {
    "name":        "Modbus Native Writer (C implementation)",
    "language":    "c",
    "entry_point": "modbus_write",
    "impact":      "CRITICAL",
    "description": (
        "C implementation of Modbus TCP write operations for performance-critical "
        "attacks. Provides FC16 bulk write with zero-delay framing, "
        "FC66 vendor-specific (Schneider/Rockwell extended), and "
        "rate-limited flood write. Compiles in-memory at runtime via gcc."
    ),
    "mitre":     ["T0831", "T0836"],
    "cve":       "N/A (Modbus design vulnerability)",
    "cvss":      "9.8",
    "requires_destructive": True,
    "requires_repo_clone":  True,
}
