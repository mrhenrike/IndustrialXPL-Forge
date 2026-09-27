"""TRITON/TRISIS native payload manifest."""

PAYLOAD_META = {
    "name":        "TRITON/TRISIS TriStation Protocol Native Payload",
    "language":    "python",
    "entry_point": "run",
    "impact":      "CATASTROPHIC",
    "description": (
        "Full TriStation protocol implementation targeting Schneider Electric "
        "Triconex Safety Instrumented System (SIS) controllers. "
        "Implements the complete TRITON attack chain: "
        "READ_PROGRAM_INFO -> READ_PROGRAM_SIS -> WRITE_PROGRAM_SIS (inject logic) -> HALT_SIS. "
        "Exploits CVE-2019-6829 (hardcoded engineering key). "
        "WARNING: Execution against a live SIS WILL disable safety functions. "
        "This caused the Tasnee facility incident in 2017 (Saudi Arabia). "
        "AUTHORIZED ISOLATED LAB ENVIRONMENTS ONLY."
    ),
    "mitre": [
        "T0816",  # Device Restart/Shutdown
        "T0880",  # Loss of Safety
        "T0837",  # Loss of Control
        "T0838",  # Modify Alarm Settings
    ],
    "cve": "CVE-2019-6829",
    "cvss": "9.8",
    "references": [
        "https://www.dragos.com/threat/trisis/",
        "https://www.mandiant.com/resources/reports/triton-ics-safety-system-attack",
        "https://nvd.nist.gov/vuln/detail/CVE-2019-6829",
    ],
    "requires_auth": True,
    "requires_destructive": True,
    "requires_repo_clone": True,
}
