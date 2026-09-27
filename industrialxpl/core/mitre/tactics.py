"""MITRE ATT&CK for ICS v19 — tactics constants and aliases."""

TACTICS: dict[str, str] = {
    "TA0108": "Initial Access",
    "TA0104": "Execution",
    "TA0110": "Persistence",
    "TA0111": "Privilege Escalation",
    "TA0103": "Evasion",
    "TA0102": "Discovery",
    "TA0109": "Lateral Movement",
    "TA0100": "Collection",
    "TA0101": "Command and Control",
    "TA0107": "Inhibit Response Function",
    "TA0106": "Impair Process Control",
    "TA0105": "Impact",
}

TACTIC_ALIASES: dict[str, str] = {
    "initial-access":        "TA0108", "initial_access":       "TA0108",
    "initial access":        "TA0108",
    "execution":             "TA0104",
    "persistence":           "TA0110",
    "privilege-escalation":  "TA0111", "privilege_escalation": "TA0111",
    "privesc":               "TA0111",
    "evasion":               "TA0103", "defense-evasion":      "TA0103",
    "discovery":             "TA0102",
    "lateral-movement":      "TA0109", "lateral_movement":     "TA0109",
    "lateral":               "TA0109",
    "collection":            "TA0100",
    "command-and-control":   "TA0101", "command_and_control":  "TA0101",
    "c2":                    "TA0101", "c&c":                  "TA0101",
    "inhibit-response":      "TA0107", "inhibit_response":     "TA0107",
    "inhibit":               "TA0107",
    "impair-process":        "TA0106", "impair_process":       "TA0106",
    "impair":                "TA0106",
    "impact":                "TA0105",
}

# Technique IDs per tactic (MITRE ATT&CK for ICS v19)
TACTIC_TIDS: dict[str, list[str]] = {
    "TA0108": ["T0817", "T0819", "T0822", "T0883", "T0862", "T0847", "T0865", "T0864", "T0860"],
    "TA0104": ["T0807", "T0871", "T0823", "T0874", "T0834", "T0853", "T0863", "T0894", "T0895"],
    "TA0110": ["T0873", "T0873.001", "T1693", "T1693.001", "T1693.002", "T0889", "T0851", "T0859"],
    "TA0111": ["T0890", "T0874"],
    "TA0103": ["T0858", "T0820", "T0849", "T0872", "T0894"],
    "TA0102": [
        "T0802", "T0868", "T0840", "T0842", "T0861", "T0845",
        "T0846", "T0846.001", "T0846.002", "T0846.003",
        "T0888", "T0801", "T0887",
    ],
    "TA0109": ["T0867", "T0886", "T0847"],
    "TA0100": ["T0802", "T0811", "T0893", "T0877", "T0801", "T0861", "T0852", "T0882", "T0887"],
    "TA0101": ["T0885", "T0884", "T0869"],
    "TA0107": [
        "T0800", "T0878",
        "T1691", "T1691.001", "T1691.002",
        "T1695", "T1695.001", "T1695.002", "T1695.003",
        "T0813", "T0814", "T0815", "T0816", "T0835", "T0838", "T0881",
        "T1692", "T1692.001", "T1692.002",
    ],
    "TA0106": [
        "T0806", "T0836", "T0821", "T0831", "T0832",
        "T0843", "T0843.001", "T0843.002", "T0843.003",
        "T0848", "T1692",
    ],
    "TA0105": [
        "T0879", "T0813", "T0814", "T0815",
        "T0826", "T0827", "T0828", "T0837", "T0880",
        "T0829", "T0831", "T0882",
    ],
}
