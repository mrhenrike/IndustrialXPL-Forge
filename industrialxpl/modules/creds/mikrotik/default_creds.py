"""Default credentials — mikrotik (issue #5)."""
from industrialxpl.core.exploit import OptPort
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        "name": "Mikrotik RouterOS Default Credentials",
        "description": "Tests common default HTTP credentials against Mikrotik RouterOS.",
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (),
        "devices": ("Mikrotik RouterOS",),
        "impact": "MEDIUM",
        "exploit_type": "Default Credentials",
        "cve": "N/A",
        "cvss": "N/A",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1694.001", "T0859", "T0883"],
        "mitre_tactics": ["Initial Access"],
    }

    port = OptPort(80, "HTTP(S) port")
