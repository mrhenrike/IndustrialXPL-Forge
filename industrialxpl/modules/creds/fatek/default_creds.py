"""Default credentials — fatek (issue #5)."""
from industrialxpl.core.exploit import OptPort
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        "name": "Fatek PLC Default Credentials",
        "description": "Tests common default HTTP credentials against Fatek PLC.",
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (),
        "devices": ("Fatek PLC",),
        "impact": "MEDIUM",
        "exploit_type": "Default Credentials",
        "cve": "N/A",
        "cvss": "N/A",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1694.001", "T0859", "T0883"],
        "mitre_tactics": ["Initial Access"],
    }

    port = OptPort(80, "HTTP(S) port")
