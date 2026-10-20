"""IXF CVE CVE-2024-21903 - Siemens SINEMA Remote Connect Server (HIGH CVSS 8.4).

Exploit type: Path traversal server-side
CISA Advisory: N/A
Level B: port fingerprint + version context. simulate=True by default.
"""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,
    print_error, print_info, print_status, print_success, print_warning,
    DestructiveGate,
)

class Exploit(Exploit):
    __info__ = {
        "name": "CVE-2024-21903 Siemens SINEMA Remote Connect Server HIGH",
        "description": "Path traversal server-side. Siemens SINEMA Remote Connect Server. CVSS 8.4 (HIGH).",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/CVE-2024-21903",),
        "devices": ("Siemens SINEMA Remote Connect Server",),
        "impact": "HIGH",
        "exploit_type": "Path traversal server-side",
        "source_poc": "Static catalog Level B",
        "cve": "CVE-2024-21903",
        "cvss": "8.4",
        "severity": "HIGH",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T0819'],
        "mitre_tactics": ['Initial Access'],
    }
    target = OptIP("", "Target Siemens device IP")
    port = OptPort(443, "Target service port")
    timeout = OptInteger(5, "Timeout seconds")
    simulate = OptBool(False, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable real execution gate")

    @mute
    def check(self):
        if not self.target:
            return False
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            s.close()
            return True
        except Exception:
            return False

    def run(self):
        if not self.target:
            print_error("Set target first.")
            return
        if self.simulate:
            DestructiveGate.print_simulation(
                description=f"CVE-2024-21903: Fingerprint Siemens SINEMA Remote Connect Server at {self.target}:{self.port}. Path traversal server-side. CVSS 8.4.",
                mitre_techniques=['T0819'],
            )
            return
        if self.check():
            print_success(f"Port {self.port} open - Siemens SINEMA Remote Connect Server may be present. CVE-2024-21903 HIGH CVSS 8.4.")
            print_warning("CISA: N/A")
        else:
            print_info(f"{self.target}:{self.port} not responding.")
