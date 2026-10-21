"""IXF CVE CVE-2022-31217 - Phoenix Contact AUTOMATIONWORX (CRITICAL CVSS 9.8).

Exploit type: Path traversal RCE
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
        "name": "CVE-2022-31217 Phoenix Contact AUTOMATIONWORX CRITICAL",
        "description": "Path traversal RCE. Phoenix Contact AUTOMATIONWORX. CVSS 9.8 (CRITICAL).",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/CVE-2022-31217",),
        "devices": ("Phoenix Contact AUTOMATIONWORX",),
        "impact": "CRITICAL",
        "exploit_type": "Path traversal RCE",
        "source_poc": "Static catalog Level B",
        "cve": "CVE-2022-31217",
        "cvss": "9.8",
        "severity": "CRITICAL",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T0819', 'T0866'],
        "mitre_tactics": ['Initial Access'],
    }
    target = OptIP("", "Target Phoenix Contact device IP")
    port = OptPort(80, "Target service port")
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
        except (ConnectionError, TimeoutError, OSError):
            return False

    def run(self):
        if not self.target:
            print_error("Set target first.")
            return
        if self.simulate:
            DestructiveGate.print_simulation(
                description=f"CVE-2022-31217: Fingerprint Phoenix Contact AUTOMATIONWORX at {self.target}:{self.port}. Path traversal RCE. CVSS 9.8.",
                mitre_techniques=['T0819', 'T0866'],
            )
            return
        if self.check():
            print_success(f"Port {self.port} open - Phoenix Contact AUTOMATIONWORX may be present. CVE-2022-31217 CRITICAL CVSS 9.8.")
            print_warning("CISA: N/A")
        else:
            print_info(f"{self.target}:{self.port} not responding.")
