"""IXF CVE CVE-2023-34982 — OSIsoft AVEVA PI Web API CSRF (CRITICAL CVSS 9.0).

Exploit type: CSRF to RCE on PI Web API
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
        "name": "CVE-2023-34982 OSIsoft AVEVA PI Web API CSRF CRITICAL",
        "description": "CSRF to RCE on PI Web API. OSIsoft AVEVA PI Web API CSRF. CVSS 9.0 (CRITICAL).",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/CVE-2023-34982",),
        "devices": ("OSIsoft AVEVA PI Web API CSRF",),
        "impact": "CRITICAL",
        "exploit_type": "CSRF to RCE on PI Web API",
        "source_poc": "Static catalog Level B",
        "cve": "CVE-2023-34982",
        "cvss": "9.0",
        "severity": "CRITICAL",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T0819', 'T0866'],
        "mitre_tactics": ['Initial Access'],
    }
    target = OptIP("", "Target OSIsoft AVEVA device IP")
    port = OptPort(443, "Target service port")
    timeout = OptInteger(5, "Timeout seconds")
    simulate = OptBool(True, "Simulate mode (default: True)")
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
                description="CVE-2023-34982: Fingerprint OSIsoft AVEVA PI Web API CSRF at {}:{}. CSRF to RCE on PI Web API. CVSS 9.0.".format(self.target, self.port),
                mitre_techniques=['T0819', 'T0866'],
            )
            return
        if self.check():
            print_success("Port {} open — OSIsoft AVEVA PI Web API CSRF may be present. CVE-2023-34982 CRITICAL CVSS 9.0.".format(self.port))
            print_warning("CISA: N/A")
        else:
            print_info("{}:{} not responding.".format(self.target, self.port))
