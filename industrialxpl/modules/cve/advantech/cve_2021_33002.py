"""IXF CVE CVE-2021-33002 - Advantech WebAccess Node runtime (CRITICAL CVSS 9.8).

Exploit type: Path traversal arbitrary file creation
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
        "name": "CVE-2021-33002 Advantech WebAccess Node runtime CRITICAL",
        "description": "Path traversal arbitrary file creation. Advantech WebAccess Node runtime. CVSS 9.8 (CRITICAL).",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/CVE-2021-33002",),
        "devices": ("Advantech WebAccess Node runtime",),
        "impact": "CRITICAL",
        "exploit_type": "Path traversal arbitrary file creation",
        "source_poc": "Static catalog Level B",
        "cve": "CVE-2021-33002",
        "cvss": "9.8",
        "severity": "CRITICAL",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T0819'],
        "mitre_tactics": ['Initial Access'],
    }
    target = OptIP("", "Target Advantech device IP")
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
        except Exception:
            return False

    def run(self):
        if not self.target:
            print_error("Set target first.")
            return
        if self.simulate:
            DestructiveGate.print_simulation(
                description=f"CVE-2021-33002: Fingerprint Advantech WebAccess Node runtime at {self.target}:{self.port}. Path traversal arbitrary file creation. CVSS 9.8.",
                mitre_techniques=['T0819'],
            )
            return
        if self.check():
            print_success(f"Port {self.port} open - Advantech WebAccess Node runtime may be present. CVE-2021-33002 CRITICAL CVSS 9.8.")
            print_warning("CISA: N/A")
        else:
            print_info(f"{self.target}:{self.port} not responding.")
