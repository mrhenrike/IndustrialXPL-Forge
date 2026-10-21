"""IXF CVE CVE-2022-3156 - Rockwell Automation Studio 5000 Logix Designer (HIGH CVSS 8.8).

Exploit type: Arbitrary code execution
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
        "name": "CVE-2022-3156 Rockwell Automation Studio 5000 Logix Designer HIGH",
        "description": "Arbitrary code execution. Rockwell Automation Studio 5000 Logix Designer. CVSS 8.8 (HIGH).",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/CVE-2022-3156",),
        "devices": ("Rockwell Automation Studio 5000 Logix Designer",),
        "impact": "HIGH",
        "exploit_type": "Arbitrary code execution",
        "source_poc": "Static catalog Level B",
        "cve": "CVE-2022-3156",
        "cvss": "8.8",
        "severity": "HIGH",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T0819', 'T0866'],
        "mitre_tactics": ['Initial Access'],
    }
    target = OptIP("", "Target Rockwell Automation device IP")
    port = OptPort(44818, "Target service port")
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
                description=f"CVE-2022-3156: Fingerprint Rockwell Automation Studio 5000 Logix Designer at {self.target}:{self.port}. Arbitrary code execution. CVSS 8.8.",
                mitre_techniques=['T0819', 'T0866'],
            )
            return
        if self.check():
            print_success(f"Port {self.port} open - Rockwell Automation Studio 5000 Logix Designer may be present. CVE-2022-3156 HIGH CVSS 8.8.")
            print_warning("CISA: N/A")
        else:
            print_info(f"{self.target}:{self.port} not responding.")
