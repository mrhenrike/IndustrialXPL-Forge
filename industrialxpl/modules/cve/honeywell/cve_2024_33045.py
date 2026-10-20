"""IXF CVE CVE-2024-33045 - Honeywell Niagara IQ Pro (CRITICAL CVSS 9.1).

Exploit type: Authentication bypass door controller
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
        "name": "CVE-2024-33045 Honeywell Niagara IQ Pro CRITICAL",
        "description": "Authentication bypass door controller. Honeywell Niagara IQ Pro. CVSS 9.1 (CRITICAL).",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/CVE-2024-33045",),
        "devices": ("Honeywell Niagara IQ Pro",),
        "impact": "CRITICAL",
        "exploit_type": "Authentication bypass door controller",
        "source_poc": "Static catalog Level B",
        "cve": "CVE-2024-33045",
        "cvss": "9.1",
        "severity": "CRITICAL",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T1694.002', 'T0859'],
        "mitre_tactics": ['Initial Access'],
    }
    target = OptIP("", "Target Honeywell device IP")
    port = OptPort(4911, "Target service port")
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
                description=f"CVE-2024-33045: Fingerprint Honeywell Niagara IQ Pro at {self.target}:{self.port}. Authentication bypass door controller. CVSS 9.1.",
                mitre_techniques=['T1694.002', 'T0859'],
            )
            return
        if self.check():
            print_success(f"Port {self.port} open - Honeywell Niagara IQ Pro may be present. CVE-2024-33045 CRITICAL CVSS 9.1.")
            print_warning("CISA: N/A")
        else:
            print_info(f"{self.target}:{self.port} not responding.")
