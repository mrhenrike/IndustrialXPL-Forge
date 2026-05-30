"""IXF CVE CVE-2012-6435 — Rockwell Automation MicroLogix 1100 1400 (CRITICAL CVSS 9.8).

Exploit type: Unauthenticated firmware upload
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
        "name": "CVE-2012-6435 Rockwell Automation MicroLogix 1100 1400 CRITICAL",
        "description": "Unauthenticated firmware upload. Rockwell Automation MicroLogix 1100 1400. CVSS 9.8 (CRITICAL).",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/CVE-2012-6435",),
        "devices": ("Rockwell Automation MicroLogix 1100 1400",),
        "impact": "CRITICAL",
        "exploit_type": "Unauthenticated firmware upload",
        "source_poc": "Static catalog Level B",
        "cve": "CVE-2012-6435",
        "cvss": "9.8",
        "severity": "CRITICAL",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T0819', 'T0866', 'T1694.002', 'T0859'],
        "mitre_tactics": ['Initial Access'],
    }
    target = OptIP("", "Target Rockwell Automation device IP")
    port = OptPort(44818, "Target service port")
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
                description="CVE-2012-6435: Fingerprint Rockwell Automation MicroLogix 1100 1400 at {}:{}. Unauthenticated firmware upload. CVSS 9.8.".format(self.target, self.port),
                mitre_techniques=['T0819', 'T0866', 'T1694.002', 'T0859'],
            )
            return
        if self.check():
            print_success("Port {} open — Rockwell Automation MicroLogix 1100 1400 may be present. CVE-2012-6435 CRITICAL CVSS 9.8.".format(self.port))
            print_warning("CISA: N/A")
        else:
            print_info("{}:{} not responding.".format(self.target, self.port))
