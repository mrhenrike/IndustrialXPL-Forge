"""IXF CVE CVE-2017-7899 Rockwell Automation RSLinx Classic EDS subsystem CRITICAL CVSS 9.8.
Exploit: Stack buffer overflow. CISA: N/A.
"""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,
    print_error, print_info, print_success, DestructiveGate,
)

class Exploit(Exploit):
    __info__ = {
        "name": "CVE-2017-7899 Rockwell Automation CRITICAL",
        "description": "Stack buffer overflow. Rockwell Automation RSLinx Classic EDS subsystem. CVSS 9.8 (CRITICAL).",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/CVE-2017-7899",),
        "devices": ("Rockwell Automation RSLinx Classic EDS subsystem",),
        "impact": "CRITICAL",
        "exploit_type": "Stack buffer overflow",
        "source_poc": "Static catalog Level B",
        "cve": "CVE-2017-7899",
        "cvss": "9.8",
        "severity": "CRITICAL",
        "cisa_advisory": "N/A",
        "mitre_techniques": ["T0883", "T0888"],
        "mitre_tactics": ["Discovery"],
    }
    target = OptIP("", "Target Rockwell Automation IP")
    port = OptPort(44818, "Target port")
    timeout = OptInteger(5, "Timeout")
    simulate = OptBool(False, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable real execution")

    @mute
    def check(self):
        if not self.target: return False
        try:
            s = socket.socket(); s.settimeout(self.timeout)
            s.connect((self.target, self.port)); s.close(); return True
        except OSError: return False

    def run(self):
        if not self.target: print_error("Set target."); return
        if self.simulate:
            DestructiveGate.print_simulation(
                description=f"CVE-2017-7899: {self.target}:{self.port}.  Stack buffer overflow. CVSS 9.8.",
                mitre_techniques=["T0883"],
            ); return
        print_success(f"CVE-2017-7899 CRITICAL - port {self.port} open.") if self.check() else print_error("Not responding.")
