"""IXF CVE CVE-2024-2426 Rockwell Automation FactoryTalk View ME Station CRITICAL CVSS 9.8.
Exploit: Authentication bypass remote. CISA: N/A.
"""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,
    print_error, print_info, print_success, DestructiveGate,
)

class Exploit(Exploit):
    __info__ = {
        "name": "CVE-2024-2426 Rockwell Automation CRITICAL",
        "description": "Authentication bypass remote. Rockwell Automation FactoryTalk View ME Station. CVSS 9.8 (CRITICAL).",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/CVE-2024-2426",),
        "devices": ("Rockwell Automation FactoryTalk View ME Station",),
        "impact": "CRITICAL",
        "exploit_type": "Authentication bypass remote",
        "source_poc": "Static catalog Level B",
        "cve": "CVE-2024-2426",
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
                description=f"CVE-2024-2426: {self.target}:{self.port}.  Authentication bypass remote. CVSS 9.8.",
                mitre_techniques=["T0883"],
            ); return
        print_success(f"CVE-2024-2426 CRITICAL - port {self.port} open.") if self.check() else print_error("Not responding.")
