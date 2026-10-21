"""IXF CVE CVE-2024-4609 GE Vernova Grid Solutions Modbus HIGH CVSS 7.5.
Exploit: Denial of service Modbus protocol. CISA: N/A.
"""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,
    print_error, print_info, print_success, DestructiveGate,
)

class Exploit(Exploit):
    __info__ = {
        "name": "CVE-2024-4609 GE Vernova HIGH",
        "description": "Denial of service Modbus protocol. GE Vernova Grid Solutions Modbus. CVSS 7.5 (HIGH).",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/CVE-2024-4609",),
        "devices": ("GE Vernova Grid Solutions Modbus",),
        "impact": "HIGH",
        "exploit_type": "Denial of service Modbus protocol",
        "source_poc": "Static catalog Level B",
        "cve": "CVE-2024-4609",
        "cvss": "7.5",
        "severity": "HIGH",
        "cisa_advisory": "N/A",
        "mitre_techniques": ["T0883", "T0888"],
        "mitre_tactics": ["Discovery"],
    }
    target = OptIP("", "Target GE Vernova IP")
    port = OptPort(502, "Target port")
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
                description=f"CVE-2024-4609: {self.target}:{self.port}.  Denial of service Modbus protocol. CVSS 7.5.",
                mitre_techniques=["T0883"],
            ); return
        print_success(f"CVE-2024-4609 HIGH - port {self.port} open.") if self.check() else print_error("Not responding.")
