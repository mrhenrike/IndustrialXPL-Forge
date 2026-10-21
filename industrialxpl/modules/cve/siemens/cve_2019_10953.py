"""IXF CVE CVE-2019-10953 Siemens SIMATIC WinCC V7.3 HIGH CVSS 7.5.
Exploit: SQL injection SCADA historian. CISA: N/A.
"""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,
    print_error, print_info, print_success, DestructiveGate,
)

class Exploit(Exploit):
    __info__ = {
        "name": "CVE-2019-10953 Siemens HIGH",
        "description": "SQL injection SCADA historian. Siemens SIMATIC WinCC V7.3. CVSS 7.5 (HIGH).",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/CVE-2019-10953",),
        "devices": ("Siemens SIMATIC WinCC V7.3",),
        "impact": "HIGH",
        "exploit_type": "SQL injection SCADA historian",
        "source_poc": "Static catalog Level B",
        "cve": "CVE-2019-10953",
        "cvss": "7.5",
        "severity": "HIGH",
        "cisa_advisory": "N/A",
        "mitre_techniques": ["T0883", "T0888"],
        "mitre_tactics": ["Discovery"],
    }
    target = OptIP("", "Target Siemens IP")
    port = OptPort(1433, "Target port")
    timeout = OptInteger(5, "Timeout")
    simulate = OptBool(False, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable real execution")

    @mute
    def check(self):
        if not self.target: return False
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((self.target, self.port)); s.close(); return True
        except OSError: return False

    def run(self):
        if not self.target:
            print_error("Set target.")
            return
        if self.simulate:
            DestructiveGate.print_simulation(
                description=f"CVE-2019-10953: {self.target}:{self.port}.  SQL injection SCADA historian. CVSS 7.5.",
                mitre_techniques=["T0883"],
            ); return
        print_success(f"CVE-2019-10953 HIGH - port {self.port} open.") if self.check() else print_error("Not responding.")
