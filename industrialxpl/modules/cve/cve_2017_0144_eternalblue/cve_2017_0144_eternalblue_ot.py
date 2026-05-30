"""IXF CVE-2017-0144 EternalBlue SMB RCE in OT Networks (CVE-2017-0144).

NSA exploit used by WannaCry/NotPetya devastating OT networks in 2017.

Severity: CRITICAL CVSS 9.3
Type: SMB RCE WannaCry NotPetya in OT
Reference: https://nvd.nist.gov/vuln/detail/CVE-2017-0144
"""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,
    print_error, print_info, print_status, print_success, print_warning, DestructiveGate,
)

class Exploit(Exploit):
    __info__ = {
        "name": "EternalBlue SMB RCE in OT Networks (CVE-2017-0144)",
        "description": "NSA exploit used by WannaCry/NotPetya devastating OT networks in 2017.",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/CVE-2017-0144",),
        "devices": ("Target device",),
        "impact": "CRITICAL",
        "exploit_type": "SMB RCE WannaCry NotPetya in OT",
        "source_poc": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
        "cve": "CVE-2017-0144",
        "cvss": "9.3",
        "severity": "CRITICAL",
        "mitre_techniques": ['T0819', 'T0866'],
        "mitre_tactics": ["Initial Access", "Inhibit Response Function"],
        "destructive_description": "EternalBlue SMB exploit on port 445 — RCE via MS17-010 on OT Windows hosts.",
    }
    target = OptIP("", "Target IP")
    port = OptPort(445, "Target port")
    timeout = OptInteger(5, "Timeout")
    simulate = OptBool(True, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable real execution")

    @mute
    def check(self):
        if not self.target: return False
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
                description="CVE-2017-0144: SMB RCE WannaCry NotPetya in OT against target at port 445.",
                mitre_techniques=['T0819', 'T0866'],
            )
            return
        if self.check():
            print_success("Port 445 open — EternalBlue SMB RCE in OT Networks (CVE-2017-0144). CVE-2017-0144 CRITICAL.")
        else:
            print_error("Target not responding on port 445.")
