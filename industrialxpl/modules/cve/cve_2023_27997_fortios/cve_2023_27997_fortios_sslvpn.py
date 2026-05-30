"""IXF CVE-2023-27997 FortiOS SSL-VPN Pre-Auth Heap Overflow RCE (CVE-2023-27997).

FortiOS SSL-VPN pre-auth heap overflow RCE CVSS 9.8 used as OT border VPN.

Severity: CRITICAL CVSS 9.8
Type: Pre-auth heap overflow on OT border VPN
Reference: https://nvd.nist.gov/vuln/detail/CVE-2023-27997
"""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,
    print_error, print_info, print_status, print_success, print_warning, DestructiveGate,
)

class Exploit(Exploit):
    __info__ = {
        "name": "FortiOS SSL-VPN Pre-Auth Heap Overflow RCE (CVE-2023-27997)",
        "description": "FortiOS SSL-VPN pre-auth heap overflow RCE CVSS 9.8 used as OT border VPN.",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/CVE-2023-27997",),
        "devices": ("Target device",),
        "impact": "CRITICAL",
        "exploit_type": "Pre-auth heap overflow on OT border VPN",
        "source_poc": "https://nvd.nist.gov/vuln/detail/CVE-2023-27997",
        "cve": "CVE-2023-27997",
        "cvss": "9.8",
        "severity": "CRITICAL",
        "mitre_techniques": ['T0819', 'T0822'],
        "mitre_tactics": ["Initial Access", "Inhibit Response Function"],
        "destructive_description": "FortiOS SSL-VPN heap overflow on port 443 — RCE on OT border firewall VPN.",
    }
    target = OptIP("", "Target IP")
    port = OptPort(443, "Target port")
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
                description="CVE-2023-27997: Pre-auth heap overflow on OT border VPN against target at port 443.",
                mitre_techniques=['T0819', 'T0822'],
            )
            return
        if self.check():
            print_success("Port 443 open — FortiOS SSL-VPN Pre-Auth Heap Overflow RCE (CVE-2023-27997). CVE-2023-27997 CRITICAL.")
        else:
            print_error("Target not responding on port 443.")
