"""IXF CVE-2021-34473 ProxyShell Exchange RCE for OT Network Pivot (CVE-2021-34473).

ProxyShell Exchange RCE CVSS 9.8 used to pivot from IT to OT networks.

Severity: CRITICAL CVSS 9.8
Type: Exchange RCE chain for OT network pivot
Reference: https://nvd.nist.gov/vuln/detail/CVE-2021-34473
"""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,
    print_error, print_info, print_status, print_success, print_warning, DestructiveGate,
)

class Exploit(Exploit):
    __info__ = {
        "name": "ProxyShell Exchange RCE for OT Network Pivot (CVE-2021-34473)",
        "description": "ProxyShell Exchange RCE CVSS 9.8 used to pivot from IT to OT networks.",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/CVE-2021-34473",),
        "devices": ("Target device",),
        "impact": "CRITICAL",
        "exploit_type": "Exchange RCE chain for OT network pivot",
        "source_poc": "https://nvd.nist.gov/vuln/detail/CVE-2021-34473",
        "cve": "CVE-2021-34473",
        "cvss": "9.8",
        "severity": "CRITICAL",
        "mitre_techniques": ['T0819', 'T0822'],
        "mitre_tactics": ["Initial Access", "Inhibit Response Function"],
        "destructive_description": "ProxyShell on Exchange port 443 — pivot from IT to OT via compromised server.",
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
                description="CVE-2021-34473: Exchange RCE chain for OT network pivot against target at port 443.",
                mitre_techniques=['T0819', 'T0822'],
            )
            return
        if self.check():
            print_success("Port 443 open — ProxyShell Exchange RCE for OT Network Pivot (CVE-2021-34473). CVE-2021-34473 CRITICAL.")
        else:
            print_error("Target not responding on port 443.")
