"""IXF CVE Module — CVE-2023-4486 (Johnson Controls Metasys BAS).

CVSS: 9.8 (CRITICAL) | CWE: CWE-288
Affected: Metasys 10.x to 12.0.1
simulate=True default. Requires authorization.
"""
import socket
import struct
import time
import urllib.request
import urllib.error

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptString, mute,
    print_error, print_info, print_status, print_success, print_warning,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "CVE-2023-4486 — Johnson Controls Metasys BAS Authentication bypass — BAS full control",
        "description":      "Johnson Controls Metasys building automation system authentication bypass — full BAS access.",
        "authors":          ("Andre Henrique (@mrhenrike)",),
        "references":       ('https://www.cisa.gov/uscert/ics/advisories/icsa-23-234-02',),
        "devices":          ("Johnson Controls Metasys BAS",),
        "impact":           "CRITICAL",
        "exploit_type":     "Authentication Bypass",
        "source_poc":       "https://www.cisa.gov/uscert/ics/advisories/icsa-23-234-02",
        "cve":              "CVE-2023-4486",
        "cvss":             "9.8",
        "severity":         "CRITICAL",
        "mitre_techniques": ['T0865', 'T0836'],
        "mitre_tactics":    ['Initial Access'],
    }

    target      = OptIP("", "Target Johnson Controls Metasys BAS IP")
    port        = OptPort(443, "Target service port")
    simulate    = OptBool(True,  "Simulate (default: True)")
    destructive = OptBool(False, "Enable live exploitation")

    @mute
    def check(self):
        if not self.target: return False
        try:
            s = socket.socket(); s.settimeout(5)
            s.connect((self.target, self.port)); s.close(); return True
        except: return False

    def run(self):
        if not self.target:
            print_error("Set 'target' option.")
            return
        if self.simulate:
            DestructiveGate.print_simulation(
                description="CVE-2023-4486 Johnson Controls Metasys BAS\nCVSS 9.8 (CRITICAL) | Authentication bypass — BAS full control\n\nStep 1: Access Metasys web interface on port 443\nStep 2: Bypass authentication via crafted session token\nStep 3: Access all building systems: HVAC, lighting, access control\nStep 4: Modify setpoints — building environment manipulation",
                mitre_techniques=['T0865', 'T0836'],
            )
            print_info("Affected: Metasys 10.x to 12.0.1")
            print_info("PoC: https://www.cisa.gov/uscert/ics/advisories/icsa-23-234-02")
            return
        print_status("[CVE-2023-4486] Exploiting {}:{}...".format(self.target, self.port))
        print_info('Live payload: implement protocol-specific exploit')
