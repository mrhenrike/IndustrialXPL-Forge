"""IXF ICS CVE Module — CVE-2023-3595 (Rockwell Automation ControlLogix/CompactLogix 1756-EN2x).

Unauthenticated RCE in Rockwell ControlLogix/CompactLogix 1756-EN2x EtherNet/IP module. CISA emergency advisory. Allows firmware modification and persistent access.

CVSS: 9.8 (CRITICAL)
CWE: CWE-787
Affected: 1756-EN2x EtherNet/IP communication module
PoC reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-191a

simulate=True by default. Requires target authorization.
"""
import socket
import struct
import time
import urllib.request
import urllib.error

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptInteger, OptString, mute,
    print_error, print_info, print_status, print_success, print_warning,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "CVE-2023-3595 — Rockwell Automation ControlLogix/CompactLogix 1756-EN2x Out-of-bounds write — arbitrary code execution in firmware",
        "description":      "Rockwell ControlLogix 1756-EN2x unauthenticated RCE — CISA emergency advisory. CVSS 9.8.",
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":       ('https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-191a', 'https://rockwellautomation.custhelp.com/app/answers/answer_view/a_id/3455'),
        "devices":          ("Rockwell Automation ControlLogix/CompactLogix 1756-EN2x",),
        "impact":           "CRITICAL",
        "exploit_type":     "Out-of-bounds Write — RCE",
        "source_poc":       "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-191a",
        "cve":              "CVE-2023-3595",
        "cvss":             "9.8",
        "severity":         "CRITICAL",
        "mitre_techniques": ['T0866', 'T0836', 'T0880'],
        "mitre_tactics":    ['Initial Access', 'Impact'],
    }

    target   = OptIP("", "Target Rockwell Automation ControlLogix/CompactLogix 1756-EN2x IP")
    port     = OptPort(44818, "Target service port")
    simulate = OptBool(True, "Simulate attack (default: True)")
    destructive = OptBool(False, "Enable live exploitation — requires authorization")

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
                description=(
                    "CVE-2023-3595 — Rockwell Automation ControlLogix/CompactLogix 1756-EN2x\n"
                    "CVSS 9.8 (CRITICAL) | Out-of-bounds write — arbitrary code execution in firmware\n\n"
                    "Step 1: Connect to EtherNet/IP port 44818 on 1756-EN2x module\nStep 2: Send crafted CIP command with out-of-bounds write\nStep 3: Achieve arbitrary code execution in EN2x firmware\nStep 4: Modify PLC logic, disable comms, or install backdoor"
                ),
                mitre_techniques=['T0866', 'T0836', 'T0880'],
            )
            print_info("Affected: 1756-EN2x EtherNet/IP communication module")
            print_info("PoC reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-191a")
            return

        print_status("[CVE-2023-3595] Exploiting {}:{}...".format(self.target, self.port))
        print_info('Live payload: implement protocol-specific exploit')
