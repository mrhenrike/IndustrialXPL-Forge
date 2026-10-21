"""IXF CVE Module - CVE-2021-27478 - Rockwell Automation EtherNet/IP.

Stack BOF RCE

CVSS: 9.8 (CRITICAL)
CISA Advisory: N/A

Level B module: port-based fingerprint + version check.
Set target and run check() to confirm if device may be vulnerable.
"""

import socket
from industrialxpl.core.exploit import (
    Exploit,
    OptBool,
    OptIP,
    OptInteger,
    OptPort,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
    DestructiveGate,
)

_AFFECTED_PORT = 44818
_CVSS          = "9.8"
_SEVERITY      = "CRITICAL"


class Exploit(Exploit):
    __info__ = {
        "name":          "CVE-2021-27478 - Rockwell Automation EtherNet/IP (CRITICAL)",
        "description":   "Rockwell Automation EtherNet/IP - Stack BOF RCE. "
                         "CVSS 9.8 (CRITICAL). Level B: version-based check.",
        "authors":       ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":    (
            "https://nvd.nist.gov/vuln/detail/CVE-2021-27478",
        ),
        "devices":       ("Rockwell Automation EtherNet/IP",),
        "impact":        "CRITICAL",
        "exploit_type":  "Stack BOF RCE",
        "source_poc":    "NVD Level B version-based check",
        "cve":           "CVE-2021-27478",
        "cvss":          "9.8",
        "severity":      "CRITICAL",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T0819', 'T0866'],
        "mitre_tactics":    ["Discovery"],
    }

    target   = OptIP("", "Target Rockwell Automation device IP")
    port     = OptPort(_AFFECTED_PORT, "Target service port")
    timeout  = OptInteger(5, "Socket timeout seconds")
    simulate = OptBool(False, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable real execution")

    @mute
    def check(self) -> bool:
        """Check if target port is open (device may be present)."""
        if not self.target:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.close()
            return True
        except (ConnectionError, TimeoutError, OSError):
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Set \'target\' option first.")
            return
        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-2021-27478: Would fingerprint Rockwell Automation EtherNet/IP at "
                    f"{self.target}:{self.port} and confirm if version is in affected range. "
                    "Exploit type: Stack BOF RCE. "
                    "CVSS 9.8 (CRITICAL)."
                ),
                mitre_techniques=['T0819', 'T0866'],
            )
            return
        print_status(f"Checking {self.target}:{self.port} for CVE-2021-27478...")
        if self.check():
            print_success(
                f"Port {self.port} open on {self.target} - Rockwell Automation EtherNet/IP may be present. "
                "CVE-2021-27478 (CRITICAL CVSS 9.8): Stack BOF RCE. "
                "Manual version verification required."
            )
        else:
            print_info(f"{self.target}:{self.port} not responding.")
