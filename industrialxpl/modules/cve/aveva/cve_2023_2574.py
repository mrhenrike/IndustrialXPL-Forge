"""IXF CVE Module - CVE-2023-2574 - AVEVA InTouch HMI.

Path traversal

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

_AFFECTED_PORT = 502
_CVSS          = "9.8"
_SEVERITY      = "CRITICAL"


class Exploit(Exploit):
    __info__ = {
        "name":          "CVE-2023-2574 - AVEVA InTouch HMI (CRITICAL)",
        "description":   "AVEVA InTouch HMI - Path traversal. "
                         "CVSS 9.8 (CRITICAL). Level B: version-based check.",
        "authors":       ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":    (
            "https://nvd.nist.gov/vuln/detail/CVE-2023-2574",
        ),
        "devices":       ("AVEVA InTouch HMI",),
        "impact":        "CRITICAL",
        "exploit_type":  "Path traversal",
        "source_poc":    "NVD Level B version-based check",
        "cve":           "CVE-2023-2574",
        "cvss":          "9.8",
        "severity":      "CRITICAL",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T0819'],
        "mitre_tactics":    ["Discovery"],
    }

    target   = OptIP("", "Target AVEVA device IP")
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
                    "CVE-2023-2574: Would fingerprint AVEVA InTouch HMI at "
                    f"{self.target}:{self.port} and confirm if version is in affected range. "
                    "Exploit type: Path traversal. "
                    "CVSS 9.8 (CRITICAL)."
                ),
                mitre_techniques=['T0819'],
            )
            return
        print_status(f"Checking {self.target}:{self.port} for CVE-2023-2574...")
        if self.check():
            print_success(
                f"Port {self.port} open on {self.target} - AVEVA InTouch HMI may be present. "
                "CVE-2023-2574 (CRITICAL CVSS 9.8): Path traversal. "
                "Manual version verification required."
            )
        else:
            print_info(f"{self.target}:{self.port} not responding.")
