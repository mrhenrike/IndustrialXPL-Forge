"""IXF CVE Module - CVE-2022-25151 - JTEKT Toyopuc PLC.

Logic upload no auth

CVSS: 9.1 (CRITICAL)
CISA Advisory: ICSA-22-179-01

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
_CVSS          = "9.1"
_SEVERITY      = "CRITICAL"


class Exploit(Exploit):
    __info__ = {
        "name":          "CVE-2022-25151 - JTEKT Toyopuc PLC (CRITICAL)",
        "description":   "JTEKT Toyopuc PLC - Logic upload no auth. "
                         "CVSS 9.1 (CRITICAL). Level B: version-based check.",
        "authors":       ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":    (
            "https://nvd.nist.gov/vuln/detail/CVE-2022-25151",
        ),
        "devices":       ("JTEKT Toyopuc PLC",),
        "impact":        "CRITICAL",
        "exploit_type":  "Logic upload no auth",
        "source_poc":    "NVD Level B version-based check",
        "cve":           "CVE-2022-25151",
        "cvss":          "9.1",
        "severity":      "CRITICAL",
        "cisa_advisory": "ICSA-22-179-01",
        "mitre_techniques": ['T1694.002', 'T0859', 'T0819', 'T0843'],
        "mitre_tactics":    ["Discovery"],
    }

    target   = OptIP("", "Target JTEKT device IP")
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
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Set \'target\' option first.")
            return
        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-2022-25151: Would fingerprint JTEKT Toyopuc PLC at "
                    f"{self.target}:{self.port} and confirm if version is in affected range. "
                    "Exploit type: Logic upload no auth. "
                    "CVSS 9.1 (CRITICAL)."
                ),
                mitre_techniques=['T1694.002', 'T0859', 'T0819', 'T0843'],
            )
            return
        print_status(f"Checking {self.target}:{self.port} for CVE-2022-25151...")
        if self.check():
            print_success(
                f"Port {self.port} open on {self.target} - JTEKT Toyopuc PLC may be present. "
                "CVE-2022-25151 (CRITICAL CVSS 9.1): Logic upload no auth. "
                "Manual version verification required."
            )
        else:
            print_info(f"{self.target}:{self.port} not responding.")
