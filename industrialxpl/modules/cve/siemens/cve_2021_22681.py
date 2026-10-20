"""IXF CVE Module - CVE-2021-22681 - Siemens S7-1200 S7-1500.

Hardcoded crypto key (ICEFALL)

CVSS: 7.5 (HIGH)
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

_AFFECTED_PORT = 102
_CVSS          = "7.5"
_SEVERITY      = "HIGH"


class Exploit(Exploit):
    __info__ = {
        "name":          "CVE-2021-22681 - Siemens S7-1200 S7-1500 (HIGH)",
        "description":   "Siemens S7-1200 S7-1500 - Hardcoded crypto key (ICEFALL). "
                         "CVSS 7.5 (HIGH). Level B: version-based check.",
        "authors":       ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":    (
            "https://nvd.nist.gov/vuln/detail/CVE-2021-22681",
        ),
        "devices":       ("Siemens S7-1200 S7-1500",),
        "impact":        "HIGH",
        "exploit_type":  "Hardcoded crypto key (ICEFALL)",
        "source_poc":    "NVD Level B version-based check",
        "cve":           "CVE-2021-22681",
        "cvss":          "7.5",
        "severity":      "HIGH",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T1694.002', 'T0859'],
        "mitre_tactics":    ["Discovery"],
    }

    target   = OptIP("", "Target Siemens device IP")
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
                    "CVE-2021-22681: Would fingerprint Siemens S7-1200 S7-1500 at "
                    f"{self.target}:{self.port} and confirm if version is in affected range. "
                    "Exploit type: Hardcoded crypto key (ICEFALL). "
                    "CVSS 7.5 (HIGH)."
                ),
                mitre_techniques=['T1694.002', 'T0859'],
            )
            return
        print_status(f"Checking {self.target}:{self.port} for CVE-2021-22681...")
        if self.check():
            print_success(
                f"Port {self.port} open on {self.target} - Siemens S7-1200 S7-1500 may be present. "
                "CVE-2021-22681 (HIGH CVSS 7.5): Hardcoded crypto key (ICEFALL). "
                "Manual version verification required."
            )
        else:
            print_info(f"{self.target}:{self.port} not responding.")
