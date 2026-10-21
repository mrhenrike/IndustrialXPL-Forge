"""IXF CVE Module - CVE-2016-5645 - Rockwell Automation 1766-L32 EIP.

Ethernet interface DoS

CVSS: 5.0 (MEDIUM)
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
_CVSS          = "5.0"
_SEVERITY      = "MEDIUM"


class Exploit(Exploit):
    __info__ = {
        "name":          "CVE-2016-5645 - Rockwell Automation 1766-L32 EIP (MEDIUM)",
        "description":   "Rockwell Automation 1766-L32 EIP - Ethernet interface DoS. "
                         "CVSS 5.0 (MEDIUM). Level B: version-based check.",
        "authors":       ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":    (
            "https://nvd.nist.gov/vuln/detail/CVE-2016-5645",
        ),
        "devices":       ("Rockwell Automation 1766-L32 EIP",),
        "impact":        "MEDIUM",
        "exploit_type":  "Ethernet interface DoS",
        "source_poc":    "NVD Level B version-based check",
        "cve":           "CVE-2016-5645",
        "cvss":          "5.0",
        "severity":      "MEDIUM",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T0814'],
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
                    "CVE-2016-5645: Would fingerprint Rockwell Automation 1766-L32 EIP at "
                    f"{self.target}:{self.port} and confirm if version is in affected range. "
                    "Exploit type: Ethernet interface DoS. "
                    "CVSS 5.0 (MEDIUM)."
                ),
                mitre_techniques=['T0814'],
            )
            return
        print_status(f"Checking {self.target}:{self.port} for CVE-2016-5645...")
        if self.check():
            print_success(
                f"Port {self.port} open on {self.target} - Rockwell Automation 1766-L32 EIP may be present. "
                "CVE-2016-5645 (MEDIUM CVSS 5.0): Ethernet interface DoS. "
                "Manual version verification required."
            )
        else:
            print_info(f"{self.target}:{self.port} not responding.")
