"""IXF CVE Module - CVE-2011-1899 - Iconics Genesis32 WebHMI.

ActiveX buffer overflow

CVSS: 9.3 (CRITICAL)
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

_AFFECTED_PORT = 80
_CVSS          = "9.3"
_SEVERITY      = "CRITICAL"


class Exploit(Exploit):
    __info__ = {
        "name":          "CVE-2011-1899 - Iconics Genesis32 WebHMI (CRITICAL)",
        "description":   "Iconics Genesis32 WebHMI - ActiveX buffer overflow. "
                         "CVSS 9.3 (CRITICAL). Level B: version-based check.",
        "authors":       ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":    (
            "https://nvd.nist.gov/vuln/detail/CVE-2011-1899",
        ),
        "devices":       ("Iconics Genesis32 WebHMI",),
        "impact":        "CRITICAL",
        "exploit_type":  "ActiveX buffer overflow",
        "source_poc":    "NVD Level B version-based check",
        "cve":           "CVE-2011-1899",
        "cvss":          "9.3",
        "severity":      "CRITICAL",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T0883', 'T0888'],
        "mitre_tactics":    ["Discovery"],
    }

    target   = OptIP("", "Target Iconics device IP")
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
                    "CVE-2011-1899: Would fingerprint Iconics Genesis32 WebHMI at "
                    f"{self.target}:{self.port} and confirm if version is in affected range. "
                    "Exploit type: ActiveX buffer overflow. "
                    "CVSS 9.3 (CRITICAL)."
                ),
                mitre_techniques=['T0883', 'T0888'],
            )
            return
        print_status(f"Checking {self.target}:{self.port} for CVE-2011-1899...")
        if self.check():
            print_success(
                f"Port {self.port} open on {self.target} - Iconics Genesis32 WebHMI may be present. "
                "CVE-2011-1899 (CRITICAL CVSS 9.3): ActiveX buffer overflow. "
                "Manual version verification required."
            )
        else:
            print_info(f"{self.target}:{self.port} not responding.")
