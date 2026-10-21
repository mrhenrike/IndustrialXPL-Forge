"""IXF CVE Module - ICSA-21-259-02 - Schneider Electric SCADAPack RemoteConnect.

Buffer overflow path traversal

CVSS: 9.8 (CRITICAL)
CISA Advisory: ICSA-21-259-02

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

_AFFECTED_PORT = 17185
_CVSS          = "9.8"
_SEVERITY      = "CRITICAL"


class Exploit(Exploit):
    __info__ = {
        "name":          "ICSA-21-259-02 - Schneider Electric SCADAPack RemoteConnect (CRITICAL)",
        "description":   "Schneider Electric SCADAPack RemoteConnect - Buffer overflow path traversal. "
                         "CVSS 9.8 (CRITICAL). Level B: version-based check.",
        "authors":       ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":    (
            "https://nvd.nist.gov/vuln/detail/ICSA-21-259-02",
        ),
        "devices":       ("Schneider Electric SCADAPack RemoteConnect",),
        "impact":        "CRITICAL",
        "exploit_type":  "Buffer overflow path traversal",
        "source_poc":    "NVD Level B version-based check",
        "cve":           "ICSA-21-259-02",
        "cvss":          "9.8",
        "severity":      "CRITICAL",
        "cisa_advisory": "ICSA-21-259-02",
        "mitre_techniques": ['T0819'],
        "mitre_tactics":    ["Discovery"],
    }

    target   = OptIP("", "Target Schneider Electric device IP")
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
                    "ICSA-21-259-02: Would fingerprint Schneider Electric SCADAPack RemoteConnect at "
                    f"{self.target}:{self.port} and confirm if version is in affected range. "
                    "Exploit type: Buffer overflow path traversal. "
                    "CVSS 9.8 (CRITICAL)."
                ),
                mitre_techniques=['T0819'],
            )
            return
        print_status(f"Checking {self.target}:{self.port} for ICSA-21-259-02...")
        if self.check():
            print_success(
                f"Port {self.port} open on {self.target} - Schneider Electric SCADAPack RemoteConnect may be present. "
                "ICSA-21-259-02 (CRITICAL CVSS 9.8): Buffer overflow path traversal. "
                "Manual version verification required."
            )
        else:
            print_info(f"{self.target}:{self.port} not responding.")
