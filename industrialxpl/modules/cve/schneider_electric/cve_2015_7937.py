"""IXF CVE Module - CVE-2015-7937 - Schneider Electric TM221 Modbus.

CPU crash via FC 0x71

CVSS: 7.8 (HIGH)
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
_CVSS          = "7.8"
_SEVERITY      = "HIGH"


class Exploit(Exploit):
    __info__ = {
        "name":          "CVE-2015-7937 - Schneider Electric TM221 Modbus (HIGH)",
        "description":   "Schneider Electric TM221 Modbus - CPU crash via FC 0x71. "
                         "CVSS 7.8 (HIGH). Level B: version-based check.",
        "authors":       ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":    (
            "https://nvd.nist.gov/vuln/detail/CVE-2015-7937",
        ),
        "devices":       ("Schneider Electric TM221 Modbus",),
        "impact":        "HIGH",
        "exploit_type":  "CPU crash via FC 0x71",
        "source_poc":    "NVD Level B version-based check",
        "cve":           "CVE-2015-7937",
        "cvss":          "7.8",
        "severity":      "HIGH",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T0883', 'T0888'],
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
                    "CVE-2015-7937: Would fingerprint Schneider Electric TM221 Modbus at "
                    f"{self.target}:{self.port} and confirm if version is in affected range. "
                    "Exploit type: CPU crash via FC 0x71. "
                    "CVSS 7.8 (HIGH)."
                ),
                mitre_techniques=['T0883', 'T0888'],
            )
            return
        print_status(f"Checking {self.target}:{self.port} for CVE-2015-7937...")
        if self.check():
            print_success(
                f"Port {self.port} open on {self.target} - Schneider Electric TM221 Modbus may be present. "
                "CVE-2015-7937 (HIGH CVSS 7.8): CPU crash via FC 0x71. "
                "Manual version verification required."
            )
        else:
            print_info(f"{self.target}:{self.port} not responding.")
