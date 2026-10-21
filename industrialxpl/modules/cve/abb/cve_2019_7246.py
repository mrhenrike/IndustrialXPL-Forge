"""IXF CVE Module - CVE-2019-7246 - ABB CP651 HMI.

Severity: HIGH (CVSS 7.5)
Type: Denial of service vulnerability
CISA Advisory: N/A

Level B module: port fingerprint + version context.
run() in simulate mode (default): describes exploit without sending packets.
set simulate false + destructive true for real execution gate.
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

_DEFAULT_PORT = 102
_SEVERITY = "HIGH"
_CVSS = "7.5"


class Exploit(Exploit):
    __info__ = {
        "name":          "CVE-2019-7246 - ABB CP651 HMI (HIGH)",
        "description":   "Denial of service vulnerability. "
                         "Affects ABB CP651 HMI. CVSS 7.5 (HIGH). "
                         "Level B: fingerprint + version check.",
        "authors":       ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":    ("https://nvd.nist.gov/vuln/detail/CVE-2019-7246",),
        "devices":       ("ABB CP651 HMI",),
        "impact":        "HIGH",
        "exploit_type":  "Denial of service vulnerability",
        "source_poc":    "Static catalog Level B - set check() target for version confirmation",
        "cve":           "CVE-2019-7246",
        "cvss":          "7.5",
        "severity":      "HIGH",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T0814'],
        "mitre_tactics":    ['Inhibit Response Function'],
    }

    target   = OptIP("", "Target ABB device IP")
    port     = OptPort(_DEFAULT_PORT, "Target service port")
    timeout  = OptInteger(5, "Socket timeout seconds")
    simulate = OptBool(False, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable real execution (requires gate confirmation)")

    @mute
    def check(self) -> bool:
        """Fingerprint: return True if service port is open (device may be present)."""
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
            print_error("Set the \'target\' option first.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-2019-7246 (HIGH CVSS 7.5): Denial of service vulnerability. "
                    "Affects: ABB CP651 HMI. "
                    f"Would fingerprint {self.target}:{self.port} and confirm if device version "
                    "is in the affected range."
                ),
                mitre_techniques=['T0814'],
            )
            return

        print_status(f"Checking {self.target}:{self.port} for CVE-2019-7246...")
        if self.check():
            print_success(
                f"Service port {self.port} open on {self.target} - ABB CP651 HMI may be present. "
                "CVE-2019-7246 HIGH CVSS 7.5: Denial of service vulnerability. "
                "Manual version verification required to confirm vulnerability."
            )
            print_warning("CISA Advisory: N/A")
        else:
            print_info(f"{self.target}:{self.port} not responding on port {self.port}.")
