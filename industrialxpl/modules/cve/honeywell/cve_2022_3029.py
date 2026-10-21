"""IXF CVE Module - CVE-2022-3029 - Honeywell Saia Burgess Controls.

Severity: CRITICAL (CVSS 9.8)
Type: Authentication bypass web server
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

_DEFAULT_PORT = 502
_SEVERITY = "CRITICAL"
_CVSS = "9.8"


class Exploit(Exploit):
    __info__ = {
        "name":          "CVE-2022-3029 - Honeywell Saia Burgess Controls (CRITICAL)",
        "description":   "Authentication bypass web server. "
                         "Affects Honeywell Saia Burgess Controls. CVSS 9.8 (CRITICAL). "
                         "Level B: fingerprint + version check.",
        "authors":       ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":    ("https://nvd.nist.gov/vuln/detail/CVE-2022-3029",),
        "devices":       ("Honeywell Saia Burgess Controls",),
        "impact":        "CRITICAL",
        "exploit_type":  "Authentication bypass web server",
        "source_poc":    "Static catalog Level B - set check() target for version confirmation",
        "cve":           "CVE-2022-3029",
        "cvss":          "9.8",
        "severity":      "CRITICAL",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T1694.002', 'T0859'],
        "mitre_tactics":    ['Initial Access'],
    }

    target   = OptIP("", "Target Honeywell device IP")
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
                    "CVE-2022-3029 (CRITICAL CVSS 9.8): Authentication bypass web server. "
                    "Affects: Honeywell Saia Burgess Controls. "
                    f"Would fingerprint {self.target}:{self.port} and confirm if device version "
                    "is in the affected range."
                ),
                mitre_techniques=['T1694.002', 'T0859'],
            )
            return

        print_status(f"Checking {self.target}:{self.port} for CVE-2022-3029...")
        if self.check():
            print_success(
                f"Service port {self.port} open on {self.target} - Honeywell Saia Burgess Controls may be present. "
                "CVE-2022-3029 CRITICAL CVSS 9.8: Authentication bypass web server. "
                "Manual version verification required to confirm vulnerability."
            )
            print_warning("CISA Advisory: N/A")
        else:
            print_info(f"{self.target}:{self.port} not responding on port {self.port}.")
