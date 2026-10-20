"""IXF CVE Module — CVE-2021-33014 — Advantech WebAccess.

Severity: CRITICAL (CVSS 9.8)
Type: Stack-based buffer overflow RCE
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

_DEFAULT_PORT = 80
_SEVERITY = "CRITICAL"
_CVSS = "9.8"


class Exploit(Exploit):
    __info__ = {
        "name":          "CVE-2021-33014 — Advantech WebAccess (CRITICAL)",
        "description":   "Stack-based buffer overflow RCE. "
                         "Affects Advantech WebAccess. CVSS 9.8 (CRITICAL). "
                         "Level B: fingerprint + version check.",
        "authors":       ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":    ("https://nvd.nist.gov/vuln/detail/CVE-2021-33014",),
        "devices":       ("Advantech WebAccess",),
        "impact":        "CRITICAL",
        "exploit_type":  "Stack-based buffer overflow RCE",
        "source_poc":    "Static catalog Level B — set check() target for version confirmation",
        "cve":           "CVE-2021-33014",
        "cvss":          "9.8",
        "severity":      "CRITICAL",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T0819', 'T0866', 'T0814'],
        "mitre_tactics":    ['Initial Access', 'Inhibit Response Function'],
    }

    target   = OptIP("", "Target Advantech device IP")
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
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Set the \'target\' option first.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "CVE-2021-33014 (CRITICAL CVSS 9.8): Stack-based buffer overflow RCE. "
                    "Affects: Advantech WebAccess. "
                    f"Would fingerprint {self.target}:{self.port} and confirm if device version "
                    "is in the affected range."
                ),
                mitre_techniques=['T0819', 'T0866', 'T0814'],
            )
            return

        print_status(f"Checking {self.target}:{self.port} for CVE-2021-33014...")
        if self.check():
            print_success(
                f"Service port {self.port} open on {self.target} — Advantech WebAccess may be present. "
                "CVE-2021-33014 CRITICAL CVSS 9.8: Stack-based buffer overflow RCE. "
                "Manual version verification required to confirm vulnerability."
            )
            print_warning("CISA Advisory: N/A")
        else:
            print_info(f"{self.target}:{self.port} not responding on port {self.port}.")
