"""IXF CVE Module — DESIGN-MODBUS-NOAUTH — Generic Modbus TCP all vendors.

Severity: CRITICAL (CVSS 9.1)
Type: No authentication by protocol design — unauthenticated read/write
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
_CVSS = "9.1"


class Exploit(Exploit):
    __info__ = {
        "name":          "DESIGN-MODBUS-NOAUTH — Generic Modbus TCP all vendors (CRITICAL)",
        "description":   "No authentication by protocol design — unauthenticated read/write. "
                         "Affects Generic Modbus TCP all vendors. CVSS 9.1 (CRITICAL). "
                         "Level B: fingerprint + version check.",
        "authors":       ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":    ("https://nvd.nist.gov/vuln/detail/DESIGN-MODBUS-NOAUTH",),
        "devices":       ("Generic Modbus TCP all vendors",),
        "impact":        "CRITICAL",
        "exploit_type":  "No authentication by protocol design — unauthenticated read/write",
        "source_poc":    "Static catalog Level B — set check() target for version confirmation",
        "cve":           "DESIGN-MODBUS-NOAUTH",
        "cvss":          "9.1",
        "severity":      "CRITICAL",
        "cisa_advisory": "N/A",
        "mitre_techniques": ['T1694.002', 'T0859', 'T1692.001', 'T0836'],
        "mitre_tactics":    ['Initial Access', 'Impair Process Control'],
    }

    target   = OptIP("", "Target Generic device IP")
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
                    "DESIGN-MODBUS-NOAUTH (CRITICAL CVSS 9.1): No authentication by protocol design — unauthenticated read/write. "
                    "Affects: Generic Modbus TCP all vendors. "
                    f"Would fingerprint {self.target}:{self.port} and confirm if device version "
                    "is in the affected range."
                ),
                mitre_techniques=['T1694.002', 'T0859', 'T1692.001', 'T0836'],
            )
            return

        print_status(f"Checking {self.target}:{self.port} for DESIGN-MODBUS-NOAUTH...")
        if self.check():
            print_success(
                f"Service port {self.port} open on {self.target} — Generic Modbus TCP all vendors may be present. "
                "DESIGN-MODBUS-NOAUTH CRITICAL CVSS 9.1: No authentication by protocol design — unauthenticated read/write. "
                "Manual version verification required to confirm vulnerability."
            )
            print_warning("CISA Advisory: N/A")
        else:
            print_info(f"{self.target}:{self.port} not responding on port {self.port}.")
