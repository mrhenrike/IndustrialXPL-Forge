"""NSA ELITEWOLF Web Diagnostic Endpoint Scanner.

Based on the NSA ELITEWOLF wordlist (OT/ICS vendor web diagnostic paths).
Probes known diagnostic/management web endpoints for industrial devices
from Allen-Bradley/Rockwell, Schweitzer Engineering Laboratories (SEL),
and Siemens.

Source: NSA ELITEWOLF project / ICS-Security OSINT
"""

import socket
import urllib.request
import urllib.error
import ssl

from industrialxpl.core.exploit import (
    Exploit,
    OptBool,
    OptIP,
    OptInteger,
    OptPort,
    OptString,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_table,
    print_warning,
    DestructiveGate,
)


# ELITEWOLF paths by vendor
_ELITEWOLF_PATHS = {
    "Allen-Bradley/Rockwell": [
        "/rokform/advancedDiags?pageReq=advDiagInitPage",
        "/1756-enet/web/homepage.htm",
        "/css/radevice.css",
        "/1756-l1/web/",
        "/web/homepage.htm",
    ],
    "Schweitzer (SEL)": [
        "/home.sel",
        "/errors/err401.sel?username=",
        "/default.sel",
        "/scripts/dScripts.sel",
        "/relay/",
    ],
    "Siemens": [
        "/CSS/S7Web.css",
        "/Images/CPU1200/",
        "/Portal/",
        "/awp/",
        "/simatic/",
    ],
    "Generic OT Web": [
        "/index.htm",
        "/login.html",
        "/cgi-bin/login.cgi",
        "/goform/login",
        "/webui/",
    ],
}


class Exploit(Exploit):
    __info__ = {
        "name":         "NSA ELITEWOLF ICS Web Diagnostic Endpoint Scanner",
        "description":  "Probes known OT/ICS vendor web diagnostic endpoints based on "
                        "the NSA ELITEWOLF OSINT wordlist. Detects exposed Allen-Bradley/"
                        "Rockwell, Schweitzer (SEL), and Siemens web management interfaces "
                        "without authentication. Non-destructive: HTTP GET only.",
        "authors":      ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":   (
            "NSA ELITEWOLF — OT/ICS OSINT Wordlist",
            "https://github.com/nsacyber/ELITEWOLF",
        ),
        "devices":      ("Allen-Bradley/Rockwell PLCs", "Schweitzer SEL relays", "Siemens SIMATIC"),
        "impact":       "INFO",
        "exploit_type": "Web Diagnostic Endpoint Discovery",
        "source_poc":   "IXF native (HTTP GET, NSA ELITEWOLF paths)",
        "cve":          "N/A", "cvss": "N/A", "severity": "INFO",
        "mitre_techniques": ["T0883", "T0888", "T0846"],
        "mitre_tactics":    ["Discovery", "Initial Access"],
    }

    target   = OptIP("", "Target OT device IP")
    port     = OptPort(80, "HTTP port (80 or 443)")
    vendor   = OptString("all", "Vendor filter: all | rockwell | sel | siemens | generic")
    timeout  = OptInteger(5, "HTTP timeout per path")
    use_https = OptBool(False, "Use HTTPS")
    simulate = OptBool(True, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable real HTTP probing")

    @mute
    def check(self) -> bool:
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
            print_error("Set 'target' option first.")
            return

        scheme = "https" if self.use_https else "http"
        base_url = "{}://{}:{}".format(scheme, self.target, self.port)

        # Filter paths by vendor
        paths_to_probe = {}
        vendor_filter = self.vendor.lower()
        for vendor, paths in _ELITEWOLF_PATHS.items():
            if (vendor_filter == "all" or
                    vendor_filter in vendor.lower() or
                    vendor.lower().startswith(vendor_filter)):
                paths_to_probe[vendor] = paths

        if self.simulate:
            total_paths = sum(len(p) for p in paths_to_probe.values())
            DestructiveGate.print_simulation(
                description=(
                    "ELITEWOLF: Would probe {} paths across {} vendor(s) on {} via HTTP GET. "
                    "Looking for exposed diagnostic endpoints.".format(
                        total_paths, len(paths_to_probe), base_url
                    )
                ),
                payload_human="GET {} HTTP/1.1\nHost: {}:{}".format(
                    next(iter(next(iter(paths_to_probe.values())))), self.target, self.port
                ),
                mitre_techniques=["T0883"],
            )
            for vendor, paths in paths_to_probe.items():
                print_info("[ELITEWOLF] {} paths to probe for {}:".format(len(paths), vendor))
                for p in paths[:3]:
                    print_info("  GET {}{}".format(base_url, p))
            return

        # Real probing
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        found = []
        print_status("[ELITEWOLF] Probing {} ({} vendors)…".format(base_url, len(paths_to_probe)))

        for vendor, paths in paths_to_probe.items():
            for path in paths:
                url = "{}{}".format(base_url, path)
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req, timeout=self.timeout,
                                                context=ctx if self.use_https else None) as resp:
                        status = resp.status
                        if status in (200, 301, 302, 401, 403):
                            found.append((vendor[:20], path[:40], str(status)))
                            if status == 200:
                                print_success("[ELITEWOLF] {} — HTTP {} {}".format(vendor, status, url))
                            else:
                                print_info("[ELITEWOLF] {} — HTTP {} {}".format(vendor, status, url))
                except urllib.error.HTTPError as e:
                    if e.code in (401, 403):
                        found.append((vendor[:20], path[:40], str(e.code)))
                        print_info("[ELITEWOLF] {} — HTTP {} {}".format(vendor, e.code, url))
                except Exception:
                    pass

        if found:
            print_table(["Vendor", "Path", "HTTP Status"], found,
                        title="ELITEWOLF Endpoints Found — {}".format(self.target))
        else:
            print_info("[ELITEWOLF] No diagnostic endpoints found on {}.".format(self.target))
