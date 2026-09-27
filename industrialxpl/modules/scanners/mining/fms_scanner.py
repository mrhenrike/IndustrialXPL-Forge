# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Fleet Management System (FMS) Scanner for Mining Operations.

Detects and fingerprints Fleet Management Systems used in open-pit and
underground mining. FMS platforms coordinate autonomous and semi-autonomous
haul trucks, excavators, drills, and support equipment.

Targeted systems:
  - Wenco FMS (Hitachi Construction Machinery)
    Web interface on TCP/8080 (HTTP) and TCP/8443 (HTTPS)
    API endpoints on /api/v1/ — often unauthenticated in older installs
  - Caterpillar MineStar (see caterpillar_minestar_api.py)
  - Komatsu Dispatch (KOMTRAX Plus, port 8080)
  - Modular Mining ProVision (port 8080/80)
  - MICROMINE Pitram (port 80/443)

Attack surface overview (mining FMS):
  - Ransomware groups (BianLian, Cl0p) targeted FMS servers in 2024-2025
  - Disrupting FMS halts autonomous fleet scheduling without touching vehicles
  - Copper Mountain Mining (2022): ransomware via stolen creds -> mill shutdown 5 days
  - Northern Minerals (2024): BianLian exfiltrated 1 TB from FMS-adjacent systems

References:
  - https://miningfms.com/knowledge-base/system-architecture/fms-network-security/
  - ICS-CERT Advisory on FMS network exposure (2024)
  - MITRE ATT&CK ICS: T0883 Internet-Accessible Device, T0846 Remote System Discovery
"""

import socket
import re
from typing import Optional, List, Dict

from industrialxpl.core.exploit import (
    Exploit, OptIP, OptBool, OptInteger,
    mute, print_error, print_info, print_status, print_success, print_warning,
    print_table,
)

_FMS_FINGERPRINTS = {
    "wenco": {
        "headers": ["wenco", "hitachi", "x-wenco", "wms"],
        "paths": ["/", "/login", "/api/v1/status", "/api/v1/fleet", "/api/vehicles"],
        "ports": [8080, 8443, 443, 80],
        "vendor": "Wenco FMS (Hitachi Construction Machinery)",
        "cve": "N/A",
        "risk": "HIGH",
        "notes": "Only FMS vendor with confirmed ISO 27001. Default admin credentials common in legacy deployments.",
    },
    "komatsu": {
        "headers": ["komatsu", "komtrax", "dispatch"],
        "paths": ["/", "/login.html", "/dispatch/", "/api/status"],
        "ports": [8080, 80, 443],
        "vendor": "Komatsu Dispatch / KOMTRAX Plus",
        "cve": "N/A",
        "risk": "HIGH",
        "notes": "AHS (Autonomous Haulage System) control interface. Disruption can halt autonomous truck fleet.",
    },
    "modular": {
        "headers": ["modular mining", "provision", "modmining"],
        "paths": ["/", "/ProVision", "/api/", "/equipment/status"],
        "ports": [8080, 80, 443],
        "vendor": "Modular Mining ProVision",
        "cve": "N/A",
        "risk": "HIGH",
        "notes": "Used by major copper and gold mines. No public CVEs but common misconfigurations.",
    },
    "pitram": {
        "headers": ["pitram", "micromine"],
        "paths": ["/", "/pitram/", "/api/v1/"],
        "ports": [80, 443, 8080],
        "vendor": "MICROMINE Pitram",
        "cve": "N/A",
        "risk": "MEDIUM",
        "notes": "Shift and activity management. Often exposed on corporate network segments.",
    },
}

_UNAUTHENTICATED_PATHS = [
    "/api/v1/status",
    "/api/v1/fleet",
    "/api/vehicles",
    "/api/equipment",
    "/api/shifts",
    "/status",
    "/health",
    "/metrics",
    "/version",
]


def _http_probe(host: str, port: int, path: str, use_tls: bool, timeout: float) -> Optional[Dict]:
    """Send a minimal HTTP GET and return status + headers."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        request = "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".format(
            path, host
        )
        sock.sendall(request.encode())
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
            if len(raw) > 16384:
                break
        sock.close()
        text = raw.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        status = lines[0] if lines else ""
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, _, v = line.partition(": ")
                headers[k.lower()] = v
        body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
        return {"status": status, "headers": headers, "body": body[:2048]}
    except Exception:
        return None


def _identify_fms(resp: Dict) -> Optional[str]:
    """Match response against known FMS fingerprints."""
    if not resp:
        return None
    combined = (
        resp.get("status", "")
        + " ".join(resp.get("headers", {}).values())
        + resp.get("body", "")
    ).lower()
    for name, fp in _FMS_FINGERPRINTS.items():
        if any(h in combined for h in fp["headers"]):
            return name
    return None


class Exploit(Exploit):
    """Fleet Management System (FMS) Scanner for Mining Operations."""

    __info__ = {
        "name":         "Mining FMS Scanner (Wenco, Komatsu, Modular Mining, Pitram)",
        "description":  (
            "Detects and fingerprints Fleet Management Systems used in mining. "
            "Scans for Wenco, Komatsu Dispatch, Modular Mining ProVision, and MICROMINE Pitram "
            "web interfaces. Checks for unauthenticated API endpoints and misconfigurations. "
            "FMS disruption can halt entire autonomous truck fleets without touching the vehicles."
        ),
        "authors":      ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":   (
            "https://miningfms.com/knowledge-base/system-architecture/fms-network-security/",
            "https://blog.aristacyber.io/ot-cybersecurity-mining-operations-remote-sites-autonomous",
            "https://attack.mitre.org/techniques/T0883/",
        ),
        "devices":      (
            "Wenco FMS (Hitachi)",
            "Komatsu Dispatch / KOMTRAX Plus",
            "Caterpillar MineStar Fleet",
            "Modular Mining ProVision",
            "MICROMINE Pitram",
        ),
        "impact":       "READ",
        "exploit_type": "Service Discovery / Configuration Check",
        "cve":          "N/A",
        "cvss":         "N/A",
        "severity":     "INFO",
        "mitre_techniques": ["T0883", "T0846", "T0888"],
        "mitre_tactics":    ["Discovery", "Collection"],
    }

    target   = OptIP("", "Target FMS server IP or hostname")
    timeout  = OptInteger(5, "Connection timeout in seconds")
    check_unauth = __import__("industrialxpl.core.exploit.option", fromlist=["OptBool"]).OptBool(
        True, "Check for unauthenticated API endpoints"
    )

    @mute
    def check(self) -> bool:
        """Return True if any FMS port is open."""
        for _, fp in _FMS_FINGERPRINTS.items():
            for port in fp["ports"]:
                try:
                    sock = socket.create_connection((self.target, port), timeout=2)
                    sock.close()
                    return True
                except Exception:
                    pass
        return False

    def run(self) -> None:
        if not self.target:
            print_error("Set TARGET first.")
            return

        print_status("Scanning {} for Fleet Management System interfaces...".format(self.target))
        print_info("")

        found: List[Dict] = []

        for name, fp in _FMS_FINGERPRINTS.items():
            for port in fp["ports"]:
                use_tls = port in (443, 8443)
                proto = "https" if use_tls else "http"
                url = "{}://{}:{}".format(proto, self.target, port)

                resp = _http_probe(self.target, port, "/", use_tls, self.timeout)
                if resp is None:
                    continue

                fms_name = _identify_fms(resp)
                status_code = re.search(r"HTTP/[\d.]+ (\d+)", resp.get("status", ""))
                code = status_code.group(1) if status_code else "?"
                server = resp.get("headers", {}).get("server", "unknown")

                if fms_name:
                    matched_fp = _FMS_FINGERPRINTS[fms_name]
                    print_success("FMS detected on {}".format(url))
                    print_info("  System  : {}".format(matched_fp["vendor"]))
                    print_info("  HTTP    : {} | Server: {}".format(code, server))
                    print_info("  Risk    : {}".format(matched_fp["risk"]))
                    print_info("  Notes   : {}".format(matched_fp["notes"]))
                    found.append({"url": url, "system": fms_name, "port": port, "fp": matched_fp})
                else:
                    print_info("  {}:{} -> HTTP {} | Server: {} (not FMS fingerprinted)".format(
                        self.target, port, code, server
                    ))

        if self.check_unauth and found:
            print_info("")
            print_status("Checking unauthenticated API endpoints...")
            for entry in found:
                port = entry["port"]
                use_tls = port in (443, 8443)
                for path in _UNAUTHENTICATED_PATHS:
                    resp = _http_probe(self.target, port, path, use_tls, self.timeout)
                    if resp:
                        code_m = re.search(r"HTTP/[\d.]+ (\d+)", resp.get("status", ""))
                        code = code_m.group(1) if code_m else "?"
                        if code in ("200", "201", "204"):
                            body_preview = resp.get("body", "")[:120].replace("\n", " ")
                            print_warning("  UNAUTH  : {} -> HTTP {} | {}".format(
                                path, code, body_preview
                            ))
                        elif code in ("401", "403"):
                            print_info("  AUTH    : {} -> HTTP {} (protected)".format(path, code))

        if not found:
            print_info("No FMS interfaces detected on {}.".format(self.target))
            print_info("Try: search sector=mining for other mining-specific modules.")
        else:
            print_info("")
            print_warning("FMS systems control autonomous fleets worth millions in equipment.")
            print_warning("Unauthorized access can halt operations or cause physical safety incidents.")
