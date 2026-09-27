# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Caterpillar MineStar / Command Unauthenticated API Check.

Caterpillar MineStar is the largest autonomous haulage system (AHS) platform
globally. MineStar Command controls autonomous Cat 793F and 797F haul trucks
(payload: 220-363 tonnes). A single MineStar server can coordinate hundreds of
autonomous vehicles simultaneously.

MineStar components:
  - MineStar Command (AHS -- autonomous haulage)
  - MineStar Fleet (fleet management and dispatch)
  - MineStar Terrain (machine guidance)
  - MineStar Health (equipment monitoring and telematics)
  - MineStar Edge (onboard processing)

Known exposure vectors:
  - Web management interface on TCP/8080 (HTTP) and TCP/4040
  - REST API on /api/minestar/ -- often accessible without session token
    in older installs (pre-2022 security hardening)
  - MineStar Health MQTT telemetry on TCP/1883 (unauthenticated in some configs)
  - CAT LINK portal integration -- third-party supply chain risk

Attack impact:
  - Disrupting MineStar Fleet halts dispatch scheduling for all trucks
  - Corrupting Terrain data causes blade/dozer to grade incorrectly
  - Manipulating AHS waypoints can cause physical collision or off-road events

References:
  - Caterpillar NIST CSF and ISO 27001 alignment (SEC filing 2024)
  - https://www.cat.com/en_US/support/operations/technology-solutions/minestar.html
  - MITRE ATT&CK ICS: T0883, T0836, T0846
"""

import socket
import re
from typing import Optional, Dict, List

from industrialxpl.core.exploit import (
    Exploit, OptIP, OptInteger, OptBool,
    mute, print_error, print_info, print_status, print_success, print_warning,
)

_MINESTAR_PORTS = [8080, 4040, 443, 80, 8443, 9090]

_MINESTAR_API_PATHS = [
    ("/", "Main interface"),
    ("/login", "Login page"),
    ("/api/minestar/status", "System status"),
    ("/api/minestar/fleet", "Fleet status (trucks, excavators)"),
    ("/api/minestar/equipment", "Equipment list"),
    ("/api/minestar/health", "Equipment health telemetry"),
    ("/api/v1/assets", "Asset inventory"),
    ("/api/v1/locations", "Real-time equipment locations"),
    ("/minestar/", "MineStar web root"),
    ("/MineStar/", "MineStar (case variant)"),
    ("/command/", "Command module"),
    ("/fleet/", "Fleet module"),
    ("/terrain/", "Terrain module"),
    ("/health/dashboard", "Health dashboard"),
    ("/actuator/health", "Spring Boot health (Java stack)"),
    ("/actuator/info", "Spring Boot info -- version disclosure"),
    ("/metrics", "Metrics endpoint"),
]

_MINESTAR_FINGERPRINTS = [
    "minestar", "cat command", "caterpillar", "terrain server",
    "minestarkiosk", "fleet management", "autonomous haulage",
    "cat link", "vims", "product link",
]


def _http_probe(host: str, port: int, path: str, use_tls: bool, timeout: float) -> Optional[Dict]:
    """Send HTTP GET and return parsed response."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        req = "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: MineStar-Admin/5.0\r\nConnection: close\r\n\r\n".format(
            path, host
        )
        sock.sendall(req.encode())
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
            if len(raw) > 32768:
                break
        sock.close()
        text = raw.decode("utf-8", errors="replace")
        status_line = text.split("\r\n")[0] if text else ""
        headers = {}
        if "\r\n" in text:
            for line in text.split("\r\n")[1:]:
                if ": " in line:
                    k, _, v = line.partition(": ")
                    headers[k.lower()] = v
        body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
        return {"status": status_line, "headers": headers, "body": body[:4096]}
    except Exception:
        return None


class Exploit(Exploit):
    """Caterpillar MineStar/Command unauthenticated API check."""

    __info__ = {
        "name":         "Caterpillar MineStar / Command API Scanner",
        "description":  (
            "Checks for unauthenticated access to Caterpillar MineStar Fleet, "
            "Command (AHS), Terrain, and Health APIs. MineStar controls autonomous "
            "haul trucks (Cat 793F/797F, 220-363t payload). Unauthorized API access "
            "can expose real-time fleet locations, equipment health, and haulage routes."
        ),
        "authors":      ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":   (
            "https://www.cat.com/en_US/support/operations/technology-solutions/minestar.html",
            "https://miningfms.com/knowledge-base/system-architecture/fms-network-security/",
            "https://attack.mitre.org/techniques/T0883/",
        ),
        "devices":      (
            "Caterpillar MineStar Fleet",
            "Caterpillar MineStar Command (AHS)",
            "Caterpillar MineStar Terrain",
            "Caterpillar MineStar Health",
            "Caterpillar MineStar Edge",
        ),
        "impact":       "READ",
        "exploit_type": "Unauthenticated API Discovery",
        "cve":          "N/A",
        "cvss":         "N/A",
        "severity":     "HIGH",
        "mitre_techniques": ["T0883", "T0836", "T0846", "T0888"],
        "mitre_tactics":    ["Discovery", "Collection"],
    }

    target  = OptIP("", "Target MineStar server IP")
    timeout = OptInteger(5, "Connection timeout in seconds")
    deep    = __import__("industrialxpl.core.exploit.option", fromlist=["OptBool"]).OptBool(
        True, "Check all API paths (deep scan)"
    )

    @mute
    def check(self) -> bool:
        for port in _MINESTAR_PORTS:
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

        print_status("Scanning {} for Caterpillar MineStar interfaces...".format(self.target))
        print_info("")

        open_ports: List[int] = []
        for port in _MINESTAR_PORTS:
            use_tls = port in (443, 8443)
            resp = _http_probe(self.target, port, "/", use_tls, self.timeout)
            if resp is None:
                continue
            code_m = re.search(r"HTTP/[\d.]+ (\d+)", resp.get("status", ""))
            code = code_m.group(1) if code_m else "?"
            body_low = resp.get("body", "").lower()
            server = resp.get("headers", {}).get("server", "unknown")
            is_minestar = any(fp in body_low for fp in _MINESTAR_FINGERPRINTS)
            proto = "https" if use_tls else "http"
            if is_minestar:
                print_success("MineStar confirmed on {}://{}:{} (HTTP {})".format(
                    proto, self.target, port, code
                ))
                open_ports.append(port)
            else:
                print_info("  {}:{} -> HTTP {} | Server: {}".format(
                    self.target, port, code, server
                ))
                open_ports.append(port)

        if not open_ports:
            print_info("No web service found on {}. MineStar may not be installed.".format(self.target))
            return

        if self.deep:
            print_info("")
            print_status("Checking API paths for unauthenticated access...")
            results = []
            for port in open_ports[:2]:
                use_tls = port in (443, 8443)
                for path, desc in _MINESTAR_API_PATHS:
                    resp = _http_probe(self.target, port, path, use_tls, self.timeout)
                    if resp is None:
                        continue
                    code_m = re.search(r"HTTP/[\d.]+ (\d+)", resp.get("status", ""))
                    code = code_m.group(1) if code_m else "?"
                    content_type = resp.get("headers", {}).get("content-type", "")
                    body = resp.get("body", "")[:80].replace("\n", " ")
                    if code in ("200", "201"):
                        print_warning("  UNAUTH {}:{}{} -> HTTP {} ({}) | {}".format(
                            self.target, port, path, code, desc, body
                        ))
                        results.append((path, code, desc))
                    elif code in ("401", "403"):
                        print_info("  AUTH   {}:{}{} -> HTTP {} (protected)".format(
                            self.target, port, path, code
                        ))

            if results:
                print_info("")
                print_warning("{} unauthenticated endpoint(s) found.".format(len(results)))
                print_warning("MineStar Command API exposure can reveal AHS fleet positions and routes.")
            else:
                print_info("All checked endpoints require authentication.")
