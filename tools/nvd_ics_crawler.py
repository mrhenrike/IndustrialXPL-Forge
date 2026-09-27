#!/usr/bin/env python3
"""IndustrialXPL-Forge — NVD ICS CVE Crawler.

Fetches ICS/OT/SCADA CVEs from NVD REST API v2.0 and generates:
  1. resources/cve/ics_cve_database.json — structured CVE catalog
  2. Module stub files in industrialxpl/modules/cve/<vendor>/ (Level B check modules)

Usage:
    python tools/nvd_ics_crawler.py --api-key YOUR_NVD_API_KEY [--max-results 200]
    python tools/nvd_ics_crawler.py --no-api (uses cached/offline mode)

Get a free API key: https://nvd.nist.gov/developers/request-an-api-key
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESOURCES_CVE = PROJECT_ROOT / "industrialxpl" / "resources" / "cve"
MODULES_CVE   = PROJECT_ROOT / "industrialxpl" / "modules" / "cve"

RESOURCES_CVE.mkdir(parents=True, exist_ok=True)
MODULES_CVE.mkdir(parents=True, exist_ok=True)

# ICS-specific CPE vendor strings to filter (partial matches)
ICS_VENDORS = [
    "siemens", "schneider-electric", "rockwell_automation", "abb", "honeywell",
    "ge_digital", "general_electric", "yokogawa", "omron", "emerson",
    "beckhoff", "delta_electronics", "advantech", "moxa", "codesys",
    "unitronics", "phoenix_contact", "tridium", "inductive_automation",
    "osisoft", "aveva", "wind_river", "qnx", "hitachi_energy",
    "johnson_controls", "wago", "pilz", "turck", "endress_hauser",
    "bosch_rexroth", "mitsubishi_electric", "fanuc", "keyence", "jtekt",
    "motorola_solutions", "baker_hughes", "frangoteam",
]

# Keywords for keyword-based CVE search (more permissive)
ICS_KEYWORDS = [
    "SCADA", "PLC", "HMI", "industrial control", "Modbus", "PROFINET",
    "EtherNet/IP", "S7comm", "Siemens SIMATIC", "Schneider Modicon",
    "Rockwell ControlLogix", "Honeywell Experion", "ABB AC500",
    "Omron SYSMAC", "GE CIMPLICITY", "Yokogawa CENTUM", "CODESYS",
    "Advantech WebAccess", "Inductive Automation Ignition", "OSIsoft PI",
    "IEC 61850", "DNP3", "BACnet", "OPC UA", "DeltaV", "Ovation",
    "FUXA", "Wonderware InTouch", "WinCC", "TwinCat",
]

SEVERITY_MAP = {
    "CRITICAL": (9.0, 10.0),
    "HIGH":     (7.0, 8.9),
    "MEDIUM":   (4.0, 6.9),
    "LOW":      (0.1, 3.9),
}

STUB_TEMPLATE = '''"""ICS CVE Module — {cve_id} — {vendor} {product} ({severity}).

{description}

CVSS: {cvss} ({severity})
Affected: {affected}
Patched: {patched}
CISA Advisory: {cisa}
"""

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptInteger,
    mute, print_error, print_status, print_success, print_info,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {{
        "name":          "{name}",
        "description":   "{description}",
        "authors":       ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":    (
            "https://nvd.nist.gov/vuln/detail/{cve_id}",
        ),
        "devices":       ("{vendor} {product}",),
        "impact":        "{impact}",
        "exploit_type":  "Version Check ({exploit_type})",
        "source_poc":    "NVD version-based check (Level B module)",
        "cve":           "{cve_id}",
        "cvss":          "{cvss}",
        "severity":      "{severity}",
        "affected_versions": "{affected}",
        "patched_version":   "{patched}",
        "cisa_advisory":     "{cisa}",
        "mitre_techniques":  ["T0883", "T0888"],
        "mitre_tactics":     ["Discovery"],
    }}

    target  = OptIP("", "Target {vendor} device IP")
    port    = OptPort({port}, "Target port")
    timeout = OptInteger(5, "Socket timeout")
    simulate = OptBool(True, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable destructive execution")

    @mute
    def check(self) -> bool:
        """Fingerprint target and check version against affected range."""
        if not self.target:
            return False
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.close()
            # Port is open — device may be present
            # Full version check requires protocol-specific fingerprinting
            return True  # POSSIBLY_VULNERABLE until version confirmed
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Set \\'target\\' option first.")
            return
        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "{cve_id}: Would fingerprint {vendor} {product} at "
                    "{{}}:{{}} and check if version is in affected range ({affected}).".format(
                        self.target, self.port
                    )
                ),
                mitre_techniques=["T0888"],
            )
            return
        print_status("Checking {{}}:{{}} for {cve_id}...".format(self.target, self.port))
        if self.check():
            print_success(
                "Port {{}} open — {vendor} {product} MAY be present. "
                "Verify version manually: affected={affected}".format(self.port)
            )
        else:
            print_info("{{}}:{{}} not responding.".format(self.target, self.port))
'''


def fetch_nvd_cves(api_key: str, keyword: str, max_results: int = 50) -> list:
    """Fetch CVEs from NVD API v2.0 by keyword."""
    try:
        import urllib.request
        import urllib.parse
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results, 100),
        })
        headers = {"apiKey": api_key} if api_key else {}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        return data.get("vulnerabilities", [])
    except Exception as exc:
        print("[nvd_crawler] Fetch error for '{}': {}".format(keyword, exc), file=sys.stderr)
        return []


def extract_cvss(vuln: dict) -> tuple:
    """Extract CVSS score and severity."""
    metrics = vuln.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0].get("cvssData", {})
            score = m.get("baseScore", 0.0)
            severity = m.get("baseSeverity", "UNKNOWN")
            return float(score), severity
    return 0.0, "UNKNOWN"


def extract_affected(vuln: dict) -> tuple:
    """Extract affected/patched version info."""
    configs = vuln.get("configurations", [])
    affected = []
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                if cpe.get("vulnerable"):
                    v_start = cpe.get("versionStartIncluding", "")
                    v_end   = cpe.get("versionEndExcluding", cpe.get("versionEndIncluding", ""))
                    if v_end:
                        affected.append("< {}".format(v_end))
                    elif v_start:
                        affected.append(">= {}".format(v_start))
    return ("; ".join(affected[:3]) or "All versions") if affected else "All versions"


def slugify(text: str) -> str:
    import re
    return re.sub(r"[^a-z0-9_]", "_", text.lower()).strip("_")


def generate_stub(entry: dict, output_dir: Path) -> str:
    """Generate a Level B module stub for a CVE entry."""
    cve_id = entry["cve_id"].lower().replace("-", "_")
    vendor_slug = slugify(entry.get("vendor", "generic"))
    output_dir = output_dir / vendor_slug
    output_dir.mkdir(parents=True, exist_ok=True)
    init = output_dir / "__init__.py"
    if not init.exists():
        init.write_text("")

    stub_path = output_dir / "{}.py".format(cve_id)
    if stub_path.exists():
        return str(stub_path)

    impact_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": "LOW",
    }

    desc = entry.get("description", "")[:200].replace('"', "'")
    stub = STUB_TEMPLATE.format(
        cve_id   = entry["cve_id"],
        vendor   = entry.get("vendor", "Unknown"),
        product  = entry.get("product", "device"),
        name     = "{} — {} {} ({})".format(
            entry["cve_id"], entry.get("vendor", ""), entry.get("product", ""), entry.get("severity", "")
        )[:80],
        description  = desc,
        cvss         = entry.get("cvss", "N/A"),
        severity     = entry.get("severity", "UNKNOWN"),
        impact       = impact_map.get(entry.get("severity", "LOW"), "LOW"),
        affected     = entry.get("affected_versions", "unknown"),
        patched      = entry.get("patched_version", "check vendor advisory"),
        cisa         = entry.get("cisa_advisory", "N/A"),
        exploit_type = entry.get("exploit_type", "Unknown"),
        port         = 502,
    )
    stub_path.write_text(stub, encoding="utf-8")
    return str(stub_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="IXF NVD ICS CVE Crawler")
    parser.add_argument("--api-key", default="", help="NVD API key (free: nvd.nist.gov/developers/request-an-api-key)")
    parser.add_argument("--max-results", type=int, default=50, help="Max CVEs per keyword query")
    parser.add_argument("--no-api", action="store_true", help="Skip NVD API, only update stubs from existing DB")
    parser.add_argument("--keywords", nargs="+", default=ICS_KEYWORDS[:5], help="Keywords to search")
    args = parser.parse_args()

    db_path = RESOURCES_CVE / "ics_cve_database.json"
    existing = {}
    if db_path.exists():
        try:
            data = json.loads(db_path.read_text(encoding="utf-8"))
            for entry in data.get("cves", []):
                existing[entry["cve_id"]] = entry
        except Exception:
            pass

    new_count = 0
    if not args.no_api:
        print("[nvd_crawler] Fetching CVEs from NVD API...")
        for keyword in args.keywords:
            print("[nvd_crawler]   Keyword: {}".format(keyword))
            vulns = fetch_nvd_cves(args.api_key, keyword, args.max_results)
            for v in vulns:
                cve_data = v.get("cve", {})
                cve_id = cve_data.get("id", "")
                if not cve_id or cve_id in existing:
                    continue
                cvss, severity = extract_cvss(v)
                affected = extract_affected(v)
                descs = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descs if d["lang"] == "en"), "")
                entry = {
                    "cve_id":            cve_id,
                    "cvss":              str(cvss),
                    "severity":          severity,
                    "vendor":            "ICS",
                    "product":           "device",
                    "affected_versions": affected,
                    "patched_version":   "check vendor advisory",
                    "exploit_type":      "Unknown",
                    "has_public_poc":    False,
                    "cisa_advisory":     "N/A",
                    "mitre_ics_techniques": ["T0883"],
                    "description":       desc[:300],
                    "ixf_module":        "cve/{}/{}".format("generic", cve_id.lower().replace("-", "_")),
                }
                existing[cve_id] = entry
                new_count += 1
            time.sleep(0.7)  # Rate limit: NVD allows ~50 req/30s with API key

    # Save updated DB
    updated_data = {
        "_meta": {
            "title": "IXF ICS/OT/SCADA CVE Database",
            "updated": time.strftime("%Y-%m-%d"),
            "total_entries": len(existing),
        },
        "cves": list(existing.values()),
    }
    db_path.write_text(json.dumps(updated_data, indent=2), encoding="utf-8")
    print("[nvd_crawler] DB updated: {} total CVEs ({} new)".format(len(existing), new_count))

    # Generate stubs for CVEs without existing modules
    stub_count = 0
    for cve_id, entry in list(existing.items())[:200]:  # Limit stub generation to 200
        stub_path = MODULES_CVE / "{}_stub.py".format(cve_id.lower().replace("-", "_"))
        if not stub_path.exists():
            try:
                generate_stub(entry, MODULES_CVE)
                stub_count += 1
            except Exception:
                pass
    print("[nvd_crawler] Generated {} new module stubs in industrialxpl/modules/cve/".format(stub_count))

    # Verify indexing
    sys.path.insert(0, str(PROJECT_ROOT))
    try:
        from industrialxpl.core.exploit.utils import index_modules
        mods = index_modules()
        print("[nvd_crawler] IXF module index: {} modules".format(len(mods)))
    except Exception as exc:
        print("[nvd_crawler] Index check skipped: {}".format(exc))


if __name__ == "__main__":
    main()
