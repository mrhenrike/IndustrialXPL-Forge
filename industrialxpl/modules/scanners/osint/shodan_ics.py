"""Shodan ICS/OT Device Discovery Scanner.

Queries the Shodan search engine for OT/ICS devices exposed to the internet
using protocol-specific and vendor-specific search queries.

Uses resources/osint/shodan_ics_dorks.json for the query catalog.
Requires a Shodan API key (free: https://account.shodan.io/)

In simulate mode: prints the queries without calling Shodan API.
"""

import json
from pathlib import Path

from industrialxpl.core.exploit import (
    Exploit,
    OptBool,
    OptInteger,
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

_DORKS_PATH = Path(__file__).resolve().parents[4] / "resources" / "osint" / "shodan_ics_dorks.json"

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


def _load_dorks() -> dict:
    if _DORKS_PATH.exists():
        try:
            return json.loads(_DORKS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


class Exploit(Exploit):
    __info__ = {
        "name":         "Shodan ICS/OT Device Exposure Scanner",
        "description":  "Searches Shodan for OT/ICS devices exposed to the internet using "
                        "protocol-specific and vendor-specific queries. Covers Modbus, S7comm, "
                        "EtherNet/IP, BACnet, DNP3, OPC UA, Unitronics, SCADAPack, Honeywell, "
                        "Siemens, Schneider, and 30+ other vendors. "
                        "Requires Shodan API key (free tier available).",
        "authors":      ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":   (
            "Shodan QuickStart Guide for ICS OT (UtilSec)",
            "ZeronTek OT Hunt research",
            "https://shodan.io",
        ),
        "devices":      ("OSINT tool — internet-exposed OT devices",),
        "impact":       "INFO",
        "exploit_type": "OSINT / Passive Discovery",
        "source_poc":   "IXF native + Shodan API",
        "cve":          "N/A", "cvss": "N/A", "severity": "INFO",
        "mitre_techniques": ["T0883", "T0846"],
        "mitre_tactics":    ["Discovery", "Initial Access"],
    }

    api_key   = OptString("", "Shodan API key (https://account.shodan.io/)")
    category  = OptString("all", "Query category: all | protocols | vendors | attack_surface")
    vendor    = OptString("", "Specific vendor (e.g. siemens, schneider, unitronics)")
    max_results = OptInteger(10, "Max results per query (Shodan free: 100)")
    simulate  = OptBool(True, "Simulate mode (default: True — prints queries, no API call)")
    destructive = OptBool(False, "N/A — passive OSINT only")

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        dorks = _load_dorks()
        if not dorks:
            print_error("Could not load shodan_ics_dorks.json from resources/osint/")
            return

        # Build query list
        queries = []
        cat = self.category.lower()
        vendor_filter = self.vendor.lower()

        if vendor_filter:
            vendor_queries = dorks.get("vendors", {}).get(vendor_filter, [])
            if vendor_queries:
                queries = [(vendor_filter, q) for q in vendor_queries[:3]]
            else:
                print_error("Vendor '{}' not found in dork catalog. Available: {}".format(
                    vendor_filter, ", ".join(list(dorks.get("vendors", {}).keys())[:10])
                ))
                return
        elif cat in ("protocols", "all"):
            for proto, qs in list(dorks.get("protocols", {}).items())[:5]:
                queries.extend([(proto, q) for q in qs[:1]])
        elif cat == "vendors":
            for v, qs in list(dorks.get("vendors", {}).items())[:5]:
                queries.extend([(v, q) for q in qs[:1]])
        elif cat == "attack_surface":
            for surface, qs in dorks.get("attack_surface", {}).items():
                queries.extend([(surface, q) for q in qs[:2]])

        if not queries:
            print_error("No queries to run for category={}".format(cat))
            return

        if self.simulate:
            print_info("[Shodan ICS] Queries that would be executed:")
            rows = [(label[:30], query[:50]) for label, query in queries[:10]]
            print_table(["Category", "Shodan Query"], rows, title="Shodan ICS Dorks Preview")
            DestructiveGate.print_simulation(
                description=(
                    "Would send {} Shodan API queries, collecting up to {} results each. "
                    "Set api_key and simulate=false to execute real searches.".format(
                        len(queries), self.max_results
                    )
                ),
                mitre_techniques=["T0883"],
            )
            return

        if not self.api_key:
            print_error("Set 'api_key' option with your Shodan API key.")
            print_info("Get free API key: https://account.shodan.io/")
            return

        if not _HAS_REQUESTS:
            print_error("'requests' library required: pip install requests")
            return

        print_status("[Shodan ICS] Executing {} queries…".format(len(queries)))
        all_results = []

        for label, query in queries[:5]:
            url = "https://api.shodan.io/shodan/host/search"
            try:
                resp = _requests.get(url, params={
                    "key": self.api_key,
                    "query": query,
                    "minify": True,
                }, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    total = data.get("total", 0)
                    matches = data.get("matches", [])[:self.max_results]
                    print_success("[Shodan] '{}': {} results".format(query, total))
                    for match in matches[:5]:
                        ip = match.get("ip_str", "")
                        port = match.get("port", "")
                        org = match.get("org", "unknown")
                        country = match.get("location", {}).get("country_name", "")
                        all_results.append((ip, str(port), org[:20], country[:15], label[:20]))
                elif resp.status_code == 401:
                    print_error("Invalid Shodan API key.")
                    return
                else:
                    print_warning("[Shodan] HTTP {} for query: {}".format(resp.status_code, query))
            except Exception as exc:
                print_error("[Shodan] Error: {}".format(exc))

        if all_results:
            print_table(
                ["IP", "Port", "Organization", "Country", "Category"],
                all_results,
                title="Shodan ICS Results (Top {})".format(len(all_results)),
            )
            print_warning("These are REAL internet-exposed OT devices. Handle responsibly.")
        else:
            print_info("No results returned.")
