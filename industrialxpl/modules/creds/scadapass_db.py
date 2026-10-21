"""SCADAPASS: Default credentials database for ICS/SCADA/OT devices.

Comprehensive database of factory-default credentials for industrial
control systems, PLCs, RTUs, HMIs, SCADA servers, engineering workstations,
network switches, gateways, IIoT appliances, and OT-adjacent devices.

All credential data is loaded from resources/wordlists/scadapass_full_export.csv
at import time. No credentials are stored in Python source code.

Sources:
  - SCADAPASS project by SCADA StrangeLove (public domain ICS credential lists)
  - Vendor documentation, manuals, and security advisories
  - ICS-CERT / CISA advisories on default credentials
  - CISA ICS-CERT Alert TA17-156A (Default Credentials)
  - CVE entries with hardcoded/default credential references
  - Mirai botnet source code (scanner.c credential table)
  - SecLists project (danielmiessler/SecLists)
  - Nessus/Tenable ICS default credential plugins
  - Shodan/Censys ICS exposure research

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import csv
import io
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptString,
    print_error, print_info, print_status, print_success, print_warning,
)

log = logging.getLogger(__name__)

_WORDLISTS_DIR = Path(__file__).resolve().parents[2] / "resources" / "wordlists"
_CSV_FILE = _WORDLISTS_DIR / "scadapass_full_export.csv"


class CredCategory(str, Enum):
    PLC = "plc"
    RTU = "rtu"
    DCS = "dcs"
    HMI = "hmi"
    SCADA = "scada"
    EWS = "ews"
    SWITCH = "switch"
    ROUTER = "router"
    GATEWAY = "gateway"
    FIREWALL_OT = "firewall_ot"
    IED = "ied"
    RELAY = "relay"
    METER = "meter"
    DRIVE = "drive"
    ROBOT = "robot"
    IIOT = "iiot"
    HISTORIAN = "historian"
    PROTOCOL = "protocol"
    SNMP = "snmp"
    BOTNET = "botnet"
    BMS = "bms"
    UPS = "ups"
    SERIAL = "serial_device"
    CAMERA = "camera"
    NAS = "nas"
    PRINTER = "printer"


@dataclass
class DefaultCredential:
    """A single default credential entry."""
    vendor: str
    product: str
    protocol: str
    port: int
    username: str
    password: str
    access_level: str = "admin"
    notes: str = ""
    cve: str = ""
    verified: bool = True
    category: str = ""


def _load_csv_db() -> list[DefaultCredential]:
    """Load the credential database from the CSV file."""
    if not _CSV_FILE.is_file():
        log.warning("SCADAPASS CSV not found: %s", _CSV_FILE)
        return []
    entries: list[DefaultCredential] = []
    with open(_CSV_FILE, encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            try:
                port = int(row.get("Port", "0") or "0")
            except ValueError:
                port = 0
            entries.append(DefaultCredential(
                vendor=row.get("Vendor", ""),
                product=row.get("Product", ""),
                protocol=row.get("Protocol", ""),
                port=port,
                username=row.get("Username", ""),
                password=row.get("Password", ""),
                access_level=row.get("Access Level", "admin"),
                notes=row.get("Notes", ""),
                cve=row.get("CVE", ""),
                category=row.get("Category", ""),
            ))
    return entries


CREDENTIAL_DB: list[DefaultCredential] = _load_csv_db()


# ---------------------------------------------------------------------------
# Search / query functions
# ---------------------------------------------------------------------------

def search_by_vendor(vendor: str) -> list[DefaultCredential]:
    """Find credentials by vendor name (case-insensitive partial match)."""
    v = vendor.lower()
    return [c for c in CREDENTIAL_DB if v in c.vendor.lower()]


def search_by_product(product: str) -> list[DefaultCredential]:
    """Find credentials by product name (case-insensitive partial match)."""
    p = product.lower()
    return [c for c in CREDENTIAL_DB if p in c.product.lower()]


def search_by_protocol(protocol: str) -> list[DefaultCredential]:
    """Find credentials by protocol (case-insensitive partial match)."""
    p = protocol.lower()
    return [c for c in CREDENTIAL_DB if p in c.protocol.lower()]


def search_by_port(port: int) -> list[DefaultCredential]:
    """Find credentials by port number."""
    return [c for c in CREDENTIAL_DB if c.port == port]


def search_by_category(category: str) -> list[DefaultCredential]:
    """Find credentials by device category (plc, rtu, hmi, switch, etc.)."""
    cat = category.lower()
    return [c for c in CREDENTIAL_DB if cat in c.category.lower()]


def search_by_cve(cve_id: str) -> list[DefaultCredential]:
    """Find credentials associated with a specific CVE."""
    cve = cve_id.upper()
    return [c for c in CREDENTIAL_DB if cve in c.cve.upper()]


def get_all_vendors() -> list[str]:
    """Return sorted list of unique vendors."""
    return sorted(set(c.vendor for c in CREDENTIAL_DB))


def get_all_categories() -> list[str]:
    """Return sorted list of unique categories."""
    return sorted(set(c.category for c in CREDENTIAL_DB if c.category))


def get_mirai_wordlist() -> list[tuple[str, str]]:
    """Return the Mirai botnet credential pairs as (username, password) tuples."""
    return [(c.username, c.password) for c in CREDENTIAL_DB
            if c.vendor == "(Mirai)"]


def get_snmp_communities() -> list[str]:
    """Return all SNMP community strings from the database."""
    return [c.username for c in CREDENTIAL_DB
            if c.protocol == "SNMP" and c.username]


def get_stats() -> dict[str, int]:
    """Return database statistics."""
    vendors = set(c.vendor for c in CREDENTIAL_DB
                  if not c.vendor.startswith("("))
    return {
        "total_entries": len(CREDENTIAL_DB),
        "unique_vendors": len(vendors),
        "unique_products": len(set(c.product for c in CREDENTIAL_DB)),
        "protocols_with_no_auth": sum(1 for c in CREDENTIAL_DB
                                      if c.vendor == "(Protocol)"),
        "mirai_pairs": sum(1 for c in CREDENTIAL_DB
                           if c.vendor == "(Mirai)"),
        "snmp_communities": sum(1 for c in CREDENTIAL_DB
                                if c.category == "snmp"),
        "entries_with_cve": sum(1 for c in CREDENTIAL_DB if c.cve),
    }


def export_csv() -> str:
    """Export the credential database as CSV string."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Vendor", "Product", "Protocol", "Port",
                     "Username", "Password", "Access Level", "Notes",
                     "CVE", "Category"])
    for c in CREDENTIAL_DB:
        writer.writerow([c.vendor, c.product, c.protocol, c.port,
                         c.username, c.password, c.access_level, c.notes,
                         c.cve, c.category])
    return out.getvalue()


# ---------------------------------------------------------------------------
# Exploit module interface
# ---------------------------------------------------------------------------

class SCADAPassDB(Exploit):
    """ICS/SCADA default credential database lookup."""

    __info__ = {
        "name": "SCADAPASS DB",
        "description": (
            "Default credential database for ICS/SCADA/OT devices, protocols, "
            "SNMP communities, and IoT botnet wordlists (Mirai). "
            "Covers 60+ manufacturers, 30+ protocols, and 350+ credential entries."
        ),
        "authors": ["Andre Henrique (@mrhenrike)"],
        "references": [
            "CISA ICS-CERT Alert TA17-156A",
            "ICS-CERT Advisory ICSA-15-258-01",
            "SCADAPASS project (SCADA StrangeLove)",
            "CVE-2023-6448 (Unitronics Vision/Samba)",
            "CVE-2022-31806 (CODESYS V2 no auth)",
            "CVE-2022-30314 (Honeywell Safety Manager hardcoded)",
            "CVE-2013-0694 (Emerson ROC800 hardcoded)",
            "CVE-2016-5645 (Rockwell MicroLogix SNMP)",
            "Mirai botnet source (scanner.c credential table)",
        ],
        "mitre_techniques": ["T0812", "T0859", "T0886"],
        "mitre_tactics": ["Credential Access", "Initial Access"],
    }

    query = OptString("", "Search query (vendor, product, protocol, category, or CVE)")
    search_type = OptString("vendor",
                            "Search by: vendor, product, protocol, port, category, cve, "
                            "mirai, snmp, stats, all")
    export = OptBool(False, "Export full database as CSV")

    def run(self) -> list[DefaultCredential]:
        if self.export:
            csv_data = export_csv()
            stats = get_stats()
            print_info(f"Exported {stats['total_entries']} entries "
                       f"({stats['unique_vendors']} vendors)")
            return CREDENTIAL_DB

        q = self.query
        stype = self.search_type.lower()

        if stype == "stats":
            stats = get_stats()
            print_status("SCADAPASS Database Statistics:")
            for key, val in stats.items():
                print_info(f"  {key}: {val}")
            return []

        if stype == "mirai":
            results = [c for c in CREDENTIAL_DB if c.vendor == "(Mirai)"]
        elif stype == "snmp":
            results = [c for c in CREDENTIAL_DB if c.category == "snmp"]
        elif stype == "all" or not q:
            results = CREDENTIAL_DB
        elif stype == "vendor":
            results = search_by_vendor(q)
        elif stype == "product":
            results = search_by_product(q)
        elif stype == "protocol":
            results = search_by_protocol(q)
        elif stype == "port":
            results = search_by_port(int(q))
        elif stype == "category":
            results = search_by_category(q)
        elif stype == "cve":
            results = search_by_cve(q)
        else:
            results = search_by_vendor(q) + search_by_product(q)

        print_status(f"SCADAPASS: {len(results)} credential entries found for '{q}'")
        for c in results:
            user = c.username if c.username else "(empty)"
            pwd = c.password if c.password else "(empty)"
            cat = f" ({c.category})" if c.category else ""
            cve_tag = f" [{c.cve}]" if c.cve else ""
            print_info(f"  {c.vendor:20s} {c.product:30s} {c.protocol:12s} "
                       f":{c.port:<6d} {user}:{pwd} [{c.access_level}]"
                       f"{cat}{cve_tag}")
            if c.notes:
                print_info(f"    Note: {c.notes}")

        return results


MANIFEST = {
    "name": "scadapass_db",
    "category": "creds",
    "entry_count": len(CREDENTIAL_DB),
    "vendors": len(set(c.vendor for c in CREDENTIAL_DB if not c.vendor.startswith("("))),
    "mitre_ics": ["T0812", "T0859", "T0886"],
}
