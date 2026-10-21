"""SCADAPASS: Default credentials database for ICS/SCADA/OT devices.

Comprehensive database of factory-default credentials for industrial
control systems, PLCs, RTUs, HMIs, SCADA servers, engineering workstations,
network switches, and ICS-specific appliances.

Sources:
  - SCADAPASS project (public domain ICS credential lists)
  - Vendor documentation and security advisories
  - ICS-CERT advisories on default credentials
  - CISA ICS-CERT Alert TA17-156A (Default Credentials)

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import csv
import io
import logging
from dataclasses import dataclass, field
from typing import Optional

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptString,
    print_error, print_info, print_status, print_success, print_warning,
)

log = logging.getLogger(__name__)


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


# ---------------------------------------------------------------------------
# Embedded credential database
# ---------------------------------------------------------------------------

CREDENTIAL_DB: list[DefaultCredential] = [
    # Siemens
    DefaultCredential("Siemens", "S7-300/400", "S7comm", 102, "", "", "full", "No auth by default"),
    DefaultCredential("Siemens", "S7-1200 Web", "HTTP", 80, "admin", "admin", "admin"),
    DefaultCredential("Siemens", "S7-1500 Web", "HTTPS", 443, "admin", "", "admin", "Empty password default"),
    DefaultCredential("Siemens", "WinCC", "HTTP", 80, "administrator", "", "admin"),
    DefaultCredential("Siemens", "WinCC OA", "HTTP", 4999, "root", "", "admin"),
    DefaultCredential("Siemens", "SCALANCE X", "HTTP", 80, "admin", "admin", "admin", "Industrial switch"),
    DefaultCredential("Siemens", "SCALANCE W", "HTTP", 80, "admin", "admin", "admin", "Wireless AP"),
    DefaultCredential("Siemens", "SINEMA Server", "HTTPS", 443, "admin", "admin", "admin"),
    DefaultCredential("Siemens", "TIA Portal", "OPC-UA", 4840, "", "", "read", "OPC-UA no auth"),
    DefaultCredential("Siemens", "LOGO!", "HTTP", 80, "admin", "admin", "admin"),

    # Allen-Bradley / Rockwell
    DefaultCredential("Rockwell", "ControlLogix", "EtherNet/IP", 44818, "", "", "full", "No auth default"),
    DefaultCredential("Rockwell", "CompactLogix", "EtherNet/IP", 44818, "", "", "full", "No auth default"),
    DefaultCredential("Rockwell", "MicroLogix 1100", "HTTP", 80, "admin", "1234", "admin"),
    DefaultCredential("Rockwell", "PanelView Plus", "HTTP", 80, "admin", "", "admin"),
    DefaultCredential("Rockwell", "FactoryTalk View SE", "HTTP", 80, "admin", "", "admin"),
    DefaultCredential("Rockwell", "Stratix 5700", "SSH", 22, "admin", "admin", "admin", "Managed switch"),

    # Schneider Electric
    DefaultCredential("Schneider", "Modicon M340", "Modbus", 502, "", "", "full", "No Modbus auth"),
    DefaultCredential("Schneider", "Modicon M580", "Modbus", 502, "", "", "full", "No Modbus auth"),
    DefaultCredential("Schneider", "Quantum", "Modbus", 502, "", "", "full"),
    DefaultCredential("Schneider", "Unity Pro", "HTTP", 80, "USER", "USER", "engineer"),
    DefaultCredential("Schneider", "ClearSCADA", "HTTPS", 443, "admin", "admin", "admin"),
    DefaultCredential("Schneider", "ION 7650", "HTTP", 80, "ADMIN", "0", "admin", "Power meter"),
    DefaultCredential("Schneider", "PowerLogic PM800", "HTTP", 80, "admin", "admin", "admin"),
    DefaultCredential("Schneider", "Magelis HMI", "HTTP", 80, "USER", "USER", "operator"),
    DefaultCredential("Schneider", "APC UPS (NMC)", "HTTP", 80, "apc", "apc", "admin"),

    # ABB
    DefaultCredential("ABB", "AC500", "HTTP", 80, "admin", "admin", "admin"),
    DefaultCredential("ABB", "AC800M", "OPC-UA", 4840, "", "", "read"),
    DefaultCredential("ABB", "Freelance", "HTTP", 80, "admin", "admin", "admin"),
    DefaultCredential("ABB", "REF615", "HTTP", 80, "admin", "admin", "admin", "Protection relay"),
    DefaultCredential("ABB", "RTU560", "HTTP", 80, "admin", "admin", "admin"),
    DefaultCredential("ABB", "Symphony Plus", "HTTP", 80, "ADMIN", "ADMIN", "admin"),

    # GE
    DefaultCredential("GE", "Mark VIe", "HTTP", 80, "admin", "admin", "admin", "Turbine control"),
    DefaultCredential("GE", "PACSystems RX3i", "SRTP", 18245, "", "", "full", "No auth"),
    DefaultCredential("GE", "Cimplicity", "HTTP", 80, "admin", "", "admin"),
    DefaultCredential("GE", "iFIX", "HTTP", 80, "admin", "", "admin"),
    DefaultCredential("GE", "Multilin 850", "HTTP", 80, "admin", "admin", "admin", "Protection relay"),

    # Honeywell
    DefaultCredential("Honeywell", "Experion PKS", "HTTP", 80, "ADMIN", "ADMIN", "admin"),
    DefaultCredential("Honeywell", "C300 Controller", "HTTP", 80, "admin", "1234", "admin"),

    # Emerson / Fisher
    DefaultCredential("Emerson", "DeltaV", "HTTP", 80, "admin", "admin", "admin"),
    DefaultCredential("Emerson", "DeltaV SIS", "HTTP", 80, "admin", "deltav", "admin"),
    DefaultCredential("Emerson", "ROC800", "Serial", 0, "LOI", "1000", "engineer"),
    DefaultCredential("Emerson", "OpenBSI", "HTTP", 80, "admin", "", "admin"),

    # Yokogawa
    DefaultCredential("Yokogawa", "CENTUM VP", "HTTP", 20171, "admin", "admin", "admin"),
    DefaultCredential("Yokogawa", "ProSafe-RS", "HTTP", 80, "admin", "admin", "admin"),
    DefaultCredential("Yokogawa", "STARDOM", "HTTP", 80, "admin", "admin", "admin"),

    # Mitsubishi
    DefaultCredential("Mitsubishi", "MELSEC-Q", "MELSEC", 5007, "", "", "full", "No auth"),
    DefaultCredential("Mitsubishi", "MELSEC iQ-R", "MELSEC", 5007, "", "", "full"),
    DefaultCredential("Mitsubishi", "GOT2000 HMI", "HTTP", 80, "admin", "", "admin"),

    # Omron
    DefaultCredential("Omron", "CJ2M", "FINS", 9600, "", "", "full", "No FINS auth"),
    DefaultCredential("Omron", "NJ/NX Series", "HTTP", 80, "admin", "admin", "admin"),
    DefaultCredential("Omron", "NA Series HMI", "HTTP", 80, "admin", "", "admin"),

    # WAGO
    DefaultCredential("WAGO", "PFC200", "HTTP", 80, "admin", "wago", "admin"),
    DefaultCredential("WAGO", "PFC100", "HTTP", 80, "admin", "wago", "admin"),

    # Phoenix Contact
    DefaultCredential("Phoenix Contact", "ILC 2050", "HTTP", 80, "admin", "admin", "admin"),
    DefaultCredential("Phoenix Contact", "AXC F 2152", "HTTP", 80, "admin", "", "admin"),

    # Beckhoff
    DefaultCredential("Beckhoff", "TwinCAT", "ADS", 48898, "", "", "full", "No ADS auth default"),
    DefaultCredential("Beckhoff", "CX Series", "HTTP", 80, "admin", "1", "admin"),

    # CODESYS
    DefaultCredential("CODESYS", "Runtime V3", "HTTP", 8080, "admin", "", "admin"),
    DefaultCredential("CODESYS", "Runtime V2", "TCP", 1200, "", "", "full", "No auth on control port"),

    # Moxa
    DefaultCredential("Moxa", "NPort", "HTTP", 80, "admin", "", "admin"),
    DefaultCredential("Moxa", "NPort", "Telnet", 23, "admin", "", "admin"),
    DefaultCredential("Moxa", "EDS-408A", "HTTP", 80, "admin", "", "admin", "Industrial switch"),
    DefaultCredential("Moxa", "MGate", "HTTP", 80, "admin", "", "admin", "Protocol gateway"),
    DefaultCredential("Moxa", "ioLogik E1210", "HTTP", 80, "admin", "", "admin"),

    # Advantech
    DefaultCredential("Advantech", "WebAccess", "HTTP", 80, "admin", "admin", "admin"),
    DefaultCredential("Advantech", "ADAM-6000", "HTTP", 80, "admin", "admin", "admin"),

    # Delta Electronics
    DefaultCredential("Delta", "DVP Series PLC", "Modbus", 502, "", "", "full"),
    DefaultCredential("Delta", "DOP Series HMI", "HTTP", 80, "admin", "admin", "admin"),
    DefaultCredential("Delta", "InfraSuite", "HTTP", 80, "admin", "admin", "admin"),

    # Bosch Rexroth
    DefaultCredential("Bosch Rexroth", "ctrlX CORE", "HTTPS", 443, "boschrexroth", "boschrexroth", "admin"),
    DefaultCredential("Bosch Rexroth", "IndraControl XM", "HTTP", 80, "admin", "admin", "admin"),

    # FANUC
    DefaultCredential("FANUC", "R-30iB", "HTTP", 80, "admin", "", "admin", "Robot controller"),
    DefaultCredential("FANUC", "ROBOGUIDE", "HTTP", 80, "", "", "read"),

    # Protocol-specific (no authentication by design)
    DefaultCredential("(Protocol)", "Modbus TCP", "Modbus", 502, "", "", "full",
                      "No auth in protocol spec; any node can R/W"),
    DefaultCredential("(Protocol)", "S7comm", "S7comm", 102, "", "", "full",
                      "No auth in standard mode; PLC memory R/W"),
    DefaultCredential("(Protocol)", "BACnet/IP", "BACnet", 47808, "", "", "full",
                      "No auth; R/W any object property"),
    DefaultCredential("(Protocol)", "EtherNet/IP CIP", "CIP", 44818, "", "", "full",
                      "No implicit message auth"),
    DefaultCredential("(Protocol)", "DNP3", "DNP3", 20000, "", "", "full",
                      "Pre-SA has no auth; inject commands"),
    DefaultCredential("(Protocol)", "IEC 60870-5-104", "IEC104", 2404, "", "", "full",
                      "No auth; STARTDT accepted"),
    DefaultCredential("(Protocol)", "OPC DA/Classic", "DCOM", 135, "", "", "varies",
                      "DCOM-based; often misconfigured"),
    DefaultCredential("(Protocol)", "PROFINET IO", "PROFINET", 34964, "", "", "full",
                      "No auth on IO data exchange"),
    DefaultCredential("(Protocol)", "FINS (Omron)", "FINS", 9600, "", "", "full",
                      "No auth on FINS commands"),
    DefaultCredential("(Protocol)", "MELSEC (Mitsubishi)", "MELSEC", 5007, "", "", "full",
                      "No auth on binary protocol"),
    DefaultCredential("(Protocol)", "ADS (Beckhoff)", "ADS", 48898, "", "", "full",
                      "No auth; direct PLC memory access"),
    DefaultCredential("(Protocol)", "MQTT", "MQTT", 1883, "", "", "varies",
                      "Often deployed without auth in OT"),
    DefaultCredential("(Protocol)", "CoAP", "CoAP", 5683, "", "", "varies",
                      "UDP REST-like; often no auth"),
]


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


def get_all_vendors() -> list[str]:
    """Return sorted list of unique vendors."""
    return sorted(set(c.vendor for c in CREDENTIAL_DB))


def export_csv() -> str:
    """Export the credential database as CSV string."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Vendor", "Product", "Protocol", "Port",
                     "Username", "Password", "Access Level", "Notes", "CVE"])
    for c in CREDENTIAL_DB:
        writer.writerow([c.vendor, c.product, c.protocol, c.port,
                         c.username, c.password, c.access_level, c.notes, c.cve])
    return out.getvalue()


# ---------------------------------------------------------------------------
# Exploit module interface
# ---------------------------------------------------------------------------

class SCADAPassDB(Exploit):
    """ICS/SCADA default credential database lookup."""

    __info__ = {
        "name": "SCADAPASS DB",
        "description": "Default credential database for ICS/SCADA devices and protocols",
        "authors": ["Andre Henrique (@mrhenrike)"],
        "references": [
            "CISA ICS-CERT Alert TA17-156A",
            "ICS-CERT Advisory ICSA-15-258-01",
        ],
    }

    query = OptString("", "Search query (vendor, product, or protocol name)")
    search_type = OptString("vendor", "Search by: vendor, product, protocol, port, all")
    export = OptBool(False, "Export full database as CSV")

    def run(self) -> list[DefaultCredential]:
        if self.export:
            csv_data = export_csv()
            print_info(f"Exported {len(CREDENTIAL_DB)} entries")
            return CREDENTIAL_DB

        q = self.query
        stype = self.search_type.lower()

        if stype == "all" or not q:
            results = CREDENTIAL_DB
        elif stype == "vendor":
            results = search_by_vendor(q)
        elif stype == "product":
            results = search_by_product(q)
        elif stype == "protocol":
            results = search_by_protocol(q)
        elif stype == "port":
            results = search_by_port(int(q))
        else:
            results = search_by_vendor(q) + search_by_product(q)

        print_status(f"SCADAPASS: {len(results)} credential entries found for '{q}'")
        for c in results:
            user = c.username if c.username else "(empty)"
            pwd = c.password if c.password else "(empty)"
            print_info(f"  {c.vendor:20s} {c.product:25s} {c.protocol:10s} "
                       f":{c.port:<6d} {user}:{pwd} [{c.access_level}]")
            if c.notes:
                print_info(f"    Note: {c.notes}")

        return results


MANIFEST = {
    "name": "scadapass_db",
    "category": "creds",
    "entry_count": len(CREDENTIAL_DB),
    "vendors": len(set(c.vendor for c in CREDENTIAL_DB)),
    "mitre_ics": ["T0812", "T0859"],
}
