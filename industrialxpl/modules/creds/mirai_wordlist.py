"""Mirai botnet default credential wordlist.

Complete credential list from the original Mirai source code (scanner.c)
plus known variants from Mirai offspring (Satori, Okiru, Masuta, Hajime,
BrickerBot, Mozi, Echobot). These credentials target IoT devices, IP cameras,
DVRs, routers, and ICS gateways commonly found in OT networks.

Sources:
  - Mirai source code (scanner.c, leaked 2016-09-30 by Anna-senpai)
  - US-CERT Alert TA16-288A
  - NIST SP 800-183 (IoT default credentials)
  - Public analyses of Mirai variants

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

MIRAI_ORIGINAL: list[tuple[str, str, int]] = [
    # (username, password, weight) from scanner.c
    # Weight indicates priority: higher = tried first
    ("root", "xc3511", 10),
    ("root", "vizxv", 9),
    ("root", "admin", 8),
    ("admin", "admin", 7),
    ("root", "888888", 6),
    ("root", "xmhdipc", 5),
    ("root", "default", 5),
    ("root", "juantech", 5),
    ("root", "123456", 5),
    ("root", "54321", 5),
    ("support", "support", 5),
    ("root", "", 4),
    ("admin", "password", 4),
    ("root", "root", 4),
    ("root", "12345", 4),
    ("user", "user", 3),
    ("admin", "", 3),
    ("root", "pass", 3),
    ("admin", "admin1234", 3),
    ("root", "1111", 3),
    ("admin", "smcadmin", 3),
    ("admin", "1111", 2),
    ("root", "666666", 2),
    ("root", "password", 2),
    ("root", "1234", 2),
    ("root", "klv123", 1),
    ("Administrator", "admin", 1),
    ("service", "service", 1),
    ("supervisor", "supervisor", 1),
    ("guest", "guest", 1),
    ("guest", "12345", 1),
    ("guest", "12345", 1),
    ("admin1", "password", 1),
    ("administrator", "1234", 1),
    ("666666", "666666", 1),
    ("888888", "888888", 1),
    ("ubnt", "ubnt", 1),
    ("root", "klv1234", 1),
    ("root", "Zte521", 1),
    ("root", "hi3518", 1),
    ("root", "jvbzd", 1),
    ("root", "anko", 4),
    ("root", "zlxx.", 1),
    ("root", "7ujMko0vizxv", 1),
    ("root", "7ujMko0admin", 1),
    ("root", "system", 1),
    ("root", "ikwb", 1),
    ("root", "dreambox", 1),
    ("root", "user", 1),
    ("root", "realtek", 1),
    ("root", "00000000", 1),
    ("admin", "1111111", 1),
    ("admin", "1234", 1),
    ("admin", "12345", 1),
    ("admin", "54321", 1),
    ("admin", "123456", 1),
    ("admin", "7ujMko0admin", 1),
    ("admin", "1234", 1),
    ("admin", "pass", 1),
    ("admin", "meinsm", 1),
    ("tech", "tech", 1),
    ("mother", "fucker", 1),
]

MIRAI_VARIANTS_EXTRA: list[tuple[str, str, str]] = [
    # (username, password, variant_name) credentials added by Mirai offspring
    # Satori / Okiru (2017-2018)
    ("root", "t0talc0ntr0l4!", "Satori"),
    ("root", "cat1029", "Satori"),
    ("root", "GM8182", "Satori"),
    ("root", "OxhlwSG8", "Satori"),
    ("root", "S2fGqNFs", "Satori"),
    ("root", "tsgoingon", "Satori"),
    # Masuta (2018)
    ("admin", "CentryL1nk", "Masuta"),
    ("admin", "QwestM0dem", "Masuta"),
    # Hajime (2016-2017)
    ("root", "5up", "Hajime"),
    ("admin", "epicrouter", "Hajime"),
    ("root", "toor", "Hajime"),
    # BrickerBot (2017)
    ("root", "changeme", "BrickerBot"),
    ("root", "oelinux123", "BrickerBot"),
    ("root", "ipc71a", "BrickerBot"),
    # Mozi (2019-2021)
    ("root", "gpon", "Mozi"),
    ("admin", "oelinux123", "Mozi"),
    ("root", "antslq", "Mozi"),
    # Echobot (2019)
    ("root", "taZz@23495859", "Echobot"),
    ("root", "aquario", "Echobot"),
    # Generic IoT additions (common across variants)
    ("admin", "ttnet", "generic"),
    ("admin", "huigu309", "generic"),
    ("root", "ls123", "generic"),
    ("root", "t0talc0ntr0l", "generic"),
    ("root", "GM8182", "generic"),
    ("daemon", "daemon", "generic"),
    ("operator", "operator", "generic"),
    ("default", "default", "generic"),
    ("root", "synnet", "generic"),
    ("root", "ascend", "generic"),
    ("admin", "conexant", "generic"),
    ("root", "D13HH[", "generic"),
    ("admin", "admin01", "generic"),
    ("root", "ipcam_rt5350", "generic"),
    ("root", "access", "generic"),
    ("root", "anicmv", "generic"),
]

ICS_IOT_GATEWAY_CREDS: list[tuple[str, str, str]] = [
    # Credentials for ICS/OT IoT gateways commonly scanned by Mirai variants
    ("admin", "", "Moxa NPort/MGate"),
    ("admin", "moxa", "Moxa EDS switch"),
    ("admin", "wago", "WAGO PFC100/200"),
    ("admin", "admin", "Generic ICS webUI"),
    ("root", "root", "Embedded Linux ICS"),
    ("admin", "1234", "Rockwell MicroLogix"),
    ("USER", "USER", "Schneider Unity Pro"),
    ("apc", "apc", "APC/Schneider UPS NMC"),
    ("admin", "1", "Beckhoff CX Series"),
    ("admin", "", "Advantech ADAM"),
    ("admin", "password", "Lantronix device server"),
    ("root", "calvin", "Dell iDRAC (OT servers)"),
    ("admin", "Netman", "ABB PowerValue UPS"),
    ("ADMIN", "ADMIN", "Honeywell Experion"),
    ("admin", "admin", "Siemens SCALANCE"),
    ("boschrexroth", "boschrexroth", "Bosch Rexroth ctrlX"),
    ("admin", "westermo", "Westermo switches"),
    ("admin", "hirschmann", "Hirschmann/Belden switches"),
    ("admin", "phoenix", "Phoenix Contact managed switch"),
    ("admin", "smc", "SMC managed switch (OT)"),
    ("root", "emerson", "Emerson ROC Serial"),
    ("Manager", "Manager", "Red Lion HMI"),
    ("admin", "redlion", "Red Lion Sixnet"),
]

SNMP_COMMUNITY_STRINGS: list[tuple[str, str]] = [
    # (community_string, context) common in ICS/OT environments
    ("public", "Read-only default (RFC 1157)"),
    ("private", "Read-write default (RFC 1157)"),
    ("community", "Common alternate"),
    ("snmpd", "Net-SNMP default"),
    ("mngt", "Management default"),
    ("admin", "Administrative community"),
    ("cisco", "Cisco default"),
    ("cable-d0csis", "Cable modem"),
    ("ILMI", "ATM interface (Cisco)"),
    ("Intermec", "Intermec devices"),
    ("internal", "Internal community"),
    ("all", "Some HP devices"),
    ("all private", "Some HP devices"),
    ("secret", "Common weak community"),
    ("manager", "Management community"),
    ("security", "Security community"),
    ("monitor", "Monitoring community"),
    ("default", "Generic default"),
    ("public@es0", "Context-specific SNMPv3 migration"),
    ("ANYCOM", "3Com/HP switches"),
    ("volition", "Belden/Hirschmann switches"),
    ("TENmanUFactworworworworworworworwoworwor", "Siemens SCALANCE (some firmware)"),
    ("ABB", "ABB RTU/relay"),
    ("schneider", "Schneider Electric"),
    ("moxa", "Moxa serial servers"),
]


def get_mirai_full_list() -> list[tuple[str, str]]:
    """Return deduplicated (user, pass) pairs from original + variants."""
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []
    for user, pwd, _w in sorted(MIRAI_ORIGINAL, key=lambda x: -x[2]):
        pair = (user, pwd)
        if pair not in seen:
            seen.add(pair)
            result.append(pair)
    for user, pwd, _v in MIRAI_VARIANTS_EXTRA:
        pair = (user, pwd)
        if pair not in seen:
            seen.add(pair)
            result.append(pair)
    return result


def get_ics_iot_creds() -> list[tuple[str, str]]:
    """Return ICS/OT gateway credentials for brute force."""
    return [(u, p) for u, p, _d in ICS_IOT_GATEWAY_CREDS]


def get_snmp_communities() -> list[str]:
    """Return SNMP community strings for brute force."""
    return [c for c, _d in SNMP_COMMUNITY_STRINGS]


def export_mirai_wordlist_txt() -> str:
    """Export Mirai credentials as username:password lines."""
    lines: list[str] = []
    for user, pwd in get_mirai_full_list():
        lines.append(f"{user}:{pwd}")
    return "\n".join(lines) + "\n"


MANIFEST = {
    "name": "mirai_wordlist",
    "category": "creds",
    "mirai_original_count": len(MIRAI_ORIGINAL),
    "mirai_variants_count": len(MIRAI_VARIANTS_EXTRA),
    "ics_gateway_count": len(ICS_IOT_GATEWAY_CREDS),
    "snmp_count": len(SNMP_COMMUNITY_STRINGS),
    "mitre_ics": ["T0812", "T0859"],
}
