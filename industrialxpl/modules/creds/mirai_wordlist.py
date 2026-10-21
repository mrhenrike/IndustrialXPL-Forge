"""Mirai botnet default credential wordlist.

Complete credential list from the original Mirai source code (scanner.c)
plus known variants from Mirai offspring (Satori, Okiru, Masuta, Hajime,
BrickerBot, Mozi, Echobot). These credentials target IoT devices, IP cameras,
DVRs, routers, and ICS gateways commonly found in OT networks.

All credential data is loaded from CSV/TXT files in resources/wordlists/.
No credentials are stored in Python source code.

Sources:
  - Mirai source code (scanner.c, leaked 2016-09-30 by Anna-senpai)
  - US-CERT Alert TA16-288A
  - NIST SP 800-183 (IoT default credentials)
  - Public analyses of Mirai variants

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

from industrialxpl.modules.creds._wordlist_loader import (
    load_community_csv,
    load_variant_csv,
    load_weighted_csv,
)

MIRAI_ORIGINAL: list[tuple[str, str, int]] = load_weighted_csv("mirai_original.csv")

MIRAI_VARIANTS_EXTRA: list[tuple[str, str, str]] = load_variant_csv("mirai_variants.csv")

ICS_IOT_GATEWAY_CREDS: list[tuple[str, str, str]] = load_variant_csv("ics_iot_gateway_creds.csv")

SNMP_COMMUNITY_STRINGS: list[tuple[str, str]] = load_community_csv("snmp_communities_full.csv")


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
