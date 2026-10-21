"""Tests for credential wordlist loader and refactored modules."""

import pytest

from industrialxpl.modules.creds._wordlist_loader import (
    WORDLISTS_DIR,
    load_community_csv,
    load_credential_pairs,
    load_csv_rows,
    load_single_column,
    load_variant_csv,
    load_weighted_csv,
)


class TestWordlistLoader:
    def test_wordlists_dir_exists(self) -> None:
        assert WORDLISTS_DIR.is_dir()

    def test_load_credential_pairs_ftp(self) -> None:
        pairs = load_credential_pairs("ftp_default_credentials.txt")
        assert len(pairs) >= 20
        assert all(isinstance(p, tuple) and len(p) == 2 for p in pairs)

    def test_load_credential_pairs_ssh(self) -> None:
        pairs = load_credential_pairs("ssh_default_credentials.txt")
        assert len(pairs) >= 14

    def test_load_credential_pairs_http(self) -> None:
        pairs = load_credential_pairs("http_default_credentials.txt")
        assert len(pairs) >= 28

    def test_load_credential_pairs_telnet(self) -> None:
        pairs = load_credential_pairs("telnet_default_credentials.txt")
        assert len(pairs) >= 60

    def test_load_credential_pairs_mqtt(self) -> None:
        pairs = load_credential_pairs("mqtt_default_credentials.txt")
        assert len(pairs) >= 18

    def test_load_credential_pairs_missing_file(self) -> None:
        assert load_credential_pairs("nonexistent.txt") == []

    def test_load_single_column_snmp(self) -> None:
        communities = load_single_column("snmp_communities_bruteforce.txt")
        assert len(communities) >= 16
        assert "public" in communities
        assert "private" in communities

    def test_load_single_column_usernames(self) -> None:
        usernames = load_single_column("ics_telnet_usernames.txt")
        assert len(usernames) >= 10
        assert "admin" in usernames
        assert "root" in usernames

    def test_load_single_column_passwords(self) -> None:
        passwords = load_single_column("ics_telnet_passwords.txt")
        assert len(passwords) >= 20

    def test_load_single_column_missing_file(self) -> None:
        assert load_single_column("nonexistent.txt") == []

    def test_load_csv_rows_scadapass(self) -> None:
        rows = load_csv_rows("scadapass_full_export.csv")
        assert len(rows) >= 422
        assert "Vendor" in rows[0]

    def test_load_weighted_csv_mirai(self) -> None:
        entries = load_weighted_csv("mirai_original.csv")
        assert len(entries) >= 60
        assert all(isinstance(e, tuple) and len(e) == 3 for e in entries)
        user, pwd, weight = entries[0]
        assert isinstance(weight, int)

    def test_load_variant_csv_mirai(self) -> None:
        entries = load_variant_csv("mirai_variants.csv")
        assert len(entries) >= 35
        assert all(isinstance(e, tuple) and len(e) == 3 for e in entries)

    def test_load_variant_csv_ics_gateway(self) -> None:
        entries = load_variant_csv("ics_iot_gateway_creds.csv")
        assert len(entries) >= 23

    def test_load_community_csv(self) -> None:
        communities = load_community_csv("snmp_communities_full.csv")
        assert len(communities) >= 25
        assert all(isinstance(c, tuple) and len(c) == 2 for c in communities)


class TestScadapassDB:
    def test_credential_db_loaded(self) -> None:
        from industrialxpl.modules.creds.scadapass_db import CREDENTIAL_DB
        assert len(CREDENTIAL_DB) >= 422

    def test_get_stats(self) -> None:
        from industrialxpl.modules.creds.scadapass_db import get_stats
        stats = get_stats()
        assert stats["total_entries"] >= 422
        assert stats["unique_vendors"] >= 50

    def test_search_by_vendor(self) -> None:
        from industrialxpl.modules.creds.scadapass_db import search_by_vendor
        results = search_by_vendor("Siemens")
        assert len(results) > 0

    def test_search_by_protocol(self) -> None:
        from industrialxpl.modules.creds.scadapass_db import search_by_protocol
        results = search_by_protocol("Modbus")
        assert len(results) > 0

    def test_search_by_category(self) -> None:
        from industrialxpl.modules.creds.scadapass_db import search_by_category
        results = search_by_category("plc")
        assert len(results) > 0

    def test_search_by_cve(self) -> None:
        from industrialxpl.modules.creds.scadapass_db import search_by_cve
        results = search_by_cve("CVE-2023-6448")
        assert len(results) > 0

    def test_get_mirai_wordlist(self) -> None:
        from industrialxpl.modules.creds.scadapass_db import get_mirai_wordlist
        mirai = get_mirai_wordlist()
        assert len(mirai) >= 50

    def test_get_snmp_communities(self) -> None:
        from industrialxpl.modules.creds.scadapass_db import get_snmp_communities
        snmp = get_snmp_communities()
        assert len(snmp) >= 5

    def test_export_csv(self) -> None:
        from industrialxpl.modules.creds.scadapass_db import export_csv
        csv_data = export_csv()
        assert "Vendor,Product,Protocol" in csv_data
        assert len(csv_data.strip().split("\n")) >= 422

    def test_cred_category_enum(self) -> None:
        from industrialxpl.modules.creds.scadapass_db import CredCategory
        assert CredCategory.PLC.value == "plc"
        assert CredCategory.BOTNET.value == "botnet"


class TestMiraiWordlist:
    def test_mirai_original_loaded(self) -> None:
        from industrialxpl.modules.creds.mirai_wordlist import MIRAI_ORIGINAL
        assert len(MIRAI_ORIGINAL) >= 60

    def test_mirai_variants_loaded(self) -> None:
        from industrialxpl.modules.creds.mirai_wordlist import MIRAI_VARIANTS_EXTRA
        assert len(MIRAI_VARIANTS_EXTRA) >= 35

    def test_ics_gateway_loaded(self) -> None:
        from industrialxpl.modules.creds.mirai_wordlist import ICS_IOT_GATEWAY_CREDS
        assert len(ICS_IOT_GATEWAY_CREDS) >= 23

    def test_snmp_communities_loaded(self) -> None:
        from industrialxpl.modules.creds.mirai_wordlist import SNMP_COMMUNITY_STRINGS
        assert len(SNMP_COMMUNITY_STRINGS) >= 25

    def test_get_mirai_full_list_dedup(self) -> None:
        from industrialxpl.modules.creds.mirai_wordlist import get_mirai_full_list
        full = get_mirai_full_list()
        assert len(full) >= 80
        assert len(full) == len(set(full))

    def test_export_mirai_wordlist_txt(self) -> None:
        from industrialxpl.modules.creds.mirai_wordlist import export_mirai_wordlist_txt
        txt = export_mirai_wordlist_txt()
        lines = [l for l in txt.strip().split("\n") if l]
        assert len(lines) >= 80
        assert all(":" in l for l in lines)


class TestGenericModulesLoadFromWordlists:
    def test_ftp_default_creds(self) -> None:
        from industrialxpl.modules.creds.generic.ftp_default import _DEFAULT_CREDS
        assert len(_DEFAULT_CREDS) >= 20

    def test_ssh_default_creds(self) -> None:
        from industrialxpl.modules.creds.generic.ssh_default import _DEFAULT_CREDS
        assert len(_DEFAULT_CREDS) >= 14

    def test_telnet_default_creds(self) -> None:
        from industrialxpl.modules.creds.generic.telnet_default import _DEFAULT_CREDS
        assert len(_DEFAULT_CREDS) >= 60

    def test_http_default_creds(self) -> None:
        from industrialxpl.modules.creds.generic.http_default import _DEFAULT_CREDS
        assert len(_DEFAULT_CREDS) >= 28

    def test_mqtt_default_creds(self) -> None:
        from industrialxpl.modules.creds.generic.ics_mqtt_bruteforce import _DEFAULT_CREDENTIALS
        assert len(_DEFAULT_CREDENTIALS) >= 18

    def test_snmp_default_communities(self) -> None:
        from industrialxpl.modules.creds.generic.ics_snmp_bruteforce import _DEFAULT_SNMP_COMMUNITIES
        assert len(_DEFAULT_SNMP_COMMUNITIES) >= 16

    def test_telnet_brute_usernames(self) -> None:
        from industrialxpl.modules.creds.generic.ics_telnet_bruteforce import _DEFAULT_USERNAMES
        assert len(_DEFAULT_USERNAMES) >= 10

    def test_telnet_brute_passwords(self) -> None:
        from industrialxpl.modules.creds.generic.ics_telnet_bruteforce import _DEFAULT_PASSWORDS
        assert len(_DEFAULT_PASSWORDS) >= 20
