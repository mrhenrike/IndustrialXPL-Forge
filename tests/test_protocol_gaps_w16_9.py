"""Tests for W16.9 protocol gap modules: J1939, WirelessHART, PROFIBUS DP."""

import importlib

import pytest


class TestJ1939Scanner:
    """Test J1939 scanner helpers and class instantiation."""

    def test_import(self):
        mod = importlib.import_module("industrialxpl.modules.exploits.protocols.j1939.j1939_scanner")
        assert hasattr(mod, "J1939Scanner")
        assert hasattr(mod, "_build_j1939_id")
        assert hasattr(mod, "_parse_j1939_id")

    def test_build_j1939_id(self):
        from industrialxpl.modules.exploits.protocols.j1939.j1939_scanner import _build_j1939_id
        can_id = _build_j1939_id(6, 0x00EE00, 0xFE)
        assert can_id & 0xFF == 0xFE
        assert ((can_id >> 26) & 0x07) == 6

    def test_parse_j1939_id_roundtrip(self):
        from industrialxpl.modules.exploits.protocols.j1939.j1939_scanner import (
            _build_j1939_id,
            _parse_j1939_id,
        )
        original_priority = 6
        original_pgn = 0x00EE00
        original_source = 0x42
        can_id = _build_j1939_id(original_priority, original_pgn, original_source)
        parsed = _parse_j1939_id(can_id)
        assert parsed["priority"] == original_priority
        assert parsed["source"] == original_source
        assert parsed["pgn"] == original_pgn

    def test_parse_address_claim(self):
        from industrialxpl.modules.exploits.protocols.j1939.j1939_scanner import _parse_address_claim
        name_value = 0x0000000000000001
        data = name_value.to_bytes(8, "little")
        result = _parse_address_claim(data)
        assert "identity_number" in result
        assert "manufacturer_code" in result
        assert result["identity_number"] == 1

    def test_parse_address_claim_short(self):
        from industrialxpl.modules.exploits.protocols.j1939.j1939_scanner import _parse_address_claim
        result = _parse_address_claim(b"\x01\x02\x03")
        assert "raw" in result

    def test_build_request_frame(self):
        from industrialxpl.modules.exploits.protocols.j1939.j1939_scanner import _build_request_frame
        can_id, data = _build_request_frame(0x00EE00, source=0xFE)
        assert len(data) == 3
        assert can_id & 0xFF == 0xFE

    def test_scanner_init(self):
        from industrialxpl.modules.exploits.protocols.j1939.j1939_scanner import J1939Scanner
        scanner = J1939Scanner(interface="virtual", channel="vcan0", timeout=1.0)
        assert scanner.interface == "virtual"
        assert scanner.channel == "vcan0"

    def test_standard_pgns_populated(self):
        from industrialxpl.modules.exploits.protocols.j1939.j1939_scanner import STANDARD_PGNS
        assert len(STANDARD_PGNS) >= 10
        for pgn, desc in STANDARD_PGNS:
            assert isinstance(pgn, int)
            assert isinstance(desc, str)


class TestJ1939Attack:
    """Test J1939 attack module instantiation and validation."""

    def test_import(self):
        mod = importlib.import_module("industrialxpl.modules.exploits.protocols.j1939.j1939_attack")
        assert hasattr(mod, "J1939AddressClaimSpoof")
        assert hasattr(mod, "J1939UDSInjection")

    def test_address_claim_init(self):
        from industrialxpl.modules.exploits.protocols.j1939.j1939_attack import J1939AddressClaimSpoof
        spoof = J1939AddressClaimSpoof(target_address=10, interface="virtual", channel="vcan0")
        assert spoof.target_address == 10

    def test_address_claim_invalid_address(self):
        from industrialxpl.modules.exploits.protocols.j1939.j1939_attack import J1939AddressClaimSpoof
        with pytest.raises(ValueError, match="0-253"):
            J1939AddressClaimSpoof(target_address=255)

    def test_craft_name_lower(self):
        from industrialxpl.modules.exploits.protocols.j1939.j1939_attack import J1939AddressClaimSpoof
        spoof = J1939AddressClaimSpoof(target_address=10)
        name = spoof._craft_name(lower_than=100)
        assert int.from_bytes(name, "little") < 100

    def test_craft_name_zero(self):
        from industrialxpl.modules.exploits.protocols.j1939.j1939_attack import J1939AddressClaimSpoof
        spoof = J1939AddressClaimSpoof(target_address=10)
        name = spoof._craft_name(lower_than=0)
        assert len(name) == 8

    def test_uds_injection_init(self):
        from industrialxpl.modules.exploits.protocols.j1939.j1939_attack import J1939UDSInjection
        inj = J1939UDSInjection(target_address=0x20, source_address=0xF9)
        assert inj.target_address == 0x20
        assert inj.source_address == 0xF9

    def test_uds_injection_invalid_address(self):
        from industrialxpl.modules.exploits.protocols.j1939.j1939_attack import J1939UDSInjection
        with pytest.raises(ValueError, match="0-253"):
            J1939UDSInjection(target_address=300)

    def test_uds_constants(self):
        from industrialxpl.modules.exploits.protocols.j1939 import j1939_attack
        assert j1939_attack.UDS_SERVICE_ECU_RESET == 0x11
        assert j1939_attack.UDS_SERVICE_TESTER_PRESENT == 0x3E

    def test_run_without_can(self):
        from industrialxpl.modules.exploits.protocols.j1939.j1939_attack import J1939AddressClaimSpoof
        spoof = J1939AddressClaimSpoof(target_address=10, interface="virtual", channel="vcan0")
        result = spoof.run()
        assert result["attack"] == "j1939_address_claim_spoof"
        assert "success" in result or "error" in result


class TestWirelessHARTScanner:
    """Test WirelessHART scanner module."""

    def test_import(self):
        mod = importlib.import_module(
            "industrialxpl.modules.exploits.protocols.wirelesshart.wirelesshart_scanner"
        )
        assert hasattr(mod, "WirelessHARTScanner")

    def test_scanner_init(self):
        from industrialxpl.modules.exploits.protocols.wirelesshart.wirelesshart_scanner import (
            WirelessHARTScanner,
        )
        scanner = WirelessHARTScanner(gateway_ip="192.168.1.1", port=5094, timeout=2.0)
        assert scanner.gateway_ip == "192.168.1.1"
        assert scanner.port == 5094

    def test_build_hart_ip_header(self):
        from industrialxpl.modules.exploits.protocols.wirelesshart.wirelesshart_scanner import (
            _build_hart_ip_header,
        )
        header = _build_hart_ip_header(msg_type=0, msg_id=1, payload_len=10)
        assert len(header) == 8
        version = header[0]
        assert version == 1

    def test_build_command_frame(self):
        from industrialxpl.modules.exploits.protocols.wirelesshart.wirelesshart_scanner import (
            _build_command_frame,
        )
        frame = _build_command_frame(command=0, address=b"\x00" * 5)
        assert frame[:5] == b"\xFF" * 5
        checksum = 0
        for b in frame[5:-1]:
            checksum ^= b
        assert frame[-1] == checksum

    def test_device_types_dict(self):
        from industrialxpl.modules.exploits.protocols.wirelesshart.wirelesshart_scanner import (
            DEVICE_TYPES,
        )
        assert isinstance(DEVICE_TYPES, dict)
        assert len(DEVICE_TYPES) >= 5


class TestWirelessHARTAttack:
    """Test WirelessHART attack modules."""

    def test_import(self):
        mod = importlib.import_module(
            "industrialxpl.modules.exploits.protocols.wirelesshart.wirelesshart_attack"
        )
        assert hasattr(mod, "WirelessHARTJoinKeyAudit")
        assert hasattr(mod, "WirelessHARTCommandInjection")

    def test_join_key_audit_init(self):
        from industrialxpl.modules.exploits.protocols.wirelesshart.wirelesshart_attack import (
            WirelessHARTJoinKeyAudit,
        )
        audit = WirelessHARTJoinKeyAudit(gateway_ip="10.0.0.1", custom_keys=["AA" * 16])
        assert audit.gateway_ip == "10.0.0.1"
        assert len(audit.custom_keys) == 1

    def test_default_join_keys(self):
        from industrialxpl.modules.exploits.protocols.wirelesshart.wirelesshart_attack import (
            DEFAULT_JOIN_KEYS,
        )
        assert len(DEFAULT_JOIN_KEYS) >= 3
        for entry in DEFAULT_JOIN_KEYS:
            assert "key" in entry
            assert "vendor" in entry
            assert len(entry["key"]) == 32

    def test_command_injection_init(self):
        from industrialxpl.modules.exploits.protocols.wirelesshart.wirelesshart_attack import (
            WirelessHARTCommandInjection,
        )
        inj = WirelessHARTCommandInjection(gateway_ip="10.0.0.1", target_address=5)
        assert inj.target_address == 5


class TestPROFIBUSDPAttack:
    """Test PROFIBUS DP attack modules."""

    def test_import(self):
        mod = importlib.import_module(
            "industrialxpl.modules.exploits.protocols.profibus.profibus_dp_attack"
        )
        assert hasattr(mod, "PROFIBUSDPSlaveSpoof")
        assert hasattr(mod, "PROFIBUSDPGlobalControl")

    def test_build_sd2_frame(self):
        from industrialxpl.modules.exploits.protocols.profibus.profibus_dp_attack import (
            ED,
            SD2,
            _build_sd2_frame,
        )
        frame = _build_sd2_frame(da=3, sa=0, fc=0x4C, dsap=60, ssap=60)
        assert frame[0] == SD2
        assert frame[-1] == ED

    def test_build_sd1_frame(self):
        from industrialxpl.modules.exploits.protocols.profibus.profibus_dp_attack import (
            ED,
            SD1,
            _build_sd1_frame,
        )
        frame = _build_sd1_frame(da=3, sa=0, fc=0x49)
        assert frame[0] == SD1
        assert frame[-1] == ED
        fcs = (3 + 0 + 0x49) & 0xFF
        assert frame[-2] == fcs

    def test_slave_spoof_init(self):
        from industrialxpl.modules.exploits.protocols.profibus.profibus_dp_attack import (
            PROFIBUSDPSlaveSpoof,
        )
        spoof = PROFIBUSDPSlaveSpoof(
            gateway_ip="10.0.0.1",
            target_slave_addr=5,
            spoof_addr=5,
        )
        assert spoof.target_slave_addr == 5

    def test_slave_spoof_invalid_address(self):
        from industrialxpl.modules.exploits.protocols.profibus.profibus_dp_attack import (
            PROFIBUSDPSlaveSpoof,
        )
        with pytest.raises(ValueError, match="0-125"):
            PROFIBUSDPSlaveSpoof(gateway_ip="10.0.0.1", target_slave_addr=200)

    def test_global_control_init(self):
        from industrialxpl.modules.exploits.protocols.profibus.profibus_dp_attack import (
            PROFIBUSDPGlobalControl,
        )
        gc = PROFIBUSDPGlobalControl(gateway_ip="10.0.0.1")
        assert gc.gateway_ip == "10.0.0.1"

    def test_gc_constants(self):
        from industrialxpl.modules.exploits.protocols.profibus.profibus_dp_attack import (
            PROFIBUSDPGlobalControl,
        )
        assert PROFIBUSDPGlobalControl.GC_CLEAR == 0x02
        assert PROFIBUSDPGlobalControl.GC_FREEZE == 0x08
        assert PROFIBUSDPGlobalControl.GC_SYNC == 0x20
