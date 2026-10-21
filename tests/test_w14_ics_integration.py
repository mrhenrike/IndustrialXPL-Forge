"""Tests for W14 ICS/OT integration modules.

Validates importability and basic instantiation of all new modules.
No live targets required.
"""

import importlib
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# Ensure the package is importable
FORGE_ROOT = Path(__file__).parent.parent
if str(FORGE_ROOT) not in sys.path:
    sys.path.insert(0, str(FORGE_ROOT))


class TestICSNinjaScanner:
    """Test ICS Ninja Scanner multi-protocol module."""

    def test_import(self):
        mod = importlib.import_module(
            "industrialxpl.modules.scanners.ics.ics_ninja_scanner")
        assert hasattr(mod, "ICSNinjaScanner")
        assert hasattr(mod, "PROTOCOL_SCANNERS")
        assert hasattr(mod, "MANIFEST")

    def test_protocol_registry(self):
        from industrialxpl.modules.scanners.ics.ics_ninja_scanner import (
            PROTOCOL_SCANNERS,
        )
        expected = {"modbus", "s7comm", "dnp3", "bacnet", "enip", "iec104", "mqtt"}
        assert set(PROTOCOL_SCANNERS.keys()) == expected

    def test_scan_result_dataclass(self):
        from industrialxpl.modules.scanners.ics.ics_ninja_scanner import ScanResult
        r = ScanResult(protocol="modbus", target="10.0.0.1", port=502)
        assert r.protocol == "modbus"
        assert r.device_info == {}
        assert r.issues == []

    def test_modbus_packet_build(self):
        from industrialxpl.modules.scanners.ics.ics_ninja_scanner import (
            _modbus_build, _modbus_parse,
        )
        pkt = _modbus_build(1, 3, b"\x00\x00\x00\x01", tid=42)
        assert len(pkt) == 12
        assert pkt[0:2] == b"\x00\x2a"  # tid=42

    def test_dnp3_crc(self):
        from industrialxpl.modules.scanners.ics.ics_ninja_scanner import _dnp3_crc
        crc = _dnp3_crc(b"\x05\xc0\x01\x00\x00\x00")
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF


class TestPLCScanner:
    """Test PLC Scanner module (plcscan port)."""

    def test_import(self):
        mod = importlib.import_module(
            "industrialxpl.modules.scanners.ics.plcscan")
        assert hasattr(mod, "PLCScanner")
        assert hasattr(mod, "ModbusClient")
        assert hasattr(mod, "S7Client")

    def test_modbus_packet(self):
        from industrialxpl.modules.scanners.ics.plcscan import ModbusPacket
        pkt = ModbusPacket(transaction_id=1, unit_id=1, function_id=3,
                           data=b"\x00\x00\x00\x01")
        raw = pkt.pack()
        assert len(raw) == 12
        parsed = ModbusPacket.unpack(raw)
        assert parsed.function_id == 3

    def test_expand_targets(self):
        from industrialxpl.modules.scanners.ics.plcscan import expand_targets
        hosts = expand_targets("192.168.1.0/30")
        assert len(hosts) == 2
        assert "192.168.1.1" in hosts
        assert "192.168.1.2" in hosts

    def test_expand_targets_single(self):
        from industrialxpl.modules.scanners.ics.plcscan import expand_targets
        hosts = expand_targets("10.0.0.1")
        assert hosts == ["10.0.0.1"]


class TestModbusFuzzer:
    """Test Modbus TCP Fuzzer module."""

    def test_import(self):
        mod = importlib.import_module(
            "industrialxpl.modules.fuzzers.modbus_fuzzer")
        assert hasattr(mod, "ModbusFuzzer")
        assert hasattr(mod, "FUNCTION_CODE_NAMES")

    def test_frame_pack_unpack(self):
        from industrialxpl.modules.fuzzers.modbus_fuzzer import ModbusTCPFrame
        frame = ModbusTCPFrame(transaction_id=100, unit_id=1,
                               function_code=3, data=b"\x00\x00\x00\x01")
        raw = frame.pack()
        parsed = ModbusTCPFrame.unpack(raw)
        assert parsed.transaction_id == 100
        assert parsed.function_code == 3
        assert not parsed.is_exception()

    def test_request_builders(self):
        from industrialxpl.modules.fuzzers.modbus_fuzzer import (
            read_coils, read_holding_registers, write_single_coil,
            write_single_register, write_multiple_registers,
        )
        assert len(read_coils(0, 10)) == 4
        assert len(read_holding_registers(100, 5)) == 4
        assert len(write_single_coil(0, True)) == 4
        assert len(write_single_register(0, 1234)) == 4
        data = write_multiple_registers(0, [1, 2, 3])
        assert len(data) == 5 + 6  # header + 3 words


class TestSCADAPassDB:
    """Test SCADAPASS default credential database."""

    def test_import(self):
        mod = importlib.import_module(
            "industrialxpl.modules.creds.scadapass_db")
        assert hasattr(mod, "SCADAPassDB")
        assert hasattr(mod, "CREDENTIAL_DB")

    def test_db_not_empty(self):
        from industrialxpl.modules.creds.scadapass_db import CREDENTIAL_DB
        assert len(CREDENTIAL_DB) > 50

    def test_search_by_vendor(self):
        from industrialxpl.modules.creds.scadapass_db import search_by_vendor
        results = search_by_vendor("Siemens")
        assert len(results) > 0
        assert all("siemens" in r.vendor.lower() for r in results)

    def test_search_by_protocol(self):
        from industrialxpl.modules.creds.scadapass_db import search_by_protocol
        results = search_by_protocol("Modbus")
        assert len(results) > 0

    def test_export_csv(self):
        from industrialxpl.modules.creds.scadapass_db import export_csv
        csv_data = export_csv()
        assert "Vendor" in csv_data
        assert "Siemens" in csv_data

    def test_all_vendors(self):
        from industrialxpl.modules.creds.scadapass_db import get_all_vendors
        vendors = get_all_vendors()
        assert "Siemens" in vendors
        assert "Rockwell" in vendors


class TestRedpointNSE:
    """Test Redpoint NSE wrapper module."""

    def test_import(self):
        mod = importlib.import_module(
            "industrialxpl.modules.scanners.ics.redpoint_nse")
        assert hasattr(mod, "RedpointScanner")
        assert hasattr(mod, "REDPOINT_SCRIPTS")

    def test_script_registry(self):
        from industrialxpl.modules.scanners.ics.redpoint_nse import REDPOINT_SCRIPTS
        assert "s7-enumerate" in REDPOINT_SCRIPTS
        assert "BACnet-discover-enumerate" in REDPOINT_SCRIPTS
        assert len(REDPOINT_SCRIPTS) >= 12


class TestBoofuzzICS:
    """Test boofuzz ICS fuzzer module."""

    def test_import(self):
        mod = importlib.import_module(
            "industrialxpl.modules.fuzzers.boofuzz_ics")
        assert hasattr(mod, "BoofuzzICS")
        assert hasattr(mod, "SESSION_FACTORIES")

    def test_session_factories(self):
        from industrialxpl.modules.fuzzers.boofuzz_ics import SESSION_FACTORIES
        assert "modbus" in SESSION_FACTORIES
        assert "dnp3" in SESSION_FACTORIES
        assert "enip" in SESSION_FACTORIES


class TestConpotDeployer:
    """Test Conpot honeypot deployer module."""

    def test_import(self):
        mod = importlib.import_module(
            "industrialxpl.modules.deception.conpot_deployer")
        assert hasattr(mod, "ConpotDeployer")
        assert hasattr(mod, "CONPOT_TEMPLATES")

    def test_templates(self):
        from industrialxpl.modules.deception.conpot_deployer import CONPOT_TEMPLATES
        assert "default" in CONPOT_TEMPLATES
        assert "guardian_ast" in CONPOT_TEMPLATES


class TestMoxaExploit:
    """Test Moxa NPort exploit module."""

    def test_import(self):
        mod = importlib.import_module(
            "industrialxpl.modules.exploits.ics.moxa_nport_exploit")
        assert hasattr(mod, "MoxaNPortExploit")
        assert hasattr(mod, "MOXA_DEFAULT_CREDS")

    def test_default_creds(self):
        from industrialxpl.modules.exploits.ics.moxa_nport_exploit import (
            MOXA_DEFAULT_CREDS,
        )
        assert len(MOXA_DEFAULT_CREDS) >= 4
        usernames = [u for u, _ in MOXA_DEFAULT_CREDS]
        assert "admin" in usernames

    def test_device_info_dataclass(self):
        from industrialxpl.modules.exploits.ics.moxa_nport_exploit import MoxaDeviceInfo
        info = MoxaDeviceInfo(ip="10.0.0.1", model="NPort 5110")
        assert info.model == "NPort 5110"
        assert info.credentials_found == []


class TestSnap7Toolkit:
    """Test Snap7 S7comm toolkit module."""

    def test_import(self):
        mod = importlib.import_module(
            "industrialxpl.modules.protocols.s7comm.snap7_toolkit")
        assert hasattr(mod, "Snap7Toolkit")
        assert hasattr(mod, "PROTECTION_LEVELS")

    def test_constants(self):
        from industrialxpl.modules.protocols.s7comm.snap7_toolkit import (
            S7_AREA_DB, S7_AREA_MK, BLOCK_TYPES,
        )
        assert S7_AREA_DB == 0x84
        assert S7_AREA_MK == 0x83
        assert "OB" in BLOCK_TYPES
