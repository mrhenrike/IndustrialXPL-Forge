"""Tests for Modbus TCP Device Identification Scanner module."""

import pytest
from unittest.mock import patch, MagicMock

from industrialxpl.modules.scanners.asset.modbus_scan import Exploit as ModbusScan


class TestModbusScanMetadata:
    def test_info_name(self):
        e = ModbusScan()
        info = e.get_info()
        assert "Modbus" in info["name"]

    def test_info_mitre(self):
        e = ModbusScan()
        assert "T0846" in e.get_info()["mitre"]

    def test_info_severity(self):
        e = ModbusScan()
        assert e.get_info()["severity"] == "info"

    def test_info_has_authors(self):
        e = ModbusScan()
        assert len(e.get_info()["authors"]) > 0

    def test_info_has_references(self):
        e = ModbusScan()
        assert len(e.get_info()["references"]) > 0


class TestModbusScanDefaults:
    def test_default_port(self):
        e = ModbusScan()
        assert int(e.port) == 502

    def test_scan_range_default_false(self):
        e = ModbusScan()
        assert e.scan_range is False

    def test_has_probe_device_method(self):
        e = ModbusScan()
        assert hasattr(e, "_probe_device")
        assert callable(e._probe_device)

    def test_has_run_method(self):
        e = ModbusScan()
        assert hasattr(e, "run")
        assert callable(e.run)


class TestModbusScanProbe:
    def test_probe_device_with_no_response(self):
        e = ModbusScan()
        mock_sock = MagicMock()
        mock_sock.read_device_identification.return_value = None
        mock_sock.report_server_id.return_value = None
        result = e._probe_device(mock_sock)
        assert result is False

    def test_probe_device_with_fc43_response(self):
        e = ModbusScan()
        mock_sock = MagicMock()
        # Build a minimal FC43 response: at least 9 bytes, byte[7] = 0x2B
        resp = bytearray(12)
        resp[7] = 0x2B  # FC43 response
        resp[11] = 0    # object count = 0
        mock_sock.read_device_identification.return_value = bytes(resp)
        mock_sock.report_server_id.return_value = None
        result = e._probe_device(mock_sock)
        assert result is True

    def test_probe_device_with_fc43_exception(self):
        e = ModbusScan()
        mock_sock = MagicMock()
        resp = bytearray(10)
        resp[7] = 0xAB  # FC43 exception (0x80 | 0x2B)
        resp[8] = 0x01  # exception code
        mock_sock.read_device_identification.return_value = bytes(resp)
        mock_sock.report_server_id.return_value = None
        result = e._probe_device(mock_sock)
        assert result is True

    def test_probe_device_with_fc17_response(self):
        e = ModbusScan()
        mock_sock = MagicMock()
        mock_sock.read_device_identification.return_value = None
        resp = bytearray(20)
        resp[7] = 0x11  # FC17 response
        resp[9:15] = b"PLC001"
        mock_sock.report_server_id.return_value = bytes(resp)
        result = e._probe_device(mock_sock)
        assert result is True
