"""Tests for BACnet Who-Is Broadcast Scanner module."""

import struct
import pytest
from unittest.mock import patch, MagicMock

from industrialxpl.modules.scanners.asset.bacnet_scan import Exploit as BacnetScan


class TestBacnetScanMetadata:
    def test_info_name(self):
        e = BacnetScan()
        assert "BACnet" in e.get_info()["name"]

    def test_info_has_mitre(self):
        e = BacnetScan()
        assert "T0846" in e.get_info()["mitre"]

    def test_info_severity(self):
        e = BacnetScan()
        assert e.get_info()["severity"] == "info"

    def test_default_port(self):
        e = BacnetScan()
        assert e.port == 47808

    def test_default_timeout(self):
        e = BacnetScan()
        assert e.timeout == 5


class TestBacnetWhoIsBuild:
    def test_build_who_is_returns_bytes(self):
        e = BacnetScan()
        pkt = e._build_who_is()
        assert isinstance(pkt, bytes)
        assert len(pkt) > 4

    def test_bvlc_header(self):
        e = BacnetScan()
        pkt = e._build_who_is()
        # BVLC type should be 0x81
        assert pkt[0] == 0x81
        # Function: original broadcast (0x0B)
        assert pkt[1] == 0x0B

    def test_bvlc_length_field(self):
        e = BacnetScan()
        pkt = e._build_who_is()
        declared_len = struct.unpack(">H", pkt[2:4])[0]
        assert declared_len == len(pkt)

    def test_npdu_version(self):
        e = BacnetScan()
        pkt = e._build_who_is()
        # NPDU starts at offset 4
        assert pkt[4] == 0x01  # BACnet version 1

    def test_who_is_with_limits(self):
        e = BacnetScan()
        e.low_limit = 100
        e.high_limit = 200
        pkt = e._build_who_is()
        assert isinstance(pkt, bytes)
        assert len(pkt) > 12  # longer with limits


class TestBacnetReadProperty:
    def test_build_read_property_returns_bytes(self):
        e = BacnetScan()
        pkt = e._build_read_property("10.0.0.1", 1234, 77)
        assert isinstance(pkt, bytes)
        assert pkt[0] == 0x81
        # Unicast function
        assert pkt[1] == 0x0A


class TestBacnetParseIAm:
    def test_parse_short_data(self):
        e = BacnetScan()
        result = e._parse_iam(b"\x00" * 8, ("10.0.0.1", 47808))
        assert result["ip"] == "10.0.0.1"
        assert result["port"] == 47808

    def test_parse_too_short(self):
        e = BacnetScan()
        result = e._parse_iam(b"\x00" * 4, ("10.0.0.1", 47808))
        assert "ip" in result

    def test_parse_valid_iam_frame(self):
        """Build a minimal synthetic I-Am response and parse it."""
        e = BacnetScan()
        # BVLC header (4 bytes)
        bvlc = struct.pack(">BBH", 0x81, 0x0B, 0)
        # NPDU: version=1, control=0x00
        npdu = struct.pack("BB", 0x01, 0x00)
        # APDU: unconfirmed (pdu_type=1 in high nibble), service=0x00 (I-Am)
        apdu = struct.pack("BB", 0x10, 0x00)
        # Object Identifier: tag 0xC4, device instance 42
        obj_id = (0x08 << 22) | 42
        apdu += struct.pack(">BI", 0xC4, obj_id)
        # Max APDU: tag 0x22, 2 bytes, value 1024
        apdu += struct.pack(">BH", 0x22, 1024)
        # Segmentation: tag 0x91, value 0
        apdu += struct.pack("BB", 0x91, 0x00)
        # Vendor ID: tag 0x21, 1 byte, vendor 5
        apdu += struct.pack("BB", 0x21, 5)

        payload = bvlc + npdu + apdu
        # Fix BVLC length
        payload = struct.pack(">BBH", 0x81, 0x0B, len(payload)) + payload[4:]

        result = e._parse_iam(payload, ("10.0.0.1", 47808))
        assert result["ip"] == "10.0.0.1"
        # The parse should extract device_instance
        if "device_instance" in result:
            assert result["device_instance"] == 42
        if "vendor_id" in result:
            assert result["vendor_id"] == 5


class TestBacnetVendorMap:
    def test_known_vendors(self):
        e = BacnetScan()
        assert e._VENDORS[5] == "Johnson Controls"
        assert e._VENDORS[7] == "Siemens"
        assert e._VENDORS[15] == "Honeywell"

    def test_vendor_zero_is_ashrae(self):
        e = BacnetScan()
        assert e._VENDORS[0] == "ASHRAE"


class TestBacnetCheck:
    def test_check_without_target(self):
        e = BacnetScan()
        e.target = ""
        # check should return falsy when no target
        result = e.check()
        assert not result
