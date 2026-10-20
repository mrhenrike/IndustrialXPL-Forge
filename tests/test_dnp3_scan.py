"""Tests for DNP3 Data Link Layer Scanner module."""

import struct
import pytest

from industrialxpl.modules.scanners.asset.dnp3_scan import Exploit as Dnp3Scan


class TestDnp3ScanMetadata:
    def test_info_name(self):
        e = Dnp3Scan()
        info = e.get_info()
        assert "DNP3" in info["name"]

    def test_info_mitre(self):
        e = Dnp3Scan()
        assert "T0846" in e.get_info()["mitre"]

    def test_default_port(self):
        e = Dnp3Scan()
        assert e.port == 20000

    def test_default_master_addr(self):
        e = Dnp3Scan()
        assert e.master_addr == 1

    def test_default_scan_range(self):
        e = Dnp3Scan()
        assert e.scan_start == 1
        assert e.scan_end == 20


class TestDnp3CRC:
    def test_crc_returns_int(self):
        e = Dnp3Scan()
        crc = e._crc16_dnp3(b"\x05\x64")
        assert isinstance(crc, int)
        assert 0 <= crc <= 0xFFFF

    def test_crc_deterministic(self):
        e = Dnp3Scan()
        data = b"\x05\x64\x05\xc9\x01\x00\x01\x00"
        c1 = e._crc16_dnp3(data)
        c2 = e._crc16_dnp3(data)
        assert c1 == c2

    def test_crc_empty(self):
        e = Dnp3Scan()
        crc = e._crc16_dnp3(b"")
        assert isinstance(crc, int)

    def test_crc_different_for_different_data(self):
        e = Dnp3Scan()
        c1 = e._crc16_dnp3(b"\x00")
        c2 = e._crc16_dnp3(b"\x01")
        assert c1 != c2


class TestDnp3FrameBuilding:
    def test_link_status_returns_bytes(self):
        e = Dnp3Scan()
        frame = e._build_link_status_request(10)
        assert isinstance(frame, bytes)
        assert len(frame) == 10  # 8 header + 2 CRC

    def test_link_status_start_bytes(self):
        e = Dnp3Scan()
        frame = e._build_link_status_request(1)
        start = struct.unpack("<H", frame[:2])[0]
        assert start == 0x0564

    def test_link_status_length_field(self):
        e = Dnp3Scan()
        frame = e._build_link_status_request(1)
        length = frame[2]
        assert length == 5

    def test_link_status_control_byte(self):
        e = Dnp3Scan()
        frame = e._build_link_status_request(1)
        ctrl = frame[3]
        # DIR=1, PRM=1, FC=9 => 0x80 | 0x40 | 0x09 = 0xC9
        assert ctrl == 0xC9

    def test_link_status_dst_addr(self):
        e = Dnp3Scan()
        frame = e._build_link_status_request(42)
        dst = struct.unpack("<H", frame[4:6])[0]
        assert dst == 42

    def test_link_status_src_addr(self):
        e = Dnp3Scan()
        e.master_addr = 5
        frame = e._build_link_status_request(10)
        src = struct.unpack("<H", frame[6:8])[0]
        assert src == 5

    def test_test_link_returns_bytes(self):
        e = Dnp3Scan()
        frame = e._build_test_link(10)
        assert isinstance(frame, bytes)
        assert len(frame) == 10

    def test_test_link_control_byte(self):
        e = Dnp3Scan()
        frame = e._build_test_link(1)
        ctrl = frame[3]
        # DIR=1, PRM=1, FC=2 => 0x80 | 0x40 | 0x02 = 0xC2
        assert ctrl == 0xC2

    def test_crc_in_frame_is_valid(self):
        e = Dnp3Scan()
        frame = e._build_link_status_request(1)
        header = frame[:8]
        crc_in_frame = struct.unpack("<H", frame[8:10])[0]
        crc_calc = e._crc16_dnp3(header)
        assert crc_in_frame == crc_calc


class TestDnp3ParseResponse:
    def test_parse_empty(self):
        e = Dnp3Scan()
        result = e._parse_link_response(b"")
        assert isinstance(result, dict)

    def test_parse_short_data(self):
        e = Dnp3Scan()
        result = e._parse_link_response(b"\x05\x64\x05")
        assert isinstance(result, dict)
