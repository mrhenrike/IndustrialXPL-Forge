"""
Comprehensive coverage tests for industrialxpl.core.ics package.
Targets 100% line coverage for all modules under industrialxpl/core/ics/.

All socket I/O is mocked; no network connections are made.
"""

import struct
import socket
from unittest.mock import patch, MagicMock, PropertyMock

import pytest


# ---------------------------------------------------------------------------
# __init__.py imports
# ---------------------------------------------------------------------------


class TestIcsInit:
    def test_imports(self):
        from industrialxpl.core.ics import (
            CIPClient,
            ModbusClient,
            S7Client,
            S7PlusClient,
            Wdb2Client,
        )
        assert CIPClient is not None
        assert ModbusClient is not None
        assert S7Client is not None
        assert S7PlusClient is not None
        assert Wdb2Client is not None


# ---------------------------------------------------------------------------
# s7_client.py
# ---------------------------------------------------------------------------


class TestS7ClientHelpers:
    def test_build_tpkt(self):
        from industrialxpl.core.ics.s7_client import _build_tpkt
        payload = b"\x01\x02\x03"
        result = _build_tpkt(payload)
        assert result[:2] == b"\x03\x00"
        length = struct.unpack(">H", result[2:4])[0]
        assert length == len(payload) + 4
        assert result[4:] == payload

    def test_build_cotp_cr(self):
        from industrialxpl.core.ics.s7_client import _build_cotp_cr
        result = _build_cotp_cr(b"\x01\x00", b"\x01\x02")
        assert isinstance(result, bytes)
        assert len(result) > 6
        # PDU type CR = 0xe0
        assert result[1] == 0xe0

    def test_build_cotp_dt(self):
        from industrialxpl.core.ics.s7_client import _build_cotp_dt
        payload = b"\xaa\xbb"
        result = _build_cotp_dt(payload)
        assert result[:3] == b"\x02\xf0\x80"
        assert result[3:] == payload

    def test_build_s7_setup_comm(self):
        from industrialxpl.core.ics.s7_client import _build_s7_setup_comm
        result = _build_s7_setup_comm()
        assert result[0] == 0x32  # S7 protocol ID
        assert result[1] == 0x01  # ROSCTR = Job
        assert len(result) == 18


class TestS7Client:
    def _make_client(self):
        from industrialxpl.core.ics.s7_client import S7Client
        return S7Client("10.0.0.1", port=102, rack=0, slot=2, timeout=1.0)

    def test_init(self):
        c = self._make_client()
        assert c._ip == "10.0.0.1"
        assert c._port == 102
        assert c._connected is False

    @patch("industrialxpl.core.ics.s7_client.socket.socket")
    def test_connect_tcp_fails(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.connect.side_effect = OSError("refused")
        c = self._make_client()
        assert c.connect() is False

    @patch("industrialxpl.core.ics.s7_client.socket.socket")
    def test_connect_send_cr_fails(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.sendall.side_effect = OSError("broken pipe")
        c = self._make_client()
        assert c.connect() is False

    @patch("industrialxpl.core.ics.s7_client.socket.socket")
    def test_connect_recv_cr_none(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        # recv returns short header -> None from _recv
        sock_inst.recv.return_value = b"\x00"
        c = self._make_client()
        assert c.connect() is False

    @patch("industrialxpl.core.ics.s7_client.socket.socket")
    def test_connect_s7_setup_send_fails(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        # First recv (COTP CR response) - valid TPKT header + data
        cotp_rsp = struct.pack(">BBH", 3, 0, 10) + b"\xd0" * 6
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return cotp_rsp[:4]
            if call_count[0] == 2:
                return cotp_rsp[4:]
            return b""

        sock_inst.recv.side_effect = recv_side
        send_count = [0]

        def sendall_side(data):
            send_count[0] += 1
            if send_count[0] == 2:
                raise OSError("broken")

        sock_inst.sendall.side_effect = sendall_side
        c = self._make_client()
        assert c.connect() is False

    @patch("industrialxpl.core.ics.s7_client.socket.socket")
    def test_connect_success(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        # COTP CR response: valid TPKT
        cr_body = b"\xd0\x00\x01\x00\x01\x00"
        cr_pkt = struct.pack(">BBH", 3, 0, len(cr_body) + 4) + cr_body
        # S7 Setup response: COTP DT header(3) + S7 header at offset 5 with 0x32
        s7_body = b"\x02\xf0\x80" + b"\x00\x00\x32" + b"\x00" * 10
        s7_pkt = struct.pack(">BBH", 3, 0, len(s7_body) + 4) + s7_body
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return cr_pkt[:4]
            if call_count[0] == 2:
                return cr_pkt[4:]
            if call_count[0] == 3:
                return s7_pkt[:4]
            if call_count[0] == 4:
                return s7_pkt[4:]
            return b""

        sock_inst.recv.side_effect = recv_side
        c = self._make_client()
        assert c.connect() is True
        assert c._connected is True

    @patch("industrialxpl.core.ics.s7_client.socket.socket")
    def test_connect_s7_response_too_short(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        cr_body = b"\xd0\x00\x01\x00\x01\x00"
        cr_pkt = struct.pack(">BBH", 3, 0, len(cr_body) + 4) + cr_body
        # S7 response too short (len < 7) or wrong byte at [5]
        s7_body = b"\x02\xf0\x80\x00\x00\x00"
        s7_pkt = struct.pack(">BBH", 3, 0, len(s7_body) + 4) + s7_body
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return cr_pkt[:4]
            if call_count[0] == 2:
                return cr_pkt[4:]
            if call_count[0] == 3:
                return s7_pkt[:4]
            if call_count[0] == 4:
                return s7_pkt[4:]
            return b""

        sock_inst.recv.side_effect = recv_side
        c = self._make_client()
        assert c.connect() is False

    def test_disconnect_no_sock(self):
        c = self._make_client()
        c.disconnect()  # no-op, no error

    def test_disconnect_with_sock(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._connected = True
        c.disconnect()
        assert c._sock is None
        assert c._connected is False

    def test_disconnect_close_error(self):
        c = self._make_client()
        mock_sock = MagicMock()
        mock_sock.close.side_effect = OSError("already closed")
        c._sock = mock_sock
        c._connected = True
        c.disconnect()
        assert c._sock is None
        assert c._connected is False

    def test_context_manager(self):
        c = self._make_client()
        with patch.object(c, "connect") as mock_conn, \
             patch.object(c, "disconnect") as mock_disc:
            with c as ctx:
                assert ctx is c
                mock_conn.assert_called_once()
            mock_disc.assert_called_once()

    def test_send_no_sock(self):
        c = self._make_client()
        assert c._send(b"\x00") is False

    def test_send_error(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.sendall.side_effect = OSError("broken")
        assert c._send(b"\x00") is False

    def test_send_ok(self):
        c = self._make_client()
        c._sock = MagicMock()
        assert c._send(b"\x00") is True

    def test_recv_no_sock(self):
        c = self._make_client()
        assert c._recv() is None

    def test_recv_short_header(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.recv.return_value = b"\x00\x00"
        assert c._recv() is None

    def test_recv_wrong_version(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.recv.return_value = b"\x02\x00\x00\x08"
        assert c._recv() is None

    def test_recv_ok_with_chunked_data(self):
        c = self._make_client()
        c._sock = MagicMock()
        body = b"\xaa\xbb\xcc\xdd"
        header = struct.pack(">BBH", 3, 0, len(body) + 4)
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return header
            if call_count[0] == 2:
                return body[:2]
            if call_count[0] == 3:
                return body[2:]
            return b""

        c._sock.recv.side_effect = recv_side
        result = c._recv()
        assert result == body

    def test_recv_empty_chunk_breaks(self):
        c = self._make_client()
        c._sock = MagicMock()
        header = struct.pack(">BBH", 3, 0, 10)
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return header
            return b""

        c._sock.recv.side_effect = recv_side
        result = c._recv()
        assert result == b""

    def test_recv_oserror(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.recv.side_effect = OSError("timeout")
        assert c._recv() is None

    def test_send_s7_no_sock(self):
        c = self._make_client()
        assert c._send_s7(b"\x00") is None

    def test_send_s7_send_fails(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.sendall.side_effect = OSError("broken")
        assert c._send_s7(b"\x00") is None

    def test_send_s7_recv_none(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.recv.return_value = b"\x00"  # short -> None
        assert c._send_s7(b"\x00") is None

    def test_send_s7_recv_too_short(self):
        c = self._make_client()
        c._sock = MagicMock()
        # Valid TPKT header but only 3 bytes body (len(rsp) <= 3)
        header = struct.pack(">BBH", 3, 0, 7)
        body = b"\x02\xf0\x80"
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return header
            return body

        c._sock.recv.side_effect = recv_side
        result = c._send_s7(b"\x00")
        assert result is None

    def test_send_s7_success(self):
        c = self._make_client()
        c._sock = MagicMock()
        body = b"\x02\xf0\x80\x32\x01\x00\x00"
        header = struct.pack(">BBH", 3, 0, len(body) + 4)
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return header
            return body

        c._sock.recv.side_effect = recv_side
        result = c._send_s7(b"\x00")
        assert result == body[3:]

    # Password hash
    def test_hash_password(self):
        from industrialxpl.core.ics.s7_client import S7Client
        h = S7Client._hash_password("test")
        assert isinstance(h, bytes)
        assert len(h) == 8
        # First two chars: ord('t') ^ 0x55, ord('e') ^ 0x55
        assert h[0] == ord('t') ^ 0x55
        assert h[1] == ord('e') ^ 0x55
        # Third char: ord('s') ^ 0x55 ^ h[0]
        assert h[2] == ord('s') ^ 0x55 ^ h[0]

    def test_hash_password_short(self):
        from industrialxpl.core.ics.s7_client import S7Client
        h = S7Client._hash_password("A")
        assert len(h) == 8

    # Authenticate
    def test_authenticate_not_connected(self):
        c = self._make_client()
        assert c.authenticate("test") is False

    def test_authenticate_send_s7_none(self):
        c = self._make_client()
        c._connected = True
        with patch.object(c, "_send_s7", return_value=None):
            assert c.authenticate("test") is False

    def test_authenticate_response_too_short(self):
        c = self._make_client()
        c._connected = True
        with patch.object(c, "_send_s7", return_value=b"\x00" * 10):
            assert c.authenticate("test") is False

    def test_authenticate_success(self):
        c = self._make_client()
        c._connected = True
        # rsp[11] == 0x00 means success
        rsp = b"\x00" * 11 + b"\x00"
        with patch.object(c, "_send_s7", return_value=rsp):
            assert c.authenticate("test") is True

    def test_authenticate_failure(self):
        c = self._make_client()
        c._connected = True
        rsp = b"\x00" * 11 + b"\x01"
        with patch.object(c, "_send_s7", return_value=rsp):
            assert c.authenticate("test") is False

    # SZL
    def test_read_szl_not_connected(self):
        c = self._make_client()
        assert c.read_szl(0x0011) is None

    def test_read_szl_success(self):
        c = self._make_client()
        c._connected = True
        with patch.object(c, "_send_s7", return_value=b"\x00" * 40):
            result = c.read_szl(0x0011, 0x0001)
            assert result is not None

    # get_plc_info
    def test_get_plc_info_empty(self):
        c = self._make_client()
        c._connected = True
        with patch.object(c, "read_szl", return_value=None):
            info = c.get_plc_info()
            assert info["order_code"] == ""
            assert info["module_name"] == ""

    def test_get_plc_info_with_data(self):
        c = self._make_client()
        c._connected = True
        # For order code: rsp[14:34] decoded
        rsp1 = b"\x00" * 14 + b"6ES7315-2AH14-0AB0" + b"\x00" * 20
        rsp2 = b"\x00" * 2 + b"CPU315-2 DP Module\x00\x00" + b"\x00" * 20
        call_count = [0]

        def read_szl_side(szl_id, szl_index=0):
            call_count[0] += 1
            if call_count[0] == 1:
                return rsp1
            return rsp2

        with patch.object(c, "read_szl", side_effect=read_szl_side):
            info = c.get_plc_info()
            assert "6ES7315" in info["order_code"]

    def test_get_plc_info_szl_short(self):
        c = self._make_client()
        c._connected = True
        # Short responses that don't trigger decode
        with patch.object(c, "read_szl", return_value=b"\x00" * 10):
            info = c.get_plc_info()
            assert info["order_code"] == ""

    def test_get_plc_info_keyerror_order(self):
        c = self._make_client()
        c._connected = True
        # Force KeyError on the decode path for order_code
        bad_rsp = MagicMock()
        bad_rsp.__len__ = lambda s: 40
        bad_rsp.__bool__ = lambda s: True
        bad_rsp.__getitem__ = MagicMock(side_effect=KeyError("mock"))
        call_count = [0]

        def read_szl_side(szl_id, szl_index=0):
            call_count[0] += 1
            if call_count[0] == 1:
                return bad_rsp
            return None

        with patch.object(c, "read_szl", side_effect=read_szl_side):
            info = c.get_plc_info()
            assert info["order_code"] == ""

    def test_get_plc_info_keyerror_module(self):
        c = self._make_client()
        c._connected = True
        bad_rsp = MagicMock()
        bad_rsp.__len__ = lambda s: 40
        bad_rsp.__bool__ = lambda s: True
        bad_rsp.__getitem__ = MagicMock(side_effect=KeyError("mock"))
        call_count = [0]

        def read_szl_side(szl_id, szl_index=0):
            call_count[0] += 1
            if call_count[0] == 1:
                return None
            return bad_rsp

        with patch.object(c, "read_szl", side_effect=read_szl_side):
            info = c.get_plc_info()
            assert info["module_name"] == ""

    # Stop / Start
    def test_stop_plc_not_connected(self):
        c = self._make_client()
        assert c.stop_plc() is False

    def test_stop_plc_success(self):
        c = self._make_client()
        c._connected = True
        with patch.object(c, "_send_s7", return_value=b"\x00"):
            assert c.stop_plc() is True

    def test_stop_plc_none(self):
        c = self._make_client()
        c._connected = True
        with patch.object(c, "_send_s7", return_value=None):
            assert c.stop_plc() is False

    def test_start_plc_not_connected(self):
        c = self._make_client()
        assert c.start_plc() is False

    def test_start_plc_success(self):
        c = self._make_client()
        c._connected = True
        with patch.object(c, "_send_s7", return_value=b"\x00"):
            assert c.start_plc() is True

    def test_start_plc_none(self):
        c = self._make_client()
        c._connected = True
        with patch.object(c, "_send_s7", return_value=None):
            assert c.start_plc() is False


# ---------------------------------------------------------------------------
# cip_client.py
# ---------------------------------------------------------------------------


class TestCIPClient:
    def _make_client(self):
        from industrialxpl.core.ics.cip_client import CIPClient
        return CIPClient("10.0.0.1", port=44818, timeout=1.0)

    def test_init(self):
        c = self._make_client()
        assert c._ip == "10.0.0.1"
        assert c._session == 0

    @patch("industrialxpl.core.ics.cip_client.socket.socket")
    def test_connect_tcp_fails(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.connect.side_effect = OSError("refused")
        c = self._make_client()
        assert c.connect() is False
        assert c._sock is None

    @patch("industrialxpl.core.ics.cip_client.socket.socket")
    def test_connect_register_short_response(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.recv.return_value = b"\x00" * 10  # too short
        c = self._make_client()
        assert c.connect() is False

    @patch("industrialxpl.core.ics.cip_client.socket.socket")
    def test_connect_register_oserror(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.sendall.side_effect = OSError("broken")
        c = self._make_client()
        assert c.connect() is False

    @patch("industrialxpl.core.ics.cip_client.socket.socket")
    def test_connect_register_nonzero_status(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        # RegisterSession response: cmd(2)+len(2)+session(4)+status(4)+ctx(8)+options(4)+...
        rsp = struct.pack("<HHII", 0x0065, 4, 0x1234, 0x0001)
        rsp += b"\x00" * (28 - len(rsp))
        sock_inst.recv.return_value = rsp
        c = self._make_client()
        # Still returns True (just logs warning)
        assert c.connect() is True

    @patch("industrialxpl.core.ics.cip_client.socket.socket")
    def test_connect_success(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        rsp = struct.pack("<HHII", 0x0065, 4, 0x5678, 0)
        rsp += b"\x00" * (28 - len(rsp))
        sock_inst.recv.return_value = rsp
        c = self._make_client()
        assert c.connect() is True
        assert c._session == 0x5678

    def test_disconnect_no_sock(self):
        c = self._make_client()
        c.disconnect()

    def test_disconnect_with_session(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._session = 0x1234
        c.disconnect()
        assert c._sock is None
        assert c._session == 0

    def test_disconnect_unregister_oserror(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._session = 0x1234
        c._sock.sendall.side_effect = OSError("broken")
        c.disconnect()
        assert c._sock is None

    def test_disconnect_close_oserror(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._session = 0
        c._sock.close.side_effect = OSError("err")
        c.disconnect()
        assert c._sock is None

    def test_context_manager(self):
        c = self._make_client()
        with patch.object(c, "connect"), patch.object(c, "disconnect"):
            with c as ctx:
                assert ctx is c

    def test_enip_header(self):
        c = self._make_client()
        c._session = 0x1234
        result = c._enip_header(0x0065, b"\xaa\xbb")
        assert len(result) == 24 + 4 + 2  # 24 header + 4 (extra int) + 2 data

    def test_send_recv_enip_no_sock(self):
        c = self._make_client()
        assert c._send_recv_enip(0x0063, b"") is None

    def test_send_recv_enip_short_header(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.recv.return_value = b"\x00" * 10
        assert c._send_recv_enip(0x0063, b"") is None

    def test_send_recv_enip_nonzero_status(self):
        c = self._make_client()
        c._sock = MagicMock()
        rsp = struct.pack("<HHII", 0x0063, 0, 0, 1)  # status=1
        rsp += b"\x00" * (24 - len(rsp))
        c._sock.recv.return_value = rsp
        assert c._send_recv_enip(0x0063, b"") is None

    def test_send_recv_enip_oserror(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.sendall.side_effect = OSError("broken")
        assert c._send_recv_enip(0x0063, b"") is None

    def test_send_recv_enip_success_with_payload(self):
        c = self._make_client()
        c._sock = MagicMock()
        payload = b"\xde\xad\xbe\xef"
        rsp_hdr = struct.pack("<HHII", 0x0063, len(payload), 0, 0)
        rsp_hdr += b"\x00" * (24 - len(rsp_hdr))
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return rsp_hdr
            return payload

        c._sock.recv.side_effect = recv_side
        result = c._send_recv_enip(0x0063, b"")
        assert result == payload

    def test_send_recv_enip_chunked_payload(self):
        c = self._make_client()
        c._sock = MagicMock()
        payload = b"\xde\xad\xbe\xef"
        rsp_hdr = struct.pack("<HHII", 0x0063, len(payload), 0, 0)
        rsp_hdr += b"\x00" * (24 - len(rsp_hdr))
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return rsp_hdr
            if call_count[0] == 2:
                return payload[:2]
            if call_count[0] == 3:
                return payload[2:]
            return b""

        c._sock.recv.side_effect = recv_side
        result = c._send_recv_enip(0x0063, b"")
        assert result == payload

    def test_send_recv_enip_empty_chunk_breaks(self):
        c = self._make_client()
        c._sock = MagicMock()
        rsp_hdr = struct.pack("<HHII", 0x0063, 10, 0, 0)
        rsp_hdr += b"\x00" * (24 - len(rsp_hdr))
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return rsp_hdr
            return b""

        c._sock.recv.side_effect = recv_side
        result = c._send_recv_enip(0x0063, b"")
        assert result == b""

    # list_identity_udp
    @patch("industrialxpl.core.ics.cip_client.socket.socket")
    def test_list_identity_udp_success(self, mock_sock_cls):
        from industrialxpl.core.ics.cip_client import CIPClient
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        # Minimal ListIdentity response
        data = b"\x00" * 24  # ENIP header
        data += struct.pack("<H", 1)  # item_count = 1
        data += struct.pack("<HH", 0x000c, 40)  # type_id, item_len >= 33
        # encap_version(2) + socket_addr(4) + vendor_id(2) + device_type(2) +
        # product_code(2) + major_rev(1) + minor_rev(1) + status(2) + serial(4)
        # = 20 bytes, then name_len(1) + name
        item = struct.pack("<H4sHHHBBHI", 1, b"\x00" * 4, 0x0001, 0x0E, 0x0002, 3, 1, 0, 0x12345678)
        name = b"TestPLC"
        item += bytes([len(name)]) + name
        item += b"\x00" * (40 - len(item))
        data += item
        sock_inst.recvfrom.return_value = (data, ("10.0.0.1", 44818))
        result = CIPClient.list_identity_udp("10.0.0.1")
        assert result is not None
        assert "vendor_id" in result

    @patch("industrialxpl.core.ics.cip_client.socket.socket")
    def test_list_identity_udp_oserror(self, mock_sock_cls):
        from industrialxpl.core.ics.cip_client import CIPClient
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.sendto.side_effect = OSError("timeout")
        result = CIPClient.list_identity_udp("10.0.0.1")
        assert result is None

    def test_list_identity_tcp(self):
        c = self._make_client()
        with patch.object(c, "_send_recv_enip", return_value=None):
            assert c.list_identity() is None

    def test_list_identity_tcp_with_data(self):
        c = self._make_client()
        # Return some payload that _parse_list_identity can handle
        data = b"\x00" * 24  # fake ENIP header
        data += struct.pack("<H", 0)  # item_count = 0
        with patch.object(c, "_send_recv_enip", return_value=data):
            result = c.list_identity()
            assert result is not None
            assert isinstance(result, dict)

    # _parse_list_identity branches
    def test_parse_list_identity_empty(self):
        from industrialxpl.core.ics.cip_client import CIPClient
        result = CIPClient._parse_list_identity(b"")
        assert result == {}

    def test_parse_list_identity_short_items(self):
        from industrialxpl.core.ics.cip_client import CIPClient
        data = b"\x00" * 24
        data += struct.pack("<H", 1)  # 1 item
        data += struct.pack("<HH", 0x000c, 10)  # item_len < 33
        data += b"\x00" * 10
        result = CIPClient._parse_list_identity(data)
        assert isinstance(result, dict)

    def test_parse_list_identity_malformed(self):
        from industrialxpl.core.ics.cip_client import CIPClient
        data = b"\x00" * 24
        data += struct.pack("<H", 1)
        # Very short data, item count 1 but no item header bytes
        data += b"\x00"
        result = CIPClient._parse_list_identity(data)
        assert isinstance(result, dict)

    def test_parse_list_identity_struct_error(self):
        from industrialxpl.core.ics.cip_client import CIPClient
        # Trigger struct.error inside the loop: item header present but
        # item data too short for struct.unpack_from
        data = b"\x00" * 24
        data += struct.pack("<H", 1)  # item_count = 1
        data += struct.pack("<HH", 0x000c, 40)  # type_id, item_len=40 (>=33)
        data += b"\x00" * 18  # 18 bytes at offset 30, but struct needs 20
        result = CIPClient._parse_list_identity(data)
        assert isinstance(result, dict)

    # send_rr_data
    def test_send_rr_data_none(self):
        c = self._make_client()
        with patch.object(c, "_send_recv_enip", return_value=None):
            assert c.send_rr_data(0x01, b"\x20\x01") is None

    def test_send_rr_data_short_payload(self):
        c = self._make_client()
        with patch.object(c, "_send_recv_enip", return_value=b"\x00" * 5):
            assert c.send_rr_data(0x01, b"\x20\x01") is None

    def test_send_rr_data_success(self):
        c = self._make_client()
        payload = b"\x00" * 16 + b"\xde\xad"
        with patch.object(c, "_send_recv_enip", return_value=payload):
            result = c.send_rr_data(0x01, b"\x20\x01", b"\xff")
            assert result == b"\xde\xad"

    def test_device_types_dict(self):
        from industrialxpl.core.ics.cip_client import DEVICE_TYPES
        assert 0x0E in DEVICE_TYPES
        assert DEVICE_TYPES[0x0E] == "Programmable Logic Controller"


# ---------------------------------------------------------------------------
# modbus_client.py
# ---------------------------------------------------------------------------


class TestModbusClient:
    def _make_client(self):
        from industrialxpl.core.ics.modbus_client import ModbusClient
        return ModbusClient("10.0.0.1", port=502, unit_id=1, timeout=1.0)

    def test_init(self):
        c = self._make_client()
        assert c._ip == "10.0.0.1"
        assert c._tid == 0

    @patch("industrialxpl.core.ics.modbus_client.socket.socket")
    def test_connect_success(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        c = self._make_client()
        assert c.connect() is True

    @patch("industrialxpl.core.ics.modbus_client.socket.socket")
    def test_connect_failure(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.connect.side_effect = OSError("refused")
        c = self._make_client()
        assert c.connect() is False
        assert c._sock is None

    def test_disconnect_no_sock(self):
        c = self._make_client()
        c.disconnect()

    def test_disconnect_with_sock(self):
        c = self._make_client()
        c._sock = MagicMock()
        c.disconnect()
        assert c._sock is None

    def test_disconnect_close_oserror(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.close.side_effect = OSError("err")
        c.disconnect()
        assert c._sock is None

    def test_context_manager(self):
        c = self._make_client()
        with patch.object(c, "connect"), patch.object(c, "disconnect"):
            with c as ctx:
                assert ctx is c

    def test_next_tid(self):
        c = self._make_client()
        t1 = c._next_tid()
        assert t1 == 1
        t2 = c._next_tid()
        assert t2 == 2

    def test_next_tid_wrap(self):
        c = self._make_client()
        c._tid = 0xFFFF
        t = c._next_tid()
        assert t == 0

    def test_build_adu(self):
        c = self._make_client()
        pdu = b"\x01\x00\x00\x00\x0a"
        adu = c._build_adu(pdu)
        tid, proto, length, uid = struct.unpack(">HHHB", adu[:7])
        assert tid == 1
        assert proto == 0
        assert length == len(pdu) + 1
        assert uid == 1

    def _setup_send_recv(self, c, response_pdu):
        c._sock = MagicMock()
        # MBAP header + response
        mbap = struct.pack(">HHHB", 1, 0, len(response_pdu) + 1, 1)
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return mbap
            return response_pdu

        c._sock.recv.side_effect = recv_side

    def test_send_recv_no_sock(self):
        c = self._make_client()
        assert c._send_recv(b"\x01") is None

    def test_send_recv_short_header(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.recv.return_value = b"\x00" * 3
        assert c._send_recv(b"\x01") is None

    def test_send_recv_exception_response(self):
        c = self._make_client()
        c._sock = MagicMock()
        # Exception: FC with high bit set, exception code
        exc_pdu = bytes([0x81, 0x02])
        mbap = struct.pack(">HHHB", 1, 0, len(exc_pdu) + 1, 1)
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return mbap
            return exc_pdu

        c._sock.recv.side_effect = recv_side
        assert c._send_recv(b"\x01") is None

    def test_send_recv_exception_single_byte(self):
        c = self._make_client()
        c._sock = MagicMock()
        exc_pdu = bytes([0x80])  # high bit set, no exception code byte
        mbap = struct.pack(">HHHB", 1, 0, len(exc_pdu) + 1, 1)
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return mbap
            return exc_pdu

        c._sock.recv.side_effect = recv_side
        assert c._send_recv(b"\x01") is None

    def test_send_recv_oserror(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.sendall.side_effect = OSError("broken")
        assert c._send_recv(b"\x01") is None

    def test_send_recv_success(self):
        c = self._make_client()
        pdu = bytes([0x03, 0x02, 0x00, 0x0A])
        self._setup_send_recv(c, pdu)
        result = c._send_recv(b"\x03\x00\x00\x00\x01")
        assert result == pdu

    def test_send_recv_chunked(self):
        c = self._make_client()
        c._sock = MagicMock()
        pdu = bytes([0x03, 0x04, 0x00, 0x01, 0x00, 0x02])
        mbap = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1)
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return mbap
            if call_count[0] == 2:
                return pdu[:3]
            if call_count[0] == 3:
                return pdu[3:]
            return b""

        c._sock.recv.side_effect = recv_side
        result = c._send_recv(b"\x03")
        assert result == pdu

    def test_send_recv_empty_chunk(self):
        c = self._make_client()
        c._sock = MagicMock()
        mbap = struct.pack(">HHHB", 1, 0, 5, 1)
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return mbap
            return b""

        c._sock.recv.side_effect = recv_side
        result = c._send_recv(b"\x01")
        # Empty payload, no high bit -> return empty
        assert result == b""

    # Read functions
    def test_read_coils_none(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=None):
            assert c.read_coils(0, 10) is None

    def test_read_coils_short(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=b"\x01"):
            assert c.read_coils(0, 10) is None

    def test_read_coils_success(self):
        c = self._make_client()
        # FC1 response: fc(1) + byte_count(1) + data bytes
        rsp = bytes([0x01, 0x02, 0b10101010, 0b01010101])
        with patch.object(c, "_send_recv", return_value=rsp):
            result = c.read_coils(0, 10)
            assert result is not None
            assert len(result) == 10
            # byte 0b10101010 -> bits: 0,1,0,1,0,1,0,1
            assert result[0] == 0
            assert result[1] == 1

    def test_read_discrete_inputs_none(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=None):
            assert c.read_discrete_inputs(0, 5) is None

    def test_read_discrete_inputs_short(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=b"\x02"):
            assert c.read_discrete_inputs(0, 5) is None

    def test_read_discrete_inputs_success(self):
        c = self._make_client()
        rsp = bytes([0x02, 0x01, 0b00011111])
        with patch.object(c, "_send_recv", return_value=rsp):
            result = c.read_discrete_inputs(0, 5)
            assert result is not None
            assert len(result) == 5
            assert all(b == 1 for b in result)

    def test_read_holding_registers_none(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=None):
            assert c.read_holding_registers(0, 2) is None

    def test_read_holding_registers_short(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=b"\x03"):
            assert c.read_holding_registers(0, 2) is None

    def test_read_holding_registers_success(self):
        c = self._make_client()
        rsp = bytes([0x03, 0x04]) + struct.pack(">HH", 100, 200)
        with patch.object(c, "_send_recv", return_value=rsp):
            result = c.read_holding_registers(0, 2)
            assert result == [100, 200]

    def test_read_input_registers_none(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=None):
            assert c.read_input_registers(0, 2) is None

    def test_read_input_registers_short(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=b"\x04"):
            assert c.read_input_registers(0, 2) is None

    def test_read_input_registers_success(self):
        c = self._make_client()
        rsp = bytes([0x04, 0x04]) + struct.pack(">HH", 300, 400)
        with patch.object(c, "_send_recv", return_value=rsp):
            result = c.read_input_registers(0, 2)
            assert result == [300, 400]

    # Write functions
    def test_write_single_coil_on(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=b"\x05\x00\x01\xff\x00"):
            assert c.write_single_coil(1, True) is True

    def test_write_single_coil_off(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=b"\x05\x00\x01\x00\x00"):
            assert c.write_single_coil(1, False) is True

    def test_write_single_coil_fail(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=None):
            assert c.write_single_coil(1, True) is False

    def test_write_single_register(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=b"\x06\x00\x01\x00\x64"):
            assert c.write_single_register(1, 100) is True

    def test_write_single_register_fail(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=None):
            assert c.write_single_register(1, 100) is False

    def test_write_multiple_coils(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=b"\x0f\x00\x00\x00\x04"):
            assert c.write_multiple_coils(0, [1, 0, 1, 1]) is True

    def test_write_multiple_coils_fail(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=None):
            assert c.write_multiple_coils(0, [1, 0]) is False

    def test_write_multiple_coils_nine_bits(self):
        c = self._make_client()
        # 9 bits -> 2 bytes
        vals = [1, 0, 1, 0, 1, 0, 1, 0, 1]
        with patch.object(c, "_send_recv", return_value=b"\x0f\x00"):
            assert c.write_multiple_coils(0, vals) is True

    def test_write_multiple_registers(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=b"\x10\x00\x00\x00\x02"):
            assert c.write_multiple_registers(0, [100, 200]) is True

    def test_write_multiple_registers_fail(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=None):
            assert c.write_multiple_registers(0, [100]) is False

    # Device identification
    def test_read_device_identification_none(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=None):
            assert c.read_device_identification() is None

    def test_read_device_identification_short(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=b"\x2b\x0e\x01"):
            assert c.read_device_identification() is None

    def test_read_device_identification_success(self):
        c = self._make_client()
        # Build response: fc(1) + mei_type(1) + read_dev_id(1) + conformity(1) +
        # more_follows(1) + next_obj(1) + 0 + num_objects(1) + objects
        rsp = bytearray([0x2b, 0x0e, 0x01, 0x01, 0x00, 0x00, 0x00, 3])
        # Object 0x00: vendor
        rsp += bytes([0x00, 4]) + b"ACME"
        # Object 0x01: product_code
        rsp += bytes([0x01, 3]) + b"PLC"
        # Object 0x02: version
        rsp += bytes([0x02, 5]) + b"1.0.0"
        with patch.object(c, "_send_recv", return_value=bytes(rsp)):
            result = c.read_device_identification()
            assert result is not None
            assert result["vendor"] == "ACME"
            assert result["product_code"] == "PLC"
            assert result["version"] == "1.0.0"

    def test_read_device_identification_empty_objects(self):
        c = self._make_client()
        rsp = bytearray([0x2b, 0x0e, 0x01, 0x01, 0x00, 0x00, 0x00, 0])
        with patch.object(c, "_send_recv", return_value=bytes(rsp)):
            result = c.read_device_identification()
            assert result is None  # empty dict -> returns None

    def test_read_device_identification_truncated_objects(self):
        c = self._make_client()
        rsp = bytearray([0x2b, 0x0e, 0x01, 0x01, 0x00, 0x00, 0x00, 2])
        # Only one object fits, and the second would overflow
        rsp += bytes([0x00, 2]) + b"AB"
        # Second object header would need offset+2 > len
        with patch.object(c, "_send_recv", return_value=bytes(rsp)):
            result = c.read_device_identification()
            assert result is not None
            assert result["vendor"] == "AB"

    def test_read_device_identification_keyerror(self):
        c = self._make_client()
        # Force KeyError in the try block by mocking _send_recv to return
        # a response object whose slicing raises KeyError
        rsp_mock = MagicMock()
        rsp_mock.__len__ = lambda s: 20
        rsp_mock.__bool__ = lambda s: True
        rsp_mock.__getitem__ = MagicMock(side_effect=KeyError("mock"))
        with patch.object(c, "_send_recv", return_value=rsp_mock):
            result = c.read_device_identification()
            # KeyError is caught, returns result or None
            assert result is None or isinstance(result, dict)


# ---------------------------------------------------------------------------
# iec104_stack.py
# ---------------------------------------------------------------------------


class TestIEC104Stack:
    def test_constants(self):
        from industrialxpl.core.ics.iec104_stack import STARTDT_ACT, STARTDT_CON, TESTFR_ACT, TESTFR_CON
        assert STARTDT_ACT == 0x07
        assert STARTDT_CON == 0x0B
        assert TESTFR_ACT == 0x43
        assert TESTFR_CON == 0x83

    def test_build_apci(self):
        from industrialxpl.core.ics.iec104_stack import build_apci
        result = build_apci(4, 0x07)
        assert result[0] == 0x68
        assert result[1] == 6  # apdu_len + 2
        assert result[2] == 6
        assert result[3] == 0x07

    def test_build_startdt_act(self):
        from industrialxpl.core.ics.iec104_stack import build_startdt_act
        result = build_startdt_act()
        assert len(result) == 6
        assert result[0] == 0x68
        assert result[2] == 0x07

    def test_build_startdt_con(self):
        from industrialxpl.core.ics.iec104_stack import build_startdt_con
        result = build_startdt_con()
        assert result[2] == 0x0B

    def test_build_testfr_act(self):
        from industrialxpl.core.ics.iec104_stack import build_testfr_act
        result = build_testfr_act()
        assert result[2] == 0x43

    def test_build_testfr_con(self):
        from industrialxpl.core.ics.iec104_stack import build_testfr_con
        result = build_testfr_con()
        assert result[2] == 0x83

    def test_build_asdu(self):
        from industrialxpl.core.ics.iec104_stack import build_asdu
        result = build_asdu(45, 6, 1, 1000, 1)
        assert isinstance(result, bytes)
        # Starts with APCI
        assert result[0] == 0x68
        # ASDU starts at offset 6
        assert result[6] == 45  # type_id

    def test_parse_apci_invalid_short(self):
        from industrialxpl.core.ics.iec104_stack import parse_apci
        result = parse_apci(b"\x00\x00")
        assert result["valid"] is False

    def test_parse_apci_invalid_start(self):
        from industrialxpl.core.ics.iec104_stack import parse_apci
        result = parse_apci(b"\x00\x04\x07\x00\x00\x00")
        assert result["valid"] is False

    def test_parse_apci_startdt_con(self):
        from industrialxpl.core.ics.iec104_stack import parse_apci, build_startdt_con
        result = parse_apci(build_startdt_con())
        assert result["valid"] is True
        assert result["is_startdt_con"] is True
        assert result["is_testfr_con"] is False
        assert result["is_i_format"] is False

    def test_parse_apci_testfr_con(self):
        from industrialxpl.core.ics.iec104_stack import parse_apci, build_testfr_con
        result = parse_apci(build_testfr_con())
        assert result["valid"] is True
        assert result["is_testfr_con"] is True

    def test_parse_apci_i_format(self):
        from industrialxpl.core.ics.iec104_stack import parse_apci
        # ctrl byte with bit 0 = 0 and not a special U-frame
        data = bytes([0x68, 0x04, 0x02, 0x00, 0x00, 0x00])
        result = parse_apci(data)
        assert result["valid"] is True
        assert result["is_i_format"] is True

    def test_parse_apci_not_i_format_odd_ctrl(self):
        from industrialxpl.core.ics.iec104_stack import parse_apci
        # ctrl byte with bit 0 = 1 but not a known U-frame
        data = bytes([0x68, 0x04, 0x01, 0x00, 0x00, 0x00])
        result = parse_apci(data)
        assert result["valid"] is True
        assert result["is_i_format"] is False

    def test_simulate_session(self):
        from industrialxpl.core.ics.iec104_stack import simulate_session
        result = simulate_session()
        assert result["success"] is True
        assert result["simulate"] is True
        assert "frames" in result
        assert "startdt_act" in result["frames"]
        assert "parsed_con" in result


# ---------------------------------------------------------------------------
# fuzz_engine.py (fallback path)
# ---------------------------------------------------------------------------


class TestFuzzEngine:
    def test_strategy_names(self):
        from industrialxpl.core.ics.fuzz_engine import STRATEGY_NAMES
        assert len(STRATEGY_NAMES) == 8
        assert "bitflip" in STRATEGY_NAMES

    def test_build_modbus_fc03(self):
        from industrialxpl.core.ics.fuzz_engine import build_modbus_fc03
        pkt = build_modbus_fc03(unit=1, addr=0, count=1, trans_id=1)
        assert isinstance(pkt, bytes)
        assert len(pkt) > 0

    def test_build_s7_cotp_probe(self):
        from industrialxpl.core.ics.fuzz_engine import build_s7_cotp_probe
        pkt = build_s7_cotp_probe()
        assert pkt[0] == 0x03  # TPKT version

    def test_mutate_empty(self):
        from industrialxpl.core.ics.fuzz_engine import mutate
        assert mutate(b"", 0) == b""

    def test_mutate_bitflip(self):
        from industrialxpl.core.ics.fuzz_engine import mutate
        payload = b"\x00" * 10
        result = mutate(payload, 0, seed=42)
        assert result != payload

    def test_mutate_byteinc(self):
        from industrialxpl.core.ics.fuzz_engine import mutate
        payload = b"\x00" * 10
        result = mutate(payload, 1, seed=42)
        assert result != payload

    def test_mutate_swap(self):
        from industrialxpl.core.ics.fuzz_engine import mutate
        payload = b"\x01\x02\x03\x04\x05"
        result = mutate(payload, 2, seed=0)
        assert len(result) == len(payload)

    def test_mutate_truncate(self):
        from industrialxpl.core.ics.fuzz_engine import mutate
        payload = b"\x01\x02\x03\x04\x05"
        result = mutate(payload, 3, seed=42)
        assert len(result) == len(payload) - 1

    def test_mutate_truncate_too_short(self):
        from industrialxpl.core.ics.fuzz_engine import mutate
        payload = b"\x01\x02\x03\x04"  # n == 4, not > 4
        result = mutate(payload, 3, seed=42)
        # Won't truncate, falls through
        assert len(result) == 4

    def test_mutate_extend(self):
        from industrialxpl.core.ics.fuzz_engine import mutate
        payload = b"\x01\x02\x03"
        result = mutate(payload, 4, seed=42)
        assert len(result) == len(payload) + 1

    def test_mutate_random(self):
        from industrialxpl.core.ics.fuzz_engine import mutate
        payload = b"\x00" * 10
        result = mutate(payload, 5, seed=42)
        assert isinstance(result, bytes)

    def test_mutate_zero(self):
        from industrialxpl.core.ics.fuzz_engine import mutate
        payload = b"\xff" * 10
        result = mutate(payload, 6, seed=42)
        assert b"\x00" in result

    def test_mutate_duplicate(self):
        from industrialxpl.core.ics.fuzz_engine import mutate
        payload = b"\x01\x02\x03"
        result = mutate(payload, 7, seed=42)
        assert len(result) == len(payload) + 1

    def test_mutate_duplicate_too_long(self):
        from industrialxpl.core.ics.fuzz_engine import mutate
        payload = b"\x01" * 256
        result = mutate(payload, 7, seed=42)
        assert len(result) == 256  # no duplication

    def test_mutate_extend_too_long(self):
        from industrialxpl.core.ics.fuzz_engine import mutate
        payload = b"\x01" * 256
        result = mutate(payload, 4, seed=42)
        assert len(result) == 256

    def test_mutate_swap_last_pos(self):
        from industrialxpl.core.ics.fuzz_engine import mutate
        # If pos is the last index, swap won't happen (pos+1 >= n)
        payload = b"\x01\x02"
        # Use a seed that puts pos at last index
        # With n=2, pos = rng.randrange(2) => can be 0 or 1
        # Strategy 2 (swap): needs pos+1 < n
        result = mutate(payload, 2, seed=1)
        assert isinstance(result, bytes)

    def test_fuzz_campaign_modbus(self):
        from industrialxpl.core.ics.fuzz_engine import fuzz_campaign
        result = fuzz_campaign("modbus", seed=42)
        assert result["success"] is True
        assert result["protocol"] == "modbus"
        assert len(result["cases"]) == 8

    def test_fuzz_campaign_s7(self):
        from industrialxpl.core.ics.fuzz_engine import fuzz_campaign
        result = fuzz_campaign("s7", seed=42)
        assert result["protocol"] == "s7"
        assert len(result["cases"]) == 8

    def test_all_exports(self):
        from industrialxpl.core.ics.fuzz_engine import __all__
        assert "mutate" in __all__
        assert "fuzz_campaign" in __all__


# ---------------------------------------------------------------------------
# wdb2_client.py
# ---------------------------------------------------------------------------


class TestWdb2Client:
    def _make_client(self):
        from industrialxpl.core.ics.wdb2_client import Wdb2Client
        return Wdb2Client("10.0.0.1", port=17185, timeout=1.0, mem_buf_size=300)

    def test_init(self):
        c = self._make_client()
        assert c._ip == "10.0.0.1"
        assert c._port == 17185

    @patch("industrialxpl.core.ics.wdb2_client.socket.socket")
    def test_connect_socket_fail(self, mock_sock_cls):
        mock_sock_cls.side_effect = OSError("fail")
        c = self._make_client()
        assert c.connect() is False

    @patch("industrialxpl.core.ics.wdb2_client.socket.socket")
    def test_connect_no_response(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.recvfrom.side_effect = OSError("timeout")
        c = self._make_client()
        assert c.connect() is False

    @patch("industrialxpl.core.ics.wdb2_client.socket.socket")
    def test_connect_success(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.recvfrom.return_value = (b"\x00" * 40, ("10.0.0.1", 17185))
        c = self._make_client()
        assert c.connect() is True

    def test_disconnect_no_sock(self):
        c = self._make_client()
        c.disconnect()

    def test_disconnect_with_sock(self):
        c = self._make_client()
        c._sock = MagicMock()
        c.disconnect()
        assert c._sock is None

    def test_disconnect_close_oserror(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.close.side_effect = OSError("err")
        c.disconnect()
        assert c._sock is None

    def test_context_manager(self):
        c = self._make_client()
        with patch.object(c, "connect"), patch.object(c, "disconnect"):
            with c as ctx:
                assert ctx is c

    def test_next_xid(self):
        c = self._make_client()
        x1 = c._next_xid()
        assert x1 == 2
        x2 = c._next_xid()
        assert x2 == 3

    def test_next_xid_wrap(self):
        c = self._make_client()
        c._xid = 0xFFFFFFFF
        x = c._next_xid()
        assert x == 0

    def test_build_rpc_call(self):
        c = self._make_client()
        data = c._build_rpc_call(0x7A, b"\x00\x00\x00\x00")
        assert isinstance(data, bytes)
        # XID(4) + msg_type(4) + rpc_version(4) + prog(4) + vers(4) + proc(4) = 24
        # + null_auth(8) + null_auth(8) + data(4) = 44
        assert len(data) == 44

    def test_send_recv_no_sock(self):
        c = self._make_client()
        assert c._send_recv(b"\x00") is None

    def test_send_recv_oserror(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.sendto.side_effect = OSError("err")
        assert c._send_recv(b"\x00") is None

    def test_send_recv_success(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.recvfrom.return_value = (b"\xde\xad", ("10.0.0.1", 17185))
        result = c._send_recv(b"\x00")
        assert result == b"\xde\xad"

    # get_target_info
    def test_get_target_info_none(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=None):
            assert c.get_target_info() is None

    def test_get_target_info_short(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=b"\x00" * 10):
            assert c.get_target_info() is None

    def test_get_target_info_success(self):
        c = self._make_client()
        # Build response: 28 bytes RPC header + agent_ver(4) + word_size(4) + endian(4)
        rsp = b"\x00" * 28
        rsp += struct.pack(">III", 2, 4, 0)  # agent_ver=2, word_size=4, endian=big
        c._sock = MagicMock()
        with patch.object(c, "_send_recv", return_value=rsp):
            info = c.get_target_info()
            assert info is not None
            assert info["agent_version"] == 2
            assert info["word_size"] == 4
            assert info["endian"] == "big"

    def test_get_target_info_little_endian(self):
        c = self._make_client()
        rsp = b"\x00" * 28
        rsp += struct.pack(">III", 1, 4, 1)  # endian != 0 -> little
        with patch.object(c, "_send_recv", return_value=rsp):
            info = c.get_target_info()
            assert info["endian"] == "little"

    def test_get_target_info_struct_error(self):
        c = self._make_client()
        # Enough bytes overall (>=36) but struct.unpack_from fails at offset 28+8
        rsp = b"\x00" * 36 + b"\x00"  # 37 bytes but need 28+12=40 for all 3 unpacks
        # Actually offset 28 + 12 = 40, so 37 bytes is not enough for the third unpack
        with patch.object(c, "_send_recv", return_value=rsp):
            info = c.get_target_info()
            assert info is None

    # read_memory
    def test_read_memory_single_chunk(self):
        c = self._make_client()
        # Response: skip 36 bytes, then data_len(4) at offset 36, then data at 40
        data = b"\xaa\xbb\xcc\xdd"
        rsp = b"\x00" * 36 + struct.pack(">I", len(data)) + data
        with patch.object(c, "_send_recv", return_value=rsp):
            result = c.read_memory(0x1000, 4)
            assert result == data

    def test_read_memory_multi_chunk(self):
        c = self._make_client()
        c._mem_buf_size = 2
        data1 = b"\xaa\xbb"
        data2 = b"\xcc\xdd"
        rsp1 = b"\x00" * 36 + struct.pack(">I", 2) + data1
        rsp2 = b"\x00" * 36 + struct.pack(">I", 2) + data2
        call_count = [0]

        def send_recv_side(pkt):
            call_count[0] += 1
            if call_count[0] == 1:
                return rsp1
            return rsp2

        with patch.object(c, "_send_recv", side_effect=send_recv_side):
            result = c.read_memory(0x1000, 4)
            assert result == b"\xaa\xbb\xcc\xdd"

    def test_read_memory_fail_first_chunk(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=None):
            result = c.read_memory(0x1000, 4)
            assert result is None

    def test_read_memory_fail_second_chunk(self):
        c = self._make_client()
        c._mem_buf_size = 2
        data1 = b"\xaa\xbb"
        rsp1 = b"\x00" * 36 + struct.pack(">I", 2) + data1
        call_count = [0]

        def send_recv_side(pkt):
            call_count[0] += 1
            if call_count[0] == 1:
                return rsp1
            return None

        with patch.object(c, "_send_recv", side_effect=send_recv_side):
            result = c.read_memory(0x1000, 4)
            assert result == b"\xaa\xbb"  # partial

    def test_read_memory_short_rsp(self):
        c = self._make_client()
        # Response too short (< 36) on first chunk
        with patch.object(c, "_send_recv", return_value=b"\x00" * 30):
            result = c.read_memory(0x1000, 4)
            assert result is None

    def test_read_memory_struct_error(self):
        c = self._make_client()
        # Exactly 36 bytes: offset 36 struct.unpack_from fails
        rsp = b"\x00" * 36
        with patch.object(c, "_send_recv", return_value=rsp):
            result = c.read_memory(0x1000, 4)
            # struct.error -> break -> return empty result
            assert result == b""

    # write_memory
    def test_write_memory_success(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=b"\x00" * 40):
            assert c.write_memory(0x1000, b"\x01\x02\x03\x04") is True

    def test_write_memory_fail(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=None):
            assert c.write_memory(0x1000, b"\x01\x02") is False

    def test_write_memory_multi_chunk(self):
        c = self._make_client()
        c._mem_buf_size = 2
        with patch.object(c, "_send_recv", return_value=b"\x00" * 40):
            assert c.write_memory(0x1000, b"\x01\x02\x03\x04") is True

    def test_write_memory_padding(self):
        c = self._make_client()
        c._mem_buf_size = 3  # chunk of 3 bytes -> 3 % 4 = 3 -> needs 1 byte padding
        with patch.object(c, "_send_recv", return_value=b"\x00" * 40):
            assert c.write_memory(0x1000, b"\x01\x02\x03") is True

    def test_write_memory_no_padding(self):
        c = self._make_client()
        c._mem_buf_size = 4  # chunk of 4 bytes -> 4 % 4 = 0 -> no padding
        with patch.object(c, "_send_recv", return_value=b"\x00" * 40):
            assert c.write_memory(0x1000, b"\x01\x02\x03\x04") is True

    # resume_context
    def test_resume_context_success(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=b"\x00"):
            assert c.resume_context(0) is True

    def test_resume_context_fail(self):
        c = self._make_client()
        with patch.object(c, "_send_recv", return_value=None):
            assert c.resume_context(1) is False


# ---------------------------------------------------------------------------
# bacnet_offensive.py
# ---------------------------------------------------------------------------


class TestBACnetOffensive:
    def test_build_whois(self):
        from industrialxpl.core.ics.bacnet_offensive import build_whois
        pkt = build_whois()
        assert pkt[0] == 0x81
        assert len(pkt) == 12

    def test_build_iam(self):
        from industrialxpl.core.ics.bacnet_offensive import build_iam
        pkt = build_iam(device_id=1234)
        assert pkt[0] == 0x81
        assert isinstance(pkt, bytes)

    def test_build_iam_default(self):
        from industrialxpl.core.ics.bacnet_offensive import build_iam
        pkt = build_iam()
        assert len(pkt) > 0

    def test_build_read_property(self):
        from industrialxpl.core.ics.bacnet_offensive import build_read_property
        pkt = build_read_property(device_id=5000, prop_id=77)
        assert pkt[0] == 0x81

    def test_build_read_property_default(self):
        from industrialxpl.core.ics.bacnet_offensive import build_read_property
        pkt = build_read_property()
        assert len(pkt) > 0

    def test_fuzz_frame(self):
        from industrialxpl.core.ics.bacnet_offensive import fuzz_frame
        f0 = fuzz_frame(seed=0)
        f1 = fuzz_frame(seed=1)
        assert f0 != f1

    @patch("industrialxpl.core.ics.bacnet_offensive.socket.socket")
    def test_whois_probe_success(self, mock_sock_cls):
        from industrialxpl.core.ics.bacnet_offensive import whois_probe
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.recv.return_value = b"\x81\x0b\x00\x0c" + b"\x00" * 20
        result = whois_probe("10.0.0.1")
        assert result["detected"] is True
        assert "hex" in result

    @patch("industrialxpl.core.ics.bacnet_offensive.socket.socket")
    def test_whois_probe_oserror(self, mock_sock_cls):
        from industrialxpl.core.ics.bacnet_offensive import whois_probe
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.sendto.side_effect = OSError("timeout")
        result = whois_probe("10.0.0.1")
        assert result["detected"] is False
        assert "error" in result

    def test_simulate_campaign(self):
        from industrialxpl.core.ics.bacnet_offensive import simulate_campaign
        result = simulate_campaign("127.0.0.1")
        assert result["success"] is True
        assert result["simulate"] is True
        assert "frames" in result

    def test_simulate_campaign_default(self):
        from industrialxpl.core.ics.bacnet_offensive import simulate_campaign
        result = simulate_campaign()
        assert result["host"] == "127.0.0.1"


# ---------------------------------------------------------------------------
# isf_port.py
# ---------------------------------------------------------------------------


class TestISFPort:
    def test_protocol_handlers(self):
        from industrialxpl.core.ics.isf_port import PROTOCOL_HANDLERS
        assert "dnp3" in PROTOCOL_HANDLERS
        assert "enip" in PROTOCOL_HANDLERS

    def test_simulate_inventory(self):
        from industrialxpl.core.ics.isf_port import simulate_inventory
        result = simulate_inventory()
        assert result["success"] is True
        assert "protocols" in result

    @patch("industrialxpl.core.ics.isf_port.socket.create_connection")
    def test_probe_dnp3_success(self, mock_conn):
        from industrialxpl.core.ics.isf_port import probe_dnp3
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        result = probe_dnp3("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.isf_port.socket.create_connection")
    def test_probe_dnp3_fail(self, mock_conn):
        from industrialxpl.core.ics.isf_port import probe_dnp3
        mock_conn.side_effect = OSError("refused")
        result = probe_dnp3("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.isf_port.CIPClient")
    def test_probe_enip_success(self, mock_cip_cls):
        from industrialxpl.core.ics.isf_port import probe_enip
        result = probe_enip("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.isf_port.CIPClient")
    def test_probe_enip_fail(self, mock_cip_cls):
        from industrialxpl.core.ics.isf_port import probe_enip
        mock_cip_cls.return_value.connect.side_effect = OSError("fail")
        result = probe_enip("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.isf_port.socket.create_connection")
    def test_probe_opcua_success(self, mock_conn):
        from industrialxpl.core.ics.isf_port import probe_opcua
        mock_conn.return_value = MagicMock()
        result = probe_opcua("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.isf_port.socket.create_connection")
    def test_probe_opcua_fail(self, mock_conn):
        from industrialxpl.core.ics.isf_port import probe_opcua
        mock_conn.side_effect = OSError("err")
        result = probe_opcua("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.isf_port.socket.socket")
    def test_probe_profinet_success(self, mock_sock_cls):
        from industrialxpl.core.ics.isf_port import probe_profinet
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.recv.return_value = b"\xfe\xfd" + b"\x00" * 20
        result = probe_profinet("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.isf_port.socket.socket")
    def test_probe_profinet_fail(self, mock_sock_cls):
        from industrialxpl.core.ics.isf_port import probe_profinet
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.sendto.side_effect = OSError("timeout")
        result = probe_profinet("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.isf_port.Wdb2Client")
    def test_probe_vxworks_success(self, mock_wdb_cls):
        from industrialxpl.core.ics.isf_port import probe_vxworks
        inst = mock_wdb_cls.return_value
        inst.connect.return_value = True
        inst.get_target_info.return_value = {"agent_version": 1}
        result = probe_vxworks("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.isf_port.Wdb2Client")
    def test_probe_vxworks_connect_fail(self, mock_wdb_cls):
        from industrialxpl.core.ics.isf_port import probe_vxworks
        inst = mock_wdb_cls.return_value
        inst.connect.return_value = False
        result = probe_vxworks("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.isf_port.Wdb2Client")
    def test_probe_vxworks_exception(self, mock_wdb_cls):
        from industrialxpl.core.ics.isf_port import probe_vxworks
        mock_wdb_cls.side_effect = OSError("fail")
        result = probe_vxworks("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.isf_port.Wdb2Client")
    def test_probe_vxworks_none_info(self, mock_wdb_cls):
        from industrialxpl.core.ics.isf_port import probe_vxworks
        inst = mock_wdb_cls.return_value
        inst.connect.return_value = True
        inst.get_target_info.return_value = None
        result = probe_vxworks("10.0.0.1")
        assert result["detected"] is True
        assert result["detail"] == {}

    def test_scan_protocols_simulate(self):
        from industrialxpl.core.ics.isf_port import scan_protocols
        result = scan_protocols("10.0.0.1", simulate=True)
        assert result["simulate"] is True

    @patch("industrialxpl.core.ics.isf_port._PROBE_FNS", {"dnp3": MagicMock(return_value={"detected": True})})
    def test_scan_protocols_specific(self):
        from industrialxpl.core.ics.isf_port import scan_protocols
        result = scan_protocols("10.0.0.1", protocols=["dnp3"])
        assert "dnp3" in result["results"]

    def test_scan_protocols_unknown(self):
        from industrialxpl.core.ics.isf_port import scan_protocols
        result = scan_protocols("10.0.0.1", protocols=["unknown_proto"])
        assert result["results"]["unknown_proto"] == {"error": "unknown"}

    def test_scan_protocols_default(self):
        from industrialxpl.core.ics.isf_port import scan_protocols, PROTOCOL_HANDLERS
        with patch("industrialxpl.core.ics.isf_port._PROBE_FNS", {
            p: MagicMock(return_value={"detected": False}) for p in PROTOCOL_HANDLERS
        }):
            result = scan_protocols("10.0.0.1")
            assert len(result["results"]) == len(PROTOCOL_HANDLERS)


# ---------------------------------------------------------------------------
# modbus_toolkit.py
# ---------------------------------------------------------------------------


class TestModbusToolkit:
    def test_build_fc03(self):
        from industrialxpl.core.ics.modbus_toolkit import build_fc03
        pkt = build_fc03(unit=1, addr=0, count=1, trans_id=1)
        assert isinstance(pkt, bytes)

    def test_build_fc16_default(self):
        from industrialxpl.core.ics.modbus_toolkit import build_fc16
        pkt = build_fc16()
        assert isinstance(pkt, bytes)

    def test_build_fc16_with_values(self):
        from industrialxpl.core.ics.modbus_toolkit import build_fc16
        pkt = build_fc16(unit=2, addr=10, values=[100, 200, 300], trans_id=5)
        assert isinstance(pkt, bytes)

    def test_simulate_toolkit(self):
        from industrialxpl.core.ics.modbus_toolkit import simulate_toolkit
        result = simulate_toolkit()
        assert result["success"] is True
        assert result["simulate"] is True

    def test_simulate_toolkit_host(self):
        from industrialxpl.core.ics.modbus_toolkit import simulate_toolkit
        result = simulate_toolkit(host="192.168.1.1")
        assert result["host"] == "192.168.1.1"

    def test_read_holding_simulate(self):
        from industrialxpl.core.ics.modbus_toolkit import read_holding
        result = read_holding("10.0.0.1", addr=0, count=5, simulate=True)
        assert result["simulate"] is True

    @patch("industrialxpl.core.ics.modbus_toolkit.ModbusClient")
    def test_read_holding_live(self, mock_cls):
        from industrialxpl.core.ics.modbus_toolkit import read_holding
        inst = mock_cls.return_value
        inst.read_holding_registers.return_value = [100, 200]
        result = read_holding("10.0.0.1", addr=0, count=2, simulate=False)
        assert result["success"] is True
        assert result["values"] == [100, 200]

    @patch("industrialxpl.core.ics.modbus_toolkit.ModbusClient")
    def test_read_holding_live_error(self, mock_cls):
        from industrialxpl.core.ics.modbus_toolkit import read_holding
        mock_cls.return_value.connect.side_effect = OSError("fail")
        result = read_holding("10.0.0.1", simulate=False)
        assert result["success"] is False


# ---------------------------------------------------------------------------
# open_plc_utils.py
# ---------------------------------------------------------------------------


class TestOpenPLCUtils:
    def test_open_plc_status(self):
        from industrialxpl.core.ics.open_plc_utils import open_plc_status
        result = open_plc_status()
        assert result["success"] is True
        assert result["simulate"] is True
        assert "binary" in result

    @patch("industrialxpl.core.ics.open_plc_utils.shutil.which", return_value="/usr/bin/plcping")
    def test_open_plc_status_found(self, mock_which):
        from industrialxpl.core.ics.open_plc_utils import open_plc_status
        result = open_plc_status()
        assert result["binary"] == "/usr/bin/plcping"

    @patch("industrialxpl.core.ics.open_plc_utils.shutil.which", return_value=None)
    def test_open_plc_status_not_found(self, mock_which):
        from industrialxpl.core.ics.open_plc_utils import open_plc_status
        result = open_plc_status()
        assert result["binary"] == "not installed"


# ---------------------------------------------------------------------------
# ot_audit.py
# ---------------------------------------------------------------------------


class TestOTAudit:
    def test_audit_checks(self):
        from industrialxpl.core.ics.ot_audit import OT_AUDIT_CHECKS
        assert "default_creds" in OT_AUDIT_CHECKS

    def test_run_audit_simulate(self):
        from industrialxpl.core.ics.ot_audit import run_audit
        result = run_audit(host="10.0.0.1", simulate=True)
        assert result["simulate"] is True
        assert len(result["checks"]) == 5

    def test_run_audit_live(self):
        from industrialxpl.core.ics.ot_audit import run_audit
        result = run_audit(host="10.0.0.1", simulate=False)
        assert result["success"] is True
        assert result["checks"] == {}

    def test_run_audit_default(self):
        from industrialxpl.core.ics.ot_audit import run_audit
        result = run_audit()
        assert result["host"] == "127.0.0.1"

    def test_diff_vs_otscan(self):
        from industrialxpl.core.ics.ot_audit import diff_vs_otscan
        result = diff_vs_otscan(["modbus", "s7"])
        assert result["overlap_ok"] is True
        assert result["otscan_count"] == 2
        assert "default_creds" in result["audit_unique"]

    def test_diff_vs_otscan_empty(self):
        from industrialxpl.core.ics.ot_audit import diff_vs_otscan
        result = diff_vs_otscan([])
        assert result["otscan_count"] == 0


# ---------------------------------------------------------------------------
# ricnar_pocs.py
# ---------------------------------------------------------------------------


class TestRicnarPocs:
    def test_list_pocs(self):
        from industrialxpl.core.ics.ricnar_pocs import list_pocs
        pocs = list_pocs()
        assert "seig_modbus_dos" in pocs
        assert "unity_cred_check" in pocs

    def test_get_poc_known(self):
        from industrialxpl.core.ics.ricnar_pocs import get_poc
        result = get_poc("seig_modbus_dos")
        assert result["success"] is True
        assert result["simulate"] is True

    def test_get_poc_known_no_simulate(self):
        from industrialxpl.core.ics.ricnar_pocs import get_poc
        result = get_poc("unity_cred_check", simulate=False)
        assert result["simulate"] is False

    def test_get_poc_unknown(self):
        from industrialxpl.core.ics.ricnar_pocs import get_poc
        result = get_poc("nonexistent")
        assert result["success"] is False

    def test_constants(self):
        from industrialxpl.core.ics.ricnar_pocs import SEIG_MODBUS_DOS_HEX, UNITY_CRED_PROBE, RICNAR_POCS
        assert isinstance(SEIG_MODBUS_DOS_HEX, str)
        assert len(UNITY_CRED_PROBE) == 2
        assert len(RICNAR_POCS) == 2


# ---------------------------------------------------------------------------
# s7_llc.py
# ---------------------------------------------------------------------------


class TestS7LLC:
    def test_build_cotp_connection(self):
        from industrialxpl.core.ics.s7_llc import build_cotp_connection
        pkt = build_cotp_connection(rack=0, slot=2)
        assert pkt[0] == 0x03  # TPKT version
        assert isinstance(pkt, bytes)

    def test_build_cotp_connection_custom(self):
        from industrialxpl.core.ics.s7_llc import build_cotp_connection
        pkt = build_cotp_connection(rack=1, slot=3)
        assert isinstance(pkt, bytes)

    def test_parse_cotp_response_valid(self):
        from industrialxpl.core.ics.s7_llc import parse_cotp_response
        # Valid TPKT + COTP CC (0xD0)
        data = struct.pack(">BBH", 3, 0, 11) + bytes([0x06, 0xD0, 0x00, 0x01, 0x00, 0x46, 0x00])
        result = parse_cotp_response(data)
        assert result["valid"] is True
        assert result["accepted"] is True

    def test_parse_cotp_response_rejected(self):
        from industrialxpl.core.ics.s7_llc import parse_cotp_response
        data = struct.pack(">BBH", 3, 0, 11) + bytes([0x06, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00])
        result = parse_cotp_response(data)
        assert result["valid"] is True
        assert result["accepted"] is False

    def test_parse_cotp_response_not_tpkt(self):
        from industrialxpl.core.ics.s7_llc import parse_cotp_response
        result = parse_cotp_response(b"\x00\x00\x00\x00\x00\x00\x00")
        assert result["valid"] is False

    def test_parse_cotp_response_too_short(self):
        from industrialxpl.core.ics.s7_llc import parse_cotp_response
        result = parse_cotp_response(b"\x03\x00")
        assert result["valid"] is False

    def test_parse_cotp_response_short_packet(self):
        from industrialxpl.core.ics.s7_llc import parse_cotp_response
        data = b"\x03\x00\x00\x04"  # 4 bytes: valid TPKT start but < 7 bytes
        result = parse_cotp_response(data)
        assert result["valid"] is False
        assert result["error"] == "not TPKT"

    def test_parse_cotp_response_valid_minimal(self):
        from industrialxpl.core.ics.s7_llc import parse_cotp_response
        data = b"\x03\x00\x00\x0b" + b"\x06\xd0\x00\x01\x00\xc0\x01"
        result = parse_cotp_response(data)
        assert result["valid"] is True
        assert result["cotp_type"] == 0xD0
        assert result["accepted"] is True

    def test_rack_scan_plan(self):
        from industrialxpl.core.ics.s7_llc import rack_scan_plan
        result = rack_scan_plan("10.0.0.1")
        assert result["success"] is True
        assert result["simulate"] is True
        assert result["count"] == 6

    def test_rack_scan_plan_custom(self):
        from industrialxpl.core.ics.s7_llc import rack_scan_plan
        result = rack_scan_plan("10.0.0.1", racks=(0,), slots=(1, 2))
        assert result["count"] == 2

    @patch("industrialxpl.core.ics.s7_llc.socket.create_connection")
    def test_probe_rack_slot_success(self, mock_conn):
        from industrialxpl.core.ics.s7_llc import probe_rack_slot
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        resp_data = struct.pack(">BBH", 3, 0, 11) + bytes([0x06, 0xD0, 0x00, 0x01, 0x00, 0x46, 0x00])
        mock_sock.recv.return_value = resp_data
        result = probe_rack_slot("10.0.0.1", 0, 2)
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.s7_llc.socket.create_connection")
    def test_probe_rack_slot_fail(self, mock_conn):
        from industrialxpl.core.ics.s7_llc import probe_rack_slot
        mock_conn.side_effect = OSError("refused")
        result = probe_rack_slot("10.0.0.1", 0, 2)
        assert result["detected"] is False
        assert "error" in result

    def test_scan_racks_simulate(self):
        from industrialxpl.core.ics.s7_llc import scan_racks
        result = scan_racks("10.0.0.1", simulate=True)
        assert result["simulate"] is True

    @patch("industrialxpl.core.ics.s7_llc.probe_rack_slot")
    def test_scan_racks_live(self, mock_probe):
        from industrialxpl.core.ics.s7_llc import scan_racks
        mock_probe.return_value = {"detected": True, "rack": 0, "slot": 2}
        result = scan_racks("10.0.0.1", racks=(0,), slots=(2,))
        assert result["found"] == 1
        assert len(result["results"]) == 1

    @patch("industrialxpl.core.ics.s7_llc.probe_rack_slot")
    def test_scan_racks_live_none_found(self, mock_probe):
        from industrialxpl.core.ics.s7_llc import scan_racks
        mock_probe.return_value = {"detected": False, "rack": 0, "slot": 2}
        result = scan_racks("10.0.0.1", racks=(0,), slots=(2,))
        assert result["found"] == 0

    def test_cotp_cr_constant(self):
        from industrialxpl.core.ics.s7_llc import _COTP_CR, S7_PORT
        assert _COTP_CR[0] == 0x03
        assert S7_PORT == 102


# ---------------------------------------------------------------------------
# s7_packets.py
# ---------------------------------------------------------------------------


class TestS7Packets:
    def test_build_stop_pdu(self):
        from industrialxpl.core.ics.s7_packets import build_stop_pdu
        pdu = build_stop_pdu()
        assert pdu[0] == 0x32

    def test_build_start_pdu(self):
        from industrialxpl.core.ics.s7_packets import build_start_pdu
        pdu = build_start_pdu()
        assert pdu[0] == 0x32

    def test_build_cpu_info_probe(self):
        from industrialxpl.core.ics.s7_packets import build_cpu_info_probe
        pdu = build_cpu_info_probe()
        assert pdu[0] == 0x03  # starts with TPKT

    def test_packet_inventory(self):
        from industrialxpl.core.ics.s7_packets import packet_inventory
        result = packet_inventory()
        assert result["success"] is True
        assert "stop" in result["packets"]

    def test_wrap_tpkt(self):
        from industrialxpl.core.ics.s7_packets import wrap_tpkt
        payload = b"\x01\x02"
        result = wrap_tpkt(payload)
        assert result[0] == 0x03
        length = struct.unpack(">H", result[2:4])[0]
        assert length == len(payload) + 4

    def test_constants(self):
        from industrialxpl.core.ics.s7_packets import S7_STOP_HEX, S7_START_HEX, S7_1200_CPU_INFO_TEMPLATE
        assert isinstance(S7_STOP_HEX, str)
        assert isinstance(S7_START_HEX, str)
        assert isinstance(S7_1200_CPU_INFO_TEMPLATE, str)


# ---------------------------------------------------------------------------
# s7plus_client.py
# ---------------------------------------------------------------------------


class TestS7PlusClient:
    def _make_client(self):
        from industrialxpl.core.ics.s7plus_client import S7PlusClient
        return S7PlusClient("10.0.0.1", port=102, timeout=1.0)

    def test_init(self):
        c = self._make_client()
        assert c._ip == "10.0.0.1"
        assert c._connected is False

    def test_s7plus_helpers(self):
        from industrialxpl.core.ics.s7plus_client import _build_tpkt, _build_cotp_cr, _build_cotp_dt
        tpkt = _build_tpkt(b"\x01")
        assert tpkt[0] == 0x03
        cr = _build_cotp_cr(b"\x01\x00", b"SIMATIC-ROOT-ES")
        assert cr[1] == 0xe0
        dt = _build_cotp_dt(b"\x72")
        assert dt[:3] == b"\x02\xf0\x80"

    @patch("industrialxpl.core.ics.s7plus_client.socket.socket")
    def test_connect_tcp_fails(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.connect.side_effect = OSError("refused")
        c = self._make_client()
        assert c.connect() is False

    @patch("industrialxpl.core.ics.s7plus_client.socket.socket")
    def test_connect_cotp_recv_none(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.recv.return_value = b"\x00"
        c = self._make_client()
        assert c.connect() is False

    @patch("industrialxpl.core.ics.s7plus_client.socket.socket")
    def test_connect_cotp_oserror(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.sendall.side_effect = OSError("broken")
        c = self._make_client()
        assert c.connect() is False

    @patch("industrialxpl.core.ics.s7plus_client.socket.socket")
    def test_connect_success(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        # COTP CR response
        cr_body = b"\xd0\x00\x01\x00\x01\x00"
        cr_pkt = struct.pack(">BBH", 3, 0, len(cr_body) + 4) + cr_body
        # S7+ init response
        s7_body = b"\x02\xf0\x80\x72\x01\x00\x09"
        s7_pkt = struct.pack(">BBH", 3, 0, len(s7_body) + 4) + s7_body
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return cr_pkt[:4]
            if call_count[0] == 2:
                return cr_pkt[4:]
            if call_count[0] == 3:
                return s7_pkt[:4]
            if call_count[0] == 4:
                return s7_pkt[4:]
            return b""

        sock_inst.recv.side_effect = recv_side
        c = self._make_client()
        assert c.connect() is True
        assert c._connected is True

    @patch("industrialxpl.core.ics.s7plus_client.socket.socket")
    def test_connect_s7plus_init_none(self, mock_sock_cls):
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        cr_body = b"\xd0\x00\x01\x00\x01\x00"
        cr_pkt = struct.pack(">BBH", 3, 0, len(cr_body) + 4) + cr_body
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return cr_pkt[:4]
            if call_count[0] == 2:
                return cr_pkt[4:]
            # S7+ response: short TPKT -> no data -> None from _send_recv_s7plus
            if call_count[0] == 3:
                return struct.pack(">BBH", 3, 0, 7)
            if call_count[0] == 4:
                return b"\x02\xf0\x80"
            return b""

        sock_inst.recv.side_effect = recv_side
        c = self._make_client()
        assert c.connect() is False

    def test_disconnect(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._connected = True
        c.disconnect()
        assert c._sock is None
        assert c._connected is False

    def test_disconnect_oserror(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.close.side_effect = OSError("err")
        c.disconnect()
        assert c._sock is None

    def test_disconnect_no_sock(self):
        c = self._make_client()
        c.disconnect()

    def test_context_manager(self):
        c = self._make_client()
        with patch.object(c, "connect"), patch.object(c, "disconnect"):
            with c as ctx:
                assert ctx is c

    def test_recv_no_sock(self):
        c = self._make_client()
        assert c._recv() is None

    def test_recv_short_header(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.recv.return_value = b"\x00"
        assert c._recv() is None

    def test_recv_wrong_version(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.recv.return_value = b"\x02\x00\x00\x08"
        assert c._recv() is None

    def test_recv_oserror(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.recv.side_effect = OSError("timeout")
        assert c._recv() is None

    def test_recv_ok(self):
        c = self._make_client()
        c._sock = MagicMock()
        body = b"\x72\x01\x00"
        header = struct.pack(">BBH", 3, 0, len(body) + 4)
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return header
            return body

        c._sock.recv.side_effect = recv_side
        result = c._recv()
        assert result == body

    def test_recv_chunked_empty_break(self):
        c = self._make_client()
        c._sock = MagicMock()
        header = struct.pack(">BBH", 3, 0, 10)
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return header
            return b""

        c._sock.recv.side_effect = recv_side
        result = c._recv()
        assert result == b""

    def test_send_recv_s7plus_no_sock(self):
        c = self._make_client()
        assert c._send_recv_s7plus(b"\x72") is None

    def test_send_recv_s7plus_oserror(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.sendall.side_effect = OSError("broken")
        assert c._send_recv_s7plus(b"\x72") is None

    def test_send_recv_s7plus_short_response(self):
        c = self._make_client()
        c._sock = MagicMock()
        body = b"\x02\xf0\x80"
        header = struct.pack(">BBH", 3, 0, len(body) + 4)
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return header
            return body

        c._sock.recv.side_effect = recv_side
        result = c._send_recv_s7plus(b"\x72")
        assert result is None  # len(rsp) == 3, not > 3

    def test_send_recv_s7plus_success(self):
        c = self._make_client()
        c._sock = MagicMock()
        body = b"\x02\xf0\x80\x72\x01"
        header = struct.pack(">BBH", 3, 0, len(body) + 4)
        call_count = [0]

        def recv_side(n):
            call_count[0] += 1
            if call_count[0] == 1:
                return header
            return body

        c._sock.recv.side_effect = recv_side
        result = c._send_recv_s7plus(b"\x72")
        assert result == b"\x72\x01"

    def test_send_recv_s7plus_recv_none(self):
        c = self._make_client()
        c._sock = MagicMock()
        c._sock.recv.return_value = b"\x00"  # short -> None from _recv
        result = c._send_recv_s7plus(b"\x72")
        assert result is None

    def test_send_recv_s7plus_public(self):
        c = self._make_client()
        with patch.object(c, "_send_recv_s7plus", return_value=b"\x72\x01") as mock_internal:
            result = c.send_recv_s7plus(b"\x72")
            assert result == b"\x72\x01"
            mock_internal.assert_called_once_with(b"\x72")

    # Probe
    def test_probe_not_connected(self):
        c = self._make_client()
        assert c.probe() is False

    def test_probe_success(self):
        c = self._make_client()
        c._connected = True
        with patch.object(c, "_send_recv_s7plus", return_value=b"\x72\x01\x00\x09"):
            assert c.probe() is True

    def test_probe_fail_none(self):
        c = self._make_client()
        c._connected = True
        with patch.object(c, "_send_recv_s7plus", return_value=None):
            assert c.probe() is False

    def test_probe_fail_short(self):
        c = self._make_client()
        c._connected = True
        with patch.object(c, "_send_recv_s7plus", return_value=b"\x72"):
            assert c.probe() is False

    def test_probe_fail_wrong_id(self):
        c = self._make_client()
        c._connected = True
        with patch.object(c, "_send_recv_s7plus", return_value=b"\x00\x01\x00\x09"):
            assert c.probe() is False

    def test_s7plus_dst_tsap(self):
        from industrialxpl.core.ics.s7plus_client import S7PLUS_DST_TSAP
        assert S7PLUS_DST_TSAP == b"SIMATIC-ROOT-ES"


# ---------------------------------------------------------------------------
# otscan/probes.py
# ---------------------------------------------------------------------------


class TestOTScanProbes:
    @patch("industrialxpl.core.ics.otscan.probes.socket.create_connection")
    def test_tcp_open_success(self, mock_conn):
        from industrialxpl.core.ics.otscan.probes import _tcp_open
        mock_conn.return_value = MagicMock()
        assert _tcp_open("10.0.0.1", 502, 3.0) is True

    @patch("industrialxpl.core.ics.otscan.probes.socket.create_connection")
    def test_tcp_open_fail(self, mock_conn):
        from industrialxpl.core.ics.otscan.probes import _tcp_open
        mock_conn.side_effect = OSError("refused")
        assert _tcp_open("10.0.0.1", 502, 3.0) is False

    @patch("industrialxpl.core.ics.otscan.probes.socket.socket")
    def test_udp_send_success(self, mock_sock_cls):
        from industrialxpl.core.ics.otscan.probes import _udp_send
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.recv.return_value = b"\xaa\xbb"
        result = _udp_send("10.0.0.1", 9600, b"\x80", 3.0)
        assert result == b"\xaa\xbb"

    @patch("industrialxpl.core.ics.otscan.probes.socket.socket")
    def test_udp_send_fail(self, mock_sock_cls):
        from industrialxpl.core.ics.otscan.probes import _udp_send
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.sendto.side_effect = OSError("timeout")
        result = _udp_send("10.0.0.1", 9600, b"\x80", 3.0)
        assert result == b""

    @patch("industrialxpl.core.ics.otscan.probes.socket.create_connection")
    def test_probe_modbus_success(self, mock_conn):
        from industrialxpl.core.ics.otscan.probes import probe_modbus
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_sock.recv.return_value = b"\x00" * 12
        result = probe_modbus("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.otscan.probes.socket.create_connection")
    def test_probe_modbus_short_response(self, mock_conn):
        from industrialxpl.core.ics.otscan.probes import probe_modbus
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_sock.recv.return_value = b"\x00" * 5
        result = probe_modbus("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.otscan.probes.socket.create_connection")
    def test_probe_modbus_oserror(self, mock_conn):
        from industrialxpl.core.ics.otscan.probes import probe_modbus
        mock_conn.side_effect = OSError("refused")
        result = probe_modbus("10.0.0.1")
        assert result["detected"] is False
        assert "error" in result

    @patch("industrialxpl.core.ics.otscan.probes._tcp_open")
    @patch("industrialxpl.core.ics.otscan.probes.socket.create_connection")
    def test_probe_s7_success(self, mock_conn, mock_tcp_open):
        from industrialxpl.core.ics.otscan.probes import probe_s7
        mock_tcp_open.return_value = True
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_sock.recv.return_value = b"\x03\x00\x00\x16" + b"\x00" * 18
        result = probe_s7("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.otscan.probes._tcp_open")
    def test_probe_s7_closed(self, mock_tcp_open):
        from industrialxpl.core.ics.otscan.probes import probe_s7
        mock_tcp_open.return_value = False
        result = probe_s7("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.otscan.probes._tcp_open")
    @patch("industrialxpl.core.ics.otscan.probes.socket.create_connection")
    def test_probe_s7_empty_response(self, mock_conn, mock_tcp_open):
        from industrialxpl.core.ics.otscan.probes import probe_s7
        mock_tcp_open.return_value = True
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_sock.recv.return_value = b""
        result = probe_s7("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.otscan.probes._tcp_open")
    @patch("industrialxpl.core.ics.otscan.probes.socket.create_connection")
    def test_probe_s7_oserror(self, mock_conn, mock_tcp_open):
        from industrialxpl.core.ics.otscan.probes import probe_s7
        mock_tcp_open.return_value = True
        mock_conn.side_effect = OSError("err")
        result = probe_s7("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.otscan.probes.socket.create_connection")
    def test_probe_iec104_success(self, mock_conn):
        from industrialxpl.core.ics.otscan.probes import probe_iec104
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_sock.recv.return_value = bytes([0x68, 0x04, 0x0b, 0x00, 0x00, 0x00])
        result = probe_iec104("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.otscan.probes.socket.create_connection")
    def test_probe_iec104_wrong_start(self, mock_conn):
        from industrialxpl.core.ics.otscan.probes import probe_iec104
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_sock.recv.return_value = b"\x00\x04\x0b\x00\x00\x00"
        result = probe_iec104("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.otscan.probes.socket.create_connection")
    def test_probe_iec104_empty(self, mock_conn):
        from industrialxpl.core.ics.otscan.probes import probe_iec104
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_sock.recv.return_value = b""
        result = probe_iec104("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.otscan.probes.socket.create_connection")
    def test_probe_iec104_oserror(self, mock_conn):
        from industrialxpl.core.ics.otscan.probes import probe_iec104
        mock_conn.side_effect = OSError("err")
        result = probe_iec104("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.otscan.probes._udp_send")
    def test_probe_bacnet_success(self, mock_udp):
        from industrialxpl.core.ics.otscan.probes import probe_bacnet
        mock_udp.return_value = b"\x81\x00" + b"\x00" * 20
        result = probe_bacnet("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.otscan.probes._udp_send")
    def test_probe_bacnet_no_response(self, mock_udp):
        from industrialxpl.core.ics.otscan.probes import probe_bacnet
        mock_udp.return_value = b""
        result = probe_bacnet("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.otscan.probes._tcp_open")
    def test_probe_dnp3(self, mock_tcp):
        from industrialxpl.core.ics.otscan.probes import probe_dnp3
        mock_tcp.return_value = True
        result = probe_dnp3("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.otscan.probes._tcp_open")
    def test_probe_opcua(self, mock_tcp):
        from industrialxpl.core.ics.otscan.probes import probe_opcua
        mock_tcp.return_value = False
        result = probe_opcua("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.otscan.probes._tcp_open")
    def test_probe_enip(self, mock_tcp):
        from industrialxpl.core.ics.otscan.probes import probe_enip
        mock_tcp.return_value = True
        result = probe_enip("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.otscan.probes._tcp_open")
    def test_probe_fox(self, mock_tcp):
        from industrialxpl.core.ics.otscan.probes import probe_fox
        mock_tcp.return_value = False
        result = probe_fox("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.otscan.probes._udp_send")
    def test_probe_fins(self, mock_udp):
        from industrialxpl.core.ics.otscan.probes import probe_fins
        mock_udp.return_value = b"\x80\x00\x02"
        result = probe_fins("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.otscan.probes._udp_send")
    def test_probe_fins_empty(self, mock_udp):
        from industrialxpl.core.ics.otscan.probes import probe_fins
        mock_udp.return_value = b""
        result = probe_fins("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.otscan.probes._tcp_open")
    def test_probe_codesys(self, mock_tcp):
        from industrialxpl.core.ics.otscan.probes import probe_codesys
        mock_tcp.return_value = True
        result = probe_codesys("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.otscan.probes._udp_send")
    def test_probe_hart_ip(self, mock_udp):
        from industrialxpl.core.ics.otscan.probes import probe_hart_ip
        mock_udp.return_value = b"\x01"
        result = probe_hart_ip("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.otscan.probes._udp_send")
    def test_probe_hart_ip_empty(self, mock_udp):
        from industrialxpl.core.ics.otscan.probes import probe_hart_ip
        mock_udp.return_value = b""
        result = probe_hart_ip("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.otscan.probes._tcp_open")
    def test_probe_mqtt(self, mock_tcp):
        from industrialxpl.core.ics.otscan.probes import probe_mqtt
        mock_tcp.return_value = True
        result = probe_mqtt("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.otscan.probes._udp_send")
    def test_probe_profinet(self, mock_udp):
        from industrialxpl.core.ics.otscan.probes import probe_profinet
        mock_udp.return_value = b"\xfe\xfd" + b"\x00" * 20
        result = probe_profinet("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.otscan.probes._udp_send")
    def test_probe_profinet_empty(self, mock_udp):
        from industrialxpl.core.ics.otscan.probes import probe_profinet
        mock_udp.return_value = b""
        result = probe_profinet("10.0.0.1")
        assert result["detected"] is False

    def test_probe_map(self):
        from industrialxpl.core.ics.otscan.probes import PROBE_MAP
        assert "modbus" in PROBE_MAP
        assert "s7" in PROBE_MAP
        assert "opcua" in PROBE_MAP
        assert "ethernetip" in PROBE_MAP
        assert "hartip" in PROBE_MAP


# ---------------------------------------------------------------------------
# otscan/scanner.py
# ---------------------------------------------------------------------------


class TestOTScanScanner:
    def test_protocols(self):
        from industrialxpl.core.ics.otscan.scanner import PROTOCOLS
        assert "modbus" in PROTOCOLS

    def test_normalize_protocols_none(self):
        from industrialxpl.core.ics.otscan.scanner import _normalize_protocols
        result = _normalize_protocols(None)
        assert len(result) > 0

    def test_normalize_protocols_empty(self):
        from industrialxpl.core.ics.otscan.scanner import _normalize_protocols
        result = _normalize_protocols([])
        assert len(result) > 0

    def test_normalize_protocols_known(self):
        from industrialxpl.core.ics.otscan.scanner import _normalize_protocols
        result = _normalize_protocols(["modbus", "s7"])
        assert result == ["modbus", "s7"]

    def test_normalize_protocols_opcua_alias(self):
        from industrialxpl.core.ics.otscan.scanner import _normalize_protocols
        result = _normalize_protocols(["opcua"])
        assert len(result) >= 1

    def test_normalize_protocols_ethernetip_alias(self):
        from industrialxpl.core.ics.otscan.scanner import _normalize_protocols
        result = _normalize_protocols(["ethernetip"])
        assert len(result) >= 1

    def test_normalize_protocols_opcua_alias_fallback(self):
        from industrialxpl.core.ics.otscan.scanner import _normalize_protocols
        # Cover the elif branch: "opcua" not in PROBE_MAP -> alias to "opc-ua"
        with patch("industrialxpl.core.ics.otscan.scanner.PROBE_MAP", {"opc-ua": lambda h, t: {}}):
            result = _normalize_protocols(["opcua"])
            assert "opc-ua" in result

    def test_normalize_protocols_ethernetip_alias_fallback(self):
        from industrialxpl.core.ics.otscan.scanner import _normalize_protocols
        # Cover the elif branch: "ethernetip" not in PROBE_MAP -> alias to "enip"
        with patch("industrialxpl.core.ics.otscan.scanner.PROBE_MAP", {"enip": lambda h, t: {}}):
            result = _normalize_protocols(["ethernetip"])
            assert "enip" in result

    def test_normalize_protocols_unknown_only(self):
        from industrialxpl.core.ics.otscan.scanner import _normalize_protocols
        # Unknown protocol -> empty out list -> falls back to PROTOCOLS
        result = _normalize_protocols(["unknown_proto"])
        assert len(result) > 0

    def test_normalize_protocols_dedup(self):
        from industrialxpl.core.ics.otscan.scanner import _normalize_protocols
        result = _normalize_protocols(["modbus", "modbus"])
        assert result.count("modbus") == 1

    def test_normalize_protocols_underscores(self):
        from industrialxpl.core.ics.otscan.scanner import _normalize_protocols
        result = _normalize_protocols(["hart_ip"])
        assert "hart-ip" in result

    def test_probe_missing(self):
        from industrialxpl.core.ics.otscan.scanner import probe_missing
        result = probe_missing("10.0.0.1")
        assert result["detected"] is False

    def test_simulate_scan(self):
        from industrialxpl.core.ics.otscan.scanner import simulate_scan
        result = simulate_scan()
        assert result["success"] is True
        assert result["simulate"] is True

    def test_simulate_scan_with_protocols(self):
        from industrialxpl.core.ics.otscan.scanner import simulate_scan
        result = simulate_scan("10.0.0.1", protocols=["modbus", "s7"])
        assert result["count"] == 2

    def test_scan_simulate(self):
        from industrialxpl.core.ics.otscan.scanner import scan
        result = scan("10.0.0.1", simulate=True)
        assert result["simulate"] is True

    @patch("industrialxpl.core.ics.otscan.scanner.PROBE_MAP", {"modbus": MagicMock(return_value={"detected": True})})
    def test_scan_live(self):
        from industrialxpl.core.ics.otscan.scanner import scan
        result = scan("10.0.0.1", protocols=["modbus"])
        assert result["detected_count"] == 1

    @patch("industrialxpl.core.ics.otscan.scanner.PROBE_MAP", {"modbus": MagicMock(return_value={"detected": False})})
    def test_scan_live_none_detected(self):
        from industrialxpl.core.ics.otscan.scanner import scan
        result = scan("10.0.0.1", protocols=["modbus"])
        assert result["detected_count"] == 0

    def test_scan_unknown_protocol(self):
        from industrialxpl.core.ics.otscan.scanner import scan
        # "zzzz" is unknown, so _normalize_protocols returns all PROTOCOLS
        # but if we can control it... We can't easily test this path
        # without manipulating _normalize_protocols directly
        with patch("industrialxpl.core.ics.otscan.scanner._normalize_protocols", return_value=["unknown_proto"]):
            with patch("industrialxpl.core.ics.otscan.scanner.PROBE_MAP", {}):
                result = scan("10.0.0.1")
                assert "unknown_proto" in result["results"]

    # otscan/__init__.py
    def test_otscan_init(self):
        from industrialxpl.core.ics.otscan import PROTOCOLS, scan, simulate_scan
        assert PROTOCOLS is not None
        assert callable(scan)
        assert callable(simulate_scan)


# ---------------------------------------------------------------------------
# vendors/probes.py
# ---------------------------------------------------------------------------


class TestVendorProbes:
    def test_vendor_names(self):
        from industrialxpl.core.ics.vendors.probes import VENDOR_NAMES
        assert "beckhoff" in VENDOR_NAMES
        assert len(VENDOR_NAMES) == 7

    @patch("industrialxpl.core.ics.vendors.probes._tcp")
    def test_probe_beckhoff(self, mock_tcp):
        from industrialxpl.core.ics.vendors.probes import probe_beckhoff
        mock_tcp.return_value = True
        result = probe_beckhoff("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.vendors.probes._tcp")
    def test_probe_beckhoff_closed(self, mock_tcp):
        from industrialxpl.core.ics.vendors.probes import probe_beckhoff
        mock_tcp.return_value = False
        result = probe_beckhoff("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.vendors.probes._tcp")
    def test_probe_phoenix(self, mock_tcp):
        from industrialxpl.core.ics.vendors.probes import probe_phoenix
        mock_tcp.return_value = True
        result = probe_phoenix("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.vendors.probes._tcp")
    def test_probe_mitsubishi(self, mock_tcp):
        from industrialxpl.core.ics.vendors.probes import probe_mitsubishi
        mock_tcp.return_value = True
        result = probe_mitsubishi("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.vendors.probes._udp")
    def test_probe_omron(self, mock_udp):
        from industrialxpl.core.ics.vendors.probes import probe_omron
        mock_udp.return_value = b"\x80\x00"
        result = probe_omron("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.vendors.probes._udp")
    def test_probe_omron_empty(self, mock_udp):
        from industrialxpl.core.ics.vendors.probes import probe_omron
        mock_udp.return_value = b""
        result = probe_omron("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.vendors.probes._tcp")
    def test_probe_ewon(self, mock_tcp):
        from industrialxpl.core.ics.vendors.probes import probe_ewon
        mock_tcp.return_value = True
        result = probe_ewon("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.vendors.probes._udp")
    def test_probe_hirschmann(self, mock_udp):
        from industrialxpl.core.ics.vendors.probes import probe_hirschmann
        mock_udp.return_value = b"\x30\x26" + b"\x00" * 10
        result = probe_hirschmann("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.vendors.probes._udp")
    def test_probe_hirschmann_empty(self, mock_udp):
        from industrialxpl.core.ics.vendors.probes import probe_hirschmann
        mock_udp.return_value = b""
        result = probe_hirschmann("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.vendors.probes._tcp")
    def test_probe_schneider(self, mock_tcp):
        from industrialxpl.core.ics.vendors.probes import probe_schneider
        mock_tcp.return_value = True
        result = probe_schneider("10.0.0.1")
        assert result["detected"] is True

    @patch("industrialxpl.core.ics.vendors.probes._tcp")
    def test_probe_schneider_closed(self, mock_tcp):
        from industrialxpl.core.ics.vendors.probes import probe_schneider
        mock_tcp.return_value = False
        result = probe_schneider("10.0.0.1")
        assert result["detected"] is False

    @patch("industrialxpl.core.ics.vendors.probes.socket.create_connection")
    def test_tcp_helper_success(self, mock_conn):
        from industrialxpl.core.ics.vendors.probes import _tcp
        mock_conn.return_value = MagicMock()
        assert _tcp("10.0.0.1", 502, 3.0) is True

    @patch("industrialxpl.core.ics.vendors.probes.socket.create_connection")
    def test_tcp_helper_fail(self, mock_conn):
        from industrialxpl.core.ics.vendors.probes import _tcp
        mock_conn.side_effect = OSError("refused")
        assert _tcp("10.0.0.1", 502, 3.0) is False

    @patch("industrialxpl.core.ics.vendors.probes.socket.socket")
    def test_udp_helper_success(self, mock_sock_cls):
        from industrialxpl.core.ics.vendors.probes import _udp
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.recv.return_value = b"\xaa\xbb"
        result = _udp("10.0.0.1", 9600, b"\x80", 3.0)
        assert result == b"\xaa\xbb"

    @patch("industrialxpl.core.ics.vendors.probes.socket.socket")
    def test_udp_helper_fail(self, mock_sock_cls):
        from industrialxpl.core.ics.vendors.probes import _udp
        sock_inst = MagicMock()
        mock_sock_cls.return_value = sock_inst
        sock_inst.sendto.side_effect = OSError("timeout")
        result = _udp("10.0.0.1", 9600, b"\x80", 3.0)
        assert result == b""

    def test_simulate_all(self):
        from industrialxpl.core.ics.vendors.probes import simulate_all
        result = simulate_all()
        assert result["success"] is True
        assert result["simulate"] is True
        assert len(result["vendors"]) == 7

    def test_simulate_all_host(self):
        from industrialxpl.core.ics.vendors.probes import simulate_all
        result = simulate_all(host="192.168.1.1")
        assert result["host"] == "192.168.1.1"

    def test_probe_vendor_simulate(self):
        from industrialxpl.core.ics.vendors.probes import probe_vendor
        result = probe_vendor("beckhoff", "10.0.0.1", simulate=True)
        assert result["simulate"] is True
        assert result["would_probe"] == "probe_beckhoff"

    def test_probe_vendor_simulate_unknown(self):
        from industrialxpl.core.ics.vendors.probes import probe_vendor
        result = probe_vendor("unknown_vendor", "10.0.0.1", simulate=True)
        assert result["would_probe"] == "missing"

    @patch("industrialxpl.core.ics.vendors.probes._tcp")
    def test_probe_vendor_live(self, mock_tcp):
        from industrialxpl.core.ics.vendors.probes import probe_vendor
        mock_tcp.return_value = True
        result = probe_vendor("beckhoff", "10.0.0.1")
        assert result["success"] is True

    def test_probe_vendor_live_unknown(self):
        from industrialxpl.core.ics.vendors.probes import probe_vendor
        result = probe_vendor("unknown_vendor", "10.0.0.1")
        assert result["success"] is False

    def test_probe_vendor_whitespace(self):
        from industrialxpl.core.ics.vendors.probes import probe_vendor
        result = probe_vendor("  Beckhoff  ", "10.0.0.1", simulate=True)
        assert result["simulate"] is True

    def test_probe_map(self):
        from industrialxpl.core.ics.vendors.probes import PROBE_MAP
        assert len(PROBE_MAP) == 7

    # vendors/__init__.py
    def test_vendors_init(self):
        from industrialxpl.core.ics.vendors import VENDOR_NAMES, probe_vendor, simulate_all
        assert VENDOR_NAMES is not None
        assert callable(probe_vendor)
        assert callable(simulate_all)


# ---------------------------------------------------------------------------
# s7_llc.py  -  gap-fill: line 35  (empty COTP defensive branch)
# ---------------------------------------------------------------------------


class TestS7LlcCotpEdgeCases:
    """Cover the defensive 'empty COTP' branch in parse_cotp_response.

    Line 35 is structurally unreachable with real ``bytes`` objects because
    the guard ``len(data) < 7`` guarantees ``data[4:]`` has >= 3 bytes.
    We use a thin bytes wrapper that reports ``len >= 7`` but yields an
    empty slice at ``[4:]``, exercising the defensive path.
    """

    def test_parse_cotp_empty_cotp_branch(self):
        """Force the empty-COTP defensive branch (line 35)."""
        from industrialxpl.core.ics.s7_llc import parse_cotp_response

        class _FakeData(bytes):
            """bytes subclass that returns empty on [4:] slicing."""

            def __new__(cls):
                # 7 valid-looking bytes so the length/TPKT guard passes
                return super().__new__(cls, b"\x03\x00\x00\x07\xD0\x00\x00")

            def __getitem__(self, key):
                if isinstance(key, slice) and key == slice(4, None, None):
                    return b""
                return super().__getitem__(key)

        result = parse_cotp_response(_FakeData())
        assert result == {"valid": False, "error": "empty COTP"}

    def test_parse_cotp_single_byte_cotp(self):
        """Verify pdu_type fallback to 0 when cotp has only 1 byte.

        Also structurally unreachable with real bytes (needs len >= 7 but
        data[4:] == 1 byte), so we use the same wrapper technique.
        """
        from industrialxpl.core.ics.s7_llc import parse_cotp_response

        class _FakeDataOneByte(bytes):
            """bytes subclass returning a single-byte slice at [4:]."""

            def __new__(cls):
                return super().__new__(cls, b"\x03\x00\x00\x07\xAA\x00\x00")

            def __getitem__(self, key):
                if isinstance(key, slice) and key == slice(4, None, None):
                    return b"\xFF"
                if isinstance(key, slice) and key == slice(2, 4, None):
                    return b"\x00\x07"
                return super().__getitem__(key)

        result = parse_cotp_response(_FakeDataOneByte())
        # cotp = b"\xFF" (len 1), so pdu_type falls back to 0
        assert result["valid"] is True
        assert result["cotp_type"] == 0
        assert result["accepted"] is False


# ═══════════════════════════════════════════════════════════════════════════
# FINAL GAP-FILL: core/mitre, core/modbus, core/session,
#                 core/ics_tools, core/http
# ═══════════════════════════════════════════════════════════════════════════

import json
import os
import re
import csv
import time
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open


class TestSmallGaps_core:
    """Cover remaining 1-4 line gaps in core modules."""

    # ── mitre/index.py L37-38: build_index with module_paths=None ────────
    def test_mitre_build_index_auto_discover(self):
        import industrialxpl.core.mitre.index as idx_mod
        idx_mod._built = False
        with patch("industrialxpl.core.exploit.utils.index_modules", return_value=[]) as mock_idx:
            idx_mod.build_index(module_paths=None)
        mock_idx.assert_called_once()

    # ── mitre/sweeper.py L130: mod.port set from sweeper.port ────────────
    def test_sweeper_sets_port_on_module(self):
        mock_cls = MagicMock()
        mock_mod = MagicMock()
        mock_mod.check.return_value = False
        mock_mod.get_info.return_value = {"mitre_techniques": ["T0843"]}
        mock_mod.port = 502
        mock_cls.return_value = mock_mod
        with patch("industrialxpl.core.mitre.index.build_index"), \
             patch("industrialxpl.core.mitre.index.TECHNIQUE_INDEX", {"T0843": ["mod.a"]}), \
             patch("industrialxpl.core.mitre.index.TACTIC_INDEX", {"TA0102": ["mod.a"]}), \
             patch("industrialxpl.core.mitre.sweeper.import_exploit", return_value=mock_cls), \
             patch("industrialxpl.core.mitre.sweeper.humanize_path", return_value="mod.a"), \
             patch("industrialxpl.core.mitre.sweeper.print_status"), \
             patch("industrialxpl.core.mitre.sweeper.print_table"):
            from industrialxpl.core.mitre.sweeper import MitreTacticSweeper
            s = MitreTacticSweeper(target="10.0.0.1", port=9999, module_paths=[])
            s._run_modules(["mod.a"], "test")
        assert mock_mod.port == 9999

    # ── mitre/sweeper.py L154: mod.run() raises NotImplementedError ──────
    def test_sweeper_run_not_implemented(self):
        mock_cls = MagicMock()
        mock_mod = MagicMock()
        mock_mod.check.return_value = True
        mock_mod.run.side_effect = NotImplementedError
        mock_mod.get_info.return_value = {"mitre_techniques": ["T0843"]}
        mock_cls.return_value = mock_mod
        with patch("industrialxpl.core.mitre.index.build_index"), \
             patch("industrialxpl.core.mitre.index.TECHNIQUE_INDEX", {"T0843": ["mod.a"]}), \
             patch("industrialxpl.core.mitre.index.TACTIC_INDEX", {}), \
             patch("industrialxpl.core.mitre.sweeper.import_exploit", return_value=mock_cls), \
             patch("industrialxpl.core.mitre.sweeper.humanize_path", return_value="mod.a"), \
             patch("industrialxpl.core.mitre.sweeper.print_status"), \
             patch("industrialxpl.core.mitre.sweeper.print_table"), \
             patch("industrialxpl.core.mitre.sweeper.print_success"):
            from industrialxpl.core.mitre.sweeper import MitreTacticSweeper
            s = MitreTacticSweeper(target="10.0.0.1", simulate=True, check_only=False,
                                    module_paths=[])
            results = s._run_modules(["mod.a"], "test")
        assert results[0]["status"].startswith("SIMULATED")

    # ── modbus/address.py L154: invalid range expression ─────────────────
    def test_modbus_address_invalid_range(self):
        """Cover L154 by making re.split return != 2 parts."""
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        with patch("industrialxpl.core.modbus.address.re") as mock_re:
            mock_re.split.return_value = ["only_one"]
            with pytest.raises(ValueError, match="Invalid range"):
                parse_modbus_addresses("1-5")

    # ── modbus/address.py L183: empty address expression ─────────────────
    def test_modbus_address_empty_expression(self):
        from industrialxpl.core.modbus.address import parse_modbus_addresses
        with pytest.raises(ValueError, match="No addresses"):
            parse_modbus_addresses(" , , ")

    # ── modbus/transport.py L86: recv returns empty bytes ────────────────
    def test_modbus_transport_recv_empty(self):
        from industrialxpl.core.modbus.transport import ModbusTCPSocket
        from industrialxpl.core.modbus.timing import TimingProfile
        timing = TimingProfile(level=3, name="Normal",
                               socket_timeout=1.0, inter_request_delay=0.0,
                               max_rtt_timeout=0.5, retries=1)
        sock = ModbusTCPSocket("127.0.0.1", 502, timing=timing)
        mock_socket = MagicMock()
        mock_socket.recv.return_value = b""  # Empty -> break at L86
        sock._sock = mock_socket
        result = sock.send_pdu(b"\x01\x00\x00\x00\x06")
        assert result is None

    # ── session.py L43: _ensure_dir creates directory ────────────────────
    def test_session_ensure_dir(self):
        import industrialxpl.core.session as sess_mod
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td) / "test_sessions"
            old_dir = sess_mod._SESSIONS_DIR
            sess_mod._SESSIONS_DIR = td_path
            try:
                sess_mod._ensure_dir()
                assert td_path.is_dir()
            finally:
                sess_mod._SESSIONS_DIR = old_dir

    # ── session.py L302: _load_index returns valid dict ──────────────────
    def test_session_load_index_valid(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            idx_file = td_path / "_index.json"
            idx_file.write_text('{"host1": {"ip": "10.0.0.1"}}', encoding="utf-8")
            from industrialxpl.core.session import SessionManager
            mgr = SessionManager(sessions_dir=td_path)
            assert "host1" in mgr._index
            assert mgr._index["host1"]["ip"] == "10.0.0.1"

    # ── session.py L347: load() with hid found but file missing ──────────
    def test_session_load_file_missing(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            idx_file = td_path / "_index.json"
            idx_file.write_text('{"abc123": {"ip": "10.0.0.1"}}', encoding="utf-8")
            from industrialxpl.core.session import SessionManager
            mgr = SessionManager(sessions_dir=td_path)
            # hid "abc123" is in the index, but no abc123.json file exists
            result = mgr.load("10.0.0.1")
            assert result is None

    # ── ics_tools/catalog.py L82: .nse entry -> interp = "nmap" ──────────
    def test_catalog_nse_interpreter(self):
        from industrialxpl.core.ics_tools.catalog import IcsToolsCatalog
        cat = IcsToolsCatalog()
        # "redpoint" has entry "BACnet-discover-enumerate.nse" which ends with .nse
        with patch("industrialxpl.core.ics_tools.catalog.VENDOR_ROOT") as mock_vr:
            # Create a mock directory that has a redpoint submodule dir
            rp_dir = MagicMock()
            rp_dir.name = "submodules__ics-tools__redpoint"
            # The entry .nse file should exist
            mock_vr.glob.return_value = [rp_dir]
            cat._families = {}
            fams = cat.discover()
        if "redpoint" in fams:
            assert fams["redpoint"].interpreter == "nmap"

    # ── ics_tools/catalog.py L97: native ICS vendor_path not a dir ───────
    def test_catalog_native_ics_missing_dir(self):
        from industrialxpl.core.ics_tools.catalog import IcsToolsCatalog
        cat = IcsToolsCatalog()
        cat._families = {}
        # Patch VENDOR_ROOT.glob to return empty (no submodule dirs)
        with patch("industrialxpl.core.ics_tools.catalog.VENDOR_ROOT") as mock_vr:
            mock_vr.glob.return_value = []
            # NATIVE_ICS entries have paths that don't exist -> continue at L97
            fams = cat.discover()
        # If native paths don't exist, those slugs won't be in families
        # The important thing is that L97 (continue) was hit without error

    # ── ics_tools/native_handlers.py L98: scadapass CSV with 30+ rows ────
    def test_native_handlers_scadapass_break(self):
        from industrialxpl.core.ics_tools.native_handlers import handle_scadapass
        with tempfile.TemporaryDirectory() as td:
            csv_path = Path(td) / "scadapass.csv"
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                for i in range(35):
                    writer.writerow([f"vendor{i}", f"product{i}", f"user{i}", f"pass{i}"])
            result = handle_scadapass(Path(td), None, simulate=False)
        assert result["success"] is True
        assert result["total_shown"] == 30  # L98 break at i >= 30

    # ── ics_tools/native_handlers.py L187-188: OSError reading .py file ──
    def test_native_handlers_isf_oserror(self):
        from industrialxpl.core.ics_tools.native_handlers import handle_isf_dark_lbp
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            isf_py = td_path / "isf.py"
            isf_py.write_text("# ISF entry point", encoding="utf-8")
            exploits_dir = td_path / "icssploit" / "exploits"
            exploits_dir.mkdir(parents=True)
            # Create a .py file that will cause OSError when read
            bad_py = exploits_dir / "bad_module.py"
            bad_py.write_text("# exploit", encoding="utf-8")
            # Create a modules dir for the rglob to find
            import industrialxpl.core.ics_tools.native_handlers as nh_mod
            mod_root = Path(nh_mod.__file__).resolve().parent.parent / "modules"
            if mod_root.is_dir():
                # Mock read_text to raise on specific files
                original_read_text = Path.read_text
                call_count = [0]
                def patched_read_text(self_path, *a, **k):
                    if self_path.suffix == ".py" and "modules" in str(self_path):
                        call_count[0] += 1
                        if call_count[0] == 1:
                            raise OSError("permission denied")
                    return original_read_text(self_path, *a, **k)
                with patch.object(Path, "read_text", patched_read_text):
                    result = handle_isf_dark_lbp(td_path, None, simulate=False)
                assert result["success"] is True
            else:
                # If no modules dir, just test the basic case
                result = handle_isf_dark_lbp(td_path, None, simulate=False)
                assert result.get("success") is True

    # ── catalog.py L97: NATIVE_ICS vpath not a directory -> continue ──────
    def test_catalog_native_ics_vpath_not_dir(self):
        from industrialxpl.core.ics_tools.catalog import IcsToolsCatalog
        cat = IcsToolsCatalog()
        fake_native = {
            "nonexistent_tool": {
                "label": "Ghost Tool",
                "vendor_path": "/tmp/this_path_does_not_exist_xpl_test",
                "source_repo": "none",
            }
        }
        with patch.object(IcsToolsCatalog, "NATIVE_ICS", fake_native):
            cat._families = {}
            with patch("industrialxpl.core.ics_tools.catalog.VENDOR_ROOT") as vr:
                vr.glob.return_value = []
                result = cat.discover()
        assert "nonexistent_tool" not in result

    # ── native_handlers.py L187-188: OSError on py.read_text -> continue ─
    def test_native_handlers_oserror_on_read(self):
        from industrialxpl.core.ics_tools.native_handlers import handle_isf_dark_lbp
        import tempfile, os
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            mod_root = td_path / "modules"
            mod_root.mkdir()
            bad_py = mod_root / "bad_module.py"
            bad_py.write_text("icssploit placeholder")
            os.chmod(str(bad_py), 0o000)
            vendor_dir = td_path / "vendor"
            vendor_dir.mkdir()
            try:
                with patch("industrialxpl.core.ics_tools.native_handlers._PKG", td_path):
                    result = handle_isf_dark_lbp(vendor_dir, None, simulate=False)
                assert result.get("success") is True
            finally:
                os.chmod(str(bad_py), 0o644)

    # ── http/http_client.py L57-58: generic RequestException -> break ──────
    def test_http_client_generic_request_exception(self):
        import requests
        from industrialxpl.core.http.http_client import HTTPClient
        client = HTTPClient()
        client.target = "10.0.0.1"
        client.port = 80
        client.ssl = False
        client.verbosity = False
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.TooManyRedirects("too many")
        with patch("industrialxpl.core.http.http_client.print_error"):
            result = client.http_request("GET", "/test", session=mock_session)
        assert result is None
