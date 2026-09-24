"""
industrialxpl/protocols/cotp.py - Native COTP (Connection-Oriented Transport Protocol) stack.

Implements ISO 8073 Class 0 COTP as used by Siemens S7 PLCs over TCP port 102.
Pure-Python implementation using struct - no Scapy required.

Protocol stack: TCP -> TPKT -> COTP -> S7comm

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Optional, Tuple

__version__ = "1.0.0"

# COTP PDU types
COTP_CR = 0xE0   # Connection Request
COTP_CC = 0xD0   # Connection Confirm
COTP_DT = 0xF0   # Data Transfer

# TSAP values for Siemens S7 (Source/Destination transport selectors)
TSAP_PG = b"\x01\x00"     # Programming Device (PG/PC)
TSAP_OP = b"\x01\x01"     # Operator Panel (OP)
TSAP_S7_300 = b"\x01\x02"  # S7-300/400
TSAP_S7_1200 = b"\x01\x00"  # S7-1200/1500 (OP)
TSAP_DST_S7_300 = b"\x03\x00"  # Default server TSAP for S7-300 slot 0


@dataclass
class CotpFrame:
    """Parsed COTP frame."""
    pdu_type: int
    src_ref: int = 0
    dst_ref: int = 0
    payload: bytes = field(default_factory=bytes)


def build_tpkt(data: bytes) -> bytes:
    """Wrap data in TPKT header (RFC 1006).

    TPKT: version(1) reserved(1) length(2)
    """
    length = 4 + len(data)
    return struct.pack(">BBH", 0x03, 0x00, length) + data


def build_cotp_cr(src_tsap: bytes = TSAP_PG, dst_tsap: bytes = TSAP_DST_S7_300) -> bytes:
    """Build COTP Connection Request (CR) PDU.

    Standard S7comm connection request parameters:
        - TPDU size: 1024 (0x0A)
        - Source TSAP
        - Destination TSAP
    """
    # Parameters: tpdu-size(c0 01 0a) + src-tsap(c1 02 xx xx) + dst-tsap(c2 02 xx xx)
    params = (
        b"\xc0\x01\x0a"               # TPDU size = 1024
        + b"\xc1" + bytes([len(src_tsap)]) + src_tsap
        + b"\xc2" + bytes([len(dst_tsap)]) + dst_tsap
    )
    # CR header: length(1) PDUType(1) DstRef(2) SrcRef(2) ClassOption(1) + params
    cotp_len = 6 + len(params)  # excluding the length byte itself but it counts body
    cr = (
        struct.pack(">B", cotp_len)   # Length (excluding this byte = 6 + params)
        + struct.pack(">B", COTP_CR)  # PDU Type CR
        + b"\x00\x00"                 # DST-REF
        + b"\x00\x01"                 # SRC-REF
        + b"\x00"                     # Class/Option
        + params
    )
    return build_tpkt(cr)


def build_cotp_dt(data: bytes, eot: bool = True) -> bytes:
    """Build COTP Data Transfer (DT) PDU wrapping S7comm payload."""
    eot_flag = 0x80 if eot else 0x00
    cotp_dt = struct.pack(">BBB", 0x02, COTP_DT, eot_flag)
    return build_tpkt(cotp_dt + data)


def parse_tpkt(raw: bytes) -> Tuple[bool, bytes]:
    """Parse TPKT header and return (valid, inner_data)."""
    if len(raw) < 4:
        return False, b""
    version, reserved, length = struct.unpack_from(">BBH", raw, 0)
    if version != 0x03:
        return False, b""
    return True, raw[4:length]


def parse_cotp(data: bytes) -> Optional[CotpFrame]:
    """Parse COTP PDU from inner TPKT data."""
    if len(data) < 2:
        return None
    cotp_len = data[0]
    pdu_type = data[1]

    if pdu_type == COTP_DT:
        # DT: length(1) + PDUType(1) + EOT+TPDUNR(1) + payload
        payload = data[3:]
        return CotpFrame(pdu_type=COTP_DT, payload=payload)

    elif pdu_type in (COTP_CR, COTP_CC):
        if len(data) < 7:
            return None
        dst_ref = struct.unpack_from(">H", data, 2)[0]
        src_ref = struct.unpack_from(">H", data, 4)[0]
        return CotpFrame(pdu_type=pdu_type, src_ref=src_ref, dst_ref=dst_ref)

    return CotpFrame(pdu_type=pdu_type)


class CotpConnection:
    """Manages a COTP connection to a Siemens PLC over TCP port 102.

    Abstracts the TPKT/COTP handshake so S7Client can work with clean send/recv.

    Usage:
        conn = CotpConnection("192.168.0.1")
        if conn.connect():
            conn.send(s7_data)
            resp = conn.recv()
            conn.disconnect()
    """

    S7_PORT = 102

    def __init__(
        self,
        host: str,
        port: int = S7_PORT,
        timeout: float = 5.0,
        src_tsap: bytes = TSAP_PG,
        dst_tsap: bytes = TSAP_DST_S7_300,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.src_tsap = src_tsap
        self.dst_tsap = dst_tsap
        self._sock: Optional[socket.socket] = None
        self.connected = False

    def connect(self) -> bool:
        """Establish TCP + COTP connection."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.settimeout(self.timeout)
            self._sock.connect((self.host, self.port))

            # Send COTP CR
            self._sock.sendall(build_cotp_cr(self.src_tsap, self.dst_tsap))
            resp = self._recv_raw()
            if not resp:
                return False

            valid, inner = parse_tpkt(resp)
            if not valid:
                return False

            frame = parse_cotp(inner)
            if frame is None or frame.pdu_type != COTP_CC:
                return False

            self.connected = True
            return True

        except Exception:
            self._sock = None
            return False

    def disconnect(self) -> None:
        """Close connection."""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self.connected = False

    def send(self, data: bytes) -> None:
        """Send S7comm data wrapped in COTP DT."""
        if not self._sock:
            raise ConnectionError("Not connected")
        self._sock.sendall(build_cotp_dt(data))

    def recv(self) -> bytes:
        """Receive and unwrap COTP DT payload."""
        raw = self._recv_raw()
        if not raw:
            return b""
        valid, inner = parse_tpkt(raw)
        if not valid:
            return b""
        frame = parse_cotp(inner)
        if frame is None:
            return b""
        return frame.payload

    def _recv_raw(self) -> bytes:
        """Receive complete TPKT response."""
        if not self._sock:
            return b""
        try:
            header = self._sock.recv(4)
            if len(header) < 4:
                return b""
            _, _, length = struct.unpack_from(">BBH", header, 0)
            remaining = length - 4
            data = b""
            while len(data) < remaining:
                chunk = self._sock.recv(remaining - len(data))
                if not chunk:
                    break
                data += chunk
            return header + data
        except socket.timeout:
            return b""
        except Exception:
            return b""
