"""
industrialxpl/protocols/enip.py - Native EtherNet/IP protocol stack.

Implements EtherNet/IP (ENIP) encapsulation and CIP (Common Industrial Protocol)
service codes. Pure-Python using struct + socket - no Scapy required.

Reference:
    EtherNet/IP Specification - ODVA Publication
    MITRE ATT&CK ICS: T0846 Remote System Discovery

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

__version__ = "1.0.0"

ENIP_PORT = 44818
ENIP_PORT_UDP = 2222

# Command codes
CMD_NOP = 0x0000
CMD_LIST_SERVICES = 0x0004
CMD_LIST_IDENTITY = 0x0063
CMD_LIST_INTERFACES = 0x0064
CMD_REGISTER_SESSION = 0x0065
CMD_UNREGISTER_SESSION = 0x0066
CMD_SEND_RR_DATA = 0x006F
CMD_SEND_UNIT_DATA = 0x0070

CMD_NAMES: Dict[int, str] = {
    CMD_NOP: "NOP",
    CMD_LIST_SERVICES: "ListServices",
    CMD_LIST_IDENTITY: "ListIdentity",
    CMD_LIST_INTERFACES: "ListInterfaces",
    CMD_REGISTER_SESSION: "RegisterSession",
    CMD_UNREGISTER_SESSION: "UnregisterSession",
    CMD_SEND_RR_DATA: "SendRRData",
    CMD_SEND_UNIT_DATA: "SendUnitData",
}

# Vendor IDs (subset - most relevant for ICS)
VENDOR_IDS: Dict[int, str] = {
    0x0000: "Reserved",
    0x0001: "Rockwell Automation/Allen-Bradley",
    0x0003: "Honeywell",
    0x002A: "Siemens",
    0x002C: "Yaskawa Electric",
    0x002F: "Omron",
    0x0044: "Eaton Electrical",
    0x004A: "Hitachi",
    0x004B: "ABB Robotics",
    0x004D: "Rockwell Software",
    0x0052: "Mitsubishi Electric Automation",
    0x006C: "Beckhoff Automation",
    0x006D: "National Instruments",
    0x0074: "MTS Systems",
    0x0079: "KUKA Roboter",
    0x00B3: "Schneider Electric",
}

# CIP service codes
CIP_GET_ALL = 0x01
CIP_SET_SINGLE = 0x10
CIP_GET_SINGLE = 0x0E
CIP_LIST_SERVICES = 0x55
CIP_RESET = 0x05


@dataclass
class EnipIdentity:
    """Device identity from ListIdentity response."""
    vendor_id: int = 0
    device_type: int = 0
    product_code: int = 0
    revision_major: int = 0
    revision_minor: int = 0
    status: int = 0
    serial_number: int = 0
    product_name: str = ""
    state: int = 0
    ip_address: str = ""
    port: int = ENIP_PORT
    vendor_name: str = ""


@dataclass
class EnipResponse:
    """Parsed ENIP response."""
    success: bool
    command: int = 0
    session_id: int = 0
    status: int = 0
    data: bytes = field(default_factory=bytes)
    identities: List[EnipIdentity] = field(default_factory=list)
    error: str = ""


def build_enip_header(
    command: int,
    data: bytes = b"",
    session_id: int = 0,
    options: int = 0,
    sender_context: bytes = b"\x00" * 8,
) -> bytes:
    """Build 24-byte ENIP encapsulation header + data.

    Header structure:
        Command(2) Length(2) SessionID(4) Status(4)
        SenderContext(8) Options(4)
    """
    return (
        struct.pack("<H", command)
        + struct.pack("<H", len(data))  # length in little-endian
        + struct.pack("<I", session_id)
        + struct.pack("<I", 0)  # status (0 = success in request)
        + sender_context
        + struct.pack("<I", options)
        + data
    )


def build_list_identity() -> bytes:
    """Build ENIP ListIdentity request (broadcast or unicast)."""
    return build_enip_header(CMD_LIST_IDENTITY)


def build_register_session() -> bytes:
    """Build ENIP RegisterSession request."""
    # Data: protocol version (1) + options (0)
    data = struct.pack("<HH", 1, 0)
    return build_enip_header(CMD_REGISTER_SESSION, data=data)


def parse_enip_header(raw: bytes) -> Optional[Dict[str, Any]]:
    """Parse 24-byte ENIP header."""
    if len(raw) < 24:
        return None
    cmd = struct.unpack_from("<H", raw, 0)[0]
    length = struct.unpack_from("<H", raw, 2)[0]
    session_id = struct.unpack_from("<I", raw, 4)[0]
    status = struct.unpack_from("<I", raw, 8)[0]
    data = raw[24:24 + length]
    return {
        "command": cmd,
        "command_name": CMD_NAMES.get(cmd, f"Unknown(0x{cmd:04X})"),
        "length": length,
        "session_id": session_id,
        "status": status,
        "data": data,
    }


def parse_list_identity(data: bytes) -> List[EnipIdentity]:
    """Parse ListIdentity response data into EnipIdentity objects."""
    identities: List[EnipIdentity] = []
    if len(data) < 2:
        return identities

    count = struct.unpack_from("<H", data, 0)[0]
    offset = 2

    for _ in range(count):
        if offset + 4 > len(data):
            break
        item_type = struct.unpack_from("<H", data, offset)[0]
        item_length = struct.unpack_from("<H", data, offset + 2)[0]
        offset += 4

        if item_type != 0x000C or offset + item_length > len(data):
            offset += item_length
            continue

        item_data = data[offset:offset + item_length]
        if len(item_data) < 33:
            offset += item_length
            continue

        identity = EnipIdentity()
        identity.vendor_id = struct.unpack_from("<H", item_data, 4)[0]
        identity.device_type = struct.unpack_from("<H", item_data, 6)[0]
        identity.product_code = struct.unpack_from("<H", item_data, 8)[0]
        identity.revision_major = item_data[10]
        identity.revision_minor = item_data[11]
        identity.status = struct.unpack_from("<H", item_data, 12)[0]
        identity.serial_number = struct.unpack_from("<I", item_data, 14)[0]

        name_len = item_data[18] if len(item_data) > 18 else 0
        if name_len > 0 and len(item_data) >= 19 + name_len:
            identity.product_name = item_data[19:19 + name_len].decode("ascii", errors="replace")

        identity.vendor_name = VENDOR_IDS.get(identity.vendor_id, f"Vendor(0x{identity.vendor_id:04X})")
        identities.append(identity)
        offset += item_length

    return identities


class EnipClient:
    """EtherNet/IP TCP client for CIP device discovery and interaction."""

    def __init__(
        self,
        host: str,
        port: int = ENIP_PORT,
        timeout: float = 3.0,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.session_id = 0
        self._sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        """Establish TCP connection and register session."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.settimeout(self.timeout)
            self._sock.connect((self.host, self.port))

            self._sock.sendall(build_register_session())
            resp = self._recv()
            if not resp:
                return False

            parsed = parse_enip_header(resp)
            if parsed and parsed["status"] == 0:
                self.session_id = parsed["session_id"]
                return True
            return False
        except Exception:
            self._sock = None
            return False

    def disconnect(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self.session_id = 0

    def list_identity(self) -> EnipResponse:
        """Send ListIdentity and parse device information."""
        try:
            self._sock.sendall(build_list_identity())
            raw = self._recv()
            if not raw:
                return EnipResponse(success=False, error="No response")
            parsed = parse_enip_header(raw)
            if not parsed:
                return EnipResponse(success=False, error="Invalid header")
            identities = parse_list_identity(parsed["data"])
            return EnipResponse(
                success=True,
                command=CMD_LIST_IDENTITY,
                session_id=parsed["session_id"],
                data=parsed["data"],
                identities=identities,
            )
        except Exception as exc:
            return EnipResponse(success=False, error=str(exc))

    @staticmethod
    def udp_list_identity(
        broadcast: str = "255.255.255.255",
        port: int = ENIP_PORT_UDP,
        timeout: float = 2.0,
    ) -> List[EnipIdentity]:
        """Send UDP broadcast ListIdentity and collect responses."""
        results: List[EnipIdentity] = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(timeout)
            sock.sendto(build_list_identity(), (broadcast, port))
            while True:
                try:
                    data, _ = sock.recvfrom(4096)
                    parsed = parse_enip_header(data)
                    if parsed and parsed["command"] == CMD_LIST_IDENTITY:
                        results.extend(parse_list_identity(parsed["data"]))
                except socket.timeout:
                    break
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return results

    def _recv(self) -> bytes:
        if not self._sock:
            return b""
        try:
            data = b""
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) >= 24:
                    length = struct.unpack_from("<H", data, 2)[0]
                    if len(data) >= 24 + length:
                        break
            return data
        except socket.timeout:
            return data if data else b""
