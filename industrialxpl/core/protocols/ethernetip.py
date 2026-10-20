"""EtherNet/IP (CIP over Ethernet) protocol stub.

Provides skeleton classes for communication with Allen-Bradley,
Rockwell and other CIP-based PLCs/controllers over EtherNet/IP.
Production implementation can wrap python-ethernetip or cpppo.
"""


import logging
import struct
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

ENIP_TCP_PORT = 44818
ENIP_UDP_PORT = 2222


class CipService:
    GET_ATTRIBUTE_ALL = 0x01
    GET_ATTRIBUTE_SINGLE = 0x0E
    SET_ATTRIBUTE_SINGLE = 0x10
    READ_TAG = 0x4C
    WRITE_TAG = 0x4D
    MULTI_SERVICE = 0x0A
    FORWARD_OPEN = 0x54
    FORWARD_CLOSE = 0x4E


@dataclass
class CipIdentity:
    vendor_id: int = 0
    device_type: int = 0
    product_code: int = 0
    revision_major: int = 0
    revision_minor: int = 0
    serial: int = 0
    product_name: str = ""
    state: int = 0


@dataclass
class Tag:
    name: str
    value: Any = None
    data_type: int = 0
    dimensions: list[int] = field(default_factory=list)


class EnipClient:
    """Skeleton EtherNet/IP client for CIP communication."""

    def __init__(self, host: str, port: int = ENIP_TCP_PORT) -> None:
        self.host = host
        self.port = port
        self._session_handle: int = 0
        self._connected = False

    def connect(self) -> bool:
        logger.info("EtherNet/IP connect to %s:%d", self.host, self.port)
        raise NotImplementedError("EtherNet/IP stack binding required")

    def disconnect(self) -> None:
        self._connected = False
        self._session_handle = 0

    def list_identity(self) -> CipIdentity:
        raise NotImplementedError("ListIdentity not implemented")

    def read_tag(self, tag_name: str, count: int = 1) -> Tag:
        raise NotImplementedError("CIP ReadTag not implemented")

    def write_tag(self, tag_name: str, value: Any, data_type: int = 0) -> bool:
        raise NotImplementedError("CIP WriteTag not implemented")

    def get_tags(self) -> list[Tag]:
        raise NotImplementedError("Tag enumeration not implemented")

    def forward_open(self) -> bool:
        raise NotImplementedError("CIP ForwardOpen not implemented")

    def forward_close(self) -> bool:
        raise NotImplementedError("CIP ForwardClose not implemented")


def build_register_session() -> bytes:
    """Build a RegisterSession encapsulation header."""
    command = 0x0065
    length = 4
    session_handle = 0
    status = 0
    sender_context = b"\x00" * 8
    options = 0
    header = struct.pack(
        "<HHIIQI",
        command,
        length,
        session_handle,
        status,
        int.from_bytes(sender_context, "little"),
        options,
    )
    payload = struct.pack("<HH", 1, 0)
    return header + payload
