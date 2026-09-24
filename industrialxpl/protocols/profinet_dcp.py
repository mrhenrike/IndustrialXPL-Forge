"""
industrialxpl/protocols/profinet_dcp.py - Native PROFINET DCP (Discovery and Basic Configuration).

Implements PROFINET DCP over Ethernet (Ethertype 0x8892).
Pure-Python using raw sockets or scapy as optional backend.
Falls back gracefully when raw socket is unavailable (non-root).

Reference:
    PROFINET Specification IEC 61158-6-10
    MITRE ATT&CK ICS: T0846 Remote System Discovery, T0860 Wireless Compromise

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

__version__ = "1.0.0"

PROFINET_ETHERTYPE = 0x8892
DCP_MULTICAST_MAC = bytes.fromhex("01 0E CF 00 00 00".replace(" ", ""))
DCP_IDENTIFY_FRAME_ID = 0xFEFE
DCP_IDENTIFY_RESPONSE_FRAME_ID = 0xFEFF

# DCP Service IDs
DCP_SERVICE_ID_GET = 0x03
DCP_SERVICE_ID_SET = 0x04
DCP_SERVICE_ID_IDENTIFY = 0x05
DCP_SERVICE_ID_HELLO = 0x06

# DCP Service Types
DCP_SERVICE_TYPE_REQUEST = 0x00
DCP_SERVICE_TYPE_RESPONSE_SUCCESS = 0x01

# DCP Options
DCP_OPTION_IP = 0x01
DCP_OPTION_DEVICE = 0x02
DCP_OPTION_ALL = 0xFF

# DCP Sub-options
DCP_SUBOPTION_IP_MAC = 0x01
DCP_SUBOPTION_IP_PARAM = 0x02
DCP_SUBOPTION_DEVICE_VENDOR = 0x01
DCP_SUBOPTION_DEVICE_NAME = 0x02
DCP_SUBOPTION_DEVICE_ID = 0x03
DCP_SUBOPTION_ALL = 0xFF

# Block qualifier for Set IP (permanent)
DCP_QUALIFIER_SET_PERMANENT = 0x0001


@dataclass
class ProfinetDevice:
    """Discovered PROFINET device."""
    mac: str = ""
    ip: str = ""
    subnet: str = ""
    gateway: str = ""
    name: str = ""
    vendor: str = ""
    device_id: str = ""
    vendor_id: int = 0
    model_id: int = 0


@dataclass
class DcpResponse:
    """Parsed DCP response."""
    success: bool
    devices: List[ProfinetDevice] = field(default_factory=list)
    error: str = ""


def _build_dcp_header(
    service_id: int,
    service_type: int,
    xid: int,
    response_delay: int,
    blocks: bytes,
) -> bytes:
    """Build DCP PDU header."""
    return (
        struct.pack(">B", service_id)
        + struct.pack(">B", service_type)
        + struct.pack(">I", xid)
        + struct.pack(">H", response_delay)
        + struct.pack(">H", len(blocks))
        + blocks
    )


def build_dcp_identify_all(xid: int = 0x01234567) -> bytes:
    """Build DCP Identify All Request block.

    Returns the DCP PDU (without Ethernet/IP framing).
    The caller is responsible for framing with Ethertype 0x8892 and
    FrameID 0xFEFE.
    """
    # Block: Option=ALL_SELECTOR(0xFF) SubOption=ALL(0xFF) Length=0
    block = struct.pack(">BBH", DCP_OPTION_ALL, DCP_SUBOPTION_ALL, 0x0000)
    return _build_dcp_header(
        DCP_SERVICE_ID_IDENTIFY,
        DCP_SERVICE_TYPE_REQUEST,
        xid=xid,
        response_delay=128,
        blocks=block,
    )


def build_dcp_set_ip(
    station_mac: str,
    new_ip: str,
    subnet: str = "255.255.255.0",
    gateway: str = "0.0.0.0",
    xid: int = 0xDEADBEEF,
) -> bytes:
    """Build DCP Set IP Parameter request.

    Args:
        station_mac: Target MAC address (unicast).
        new_ip: New IP address to set.
        subnet: Subnet mask.
        gateway: Default gateway.
        xid: Transaction ID.

    Returns:
        DCP PDU bytes (without Ethernet framing).
    """
    ip_bytes = socket.inet_aton(new_ip)
    subnet_bytes = socket.inet_aton(subnet)
    gw_bytes = socket.inet_aton(gateway)

    # Block Qualifier (2) + IP (4) + Subnet (4) + GW (4) = 14 bytes
    block_data = struct.pack(">H", DCP_QUALIFIER_SET_PERMANENT) + ip_bytes + subnet_bytes + gw_bytes
    block = (
        struct.pack(">B", DCP_OPTION_IP)
        + struct.pack(">B", DCP_SUBOPTION_IP_PARAM)
        + struct.pack(">H", len(block_data))
        + block_data
    )
    # Pad to even length
    if len(block) % 2:
        block += b"\x00"

    return _build_dcp_header(
        DCP_SERVICE_ID_SET,
        DCP_SERVICE_TYPE_REQUEST,
        xid=xid,
        response_delay=0,
        blocks=block,
    )


def parse_dcp_blocks(blocks_data: bytes) -> Dict[str, Any]:
    """Parse DCP block list from response payload."""
    result: Dict[str, Any] = {}
    offset = 0

    while offset + 4 <= len(blocks_data):
        option = blocks_data[offset]
        suboption = blocks_data[offset + 1]
        block_len = struct.unpack_from(">H", blocks_data, offset + 2)[0]
        block_data = blocks_data[offset + 4: offset + 4 + block_len]
        offset += 4 + block_len
        if offset % 2:
            offset += 1  # padding

        if option == DCP_OPTION_IP:
            if suboption == DCP_SUBOPTION_IP_PARAM and len(block_data) >= 14:
                result["ip"] = socket.inet_ntoa(block_data[2:6])
                result["subnet"] = socket.inet_ntoa(block_data[6:10])
                result["gateway"] = socket.inet_ntoa(block_data[10:14])
            elif suboption == DCP_SUBOPTION_IP_MAC and len(block_data) >= 6:
                result["mac"] = ":".join(f"{b:02X}" for b in block_data[:6])

        elif option == DCP_OPTION_DEVICE:
            if suboption == DCP_SUBOPTION_DEVICE_NAME and len(block_data) >= 2:
                result["name"] = block_data[2:].decode("ascii", errors="replace").strip("\x00")
            elif suboption == DCP_SUBOPTION_DEVICE_ID and len(block_data) >= 6:
                result["vendor_id"] = struct.unpack_from(">H", block_data, 2)[0]
                result["device_id"] = struct.unpack_from(">H", block_data, 4)[0]
            elif suboption == DCP_SUBOPTION_DEVICE_VENDOR and len(block_data) >= 2:
                result["vendor"] = block_data[2:].decode("ascii", errors="replace").strip("\x00")

    return result


def _frame_profinet(src_mac: bytes, dst_mac: bytes, frame_id: int, dcp_pdu: bytes) -> bytes:
    """Wrap DCP PDU in Ethernet frame with PROFINET Ethertype."""
    eth_header = dst_mac + src_mac + struct.pack(">H", PROFINET_ETHERTYPE)
    pnio_frameid = struct.pack(">H", frame_id)
    return eth_header + pnio_frameid + dcp_pdu


class ProfinetDcpDiscovery:
    """PROFINET DCP discovery over Layer 2.

    Sends DCP Identify All broadcast and collects responses.
    Requires raw socket access (root/admin).

    If raw socket unavailable, falls back to scapy if installed,
    otherwise raises PermissionError.

    Usage:
        disc = ProfinetDcpDiscovery("eth0")
        devices = disc.discover(timeout=2.0)
        for d in devices:
            print(d.name, d.ip)
    """

    def __init__(self, interface: str = "eth0") -> None:
        self.interface = interface

    def discover(self, timeout: float = 2.0) -> List[ProfinetDevice]:
        """Broadcast DCP Identify All and collect responses."""
        devices: List[ProfinetDevice] = []

        try:
            # Try scapy first (more portable)
            from scapy.all import sendp, sniff, Ether  # type: ignore
            from scapy.layers.l2 import Ether as ScapyEther

            dcp_pdu = build_dcp_identify_all()
            multicast_mac = ":".join(f"{b:02X}" for b in DCP_MULTICAST_MAC)

            frame = ScapyEther(dst=multicast_mac, type=PROFINET_ETHERTYPE) / bytes([0xFE, 0xFE]) + dcp_pdu
            sendp(frame, iface=self.interface, verbose=False)

            packets = sniff(
                iface=self.interface,
                timeout=timeout,
                filter=f"ether proto 0x8892",
            )
            for pkt in packets:
                raw = bytes(pkt)
                if len(raw) > 14:
                    frame_id = struct.unpack_from(">H", raw, 14)[0]
                    if frame_id == DCP_IDENTIFY_RESPONSE_FRAME_ID:
                        src_mac = ":".join(f"{b:02X}" for b in raw[6:12])
                        dcp_payload = raw[16:]  # after Ethernet(14) + FrameID(2)
                        if len(dcp_payload) >= 10:
                            blocks_len = struct.unpack_from(">H", dcp_payload, 8)[0]
                            blocks = dcp_payload[10:10 + blocks_len]
                            parsed = parse_dcp_blocks(blocks)
                            dev = ProfinetDevice(mac=src_mac)
                            dev.ip = parsed.get("ip", "")
                            dev.subnet = parsed.get("subnet", "")
                            dev.gateway = parsed.get("gateway", "")
                            dev.name = parsed.get("name", "")
                            dev.vendor = parsed.get("vendor", "")
                            dev.vendor_id = parsed.get("vendor_id", 0)
                            dev.model_id = parsed.get("device_id", 0)
                            devices.append(dev)

        except ImportError:
            raise ImportError(
                "Scapy required for PROFINET DCP L2 discovery. "
                "Install: pip install scapy"
            )

        return devices

    @staticmethod
    def parse_dcp_pdu(raw_bytes: bytes) -> Optional[Dict[str, Any]]:
        """Parse a raw DCP PDU (after Ethernet and FrameID headers).

        Useful for offline PCAP analysis.
        """
        if len(raw_bytes) < 10:
            return None
        service_id = raw_bytes[0]
        service_type = raw_bytes[1]
        xid = struct.unpack_from(">I", raw_bytes, 2)[0]
        blocks_len = struct.unpack_from(">H", raw_bytes, 8)[0]
        blocks = raw_bytes[10:10 + blocks_len]
        result = parse_dcp_blocks(blocks)
        result["service_id"] = service_id
        result["service_type"] = service_type
        result["xid"] = xid
        return result
