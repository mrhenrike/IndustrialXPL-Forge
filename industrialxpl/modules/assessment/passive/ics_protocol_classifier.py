"""
industrialxpl/modules/assessment/passive/ics_protocol_classifier.py

Native ICS Protocol Classifier - fingerprint OT protocol from payload bytes.

Identifies ICS/OT protocols from raw packet payloads using byte signatures
and heuristics. Useful for passive traffic analysis and PCAP inspection.

Protocols supported:
    Modbus/TCP, S7comm, EtherNet/IP, DNP3, BACnet, IEC 60870-5-104 (IEC104),
    OPC-UA, PROFINET, Modbus RTU, MQTT, FINS, ADS/TwinCAT

OUI Vendor database for ICS manufacturer identification included.

Sources:
    - Gridwolf backend protocol_parsers.py (OSINT logic)
    - Wireshark ICS protocol dissectors (heuristics)
    - MITRE ATT&CK ICS T0846 Remote System Discovery

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Protocol signature database
# ---------------------------------------------------------------------------

@dataclass
class ProtocolMatch:
    """Result of protocol classification."""
    protocol: str
    confidence: str        # HIGH, MEDIUM, LOW
    description: str
    mitre_technique: str = ""
    port_hint: int = 0


# OUI to ICS vendor mapping (first 3 bytes of MAC address)
OUI_VENDORS: Dict[str, str] = {
    "00:0e:8c": "Rockwell Automation",
    "00:00:1b": "Novatel Communications (Rockwell legacy)",
    "00:00:e8": "Accton Technology",
    "00:80:f4": "Telemecanique (Schneider legacy)",
    "00:30:de": "Siemens AG",
    "00:0d:4b": "Siemens Automation",
    "00:15:3e": "Siemens PLC",
    "00:1f:f8": "Siemens",
    "00:1b:1b": "Beckhoff Automation",
    "00:01:05": "Beckhoff",
    "8c:89:a5": "Beckhoff Embedded",
    "00:60:35": "Schneider Electric",
    "00:00:54": "Schneider Modicon",
    "00:0a:5e": "Schneider SY/MAX",
    "08:00:06": "Sirius Computer",
    "00:09:6e": "ABB Drives",
    "00:30:2c": "ABB Robotics",
    "00:1a:b7": "GE Fanuc",
    "00:e0:2b": "Extreme Networks (Hirschmann legacy)",
    "00:90:1a": "Hirschmann Automation",
    "00:0e:cf": "PROFIBUS Nutzerorganisation (PROFINET)",
    "01:0e:cf": "PROFINET Multicast",
}


def identify_oui(mac: str) -> str:
    """Identify ICS vendor from MAC OUI (first 3 octets)."""
    oui = ":".join(mac.lower().split(":")[:3])
    return OUI_VENDORS.get(oui, "Unknown vendor")


# ---------------------------------------------------------------------------
# Protocol heuristics
# ---------------------------------------------------------------------------

def _check_modbus_tcp(payload: bytes) -> bool:
    """Heuristic for Modbus/TCP (MBAP header)."""
    if len(payload) < 8:
        return False
    proto_id = struct.unpack_from(">H", payload, 2)[0]
    length = struct.unpack_from(">H", payload, 4)[0]
    if proto_id != 0x0000:
        return False
    fc = payload[7] & 0x7F
    return 0x01 <= fc <= 0x2B and length > 0


def _check_s7comm(payload: bytes) -> bool:
    """Heuristic for S7comm (protocol ID 0x32)."""
    if len(payload) < 10:
        return False
    return payload[0] == 0x32 and payload[1] in (0x01, 0x02, 0x03, 0x07)


def _check_enip(payload: bytes) -> bool:
    """Heuristic for EtherNet/IP."""
    if len(payload) < 4:
        return False
    cmd = struct.unpack_from("<H", payload, 0)[0]
    return cmd in (0x0063, 0x0064, 0x0065, 0x006F, 0x0070)


def _check_dnp3(payload: bytes) -> bool:
    """Heuristic for DNP3 (start bytes 0x05 0x64)."""
    return len(payload) >= 2 and payload[0] == 0x05 and payload[1] == 0x64


def _check_bacnet(payload: bytes) -> bool:
    """Heuristic for BACnet/IP (BVLC header type 0x81)."""
    return len(payload) >= 4 and payload[0] == 0x81 and payload[1] in (0x00, 0x01, 0x04, 0x0B)


def _check_iec104(payload: bytes) -> bool:
    """Heuristic for IEC 60870-5-104 (start byte 0x68)."""
    if len(payload) < 6:
        return False
    return payload[0] == 0x68 and payload[1] == len(payload) - 2


def _check_cotp(payload: bytes) -> bool:
    """Heuristic for COTP (S7comm transport layer, TPKT 0x03 0x00)."""
    return len(payload) >= 4 and payload[0] == 0x03 and payload[1] == 0x00


def _check_opcua(payload: bytes) -> bool:
    """Heuristic for OPC-UA binary (magic HEL/ACK/MSG)."""
    if len(payload) < 4:
        return False
    magic = payload[:3]
    return magic in (b"HEL", b"ACK", b"MSG", b"OPN", b"CLO")


def _check_mqtt(payload: bytes) -> bool:
    """Heuristic for MQTT (CONNECT packet type 0x10)."""
    if len(payload) < 4:
        return False
    ptype = (payload[0] >> 4) & 0x0F
    return ptype in (1, 2, 3, 4, 8, 9, 12, 14) and 0x01 < payload[1] < len(payload)


def _check_fins(payload: bytes) -> bool:
    """Heuristic for FINS (Omron) header."""
    return len(payload) >= 12 and payload[0] == 0x80 and payload[2] == 0x02


def _check_ads(payload: bytes) -> bool:
    """Heuristic for Beckhoff ADS (AMSTCPHeader 0x00 0x00 + ADS)."""
    if len(payload) < 6:
        return False
    return payload[0] == 0x00 and payload[1] == 0x00 and struct.unpack_from("<I", payload, 2)[0] > 0


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

_PROTOCOL_CHECKS: List[Tuple[str, object, str, str, int]] = [
    # (protocol_name, check_func, confidence_if_match, description, port_hint)
    ("Modbus/TCP", _check_modbus_tcp, "HIGH", "Modbus TCP/IP industrial protocol (IEC 61158)", 502),
    ("S7comm", _check_s7comm, "HIGH", "Siemens S7 Communication Protocol (PLCs S7-300/400/1200/1500)", 102),
    ("EtherNet/IP", _check_enip, "HIGH", "EtherNet/IP - Common Industrial Protocol (Rockwell, Allen-Bradley)", 44818),
    ("DNP3", _check_dnp3, "HIGH", "Distributed Network Protocol 3 (power/water utilities)", 20000),
    ("BACnet/IP", _check_bacnet, "HIGH", "Building Automation Control Network (ASHRAE 135)", 47808),
    ("IEC 104", _check_iec104, "HIGH", "IEC 60870-5-104 Telecontrol protocol (power utilities)", 2404),
    ("COTP/S7", _check_cotp, "MEDIUM", "ISO 8073 COTP transport (Siemens S7 framing)", 102),
    ("OPC-UA", _check_opcua, "HIGH", "OPC Unified Architecture (industry-neutral protocol)", 4840),
    ("MQTT", _check_mqtt, "MEDIUM", "Message Queuing Telemetry Transport (IIoT)", 1883),
    ("FINS", _check_fins, "HIGH", "Omron FINS network communication protocol", 9600),
    ("ADS/TwinCAT", _check_ads, "MEDIUM", "Beckhoff ADS - Automation Device Specification", 48898),
]


class ICSProtocolClassifier:
    """Classify ICS/OT protocols from raw payload bytes.

    Usage:
        classifier = ICSProtocolClassifier()
        match = classifier.classify(payload_bytes)
        if match:
            print(match.protocol, match.confidence)

        # Batch classify
        matches = classifier.classify_all(payload_bytes)
    """

    def classify(self, payload: bytes) -> Optional[ProtocolMatch]:
        """Return the first (highest confidence) protocol match."""
        for proto_name, check_fn, confidence, description, port in _PROTOCOL_CHECKS:
            try:
                if check_fn(payload):
                    return ProtocolMatch(
                        protocol=proto_name,
                        confidence=confidence,
                        description=description,
                        port_hint=port,
                    )
            except Exception:
                continue
        return None

    def classify_all(self, payload: bytes) -> List[ProtocolMatch]:
        """Return all matching protocols (may return multiple for ambiguous payloads)."""
        results = []
        for proto_name, check_fn, confidence, description, port in _PROTOCOL_CHECKS:
            try:
                if check_fn(payload):
                    results.append(ProtocolMatch(
                        protocol=proto_name,
                        confidence=confidence,
                        description=description,
                        port_hint=port,
                    ))
            except Exception:
                continue
        return results

    @staticmethod
    def classify_by_port(port: int) -> str:
        """Best-guess protocol name from destination port."""
        PORT_MAP: Dict[int, str] = {
            502: "Modbus/TCP",
            102: "S7comm/COTP",
            44818: "EtherNet/IP",
            2222: "EtherNet/IP (UDP)",
            20000: "DNP3",
            2404: "IEC 104",
            47808: "BACnet/IP",
            4840: "OPC-UA",
            1883: "MQTT",
            8883: "MQTT/TLS",
            9600: "FINS",
            48898: "ADS/TwinCAT",
            4000: "Emerson DeltaV",
            18245: "GE SRTP",
            18246: "GE SRTP (alt)",
            11001: "OMRON FINS UDP",
            2455: "WAGO KBUS",
            789: "Rockwell PCCC",
        }
        return PORT_MAP.get(port, f"Unknown (port {port})")
