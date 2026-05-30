# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""BACnet/IP Layer 3 Device Scanner — Who-Is / I-Am Enumeration (Port 47808/UDP).

Performs a BACnet Layer 3 discovery by sending a BACnet Who-Is broadcast (or
unicast) and collecting I-Am responses. Each responding device identifies itself
with:
  - Device Object Identifier (unique device instance number 0-4194302)
  - Maximum APDU length (segmentation capability)
  - Vendor ID mapped to Vendor Name

BACnet/IP (ANSI/ASHRAE Standard 135, ISO 16484-5) has no built-in access
control at the network layer. Any device that responds is directly accessible
for further read/write operations without authentication.

This scanner is a Layer 3 (IP-routable) variant of BACnet discovery,
distinct from BACnet MS/TP (RS-485 serial) or BACnet Ethernet (Layer 2).

References:
  - ANSI/ASHRAE 135 — BACnet standard
  - ICS-CERT Advisory ICSA-15-202-01
  - Project Redpoint (DigitalBond) BACnet scanning research
  - MITRE ATT&CK ICS: T0846 (Remote System Discovery), T0888 (Remote System Information Discovery)

Version: 1.0.0
"""

import socket
import struct
from typing import Optional

from industrialxpl.core.exploit import (
    Exploit,
    OptBool,
    OptIP,
    OptInteger,
    OptPort,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_table,
)

_BACNET_PORT = 47808  # 0xBAC0

# BACnet Who-Is (broadcast): BVLC + NPDU + APDU
_WHO_IS_BCAST = bytes([
    0x81, 0x0B, 0x00, 0x0C,        # BVLC: Original-Broadcast-NPDU, length=12
    0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF,  # NPDU: version=1, destination=broadcast
    0x10, 0x08,                    # APDU: Unconfirmed-Req(0x10), Who-Is(0x08)
])

# BACnet Who-Is (unicast): BVLC + NPDU + APDU
_WHO_IS_UNICAST = bytes([
    0x81, 0x0A, 0x00, 0x0C,        # BVLC: Original-Unicast-NPDU, length=12
    0x01, 0x00,                    # NPDU: version=1, no destination
    0x10, 0x08,                    # APDU: Unconfirmed-Req, Who-Is (no range = all devices)
    0x00, 0x00, 0x00, 0x00,        # padding to 12 bytes
])

# Known BACnet Vendor IDs (partial — extended from ASHRAE registry)
_VENDOR_NAMES: dict = {
    0:   "ASHRAE",
    5:   "Siemens Building Technologies",
    7:   "Trane",
    8:   "Carrier",
    10:  "Johnson Controls",
    16:  "Honeywell",
    24:  "Andover Controls",
    36:  "Alerton",
    61:  "Distech Controls",
    73:  "Invensys",
    86:  "Delta Controls",
    95:  "Cylon Controls",
    135: "Automated Logic",
    149: "Reliable Controls",
    160: "ABB",
    200: "Schneider Electric",
    260: "KMC Controls",
    309: "Daikin",
    367: "Belimo",
    398: "Rockwell Automation",
}


def _parse_i_am(data: bytes, src_ip: str) -> Optional[dict]:
    """Parse a BACnet I-Am APDU into a device information dict.

    Returns None if the packet is not a valid I-Am or is too short to parse.
    """
    if len(data) < 12:
        return None

    # Skip BVLC header (4 bytes)
    offset = 4

    # Parse NPDU: skip variable-length destination/source specifiers
    if offset >= len(data):
        return None
    npdu_control = data[offset + 1] if offset + 1 < len(data) else 0
    npdu_skip = 2
    if npdu_control & 0x20:  # destination network present
        npdu_skip += 3
        if offset + npdu_skip < len(data):
            npdu_skip += data[offset + npdu_skip - 1]  # dlen
    if npdu_control & 0x08:  # source network present
        npdu_skip += 3
        if offset + npdu_skip < len(data):
            npdu_skip += data[offset + npdu_skip - 1]  # slen
    offset += npdu_skip

    if offset + 2 > len(data):
        return None

    # APDU: type 1 = Unconfirmed-Req, service 0x00 = I-Am
    apdu_type = (data[offset] >> 4) & 0x0F
    service = data[offset + 1] if offset + 1 < len(data) else 0xFF
    if apdu_type != 1 or service != 0:
        return None

    offset += 2
    result: dict = {"IP": src_ip}

    try:
        # Object Identifier: tag 0xC4, 4-byte value
        if offset + 5 <= len(data) and data[offset] == 0xC4:
            raw = struct.unpack(">I", data[offset + 1:offset + 5])[0]
            result["DeviceInstance"] = raw & 0x3FFFFF
            offset += 5

        # Max APDU length accepted: tag 0x22, 2-byte value
        if offset + 3 <= len(data) and data[offset] == 0x22:
            result["MaxAPDU"] = struct.unpack(">H", data[offset + 1:offset + 3])[0]
            offset += 3

        # Segmentation supported: tag 0x91, 1-byte enum
        if offset + 2 <= len(data) and data[offset] == 0x91:
            result["Segmentation"] = data[offset + 1]
            offset += 2

        # Vendor ID: tag 0x21 (1 byte) or 0x22 (2 bytes)
        if offset + 2 <= len(data) and data[offset] in (0x21, 0x22):
            if data[offset] == 0x21:
                vendor_id = data[offset + 1]
                offset += 2
            else:
                vendor_id = struct.unpack(">H", data[offset + 1:offset + 3])[0]
                offset += 3
            result["VendorID"] = vendor_id
            result["VendorName"] = _VENDOR_NAMES.get(vendor_id, "Unknown(ID={})".format(vendor_id))
    except Exception:
        pass

    return result


class Exploit(Exploit):
    """BACnet/IP Layer 3 Device Scanner — Who-Is / I-Am enumeration.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "BACnet/IP Layer 3 Device Scanner",
        "description": (
            "Sends a BACnet Who-Is broadcast (or unicast) on UDP/47808 and collects "
            "I-Am responses. Identifies responding devices by Device Instance number, "
            "Vendor ID/Name, and maximum APDU length. BACnet/IP carries no access "
            "control — all discovered devices are directly accessible for further "
            "read/write operations. Covers routed (Layer 3) BACnet/IP segments."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://www.ashrae.org/technical-resources/bookstore/bacnet",
            "https://attack.mitre.org/techniques/T0846/002/",
            "https://github.com/digitalbond/Redpoint",
        ),
        "devices": (
            "BACnet PLC / BMS controller / HVAC controller",
            "Honeywell", "Siemens", "Johnson Controls", "Trane", "Carrier",
            "Schneider Electric", "Delta Controls",
        ),
        "impact": "INFO",
        "cve": "N/A",
        "cvss": "N/A",
        "severity": "INFO",
        "mitre_techniques": ["T0846.002", "T0888"],
        "mitre_tactics": ["Discovery"],
    }

    target = OptIP("255.255.255.255", "Target IP or broadcast (default: 255.255.255.255)")
    port = OptPort(_BACNET_PORT, "BACnet/UDP port (default 47808)")
    timeout = OptInteger(5, "Listen timeout in seconds after Who-Is")
    simulate = OptBool(True, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable destructive execution")

    @mute
    def check(self) -> bool:
        """Return True if at least one BACnet device responds to Who-Is."""
        if not self.target:
            return False
        is_broadcast = self.target.endswith(".255") or self.target == "255.255.255.255"
        payload = _WHO_IS_BCAST if is_broadcast else _WHO_IS_UNICAST
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(3)
        try:
            sock.sendto(payload, (self.target, self.port))
            data, _ = sock.recvfrom(512)
            return bool(data)
        except Exception:
            return False
        finally:
            sock.close()

    def run(self) -> None:
        """Send BACnet Who-Is and collect I-Am responses."""
        is_broadcast = self.target.endswith(".255") or self.target == "255.255.255.255"
        payload = _WHO_IS_BCAST if is_broadcast else _WHO_IS_UNICAST

        print_status("[BACnet-L3] Sending Who-Is to {}:{}/UDP...".format(
            self.target, self.port
        ))

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(self.timeout)

        devices: list = []
        try:
            sock.sendto(payload, (self.target, self.port))
            while True:
                try:
                    data, (src_ip, _) = sock.recvfrom(512)
                    info = _parse_i_am(data, src_ip)
                    if info:
                        devices.append(info)
                        print_success(
                            "[BACnet-L3] I-Am from {} | Instance={} | Vendor={} | MaxAPDU={}".format(
                                src_ip,
                                info.get("DeviceInstance", "?"),
                                info.get("VendorName", "?"),
                                info.get("MaxAPDU", "?"),
                            )
                        )
                    else:
                        print_info("[BACnet-L3] Response from {} ({} B) — not I-Am".format(
                            src_ip, len(data)
                        ))
                except socket.timeout:
                    break
        finally:
            sock.close()

        if not devices:
            print_error("[BACnet-L3] No BACnet I-Am responses received.")
            return

        print_status("[BACnet-L3] {} device(s) discovered.".format(len(devices)))
        print_table(
            name="BACnet/IP L3 Discovered Devices",
            header=("IP", "DeviceInstance", "VendorName", "MaxAPDU"),
            rows=[
                (
                    d.get("IP", ""),
                    str(d.get("DeviceInstance", "?")),
                    d.get("VendorName", "?"),
                    str(d.get("MaxAPDU", "?")),
                )
                for d in devices
            ],
        )
