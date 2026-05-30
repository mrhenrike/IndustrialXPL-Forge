# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Unitronics PCOM Protocol Scanner (Port 20256/TCP).

Unitronics Vision/Samba/UniStream PLCs implement the PCOM (Programmable
Controller Communication) protocol on TCP port 20256. PCOM provides access
to PLC data, I/O, operands, and program control.

PCOM has a known default password "1111" that is widely used and rarely changed
on deployed Unitronics PLCs. This was highlighted in ICS security research as
"OT Hunt #10 ZeronTek" and contributed to the Aliquippa, PA water utility
cyberattack in November 2023 (CyberAv3ngers targeting UNITRONICS Vision PLC).

This scanner:
  1. Connects to TCP/20256 and sends a PCOM Binary Identity Request
  2. Verifies the response matches expected PCOM framing
  3. Reports device identity, model, and firmware version

References:
  - Unitronics PCOM protocol documentation
  - OT Hunt #10 ZeronTek — default password "1111"
  - CISA Alert AA23-335A (CyberAv3ngers — Unitronics PLC targeting, 2023)
  - MITRE ATT&CK ICS: T0846 (Remote System Discovery)

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
    print_warning,
    print_table,
)

_PCOM_PORT = 20256

# PCOM Binary frame structure:
#   STX (0x02)
#   Reserved (0x65)
#   Unit ID (1 byte, 0x00 = broadcast/default)
#   Command ID (1 byte)
#   Length (1 byte)
#   Data (variable)
#   Checksum (1 byte, XOR of all bytes)
#   ETX (0x03)

_PCOM_STX = 0x02
_PCOM_ETX = 0x03

# Command codes
_CMD_GET_ID = 0x01  # Get Identity (returns model, OS version, hardware info)


def _xor_checksum(data: bytes) -> int:
    """Compute XOR checksum over all bytes."""
    result = 0
    for b in data:
        result ^= b
    return result


def _build_pcom_frame(unit_id: int, command: int, data: bytes = b"") -> bytes:
    """Build a PCOM Binary protocol frame."""
    body = bytes([0x65, unit_id & 0xFF, command & 0xFF, len(data)]) + data
    checksum = _xor_checksum(body)
    return bytes([_PCOM_STX]) + body + bytes([checksum, _PCOM_ETX])


_PCOM_IDENTITY_FRAME = _build_pcom_frame(unit_id=0x00, command=_CMD_GET_ID)


def _send_pcom(target: str, port: int, frame: bytes, timeout: int) -> Optional[bytes]:
    """Send PCOM frame via TCP and return response."""
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.sendall(frame)
        sock.settimeout(timeout)
        resp = sock.recv(256)
        sock.close()
        return resp
    except Exception:
        return None


def _parse_pcom_identity(resp: bytes) -> Optional[dict]:
    """Parse PCOM Identity response into device information dict."""
    if not resp or len(resp) < 6:
        return None
    if resp[0] != _PCOM_STX:
        return None

    result: dict = {}
    try:
        data_start = 5
        data_end = len(resp) - 2  # exclude checksum and ETX
        if data_end <= data_start:
            return result

        payload = resp[data_start:data_end]
        if len(payload) >= 1:
            result["HardwareType"] = "0x{:02X}".format(payload[0])
        if len(payload) >= 2:
            result["OSVersion"] = payload[1]
        if len(payload) >= 3:
            result["OSRelease"] = payload[2]
        if len(payload) >= 8:
            result["PLCName"] = payload[3:8].rstrip(b"\x00").decode("ascii", errors="replace")
    except Exception:
        pass

    return result


class Exploit(Exploit):
    """Unitronics PCOM Protocol Scanner.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Unitronics PCOM Scanner (20256/TCP)",
        "description": (
            "Sends a PCOM Binary Identity Request to Unitronics Vision/Samba/UniStream "
            "PLCs on TCP/20256. PCOM has no authentication on the default configuration "
            "and uses a well-known default password '1111'. Deployed Unitronics PLCs were "
            "targeted in the November 2023 Aliquippa water utility attack (CyberAv3ngers). "
            "This scanner detects exposed PCOM services and extracts device identity."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://www.cisa.gov/news-events/alerts/2023/11/28/exploitation-unitronics-plcs-used-water-and-wastewater-systems",
            "https://www.unitronicsplc.com/pcom-protocol/",
            "https://attack.mitre.org/techniques/T0846/001/",
        ),
        "devices": (
            "Unitronics Vision series (V120/V230/V280/V290/V350/V430/V560/V700)",
            "Unitronics Samba series",
            "Unitronics UniStream series",
        ),
        "impact": "INFO",
        "cve": "N/A",
        "cvss": "N/A",
        "severity": "INFO",
        "mitre_techniques": ["T0846.001", "T0888"],
        "mitre_tactics": ["Discovery"],
    }

    target = OptIP("", "Target Unitronics PLC IP address")
    port = OptPort(_PCOM_PORT, "PCOM TCP port (default 20256)")
    timeout = OptInteger(5, "Socket timeout in seconds")
    simulate = OptBool(True, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable destructive execution")

    @mute
    def check(self) -> bool:
        """Return True if PCOM responds on TCP/20256."""
        if not self.target:
            return False
        resp = _send_pcom(self.target, self.port, _PCOM_IDENTITY_FRAME, 3)
        return resp is not None and len(resp) >= 4 and resp[0] == _PCOM_STX

    def run(self) -> None:
        """Probe PCOM service and report device identity."""
        if not self.target:
            print_error("Set 'target' option first.")
            return

        print_status("[PCOM] Probing {}:{}/TCP for Unitronics PCOM...".format(
            self.target, self.port
        ))

        resp = _send_pcom(self.target, self.port, _PCOM_IDENTITY_FRAME, self.timeout)
        if not resp:
            print_error("[PCOM] No response — PCOM not detected or port closed.")
            return

        if resp[0] != _PCOM_STX:
            print_info("[PCOM] TCP port responded but PCOM STX not found.")
            print_info("[PCOM] Raw response: {}".format(resp[:32].hex()))
            return

        print_success("[PCOM] PCOM response detected from {}!".format(self.target))
        info = _parse_pcom_identity(resp)

        if info:
            rows = [(k, str(v)) for k, v in info.items()]
            print_table(
                name="Unitronics PCOM Device Info",
                header=("Field", "Value"),
                rows=rows,
            )
        else:
            print_info("[PCOM] Response received but identity parsing yielded no fields.")
            print_info("[PCOM] Raw ({} B): {}".format(len(resp), resp.hex()))

        print_warning(
            "[PCOM] Default password is '1111'. No authentication on default config. "
            "OT Hunt #10 (ZeronTek). See CISA Alert AA23-335A (CyberAv3ngers, 2023)."
        )
