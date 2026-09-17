"""S7comm Protocol Scanner and Enumerator.

Scans Siemens S7 PLCs (port 102) using the ISO-TSAP / S7comm protocol.
Implements ISO-TSAP connection setup and S7comm Read SZL (System Status List)
to identify PLC model, firmware, and configuration.

Based on xpl-forge-full-integration.plan.md Bloco 1 requirements.

Protocol stack:
  TCP:102 -> ISO-TSAP (COTP) -> S7comm

References:
  - Siemens S7 communication spec
  - Nmap s7-info.nse
  - snap7 library

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from embedxpl.core.exploit.base import Base
from embedxpl.core.exploit.option import OptIP, OptInt, OptBool


# ISO-TSAP connection request packet
COTP_CONNECT_REQUEST = bytes([
    0x03, 0x00, 0x00, 0x16,  # TPKT header: version=3, length=22
    0x11,                    # COTP length
    0xe0,                    # COTP: Connection Request
    0x00, 0x00,              # destination reference
    0x00, 0x01,              # source reference
    0x00,                    # class
    0xc0, 0x01, 0x0a,        # option: TPDU size = 1024
    0xc1, 0x02, 0x01, 0x00,  # src-tsap: rack 0, slot 0
    0xc2, 0x02, 0x01, 0x02,  # dst-tsap: rack 0, slot 2 (CPU)
])

# S7comm Setup Communication request
S7_SETUP_COMM = bytes([
    0x03, 0x00, 0x00, 0x19,  # TPKT
    0x02, 0xf0, 0x80,        # COTP Data
    0x32, 0x01, 0x00, 0x00,  # S7: protocol ID, message type, reserved
    0x04, 0x00,              # PDU reference
    0x00, 0x08, 0x00, 0x00,  # param length, data length
    0xf0, 0x00,              # function: Setup Communication
    0x00, 0x01, 0x00, 0x01,  # reserved, max AMQ caller, max AMQ called
    0x01, 0xe0,              # max PDU length: 480
])

# S7comm Read SZL request (System Status List - hardware info)
S7_READ_SZL = bytes([
    0x03, 0x00, 0x00, 0x21,
    0x02, 0xf0, 0x80,
    0x32, 0x07, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x08,
    0x00, 0x0c, 0x00, 0x01,
    0x12, 0x08, 0x12, 0x84,
    0x01, 0x01, 0x00, 0x00,  # SZL-ID: 0x0011 (module ident)
    0x00, 0x00, 0x00, 0x00, 0x00,
])


class S7CommScanner(Base):
    """S7comm PLC scanner for Siemens S7-300/400/1200/1500 PLCs."""

    __info__ = {
        "name": "S7comm PLC Scanner",
        "description": "Enumerate Siemens S7 PLC info via S7comm/ISO-TSAP (port 102)",
        "category": "ics_protocol",
        "author": "Andre Henrique (@mrhenrike) | Uniao Geek",
        "references": [
            "https://github.com/klemmm/s7-info",
            "nmap s7-info.nse",
        ],
    }

    target = OptIP("", "Target PLC IP address")
    port = OptInt(102, "S7comm port (default: 102)")
    timeout = OptInt(5, "Connection timeout (seconds)")
    rack = OptInt(0, "PLC rack number (default: 0)")
    slot = OptInt(2, "PLC slot number (default: 2 for CPU)")

    def _connect(self) -> Optional[socket.socket]:
        """Open ISO-TSAP connection to S7 PLC."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            return sock
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _recv_tpkt(self, sock: socket.socket) -> bytes:
        """Receive a TPKT frame."""
        header = sock.recv(4)
        if len(header) < 4:
            return b""
        length = struct.unpack(">H", header[2:4])[0]
        data = b""
        remaining = length - 4
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                break
            data += chunk
            remaining -= len(chunk)
        return header + data

    def check(self) -> bool:
        """Check if port 102 is open and responds to COTP connection."""
        if not self.target:
            return False
        sock = self._connect()
        if not sock:
            return False
        try:
            sock.send(COTP_CONNECT_REQUEST)
            resp = self._recv_tpkt(sock)
            # Look for COTP Connection Confirm (0xd0)
            return len(resp) >= 5 and resp[4] == 0xd0
        except Exception:
            return False
        finally:
            sock.close()

    def run(self) -> None:
        """Enumerate S7 PLC via S7comm protocol."""
        if not self.check():
            print(f"[-] {self.target}:{self.port} not responding to S7comm/ISO-TSAP")
            return

        sock = self._connect()
        if not sock:
            return

        try:
            # Step 1: COTP connection
            sock.send(COTP_CONNECT_REQUEST)
            resp = self._recv_tpkt(sock)
            if not resp or resp[4] != 0xd0:
                print(f"[-] COTP connection rejected")
                return
            print(f"[+] {self.target}:{self.port} - COTP Connected")

            # Step 2: S7 Setup Communication
            sock.send(S7_SETUP_COMM)
            resp = self._recv_tpkt(sock)
            if len(resp) >= 10 and resp[7] == 0x07:
                print(f"[+] S7comm communication established")

            # Step 3: Read SZL (System Status List)
            sock.send(S7_READ_SZL)
            resp = self._recv_tpkt(sock)
            if len(resp) > 30:
                # Parse PLC info from SZL response
                self._parse_szl(resp)
            else:
                print(f"[+] SZL request sent - no detailed response")

        except Exception as exc:
            print(f"[-] Error: {exc}")
        finally:
            sock.close()

    def _parse_szl(self, data: bytes) -> None:
        """Parse SZL response to extract PLC identification."""
        try:
            # SZL data starts after S7 header (~28 bytes)
            szl_data = data[28:]
            # Module designation is ASCII in SZL item (first 20 bytes)
            module_name = szl_data[:20].decode("ascii", errors="replace").strip("\x00 ")
            print(f"[+] Module: {module_name or 'Unknown'}")
            # Serial number
            if len(szl_data) >= 30:
                serial = szl_data[20:30].decode("ascii", errors="replace").strip("\x00 ")
                print(f"[+] Serial: {serial or 'N/A'}")
        except Exception:
            print(f"[+] PLC responded to SZL query (raw: {data[28:48].hex()})")
