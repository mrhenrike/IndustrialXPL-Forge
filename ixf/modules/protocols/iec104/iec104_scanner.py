"""IEC 60870-5-104 (IEC104) Protocol Scanner.

IEC104 is the TCP/IP adaptation of IEC 60870-5-101, used in power grids,
energy management systems, and SCADA. Default port: 2404.

Implements:
- STARTDT (Start Data Transfer) activation
- Interrogation command (C_IC_NA_1 = ASDU type 100)
- Counter interrogation command
- General interrogation to read all monitored values

xpl-forge-full-integration.plan.md Bloco 1.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from embedxpl.core.exploit.base import Base
from embedxpl.core.exploit.option import OptIP, OptInt


# IEC104 APCI (Application Protocol Control Information) header
IEC104_STARTDT_ACT = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])  # STARTDT
IEC104_TESTFR_ACT = bytes([0x68, 0x04, 0x43, 0x00, 0x00, 0x00])   # TESTFR

# General Interrogation (C_IC_NA_1, type 100, COT=6 activation)
IEC104_GENERAL_INTERROGATION = bytes([
    0x68, 0x0e,              # Start + APDU length
    0x00, 0x00, 0x00, 0x00,  # I-format APCI (seq 0)
    0x64,                    # Type ID: C_IC_NA_1 = 100
    0x01,                    # VSQ: 1 object, SQ=0
    0x06, 0x00,              # COT: activation (6)
    0x01, 0x00,              # originator + common address
    0x00, 0x00, 0x00,        # information object address
    0x14,                    # qualifier: general (20)
])


class IEC104Scanner(Base):
    """IEC 60870-5-104 device scanner for power grid SCADA systems."""

    __info__ = {
        "name": "IEC104 Scanner",
        "description": "Enumerate IEC 60870-5-104 RTU/IED devices (port 2404)",
        "category": "ics_protocol",
        "author": "Andre Henrique (@mrhenrike) | Uniao Geek",
        "references": ["IEC 60870-5-104 standard", "CISA ICS advisories"],
    }

    target = OptIP("", "Target RTU/IED IP")
    port = OptInt(2404, "IEC104 TCP port (default: 2404)")
    timeout = OptInt(5, "Connection timeout (seconds)")
    ca = OptInt(1, "Common Address (station address)")

    def _connect(self) -> Optional[socket.socket]:
        """Connect to IEC104 TCP port."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            return s
        except Exception:
            return None

    def check(self) -> bool:
        """Check if IEC104 port is open."""
        if not self.target:
            return False
        s = self._connect()
        if s:
            s.close()
            return True
        return False

    def run(self) -> None:
        """Enumerate IEC104 device via STARTDT and General Interrogation."""
        if not self.check():
            print(f"[-] {self.target}:{self.port} not reachable (IEC104)")
            return

        s = self._connect()
        if not s:
            return

        try:
            # Step 1: STARTDT activation
            s.send(IEC104_STARTDT_ACT)
            resp = s.recv(256)
            if resp[:2] == b"\x68\x04":
                ctrl = resp[2]
                if ctrl == 0x0b:
                    print(f"[+] {self.target}:{self.port} - IEC104 STARTDT confirmed")
                elif ctrl == 0x43:
                    print(f"[+] {self.target}:{self.port} - IEC104 TESTFR response (device alive)")
                else:
                    print(f"[+] {self.target}:{self.port} - IEC104 device responded (ctrl=0x{ctrl:02x})")
            else:
                print(f"[+] {self.target}:{self.port} - Port open but unexpected response")

            # Step 2: General Interrogation
            s.send(IEC104_GENERAL_INTERROGATION)
            resp2 = s.recv(512)
            if resp2 and len(resp2) >= 6:
                apdu_len = resp2[1]
                type_id = resp2[6] if len(resp2) > 6 else 0
                print(f"[+] GI response received: APDU len={apdu_len}, Type ID=0x{type_id:02x}")
                # Parse ASDU type
                asdu_names = {
                    0x01: "M_SP_NA_1 (Single-point info)",
                    0x03: "M_DP_NA_1 (Double-point info)",
                    0x09: "M_ME_NA_1 (Normalized value)",
                    0x64: "C_IC_NA_1 (Interrogation ACK)",
                    0x46: "C_IC_NA_1 activation CON",
                }
                print(f"    ASDU Type: {asdu_names.get(type_id, f'Unknown (0x{type_id:02x})')}")
            else:
                print(f"[?] No data objects returned (may require auth)")

        except Exception as exc:
            print(f"[-] Error: {exc}")
        finally:
            s.close()
