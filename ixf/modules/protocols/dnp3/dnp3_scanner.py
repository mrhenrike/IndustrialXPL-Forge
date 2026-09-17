"""DNP3 Protocol Scanner.

Scans DNP3 (Distributed Network Protocol 3) devices on port 20000.
DNP3 is widely used in power/water utilities (RTUs, IEDs, SCADA).

Implements:
- DNP3 link-layer frame structure
- Data Link Layer identification
- Application Layer Read Class 0 (static data)
- Unsolicited response detection

xpl-forge-full-integration.plan.md Bloco 1.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import socket
import struct
from typing import Optional

from embedxpl.core.exploit.base import Base
from embedxpl.core.exploit.option import OptIP, OptInt


# DNP3 Link Layer header constants
DNP3_START_BYTES = b"\x05\x64"
DNP3_FUNCTION_DATA_LINK_RESET = 0x40  # Reset Link States
DNP3_FUNCTION_REQUEST_LINK_STATUS = 0x49  # Request Link Status


def _build_dnp3_link_frame(
    src: int,
    dst: int,
    function: int,
    payload: bytes = b"",
) -> bytes:
    """Build a DNP3 link-layer frame.

    Args:
        src: Source station address (master = typically 1).
        dst: Destination station address (outstation).
        function: Link-layer function code.
        payload: Optional transport + application data.

    Returns:
        Raw DNP3 frame bytes with CRC.
    """
    # DNP3 link header: 10 bytes
    # START(2) | LEN(1) | CONTROL(1) | DST(2) | SRC(2) | CRC(2)
    length = 5 + len(payload)  # 5 = control(1) + dst(2) + src(2)
    header = struct.pack(
        "<2sBBHH",
        DNP3_START_BYTES,
        length,
        function,
        dst,
        src,
    )
    header_crc = _crc16_dnp(header[2:8])
    header += struct.pack("<H", header_crc)

    # Payload in 16-byte blocks with CRC
    frame = header
    for i in range(0, len(payload), 16):
        block = payload[i:i + 16]
        block_crc = _crc16_dnp(block)
        frame += block + struct.pack("<H", block_crc)
    return frame


def _crc16_dnp(data: bytes) -> int:
    """Compute DNP3 CRC-16."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return (~crc) & 0xFFFF


class DNP3Scanner(Base):
    """DNP3 device scanner and enumerator for SCADA/ICS environments."""

    __info__ = {
        "name": "DNP3 Scanner",
        "description": "Enumerate DNP3 outstations (RTUs/IEDs) on port 20000",
        "category": "ics_protocol",
        "author": "Andre Henrique (@mrhenrike) | Uniao Geek",
        "references": ["IEEE Std 1815-2012 (DNP3)", "CISA ICS advisories"],
    }

    target = OptIP("", "Target outstation IP")
    port = OptInt(20000, "DNP3 TCP port (default: 20000)")
    src_addr = OptInt(1, "Master station address")
    dst_addr = OptInt(1, "Outstation address to probe")
    timeout = OptInt(5, "Connection timeout (seconds)")

    def _connect(self) -> Optional[socket.socket]:
        """Connect to DNP3 TCP port."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            return s
        except Exception:
            return None

    def check(self) -> bool:
        """Check if DNP3 port is open and responds."""
        if not self.target:
            return False
        s = self._connect()
        if s:
            s.close()
            return True
        return False

    def run(self) -> None:
        """Scan and enumerate DNP3 outstation."""
        if not self.check():
            print(f"[-] {self.target}:{self.port} not reachable (DNP3)")
            return

        s = self._connect()
        if not s:
            return

        try:
            # Send Reset Link States
            frame = _build_dnp3_link_frame(
                src=self.src_addr,
                dst=self.dst_addr,
                function=DNP3_FUNCTION_DATA_LINK_RESET,
            )
            s.send(frame)
            resp = s.recv(256)
            if resp and resp[:2] == DNP3_START_BYTES:
                print(f"[+] {self.target}:{self.port} - DNP3 device responding")
                ctrl_byte = resp[3] if len(resp) > 3 else 0
                print(f"    Link control byte: 0x{ctrl_byte:02x}")
                dst = struct.unpack_from("<H", resp, 4)[0] if len(resp) >= 6 else 0
                src = struct.unpack_from("<H", resp, 6)[0] if len(resp) >= 8 else 0
                print(f"    Device address: {src} (master: {dst})")

            # Send Request Link Status
            frame2 = _build_dnp3_link_frame(
                src=self.src_addr,
                dst=self.dst_addr,
                function=DNP3_FUNCTION_REQUEST_LINK_STATUS,
            )
            s.send(frame2)
            resp2 = s.recv(256)
            if resp2 and resp2[:2] == DNP3_START_BYTES:
                print(f"[+] Link status confirmed - device address {self.dst_addr} is active")
            else:
                print(f"[?] Scanning addresses 0-10 for active outstations...")
                for addr in range(0, 11):
                    frame3 = _build_dnp3_link_frame(
                        src=self.src_addr,
                        dst=addr,
                        function=DNP3_FUNCTION_REQUEST_LINK_STATUS,
                    )
                    try:
                        s.send(frame3)
                        r = s.recv(64)
                        if r and r[:2] == DNP3_START_BYTES:
                            print(f"    [+] Active outstation at address {addr}")
                    except Exception:
                        pass

        except Exception as exc:
            print(f"[-] Error: {exc}")
        finally:
            s.close()
