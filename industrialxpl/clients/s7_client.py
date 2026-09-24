"""
industrialxpl/clients/s7_client.py - Native S7 PLC client.

Wraps CotpConnection + S7comm protocol to provide a high-level API
for communicating with Siemens S7-300/400/1200/1500 PLCs.
No python-snap7, no Scapy, no external library required.

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from industrialxpl.protocols.cotp import CotpConnection, TSAP_PG, TSAP_DST_S7_300
from industrialxpl.protocols.s7comm import (
    S7Response,
    build_setup_comm,
    build_read_szl,
    build_cpu_stop,
    build_cpu_start,
    build_read_area,
    parse_s7_header,
    parse_szl_response,
    SZL_MODULE_ID,
    SZL_COMPONENT_ID,
    AREA_CODE,
)

__version__ = "1.0.0"


@dataclass
class S7ConnectionInfo:
    """Information discovered about a connected PLC."""
    host: str
    port: int
    connected: bool = False
    s7comm_session: bool = False
    pdu_size: int = 480
    cpu_state: str = "unknown"
    module_info: Dict[str, str] = field(default_factory=dict)
    risk_findings: List[Dict[str, str]] = field(default_factory=list)
    error: str = ""


class S7Client:
    """Native S7 PLC client for Siemens S7-300/400/1200/1500.

    Establishes COTP/S7comm session and provides:
    - Session negotiation
    - SZL read (module identification, CPU state)
    - Area read/write (DB, I, Q, M)
    - CPU control (stop/start) - requires destructive=True

    Usage:
        client = S7Client("192.168.0.1")
        if client.connect():
            info = client.get_module_info()
            state = client.get_cpu_state()
            regs = client.read_area("DB", db_number=1, start=0, length=10)
            client.disconnect()
    """

    def __init__(
        self,
        host: str,
        port: int = 102,
        timeout: float = 5.0,
        rack: int = 0,
        slot: int = 1,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.rack = rack
        self.slot = slot
        # Compute TSAP from rack/slot: 0x03, rack*0x20+slot
        dst_tsap = bytes([0x03, rack * 0x20 + slot])
        self._conn = CotpConnection(
            host=host,
            port=port,
            timeout=timeout,
            src_tsap=TSAP_PG,
            dst_tsap=dst_tsap,
        )
        self._info = S7ConnectionInfo(host=host, port=port)

    def connect(self) -> bool:
        """Establish COTP + S7comm session."""
        if not self._conn.connect():
            self._info.error = f"COTP connection failed to {self.host}:{self.port}"
            return False

        self._info.connected = True

        # Negotiate S7comm session (setup communication)
        self._conn.send(build_setup_comm())
        resp = self._conn.recv()
        if not resp:
            self._info.error = "S7comm setup failed - no response"
            return False

        hdr = parse_s7_header(resp)
        if hdr is None:
            self._info.error = "S7comm setup failed - invalid PDU"
            return False

        self._info.s7comm_session = True
        self._info.risk_findings.append({
            "severity": "HIGH",
            "finding": "S7comm session established without authentication",
            "detail": f"TCP {self.host}:{self.port} accepted COTP+S7 without credentials",
            "mitre": "T0846 Remote System Discovery",
        })
        return True

    def disconnect(self) -> None:
        """Close connection."""
        self._conn.disconnect()
        self._info.connected = False
        self._info.s7comm_session = False

    def get_module_info(self) -> Dict[str, str]:
        """Read SZL 0x0011 - Module Identification."""
        if not self._info.s7comm_session:
            return {}
        self._conn.send(build_read_szl(SZL_MODULE_ID))
        resp = self._conn.recv()
        if not resp:
            return {}
        info = parse_szl_response(resp)
        if info:
            self._info.module_info.update(info)
            self._info.risk_findings.append({
                "severity": "MEDIUM",
                "finding": "Module identification readable without authentication",
                "detail": f"SZL 0x0011: {info}",
                "mitre": "T0845 Program Upload / T0843 POU Discovery",
            })
        return info

    def get_component_info(self) -> Dict[str, str]:
        """Read SZL 0x001C - Component Identification."""
        if not self._info.s7comm_session:
            return {}
        self._conn.send(build_read_szl(SZL_COMPONENT_ID))
        resp = self._conn.recv()
        if not resp:
            return {}
        return parse_szl_response(resp)

    def get_cpu_state(self) -> str:
        """Return CPU operational state (RUN/STOP/HOLD/unknown)."""
        info = self.get_module_info()
        state = info.get("cpu_state", "unknown (comm established)")
        self._info.cpu_state = state
        return state

    def read_area(
        self,
        area: str,
        db_number: int = 0,
        start: int = 0,
        length: int = 1,
        transport_size: int = 0x04,
    ) -> Optional[bytes]:
        """Read data from PLC area (DB, I, Q, M).

        Args:
            area: Area name - "DB", "I", "Q", "M", "P", "Counter", "Timer".
            db_number: DB number (only for area="DB").
            start: Byte offset in area.
            length: Number of words to read.
            transport_size: S7 transport size code (0x04=WORD, 0x02=BYTE).

        Returns:
            Raw bytes from area, or None on error.
        """
        if not self._info.s7comm_session:
            return None
        area_code = AREA_CODE.get(area.upper())
        if area_code is None:
            return None

        frame = build_read_area(
            area=area_code,
            db_number=db_number,
            start=start * 8,  # convert byte offset to bit offset
            length=length,
            transport_size=transport_size,
        )
        self._conn.send(frame)
        resp = self._conn.recv()
        if not resp or len(resp) < 12:
            return None

        # Data starts after S7 header (12 bytes) + param + data header
        hdr = parse_s7_header(resp)
        if hdr is None:
            return None

        # Extract data section
        data_offset = 12  # AckData header
        if hdr.pdu_type == 0x03 and len(resp) > data_offset:
            # data section: return_code(1) transport_size(1) length(2) + data
            data_section = resp[data_offset + hdr.param_length:]
            if len(data_section) >= 4:
                return data_section[4:]  # skip return_code + size + length

        return None

    def cpu_stop(self, destructive: bool = False) -> S7Response:
        """Stop the PLC CPU (destructive operation).

        Requires destructive=True to execute. Simulates by default.
        """
        if not destructive:
            return S7Response(
                success=False,
                function="PLCStop",
                error="Simulate mode: set destructive=True to execute CPU stop",
            )
        if not self._info.s7comm_session:
            return S7Response(success=False, function="PLCStop", error="Not connected")
        self._conn.send(build_cpu_stop())
        resp = self._conn.recv()
        hdr = parse_s7_header(resp) if resp else None
        if hdr and hdr.error_class == 0:
            return S7Response(success=True, function="PLCStop", data=resp)
        return S7Response(success=False, function="PLCStop", error="Stop command failed or no response")

    def cpu_start(self, destructive: bool = False) -> S7Response:
        """Hot-restart the PLC CPU (destructive operation).

        Requires destructive=True to execute.
        """
        if not destructive:
            return S7Response(
                success=False,
                function="PLCStart",
                error="Simulate mode: set destructive=True to execute CPU start",
            )
        if not self._info.s7comm_session:
            return S7Response(success=False, function="PLCStart", error="Not connected")
        self._conn.send(build_cpu_start())
        resp = self._conn.recv()
        hdr = parse_s7_header(resp) if resp else None
        if hdr and hdr.error_class == 0:
            return S7Response(success=True, function="PLCStart", data=resp)
        return S7Response(success=False, function="PLCStart", error="Start command failed or no response")

    @property
    def info(self) -> S7ConnectionInfo:
        """Return discovered connection information."""
        return self._info
