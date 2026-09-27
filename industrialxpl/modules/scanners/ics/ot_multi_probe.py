# Author: André Henrique (@mrhenrike) | Uniao Geek
"""OT Multi-Protocol Probe — lightweight discovery across Modbus, DNP3, BACnet, S7, ENIP.

Uses minimal protocol handshakes to detect OT services on a target host.
Respects global setg PORT / TRANSPORT / UNIT_ID when loaded after setg.

Version: 1.0.0
"""

from __future__ import annotations

import struct
from typing import Callable, Dict, List, Optional, Tuple

from industrialxpl.core.exploit import *
from industrialxpl.core.exploit.exploit import BaseExploit
from industrialxpl.core.network.transport import (
    DEFAULT_OT_PORTS,
    connect_tcp,
    connect_udp,
    probe_tcp,
    probe_udp,
    resolve_transports,
)

_PROTOCOLS = ("modbus", "dnp3", "bacnet", "s7", "enip", "opcua")

# DNP3 Link Status (precomputed CRC)
_DNP3_LINK_STATUS = bytes([
    0x05, 0x64, 0x05, 0xC9, 0x00, 0x00, 0x01, 0x00, 0xCC, 0x5D,
])

# S7comm COTP Connection Request (minimal)
_S7_COTP_CR = bytes([
    0x03, 0x00, 0x00, 0x16,
    0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC0,
    0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02,
])

# EtherNet/IP List Identity (Encapsulation 0x0063)
_ENIP_LIST_ID = bytes([
    0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])


class Exploit(BaseExploit):
    """OT Multi-Protocol Probe — discover Modbus, DNP3, BACnet, S7, ENIP, OPC-UA."""

    __info__ = {
        "name": "OT Multi-Protocol Probe",
        "description": (
            "Lightweight OT service discovery using minimal protocol probes. "
            "Select protocol=all or a single protocol (modbus, dnp3, bacnet, s7, enip, opcua). "
            "Honors setg PORT, TRANSPORT, and UNIT_ID."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://attack.mitre.org/techniques/T0846/",
            "https://csrc.nist.gov/pubs/sp/800/82/r3/final",
        ),
        "devices": ("PLC", "RTU", "IED", "Gateway", "Any OT/ICS endpoint"),
        "mitre_techniques": ["T0846", "T0888"],
        "severity": "INFO",
    }

    target = OptIP("", "Target IPv4 or hostname")
    protocol = OptString(
        "all",
        "Protocol: all | modbus | dnp3 | bacnet | s7 | enip | opcua",
    )
    port = OptString("", "Override port (empty = well-known port per protocol)")
    transport = OptTransport("both", "Transport: tcp | udp | both")
    unit_id = OptInteger(1, "Modbus unit ID (0-255)")
    timeout = OptInteger(5, "Socket timeout in seconds")
    simulate = OptBool(False, "Simulate only (no protocol PDU on wire)")

    def _resolve_port(self, proto: str) -> int:
        if self.port and str(self.port).strip():
            expr = str(self.port).strip()
            if expr.isdigit():
                return int(expr)
            from industrialxpl.core.modbus.transport import parse_port_expression
            ports = parse_port_expression(expr)
            return ports[0]
        return DEFAULT_OT_PORTS.get(proto, 502)

    def _selected_protocols(self) -> List[str]:
        p = str(self.protocol).lower().strip()
        if p in ("all", "*"):
            return list(_PROTOCOLS)
        if p not in _PROTOCOLS:
            raise ValueError(
                "protocol must be all or one of: {}".format(", ".join(_PROTOCOLS))
            )
        return [p]

    def _modbus_pdu(self) -> bytes:
        # FC04 read 1 input register @ addr 0
        pdu = struct.pack(">BHH", 0x04, 0, 1)
        mbap = struct.pack(">HHHB", 1, 0, len(pdu) + 1, int(self.unit_id) & 0xFF)
        return mbap + pdu

    def _bacnet_whois(self) -> bytes:
        return struct.pack(">BBH", 0x81, 0x0A, 12) + b"\x01\x20\xff\xff\x00\xff\x10\x08"

    def _opcua_hello(self) -> bytes:
        # OPC UA Hello message (minimal)
        endpoint = "opc.tcp://{}:{}".format(self.target, self._resolve_port("opcua"))
        ep_bytes = endpoint.encode("utf-8")
        body = struct.pack("<I", 0)  # protocol version
        body += struct.pack("<I", 65536)  # receive buffer
        body += struct.pack("<I", 65536)  # send buffer
        body += struct.pack("<I", 0)  # max message size
        body += struct.pack("<I", 0)  # max chunk count
        body += struct.pack("<I", len(ep_bytes))
        body += ep_bytes
        hdr = b"HELF" + struct.pack("<I", len(body))
        return hdr + body

    def _probe_modbus(self) -> Optional[str]:
        port = self._resolve_port("modbus")
        if self.simulate:
            return "port open (simulate)" if connect_tcp(
                self.target, port, float(self.timeout)
            ) else None
        resp = probe_tcp(self.target, port, self._modbus_pdu(), float(self.timeout))
        if not resp or len(resp) < 8:
            return None
        if resp[7] == 0x84:
            return "Modbus exception response"
        if resp[7] == 0x04:
            return "Modbus/TCP FC04 response ({} bytes)".format(len(resp))
        return "Modbus/TCP active (FC=0x{:02X})".format(resp[7])

    def _probe_dnp3(self) -> Optional[str]:
        port = self._resolve_port("dnp3")
        mode = str(self.transport).lower()
        if mode == "udp":
            transports = [("UDP", True)]
        elif mode == "tcp":
            transports = [("TCP", False)]
        else:
            transports = resolve_transports("both")

        for label, udp in transports:
            if self.simulate:
                ok = connect_udp if udp else connect_tcp
                if ok(self.target, port, float(self.timeout)):
                    return "{} port open (simulate)".format(label)
                continue
            fn = probe_udp if udp else probe_tcp
            resp = fn(self.target, port, _DNP3_LINK_STATUS, float(self.timeout))
            if resp and len(resp) >= 5 and resp[0] == 0x05 and resp[1] == 0x64:
                return "DNP3 link response on {}/{}".format(port, label)
        return None

    def _probe_bacnet(self) -> Optional[str]:
        port = self._resolve_port("bacnet")
        if self.simulate:
            return "UDP reachable (simulate)" if connect_udp(
                self.target, port, float(self.timeout)
            ) else None
        resp = probe_udp(self.target, port, self._bacnet_whois(), float(self.timeout))
        if resp and len(resp) >= 6 and resp[0] == 0x81:
            return "BACnet/IP response ({} bytes)".format(len(resp))
        return None

    def _probe_s7(self) -> Optional[str]:
        port = self._resolve_port("s7")
        if self.simulate:
            return "port open (simulate)" if connect_tcp(
                self.target, port, float(self.timeout)
            ) else None
        resp = probe_tcp(self.target, port, _S7_COTP_CR, float(self.timeout))
        if resp and len(resp) >= 7 and resp[5] == 0xD0:
            return "S7comm COTP connection confirm"
        if resp:
            return "TCP response on S7 port ({} bytes)".format(len(resp))
        return None

    def _probe_enip(self) -> Optional[str]:
        port = self._resolve_port("enip")
        if self.simulate:
            return "port open (simulate)" if connect_tcp(
                self.target, port, float(self.timeout)
            ) else None
        resp = probe_tcp(self.target, port, _ENIP_LIST_ID, float(self.timeout))
        if resp and len(resp) >= 24:
            status = struct.unpack_from("<I", resp, 8)[0]
            if status == 0:
                return "EtherNet/IP List Identity response"
            return "EtherNet/IP encapsulation reply (status={})".format(status)
        return None

    def _probe_opcua(self) -> Optional[str]:
        port = self._resolve_port("opcua")
        if self.simulate:
            return "port open (simulate)" if connect_tcp(
                self.target, port, float(self.timeout)
            ) else None
        resp = probe_tcp(self.target, port, self._opcua_hello(), float(self.timeout))
        if resp and resp[:4] in (b"ACKF", b"ERRF"):
            return "OPC UA {} handshake".format(resp[:4].decode("ascii", errors="replace"))
        return None

    def run(self) -> None:
        if not self.target:
            print_error("Set 'target' option first.")
            return

        try:
            protos = self._selected_protocols()
        except ValueError as exc:
            print_error(str(exc))
            return

        probes: Dict[str, Callable[[], Optional[str]]] = {
            "modbus": self._probe_modbus,
            "dnp3": self._probe_dnp3,
            "bacnet": self._probe_bacnet,
            "s7": self._probe_s7,
            "enip": self._probe_enip,
            "opcua": self._probe_opcua,
        }

        print_info("Target   : {}".format(self.target))
        print_info("Protocol : {}".format(", ".join(protos)))
        if self.port:
            print_info("Port     : {} (override)".format(self.port))
        print_info("Transport: {}".format(self.transport))
        print_info("Simulate : {}".format(self.simulate))
        print_info("")

        hits = 0
        for name in protos:
            default_port = self._resolve_port(name)
            print_status("[{}] probing port {}...".format(name.upper(), default_port))
            try:
                detail = probes[name]()
            except Exception as exc:
                print_error("[{}] probe error: {}".format(name.upper(), exc))
                continue
            if detail:
                print_success("[{}] {}".format(name.upper(), detail))
                hits += 1
            else:
                print_info("[{}] no response".format(name.upper()))

        print_info("")
        if hits:
            print_success("Detected {} protocol(s) on {}".format(hits, self.target))
        else:
            print_warning("No OT protocol responses from {}".format(self.target))

    @mute
    def check(self) -> bool:
        if not self.target:
            return False
        try:
            protos = self._selected_protocols()
        except ValueError:
            return False
        probes = {
            "modbus": self._probe_modbus,
            "dnp3": self._probe_dnp3,
            "bacnet": self._probe_bacnet,
            "s7": self._probe_s7,
            "enip": self._probe_enip,
            "opcua": self._probe_opcua,
        }
        for name in protos:
            if probes[name]():
                return True
        return False
