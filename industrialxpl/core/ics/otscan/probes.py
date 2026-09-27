"""Per-protocol OT probes — stdlib + optional pymodbus."""

from __future__ import annotations

import socket
import struct
from typing import Any, Callable

ProbeFn = Callable[[str, float], dict[str, Any]]


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def _udp_send(host: str, port: int, payload: bytes, timeout: float) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        return sock.recv(4096)
    except OSError:
        return b""
    finally:
        sock.close()


def probe_modbus(host: str, timeout: float = 3.0) -> dict[str, Any]:
    pdu = struct.pack(">HHHBB", 1, 0, 6, 1, 3) + struct.pack(">HH", 0, 1)
    try:
        s = socket.create_connection((host, 502), timeout=timeout)
        s.sendall(pdu)
        resp = s.recv(256)
        s.close()
        if len(resp) >= 8:
            return {"detected": True, "port": 502, "detail": "Modbus/TCP FC03 ({} B)".format(len(resp))}
    except OSError as exc:
        return {"detected": False, "port": 502, "error": str(exc)}
    return {"detected": False, "port": 502}


def probe_s7(host: str, timeout: float = 3.0) -> dict[str, Any]:
    if not _tcp_open(host, 102, timeout):
        return {"detected": False, "port": 102}
    cotp = bytes([
        0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00,
        0x00, 0x01, 0x00, 0xC1, 0x02, 0x01, 0x00, 0xC2,
        0x02, 0x01, 0x02, 0xC0, 0x01, 0x0A,
    ])
    try:
        s = socket.create_connection((host, 102), timeout=timeout)
        s.sendall(cotp)
        resp = s.recv(128)
        s.close()
        if resp:
            return {"detected": True, "port": 102, "detail": "S7comm COTP ({} B)".format(len(resp))}
    except OSError as exc:
        return {"detected": False, "port": 102, "error": str(exc)}
    return {"detected": False, "port": 102}


def probe_iec104(host: str, timeout: float = 3.0) -> dict[str, Any]:
    # STARTDT act
    startdt = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])
    try:
        s = socket.create_connection((host, 2404), timeout=timeout)
        s.sendall(startdt)
        resp = s.recv(64)
        s.close()
        if resp and resp[0] == 0x68:
            return {"detected": True, "port": 2404, "detail": "IEC-104 STARTDT ack"}
    except OSError as exc:
        return {"detected": False, "port": 2404, "error": str(exc)}
    return {"detected": False, "port": 2404}


def probe_bacnet(host: str, timeout: float = 3.0) -> dict[str, Any]:
    whois = bytes([0x81, 0x0B, 0x00, 0x0C, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08])
    resp = _udp_send(host, 47808, whois, timeout)
    if resp:
        return {"detected": True, "port": 47808, "detail": "BACnet/IP Who-Is ({} B)".format(len(resp))}
    return {"detected": False, "port": 47808}


def probe_dnp3(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = _tcp_open(host, 20000, timeout)
    return {"detected": ok, "port": 20000, "detail": "DNP3 TCP open" if ok else "closed"}


def probe_opcua(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = _tcp_open(host, 4840, timeout)
    return {"detected": ok, "port": 4840, "detail": "OPC UA TCP" if ok else "closed"}


def probe_enip(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = _tcp_open(host, 44818, timeout)
    return {"detected": ok, "port": 44818, "detail": "EtherNet/IP" if ok else "closed"}


def probe_fox(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = _tcp_open(host, 1911, timeout)
    return {"detected": ok, "port": 1911, "detail": "Niagara Fox" if ok else "closed"}


def probe_fins(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = _udp_send(host, 9600, b"\x80\x00\x02\x00", timeout) != b""
    return {"detected": ok, "port": 9600, "detail": "Omron FINS UDP" if ok else "no response"}


def probe_codesys(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = _tcp_open(host, 11740, timeout)
    return {"detected": ok, "port": 11740, "detail": "CODESYS" if ok else "closed"}


def probe_hart_ip(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = _udp_send(host, 5094, b"\x00", timeout) != b""
    return {"detected": ok, "port": 5094, "detail": "HART-IP UDP" if ok else "no response"}


def probe_mqtt(host: str, timeout: float = 3.0) -> dict[str, Any]:
    ok = _tcp_open(host, 1883, timeout)
    return {"detected": ok, "port": 1883, "detail": "MQTT" if ok else "closed"}


def probe_profinet(host: str, timeout: float = 3.0) -> dict[str, Any]:
    dcp = bytes([0xFE, 0xFD, 0x82, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00])
    resp = _udp_send(host, 34962, dcp, timeout)
    if resp:
        return {"detected": True, "port": 34962, "detail": "Profinet DCP ({} B)".format(len(resp))}
    return {"detected": False, "port": 34962}


PROBE_MAP: dict[str, ProbeFn] = {
    "modbus": probe_modbus,
    "s7": probe_s7,
    "iec104": probe_iec104,
    "bacnet": probe_bacnet,
    "dnp3": probe_dnp3,
    "opc-ua": probe_opcua,
    "opcua": probe_opcua,
    "enip": probe_enip,
    "ethernetip": probe_enip,
    "fox": probe_fox,
    "fins": probe_fins,
    "codesys": probe_codesys,
    "hart-ip": probe_hart_ip,
    "hartip": probe_hart_ip,
    "mqtt": probe_mqtt,
    "profinet": probe_profinet,
}
