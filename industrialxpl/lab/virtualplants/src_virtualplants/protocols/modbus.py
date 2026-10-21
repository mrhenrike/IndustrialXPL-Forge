"""Modbus TCP lab server: coils, discrete inputs, input and holding registers.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ..core.events import PlantEvent
from ..core.safety import ResourceLimits, clamp_limits
from ..core.telemetry import TelemetryBus


LOGGER = logging.getLogger("virtualplants.modbus")

FC_READ_COILS = 1
FC_READ_DISCRETE = 2
FC_READ_HOLDING = 3
FC_READ_INPUT = 4
FC_WRITE_SINGLE_COIL = 5
FC_WRITE_SINGLE_REGISTER = 6
FC_WRITE_MULTI_COILS = 15
FC_WRITE_MULTI_REGISTERS = 16
FC_ENCAPSULATED_INTERFACE = 43
MEI_READ_DEVICE_ID = 14

EX_ILLEGAL_FUNCTION = 1
EX_ILLEGAL_ADDRESS = 2
EX_ILLEGAL_VALUE = 3
EX_DEVICE_FAILURE = 4
EX_SERVER_BUSY = 6


WriteHook = Callable[[str, int, int, str], None]


@dataclass
class DeviceIdentity:
    """Modbus FC43 / MEI 14 objects."""

    vendor_name: str = "Uniao Geek"
    product_code: str = "VP-PLC"
    major_minor_revision: str = "1.1.0"
    vendor_url: str = "https://uniaogeek.com.br/"
    product_name: str = "VirtualPlants Soft PLC"
    model_name: str = "VP-GENERIC"


@dataclass
class ModbusMemory:
    """Four Modbus data areas."""

    coils: List[int] = field(default_factory=lambda: [0] * 64)
    discrete_inputs: List[int] = field(default_factory=lambda: [0] * 64)
    input_registers: List[int] = field(default_factory=lambda: [0] * 64)
    holding_registers: List[int] = field(default_factory=lambda: [0] * 64)

    def snapshot(self) -> Dict[str, List[int]]:
        """Return copies of all areas."""
        return {
            "coils": list(self.coils),
            "discrete_inputs": list(self.discrete_inputs),
            "input_registers": list(self.input_registers),
            "holding_registers": list(self.holding_registers),
        }

    def restore(self, payload: Dict[str, List[int]]) -> None:
        """Restore areas from a snapshot payload."""
        self.coils = list(payload.get("coils") or self.coils)
        self.discrete_inputs = list(payload.get("discrete_inputs") or self.discrete_inputs)
        self.input_registers = list(payload.get("input_registers") or self.input_registers)
        self.holding_registers = list(payload.get("holding_registers") or self.holding_registers)


def _bits_to_bytes(bits: Sequence[int]) -> bytes:
    """Pack coil/DI bits into Modbus byte order."""
    out = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        if int(bit):
            out[index // 8] |= 1 << (index % 8)
    return bytes(out)


def _bytes_to_bits(data: bytes, count: int) -> List[int]:
    """Unpack coil write payload."""
    bits: List[int] = []
    for index in range(count):
        byte = data[index // 8] if index // 8 < len(data) else 0
        bits.append(1 if byte & (1 << (index % 8)) else 0)
    return bits


def _exception(function_code: int, code: int) -> bytes:
    """Build a Modbus exception PDU."""
    return bytes((function_code | 0x80, code))


def handle_pdu(
    memory: ModbusMemory,
    pdu: bytes,
    identity: DeviceIdentity,
    *,
    max_quantity_registers: int = 125,
    max_quantity_bits: int = 2000,
    writable_holding: bool = True,
    writable_coils: bool = True,
    on_write: Optional[WriteHook] = None,
    peer: str = "unknown",
) -> bytes:
    """Dispatch one Modbus PDU against lab memory."""
    if not pdu:
        return _exception(0, EX_ILLEGAL_FUNCTION)
    function_code = pdu[0]
    try:
        if function_code in (FC_READ_COILS, FC_READ_DISCRETE, FC_READ_HOLDING, FC_READ_INPUT):
            if len(pdu) < 5:
                return _exception(function_code, EX_ILLEGAL_VALUE)
            address, quantity = struct.unpack(">HH", pdu[1:5])
            if function_code in (FC_READ_COILS, FC_READ_DISCRETE):
                area = memory.coils if function_code == FC_READ_COILS else memory.discrete_inputs
                if quantity < 1 or quantity > max_quantity_bits:
                    return _exception(function_code, EX_ILLEGAL_VALUE)
                if address + quantity > len(area):
                    return _exception(function_code, EX_ILLEGAL_ADDRESS)
                packed = _bits_to_bytes(area[address : address + quantity])
                return bytes((function_code, len(packed))) + packed
            area = memory.holding_registers if function_code == FC_READ_HOLDING else memory.input_registers
            if quantity < 1 or quantity > max_quantity_registers:
                return _exception(function_code, EX_ILLEGAL_VALUE)
            if address + quantity > len(area):
                return _exception(function_code, EX_ILLEGAL_ADDRESS)
            body = b"".join(struct.pack(">H", int(value) & 0xFFFF) for value in area[address : address + quantity])
            return bytes((function_code, len(body))) + body

        if function_code == FC_WRITE_SINGLE_COIL:
            if not writable_coils:
                return _exception(function_code, EX_ILLEGAL_FUNCTION)
            if len(pdu) < 5:
                return _exception(function_code, EX_ILLEGAL_VALUE)
            address, raw = struct.unpack(">HH", pdu[1:5])
            if raw not in (0x0000, 0xFF00):
                return _exception(function_code, EX_ILLEGAL_VALUE)
            if address >= len(memory.coils):
                return _exception(function_code, EX_ILLEGAL_ADDRESS)
            bit = 1 if raw == 0xFF00 else 0
            memory.coils[address] = bit
            if on_write:
                on_write("coil", address, bit, peer)
            return pdu[:5]

        if function_code == FC_WRITE_SINGLE_REGISTER:
            if not writable_holding:
                return _exception(function_code, EX_ILLEGAL_FUNCTION)
            if len(pdu) < 5:
                return _exception(function_code, EX_ILLEGAL_VALUE)
            address, value = struct.unpack(">HH", pdu[1:5])
            if address >= len(memory.holding_registers):
                return _exception(function_code, EX_ILLEGAL_ADDRESS)
            memory.holding_registers[address] = value
            if on_write:
                on_write("holding_register", address, value, peer)
            return pdu[:5]

        if function_code == FC_WRITE_MULTI_COILS:
            if not writable_coils:
                return _exception(function_code, EX_ILLEGAL_FUNCTION)
            if len(pdu) < 6:
                return _exception(function_code, EX_ILLEGAL_VALUE)
            address, quantity = struct.unpack(">HH", pdu[1:5])
            byte_count = pdu[5]
            data = pdu[6 : 6 + byte_count]
            if quantity < 1 or quantity > max_quantity_bits or len(data) != byte_count:
                return _exception(function_code, EX_ILLEGAL_VALUE)
            if address + quantity > len(memory.coils):
                return _exception(function_code, EX_ILLEGAL_ADDRESS)
            bits = _bytes_to_bits(data, quantity)
            for offset, bit in enumerate(bits):
                memory.coils[address + offset] = bit
                if on_write:
                    on_write("coil", address + offset, bit, peer)
            return bytes((function_code,)) + struct.pack(">HH", address, quantity)

        if function_code == FC_WRITE_MULTI_REGISTERS:
            if not writable_holding:
                return _exception(function_code, EX_ILLEGAL_FUNCTION)
            if len(pdu) < 6:
                return _exception(function_code, EX_ILLEGAL_VALUE)
            address, quantity = struct.unpack(">HH", pdu[1:5])
            byte_count = pdu[5]
            data = pdu[6 : 6 + byte_count]
            if quantity < 1 or quantity > max_quantity_registers or byte_count != quantity * 2 or len(data) != byte_count:
                return _exception(function_code, EX_ILLEGAL_VALUE)
            if address + quantity > len(memory.holding_registers):
                return _exception(function_code, EX_ILLEGAL_ADDRESS)
            for offset in range(quantity):
                value = struct.unpack(">H", data[offset * 2 : offset * 2 + 2])[0]
                memory.holding_registers[address + offset] = value
                if on_write:
                    on_write("holding_register", address + offset, value, peer)
            return bytes((function_code,)) + struct.pack(">HH", address, quantity)

        if function_code == FC_ENCAPSULATED_INTERFACE:
            if len(pdu) < 4 or pdu[1] != MEI_READ_DEVICE_ID:
                return _exception(function_code, EX_ILLEGAL_FUNCTION)
            objects = (
                (0x00, identity.vendor_name),
                (0x01, identity.product_code),
                (0x02, identity.major_minor_revision),
                (0x03, identity.vendor_url),
                (0x04, identity.product_name),
                (0x05, identity.model_name),
            )
            body = bytearray()
            body.append(function_code)
            body.append(MEI_READ_DEVICE_ID)
            body.append(0x01)  # read device id code echo
            body.append(0x01)  # conformity
            body.append(0x00)  # more follows
            body.append(0x00)  # next object id
            body.append(len(objects))
            for obj_id, text in objects:
                encoded = text.encode("ascii", errors="replace")[:50]
                body.append(obj_id)
                body.append(len(encoded))
                body.extend(encoded)
            return bytes(body)
    except (struct.error, IndexError, ValueError):
        return _exception(function_code, EX_ILLEGAL_VALUE)
    return _exception(function_code, EX_ILLEGAL_FUNCTION)


class ModbusTcpLabServer:
    """Asyncio Modbus TCP server with connection and rate limits."""

    def __init__(
        self,
        host: str,
        port: int,
        memory: Optional[ModbusMemory] = None,
        identity: Optional[DeviceIdentity] = None,
        limits: Optional[ResourceLimits] = None,
        telemetry: Optional[TelemetryBus] = None,
        scenario_id: str = "",
        unit_id: int = 1,
        writable_holding: bool = True,
        writable_coils: bool = True,
        allow_unspecified_unit: bool = True,
        ip_allowlist: Optional[Sequence[str]] = None,
    ) -> None:
        """Configure bind address and memory image."""
        self.host = host
        self.port = int(port)
        self.memory = memory or ModbusMemory()
        self.identity = identity or DeviceIdentity()
        self.limits = clamp_limits(limits or ResourceLimits())
        self.telemetry = telemetry
        self.scenario_id = scenario_id
        self.unit_id = int(unit_id)
        self.writable_holding = writable_holding
        self.writable_coils = writable_coils
        self.allow_unspecified_unit = allow_unspecified_unit
        self.ip_allowlist = tuple(ip_allowlist or ())
        self._server: Optional[asyncio.AbstractServer] = None
        self._clients: set[asyncio.StreamWriter] = set()
        self._hits: List[float] = []
        self.rejected_connections = 0
        self.accepted_connections = 0

    def _emit(self, event_type: str, message: str, **details: object) -> None:
        """Publish protocol telemetry when a bus is attached."""
        if self.telemetry is None:
            return
        self.telemetry.emit(
            PlantEvent(
                event_type=event_type,
                source="modbus-tcp",
                message=message,
                scenario_id=self.scenario_id or None,
                details=details,
            )
        )

    def _rate_ok(self) -> bool:
        """Token-bucket style per-second cap."""
        now = time.monotonic()
        self._hits = [stamp for stamp in self._hits if now - stamp < 1.0]
        if len(self._hits) >= self.limits.rate_per_second:
            return False
        self._hits.append(now)
        return True

    def _peer_allowed(self, peer: str) -> bool:
        """Optional source IP filter used by patched profiles."""
        if not self.ip_allowlist:
            return True
        host = peer.split("%", 1)[0]
        if host.lower().startswith("::ffff:"):
            host = host.split(":", 6)[-1]
        return host in self.ip_allowlist or host in {"127.0.0.1", "::1"}

    def _on_write(self, area: str, address: int, value: int, peer: str) -> None:
        """Forward writes to telemetry."""
        self._emit(
            "modbus_write",
            "Modbus write %s[%s]=%s" % (area, address, value),
            area=area,
            address=address,
            value=value,
            peer=peer,
        )

    async def start(self) -> None:
        """Bind TCP listener."""
        self._server = await asyncio.start_server(
            self._handle,
            host=self.host,
            port=self.port,
            reuse_address=True,
        )
        sockets = self._server.sockets or []
        bound = sockets[0].getsockname() if sockets else (self.host, self.port)
        LOGGER.info("Modbus TCP lab server on %s:%s", bound[0], bound[1])
        self._emit("service_start", "Modbus TCP started", host=bound[0], port=bound[1])

    async def serve_forever(self) -> None:
        """Run until cancelled."""
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        """Close listener and clients."""
        for writer in list(self._clients):
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        self._clients.clear()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Serve one TCP client with connection quotas."""
        peer_tuple = writer.get_extra_info("peername") or ("unknown", 0)
        peer = str(peer_tuple[0])
        if not self._peer_allowed(peer):
            self.rejected_connections += 1
            self._emit("connection_denied", "source IP filtered", peer=peer)
            writer.close()
            return
        if len(self._clients) >= self.limits.max_connections:
            self.rejected_connections += 1
            self._emit("connection_exhausted", "connection quota reached", peer=peer)
            writer.close()
            return
        self._clients.add(writer)
        self.accepted_connections += 1
        self._emit("connection_open", "Modbus client connected", peer=peer)
        try:
            while True:
                header = await asyncio.wait_for(
                    reader.readexactly(7),
                    timeout=self.limits.request_timeout_seconds,
                )
                _tid, protocol, length, unit = struct.unpack(">HHHB", header)
                if protocol != 0 or length < 1 or length > self.limits.max_message_bytes:
                    break
                pdu = await asyncio.wait_for(
                    reader.readexactly(length - 1),
                    timeout=self.limits.request_timeout_seconds,
                )
                if not self._rate_ok():
                    response_pdu = _exception(pdu[0] if pdu else 0, EX_SERVER_BUSY)
                elif unit not in (self.unit_id, 0, 255) and not self.allow_unspecified_unit:
                    response_pdu = _exception(pdu[0] if pdu else 0, EX_DEVICE_FAILURE)
                else:
                    response_pdu = handle_pdu(
                        self.memory,
                        pdu,
                        self.identity,
                        writable_holding=self.writable_holding,
                        writable_coils=self.writable_coils,
                        on_write=self._on_write,
                        peer=peer,
                    )
                mbap = struct.pack(">HHHB", _tid, 0, len(response_pdu) + 1, unit)
                writer.write(mbap + response_pdu)
                await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            self._clients.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._emit("connection_close", "Modbus client disconnected", peer=peer)

    @property
    def bound_port(self) -> int:
        """Actual listening port after ephemeral bind."""
        if self._server and self._server.sockets:
            return int(self._server.sockets[0].getsockname()[1])
        return self.port
