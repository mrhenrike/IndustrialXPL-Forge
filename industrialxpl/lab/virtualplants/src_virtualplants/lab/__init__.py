"""Lab pairing targets: Delta DVP-class Modbus, FUXA HTTP, IEC and OPC UA emulators.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import asyncio
import posixpath
from typing import Dict, Optional, Tuple
from urllib.parse import unquote

from ..core.events import PlantEvent
from ..core.safety import ResourceLimits
from ..core.snapshots import SnapshotStore
from ..core.telemetry import TelemetryBus
from ..protocols.modbus import DeviceIdentity, ModbusMemory, ModbusTcpLabServer


FUXA_USERS_JSON = b'[{"id":1,"username":"operator","role":"admin"}]\n'
FUXA_ROLES_JSON = b'[{"id":1,"name":"admin"}]\n'

MALFORMED_MMS = b"VP-LAB-MMS-MALFORMED-INIT"
MALFORMED_IEC104 = b"VP-LAB-IEC104-INFLATED-VSQ"
MALFORMED_OPCUA = b"VP-LAB-OPCUA-TRANSFER-SUBS"


class DeltaDvpTarget:
    """Protocol-level stand-in for Delta DVP12SE Modbus posture.

    Vulnerable: unauthenticated writes, high connection ceiling.
    Patched: source allowlist plus tight connection and rate limits.
    This is process/protocol emulation, not vendor firmware.
    """

    def __init__(
        self,
        host: str,
        port: int,
        patched: bool,
        telemetry: Optional[TelemetryBus] = None,
        scenario_id: str = "",
        limits: Optional[ResourceLimits] = None,
    ) -> None:
        """Configure memory map and limits for the selected profile."""
        self.patched = patched
        self.snapshots = SnapshotStore()
        memory = ModbusMemory(
            coils=[0] * 128,
            discrete_inputs=[0] * 128,
            input_registers=[0] * 128,
            holding_registers=[0] * 128,
        )
        memory.holding_registers[0] = 1  # run
        identity = DeviceIdentity(
            vendor_name="VirtualPlants Lab",
            product_code="DVP12SE-EMUL",
            major_minor_revision="lab-1.1.0",
            product_name="Delta-class PLC emulator",
            model_name="DVP12SE-LAB",
        )
        if limits is None:
            if patched:
                limits = ResourceLimits(max_connections=4, rate_per_second=8, request_timeout_seconds=3.0)
            else:
                limits = ResourceLimits(max_connections=128, rate_per_second=80)
        if patched:
            allow = (host,) if host not in {"0.0.0.0", "::"} else ("127.0.0.1", "::1")
        else:
            allow = ()
        self.server = ModbusTcpLabServer(
            host=host,
            port=port,
            memory=memory,
            identity=identity,
            limits=limits,
            telemetry=telemetry,
            scenario_id=scenario_id,
            writable_holding=True,
            writable_coils=True,
            ip_allowlist=allow if patched else None,
        )
        self.snapshots.capture("delta-initial", memory.snapshot())

    async def start(self) -> None:
        """Start Modbus listener."""
        await self.server.start()

    async def stop(self) -> None:
        """Stop listener."""
        await self.server.stop()

    def restore(self) -> None:
        """Restore holding registers and coils."""
        self.server.memory.restore(self.snapshots.restore())


def normalize_request_path(raw_path: str) -> str:
    """Canonicalize an HTTP path, including dot-segments."""
    decoded = unquote(raw_path.split("?", 1)[0] or "/")
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    return posixpath.normpath(decoded)


def fuxa_is_protected(path: str) -> bool:
    """Return True for sensitive FUXA-like REST resources."""
    return path in {"/api/users", "/api/roles"} or path.startswith("/api/project/")


class FuxaHttpTarget:
    """Minimal FUXA REST emulator for CVE-2026-13207 class path confusion.

    Vulnerable: authentication is applied to the raw request path.
    Patched: path is normalized before the auth gate.
    """

    def __init__(
        self,
        host: str,
        port: int,
        patched: bool,
        telemetry: Optional[TelemetryBus] = None,
        scenario_id: str = "",
        token: str = "lab-token",
    ) -> None:
        """Store bind parameters."""
        self.host = host
        self.port = int(port)
        self.patched = patched
        self.telemetry = telemetry
        self.scenario_id = scenario_id
        self.token = token
        self._server: Optional[asyncio.AbstractServer] = None
        self.last_bypass = False

    def _emit(self, event_type: str, message: str, **details: object) -> None:
        """Publish HTTP lab events."""
        if self.telemetry is None:
            return
        self.telemetry.emit(
            PlantEvent(
                event_type=event_type,
                source="fuxa-http",
                message=message,
                scenario_id=self.scenario_id or None,
                details=details,
            )
        )

    def evaluate(self, raw_path: str, authorization: str) -> Tuple[int, bytes, str]:
        """Return status, body and decision reason for one request."""
        normalized = normalize_request_path(raw_path)
        gate_path = normalized if self.patched else raw_path.split("?", 1)[0]
        authorized = authorization.strip() == "Bearer %s" % self.token
        if fuxa_is_protected(gate_path) and not authorized:
            return 401, b'{"error":"unauthorized"}\n', "auth-required"
        if fuxa_is_protected(normalized) and not authorized:
            self.last_bypass = True
            self._emit("http_path_bypass", "dot-segment path bypassed auth", raw_path=raw_path, normalized=normalized)
            if normalized.endswith("roles"):
                return 200, FUXA_ROLES_JSON, "bypass"
            return 200, FUXA_USERS_JSON, "bypass"
        if fuxa_is_protected(normalized) and authorized:
            body = FUXA_ROLES_JSON if normalized.endswith("roles") else FUXA_USERS_JSON
            return 200, body, "authorized"
        if normalized in {"/", "/health"}:
            return 200, b'{"service":"fuxa-lab","profile":"%s"}\n' % (
                b"patched" if self.patched else b"vulnerable"
            ), "ok"
        return 404, b'{"error":"not-found"}\n', "missing"

    async def start(self) -> None:
        """Bind a raw HTTP listener so dot-segments are preserved."""
        self._server = await asyncio.start_server(self._handle, host=self.host, port=self.port)

    async def stop(self) -> None:
        """Close listener."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @property
    def bound_port(self) -> int:
        """Listening port."""
        if self._server and self._server.sockets:
            return int(self._server.sockets[0].getsockname()[1])
        return self.port

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Serve one HTTP/1.1 request."""
        try:
            header_block = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, asyncio.LimitOverrunError):
            writer.close()
            return
        text = header_block.decode("iso-8859-1", errors="replace")
        lines = text.split("\r\n")
        if not lines:
            writer.close()
            return
        parts = lines[0].split(" ")
        raw_path = parts[1] if len(parts) >= 2 else "/"
        authorization = ""
        for line in lines[1:]:
            if line.lower().startswith("authorization:"):
                authorization = line.split(":", 1)[1].strip()
        status, body, _reason = self.evaluate(raw_path, authorization)
        reason = {200: "OK", 401: "Unauthorized", 404: "Not Found"}.get(status, "OK")
        response = (
            "HTTP/1.1 %s %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n"
            % (status, reason, len(body))
        ).encode("ascii") + body
        writer.write(response)
        try:
            await writer.drain()
        finally:
            writer.close()


class ProtocolCrashTarget:
    """TCP emulator for malformed industrial frames.

    Vulnerable profile closes the connection and marks crashed=True.
    Patched profile replies NAK and stays up.
    Reproduction mode is protocol, never a real memory-corruption PoC.
    """

    def __init__(
        self,
        host: str,
        port: int,
        patched: bool,
        family: str,
        telemetry: Optional[TelemetryBus] = None,
        scenario_id: str = "",
    ) -> None:
        """Configure family-specific trigger bytes."""
        self.host = host
        self.port = int(port)
        self.patched = patched
        self.family = family
        self.telemetry = telemetry
        self.scenario_id = scenario_id
        self.crashed = False
        self._server: Optional[asyncio.AbstractServer] = None
        if family == "iec61850":
            self.trigger = MALFORMED_MMS
        elif family == "iec60870":
            self.trigger = MALFORMED_IEC104
        else:
            self.trigger = MALFORMED_OPCUA

    def _emit(self, event_type: str, message: str, **details: object) -> None:
        """Publish protocol events."""
        if self.telemetry is None:
            return
        self.telemetry.emit(
            PlantEvent(
                event_type=event_type,
                source=self.family,
                message=message,
                scenario_id=self.scenario_id or None,
                details=details,
            )
        )

    def consume(self, payload: bytes) -> bytes:
        """Apply one frame to the emulator state."""
        if self.trigger in payload:
            if self.patched:
                return b"NAK\n"
            self.crashed = True
            self._emit("protocol_crash", "%s emulator crashed on malformed frame" % self.family)
            return b""
        banner = {
            "iec61850": b"MMS-LAB-OK\n",
            "iec60870": b"IEC104-LAB-OK\n",
            "open62541": b"OPCUA-LAB-OK\n",
        }.get(self.family, b"OK\n")
        return banner

    async def start(self) -> None:
        """Bind TCP listener."""
        self._server = await asyncio.start_server(self._handle, host=self.host, port=self.port)

    async def stop(self) -> None:
        """Close listener."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @property
    def bound_port(self) -> int:
        """Listening port."""
        if self._server and self._server.sockets:
            return int(self._server.sockets[0].getsockname()[1])
        return self.port

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Read one bounded frame."""
        if self.crashed and not self.patched:
            writer.close()
            return
        try:
            payload = await asyncio.wait_for(reader.read(1024), timeout=5.0)
        except (asyncio.TimeoutError, ConnectionError):
            writer.close()
            return
        reply = self.consume(payload)
        if not reply:
            writer.close()
            return
        writer.write(reply)
        try:
            await writer.drain()
        finally:
            writer.close()
