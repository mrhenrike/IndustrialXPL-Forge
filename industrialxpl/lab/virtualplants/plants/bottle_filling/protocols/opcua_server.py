"""OPC UA server integration for bottle-filling process.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, Optional

from asyncua import Server

from ..state import SharedPlantState


LOGGER = logging.getLogger("virtualplants.opcua")


class OpcUaBridge:
    """Expose plant state via OPC UA variables."""

    def __init__(
        self,
        state: SharedPlantState,
        host: str,
        port: int,
        security_profile: str = "insecure",
        telemetry: Optional[object] = None,
        scenario_id: str = "bottle-filling",
    ) -> None:
        """Store runtime dependencies."""
        self._state = state
        self._host = host
        self._port = port
        self._security_profile = security_profile
        self._telemetry = telemetry
        self._scenario_id = scenario_id
        self._server = Server()
        self._variables: Dict[str, object] = {}
        self._last_run_command: bool = True
        self._last_reset_request: bool = False

    async def start(self) -> None:
        """Initialize OPC UA nodes and keep server running."""
        endpoint = f"opc.tcp://{self._host}:{self._port}/virtualplants/bottle-filling/"
        await self._server.init()
        self._server.set_endpoint(endpoint)
        self._server.set_server_name("VirtualPlants Bottle Filling OPCUA")
        try:
            from industrialxpl.lab.virtualplants.protocols.opcua import OpcUaSecurityProfile, apply_server_profile

            profile = OpcUaSecurityProfile(self._security_profile)
            await apply_server_profile(self._server, profile, "bottle-filling-opcua")
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("OPC UA profile %s not fully applied: %s", self._security_profile, exc)

        uri = "https://uniaogeek.com.br/virtualplants/bottle-filling"
        idx = await self._server.register_namespace(uri)
        objects = self._server.nodes.objects
        plant = await objects.add_object(idx, "BottleFillingPlant")

        self._variables["run_command"] = await plant.add_variable(idx, "run_command", True)
        self._variables["reset_request"] = await plant.add_variable(idx, "reset_request", False)
        self._variables["status"] = await plant.add_variable(idx, "status", "RUNNING")
        self._variables["bottle_in_position"] = await plant.add_variable(idx, "bottle_in_position", False)
        self._variables["level_hit"] = await plant.add_variable(idx, "level_hit", False)
        self._variables["motor_on"] = await plant.add_variable(idx, "motor_on", False)
        self._variables["nozzle_open"] = await plant.add_variable(idx, "nozzle_open", False)
        self._variables["produced_count"] = await plant.add_variable(idx, "produced_count", 0)
        self._variables["spill_count"] = await plant.add_variable(idx, "spill_count", 0)
        self._variables["current_fill_level"] = await plant.add_variable(idx, "current_fill_level", 0.0)

        await self._variables["run_command"].set_writable()
        await self._variables["reset_request"].set_writable()
        await self._variables["run_command"].write_value(True)
        await self._variables["reset_request"].write_value(False)

        LOGGER.info("Starting OPC UA server on %s", endpoint)
        async with self._server:
            await self._sync_loop()

    async def _sync_loop(self) -> None:
        """Synchronize state and writable tags."""
        while True:
            run_value = await self._variables["run_command"].read_value()
            reset_value = await self._variables["reset_request"].read_value()

            run_bool = bool(run_value)
            reset_bool = bool(reset_value)

            if run_bool != self._last_run_command:
                self._state.set_run(run_bool)

            if reset_bool and not self._last_reset_request:
                self._state.request_reset()
                await self._variables["reset_request"].write_value(False)
                reset_bool = False

            snapshot = self._state.get()
            await self._variables["status"].write_value(snapshot.status)
            await self._variables["bottle_in_position"].write_value(bool(snapshot.bottle_in_position))
            await self._variables["level_hit"].write_value(bool(snapshot.level_hit))
            await self._variables["motor_on"].write_value(bool(snapshot.motor_on))
            await self._variables["nozzle_open"].write_value(bool(snapshot.nozzle_open))
            await self._variables["produced_count"].write_value(int(snapshot.produced_count))
            await self._variables["spill_count"].write_value(int(snapshot.spill_count))
            await self._variables["current_fill_level"].write_value(float(snapshot.current_fill_level))
            await self._variables["run_command"].write_value(bool(snapshot.run_command))
            self._last_run_command = bool(snapshot.run_command)
            self._last_reset_request = reset_bool

            await asyncio.sleep(0.10)
