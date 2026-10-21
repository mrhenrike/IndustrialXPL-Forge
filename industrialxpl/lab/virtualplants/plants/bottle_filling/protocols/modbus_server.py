"""Modbus TCP bridge for bottle-filling: HR, IR, coils, DI and FC43.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 1.1.0
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..state import SharedPlantState


def _ensure_core_on_path() -> None:
    """Allow `python -m bottle_filling.main` to import industrialxpl.lab.virtualplants."""
    repo_root = Path(__file__).resolve().parents[5]
    core_src = repo_root / "src"
    core_text = str(core_src)
    if core_src.is_dir() and core_text not in sys.path:
        sys.path.insert(0, core_text)


_ensure_core_on_path()

from industrialxpl.lab.virtualplants.core.safety import ResourceLimits  # noqa: E402
from industrialxpl.lab.virtualplants.core.telemetry import TelemetryBus  # noqa: E402
from industrialxpl.lab.virtualplants.protocols.modbus import DeviceIdentity, ModbusMemory, ModbusTcpLabServer  # noqa: E402


LOGGER = logging.getLogger("virtualplants.modbus")


@dataclass
class ModbusRegisterMap:
    """Address map for holding registers 1..16 (index 0..15)."""

    run_command: int = 0
    reset_command: int = 1
    bottle_sensor_enable: int = 2
    level_sensor_enable: int = 3
    sensor_min_position: int = 4
    sensor_max_position: int = 5
    fill_level_limit: int = 6
    conveyor_speed: int = 7
    bottle_spacing: int = 8
    sensor_window: int = 9
    produced_count: int = 10
    spill_count: int = 11
    bottle_in_position: int = 12
    level_hit: int = 13
    nozzle_open: int = 14
    motor_on: int = 15


class ModbusBridge:
    """Bridge between simulation state and four Modbus areas."""

    def __init__(
        self,
        state: SharedPlantState,
        port: int,
        host: str = "127.0.0.1",
        telemetry: Optional[TelemetryBus] = None,
        scenario_id: str = "bottle-filling",
        lab_profile: str = "vulnerable",
    ) -> None:
        """Create memory image and lab server."""
        self._state = state
        self._registers = ModbusRegisterMap()
        self._memory = ModbusMemory(
            coils=[0] * 32,
            discrete_inputs=[0] * 32,
            input_registers=[0] * 32,
            holding_registers=[0] * 32,
        )
        initial = self._state.get()
        self._shadow_hr: List[int] = self._build_hr_from_state(initial)
        self._memory.holding_registers[:16] = list(self._shadow_hr)
        self._memory.coils[0] = 1 if initial.run_command else 0
        self._memory.coils[2] = 1 if initial.bottle_sensor_enabled else 0
        self._memory.coils[3] = 1 if initial.level_sensor_enabled else 0
        self._shadow_coils: List[int] = list(self._memory.coils[:6])
        patched = lab_profile == "patched"
        limits = ResourceLimits(
            max_connections=8 if patched else 32,
            rate_per_second=12 if patched else 40,
        )
        self._server = ModbusTcpLabServer(
            host=host,
            port=port,
            memory=self._memory,
            identity=DeviceIdentity(
                vendor_name="Uniao Geek",
                product_code="VP-BFP-16",
                major_minor_revision="1.1.0",
                product_name="Bottle Filling Soft PLC",
                model_name="VP-BFP-16",
            ),
            limits=limits,
            telemetry=telemetry,
            scenario_id=scenario_id,
            writable_holding=True,
            writable_coils=True,
            ip_allowlist=("127.0.0.1", "::1") if patched else None,
        )
        self._sync_task = None

    async def start(self) -> None:
        """Start synchronization and Modbus server."""
        import asyncio

        self._sync_task = asyncio.create_task(self._sync_loop(), name="modbus-sync-loop")
        await self._server.serve_forever()

    async def stop(self) -> None:
        """Stop server and sync task."""
        await self._server.stop()
        if self._sync_task is not None:
            self._sync_task.cancel()

    async def _sync_loop(self) -> None:
        """Synchronize process state and holding register / coil writes."""
        import asyncio

        while True:
            incoming_hr = list(self._memory.holding_registers[:16])
            if incoming_hr != self._shadow_hr:
                self._apply_hr_write(incoming_hr)
            incoming_coils = list(self._memory.coils[:6])
            if incoming_coils != self._shadow_coils:
                self._apply_coil_writes(incoming_coils)

            snapshot = self._state.get()
            outgoing_hr = self._build_hr_from_state(snapshot)
            self._memory.holding_registers[:16] = list(outgoing_hr)
            self._shadow_hr = outgoing_hr
            self._publish_mirrors(snapshot)
            self._shadow_coils = list(self._memory.coils[:6])
            await asyncio.sleep(0.10)

    def _apply_coil_writes(self, coils: List[int]) -> None:
        """Map coils 0..5 onto process commands when they change."""
        self._state.set_run(bool(coils[0]))
        if coils[1] == 1 and self._shadow_coils[1] == 0:
            self._state.request_reset()
            self._memory.coils[1] = 0
            return
        self._state.patch(
            bottle_sensor_enabled=bool(coils[2]),
            level_sensor_enabled=bool(coils[3]),
        )

    def _publish_mirrors(self, snapshot: object) -> None:
        """Update coils, DI and IR from process state."""
        self._memory.coils[0] = 1 if snapshot.run_command else 0
        self._memory.coils[2] = 1 if snapshot.bottle_sensor_enabled else 0
        self._memory.coils[3] = 1 if snapshot.level_sensor_enabled else 0
        self._memory.coils[4] = 1 if snapshot.motor_on else 0
        self._memory.coils[5] = 1 if snapshot.nozzle_open else 0
        self._memory.discrete_inputs[0] = 1 if snapshot.bottle_in_position else 0
        self._memory.discrete_inputs[1] = 1 if snapshot.level_hit else 0
        self._memory.discrete_inputs[2] = 1 if snapshot.motor_on else 0
        self._memory.discrete_inputs[3] = 1 if snapshot.nozzle_open else 0
        self._memory.discrete_inputs[4] = 1 if snapshot.run_command else 0
        self._memory.discrete_inputs[5] = 1 if snapshot.level_sensor_enabled else 0
        self._memory.input_registers[0] = int(snapshot.produced_count) % 65535
        self._memory.input_registers[1] = int(snapshot.spill_count) % 65535
        self._memory.input_registers[2] = int(round(float(snapshot.current_fill_level) * 1000.0)) % 65535
        self._memory.input_registers[3] = self._to_scale(float(snapshot.conveyor_speed), 0.04, 0.16)

    def _apply_hr_write(self, values: List[int]) -> None:
        """Apply external Modbus holding register writes to process state."""
        reg = self._registers
        previous = self._shadow_hr

        run_value = 1 if values[reg.run_command] > 0 else 0
        self._state.set_run(bool(run_value))

        if values[reg.reset_command] == 1 and previous[reg.reset_command] == 0:
            self._state.request_reset()
            return

        self._state.patch(
            bottle_sensor_enabled=bool(values[reg.bottle_sensor_enable]),
            level_sensor_enabled=bool(values[reg.level_sensor_enable]),
            sensor_min_position=self._from_scale(values[reg.sensor_min_position], 0.35, 0.70),
            sensor_max_position=self._from_scale(values[reg.sensor_max_position], 0.36, 0.72),
            fill_level_limit=self._from_scale(values[reg.fill_level_limit], 0.00, 1.30),
            conveyor_speed=self._from_scale(values[reg.conveyor_speed], 0.04, 0.16),
            bottle_spacing=self._from_scale(values[reg.bottle_spacing], 0.06, 0.18),
            sensor_window=self._from_scale(values[reg.sensor_window], 0.01, 0.08),
            produced_count=max(0, min(65535, int(values[reg.produced_count]))),
            spill_count=max(0, min(65535, int(values[reg.spill_count]))),
            bottle_in_position=bool(values[reg.bottle_in_position]),
            level_hit=bool(values[reg.level_hit]),
            nozzle_open=bool(values[reg.nozzle_open]),
            motor_on=bool(values[reg.motor_on]),
        )

    def _build_hr_from_state(self, snapshot: object) -> List[int]:
        """Build holding register image from current state."""
        reg = self._registers
        values = [0] * 16
        values[reg.run_command] = 1 if snapshot.run_command else 0
        values[reg.reset_command] = 0
        values[reg.bottle_sensor_enable] = 1 if snapshot.bottle_sensor_enabled else 0
        values[reg.level_sensor_enable] = 1 if snapshot.level_sensor_enabled else 0
        values[reg.sensor_min_position] = self._to_scale(snapshot.sensor_min_position, 0.35, 0.70)
        values[reg.sensor_max_position] = self._to_scale(snapshot.sensor_max_position, 0.36, 0.72)
        values[reg.fill_level_limit] = self._to_scale(snapshot.fill_level_limit, 0.00, 1.30)
        values[reg.conveyor_speed] = self._to_scale(snapshot.conveyor_speed, 0.04, 0.16)
        values[reg.bottle_spacing] = self._to_scale(snapshot.bottle_spacing, 0.06, 0.18)
        values[reg.sensor_window] = self._to_scale(snapshot.sensor_window, 0.01, 0.08)
        values[reg.produced_count] = int(snapshot.produced_count) % 65535
        values[reg.spill_count] = int(snapshot.spill_count) % 65535
        values[reg.bottle_in_position] = 1 if snapshot.bottle_in_position else 0
        values[reg.level_hit] = 1 if snapshot.level_hit else 0
        values[reg.nozzle_open] = 1 if snapshot.nozzle_open else 0
        values[reg.motor_on] = 1 if snapshot.motor_on else 0
        return values

    @staticmethod
    def _to_scale(value: float, min_value: float, max_value: float) -> int:
        """Convert float range to uint16 scale 0..1000."""
        span = max_value - min_value
        if span <= 0:
            return 0
        normalized = (max(min_value, min(max_value, float(value))) - min_value) / span
        return int(round(normalized * 1000.0))

    @staticmethod
    def _from_scale(value: int, min_value: float, max_value: float) -> float:
        """Convert uint16 scale 0..1000 to float range."""
        clamped = max(0, min(1000, int(value)))
        return min_value + ((max_value - min_value) * (clamped / 1000.0))
