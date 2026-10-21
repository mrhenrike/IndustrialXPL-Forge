"""Simulation engine for bottle-filling process.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
from typing import Dict, List, Optional, Tuple

from .state import SharedPlantState


class BottleFillingSimulation:
    """Advance process state with deterministic + stochastic behavior."""

    def __init__(self, shared_state: SharedPlantState, tick_seconds: float) -> None:
        """Store shared state and runtime cadence."""
        self._state = shared_state
        self._tick_seconds = tick_seconds
        self._stop_event = asyncio.Event()
        self._base_bottle_speed = 0.040
        self._max_sabotage_speed = 0.160
        self._fill_speed = 0.22
        self._position_tolerance = 0.0015
        self._alignment_window = 0.060
        self._bottle_capacity = 1.0
        self._bottle_capacity_ml = 350.0
        self._nominal_product_level = 0.90
        self._max_bottles = 14
        self._bottles: List[Dict[str, object]] = self._build_initial_bottles(spacing=0.095)
        self._target_bottle_id: Optional[int] = None
        self._next_bottle_id = self._max_bottles + 1
        self._spill_accumulator = 0.0

    async def run(self) -> None:
        """Main simulation loop."""
        while not self._stop_event.is_set():
            self._tick()
            await asyncio.sleep(self._tick_seconds)

    def stop(self) -> None:
        """Signal graceful stop."""
        self._stop_event.set()

    def _tick(self) -> None:
        """Compute one simulation step."""
        snapshot = self._state.get()

        if self._state.consume_reset_request():
            spacing = 0.095
            self._bottles = self._build_initial_bottles(spacing=spacing)
            self._target_bottle_id = None
            self._next_bottle_id = self._max_bottles + 1
            self._spill_accumulator = 0.0
            self._state.patch(
                run_command=True,
                bottle_in_position=False,
                level_hit=False,
                motor_on=True,
                nozzle_open=False,
                current_bottle_x=self._bottles[0]["x"],
                current_fill_level=0.0,
                spill_count=0,
                produced_count=0,
                sensor_min_position=0.515,
                sensor_max_position=0.525,
                fill_level_limit=0.92,
                bottle_spacing=0.095,
                sensor_window=0.02,
                level_sensor_enabled=True,
                bottle_sensor_enabled=True,
                conveyor_speed=self._base_bottle_speed,
                jam_conveyor=False,
                free_flow_enabled=False,
                collisions_count=0,
                broken_count=0,
                fallen_count=0,
                alerts=[],
                status="RUNNING",
            )
            snapshot = self._state.get()

        run = bool(snapshot.run_command)
        bottle_sensor_enabled = bool(snapshot.bottle_sensor_enabled)
        conveyor_speed = self._clamp(
            float(snapshot.conveyor_speed),
            self._base_bottle_speed,
            self._max_sabotage_speed,
        )
        # In normal operation conveyor runs at base speed. Any higher value is treated as
        # process misconfiguration/tampering over process registers (didactic sabotage).
        if conveyor_speed < self._base_bottle_speed:
            conveyor_speed = self._base_bottle_speed
        nozzle_position = float(snapshot.nozzle_position)
        sensor_min = self._clamp(snapshot.sensor_min_position, 0.35, 0.70)
        sensor_max = self._clamp(snapshot.sensor_max_position, 0.36, 0.72)
        if sensor_max < sensor_min:
            sensor_min, sensor_max = sensor_max, sensor_min
        fill_level_limit = self._clamp(snapshot.fill_level_limit, 0.00, 1.30)
        bottle_spacing = self._clamp(snapshot.bottle_spacing, 0.06, 0.18)
        sensor_window = self._clamp(snapshot.sensor_window, 0.01, 0.08)
        level_sensor_enabled = bool(snapshot.level_sensor_enabled) and fill_level_limit > 0.01

        self._bottles.sort(key=lambda item: item["x"])
        active_bottle = self._resolve_active_bottle(
            sensor_min=sensor_min,
            sensor_max=sensor_max,
            nozzle_position=nozzle_position,
            sensor_window=sensor_window,
            bottle_sensor_enabled=bottle_sensor_enabled,
        )
        bottle_in_position = False
        level_hit = False
        motor_on = False
        nozzle_open = False
        produced_increment = 0
        spill_increment = 0
        collisions_increment = 0
        broken_increment = 0
        fallen_increment = 0
        alert_messages: List[str] = []

        if run and active_bottle is not None:
            in_zone = sensor_min <= active_bottle["x"] <= sensor_max
            offset = abs(float(active_bottle["x"]) - nozzle_position)
            centered = offset <= self._position_tolerance
            target_fill_ml = self._clamp(fill_level_limit, 0.0, 1.30) * self._bottle_capacity_ml
            current_fill_ml = float(active_bottle["fill"]) * self._bottle_capacity_ml
            level_hit = bool(level_sensor_enabled and current_fill_ml >= target_fill_ml - 0.2)
            capacity_hit = bool(current_fill_ml >= self._bottle_capacity_ml - 0.2)
            bottle_in_position = bool(bottle_sensor_enabled and in_zone)

            in_fill_window = offset <= max(sensor_window, self._position_tolerance)
            if in_zone and in_fill_window and not level_hit:
                nozzle_open = True
                motor_on = bool(conveyor_speed > (self._base_bottle_speed * 1.35))
                # In normal mode, lock bottle at nozzle center for precise filling.
                if not motor_on:
                    active_bottle["x"] = nozzle_position
                inflow_ml = self._fill_speed * self._tick_seconds * self._bottle_capacity_ml
                alignment_factor = max(0.0, 1.0 - (offset / self._alignment_window))
                captured_ml = inflow_ml * alignment_factor
                free_spill_ml = inflow_ml - captured_ml

                capacity_left_ml = max(0.0, self._bottle_capacity_ml - current_fill_ml)
                retained_ml = min(captured_ml, capacity_left_ml)
                overflow_spill_ml = captured_ml - retained_ml

                new_fill_ml = current_fill_ml + retained_ml
                active_bottle["fill"] = self._clamp(new_fill_ml / self._bottle_capacity_ml, 0.0, self._bottle_capacity)
                current_fill_ml = float(active_bottle["fill"]) * self._bottle_capacity_ml
                level_hit = bool(level_sensor_enabled and current_fill_ml >= target_fill_ml - 0.2)
                capacity_hit = bool(current_fill_ml >= self._bottle_capacity_ml - 0.2)
                if level_hit and (not bool(active_bottle["counted"])):
                    active_bottle["counted"] = True
                    produced_increment += 1

                spill_ml = max(0.0, free_spill_ml + overflow_spill_ml)
                self._spill_accumulator += spill_ml
                while self._spill_accumulator >= 1.0:
                    spill_increment += 1
                    self._spill_accumulator -= 1.0
            else:
                nozzle_open = False
                motor_on = True

            if level_hit or (capacity_hit and not level_sensor_enabled):
                nozzle_open = False
                motor_on = True
                self._target_bottle_id = None
        elif run:
            motor_on = True

        if motor_on:
            for bottle in self._bottles:
                status = str(bottle.get("status", "normal"))
                speed_factor = 1.0
                if conveyor_speed > (self._base_bottle_speed * 1.35):
                    speed_factor = 0.85 + ((int(bottle["id"]) % 5) * 0.10)
                    if float(bottle["x"]) > 0.58 and int(bottle["id"]) % 2 == 0:
                        speed_factor *= 0.35
                if status == "broken":
                    bottle["x"] += conveyor_speed * self._tick_seconds * 0.45 * speed_factor
                elif status == "fallen":
                    bottle["x"] += conveyor_speed * self._tick_seconds * 0.62 * speed_factor
                    bottle["tilt"] = min(1.25, float(bottle.get("tilt", 0.0)) + (0.35 * self._tick_seconds))
                else:
                    bottle["x"] += conveyor_speed * self._tick_seconds * speed_factor
        if conveyor_speed > (self._base_bottle_speed * 1.60) and nozzle_open and motor_on:
            # Severe overspeed condition: intermittent micro-jam under nozzle creates impacts.
            for bottle in self._bottles:
                if str(bottle.get("status", "normal")) != "normal":
                    continue
                if abs(float(bottle["x"]) - nozzle_position) <= 0.028:
                    bottle["x"] -= conveyor_speed * self._tick_seconds * 0.72

        self._bottles.sort(key=lambda item: item["x"])
        (
            collision_spill_ml,
            collisions_increment,
            broken_increment,
            fallen_increment,
            collision_alerts,
        ) = self._resolve_collisions(
            bottle_spacing=bottle_spacing,
            conveyor_speed=conveyor_speed,
            sabotage_mode=conveyor_speed > (self._base_bottle_speed * 1.35),
            collision_base=snapshot.collisions_count,
        )
        spill_increment += int(collision_spill_ml)
        alert_messages.extend(collision_alerts)

        while self._bottles and self._bottles[-1]["x"] > 1.20:
            finished = self._bottles.pop()
            if str(finished.get("status", "normal")) != "normal":
                continue
            if (not bool(finished["counted"])) and float(finished["fill"]) >= self._nominal_product_level:
                produced_increment += 1

        self._ensure_bottle_count(spacing=bottle_spacing)

        self._bottles.sort(key=lambda item: item["x"])
        current_bottle = self._find_bottle_in_sensor_zone(
            sensor_min=sensor_min,
            sensor_max=sensor_max,
            nozzle_position=nozzle_position,
            sensor_window=sensor_window,
            bottle_sensor_enabled=bottle_sensor_enabled,
        )
        current_x: Optional[float] = current_bottle["x"] if current_bottle else None
        current_fill = current_bottle["fill"] if current_bottle else 0.0
        queue_preview: List[float] = [bottle["x"] for bottle in self._bottles]
        bottle_snapshot: List[Dict[str, object]] = [
            {
                "id": int(bottle["id"]),
                "x": float(bottle["x"]),
                "fill": float(bottle["fill"]),
                "counted": bool(bottle["counted"]),
                "status": str(bottle.get("status", "normal")),
                "tilt": float(bottle.get("tilt", 0.0)),
            }
            for bottle in self._bottles
        ]

        if conveyor_speed > (self._base_bottle_speed * 1.35):
            alert_messages.append("PROCESS TAMPERING SUSPECTED - OVERSPEED")
            if conveyor_speed > (self._base_bottle_speed * 2.0):
                alert_messages.append("CONVEYOR OVERSPEED")
        projected_spill = snapshot.spill_count + spill_increment
        if projected_spill > 600:
            alert_messages.append("HIGH SPILL RATE")
        if projected_spill > 900:
            alert_messages.append("CLEANING REQUIRED - CONTAMINATION LEVEL HIGH")
        if projected_spill > 1400:
            alert_messages.append("MAINTENANCE ALARM - CONTAMINATION CRITICAL")
        if snapshot.broken_count + broken_increment > 0:
            alert_messages.append("BROKEN CONTAINERS DETECTED")
        if snapshot.fallen_count + fallen_increment > 0:
            alert_messages.append("FALLEN CONTAINERS DETECTED")

        self._state.patch(
            bottle_in_position=bottle_in_position,
            level_hit=level_hit,
            motor_on=motor_on,
            nozzle_open=nozzle_open,
            produced_count=snapshot.produced_count + produced_increment,
            spill_count=snapshot.spill_count + spill_increment,
            current_bottle_x=current_x,
            current_fill_level=current_fill,
            queue_preview=queue_preview,
            bottles=bottle_snapshot,
            conveyor_speed=conveyor_speed,
            sabotage_mode=False,
            collisions_count=snapshot.collisions_count + collisions_increment,
            broken_count=snapshot.broken_count + broken_increment,
            fallen_count=snapshot.fallen_count + fallen_increment,
            alerts=alert_messages[:6],
            sensor_min_position=sensor_min,
            sensor_max_position=sensor_max,
            fill_level_limit=fill_level_limit,
            bottle_spacing=bottle_spacing,
            sensor_window=sensor_window,
            level_sensor_enabled=level_sensor_enabled,
            bottle_sensor_enabled=bottle_sensor_enabled,
            jam_conveyor=False,
            free_flow_enabled=False,
            status="RUNNING" if run else "STOPPED",
        )

    def _build_initial_bottles(self, spacing: float) -> List[Dict[str, object]]:
        """Create evenly spaced bottles entering from left side."""
        start_x = 0.42
        return [
            {
                "id": idx + 1,
                "x": start_x - (idx * spacing),
                "fill": 0.0,
                "counted": False,
                "status": "normal",
                "tilt": 0.0,
            }
            for idx in range(self._max_bottles)
        ]

    def _ensure_bottle_count(self, spacing: float) -> None:
        """Keep conveyor stocked with consistent spacing."""
        if not self._bottles:
            self._bottles = self._build_initial_bottles(spacing=spacing)
            return
        self._bottles.sort(key=lambda item: item["x"])
        while len(self._bottles) < self._max_bottles:
            leftmost = self._bottles[0]["x"]
            self._bottles.insert(
                0,
                {
                    "id": self._next_bottle_id,
                    "x": leftmost - spacing,
                    "fill": 0.0,
                    "counted": False,
                    "status": "normal",
                    "tilt": 0.0,
                },
            )
            self._next_bottle_id += 1

    def _resolve_collisions(
        self,
        bottle_spacing: float,
        conveyor_speed: float,
        sabotage_mode: bool,
        collision_base: int,
    ) -> Tuple[float, int, int, int, List[str]]:
        """Resolve bottle compression and generate sabotage side effects."""
        if len(self._bottles) < 2:
            return 0.0, 0, 0, 0, []
        min_gap = max(0.030, bottle_spacing * 0.76)
        spill_ml = 0.0
        collisions_inc = 0
        broken_inc = 0
        fallen_inc = 0
        alerts: List[str] = []

        for idx in range(1, len(self._bottles)):
            left = self._bottles[idx - 1]
            right = self._bottles[idx]
            left_x = float(left["x"])
            right_x = float(right["x"])
            gap = right_x - left_x
            if gap >= min_gap:
                continue

            overlap = min_gap - gap
            collisions_inc += 1
            right["x"] = right_x + (overlap * 0.84)
            left["x"] = left_x - (overlap * 0.16)
            compression = overlap / min_gap

            for bottle in (left, right):
                if str(bottle.get("status", "normal")) != "normal":
                    continue
                lost_ratio = self._clamp(compression * 0.09, 0.0, 0.20)
                current_fill = float(bottle["fill"])
                lost = min(current_fill, lost_ratio)
                bottle["fill"] = max(0.0, current_fill - lost)
                spill_ml += lost * self._bottle_capacity_ml

            if sabotage_mode and conveyor_speed > 0.080 and (
                compression > 0.04 or ((collision_base + collisions_inc) % 500 == 0)
            ):
                victim = right if float(right["fill"]) >= float(left["fill"]) else left
                status = str(victim.get("status", "normal"))
                event_key = int(victim["id"]) + collision_base + collisions_inc
                if status == "normal":
                    if event_key % 3 == 0:
                        victim["status"] = "broken"
                        victim["fill"] = 0.0
                        victim["tilt"] = 1.2
                        broken_inc += 1
                        spill_ml += 80.0 + (compression * 140.0)
                        alerts.append(f"Bottle {int(victim['id'])} BROKEN by collision")
                    elif event_key % 2 == 0:
                        victim["status"] = "fallen"
                        victim["tilt"] = 0.9
                        fallen_inc += 1
                        spill_ml += 45.0 + (compression * 80.0)
                        alerts.append(f"Bottle {int(victim['id'])} FALLEN by push")

        return spill_ml, collisions_inc, broken_inc, fallen_inc, alerts

    def _resolve_active_bottle(
        self,
        sensor_min: float,
        sensor_max: float,
        nozzle_position: float,
        sensor_window: float,
        bottle_sensor_enabled: bool,
    ) -> Optional[Dict[str, object]]:
        """Resolve bottle target for current filling cycle."""
        if self._target_bottle_id is not None:
            tracked = self._find_bottle_by_id(self._target_bottle_id)
            if tracked is not None:
                return tracked
            self._target_bottle_id = None

        candidate = self._find_bottle_in_sensor_zone(
            sensor_min=sensor_min,
            sensor_max=sensor_max,
            nozzle_position=nozzle_position,
            sensor_window=sensor_window,
            bottle_sensor_enabled=bottle_sensor_enabled,
        )
        if candidate is None:
            return None
        self._target_bottle_id = int(candidate["id"])
        return candidate

    def _find_bottle_in_sensor_zone(
        self,
        sensor_min: float,
        sensor_max: float,
        nozzle_position: float,
        sensor_window: float,
        bottle_sensor_enabled: bool,
    ) -> Optional[Dict[str, object]]:
        """Return bottle inside sensor window and nozzle range."""
        if not bottle_sensor_enabled:
            return None
        eligible = [
            bottle
            for bottle in self._bottles
            if str(bottle.get("status", "normal")) == "normal"
            if sensor_min <= bottle["x"] <= sensor_max
            and abs(bottle["x"] - nozzle_position) <= max(sensor_window, self._position_tolerance)
        ]
        if not eligible:
            return None
        return min(eligible, key=lambda bottle: abs(bottle["x"] - nozzle_position))

    def _find_bottle_by_id(self, bottle_id: int) -> Optional[Dict[str, object]]:
        """Return bottle by stable identifier."""
        for bottle in self._bottles:
            if int(bottle["id"]) == int(bottle_id):
                return bottle
        return None

    @staticmethod
    def _clamp(value: float, low: float, high: float) -> float:
        """Clamp a numeric value to bounds."""
        return max(low, min(high, value))
