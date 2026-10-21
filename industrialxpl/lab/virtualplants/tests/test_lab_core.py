"""Unit and loopback tests for VirtualPlants lab core.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import asyncio
import json
import sys
import unittest
from pathlib import Path


REPO_SRC = Path(__file__).resolve().parents[1] / "src"
if str(REPO_SRC) not in sys.path:
    sys.path.insert(0, str(REPO_SRC))

from industrialxpl.lab.virtualplants.attacks import load_catalog
from industrialxpl.lab.virtualplants.attacks.pocs import run_internal
from industrialxpl.lab.virtualplants.attacks.runner import run_attack_id
from industrialxpl.lab.virtualplants.core.detection import DetectionEngine
from industrialxpl.lab.virtualplants.core.events import PlantEvent
from industrialxpl.lab.virtualplants.core.safety import LabSafetyError, assert_lab_target, require_confirmation, validate_bind_host
from industrialxpl.lab.virtualplants.core.scenario import ManifestError, get_manifest, list_manifests, parse_manifest
from industrialxpl.lab.virtualplants.core.snapshots import SnapshotStore
from industrialxpl.lab.virtualplants.core.telemetry import TelemetryBus
from industrialxpl.lab.virtualplants.lab import FuxaHttpTarget, ProtocolCrashTarget
from industrialxpl.lab.virtualplants.protocols.modbus import DeviceIdentity, ModbusMemory, handle_pdu


class SafetyTests(unittest.TestCase):
    """Lab containment checks."""

    def test_loopback_ok(self) -> None:
        """Loopback hosts are accepted."""
        self.assertEqual(assert_lab_target("127.0.0.1"), "127.0.0.1")

    def test_public_rejected(self) -> None:
        """Public IPs cannot be attack targets."""
        with self.assertRaises(LabSafetyError):
            assert_lab_target("8.8.8.8")

    def test_bind_requires_flag(self) -> None:
        """LAN bind without the explicit flag is rejected."""
        with self.assertRaises(LabSafetyError):
            validate_bind_host("192.168.1.10", expose_lan=False)
        self.assertEqual(validate_bind_host("127.0.0.1", expose_lan=False), "127.0.0.1")

    def test_public_bind_rejected(self) -> None:
        """Public bind addresses stay forbidden even with LAN expose."""
        with self.assertRaises(LabSafetyError):
            validate_bind_host("8.8.8.8", expose_lan=True)

    def test_confirm_required(self) -> None:
        """Live PoCs require --confirm."""
        with self.assertRaises(LabSafetyError):
            require_confirmation(False, "demo")


class ManifestAndCatalogTests(unittest.TestCase):
    """Scenario and catalog loading."""

    def test_scenarios_load(self) -> None:
        """All first-wave scenarios validate."""
        loaded = {item.scenario_id: item for item in list_manifests()}
        for scenario_id in (
            "bottle-filling",
            "delta-dvp12se-vulnerable",
            "delta-dvp12se-patched",
            "fuxa-vulnerable",
            "fuxa-patched",
            "libiec61850-vulnerable",
            "libiec61850-patched",
            "lib60870-vulnerable",
            "lib60870-patched",
            "open62541-vulnerable",
            "open62541-patched",
        ):
            self.assertIn(scenario_id, loaded)

    def test_rejects_unknown_keys(self) -> None:
        """Extra JSON keys are denied."""
        raw = json.loads((Path(__file__).resolve().parents[1] / "scenarios" / "fuxa-vulnerable" / "scenario.json").read_text(encoding="utf-8"))
        raw["extra"] = True
        with self.assertRaises(ManifestError):
            parse_manifest(raw)

    def test_catalog_has_licenses(self) -> None:
        """Every attack record carries a license."""
        records = load_catalog()
        self.assertGreaterEqual(len(records), 10)
        for record in records:
            self.assertTrue(record.license)


class ModbusPduTests(unittest.TestCase):
    """PDU handler for coils, registers and MEI."""

    def test_write_and_read_register(self) -> None:
        """FC06 then FC03 round-trip."""
        memory = ModbusMemory()
        identity = DeviceIdentity()
        handle_pdu(memory, bytes([6, 0, 7, 0x03, 0xE8]), identity)
        reply = handle_pdu(memory, bytes([3, 0, 7, 0, 1]), identity)
        self.assertEqual(reply[0], 3)
        self.assertEqual(int.from_bytes(reply[2:4], "big"), 1000)

    def test_coil_write(self) -> None:
        """FC05 writes coil 0 off."""
        memory = ModbusMemory(coils=[1] * 8)
        identity = DeviceIdentity()
        handle_pdu(memory, bytes([5, 0, 0, 0, 0]), identity)
        self.assertEqual(memory.coils[0], 0)

    def test_mei_identity(self) -> None:
        """FC43 MEI 14 returns vendor name."""
        memory = ModbusMemory()
        identity = DeviceIdentity(vendor_name="Uniao Geek")
        reply = handle_pdu(memory, bytes([0x2B, 0x0E, 0x01, 0x00]), identity)
        self.assertEqual(reply[0], 0x2B)
        self.assertIn(b"Uniao Geek", reply)

    def test_write_multiple_coils(self) -> None:
        """FC15 writes a coil range."""
        memory = ModbusMemory(coils=[0] * 16)
        identity = DeviceIdentity()
        reply = handle_pdu(memory, bytes([15, 0, 0, 0, 2, 1, 0x03]), identity)
        self.assertEqual(reply[0], 15)
        self.assertEqual(memory.coils[0], 1)
        self.assertEqual(memory.coils[1], 1)

    def test_write_multiple_registers(self) -> None:
        """FC16 writes a holding-register range."""
        memory = ModbusMemory()
        identity = DeviceIdentity()
        reply = handle_pdu(memory, bytes([16, 0, 10, 0, 2, 4, 0, 10, 0, 20]), identity)
        self.assertEqual(reply[0], 16)
        self.assertEqual(memory.holding_registers[10], 10)
        self.assertEqual(memory.holding_registers[11], 20)


class SnapshotDetectionTests(unittest.TestCase):
    """Rollback and detections."""

    def test_snapshot_restore(self) -> None:
        """Snapshot returns the captured payload."""
        store = SnapshotStore()
        store.capture("a", {"holding_registers": [1, 2, 3]})
        restored = store.restore()
        self.assertEqual(restored["holding_registers"], [1, 2, 3])

    def test_overspeed_detection(self) -> None:
        """Holding register 7 overspeed raises a detection."""
        bus = TelemetryBus()
        engine = DetectionEngine(bus)
        bus.emit(
            PlantEvent(
                event_type="modbus_write",
                source="test",
                message="speed",
                details={"area": "holding_register", "address": 7, "value": 900},
            )
        )
        rules = [item.details.get("rule") for item in engine.findings()]
        self.assertIn("overspeed", rules)


class PairingLoopbackTests(unittest.IsolatedAsyncioTestCase):
    """Vulnerable versus patched pairing targets on loopback."""

    async def test_fuxa_pair(self) -> None:
        """Dot-segment bypass works only on the vulnerable profile."""
        vulnerable = FuxaHttpTarget("127.0.0.1", 0, patched=False)
        patched = FuxaHttpTarget("127.0.0.1", 0, patched=True)
        await vulnerable.start()
        await patched.start()
        try:
            vul_result = await run_internal("FUXA-PATH-BYPASS", "127.0.0.1", vulnerable.bound_port, {})
            pat_result = await run_internal("FUXA-PATH-BYPASS", "127.0.0.1", patched.bound_port, {})
            self.assertTrue(vul_result.get("bypassed"))
            self.assertFalse(pat_result.get("bypassed"))
        finally:
            await vulnerable.stop()
            await patched.stop()

    async def test_iec61850_pair(self) -> None:
        """Malformed MMS crashes only the vulnerable emulator."""
        vulnerable = ProtocolCrashTarget("127.0.0.1", 0, patched=False, family="iec61850")
        patched = ProtocolCrashTarget("127.0.0.1", 0, patched=True, family="iec61850")
        await vulnerable.start()
        await patched.start()
        try:
            vul_result = await run_internal("IEC61850-MALFORMED", "127.0.0.1", vulnerable.bound_port, {})
            pat_result = await run_internal("IEC61850-MALFORMED", "127.0.0.1", patched.bound_port, {})
            self.assertTrue(vul_result.get("crashed"))
            self.assertFalse(pat_result.get("crashed"))
            self.assertIn("NAK", str(pat_result.get("reply")))
        finally:
            await vulnerable.stop()
            await patched.stop()

    async def test_open62541_pair(self) -> None:
        """Malformed OPC UA transfer crashes only the vulnerable emulator."""
        vulnerable = ProtocolCrashTarget("127.0.0.1", 0, patched=False, family="open62541")
        patched = ProtocolCrashTarget("127.0.0.1", 0, patched=True, family="open62541")
        await vulnerable.start()
        await patched.start()
        try:
            vul_result = await run_internal("OPEN62541-MALFORMED", "127.0.0.1", vulnerable.bound_port, {})
            pat_result = await run_internal("OPEN62541-MALFORMED", "127.0.0.1", patched.bound_port, {})
            self.assertTrue(vul_result.get("crashed"))
            self.assertFalse(pat_result.get("crashed"))
            self.assertIn("NAK", str(pat_result.get("reply")))
        finally:
            await vulnerable.stop()
            await patched.stop()

    async def test_delta_modbus_and_quota(self) -> None:
        """Unauth write works; patched quota rejects extra connections."""
        from industrialxpl.lab.virtualplants.core.runtime import start_pairing_lab
        from industrialxpl.lab.virtualplants.core.telemetry import TelemetryBus

        vul_manifest = get_manifest("delta-dvp12se-vulnerable")
        pat_manifest = get_manifest("delta-dvp12se-patched")
        object.__setattr__(vul_manifest.endpoints[0], "port", 0)
        object.__setattr__(pat_manifest.endpoints[0], "port", 0)
        bus = TelemetryBus()
        vul = await start_pairing_lab(vul_manifest, bus)
        pat = await start_pairing_lab(pat_manifest, bus)
        try:
            stop = await run_attack_id(
                "DELTA-UNAUTH-STOP",
                vul_manifest,
                "127.0.0.1",
                vul.port,
                confirm=True,
                telemetry=bus,
                snapshots=vul.snapshots,
            )
            self.assertTrue(stop.get("ok"))
            flood_v = await run_internal("DELTA-CONN-EXHAUST", "127.0.0.1", vul.port, {"count": "24"})
            flood_p = await run_internal("DELTA-CONN-EXHAUST", "127.0.0.1", pat.port, {"count": "24"})
            await asyncio.sleep(0.1)
            self.assertGreaterEqual(int(flood_v.get("opened") or 0), 8)
            self.assertEqual(vul.service.server.rejected_connections, 0)
            self.assertGreater(pat.service.server.rejected_connections, 0)
            self.assertGreaterEqual(int(flood_p.get("opened") or 0), 1)
        finally:
            await vul.stop()
            await pat.stop()

    async def test_runner_requires_confirm(self) -> None:
        """Runner blocks without confirm."""
        manifest = get_manifest("fuxa-vulnerable")
        with self.assertRaises(LabSafetyError):
            await run_attack_id("FUXA-PATH-BYPASS", manifest, "127.0.0.1", 18881, confirm=False)


class CliTests(unittest.TestCase):
    """CLI guardrails."""

    def test_bottle_filling_start_rejected(self) -> None:
        """Plant UI is started by plantctl, not the pairing CLI."""
        from industrialxpl.lab.virtualplants.cli import main

        self.assertEqual(main(["start", "--scenario", "bottle-filling"]), 2)


if __name__ == "__main__":
    unittest.main()
