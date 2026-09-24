"""
industrialxpl/modules/scanners/ics/modbus_register_mapper.py

Modbus Register Mapper - full register enumeration with chunked reads.

Enumerates all Modbus register types (coils, discrete inputs, holding registers,
input registers) across a configurable address range using chunked reads for
efficiency. Produces a complete register map JSON.

Ported from BusPwn (submodules/OT/BusPwn/pwn.py) register enumeration logic.
Uses native ModbusTcpClient (no pymodbus).

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from industrialxpl.core.exploit import *
from industrialxpl.protocols.modbus_tcp import ModbusTcpClient, FC_RISK

__version__ = "1.0.0"

# Max read sizes per Modbus spec
MAX_COILS_PER_READ = 2000
MAX_REGISTERS_PER_READ = 125


class Exploit(Exploit):
    """Modbus Register Mapper - enumerate all accessible registers and coils.

    Reads all Modbus register types (FC01/02/03/04) across the full address
    space in chunks of 125 registers / 2000 coils. Produces a structured map
    useful for ICS security assessments.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    """

    __info__ = {
        "name": "Modbus Register Mapper",
        "description": (
            "Enumerates all Modbus register types (coils, discrete inputs, "
            "holding registers, input registers) using chunked reads. "
            "Produces a complete register map for ICS security assessment."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "Modbus Application Protocol Specification V1.1b3",
            "MITRE ATT&CK ICS T0846 Remote System Discovery",
            "submodules/OT/BusPwn/pwn.py (enumeration logic)",
        ),
        "targets": ("Modbus/TCP slaves, PLCs, RTUs, gateways",),
        "cve": "",
        "cvss": 5.0,
        "mitre_techniques": ["T0846"],
        "mitre_tactics": ["Collection"],
        "impact": "MEDIUM - Read-only enumeration of process data",
        "safe_mode": True,
    }

    rhost = OptString("", "Target Modbus/TCP host IP")
    rport = OptInteger(502, "Modbus/TCP port (default 502)")
    unit_id = OptInteger(1, "Modbus Unit ID (1-255)")
    start_addr = OptInteger(0, "Starting address (default 0)")
    end_addr = OptInteger(9999, "Ending address (default 9999)")
    timeout = OptFloat(3.0, "Socket timeout per request")
    delay_ms = OptInteger(50, "Delay between requests in milliseconds")
    output_json = OptString("", "Path to save JSON map (empty = no file)")
    types = OptString("holding,input,coils,discrete", "Register types to map (comma-separated)")

    def check(self) -> bool:
        """Verify Modbus TCP connectivity to target."""
        host = str(self.rhost).strip()
        if not host:
            print("[-] Set rhost.")
            return False
        client = ModbusTcpClient(host=host, port=int(self.rport), unit_id=int(self.unit_id))
        connected = client.connect()
        if connected:
            resp = client.read_holding_registers(start=0, count=1)
            client.disconnect()
            if resp.success or resp.is_exception:
                print(f"[+] Modbus/TCP reachable at {host}:{self.rport} (unit {self.unit_id})")
                return True
        print(f"[-] Cannot reach Modbus/TCP at {host}:{self.rport}")
        return False

    def run(self) -> None:
        """Map all registers in the configured range."""
        host = str(self.rhost).strip()
        if not host:
            print("[-] Set rhost.")
            return

        client = ModbusTcpClient(
            host=host,
            port=int(self.rport),
            unit_id=int(self.unit_id),
            timeout=float(self.timeout),
        )
        if not client.connect():
            print(f"[-] Cannot connect to {host}:{self.rport}")
            return

        start = int(self.start_addr)
        end = int(self.end_addr)
        delay = int(self.delay_ms) / 1000.0
        types_requested = [t.strip().lower() for t in str(self.types).split(",")]
        register_map: Dict[str, Any] = {
            "host": host,
            "port": int(self.rport),
            "unit_id": int(self.unit_id),
            "range": f"{start}-{end}",
        }

        type_configs = []
        if "holding" in types_requested:
            type_configs.append(("holding_registers", client.read_holding_registers, MAX_REGISTERS_PER_READ))
        if "input" in types_requested:
            type_configs.append(("input_registers", client.read_input_registers, MAX_REGISTERS_PER_READ))
        if "coils" in types_requested:
            type_configs.append(("coils", client.read_coils, MAX_COILS_PER_READ))
        if "discrete" in types_requested:
            type_configs.append(("discrete_inputs", client.read_discrete_inputs, MAX_COILS_PER_READ))

        for reg_type, read_fn, chunk_size in type_configs:
            print(f"[*] Mapping {reg_type} ({start}-{end})...")
            values: Dict[int, Any] = {}
            addr = start

            while addr <= end:
                count = min(chunk_size, end - addr + 1)
                resp = read_fn(start=addr, count=count)

                if resp.success and resp.values:
                    for i, v in enumerate(resp.values):
                        values[addr + i] = v
                elif resp.is_exception:
                    # Exception code 2 = illegal addr, stop this chunk range
                    if resp.exception_code == 2:
                        addr += chunk_size
                        continue
                    # Exception code 1 = FC not supported, skip this type
                    if resp.exception_code == 1:
                        print(f"    FC not supported for {reg_type}, skipping.")
                        break

                addr += count
                if delay > 0:
                    time.sleep(delay)

            register_map[reg_type] = {
                "count": len(values),
                "data": {str(k): v for k, v in values.items()},
            }
            print(f"    Found {len(values)} values in {reg_type}")

        client.disconnect()

        print()
        print(f"[+] Register map complete for {host}:{self.rport} unit {self.unit_id}")
        for rt in ["holding_registers", "input_registers", "coils", "discrete_inputs"]:
            if rt in register_map:
                print(f"    {rt:<25} {register_map[rt]['count']:>6} values")

        out_path = str(self.output_json).strip()
        if out_path:
            try:
                with open(out_path, "w") as f:
                    json.dump(register_map, f, indent=2)
                print(f"[+] Map saved to: {out_path}")
            except Exception as exc:
                print(f"[-] Could not save map: {exc}")

        return register_map
