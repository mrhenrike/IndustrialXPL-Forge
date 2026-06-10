# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Modbus Unit ID Fuzzer — brute-force slave ID discovery.

Scans all (or a subset of) Modbus Unit IDs on a target Modbus gateway
to discover which slave addresses have active devices.

Supports port ranges and T0-T5 timing profiles.
"""

from typing import List

from industrialxpl.core.exploit import (
    OptInteger, mute, print_error, print_info, print_status, print_success,
)
from industrialxpl.core.modbus.base import ModbusBaseExploit
from industrialxpl.core.modbus.transport import ModbusTCPSocket, modbus_connect
import struct


class Exploit(ModbusBaseExploit):
    """Modbus Unit ID Fuzzer — discovers active slave IDs on a Modbus gateway."""

    __info__ = {
        "name": "Modbus Unit ID Fuzzer (Slave Discovery)",
        "description": (
            "Probes Modbus Unit IDs on a gateway to find active slave addresses. "
            "Supports port ranges and T0-T5 timing profiles."
        ),
        "authors": (
            "ModBusSploit contributors",
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (
            "https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",
            "https://attack.mitre.org/techniques/T0846/",
        ),
        "devices": (
            "Modbus-to-TCP gateway",
            "Modbus multi-drop serial network bridge",
            "Any Modbus/TCP server with multiple slave IDs",
        ),
        "impact":   "READ",
        "severity": "INFO",
        "mitre":    ["T0846"],
    }

    _DEFAULT_FC   = 1
    _DEFAULT_REGS = "0-7"

    start_id = OptInteger(0,   "Starting Unit ID to fuzz (0-255)", min_value=0, max_value=255)
    end_id   = OptInteger(247, "Ending Unit ID to fuzz (0-255)",   min_value=0, max_value=255)

    def run(self) -> None:
        ports  = self._get_ports()
        timing = self._get_timing()
        addresses = self._get_addresses()
        fc      = self._resolve_fc(addresses.implied_fc)
        start_a, qty = addresses.as_bulk()

        print_info("  Target  : {}".format(self.target))
        print_info("  Port(s) : {}".format(", ".join(str(p) for p in ports)))
        print_info("  UID range: {}-{}".format(self.start_id, self.end_id))
        self._print_timing()
        self._print_address_plan(addresses, fc)
        print_info("")

        for port in ports:
            found: List[int] = []
            total = self.end_id - self.start_id + 1
            print_status("Fuzzing {}:{} UIDs {}-{} ({} total)...".format(
                self.target, port, self.start_id, self.end_id, total
            ))
            for uid in range(self.start_id, self.end_id + 1):
                print("\r[*] Testing UID {:3d} ({}/{})".format(uid, uid - self.start_id + 1, total), end="", flush=True)
                with ModbusTCPSocket(self.target, port, uid, timing) as sock:
                    if not sock._sock:
                        timing.sleep()
                        continue
                    resp = sock.send_fc(fc, start_a, min(qty, 8))
                    if resp and len(resp) >= 7 and not (resp[7] & 0x80 and resp[8] == 0x0B):
                        found.append(uid)
                        print("\r" + " " * 40, end="\r")
                        print_success("  Active UID {:3d}: FC{:02d} responded".format(uid, fc))
                timing.sleep()
            print("\r" + " " * 40, end="\r")

            if found:
                print_success("Found {} active Unit ID(s) on {}:{}: {}".format(
                    len(found), self.target, port, found
                ))
            else:
                print_info("No active UIDs found on {}:{}".format(self.target, port))

    @mute
    def check(self) -> bool:
        ports  = self._get_ports()
        timing = self._get_timing()
        for port in ports:
            sock = modbus_connect(self.target, port, timing.socket_timeout)
            if sock:
                sock.close()
                return True
        return False
