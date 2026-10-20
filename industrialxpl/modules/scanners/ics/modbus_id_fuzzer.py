# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""Modbus Unit ID Fuzzer — brute-force slave ID discovery.

Scans all (or a subset of) Modbus Unit IDs on a target Modbus gateway
to discover which slave addresses have active devices.

Supports port ranges and T0-T5 timing profiles.
"""


from industrialxpl.core.exploit import (
    OptInteger, mute, print_error, print_info, print_status, print_success,
)
from industrialxpl.core.modbus.base import ModbusBaseExploit
from industrialxpl.core.modbus.transport import ModbusTCPSocket, modbus_connect


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

        sim = getattr(self, "_simulate_mode", self.simulate)

        print_info(f"  Target  : {self.target}")
        print_info("  Port(s) : {}".format(", ".join(str(p) for p in ports)))
        print_info(f"  UID range: {self.start_id}-{self.end_id}")
        self._print_timing()
        self._print_address_plan(addresses, fc)
        print_info("")

        if sim:
            total = self.end_id - self.start_id + 1
            print_info(f"[SIMULATE] Would fuzz {total} Unit IDs on {len(ports)} port(s) with FC{fc:02d} (TCP check only)")
            for port in ports:
                sock = modbus_connect(self.target, port, timing.socket_timeout)
                if sock:
                    sock.close()
                    print_success(f"[SIMULATE] {self.target}:{port} — port open")
                else:
                    print_info(f"[SIMULATE] {self.target}:{port} — closed / no response")
            return

        for port in ports:
            found: list[int] = []
            total = self.end_id - self.start_id + 1
            print_status(f"Fuzzing {self.target}:{port} UIDs {self.start_id}-{self.end_id} ({total} total)...")
            for uid in range(self.start_id, self.end_id + 1):
                print(f"\r[*] Testing UID {uid:3d} ({uid - self.start_id + 1}/{total})", end="", flush=True)
                with ModbusTCPSocket(self.target, port, uid, timing) as sock:
                    if not sock._sock:
                        timing.sleep()
                        continue
                    resp = sock.send_fc(fc, start_a, min(qty, 8))
                    if resp and len(resp) >= 7 and not (resp[7] & 0x80 and resp[8] == 0x0B):
                        found.append(uid)
                        print("\r" + " " * 40, end="\r")
                        print_success(f"  Active UID {uid:3d}: FC{fc:02d} responded")
                timing.sleep()
            print("\r" + " " * 40, end="\r")

            if found:
                print_success(f"Found {len(found)} active Unit ID(s) on {self.target}:{port}: {found}")
            else:
                print_info(f"No active UIDs found on {self.target}:{port}")

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
