"""IXF native ICS fuzzer — protofire / ics-scada-fuzzer inspired (MIT reimplementation).

Usage (simulate default):
  ixf > use scanners/ics/fuzz_native
  ixf (fuzz) > set protocol modbus
  ixf (fuzz) > run
"""
from __future__ import annotations

from industrialxpl.core.exploit import (
    DestructiveGate,
    Exploit,
    OptBool,
    OptInteger,
    OptIP,
    OptPort,
    OptString,
    mute,
    print_error,
    print_info,
    print_status,
    print_table,
    print_warning,
)
from industrialxpl.core.ics.fuzz_engine import STRATEGY_NAMES, fuzz_campaign, mutate
from industrialxpl.core.malware.compiler import MalwareCompiler


class Exploit(Exploit):
    __info__ = {
        "name": "ICS Native Protocol Fuzzer (IXF MIT)",
        "description": (
            "8 mutation strategies for Modbus TCP and S7comm probe frames. "
            "Native C smoke targets: fuzz_modbus_smoke, fuzz_s7_smoke."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/ridpath/protofire",
            "https://github.com/ridpath/ics-scada-fuzzer",
        ),
        "devices": ("Modbus TCP PLCs", "S7 PLCs", "ICS protocol gateways"),
        "impact": "HIGH",
        "exploit_type": "ICS Fuzzing Lab",
        "mitre_techniques": ["T0897", "T0814"],
        "mitre_tactics": ["Discovery", "Denial of Service"],
        "destructive_description": "Would send mutated {protocol} frames to {target}:{port}.",
    }

    target = OptIP("", "Target IP (required for live fuzz)")
    port = OptPort(502, "Target port")
    protocol = OptString("modbus", "Protocol: modbus | s7")
    strategy = OptInteger(-1, "Strategy 0-7 or -1 for all")
    seed = OptInteger(42, "Mutation seed")
    simulate = OptBool(True, "Simulate — print payloads only")
    destructive = OptBool(False, "Send mutated frames (lab only)")

    @mute
    def check(self):
        if self.simulate:
            return True
        return bool(self.target)

    def run(self):
        proto = (self.protocol or "modbus").strip().lower()
        if proto not in ("modbus", "s7"):
            print_error("protocol must be modbus or s7")
            return

        camp = fuzz_campaign("modbus" if proto == "modbus" else "s7", seed=int(self.seed))
        comp = MalwareCompiler()
        comp.refresh()
        native_ok = all(
            comp.compile(t).get("success")
            for t in ("fuzz_modbus_smoke", "fuzz_s7_smoke")
        )

        if self.simulate or not self.destructive:
            print_warning("\n[IXF Fuzzer] simulate — {} / 8 strategies\n".format(proto))
            rows = [[c["strategy"], c["name"], c["len"], c["hex"][:48]] for c in camp["cases"]]
            if int(self.strategy) >= 0:
                s = int(self.strategy) % 8
                rows = [r for r in rows if r[0] == s]
            print_table(["id", "strategy", "len", "hex"], rows)
            print_info("Native compile smoke: {}".format("OK" if native_ok else "FAIL (need gcc)"))
            DestructiveGate.print_simulation(
                description="Fuzz campaign base={} strategies={}".format(
                    camp["base_hex"][:32], camp["strategies"]
                ),
                mitre_techniques=["T0897", "T0814"],
            )
            return

        if not self.target:
            print_error("Set target for live fuzz.")
            return
        print_warning("[IXF Fuzzer] LIVE — sending is not enabled; use protocol modules with care.")
        print_status("Generated payload: {}".format(
            camp["cases"][0]["hex"] if camp["cases"] else ""
        ))
