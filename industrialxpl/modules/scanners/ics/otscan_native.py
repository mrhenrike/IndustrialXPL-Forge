"""IXF native OT unified scanner — otscan-inspired (MIT stdlib probes).

Usage (simulate default):
  ixf > use scanners/ics/otscan_native
  ixf (otscan) > set target 192.168.1.10
  ixf (otscan) > run
"""
from __future__ import annotations

from industrialxpl.core.exploit import (
    DestructiveGate,
    Exploit,
    OptBool,
    OptIP,
    OptString,
    mute,
    print_error,
    print_info,
    print_status,
    print_table,
    print_warning,
)
from industrialxpl.core.ics.otscan import PROTOCOLS, scan, simulate_scan
from industrialxpl.core.ics_tools.native_handlers import run_native


class Exploit(Exploit):
    __info__ = {
        "name": "OT Unified Scanner (IXF MIT / otscan-inspired)",
        "description": (
            "Multi-protocol OT identify: modbus, s7, iec104, bacnet, dnp3, opc-ua, "
            "enip, fox, fins, codesys, hart-ip, mqtt, profinet."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://sundi133.github.io/otscan",),
        "devices": ("ICS/OT gateways", "PLCs", "BACnet controllers", "SCADA hosts"),
        "impact": "LOW",
        "exploit_type": "ICS Discovery",
        "mitre_techniques": ["T0846", "T0888"],
        "mitre_tactics": ["Discovery"],
        "destructive_description": "Would probe {target} for OT protocols ({protocols}).",
    }

    target = OptIP("", "Target IP (required for live scan)")
    protocols = OptString("", "Comma-separated protocols (empty = all 13)")
    simulate = OptBool(True, "Simulate — probe plan only")
    destructive = OptBool(False, "Run live protocol probes (lab only)")

    @mute
    def check(self):
        if self.simulate or not self.destructive:
            return True
        return bool(self.target)

    def run(self):
        proto_list = None
        if self.protocols:
            proto_list = [p.strip() for p in str(self.protocols).split(",") if p.strip()]

        host = str(self.target or "127.0.0.1")
        live = bool(self.destructive and self.target and not self.simulate)

        if not live:
            plan = simulate_scan(host, proto_list)
            selected = plan.get("protocols", list(PROTOCOLS))
            print_warning("\n[OTscan] simulate — {} protocols on {}\n".format(len(selected), host))
            rows = [[p, plan["results"][p].get("would_run", "probe")] for p in selected]
            print_table(["protocol", "probe_fn"], rows)
            native = run_native("otscan", simulate=True)
            print_info("ics_tools native: {}".format(native.get("would_run") if native else "n/a"))
            DestructiveGate.print_simulation(
                description="OTscan {} protocols on {}".format(len(selected), host),
                mitre_techniques=["T0846", "T0888"],
            )
            return

        print_status("[OTscan] LIVE probe on {}".format(host))
        result = scan(host, proto_list, simulate=False)
        rows = []
        for proto, detail in result.get("results", {}).items():
            rows.append([
                proto,
                "yes" if detail.get("detected") else "no",
                detail.get("detail") or detail.get("error") or "",
            ])
        print_table(["protocol", "detected", "detail"], rows)
        print_info("Detected {}/{}".format(result.get("detected_count", 0), len(result.get("protocols", []))))
