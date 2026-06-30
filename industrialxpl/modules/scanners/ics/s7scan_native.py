"""S7 rack/LLC scanner — F03 native module."""
from industrialxpl.core.exploit import Exploit, OptBool, OptIP, mute, print_table, print_warning
from industrialxpl.core.ics.s7_llc import rack_scan_plan, scan_racks


class Exploit(Exploit):
    __info__ = {"name": "S7 LLC Rack Scanner (IXF MIT)", "impact": "LOW", "exploit_type": "ICS Discovery"}

    target = OptIP("", "Target PLC IP")
    simulate = OptBool(True, "Simulate rack scan")

    @mute
    def check(self):
        return True

    def run(self):
        host = str(self.target or "127.0.0.1")
        plan = scan_racks(host, simulate=True) if self.simulate else scan_racks(host, simulate=False)
        print_warning("[S7scan] {} — {} combos".format(host, plan.get("count", plan.get("found", 0))))
        if plan.get("combos"):
            rows = [[c["rack"], c["slot"], c["cotp_hex"][:24]] for c in plan["combos"][:8]]
            print_table(["rack", "slot", "cotp"], rows)
