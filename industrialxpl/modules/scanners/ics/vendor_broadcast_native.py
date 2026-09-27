"""OT vendor broadcast scanner — F04 native module."""
from industrialxpl.core.exploit import Exploit, OptBool, OptIP, mute, print_table, print_warning
from industrialxpl.core.ics.vendors import VENDOR_NAMES, simulate_all


class Exploit(Exploit):
    __info__ = {"name": "OT Vendor Broadcast (IXF MIT)", "impact": "LOW", "exploit_type": "ICS Discovery"}

    target = OptIP("", "Target IP")
    simulate = OptBool(True, "Simulate vendor probes")

    @mute
    def check(self):
        return True

    def run(self):
        host = str(self.target or "127.0.0.1")
        plan = simulate_all(host)
        print_warning("[Vendors] {} vendors on {}".format(len(VENDOR_NAMES), host))
        print_table(["vendor", "fn"], [[v, plan["results"][v]["fn"]] for v in VENDOR_NAMES])
