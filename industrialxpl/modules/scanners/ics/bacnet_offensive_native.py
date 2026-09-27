"""BACnet offensive lab — F05 native module."""
from industrialxpl.core.exploit import Exploit, OptBool, mute, print_info, print_warning
from industrialxpl.core.ics.bacnet_offensive import simulate_campaign
from industrialxpl.core.ics_tools.native_handlers import run_native


class Exploit(Exploit):
    __info__ = {"name": "BACteria BACnet Lab (IXF MIT)", "impact": "LOW", "exploit_type": "ICS Discovery"}

    simulate = OptBool(True, "Simulate BACnet frames")

    @mute
    def check(self):
        return True

    def run(self):
        camp = simulate_campaign()
        nat = run_native("bacteria", simulate=True)
        print_warning("[BACteria] simulate — {} frames".format(len(camp.get("frames", {}))))
        print_info(nat.get("would_run") if nat else "n/a")
