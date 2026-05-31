"""IXF Scanner — Generic IEC 60870-5-104 RTU/SCADA Discovery. simulate=True."""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,
    print_error, print_status, print_info, print_table, print_success,
)
class Exploit(Exploit):
    __info__ = {
        "name": "Generic IEC 60870-5-104 RTU/SCADA Scanner",
        "description": "Discover and fingerprint Generic IEC 60870-5-104 RTU/SCADA devices on OT network.",
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": ('https://www.iec.ch/',),
        "devices": ("Generic IEC 60870-5-104 RTU/SCADA",),
        "impact": "LOW", "exploit_type": "Scanner / Fingerprint",
        "cve": "N/A", "cvss": "N/A", "severity": "INFO",
        "mitre_techniques": ["T0888", "T0802"], "mitre_tactics": ["Discovery"],
    }
    target  = OptIP("", "Target IP")
    port    = OptPort(2404, "IEC 104 port")
    timeout = OptInteger(5, "Timeout (sec)")
    simulate = OptBool(True, "Simulate (default: True)")
    destructive = OptBool(False, "Live")
    @mute
    def check(self):
        if not self.target: return False
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect((self.target, self.port)); s.close(); return True
        except: return False
    def run(self):
        if not self.target: print_error("Set target"); return
        print_status(f"[Generic] Scanning {self.target}:{self.port}...")
        results = []
        try:
            s = socket.socket(); s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            s.send(b"680407000000")
            banner = s.recv(256)
            s.close()
            results.append(("Generic IEC 60870-5-104 RTU/SCADA", f"{self.target}:{self.port}", "Detected", banner[:32].hex()))
        except Exception as e:
            results.append(("Generic IEC 60870-5-104 RTU/SCADA", f"{self.target}:{self.port}", "Unreachable", str(e)[:30]))
        if results:
            print_table(["Device","Address","Status","Banner"], results, title="Generic Scan")
        print_info("Known CVEs: CosmicEnergy, Industroyer2 vector")
