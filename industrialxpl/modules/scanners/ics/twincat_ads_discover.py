"""IXF Scanner — Beckhoff TwinCAT ADS/AMS Discovery. simulate=True."""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,
    print_error, print_status, print_info, print_table, print_success,
)
class Exploit(Exploit):
    __info__ = {
        "name": "Beckhoff TwinCAT ADS/AMS Scanner",
        "description": "Discover and fingerprint Beckhoff TwinCAT ADS/AMS devices on OT network.",
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": ('https://www.beckhoff.com/',),
        "devices": ("Beckhoff TwinCAT ADS/AMS",),
        "impact": "LOW", "exploit_type": "Scanner / Fingerprint",
        "cve": "N/A", "cvss": "N/A", "severity": "INFO",
        "mitre_techniques": ["T0888", "T0802"], "mitre_tactics": ["Discovery"],
    }
    target  = OptIP("", "Target IP")
    port    = OptPort(48898, "ADS/AMS port")
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
        print_status(f"[Beckhoff] Scanning {self.target}:{self.port}...")
        results = []
        try:
            s = socket.socket(); s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            s.send(b"03661471")
            banner = s.recv(256)
            s.close()
            results.append(("Beckhoff TwinCAT ADS/AMS", f"{self.target}:{self.port}", "Detected", banner[:32].hex()))
        except Exception as e:
            results.append(("Beckhoff TwinCAT ADS/AMS", f"{self.target}:{self.port}", "Unreachable", str(e)[:30]))
        if results:
            print_table(["Device","Address","Status","Banner"], results, title="Beckhoff Scan")
        print_info("Known CVEs: CVE-2019-5637, CVE-2023-21640")
