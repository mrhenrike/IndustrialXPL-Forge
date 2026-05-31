"""IXF Scanner — Omron FINS/TCP Discovery. simulate=True."""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,
    print_error, print_status, print_info, print_table, print_success,
)
class Exploit(Exploit):
    __info__ = {
        "name": "Omron FINS/TCP Scanner",
        "description": "Discover and fingerprint Omron FINS/TCP devices on OT network.",
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": ('https://www.cisa.gov/uscert/ics/advisories/icsa-23-131-05',),
        "devices": ("Omron FINS/TCP",),
        "impact": "LOW", "exploit_type": "Scanner / Fingerprint",
        "cve": "N/A", "cvss": "N/A", "severity": "INFO",
        "mitre_techniques": ["T0888", "T0802"], "mitre_tactics": ["Discovery"],
    }
    target  = OptIP("", "Target IP")
    port    = OptPort(9600, "FINS/TCP port")
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
        print_status(f"[Omron] Scanning {self.target}:{self.port}...")
        results = []
        try:
            s = socket.socket(); s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            s.send(b"46494e53")
            banner = s.recv(256)
            s.close()
            results.append(("Omron FINS/TCP", f"{self.target}:{self.port}", "Detected", banner[:32].hex()))
        except Exception as e:
            results.append(("Omron FINS/TCP", f"{self.target}:{self.port}", "Unreachable", str(e)[:30]))
        if results:
            print_table(["Device","Address","Status","Banner"], results, title="Omron Scan")
        print_info("Known CVEs: CVE-2023-27396, missing auth by design")
