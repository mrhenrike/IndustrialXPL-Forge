"""IXF Scanner — CODESYS V3 Runtime Discovery. simulate=True."""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,
    print_error, print_status, print_info, print_table, print_success,
)
class Exploit(Exploit):
    __info__ = {
        "name": "CODESYS V3 Runtime Scanner",
        "description": "Discover and fingerprint CODESYS V3 Runtime devices on OT network.",
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": ('https://www.codesys.com/',),
        "devices": ("CODESYS V3 Runtime",),
        "impact": "LOW", "exploit_type": "Scanner / Fingerprint",
        "cve": "N/A", "cvss": "N/A", "severity": "INFO",
        "mitre_techniques": ["T0888", "T0802"], "mitre_tactics": ["Discovery"],
    }
    target  = OptIP("", "Target IP")
    port    = OptPort(11740, "CMP port")
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
        print_status(f"[CODESYS] Scanning {self.target}:{self.port}...")
        results = []
        try:
            s = socket.socket(); s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            s.send(b"12000000")
            banner = s.recv(256)
            s.close()
            results.append(("CODESYS V3 Runtime", f"{self.target}:{self.port}", "Detected", banner[:32].hex()))
        except Exception as e:
            results.append(("CODESYS V3 Runtime", f"{self.target}:{self.port}", "Unreachable", str(e)[:30]))
        if results:
            print_table(["Device","Address","Status","Banner"], results, title="CODESYS Scan")
        print_info("Known CVEs: CVE-2022-47379, CVE-2022-31806")
