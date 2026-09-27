#!/usr/bin/env python3
"""CVE Wave 4 — Additional global OT/ICS vendors (15 new CVEs)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
MODULES_DIR = ROOT / "industrialxpl" / "modules" / "cve"

TEMPLATE = '"""IXF CVE {cve} — {vendor} {product}.\nCVSS: {cvss} ({severity}) | simulate=True default.\n"""\nimport socket\nfrom industrialxpl.core.exploit import (\n    Exploit, OptBool, OptIP, OptPort, mute,\n    print_error, print_info, print_status, DestructiveGate,\n)\nclass Exploit(Exploit):\n    __info__ = {{\n        "name":             "{cve} {vendor} {product}",\n        "description":     "{desc}",\n        "authors":          ("Andre Henrique (@mrhenrike)",),\n        "references":       {refs},\n        "devices":          ("{vendor} {product}",),\n        "impact":           "{impact}",\n        "exploit_type":     "{xtype}",\n        "cve":              "{cve}",\n        "cvss":             "{cvss}",\n        "severity":         "{severity}",\n        "mitre_techniques": {mitre},\n        "mitre_tactics":    {tactics},\n    }}\n    target = OptIP("", "Target IP")\n    port = OptPort({port}, "Port")\n    simulate = OptBool(True, "Simulate (default: True)")\n    destructive = OptBool(False, "Live exploitation")\n    @mute\n    def check(self):\n        if not self.target: return False\n        try:\n            s = socket.socket(); s.settimeout(5)\n            s.connect((self.target, self.port)); s.close(); return True\n        except: return False\n    def run(self):\n        if not self.target:\n            print_error("Set target"); return\n        if self.simulate:\n            DestructiveGate.print_simulation(\n                description="{cve} {vendor} {product}\\nCVSS {cvss}\\n{sim}",\n                mitre_techniques={mitre},\n            )\n            return\n        print_status("[{cve}] Exploiting {{}}:{{}}...".format(self.target, self.port))\n        print_info("Live exploit: implement protocol-specific code")\n'

BATCH = [
    dict(subdir="panasonic", f="cve_2022_3643_fp7_rce.py",
         cve="CVE-2022-3643", vendor="Panasonic", product="FP7 PLC", port=9094,
         cvss="9.8", severity="CRITICAL", impact="CRITICAL", xtype="Web UI Buffer Overflow RCE",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-22-270-09"],
         mitre=["T0866"], tactics=["Initial Access"],
         desc="Panasonic FP7 PLC web interface buffer overflow leading to remote code execution",
         sim="Connect port 9094, send oversized request, buffer overflow, RCE on PLC CPU"),

    dict(subdir="mitsubishi", f="cve_2023_4088_melsec_iqr_dos.py",
         cve="CVE-2023-4088", vendor="Mitsubishi Electric", product="MELSEC iQ-R Series", port=5007,
         cvss="7.5", severity="HIGH", impact="HIGH", xtype="Denial of Service",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-23-227-02"],
         mitre=["T0814"], tactics=["Inhibit Response Function"],
         desc="MELSEC iQ-R CPU enters STOP mode when receiving malformed SLMP packet",
         sim="Send malformed SLMP frame to port 5007, CPU transitions to STOP state"),

    dict(subdir="ge", f="cve_2021_27453_ifix_path_traversal.py",
         cve="CVE-2021-27453", vendor="GE", product="iFIX SCADA", port=8080,
         cvss="9.8", severity="CRITICAL", impact="CRITICAL", xtype="Path Traversal to RCE",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-21-180-04"],
         mitre=["T0866"], tactics=["Initial Access"],
         desc="GE iFIX SCADA path traversal via web server allows arbitrary file read and RCE",
         sim="GET /../../iFIX/project/*.fxg on port 8080, read SCADA project including credentials"),

    dict(subdir="advantech", f="cve_2022_3221_webaccess_sqli.py",
         cve="CVE-2022-3221", vendor="Advantech", product="WebAccess/SCADA", port=4592,
         cvss="9.8", severity="CRITICAL", impact="CRITICAL", xtype="SQL Injection",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-22-270-02"],
         mitre=["T0819", "T0832"], tactics=["Initial Access"],
         desc="Advantech WebAccess SQL injection allowing authentication bypass and data exfiltration",
         sim="POST SQLi to WebAccess login endpoint port 4592, extract user credentials and SCADA tags"),

    dict(subdir="codesys", f="cve_2022_47379_v3_heap_overflow.py",
         cve="CVE-2022-47379", vendor="CODESYS", product="V3 Runtime", port=11740,
         cvss="9.8", severity="CRITICAL", impact="CRITICAL", xtype="Heap Overflow RCE",
         refs=["https://customers.codesys.com/index.php?eID=dumpFile&t=f&f=18802"],
         mitre=["T0866"], tactics=["Initial Access"],
         desc="CODESYS V3 runtime heap overflow via crafted CMP protocol packet allows RCE",
         sim="Send crafted CMP protocol packet to CODESYS V3 port 11740, heap overflow, RCE"),

    dict(subdir="osisoft", f="cve_2023_31176_pi_archive_auth_bypass.py",
         cve="CVE-2023-31176", vendor="AVEVA/OSIsoft", product="PI Data Archive", port=5450,
         cvss="9.8", severity="CRITICAL", impact="CRITICAL", xtype="Authentication Bypass",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-23-159-05"],
         mitre=["T0803", "T0832"], tactics=["Collection"],
         desc="AVEVA PI Data Archive authentication bypass grants full historian database access",
         sim="Connect to PI Data Archive port 5450, bypass kerberos/basic auth, read all process history"),

    dict(subdir="hitachi", f="cve_2022_30793_relion_670_rce.py",
         cve="CVE-2022-30793", vendor="Hitachi Energy", product="Relion 670 Series", port=102,
         cvss="9.8", severity="CRITICAL", impact="CATASTROPHIC", xtype="IEC 61850 MMS RCE",
         refs=["https://search.abb.com/library/Download.aspx?DocumentID=9AKK107991A3764"],
         mitre=["T0827", "T0826"], tactics=["Impact"],
         desc="Hitachi Energy Relion 670 protection relay RCE via crafted IEC 61850 MMS packet",
         sim="Connect MMS ISO-TSAP port 102, send crafted INITIATE PDU, buffer overflow, RCE on relay"),

    dict(subdir="moxa", f="cve_2022_26022_nport5000_cmd_injection.py",
         cve="CVE-2022-26022", vendor="Moxa", product="NPort 5000A Series", port=80,
         cvss="9.8", severity="CRITICAL", impact="CRITICAL", xtype="Command Injection RCE",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-22-270-06"],
         mitre=["T0866", "T0822"], tactics=["Initial Access"],
         desc="Moxa NPort 5000A serial-to-Ethernet gateway web interface command injection leading to root shell",
         sim="POST malicious parameter to NPort web UI on port 80, command injection, OS root shell"),

    dict(subdir="tridium", f="cve_2023_36388_niagara4_deserialization.py",
         cve="CVE-2023-36388", vendor="Tridium", product="Niagara 4 Framework", port=4911,
         cvss="9.8", severity="CRITICAL", impact="CRITICAL", xtype="Java Deserialization RCE",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-23-213-01"],
         mitre=["T0866"], tactics=["Initial Access"],
         desc="Tridium Niagara 4 Java deserialization via Fox protocol allows unauthenticated RCE",
         sim="Connect Fox protocol port 4911, send deserialization gadget chain, RCE on Niagara server"),

    dict(subdir="siemens", f="cve_2023_29054_wincc_sql_rce.py",
         cve="CVE-2023-29054", vendor="Siemens", product="SIMATIC WinCC", port=1433,
         cvss="9.8", severity="CRITICAL", impact="CRITICAL", xtype="SQL Injection to RCE",
         refs=["https://cert-portal.siemens.com/productcert/html/ssa-552702.html"],
         mitre=["T0819", "T0822"], tactics=["Initial Access"],
         desc="Siemens SIMATIC WinCC SQL injection in web UI allows xp_cmdshell execution via SQL Server",
         sim="POST SQL injection payload to WinCC web login, exec xp_cmdshell via SQL Server, OS RCE"),

    dict(subdir="prosoft", f="cve_2022_3384_radiolinx_rce.py",
         cve="CVE-2022-3384", vendor="ProSoft Technology", product="RadioLinx ControlScape", port=80,
         cvss="9.8", severity="CRITICAL", impact="CRITICAL", xtype="Authentication Bypass to RCE",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-22-287-02"],
         mitre=["T0866"], tactics=["Initial Access"],
         desc="ProSoft RadioLinx ControlScape wireless gateway authentication bypass leading to RCE",
         sim="Access ControlScape web UI port 80, bypass auth via crafted session, execute commands"),

    dict(subdir="emerson", f="cve_2022_29953_openbsi_dcom_rce.py",
         cve="CVE-2022-29953", vendor="Emerson", product="OpenBSI DCS", port=135,
         cvss="9.8", severity="CRITICAL", impact="CRITICAL", xtype="DCOM RCE",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-22-200-01"],
         mitre=["T0866"], tactics=["Initial Access"],
         desc="Emerson OpenBSI DCS DCOM interface allows unauthenticated remote code execution",
         sim="Connect DCOM port 135, call OpenBSI RPC interface without auth, RCE on DCS server"),

    dict(subdir="schneider", f="cve_2023_37196_ecostruxure_sqli.py",
         cve="CVE-2023-37196", vendor="Schneider Electric", product="EcoStruxure IT Expert", port=443,
         cvss="9.8", severity="CRITICAL", impact="CRITICAL", xtype="SQL Injection Auth Bypass",
         refs=["https://www.se.com/ww/en/download/document/SEVD-2023-269-01/"],
         mitre=["T0819"], tactics=["Initial Access"],
         desc="Schneider Electric EcoStruxure IT Expert SQL injection leading to authentication bypass",
         sim="POST SQLi payload to login endpoint, bypass authentication, access OT infrastructure management"),

    dict(subdir="aspentech", f="cve_2021_38160_infoplus21_bof.py",
         cve="CVE-2021-38160", vendor="AspenTech", product="Aspen InfoPlus.21 Historian", port=10014,
         cvss="9.8", severity="CRITICAL", impact="CRITICAL", xtype="Buffer Overflow RCE",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-21-252-01"],
         mitre=["T0803", "T0822"], tactics=["Initial Access"],
         desc="AspenTech Aspen InfoPlus.21 historian service buffer overflow via crafted network packet",
         sim="Send oversized packet to InfoPlus.21 API port 10014, buffer overflow, RCE on historian"),

    dict(subdir="beckhoff", f="cve_2023_21640_twincat_ads_dos.py",
         cve="CVE-2023-21640", vendor="Beckhoff", product="TwinCAT/BSD ADS", port=48898,
         cvss="7.5", severity="HIGH", impact="HIGH", xtype="Denial of Service",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-23-054-03"],
         mitre=["T0814"], tactics=["Inhibit Response Function"],
         desc="Beckhoff TwinCAT ADS service crash via malformed AMS/ADS protocol packet",
         sim="Send malformed ADS packet to port 48898, ADS service crashes, PLC comms lost"),
]

def make(b):
    d = MODULES_DIR / b["subdir"]
    d.mkdir(parents=True, exist_ok=True)
    (d / "__init__.py").touch(exist_ok=True)
    f = d / b["f"]
    if f.exists():
        return False
    content = TEMPLATE.format(
        cve=b["cve"], vendor=b["vendor"], product=b["product"],
        port=b["port"], cvss=b["cvss"], severity=b["severity"],
        impact=b["impact"], xtype=b["xtype"],
        refs=str(tuple(b["refs"])),
        mitre=str(b["mitre"]), tactics=str(b["tactics"]),
        desc=b["desc"][:180], sim=b["sim"],
    )
    f.write_text(content, encoding="utf-8")
    return True

def main():
    created = 0
    for b in BATCH:
        if make(b):
            created += 1
            print(f"  {b['f']}")
    from industrialxpl.core.exploit.utils import index_modules
    mods = index_modules()
    print(f"\n[wave4] Created: {created} | Total: {len(mods)}")

if __name__ == "__main__":
    main()
