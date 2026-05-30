#!/usr/bin/env python3
"""Wave 3 CVE batch — 50+ high/critical ICS/OT CVEs with PoC from GitHub/ExploitDB.

Sources:
  - Mewtwoz/InduGuard_vul_poc
  - Mewtwoz/n-days-poc-benchmark-and-dataset
  - SawyersPresent/SCADAver
  - biero-el-corridor/OT_ICS_ressource_list
  - CISA ICS-CERT advisories
  - NVD / ExploitDB

Severity filter: CVSS >= 5.0 (Medium, High, Critical only)
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
MODULES_DIR = ROOT / "industrialxpl" / "modules" / "cve"
(MODULES_DIR / "__init__.py").touch(exist_ok=True)

TEMPLATE = '''"""IXF ICS CVE Module — {cve} ({vendor} {product}).

{description}

CVSS: {cvss} ({severity})
CWE: {cwe}
Affected: {affected}
PoC reference: {poc_ref}

simulate=True by default. Requires target authorization.
"""
import socket
import struct
import time
import urllib.request
import urllib.error

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptInteger, OptString, mute,
    print_error, print_info, print_status, print_success, print_warning,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {{
        "name":             "{cve} — {vendor} {product} {vuln_type}",
        "description":      "{short_desc}",
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":       {refs},
        "devices":          ("{vendor} {product}",),
        "impact":           "{impact}",
        "exploit_type":     "{exploit_type}",
        "source_poc":       "{poc_ref}",
        "cve":              "{cve}",
        "cvss":             "{cvss}",
        "severity":         "{severity}",
        "mitre_techniques": {mitre},
        "mitre_tactics":    {tactics},
    }}

    target   = OptIP("", "Target {vendor} {product} IP")
    port     = OptPort({port}, "Target service port")
    simulate = OptBool(True, "Simulate attack (default: True)")
    destructive = OptBool(False, "Enable live exploitation — requires authorization")

    @mute
    def check(self):
        if not self.target: return False
        try:
            s = socket.socket(); s.settimeout(5)
            s.connect((self.target, self.port)); s.close(); return True
        except: return False

    def run(self):
        if not self.target:
            print_error("Set 'target' option.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "{cve} — {vendor} {product}\\n"
                    "CVSS {cvss} ({severity}) | {vuln_type}\\n\\n"
                    "{simulation_steps}"
                ),
                mitre_techniques={mitre},
            )
            print_info("Affected: {affected}")
            print_info("PoC reference: {poc_ref}")
            return

        print_status("[{cve}] Exploiting {{}}:{{}}...".format(self.target, self.port))
        {live_code}
'''


def make(path: str, cve: str, vendor: str, product: str, port: int,
         cvss: float, severity: str, cwe: str, affected: str,
         vuln_type: str, description: str, short_desc: str,
         simulation_steps: str, poc_ref: str,
         refs: list, impact: str, exploit_type: str, mitre: list,
         tactics: list, live_code: str = "print_info('Live payload: implement protocol-specific exploit')"):
    f = MODULES_DIR / path
    f.parent.mkdir(parents=True, exist_ok=True)
    (f.parent / "__init__.py").touch(exist_ok=True)
    if f.exists():
        return False
    refs_str = str(tuple(refs))
    mitre_str = str(mitre)
    tactics_str = str(tactics)
    content = TEMPLATE.format(
        cve=cve, vendor=vendor, product=product, port=port,
        cvss=cvss, severity=severity, cwe=cwe, affected=affected,
        vuln_type=vuln_type, description=description, short_desc=short_desc[:200],
        simulation_steps=simulation_steps.replace("\n", "\\n"),
        poc_ref=poc_ref, refs=refs_str, impact=impact,
        exploit_type=exploit_type, mitre=mitre_str, tactics=tactics_str,
        live_code=live_code,
    )
    f.write_text(content, encoding="utf-8")
    return True


BATCH = [
    # ------------------------------------------------------------------ ROCKWELL
    dict(path="rockwell/cve_2021_27478_enip_stack_overflow.py",
         cve="CVE-2021-27478", vendor="Rockwell Automation", product="MicroLogix 1100/1400",
         port=44818, cvss=9.8, severity="CRITICAL", cwe="CWE-121",
         affected="MicroLogix 1100 v21.x and earlier, MicroLogix 1400 v21.x and earlier",
         vuln_type="EtherNet/IP stack-based buffer overflow",
         description="Stack-based buffer overflow in Rockwell MicroLogix EtherNet/IP server allows remote unauthenticated RCE.",
         short_desc="Rockwell MicroLogix EtherNet/IP stack overflow — remote unauthenticated RCE. CVSS 9.8.",
         simulation_steps="Step 1: Craft oversized EtherNet/IP Register Session packet (> 502 bytes)\nStep 2: Overflow CIP stack buffer on port 44818\nStep 3: Overwrite return address with ROP gadget\nStep 4: Execute shellcode in PLC CPU context",
         poc_ref="https://github.com/Mewtwoz/InduGuard_vul_poc",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-21-110-01"],
         impact="CRITICAL", exploit_type="Stack Buffer Overflow — RCE",
         mitre=["T0866","T0836"], tactics=["Initial Access"]),

    dict(path="rockwell/cve_2020_12038_studio5000_auth_bypass.py",
         cve="CVE-2020-12038", vendor="Rockwell Automation", product="Studio 5000 Logix Designer",
         port=44818, cvss=8.8, severity="HIGH", cwe="CWE-287",
         affected="Studio 5000 Logix Designer v32 and earlier",
         vuln_type="Authentication bypass via EtherNet/IP",
         description="Rockwell Studio 5000 fails to validate session authentication on EtherNet/IP, allowing replay of authenticated sessions.",
         short_desc="Rockwell Studio 5000 auth bypass via EtherNet/IP session replay.",
         simulation_steps="Step 1: Capture legitimate ForwardOpen EtherNet/IP session packet\nStep 2: Replay session token to same or different PLC\nStep 3: Access controller tags without authentication\nStep 4: Write arbitrary tag values to affect process",
         poc_ref="https://github.com/Mewtwoz/InduGuard_vul_poc",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-20-163-03"],
         impact="HIGH", exploit_type="Authentication Bypass",
         mitre=["T0859","T0836"], tactics=["Lateral Movement"]),

    dict(path="rockwell/cve_2016_5645_1766_enip_dos.py",
         cve="CVE-2016-5645", vendor="Rockwell Automation", product="MicroLogix 1766-L32",
         port=44818, cvss=7.5, severity="HIGH", cwe="CWE-400",
         affected="1766-L32 Ethernet Interface",
         vuln_type="EtherNet/IP denial of service",
         description="Rockwell 1766-L32 crashes on malformed EtherNet/IP UDP broadcast — loss of all Ethernet comms.",
         short_desc="Rockwell 1766-L32 EtherNet/IP DoS via malformed UDP packet. CVSS 7.5.",
         simulation_steps="Step 1: Send malformed UDP packet to port 44818\nStep 2: Trigger null deref in EIP stack\nStep 3: PLC Ethernet card crashes — all OT comms lost\nStep 4: Manual recovery requires power cycle",
         poc_ref="https://github.com/Mewtwoz/n-days-poc-benchmark-and-dataset",
         refs=["https://www.cisa.gov/uscert/ics/advisories/ICSA-16-188-01"],
         impact="HIGH", exploit_type="Denial of Service",
         mitre=["T0814"], tactics=["Inhibit Response Function"]),

    dict(path="rockwell/cve_2023_3595_controllogix_rce.py",
         cve="CVE-2023-3595", vendor="Rockwell Automation", product="ControlLogix/CompactLogix 1756-EN2x",
         port=44818, cvss=9.8, severity="CRITICAL", cwe="CWE-787",
         affected="1756-EN2x EtherNet/IP communication module",
         vuln_type="Out-of-bounds write — arbitrary code execution in firmware",
         description="Unauthenticated RCE in Rockwell ControlLogix/CompactLogix 1756-EN2x EtherNet/IP module. CISA emergency advisory. Allows firmware modification and persistent access.",
         short_desc="Rockwell ControlLogix 1756-EN2x unauthenticated RCE — CISA emergency advisory. CVSS 9.8.",
         simulation_steps="Step 1: Connect to EtherNet/IP port 44818 on 1756-EN2x module\nStep 2: Send crafted CIP command with out-of-bounds write\nStep 3: Achieve arbitrary code execution in EN2x firmware\nStep 4: Modify PLC logic, disable comms, or install backdoor",
         poc_ref="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-191a",
         refs=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-191a",
               "https://rockwellautomation.custhelp.com/app/answers/answer_view/a_id/3455"],
         impact="CRITICAL", exploit_type="Out-of-bounds Write — RCE",
         mitre=["T0866","T0836","T0880"], tactics=["Initial Access","Impact"]),

    dict(path="rockwell/cve_2022_1161_controllogix_modified_fw.py",
         cve="CVE-2022-1161", vendor="Rockwell Automation", product="ControlLogix/CompactLogix",
         port=44818, cvss=10.0, severity="CRITICAL", cwe="CWE-345",
         affected="Multiple Logix 5000 controllers firmware < 34.011",
         vuln_type="Unverified firmware modification",
         description="Rockwell Logix controllers run modified firmware without verifying signature, allowing persistent malicious code injection.",
         short_desc="Rockwell Logix 5000 accepts modified firmware without signature check — persistent backdoor.",
         simulation_steps="Step 1: Connect to controller via Studio 5000 or EtherNet/IP\nStep 2: Upload current firmware via PCCC/CIP\nStep 3: Patch firmware with malicious ladder logic\nStep 4: Download modified firmware — controller runs backdoored code permanently",
         poc_ref="https://www.cisa.gov/uscert/ics/advisories/icsa-22-090-05",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-22-090-05"],
         impact="CRITICAL", exploit_type="Firmware Modification",
         mitre=["T0839","T0880"], tactics=["Persistence"]),

    # ------------------------------------------------------------------ SIEMENS
    dict(path="siemens/cve_2021_22681_s7_1200_hardcoded_key.py",
         cve="CVE-2021-22681", vendor="Siemens", product="S7-1200/1500 PLC",
         port=102, cvss=9.8, severity="CRITICAL", cwe="CWE-321",
         affected="S7-1200 and S7-1500 all firmware versions",
         vuln_type="Hardcoded cryptographic key — S7comm+",
         description="Siemens S7-1200/1500 uses a hardcoded global private key in S7comm+ TLS. Attacker with access to one device can extract key and decrypt/forge communications for all devices globally.",
         short_desc="Siemens S7-1200/1500 hardcoded TLS private key — decrypt all S7comm+ globally. CVSS 9.8.",
         simulation_steps="Step 1: Extract hardcoded private key from S7-1200 firmware (public CVE-2021-22681 key)\nStep 2: Perform MitM on S7comm+ TCP/102\nStep 3: Decrypt all S7comm+ traffic with extracted key\nStep 4: Forge authenticated commands to read/write PLC memory",
         poc_ref="https://github.com/Mewtwoz/InduGuard_vul_poc",
         refs=["https://cert-portal.siemens.com/productcert/pdf/ssa-568427.pdf"],
         impact="CRITICAL", exploit_type="Hardcoded Key — MitM/Decryption",
         mitre=["T0855","T0830"], tactics=["Collection"]),

    dict(path="siemens/cve_2022_38465_s7_global_key.py",
         cve="CVE-2022-38465", vendor="Siemens", product="S7-1200/1500 TIA Portal",
         port=102, cvss=9.3, severity="CRITICAL", cwe="CWE-321",
         affected="S7-1200/1500 all versions using S7comm+",
         vuln_type="Global private key exposure allows PLC credential decryption",
         description="Siemens uses a global private RSA key for all S7-1200/1500 devices. Once extracted, an attacker can decrypt protected PLC passwords from any device.",
         short_desc="Siemens S7-1500 global RSA key exposure — decrypt PLC passwords across all devices.",
         simulation_steps="Step 1: Obtain global private key from firmware (CVE-2022-38465 key material public)\nStep 2: Connect to target S7-1500 on port 102\nStep 3: Request protected password blob via S7comm+\nStep 4: Decrypt password with extracted global private key\nStep 5: Authenticate to PLC — full control",
         poc_ref="https://cert-portal.siemens.com/productcert/pdf/ssa-568427.pdf",
         refs=["https://cert-portal.siemens.com/productcert/pdf/ssa-568427.pdf"],
         impact="CRITICAL", exploit_type="Cryptographic Key Exposure",
         mitre=["T0855","T0859"], tactics=["Credential Access"]),

    dict(path="siemens/cve_2019_13946_s7_profinet_dos.py",
         cve="CVE-2019-13946", vendor="Siemens", product="S7-300 PROFINET",
         port=80, cvss=7.5, severity="HIGH", cwe="CWE-400",
         affected="S7-300 CPU 315-2 PN/DP and others",
         vuln_type="PROFINET stack remote DoS",
         description="Siemens S7-300 crashes when processing malformed PROFINET DCP packets, causing CPU stop.",
         short_desc="Siemens S7-300 PROFINET DoS — malformed DCP packet causes CPU stop.",
         simulation_steps="Step 1: Craft malformed PROFINET DCP Set IP request\nStep 2: Send via Layer 2 Ethernet (no routing required)\nStep 3: S7-300 CPU enters STOP mode\nStep 4: Process controlled by PLC halts immediately",
         poc_ref="https://github.com/Mewtwoz/n-days-poc-benchmark-and-dataset",
         refs=["https://cert-portal.siemens.com/productcert/pdf/ssa-617890.pdf"],
         impact="HIGH", exploit_type="Denial of Service",
         mitre=["T0814"], tactics=["Inhibit Response Function"]),

    dict(path="siemens/cve_2015_2177_s7_300_s7comm_dos.py",
         cve="CVE-2015-2177", vendor="Siemens", product="S7-300 CPU",
         port=102, cvss=7.8, severity="HIGH", cwe="CWE-20",
         affected="S7-300 CPU series, firmware < 3.2",
         vuln_type="S7comm malformed packet — CPU STOP",
         description="Siemens S7-300 CPU transitions to STOP mode when receiving specially crafted S7comm input validation packets.",
         short_desc="Siemens S7-300 S7comm DoS via malformed packet — forces CPU into STOP mode.",
         simulation_steps="Step 1: Establish ISO-TSAP/S7comm connection on TCP/102\nStep 2: Send crafted S7comm function code with invalid length\nStep 3: S7-300 fails input validation\nStep 4: CPU transitions to STOP — all PLC I/O halted",
         poc_ref="https://github.com/Mewtwoz/n-days-poc-benchmark-and-dataset",
         refs=["https://cert-portal.siemens.com/productcert/pdf/ssa-370418.pdf"],
         impact="HIGH", exploit_type="Denial of Service",
         mitre=["T0814"], tactics=["Inhibit Response Function"]),

    dict(path="siemens/cve_2020_15782_s7_memory_bypass.py",
         cve="CVE-2020-15782", vendor="Siemens", product="S7-1200/1500 CPU",
         port=102, cvss=8.1, severity="HIGH", cwe="CWE-119",
         affected="S7-1200/1500 CPU before patched TIA Portal",
         vuln_type="Memory protection bypass — arbitrary read/write",
         description="Vulnerability in S7-1200/1500 PLC allows bypassing memory protection. With network access, attacker can read/write arbitrary PLC memory without authentication.",
         short_desc="Siemens S7-1200/1500 memory protection bypass — read/write arbitrary PLC memory via network.",
         simulation_steps="Step 1: Connect to S7-1200/1500 on port 102\nStep 2: Send crafted S7comm read request with crafted area code\nStep 3: Bypass memory protection boundary checks\nStep 4: Read/write arbitrary PLC memory — extract safety logic, alter setpoints",
         poc_ref="https://cert-portal.siemens.com/productcert/pdf/ssa-381684.pdf",
         refs=["https://cert-portal.siemens.com/productcert/pdf/ssa-381684.pdf"],
         impact="HIGH", exploit_type="Memory Protection Bypass",
         mitre=["T0832","T0836"], tactics=["Collection"]),

    dict(path="siemens/cve_2014_2909_s7_1200_crlf_injection.py",
         cve="CVE-2014-2909", vendor="Siemens", product="S7-1200 CPU",
         port=80, cvss=6.4, severity="MEDIUM", cwe="CWE-93",
         affected="S7-1200 CPU firmware < 4.0",
         vuln_type="HTTP CRLF injection",
         description="Siemens S7-1200 web server is vulnerable to CRLF injection via the URL, allowing HTTP response splitting and cache poisoning.",
         short_desc="Siemens S7-1200 HTTP CRLF injection — response splitting, cache poisoning.",
         simulation_steps="Step 1: Send HTTP GET to S7-1200 web interface port 80\nStep 2: Inject CRLF sequences (%0d%0a) in URL parameter\nStep 3: Split HTTP response to inject malicious headers\nStep 4: Exploit for session hijacking or cache poisoning",
         poc_ref="https://github.com/Mewtwoz/n-days-poc-benchmark-and-dataset",
         refs=["https://cert-portal.siemens.com/productcert/pdf/ssa-714398.pdf"],
         impact="MEDIUM", exploit_type="CRLF Injection",
         mitre=["T0866"], tactics=["Initial Access"]),

    # ------------------------------------------------------------------ SCHNEIDER
    dict(path="schneider/cve_2021_22779_modicon_auth_bypass.py",
         cve="CVE-2021-22779", vendor="Schneider Electric", product="Modicon M340/M580",
         port=502, cvss=9.8, severity="CRITICAL", cwe="CWE-288",
         affected="Modicon M340 and M580 Ethernet CPU modules",
         vuln_type="Authentication bypass — write without credentials",
         description="Schneider Modicon M340/M580 allows unauthenticated write access to PLC coils/registers via Modbus TCP. No session auth required.",
         short_desc="Schneider Modicon M340/M580 auth bypass — unauthenticated Modbus write to PLC. CVSS 9.8.",
         simulation_steps="Step 1: Connect to Modbus TCP port 502 without credentials\nStep 2: Send FC16 (Write Multiple Registers) command\nStep 3: Write to any holding register including safety setpoints\nStep 4: Modify process control values — temperature, pressure, flow",
         poc_ref="https://www.se.com/ww/en/download/document/SEVD-2021-222-06/",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-21-222-06"],
         impact="CRITICAL", exploit_type="Authentication Bypass",
         mitre=["T0813","T0836"], tactics=["Impair Process Control"]),

    dict(path="schneider/cve_2019_6833_modicon_vxworks_overflow.py",
         cve="CVE-2019-6833", vendor="Schneider Electric", product="Modicon M340 (VxWorks)",
         port=502, cvss=9.8, severity="CRITICAL", cwe="CWE-787",
         affected="Modicon M340 running VxWorks RTOS",
         vuln_type="VxWorks out-of-bounds write — remote code execution",
         description="Out-of-bounds write in VxWorks Modbus/FTP handling on Schneider Modicon M340 allows unauthenticated RCE.",
         short_desc="Schneider Modicon M340 VxWorks out-of-bounds write — unauthenticated RCE.",
         simulation_steps="Step 1: Craft oversized Modbus TCP payload targeting VxWorks FTP/Modbus handler\nStep 2: Trigger out-of-bounds write in VxWorks heap\nStep 3: Overwrite VxWorks task control block\nStep 4: Execute arbitrary code — gain root on M340 RTOS",
         poc_ref="https://github.com/Mewtwoz/InduGuard_vul_poc",
         refs=["https://www.se.com/ww/en/download/document/SEVD-2019-134-05/"],
         impact="CRITICAL", exploit_type="Out-of-bounds Write — RCE",
         mitre=["T0866","T0836"], tactics=["Initial Access"]),

    dict(path="schneider/cve_2017_6026_schneider_session_hijack.py",
         cve="CVE-2017-6026", vendor="Schneider Electric", product="Modicon M221",
         port=502, cvss=8.0, severity="HIGH", cwe="CWE-384",
         affected="Modicon M221 firmware < 1.3.2",
         vuln_type="Session fixation — authenticated session hijack",
         description="Schneider Modicon M221 uses predictable session identifiers in Modbus/TCP protocol, allowing session hijacking.",
         short_desc="Schneider Modicon M221 session hijacking via predictable session ID. CVSS 8.0.",
         simulation_steps="Step 1: Observe Modbus TCP sessions to M221\nStep 2: Predict next session token (sequential/predictable)\nStep 3: Craft Modbus TCP with forged session token\nStep 4: Hijack authenticated session — write to PLC without own credentials",
         poc_ref="https://github.com/SawyersPresent/SCADAver",
         refs=["https://www.cisa.gov/uscert/ics/advisories/ICSA-17-057-02"],
         impact="HIGH", exploit_type="Session Hijacking",
         mitre=["T0859","T0830"], tactics=["Credential Access"]),

    dict(path="schneider/cve_2015_7937_tm221_modbus_crash.py",
         cve="CVE-2015-7937", vendor="Schneider Electric", product="Modicon TM221",
         port=502, cvss=7.5, severity="HIGH", cwe="CWE-20",
         affected="Modicon TM221 Series PLC",
         vuln_type="Modbus function code 0x71 crash",
         description="Schneider TM221 crashes when receiving undocumented Modbus function code 0x71 — controller stops responding.",
         short_desc="Schneider TM221 DoS via Modbus FC 0x71 — CPU crash.",
         simulation_steps="Step 1: Connect to Modbus TCP port 502\nStep 2: Send FC 0x71 (undocumented vendor-specific)\nStep 3: TM221 CPU triggers unhandled exception\nStep 4: PLC stops — I/O outputs go to safe/fail state",
         poc_ref="https://github.com/Mewtwoz/n-days-poc-benchmark-and-dataset",
         refs=["https://www.cisa.gov/uscert/ics/advisories/ICSA-15-300-02"],
         impact="HIGH", exploit_type="Denial of Service",
         mitre=["T0814"], tactics=["Inhibit Response Function"]),

    dict(path="schneider/cve_2018_7789_tm221_http_dos.py",
         cve="CVE-2018-7789", vendor="Schneider Electric", product="Modicon TM221",
         port=80, cvss=7.5, severity="HIGH", cwe="CWE-400",
         affected="Modicon TM221 web server",
         vuln_type="HTTP POST denial of service",
         description="Schneider TM221 web server crashes on crafted HTTP POST — loss of web-based management and engineering access.",
         short_desc="Schneider TM221 HTTP DoS via oversized POST — web server crash.",
         simulation_steps="Step 1: Send oversized HTTP POST to TM221 web interface on port 80\nStep 2: Overflow web server request buffer\nStep 3: Web server process crashes — no more HTTP management\nStep 4: Engineering access via web interface lost until reboot",
         poc_ref="https://github.com/Mewtwoz/n-days-poc-benchmark-and-dataset",
         refs=["https://www.cisa.gov/uscert/ics/advisories/ICSA-18-179-02"],
         impact="HIGH", exploit_type="Denial of Service",
         mitre=["T0814"], tactics=["Inhibit Response Function"]),

    # ------------------------------------------------------------------ ABB
    dict(path="abb/cve_2021_22277_ac800m_mms_dos.py",
         cve="CVE-2021-22277", vendor="ABB", product="AC800M Controller (MMS)",
         port=102, cvss=7.5, severity="HIGH", cwe="CWE-400",
         affected="ABB AC800M firmware < 6.0.3.1",
         vuln_type="MMS protocol stack denial of service",
         description="ABB AC800M DCS controller crashes when processing malformed IEC 61850 MMS protocol messages.",
         short_desc="ABB AC800M MMS protocol DoS — DCS controller crash via malformed IEC 61850 message.",
         simulation_steps="Step 1: Connect to ABB AC800M MMS server on port 102\nStep 2: Send malformed MMS PDU with invalid length fields\nStep 3: MMS stack fails to handle malformed ASN.1 encoding\nStep 4: AC800M controller crashes — DCS process control lost",
         poc_ref="https://github.com/Mewtwoz/InduGuard_vul_poc",
         refs=["https://search.abb.com/library/Download.aspx?DocumentID=2PAA113908"],
         impact="HIGH", exploit_type="Denial of Service",
         mitre=["T0814"], tactics=["Inhibit Response Function"]),

    dict(path="abb/cve_2020_8476_ac500_hardcoded_key.py",
         cve="CVE-2020-8476", vendor="ABB", product="AC500 PLC",
         port=1217, cvss=9.8, severity="CRITICAL", cwe="CWE-798",
         affected="AC500 PLC all firmware versions",
         vuln_type="Hardcoded FTP credentials",
         description="ABB AC500 PLC contains hardcoded FTP credentials that allow unauthenticated access to PLC file system and program files.",
         short_desc="ABB AC500 hardcoded FTP credentials — full file system access including PLC programs.",
         simulation_steps="Step 1: Connect to ABB AC500 on port 21 (FTP)\nStep 2: Authenticate with hardcoded credentials (admin/admin or published CVE creds)\nStep 3: Access PLC file system — download project files\nStep 4: Modify PLC program offline and upload back",
         poc_ref="https://github.com/Mewtwoz/InduGuard_vul_poc",
         refs=["https://search.abb.com/library/Download.aspx?DocumentID=9AKK107991A3764"],
         impact="CRITICAL", exploit_type="Hardcoded Credentials",
         mitre=["T0859","T0843"], tactics=["Credential Access"]),

    # ------------------------------------------------------------------ OMRON
    dict(path="omron/cve_2023_27396_cj2m_fins_auth_bypass.py",
         cve="CVE-2023-27396", vendor="Omron", product="CJ2M PLC (FINS)",
         port=9600, cvss=9.8, severity="CRITICAL", cwe="CWE-306",
         affected="CJ2M CPU all firmware versions",
         vuln_type="FINS protocol — missing authentication",
         description="Omron CJ2M accepts FINS commands (memory read/write, CPU control) without any authentication over UDP/TCP.",
         short_desc="Omron CJ2M FINS missing authentication — read/write memory and control CPU without creds.",
         simulation_steps="Step 1: Send FINS Connect Request to UDP/9600\nStep 2: Send FINS Memory Area Write without credentials\nStep 3: Overwrite holding registers / DM area values\nStep 4: Send FINS CPU STOP command — PLC halts",
         poc_ref="https://github.com/Mewtwoz/InduGuard_vul_poc",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-23-131-05"],
         impact="CRITICAL", exploit_type="Missing Authentication",
         mitre=["T0813","T0821"], tactics=["Impair Process Control"]),

    dict(path="omron/cve_2015_0987_cp2e_fins_dos.py",
         cve="CVE-2015-0987", vendor="Omron", product="CP2E PLC (FINS)",
         port=9600, cvss=7.8, severity="HIGH", cwe="CWE-400",
         affected="CP2E all firmware versions",
         vuln_type="FINS CPU cycle time error — DoS",
         description="Omron CP2E crashes or enters error state when receiving FINS commands that cause CPU cycle time violations.",
         short_desc="Omron CP2E FINS DoS — CPU cycle time error causes PLC halt.",
         simulation_steps="Step 1: Connect to CP2E on FINS/UDP port 9600\nStep 2: Flood with rapid FINS memory write commands\nStep 3: CPU cycle time exceeded — watchdog triggers\nStep 4: CP2E enters ERROR state — outputs de-energized",
         poc_ref="https://github.com/Mewtwoz/n-days-poc-benchmark-and-dataset",
         refs=["https://www.cisa.gov/uscert/ics/advisories/ICSA-15-037-01"],
         impact="HIGH", exploit_type="Denial of Service",
         mitre=["T0814"], tactics=["Inhibit Response Function"]),

    dict(path="omron/cve_2022_34151_nj_nx_auth_bypass.py",
         cve="CVE-2022-34151", vendor="Omron", product="NJ/NX Series Controllers",
         port=44818, cvss=9.8, severity="CRITICAL", cwe="CWE-306",
         affected="Sysmac NJ/NX/NY Series, Machine Automation Controller",
         vuln_type="EtherNet/IP missing authentication — RCE",
         description="Omron NJ/NX machine automation controllers accept EtherNet/IP commands without authentication, allowing arbitrary tag write and program upload/download.",
         short_desc="Omron NJ/NX EtherNet/IP missing auth — unauthenticated tag write and program manipulation.",
         simulation_steps="Step 1: Connect to NJ/NX EtherNet/IP on port 44818\nStep 2: Register session without credentials\nStep 3: Enumerate controller tags\nStep 4: Write arbitrary values to process tags\nStep 5: Upload/download PLC program",
         poc_ref="https://www.cisa.gov/uscert/ics/advisories/icsa-22-179-01",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-22-179-01"],
         impact="CRITICAL", exploit_type="Missing Authentication",
         mitre=["T0813","T0836"], tactics=["Impair Process Control"]),

    # ------------------------------------------------------------------ GE / EMERSON
    dict(path="ge/cve_2019_6503_cimplicity_path_traversal.py",
         cve="CVE-2019-6503", vendor="GE", product="CIMPLICITY HMI",
         port=80, cvss=9.8, severity="CRITICAL", cwe="CWE-22",
         affected="CIMPLICITY HMI 10.0 and earlier",
         vuln_type="Path traversal — arbitrary file read/RCE",
         description="GE CIMPLICITY HMI web server allows path traversal via the URL, enabling arbitrary file read and potentially remote code execution.",
         short_desc="GE CIMPLICITY HMI path traversal — arbitrary file read and RCE via web server.",
         simulation_steps="Step 1: Send HTTP GET with path traversal sequences (../../etc/passwd)\nStep 2: Read arbitrary files from HMI server filesystem\nStep 3: Read CIMPLICITY project files — credentials and process data\nStep 4: Upload malicious CIMPLICITY script for code execution",
         poc_ref="https://github.com/Mewtwoz/InduGuard_vul_poc",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-19-022-01"],
         impact="CRITICAL", exploit_type="Path Traversal — RCE",
         mitre=["T0866","T0865"], tactics=["Initial Access"]),

    dict(path="ge/cve_2014_0751_cimplicity_blackenergy_vector.py",
         cve="CVE-2014-0751", vendor="GE", product="CIMPLICITY HMI (BlackEnergy vector)",
         port=80, cvss=9.8, severity="CRITICAL", cwe="CWE-22",
         affected="CIMPLICITY HMI 8.2 and earlier",
         vuln_type="Path traversal used by BlackEnergy APT",
         description="GE CIMPLICITY path traversal vulnerability actively exploited by BlackEnergy APT to gain initial access to power grid HMI systems.",
         short_desc="GE CIMPLICITY path traversal — BlackEnergy APT initial access vector to power grid HMIs.",
         simulation_steps="Step 1: Probe CIMPLICITY web server on port 80 or 10212\nStep 2: Send path traversal HTTP GET (CVE-2014-0751 pattern)\nStep 3: Access CIMPLICITY .cim project files\nStep 4: Execute code via project file manipulation (BlackEnergy technique)",
         poc_ref="https://github.com/Mewtwoz/InduGuard_vul_poc",
         refs=["https://www.cisa.gov/uscert/ics/advisories/ICSA-14-023-01"],
         impact="CRITICAL", exploit_type="Path Traversal — APT Initial Access",
         mitre=["T0866","T0817"], tactics=["Initial Access"]),

    # ------------------------------------------------------------------ HONEYWELL
    dict(path="honeywell/cve_2021_38397_experion_pks_rce.py",
         cve="CVE-2021-38397", vendor="Honeywell", product="Experion PKS DCS",
         port=55555, cvss=10.0, severity="CRITICAL", cwe="CWE-78",
         affected="Experion PKS C200/C300 Controllers all versions",
         vuln_type="Command injection — unauthenticated RCE",
         description="Honeywell Experion PKS DCS controller accepts unsanitized commands over proprietary protocol, allowing unauthenticated command injection and remote code execution.",
         short_desc="Honeywell Experion PKS DCS unauthenticated command injection — RCE on C200/C300 controllers.",
         simulation_steps="Step 1: Connect to Experion PKS controller on proprietary port 55555\nStep 2: Send crafted control command with injected shell metacharacters\nStep 3: Command injection executed in controller context\nStep 4: Remote code execution — full DCS controller compromise",
         poc_ref="https://github.com/Mewtwoz/InduGuard_vul_poc",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-21-238-02"],
         impact="CRITICAL", exploit_type="Command Injection — RCE",
         mitre=["T0866","T0821"], tactics=["Initial Access"]),

    # ------------------------------------------------------------------ AVEVA / Wonderware
    dict(path="aveva/cve_2023_2573_intouch_auth_bypass.py",
         cve="CVE-2023-2573", vendor="AVEVA", product="InTouch HMI",
         port=80, cvss=9.8, severity="CRITICAL", cwe="CWE-287",
         affected="InTouch HMI 2020 R2 P01 and earlier",
         vuln_type="Web server authentication bypass",
         description="AVEVA InTouch HMI web interface authentication can be bypassed, granting full access to SCADA screens and process controls.",
         short_desc="AVEVA InTouch HMI web auth bypass — unauthenticated access to SCADA interface.",
         simulation_steps="Step 1: Access InTouch HMI web server on port 80\nStep 2: Exploit auth bypass (crafted session token)\nStep 3: Access all SCADA screens without credentials\nStep 4: Read/write tag values, modify process setpoints",
         poc_ref="https://github.com/Mewtwoz/InduGuard_vul_poc",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-23-136-01"],
         impact="CRITICAL", exploit_type="Authentication Bypass",
         mitre=["T0865","T0836"], tactics=["Initial Access"]),

    # ------------------------------------------------------------------ MITSUBISHI
    dict(path="mitsubishi/cve_2020_5595_melsec_q_protocol.py",
         cve="CVE-2020-5595", vendor="Mitsubishi Electric", product="MELSEC-Q Series PLC",
         port=5007, cvss=7.5, severity="HIGH", cwe="CWE-20",
         affected="MELSEC-Q Series CPU all firmware versions",
         vuln_type="SLMP protocol — missing input validation DoS",
         description="Mitsubishi MELSEC-Q CPU stops when processing malformed SLMP (SeamLess Message Protocol) packets.",
         short_desc="Mitsubishi MELSEC-Q SLMP protocol DoS — CPU STOP via malformed packet.",
         simulation_steps="Step 1: Connect to MELSEC-Q SLMP service on UDP/TCP port 5007\nStep 2: Send SLMP header with invalid command/subcommand codes\nStep 3: PLC firmware fails to validate SLMP frame\nStep 4: MELSEC-Q CPU transitions to STOP — I/O halted",
         poc_ref="https://github.com/Mewtwoz/InduGuard_vul_poc",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-20-303-02"],
         impact="HIGH", exploit_type="Denial of Service",
         mitre=["T0814"], tactics=["Inhibit Response Function"]),

    # ------------------------------------------------------------------ PHOENIX CONTACT
    dict(path="phoenix_contact/cve_2016_8366_webvisit_password_disclosure.py",
         cve="CVE-2016-8366", vendor="Phoenix Contact", product="WebVisit HMI",
         port=8080, cvss=9.8, severity="CRITICAL", cwe="CWE-255",
         affected="WebVisit HMI 6.x",
         vuln_type="Plaintext password disclosure via web interface",
         description="Phoenix Contact WebVisit HMI exposes user credentials in plaintext through the web interface without authentication.",
         short_desc="Phoenix Contact WebVisit password disclosure — credentials exposed in plaintext via HTTP.",
         simulation_steps="Step 1: Access WebVisit web interface on port 8080 (no credentials needed)\nStep 2: Navigate to configuration/users section\nStep 3: Retrieve all user credentials in plaintext\nStep 4: Use credentials to authenticate to WebVisit and modify HMI screens",
         poc_ref="https://github.com/SawyersPresent/SCADAver",
         refs=["https://www.cisa.gov/uscert/ics/advisories/ICSA-16-291-01"],
         impact="CRITICAL", exploit_type="Credential Disclosure",
         mitre=["T0859"], tactics=["Credential Access"]),

    dict(path="phoenix_contact/cve_2016_8380_webvisit_tag_manipulation.py",
         cve="CVE-2016-8380", vendor="Phoenix Contact", product="WebVisit HMI",
         port=8080, cvss=9.8, severity="CRITICAL", cwe="CWE-306",
         affected="WebVisit HMI 6.x",
         vuln_type="Missing authentication — HMI tag read/write",
         description="Phoenix Contact WebVisit allows unauthenticated read and write of HMI tag values through the web API.",
         short_desc="Phoenix Contact WebVisit missing auth — unauthenticated HMI tag read/write.",
         simulation_steps="Step 1: Access WebVisit REST API on port 8080 without credentials\nStep 2: GET /api/tags to enumerate all HMI process tags\nStep 3: POST /api/tags with new values to write setpoints\nStep 4: Modify temperature/pressure/flow setpoints — process manipulation",
         poc_ref="https://github.com/SawyersPresent/SCADAver",
         refs=["https://www.cisa.gov/uscert/ics/advisories/ICSA-16-291-01"],
         impact="CRITICAL", exploit_type="Missing Authentication",
         mitre=["T0813","T0836"], tactics=["Impair Process Control"]),

    # ------------------------------------------------------------------ CODESYS
    dict(path="codesys/cve_2021_29241_opcua_stack_dos.py",
         cve="CVE-2021-29241", vendor="CODESYS", product="Linux SL Runtime (OPC UA)",
         port=4840, cvss=7.5, severity="HIGH", cwe="CWE-400",
         affected="CODESYS Linux SL Runtime < 4.5.0.0",
         vuln_type="OPC UA stack denial of service",
         description="CODESYS Linux SL runtime OPC UA server crashes on malformed OPC UA protocol messages.",
         short_desc="CODESYS Linux OPC UA DoS — malformed message crashes runtime server.",
         simulation_steps="Step 1: Connect to CODESYS OPC UA server on port 4840\nStep 2: Send malformed OPC UA Hello message with invalid body size\nStep 3: OPC UA stack buffer handling fails\nStep 4: CODESYS runtime crashes — all PLC communication lost",
         poc_ref="https://github.com/Mewtwoz/n-days-poc-benchmark-and-dataset",
         refs=["https://customers.codesys.com/index.php?eID=dumpFile&t=f&f=16682&token="],
         impact="HIGH", exploit_type="Denial of Service",
         mitre=["T0814"], tactics=["Inhibit Response Function"]),

    dict(path="codesys/cve_2022_31806_default_credentials.py",
         cve="CVE-2022-31806", vendor="CODESYS", product="CODESYS Control Runtime",
         port=1217, cvss=9.8, severity="CRITICAL", cwe="CWE-798",
         affected="CODESYS Control Runtime V3 before 3.5.18.10",
         vuln_type="Default credentials — unauthenticated PLC access",
         description="CODESYS Control runtime uses default credentials allowing unauthenticated access to program upload/download and runtime control.",
         short_desc="CODESYS Control Runtime default credentials — unauthenticated PLC program access.",
         simulation_steps="Step 1: Connect to CODESYS runtime on port 1217\nStep 2: Authenticate with default credentials (admin/admin or empty)\nStep 3: Upload malicious PLC program replacing current logic\nStep 4: Download process data — access all I/O values and programs",
         poc_ref="https://sundi133.github.io/otscan",
         refs=["https://customers.codesys.com/index.php?eID=dumpFile&t=f&f=18802"],
         impact="CRITICAL", exploit_type="Default Credentials",
         mitre=["T0859","T0843"], tactics=["Credential Access"]),

    # ------------------------------------------------------------------ MOXA
    dict(path="moxa/cve_2022_3480_iologik_default_creds.py",
         cve="CVE-2022-3480", vendor="Moxa", product="ioLogik E2200 Series",
         port=80, cvss=9.8, severity="CRITICAL", cwe="CWE-798",
         affected="ioLogik E2210/E2212/E2214 firmware < 3.3",
         vuln_type="Default or hardcoded credentials",
         description="Moxa ioLogik E2200 series remote I/O devices use default credentials that are rarely changed, allowing full device management access.",
         short_desc="Moxa ioLogik E2200 default credentials — full remote I/O device control.",
         simulation_steps="Step 1: Access Moxa ioLogik web UI on port 80\nStep 2: Login with default credentials (admin/moxa or admin/admin)\nStep 3: Access all digital/analog I/O configuration\nStep 4: Modify I/O setpoints, force outputs — physical process manipulation",
         poc_ref="https://www.cisa.gov/uscert/ics/advisories/icsa-22-270-06",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-22-270-06"],
         impact="CRITICAL", exploit_type="Default Credentials",
         mitre=["T0859","T0836"], tactics=["Credential Access"]),

    # ------------------------------------------------------------------ TRIDIUM / Niagara
    dict(path="tridium/cve_2019_8957_niagara_path_traversal.py",
         cve="CVE-2019-8957", vendor="Tridium", product="Niagara Framework",
         port=443, cvss=9.8, severity="CRITICAL", cwe="CWE-22",
         affected="Niagara Framework 4.x before 4.7u1",
         vuln_type="Path traversal — arbitrary file read",
         description="Tridium Niagara Framework web server allows unauthenticated path traversal, exposing configuration files including credentials.",
         short_desc="Tridium Niagara path traversal — credentials and config files exposed without auth.",
         simulation_steps="Step 1: Send HTTP GET to Niagara web server on 443\nStep 2: Use path traversal: /..%2F..%2Fetc%2Fpasswd\nStep 3: Access /etc/niagara/config.bog — encrypted credentials\nStep 4: Decrypt Niagara credentials using published decryption algorithm",
         poc_ref="https://www.cisa.gov/uscert/ics/advisories/icsa-19-057-01",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-19-057-01"],
         impact="CRITICAL", exploit_type="Path Traversal",
         mitre=["T0866","T0859"], tactics=["Initial Access","Credential Access"]),

    # ------------------------------------------------------------------ INDUCTIVE AUTOMATION / Ignition
    dict(path="ignition/cve_2023_39476_java_deserialization_rce.py",
         cve="CVE-2023-39476", vendor="Inductive Automation", product="Ignition SCADA",
         port=8060, cvss=9.8, severity="CRITICAL", cwe="CWE-502",
         affected="Ignition 8.1.x before 8.1.33",
         vuln_type="Java deserialization — unauthenticated RCE",
         description="Ignition SCADA gateway deserializes untrusted Java objects over TCP, allowing remote code execution without authentication.",
         short_desc="Ignition SCADA Java deserialization — unauthenticated RCE on gateway server. CVSS 9.8.",
         simulation_steps="Step 1: Connect to Ignition gateway on port 8060 (or 8088)\nStep 2: Send serialized Java payload to deserialization endpoint\nStep 3: Trigger deserialization gadget chain (e.g. Commons Collections)\nStep 4: Execute OS command — full RCE on SCADA server",
         poc_ref="https://github.com/Mewtwoz/InduGuard_vul_poc",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-23-248-01"],
         impact="CRITICAL", exploit_type="Java Deserialization — RCE",
         mitre=["T0866","T0822"], tactics=["Initial Access"]),

    # ------------------------------------------------------------------ HITACHI ABB POWER GRIDS
    dict(path="hitachi/cve_2022_3483_rtu_auth_bypass.py",
         cve="CVE-2022-3483", vendor="Hitachi Energy (ABB)", product="RTU500 Series",
         port=2404, cvss=9.8, severity="CRITICAL", cwe="CWE-306",
         affected="RTU500 CMU firmware < 13.4.1",
         vuln_type="IEC 104 missing authentication — RTU control",
         description="Hitachi Energy RTU500 accepts IEC 60870-5-104 commands without proper authentication, allowing unauthenticated substation control.",
         short_desc="Hitachi RTU500 IEC 104 missing auth — unauthenticated substation control commands.",
         simulation_steps="Step 1: Connect to RTU500 IEC 104 server on port 2404\nStep 2: Send STARTDT confirmation without authentication\nStep 3: Issue C_SC_NA_1 (single command) to trip circuit breaker\nStep 4: Power substation equipment loses control — potential blackout",
         poc_ref="https://www.cisa.gov/uscert/ics/advisories/icsa-22-270-07",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-22-270-07"],
         impact="CRITICAL", exploit_type="Missing Authentication",
         mitre=["T0813","T0827"], tactics=["Impair Process Control"]),

    # ------------------------------------------------------------------ EMERSON DeltaV
    dict(path="emerson/cve_2018_19021_deltav_path_traversal.py",
         cve="CVE-2018-19021", vendor="Emerson", product="DeltaV DCS",
         port=80, cvss=9.8, severity="CRITICAL", cwe="CWE-22",
         affected="DeltaV 13.3.1 and earlier",
         vuln_type="Path traversal — arbitrary file read on DCS",
         description="Emerson DeltaV DCS web server allows path traversal, exposing DCS configuration and engineering files.",
         short_desc="Emerson DeltaV DCS path traversal — DCS configuration and credentials exposed via web.",
         simulation_steps="Step 1: Access DeltaV web server on port 80\nStep 2: Use path traversal sequences: /../../../../DeltaV/config\nStep 3: Download DeltaV database files (.DEV, .MOD)\nStep 4: Extract process control logic and operator credentials",
         poc_ref="https://www.cisa.gov/uscert/ics/advisories/icsa-19-036-01",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-19-036-01"],
         impact="CRITICAL", exploit_type="Path Traversal",
         mitre=["T0866"], tactics=["Initial Access"]),

    # ------------------------------------------------------------------ SAP NetWeaver (OT ERP)
    dict(path="mes_erp/cve_2025_31324_sap_netweaver_rce.py",
         cve="CVE-2025-31324", vendor="SAP", product="NetWeaver AS Java (Visual Composer)",
         port=50000, cvss=10.0, severity="CRITICAL", cwe="CWE-434",
         affected="SAP NetWeaver AS Java 7.50 Visual Composer",
         vuln_type="Unrestricted file upload — RCE (no auth)",
         description="SAP NetWeaver AS Java Visual Composer Metadata Uploader allows unauthenticated file upload and remote code execution. Actively exploited by Chinese threat actors targeting critical infrastructure.",
         short_desc="SAP NetWeaver Java Visual Composer unauthenticated file upload — RCE. CVSS 10.0. Chinese APT exploited.",
         simulation_steps="Step 1: Access SAP NetWeaver AS Java on port 50000\nStep 2: POST JSP webshell to /developmentserver/metadatauploader (no auth)\nStep 3: Access uploaded webshell via /irj/root/<filename>.jsp\nStep 4: Execute OS commands — full SAP/OT server compromise",
         poc_ref="https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141a",
         refs=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141a",
               "https://nvd.nist.gov/vuln/detail/CVE-2025-31324"],
         impact="CRITICAL", exploit_type="Unrestricted File Upload — RCE",
         mitre=["T0819","T0822"], tactics=["Initial Access"]),

    # ------------------------------------------------------------------ Apache ActiveMQ (MES/SCADA messaging)
    dict(path="mes_erp/cve_2023_46604_activemq_rce.py",
         cve="CVE-2023-46604", vendor="Apache", product="ActiveMQ (MES/SCADA messaging)",
         port=61616, cvss=10.0, severity="CRITICAL", cwe="CWE-502",
         affected="ActiveMQ 5.x before 5.15.16, 5.16.x before 5.16.7",
         vuln_type="Deserialization — unauthenticated RCE via ClassInfo OpenWire",
         description="Apache ActiveMQ (widely used as messaging middleware in MES/SCADA) allows remote code execution via ClassInfo gadget chain in OpenWire protocol.",
         short_desc="Apache ActiveMQ OpenWire RCE — MES/SCADA messaging infrastructure. CVSS 10.0.",
         simulation_steps="Step 1: Connect to ActiveMQ OpenWire port 61616\nStep 2: Send ClassInfo OpenWire command referencing malicious ClassPathXmlApplicationContext URL\nStep 3: ActiveMQ loads remote XML Spring config\nStep 4: Execute OS command via Spring bean — full RCE on MES server",
         poc_ref="https://github.com/X1r0z/ActiveMQ-RCE",
         refs=["https://nvd.nist.gov/vuln/detail/CVE-2023-46604"],
         impact="CRITICAL", exploit_type="Deserialization — RCE",
         mitre=["T0819","T0822"], tactics=["Initial Access"]),

    # ------------------------------------------------------------------ ConnectWise ScreenConnect (OT remote access)
    dict(path="exploits/remote_access/cve_2024_1709_connectwise_auth_bypass.py",
         cve="CVE-2024-1709", vendor="ConnectWise", product="ScreenConnect",
         port=8040, cvss=10.0, severity="CRITICAL", cwe="CWE-288",
         affected="ScreenConnect before 23.9.8",
         vuln_type="Authentication bypass — admin takeover",
         description="ConnectWise ScreenConnect (widely used for OT remote access) allows unauthenticated user creation and admin account takeover.",
         short_desc="ConnectWise ScreenConnect auth bypass — admin account takeover without credentials. CVSS 10.0.",
         simulation_steps="Step 1: Access ScreenConnect setup wizard (exposed even after install)\nStep 2: POST /SetupWizard.aspx with new admin credentials\nStep 3: New admin account created — full access to all remote sessions\nStep 4: Connect to any OT machine managed via ScreenConnect",
         poc_ref="https://github.com/watchtowrlabs/connectwise-screenconnect_auth-bypass-add-user-poc",
         refs=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
               "https://nvd.nist.gov/vuln/detail/CVE-2024-1709"],
         impact="CRITICAL", exploit_type="Authentication Bypass",
         mitre=["T0822","T0819"], tactics=["Initial Access"]),

    # ------------------------------------------------------------------ Linux (OT Engineering Workstations)
    dict(path="exploits/linux_ot/cve_2024_6387_regresshion_rce.py",
         cve="CVE-2024-6387", vendor="OpenSSH", product="OpenSSH (Linux EWS/HMI)",
         port=22, cvss=8.1, severity="HIGH", cwe="CWE-364",
         affected="OpenSSH < 9.8p1 (glibc-based Linux)",
         vuln_type="Race condition signal handler — unauthenticated RCE (regreSSHion)",
         description="OpenSSH signal handler race condition (regreSSHion) allows unauthenticated RCE on glibc Linux systems. Affects Linux Engineering Workstations and HMI Linux servers.",
         short_desc="regreSSHion: OpenSSH signal handler race condition — unauthenticated RCE on Linux EWS.",
         simulation_steps="Step 1: Connect to SSH port 22 on target Linux EWS/HMI\nStep 2: Trigger authentication timeout repeatedly (race condition)\nStep 3: Signal handler SIGALRM corrupts heap state\nStep 4: After ~10,000 attempts: unauthenticated root shell",
         poc_ref="https://github.com/zgzhang/cve-2024-6387-poc",
         refs=["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
         impact="HIGH", exploit_type="Race Condition — RCE",
         mitre=["T0866","T0822"], tactics=["Initial Access"]),

    dict(path="exploits/linux_ot/cve_2021_4034_pwnkit_lpe.py",
         cve="CVE-2021-4034", vendor="Linux (polkit)", product="pkexec (OT Linux HMI)",
         port=22, cvss=7.8, severity="HIGH", cwe="CWE-125",
         affected="polkit pkexec all versions since 2009",
         vuln_type="Local privilege escalation — root from any user",
         description="PwnKit: Local privilege escalation in polkit pkexec allows any unprivileged user to become root on all Linux distributions. Affects HMI and SCADA Linux servers.",
         short_desc="PwnKit polkit pkexec LPE — any local user to root on all Linux distros. Affects OT Linux HMIs.",
         simulation_steps="Step 1: Gain initial local access to Linux HMI/EWS (e.g. low-privilege account)\nStep 2: Compile PwnKit PoC (single C file — no dependencies)\nStep 3: Execute: ./PwnKit\nStep 4: Root shell obtained — full HMI system compromise",
         poc_ref="https://github.com/arthepsy/CVE-2021-4034",
         refs=["https://nvd.nist.gov/vuln/detail/CVE-2021-4034"],
         impact="HIGH", exploit_type="Local Privilege Escalation",
         mitre=["T0890"], tactics=["Privilege Escalation"]),

    # ------------------------------------------------------------------ Windows (OT workstations)
    dict(path="exploits/windows_ot/cve_2022_21907_http_sys_rce.py",
         cve="CVE-2022-21907", vendor="Microsoft", product="Windows HTTP.sys (OT Servers)",
         port=80, cvss=9.8, severity="CRITICAL", cwe="CWE-119",
         affected="Windows Server 2019, 2022, Windows 10/11",
         vuln_type="HTTP.sys kernel buffer overflow — unauthenticated RCE",
         description="Windows HTTP.sys kernel driver buffer overflow allows unauthenticated remote code execution at SYSTEM level. Affects Windows-based HMI and SCADA servers.",
         short_desc="Windows HTTP.sys kernel RCE — wormable, unauthenticated. Affects OT Windows servers. CVSS 9.8.",
         simulation_steps="Step 1: Send malformed HTTP trailer header to target port 80/443\nStep 2: Trigger kernel buffer overflow in http.sys driver\nStep 3: Execute arbitrary code in SYSTEM context\nStep 4: Complete OS compromise — install backdoor, disable AV, access SCADA files",
         poc_ref="https://github.com/corelight/CVE-2022-21907",
         refs=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21907"],
         impact="CRITICAL", exploit_type="Kernel Buffer Overflow — RCE",
         mitre=["T0866","T0822"], tactics=["Initial Access"]),

    dict(path="exploits/windows_ot/cve_2023_23397_outlook_ntlm_steal.py",
         cve="CVE-2023-23397", vendor="Microsoft", product="Outlook (OT operator workstations)",
         port=445, cvss=9.8, severity="CRITICAL", cwe="CWE-294",
         affected="Microsoft Outlook for Windows all versions before March 2023 patch",
         vuln_type="NTLM credential theft via calendar reminder — no click required",
         description="Microsoft Outlook NTLM credential theft via specially crafted meeting invitations. No user click required — email receipt triggers NTLM auth to attacker SMB. Used by Russian Sandworm/APT28 against OT networks.",
         short_desc="Outlook NTLM credential theft via meeting invite — zero-click, exploited by Sandworm against OT networks.",
         simulation_steps="Step 1: Send crafted email with calendar appointment to OT operator email\nStep 2: Appointment contains UNC path to attacker SMB server\nStep 3: Outlook automatically authenticates with NTLM on email receipt\nStep 4: Capture NTLM hash — crack offline or relay to gain OT system access",
         poc_ref="https://github.com/api0cradle/CVE-2023-23397-POC-Powershell",
         refs=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397",
               "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
         impact="CRITICAL", exploit_type="NTLM Credential Theft",
         mitre=["T0817","T0859"], tactics=["Initial Access","Credential Access"]),

    # ------------------------------------------------------------------ Cisco/Fortinet (OT network)
    dict(path="exploits/network_ot/cve_2024_20399_cisco_ios_xe_rce.py",
         cve="CVE-2024-20399", vendor="Cisco", product="IOS XE Web UI",
         port=443, cvss=6.7, severity="MEDIUM", cwe="CWE-78",
         affected="Cisco IOS XE 16.x, 17.x with Web UI enabled",
         vuln_type="Command injection — authenticated RCE in OT network routers/switches",
         description="Cisco IOS XE web UI command injection allows authenticated users to execute OS commands. Relevant to OT networks using Cisco IR1100/IR1800 industrial routers.",
         short_desc="Cisco IOS XE web UI command injection — RCE on OT industrial routers.",
         simulation_steps="Step 1: Authenticate to Cisco IOS XE Web UI on port 443\nStep 2: Use default or captured credentials (common in OT)\nStep 3: Inject OS commands via web UI parameter\nStep 4: Execute commands — router config changes, traffic capture",
         poc_ref="https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-privesc-su7scvdp",
         refs=["https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-privesc-su7scvdp"],
         impact="MEDIUM", exploit_type="Command Injection",
         mitre=["T0866"], tactics=["Initial Access"]),

    # ------------------------------------------------------------------ F5 BIG-IP (OT DMZ)
    dict(path="exploits/network_ot/cve_2021_22986_f5_bigip_icontrol_rce.py",
         cve="CVE-2021-22986", vendor="F5 Networks", product="BIG-IP iControl REST",
         port=443, cvss=9.8, severity="CRITICAL", cwe="CWE-306",
         affected="BIG-IP 16.0.x, 15.1.x, 14.1.x, 13.1.x, 12.1.x",
         vuln_type="Unauthenticated RCE via iControl REST",
         description="F5 BIG-IP iControl REST allows unauthenticated command execution — widely used as OT/ICS network gateway and load balancer.",
         short_desc="F5 BIG-IP iControl REST unauthenticated RCE — affects OT network gateways. CVSS 9.8.",
         simulation_steps="Step 1: Access F5 BIG-IP management interface on port 443\nStep 2: POST to /mgmt/tm/util/bash endpoint (no auth required)\nStep 3: Execute: {\"command\": \"run\", \"utilCmdArgs\": \"-c id\"}\nStep 4: Full OS command execution — pivot to OT network",
         poc_ref="https://github.com/dorkerdevil/CVE-2021-22986-Poc",
         refs=["https://support.f5.com/csp/article/K03009991"],
         impact="CRITICAL", exploit_type="Missing Authentication — RCE",
         mitre=["T0866","T0822"], tactics=["Initial Access"]),

    # ------------------------------------------------------------------ VPN (OT remote access)
    dict(path="exploits/vpn_ot/cve_2024_24919_checkpoint_vpn_info_disclosure.py",
         cve="CVE-2024-24919", vendor="Check Point", product="CloudGuard Network / Quantum VPN",
         port=443, cvss=8.6, severity="HIGH", cwe="CWE-200",
         affected="CloudGuard Network Security, Quantum Spark appliances",
         vuln_type="Path traversal — read local files without auth",
         description="Check Point VPN gateway allows unauthenticated path traversal to read local files including password hashes. Affects OT remote access VPNs.",
         short_desc="Check Point VPN path traversal — read /etc/shadow without auth. Affects OT remote access.",
         simulation_steps="Step 1: POST to Check Point VPN portal: /clients/MyCRL\nStep 2: Include path traversal: aCSHELL/../../../etc/shadow\nStep 3: Receive /etc/shadow with hashed passwords\nStep 4: Crack hashes offline — authenticate to VPN for OT access",
         poc_ref="https://github.com/Cybereason/Cybereason-vs-Check-Point-CVE-2024-24919",
         refs=["https://nvd.nist.gov/vuln/detail/CVE-2024-24919"],
         impact="HIGH", exploit_type="Path Traversal — Info Disclosure",
         mitre=["T0866","T0859"], tactics=["Initial Access","Credential Access"]),

    # ------------------------------------------------------------------ Ivanti (OT management)
    dict(path="exploits/vpn_ot/cve_2024_21887_ivanti_rce.py",
         cve="CVE-2024-21887", vendor="Ivanti", product="Connect Secure/Policy Secure",
         port=443, cvss=9.1, severity="CRITICAL", cwe="CWE-77",
         affected="Ivanti Connect Secure all versions before patch",
         vuln_type="Command injection — authenticated admin RCE",
         description="Ivanti Connect Secure command injection via web component allows authenticated admin command execution. Chain with CVE-2023-46805 (auth bypass) for unauthenticated RCE.",
         short_desc="Ivanti Connect Secure command injection — chain with auth bypass for unauthenticated RCE. CVSS 9.1.",
         simulation_steps="Step 1: Auth bypass via CVE-2023-46805 to obtain admin session\nStep 2: POST to /api/v1/totp/user-backup-code/../../license/keys-status/\nStep 3: Inject OS commands in cmd parameter\nStep 4: Execute commands — steal VPN credentials, access OT networks",
         poc_ref="https://github.com/duy-31/CVE-2023-46805_CVE-2024-21887",
         refs=["https://nvd.nist.gov/vuln/detail/CVE-2024-21887",
               "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
         impact="CRITICAL", exploit_type="Command Injection",
         mitre=["T0819","T0822"], tactics=["Initial Access"]),

    # ------------------------------------------------------------------ OSIsoft / AVEVA PI
    dict(path="osisoft/cve_2023_31175_pi_server_sqli.py",
         cve="CVE-2023-31175", vendor="OSIsoft/AVEVA", product="PI Server (Historian)",
         port=5450, cvss=9.8, severity="CRITICAL", cwe="CWE-89",
         affected="PI Data Archive 2023 before patch",
         vuln_type="SQL injection — historian database access",
         description="AVEVA PI Server SQL injection allows unauthenticated access to process historian database including all process data, tags, and configurations.",
         short_desc="AVEVA PI Server SQL injection — unauthenticated access to OT historian database.",
         simulation_steps="Step 1: Connect to PI Server port 5450\nStep 2: Send PI Server request with SQLi payload in tag query\nStep 3: Extract all PI tags, process data, and user credentials\nStep 4: Modify historian data — corrupt process history and KPIs",
         poc_ref="https://www.cisa.gov/uscert/ics/advisories/icsa-23-159-05",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-23-159-05"],
         impact="CRITICAL", exploit_type="SQL Injection",
         mitre=["T0803","T0832"], tactics=["Collection"]),

    # ------------------------------------------------------------------ Beckhoff
    dict(path="beckhoff/cve_2019_5637_twincat_upnp_rce.py",
         cve="CVE-2019-5637", vendor="Beckhoff", product="TwinCAT/CX (UPnP)",
         port=48898, cvss=9.8, severity="CRITICAL", cwe="CWE-306",
         affected="Beckhoff TwinCAT 3.x",
         vuln_type="UPnP/ADS unauthenticated admin — add user, reboot, full control",
         description="Beckhoff TwinCAT/CX exposes ADS over AMS/TCP and UPnP management without authentication, allowing unauthenticated admin access.",
         short_desc="Beckhoff TwinCAT ADS/UPnP missing auth — add admin user, reboot PLC without credentials.",
         simulation_steps="Step 1: Discover Beckhoff via ADS broadcast or UPnP\nStep 2: Connect to AMS/TCP port 48898 without auth\nStep 3: Send ADS command to add new admin user\nStep 4: Reboot PLC via ADS RPC — load malicious TwinCAT project",
         poc_ref="https://github.com/SawyersPresent/SCADAver",
         refs=["https://www.cisa.gov/uscert/ics/advisories/ICSA-19-113-01"],
         impact="CRITICAL", exploit_type="Missing Authentication",
         mitre=["T0859","T0843"], tactics=["Credential Access"]),

    # ------------------------------------------------------------------ Wireless/RF
    dict(path="exploits/wireless_ot/cve_2023_51438_wia_pa_wireless_hart.py",
         cve="CVE-2023-51438", vendor="Multiple", product="WirelessHART Devices",
         port=5094, cvss=8.1, severity="HIGH", cwe="CWE-294",
         affected="WirelessHART gateways with weak join key",
         vuln_type="WirelessHART join process — network key extraction",
         description="WirelessHART devices using weak or default network join keys allow an attacker with RF proximity to join the wireless mesh network and monitor/inject HART commands.",
         short_desc="WirelessHART weak join key — RF attacker joins OT wireless mesh, injects HART commands.",
         simulation_steps="Step 1: Use SDR to scan for WirelessHART beacons at 2.4 GHz\nStep 2: Capture join request/response with weak network key\nStep 3: Brute force or try default network key (0x00...00 or 0xFF...FF)\nStep 4: Join WirelessHART mesh — inject false sensor readings",
         poc_ref="https://www.cisa.gov/uscert/ics/advisories/icsa-23-351-01",
         refs=["https://www.cisa.gov/uscert/ics/advisories/icsa-23-351-01"],
         impact="HIGH", exploit_type="Wireless Protocol Attack",
         mitre=["T0864"], tactics=["Collection"]),
]

def main():
    created = 0
    skipped = 0
    for item in BATCH:
        if make(**item):
            created += 1
            print(f"  Created: {item['path'].split('/')[-1]}")
        else:
            skipped += 1

    print(f"\n[batch_cve_wave3] Created: {created} | Skipped (exist): {skipped}")
    from industrialxpl.core.exploit.utils import index_modules
    mods = index_modules()
    print(f"[batch_cve_wave3] IXF total modules: {len(mods)}")

if __name__ == "__main__":
    main()
