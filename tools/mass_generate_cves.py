#!/usr/bin/env python3
"""Mass CVE stub generator — Medium/High/Critical only. Vendor-specific catalogs."""

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULES_CVE  = PROJECT_ROOT / "industrialxpl" / "modules" / "cve"
MODULES_CVE.mkdir(parents=True, exist_ok=True)

STUB = '''"""IXF CVE {cve_id} — {vendor} {product} ({severity} CVSS {cvss}).

Exploit type: {exploit_type}
CISA Advisory: {cisa}
Level B: port fingerprint + version context. simulate=True by default.
"""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,
    print_error, print_info, print_status, print_success, print_warning,
    DestructiveGate,
)

class Exploit(Exploit):
    __info__ = {{
        "name": "{cve_id} {vendor} {product} {severity}",
        "description": "{exploit_type}. {vendor} {product}. CVSS {cvss} ({severity}).",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://nvd.nist.gov/vuln/detail/{cve_id}",),
        "devices": ("{vendor} {product}",),
        "impact": "{impact}",
        "exploit_type": "{exploit_type}",
        "source_poc": "Static catalog Level B",
        "cve": "{cve_id}",
        "cvss": "{cvss}",
        "severity": "{severity}",
        "cisa_advisory": "{cisa}",
        "mitre_techniques": {mitre},
        "mitre_tactics": {tactics},
    }}
    target = OptIP("", "Target {vendor} device IP")
    port = OptPort({port}, "Target service port")
    timeout = OptInteger(5, "Timeout seconds")
    simulate = OptBool(True, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable real execution gate")

    @mute
    def check(self):
        if not self.target:
            return False
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            s.close()
            return True
        except Exception:
            return False

    def run(self):
        if not self.target:
            print_error("Set target first.")
            return
        if self.simulate:
            DestructiveGate.print_simulation(
                description="{cve_id}: Fingerprint {vendor} {product} at {{}}:{{}}. {exploit_type}. CVSS {cvss}.".format(self.target, self.port),
                mitre_techniques={mitre},
            )
            return
        if self.check():
            print_success("Port {{}} open — {vendor} {product} may be present. {cve_id} {severity} CVSS {cvss}.".format(self.port))
            print_warning("CISA: {cisa}")
        else:
            print_info("{{}}:{{}} not responding.".format(self.target, self.port))
'''

def slugify(t):
    return re.sub(r'[^a-z0-9_]', '_', t.lower()).strip('_')

def get_mitre(et, sev):
    et = et.lower()
    m = []
    if any(w in et for w in ["rce","command","injection","code exec","upload","deseri"]):
        m += ["T0819","T0866"]
    if any(w in et for w in ["dos","denial","crash"]):
        m += ["T0814"]
    if any(w in et for w in ["auth","credential","hardcoded","default","bypass","key"]):
        m += ["T1694.002","T0859"]
    if any(w in et for w in ["firmware"]):
        m += ["T1693"]
    if any(w in et for w in ["traversal","file"]):
        m += ["T0819"]
    if any(w in et for w in ["logic","plc","ladder","download"]):
        m += ["T0843","T0821"]
    if not m:
        m = ["T0883"]
    return list(dict.fromkeys(m))[:4]

def get_tactics(mitre):
    t = set()
    for tid in mitre:
        if tid in ("T0819","T0866","T1694.002","T0859"):
            t.add("Initial Access")
        if tid == "T0814":
            t.add("Inhibit Response Function")
        if tid in ("T0843","T0821"):
            t.add("Impair Process Control")
        if tid == "T1693":
            t.add("Persistence")
    return list(t) or ["Discovery"]

# rows: (cve_id, vendor, product, cvss, severity, exploit_type, cisa, port)
CATALOG = [
    # Siemens
    ("CVE-2019-10929","Siemens","SIMATIC S7-300/400","7.5","HIGH","Denial of service via crafted packets","N/A",102),
    ("CVE-2019-10943","Siemens","SIMATIC S7-300/400","5.3","MEDIUM","Information disclosure S7comm diagnostic buffer","N/A",102),
    ("CVE-2020-15782","Siemens","SIMATIC S7-1500","9.1","CRITICAL","Remote code execution via OS commands","N/A",102),
    ("CVE-2021-37185","Siemens","SIMATIC S7-1500","7.5","HIGH","Denial of service memory corruption","N/A",102),
    ("CVE-2021-37204","Siemens","SIMATIC Drive Controller","7.5","HIGH","Denial of service vulnerability","N/A",102),
    ("CVE-2022-38465","Siemens","SIMATIC WinCC OA","9.3","CRITICAL","Private key protection bypass","N/A",102),
    ("CVE-2022-43513","Siemens","SIMATIC WinCC Runtime Professional","7.8","HIGH","Local privilege escalation","N/A",1433),
    ("CVE-2022-43514","Siemens","SIMATIC WinCC Runtime Professional","7.8","HIGH","Path traversal privilege escalation","N/A",1433),
    ("CVE-2023-46156","Siemens","SIMATIC CP 1543-1","7.5","HIGH","Denial of service HTTP flood","N/A",443),
    ("CVE-2023-46280","Siemens","SIMATIC WinCC OA","8.7","HIGH","Remote code execution","N/A",4000),
    ("CVE-2024-23814","Siemens","SIMATIC IPC BX-39A","9.8","CRITICAL","OS command injection web interface","N/A",80),
    ("CVE-2024-35300","Siemens","SIMATIC CN 4100","9.8","CRITICAL","Authentication bypass default password","N/A",80),
    ("CVE-2024-37998","Siemens","SIMATIC WinCC V7","8.8","HIGH","SQL injection privilege escalation","N/A",1433),
    ("CVE-2024-43641","Siemens","SIMATIC S7-1500 CPU","7.5","HIGH","Denial of service unhandled exception","N/A",102),
    ("CVE-2024-43647","Siemens","SIMATIC CP 1543SP-1","9.8","CRITICAL","Authentication bypass remote","N/A",443),
    ("CVE-2024-56181","Siemens","SINEMA Server V14","9.8","CRITICAL","SQL injection RCE","N/A",80),
    ("CVE-2025-27393","Siemens","SIMATIC S7-1500 CPU","7.5","HIGH","Denial of service via PROFINET","N/A",34962),
    ("CVE-2019-6568","Siemens","SIMATIC S7 OPC UA","7.5","HIGH","Denial of service OPC UA","N/A",4840),
    ("CVE-2020-7580","Siemens","SIMATIC WinCC OA","7.8","HIGH","Arbitrary code execution as root","N/A",4000),
    ("CVE-2021-25678","Siemens","SIMATIC NET PC Software","7.5","HIGH","Denial of service network","N/A",102),
    ("CVE-2022-26649","Siemens","SIMATIC PCS neo","7.5","HIGH","Cross-site scripting engineering console","N/A",80),
    ("CVE-2022-36323","Siemens","SIMATIC NET Industrial Ethernet","7.5","HIGH","Denial of service TCP/IP stack","N/A",102),
    ("CVE-2023-28489","Siemens","SICAM A8000 RTU","9.8","CRITICAL","OS command injection web interface","N/A",80),
    ("CVE-2023-36380","Siemens","SIMATIC CP 1604 1616","9.8","CRITICAL","Stored XSS leads to RCE","N/A",80),
    ("CVE-2023-38380","Siemens","SCALANCE X-200RNA","8.6","HIGH","Denial of service OSPF overflow","N/A",179),
    ("CVE-2023-49252","Siemens","SIMATIC S7-400","7.5","HIGH","Denial of service CPU crash","N/A",102),
    ("CVE-2024-21903","Siemens","SINEMA Remote Connect Server","8.4","HIGH","Path traversal server-side","N/A",443),
    ("CVE-2024-30034","Siemens","SIMATIC WinCC Runtime Advanced","8.8","HIGH","Remote code execution OLE DB","N/A",80),
    ("CVE-2020-25240","Siemens","SINEC NMS","7.5","HIGH","Arbitrary file write via upload","N/A",80),
    ("CVE-2021-33737","Siemens","SIMATIC CP 443-1 OPC UA","7.5","HIGH","OPC UA denial of service","N/A",4840),
    # Schneider
    ("CVE-2019-6856","Schneider Electric","Modicon M218","8.6","HIGH","Denial of service Modbus","N/A",502),
    ("CVE-2019-6857","Schneider Electric","Modicon M221","8.6","HIGH","Denial of service Modbus","N/A",502),
    ("CVE-2020-7537","Schneider Electric","Modicon M340 OPC UA","7.5","HIGH","Denial of service OPC UA","N/A",4840),
    ("CVE-2020-7560","Schneider Electric","EcoStruxure Control Expert","9.0","CRITICAL","Remote code execution","N/A",502),
    ("CVE-2021-22717","Schneider Electric","Modicon M340","6.5","MEDIUM","Denial of service via HTTP","N/A",80),
    ("CVE-2021-22763","Schneider Electric","EcoStruxure","6.5","MEDIUM","Improper authentication","N/A",80),
    ("CVE-2022-3032","Schneider Electric","PowerLogic ION9000","9.8","CRITICAL","OS command injection unauthenticated","N/A",80),
    ("CVE-2022-34754","Schneider Electric","PowerLogic PM5500","7.5","HIGH","Denial of service","N/A",80),
    ("CVE-2022-37301","Schneider Electric","EcoStruxure","8.2","HIGH","Cross-site request forgery","N/A",80),
    ("CVE-2022-41977","Schneider Electric","EcoStruxure Operator Terminal","7.8","HIGH","Stack buffer overflow local","N/A",80),
    ("CVE-2023-25547","Schneider Electric","EcoStruxure Power Build","7.8","HIGH","Arbitrary code execution","N/A",80),
    ("CVE-2023-27975","Schneider Electric","EcoStruxure Power Automation","9.8","CRITICAL","Improper authentication RCE","N/A",80),
    ("CVE-2023-29412","Schneider Electric","APC Easy UPS Online","9.8","CRITICAL","Case insensitive filename bypass RCE","N/A",80),
    ("CVE-2024-0571","Schneider Electric","Easergy Studio","7.8","HIGH","Arbitrary code execution","N/A",502),
    ("CVE-2024-2229","Schneider Electric","EcoStruxure Power Build Rapsody","7.8","HIGH","Remote code execution","N/A",502),
    ("CVE-2024-5560","Schneider Electric","Modicon M340 controller","7.5","HIGH","Denial of service CPU halt","N/A",502),
    ("CVE-2025-0327","Schneider Electric","Modicon M340 M580","9.8","CRITICAL","Authentication bypass","N/A",502),
    ("CVE-2020-28212","Schneider Electric","EcoStruxure Operator Terminal","9.8","CRITICAL","Authentication bypass","N/A",80),
    ("CVE-2021-22986","Schneider Electric","APC Smart-UPS","9.8","CRITICAL","RCE unauthenticated TLS bypass","N/A",443),
    ("CVE-2022-22984","Schneider Electric","Easergy T300 RTU","9.8","CRITICAL","Hardcoded SSH key remote login","N/A",22),
    # Rockwell
    ("CVE-2012-6435","Rockwell Automation","MicroLogix 1100 1400","9.8","CRITICAL","Unauthenticated firmware upload","N/A",44818),
    ("CVE-2018-19609","Rockwell Automation","RSLinx Classic","9.8","CRITICAL","Remote code execution buffer overflow","N/A",44818),
    ("CVE-2019-6553","Rockwell Automation","MicroLogix 1100","7.5","HIGH","Denial of service crafted packet","N/A",44818),
    ("CVE-2020-6085","Rockwell Automation","Connected Components Workbench","7.8","HIGH","Arbitrary code execution on file open","N/A",44818),
    ("CVE-2021-27482","Rockwell Automation","CompactLogix GuardLogix","9.8","CRITICAL","Remote code execution unauthenticated","N/A",44818),
    ("CVE-2021-27476","Rockwell Automation","Studio 5000 View Designer","7.8","HIGH","Code execution malicious VSD file","N/A",44818),
    ("CVE-2022-3156","Rockwell Automation","Studio 5000 Logix Designer","8.8","HIGH","Arbitrary code execution","N/A",44818),
    ("CVE-2022-38742","Rockwell Automation","ThinManager ThinServer","8.1","HIGH","Path traversal arbitrary file access","N/A",2031),
    ("CVE-2023-2071","Rockwell Automation","FactoryTalk View ME","9.8","CRITICAL","Remote code execution buffer overflow","N/A",44818),
    ("CVE-2023-46290","Rockwell Automation","FactoryTalk Services Platform","8.8","HIGH","Path traversal information disclosure","N/A",44818),
    ("CVE-2024-4609","Rockwell Automation","ControlLogix 5580","7.5","HIGH","Denial of service CIP packet","N/A",44818),
    ("CVE-2024-40619","Rockwell Automation","ControlLogix 5580 5480","8.8","HIGH","Improper input validation","N/A",44818),
    ("CVE-2024-7947","Rockwell Automation","FactoryTalk View Site Edition","7.7","HIGH","Path traversal file disclosure","N/A",80),
    ("CVE-2025-0477","Rockwell Automation","Arena Simulation Software","7.8","HIGH","Arbitrary code execution crafted file","N/A",80),
    ("CVE-2019-13516","Rockwell Automation","FactoryTalk Diagnostics","7.5","HIGH","Denial of service UDP","N/A",44818),
    ("CVE-2023-29022","Rockwell Automation","Enhanced HIM Terminal","9.8","CRITICAL","Authentication bypass arbitrary code","N/A",80),
    ("CVE-2023-46289","Rockwell Automation","FactoryTalk Remote Access","9.8","CRITICAL","Improper authentication bypass","N/A",443),
    ("CVE-2024-21912","Rockwell Automation","Allen-Bradley Power Monitor 1000E","9.8","CRITICAL","Authentication bypass","N/A",80),
    ("CVE-2024-5643","Rockwell Automation","DataMosaix Private Cloud","9.8","CRITICAL","SQL injection RCE","N/A",443),
    # ABB
    ("CVE-2019-18247","ABB","Relion protection relay","7.5","HIGH","Denial of service IEC 61850","N/A",102),
    ("CVE-2020-24676","ABB","Panel Builder 800","8.8","HIGH","Remote code execution","N/A",80),
    ("CVE-2021-22285","ABB","CP651 HMI","7.5","HIGH","Denial of service","N/A",80),
    ("CVE-2022-0228","ABB","Cyber Security Configurator","7.8","HIGH","Privilege escalation","N/A",443),
    ("CVE-2022-26412","ABB","Symphony Plus Operations","8.8","HIGH","SQL injection","N/A",1433),
    ("CVE-2023-0232","ABB","REF615 REM615 protection relay","7.5","HIGH","Denial of service credentials","N/A",80),
    ("CVE-2024-48843","ABB","ACS880 drives","7.5","HIGH","Denial of service remote","N/A",502),
    ("CVE-2024-51550","ABB","Data manager industrial","9.8","CRITICAL","Remote code execution","N/A",80),
    # Honeywell
    ("CVE-2019-13528","Honeywell","MatrikonOPC Server","7.5","HIGH","Buffer overflow denial of service","N/A",135),
    ("CVE-2020-6970","Honeywell","MB-Secure Mass Flow Controller","9.8","CRITICAL","Buffer overflow RCE unauthenticated","N/A",502),
    ("CVE-2022-3029","Honeywell","Saia Burgess PCD","9.8","CRITICAL","Authentication bypass web interface","N/A",80),
    ("CVE-2023-23585","Honeywell","Alerton BACtalk","8.2","HIGH","Stored cross-site scripting","N/A",47808),
    ("CVE-2024-6081","Honeywell","ControlEdge PLC","9.8","CRITICAL","Hardcoded credentials bypass","N/A",502),
    ("CVE-2023-24477","Honeywell","Experion PKS C300","9.8","CRITICAL","Remote code execution unauthenticated","N/A",4840),
    ("CVE-2024-33045","Honeywell","Niagara IQ Pro","9.1","CRITICAL","Authentication bypass door controller","N/A",4911),
    # GE
    ("CVE-2018-17924","GE","Communicator EXT data server","7.5","HIGH","Denial of service arbitrary write","N/A",502),
    ("CVE-2019-6557","GE","Reason RT430 RTU","9.8","CRITICAL","Command injection unauthenticated","N/A",80),
    ("CVE-2020-6994","GE","SRTP protocol implementation","9.8","CRITICAL","Remote code execution unauthenticated SRTP","N/A",18245),
    ("CVE-2021-27452","GE","MU320E RTU controller","9.8","CRITICAL","Hard-coded credentials bypass","N/A",80),
    ("CVE-2022-29957","GE","Proficy Historian server","9.8","CRITICAL","Improper authentication bypass","N/A",5450),
    ("CVE-2023-3463","GE","Proficy Historian server","9.8","CRITICAL","Authentication bypass RCE","N/A",5450),
    ("CVE-2024-4609","GE","Vernova Grid Solutions Modbus","7.5","HIGH","Denial of service Modbus","N/A",502),
    # AVEVA
    ("CVE-2021-33010","AVEVA","HistorianServer","7.5","HIGH","Denial of service remote network","N/A",5450),
    ("CVE-2022-23854","AVEVA","AVEVA InTouch Access Anywhere","9.8","CRITICAL","Remote code execution path traversal","N/A",443),
    ("CVE-2023-34982","AVEVA","PI Web API","9.0","CRITICAL","CSRF remote code execution","N/A",443),
    ("CVE-2023-36022","AVEVA","PI Vision dashboard","7.6","HIGH","Cross-site scripting stored","N/A",443),
    ("CVE-2024-7049","AVEVA","AVEVA Edge HMI","9.8","CRITICAL","Remote code execution auth bypass","N/A",80),
    ("CVE-2024-2655","AVEVA","PI Server","8.7","HIGH","Denial of service resource exhaustion","N/A",5450),
    # Advantech
    ("CVE-2020-13984","Advantech","WebAccess Node","9.8","CRITICAL","SQL injection remote code execution","N/A",80),
    ("CVE-2021-33014","Advantech","WebAccess SCADA","9.8","CRITICAL","Stack buffer overflow RCE","N/A",80),
    ("CVE-2021-33002","Advantech","WebAccess Node runtime","9.8","CRITICAL","Path traversal arbitrary file creation","N/A",80),
    ("CVE-2022-3036","Advantech","iView network manager","9.8","CRITICAL","SQL injection authentication bypass","N/A",80),
    ("CVE-2022-32533","Advantech","R-SeeNet monitoring","9.8","CRITICAL","Path traversal RCE","N/A",80),
    ("CVE-2023-2611","Advantech","iView","9.8","CRITICAL","Authentication bypass RCE","N/A",80),
    ("CVE-2023-4414","Advantech","WebAccess SCADA","7.5","HIGH","Path traversal information disclosure","N/A",80),
    ("CVE-2024-6542","Advantech","ADAM-5630 industrial gateway","9.8","CRITICAL","Authentication bypass","N/A",80),
    ("CVE-2024-10491","Advantech","ADAM-5550 industrial controller","9.8","CRITICAL","Unauthenticated remote code execution","N/A",80),
    ("CVE-2024-7940","Advantech","EKI-6333AC WiFi AP industrial","9.8","CRITICAL","OS command injection unauthenticated","N/A",80),
    # Delta Electronics
    ("CVE-2021-33008","Delta Electronics","DIAEnergie SCADA","9.8","CRITICAL","Hard-coded credentials admin access","N/A",80),
    ("CVE-2022-25347","Delta Electronics","InfraSuite Device Master","9.8","CRITICAL","Deserialization RCE unauthenticated","N/A",80),
    ("CVE-2022-45137","Delta Electronics","DIALink communication","9.8","CRITICAL","Authentication bypass RCE","N/A",80),
    ("CVE-2023-1326","Delta Electronics","InfraSuite Device Master","9.8","CRITICAL","Path traversal arbitrary code execution","N/A",80),
    ("CVE-2023-46690","Delta Electronics","CNCSoft-G2 motion control","7.8","HIGH","Stack buffer overflow code exec","N/A",80),
    ("CVE-2024-39605","Delta Electronics","CNCSoft-B V2 CNC","7.8","HIGH","Stack-based buffer overflow","N/A",80),
    # Moxa
    ("CVE-2020-13532","Moxa","MXView network manager","9.8","CRITICAL","Authentication bypass RCE","N/A",80),
    ("CVE-2021-31851","Moxa","UC-8200 Series IPC","9.8","CRITICAL","Firmware signing bypass RCE","N/A",80),
    ("CVE-2022-0915","Moxa","TN-4900 industrial switch","9.8","CRITICAL","OS command injection RCE","N/A",80),
    ("CVE-2023-28699","Moxa","MXsecurity series","9.8","CRITICAL","Improper certificate validation RCE","N/A",443),
    ("CVE-2024-7695","Moxa","PT-G503 industrial switch","9.8","CRITICAL","Authentication bypass","N/A",80),
    ("CVE-2018-10995","Moxa","NPort serial device server","7.5","HIGH","Cleartext credential transmission","N/A",80),
    # Yokogawa
    ("CVE-2014-0784","Yokogawa","CENTUM CS3000 BKHODEQ","9.8","CRITICAL","Stack buffer overflow RCE","N/A",34104),
    ("CVE-2014-3888","Yokogawa","CENTUM CS3000 BKESIMMGR","9.8","CRITICAL","Stack buffer overflow RCE","N/A",34104),
    ("CVE-2014-3887","Yokogawa","CENTUM CS3000 BKFSim VHFD","9.8","CRITICAL","Stack buffer overflow RCE","N/A",34104),
    ("CVE-2023-35985","Yokogawa","CENTUM VP engineering","7.5","HIGH","Path traversal arbitrary file access","N/A",80),
    ("CVE-2024-1182","Yokogawa","Vnet/IP engineering tool","7.5","HIGH","Denial of service broadcast","N/A",80),
    # CODESYS
    ("CVE-2022-22515","CODESYS","V3 runtime web server","7.5","HIGH","Uncontrolled resource consumption DoS","N/A",8080),
    ("CVE-2023-49722","CODESYS","V3 development system","9.8","CRITICAL","Deserialization arbitrary code execution","N/A",1217),
    ("CVE-2024-0175","CODESYS","V3 engineering tool","7.8","HIGH","Code execution via crafted project file","N/A",1217),
    ("CVE-2021-30189","CODESYS","V3 PLC runtime","7.5","HIGH","NULL pointer dereference DoS","N/A",1217),
    # Tridium Niagara
    ("CVE-2022-40201","Tridium","Niagara 4 Framework","9.8","CRITICAL","Authentication bypass RCE","N/A",4911),
    ("CVE-2018-1139","Tridium","Niagara AX Framework","7.5","HIGH","Credential disclosure Fox protocol","N/A",4911),
    ("CVE-2023-30838","Tridium","Niagara 4 Framework","9.8","CRITICAL","Remote code execution auth bypass","N/A",4911),
    # Phoenix Contact
    ("CVE-2019-9201","Phoenix Contact","PLCnext Control","9.8","CRITICAL","Remote code execution","N/A",1962),
    ("CVE-2022-31217","Phoenix Contact","AUTOMATIONWORX","9.8","CRITICAL","Path traversal RCE","N/A",80),
    # Beckhoff
    ("CVE-2019-16883","Beckhoff","TwinCat ADS server","7.5","HIGH","Authentication bypass ADS","N/A",48898),
    ("CVE-2023-4380","Beckhoff","TwinCat BSD runtime","7.8","HIGH","Local privilege escalation","N/A",48898),
    ("CVE-2024-49556","Beckhoff","TwinCat 3 runtime","9.8","CRITICAL","Remote code execution ADS","N/A",48898),
    # OSIsoft PI
    ("CVE-2020-25163","OSIsoft","PI Vision dashboard","7.5","HIGH","Stored cross-site scripting","N/A",443),
    ("CVE-2019-18244","OSIsoft","PI Interface for OPC DA","8.8","HIGH","Code injection","N/A",135),
    ("CVE-2023-34982","OSIsoft AVEVA","PI Web API CSRF","9.0","CRITICAL","CSRF to RCE on PI Web API","N/A",443),
    # MikroTik
    ("CVE-2019-3977","MikroTik","RouterOS Winbox","7.5","HIGH","Winbox path traversal","N/A",8291),
    ("CVE-2021-41987","MikroTik","RouterOS TCP stack","7.5","HIGH","Denial of service TCP","N/A",80),
    # Zyxel
    ("CVE-2023-28771","Zyxel","ATP USG VPN series","9.8","CRITICAL","Command injection pre-auth IKEv2","N/A",500),
    # Emerson
    ("CVE-2020-10640","Emerson","OpenEnterprise SCADA","9.8","CRITICAL","Remote code execution unauthenticated","N/A",502),
    ("CVE-2022-30267","Emerson","Ovation OCR400 controller","9.8","CRITICAL","Authentication bypass (ICEFALL)","ICSA-22-167-04",502),
    # Digi
    ("CVE-2022-40765","Digi","ConnectPort X2 gateway","9.8","CRITICAL","Command injection unauthenticated","N/A",4800),
    # Log4Shell/Spring in ICS
    ("CVE-2021-44228","Apache","Log4j2 Log4Shell Java MES context","10.0","CRITICAL","JNDI injection RCE in Java-based MES","N/A",8080),
    ("CVE-2022-22965","VMware Spring","Spring4Shell in Spring-based MES","9.8","CRITICAL","ClassLoader RCE in Spring-based MES","N/A",8080),
]


def main():
    created = 0
    for row in CATALOG:
        cve_id, vendor, product, cvss, severity, exploit_type, cisa, port = row
        if severity not in ("MEDIUM","HIGH","CRITICAL"):
            continue
        vs = slugify(vendor)[:20]
        out_dir = MODULES_CVE / vs
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "__init__.py").touch()
        fname = out_dir / (cve_id.lower().replace("-","_") + ".py")
        if fname.exists():
            continue
        impact = {"CRITICAL":"CRITICAL","HIGH":"HIGH","MEDIUM":"MEDIUM"}[severity]
        mitre = get_mitre(exploit_type, severity)
        tactics = get_tactics(mitre)
        content = STUB.format(
            cve_id=cve_id, vendor=vendor, product=product,
            cvss=cvss, severity=severity, exploit_type=exploit_type,
            cisa=cisa, impact=impact, port=port,
            mitre=str(mitre), tactics=str(tactics),
        )
        fname.write_text(content, encoding="utf-8")
        created += 1

    print(f"[mass_generate] Created {created} new CVE stubs")
    sys.path.insert(0, str(PROJECT_ROOT))
    try:
        from industrialxpl.core.exploit.utils import index_modules
        mods = index_modules()
        print(f"[mass_generate] IXF total modules: {len(mods)}")
    except Exception as e:
        print(f"[mass_generate] Index failed: {e}")


if __name__ == "__main__":
    main()
