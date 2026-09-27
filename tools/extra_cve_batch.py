#!/usr/bin/env python3
"""Extra CVE batch — Medium/High/Critical only, expanded vendor coverage."""
import re, sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULES_CVE = PROJECT_ROOT / "industrialxpl" / "modules" / "cve"
MODULES_CVE.mkdir(parents=True, exist_ok=True)

def make_stub(cve_id, vendor, product, cvss, severity, exploit_type, cisa, port, impact):
    return (
        f'"""IXF CVE {cve_id} {vendor} {product} {severity} CVSS {cvss}.\n'
        f'Exploit: {exploit_type}. CISA: {cisa}.\n"""\n'
        "import socket\n"
        "from industrialxpl.core.exploit import (\n"
        "    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,\n"
        "    print_error, print_info, print_success, DestructiveGate,\n"
        ")\n\n"
        "class Exploit(Exploit):\n"
        "    __info__ = {\n"
        f'        "name": "{cve_id} {vendor} {severity}",\n'
        f'        "description": "{exploit_type}. {vendor} {product}. CVSS {cvss} ({severity}).",\n'
        '        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),\n'
        f'        "references": ("https://nvd.nist.gov/vuln/detail/{cve_id}",),\n'
        f'        "devices": ("{vendor} {product}",),\n'
        f'        "impact": "{impact}",\n'
        f'        "exploit_type": "{exploit_type}",\n'
        '        "source_poc": "Static catalog Level B",\n'
        f'        "cve": "{cve_id}",\n'
        f'        "cvss": "{cvss}",\n'
        f'        "severity": "{severity}",\n'
        f'        "cisa_advisory": "{cisa}",\n'
        '        "mitre_techniques": ["T0883", "T0888"],\n'
        '        "mitre_tactics": ["Discovery"],\n'
        "    }\n"
        f'    target = OptIP("", "Target {vendor} IP")\n'
        f'    port = OptPort({port}, "Target port")\n'
        "    timeout = OptInteger(5, \"Timeout\")\n"
        '    simulate = OptBool(True, "Simulate mode (default: True)")\n'
        '    destructive = OptBool(False, "Enable real execution")\n\n'
        "    @mute\n"
        "    def check(self):\n"
        "        if not self.target: return False\n"
        "        try:\n"
        "            s = socket.socket(); s.settimeout(self.timeout)\n"
        "            s.connect((self.target, self.port)); s.close(); return True\n"
        "        except Exception: return False\n\n"
        "    def run(self):\n"
        "        if not self.target: print_error(\"Set target.\"); return\n"
        "        if self.simulate:\n"
        "            DestructiveGate.print_simulation(\n"
        f'                description="{cve_id}: {{}}:{{}}.  {exploit_type}. CVSS {cvss}.".format(self.target, self.port),\n'
        '                mitre_techniques=["T0883"],\n'
        "            ); return\n"
        f'        print_success("{cve_id} {severity} — port {{}} open.".format(self.port)) if self.check() else print_error("Not responding.")\n'
    )

def sl(t):
    return re.sub(r'[^a-z0-9_]', '_', t.lower()).strip('_')

BATCH = [
    # Siemens
    ("CVE-2017-2680","Siemens","SIMATIC S7-200 SMART","7.5","HIGH","Denial of service crafted Modbus packet","N/A",502),
    ("CVE-2018-13800","Siemens","SIMATIC HMI Panels","9.8","CRITICAL","Remote code execution arbitrary file upload","N/A",80),
    ("CVE-2019-10953","Siemens","SIMATIC WinCC V7.3","7.5","HIGH","SQL injection SCADA historian","N/A",1433),
    ("CVE-2021-33925","Siemens","SIMATIC RTLS Locating Manager","8.8","HIGH","Privilege escalation","N/A",80),
    ("CVE-2022-27484","Siemens","SIMATIC WinCC Runtime","7.5","HIGH","SQL injection","N/A",1433),
    ("CVE-2023-38876","Siemens","SIMATIC CP 343-1","7.5","HIGH","Denial of service crafted packet","N/A",102),
    ("CVE-2024-21684","Siemens","SCALANCE W1700 series","9.8","CRITICAL","Stack overflow unauthenticated","N/A",80),
    ("CVE-2024-36556","Siemens","SIMATIC S7-1500 FW","7.5","HIGH","Denial of service memory","N/A",102),
    ("CVE-2025-23403","Siemens","SIMATIC WinCC unified SCADA","9.8","CRITICAL","Remote code execution unified","N/A",80),
    ("CVE-2020-28388","Siemens","OpenPCS 7 process control","5.3","MEDIUM","Information disclosure log files","N/A",80),
    # Schneider
    ("CVE-2018-7810","Schneider Electric","InduSoft Web Studio","9.8","CRITICAL","Buffer overflow remote code execution","N/A",80),
    ("CVE-2019-6819","Schneider Electric","Modicon M100","7.5","HIGH","Denial of service","N/A",502),
    ("CVE-2020-7516","Schneider Electric","EcoStruxure Augmented Operator","7.8","HIGH","Remote code execution arbitrary file","N/A",80),
    ("CVE-2021-22820","Schneider Electric","Enerlin-X Ethernet gateway","9.8","CRITICAL","Authentication bypass","N/A",80),
    ("CVE-2022-34753","Schneider Electric","SpaceLogic C-Bus Toolkit","7.8","HIGH","Remote code execution crafted file","N/A",80),
    ("CVE-2025-0972","Schneider Electric","Vijeo Designer Basic HMI","7.8","HIGH","Code execution malicious project file","N/A",80),
    # Rockwell
    ("CVE-2017-7899","Rockwell Automation","RSLinx Classic EDS subsystem","9.8","CRITICAL","Stack buffer overflow","N/A",44818),
    ("CVE-2018-14821","Rockwell Automation","RSLinx Classic EtherNet/IP","7.5","HIGH","Denial of service","N/A",44818),
    ("CVE-2019-13510","Rockwell Automation","Arena Simulation software","7.8","HIGH","Code execution crafted file","N/A",80),
    ("CVE-2020-11999","Rockwell Automation","Studio 5000 Logix Designer","7.8","HIGH","Deserialization code execution","N/A",44818),
    ("CVE-2022-2179","Rockwell Automation","FactoryTalk Analytics","7.5","HIGH","Remote code execution path traversal","N/A",80),
    ("CVE-2023-27855","Rockwell Automation","Arena Simulation","7.8","HIGH","Code execution out-of-bounds write","N/A",80),
    ("CVE-2024-2426","Rockwell Automation","FactoryTalk View ME Station","9.8","CRITICAL","Authentication bypass remote","N/A",44818),
    # Omron
    ("CVE-2019-18253","Omron","CX-One CX-Programmer","7.8","HIGH","Stack buffer overflow on file open","N/A",9600),
    ("CVE-2021-33008","Omron","CX-Supervisor HMI","7.8","HIGH","Heap overflow arbitrary code execution","N/A",9600),
    ("CVE-2024-27126","Omron","NX7 controller engineering tool","7.5","HIGH","Denial of service memory","N/A",9600),
    # GE
    ("CVE-2012-2508","GE","Proficy HMI Historian","9.8","CRITICAL","Remote code execution stack overflow","N/A",80),
    ("CVE-2016-8361","GE","Predix Machine IoT platform","8.1","HIGH","Improper authentication remote","N/A",80),
    # ABB
    ("CVE-2021-22281","ABB","Symphony Plus S+ Operations","8.8","HIGH","Deserialization of untrusted data","N/A",80),
    ("CVE-2023-0232","ABB","REF615 REM615 protection relay","7.5","HIGH","Denial of service credentials","N/A",80),
    # Honeywell
    ("CVE-2020-6970","Honeywell","MB-Secure Mass Flow Controller","9.8","CRITICAL","Buffer overflow RCE unauthenticated","N/A",502),
    ("CVE-2023-23585","Honeywell","Alerton BACtalk BMS","8.2","HIGH","Stored cross-site scripting","N/A",47808),
    ("CVE-2024-6081","Honeywell","ControlEdge PLC hardcoded","9.8","CRITICAL","Hardcoded credentials bypass","N/A",502),
    # AVEVA
    ("CVE-2021-33010","AVEVA","HistorianServer network","7.5","HIGH","Denial of service remote network","N/A",5450),
    ("CVE-2023-36022","AVEVA","PI Vision dashboard XSS","7.6","HIGH","Cross-site scripting stored","N/A",443),
    ("CVE-2024-2655","AVEVA","PI Server resource","8.7","HIGH","Denial of service resource exhaustion","N/A",5450),
    # Delta
    ("CVE-2024-39605","Delta Electronics","CNCSoft-B V2 CNC","7.8","HIGH","Stack-based buffer overflow","N/A",80),
    # Moxa
    ("CVE-2023-28699","Moxa","MXsecurity series","9.8","CRITICAL","Improper certificate validation RCE","N/A",443),
    ("CVE-2022-0915","Moxa","TN-4900 industrial switch","9.8","CRITICAL","OS command injection RCE","N/A",80),
    # MikroTik
    ("CVE-2021-41987","MikroTik","RouterOS TCP stack","7.5","HIGH","Denial of service TCP","N/A",80),
    # Zyxel
    ("CVE-2023-28771","Zyxel","ATP USG VPN IKEv2","9.8","CRITICAL","Command injection pre-auth via IKEv2","N/A",500),
    # OSIsoft
    ("CVE-2020-25163","OSIsoft","PI Vision dashboard","7.5","HIGH","Stored cross-site scripting","N/A",443),
    ("CVE-2019-18244","OSIsoft","PI Interface for OPC DA","8.8","HIGH","Code injection vulnerability","N/A",135),
    # CODESYS
    ("CVE-2022-22515","CODESYS","V3 runtime web server","7.5","HIGH","Uncontrolled resource consumption DoS","N/A",8080),
    ("CVE-2023-49722","CODESYS","V3 development system","9.8","CRITICAL","Deserialization arbitrary code execution","N/A",1217),
    ("CVE-2024-0175","CODESYS","V3 engineering tool","7.8","HIGH","Code execution crafted project file","N/A",1217),
    # Beckhoff
    ("CVE-2023-4380","Beckhoff","TwinCat BSD runtime","7.8","HIGH","Local privilege escalation","N/A",48898),
    ("CVE-2024-49556","Beckhoff","TwinCat 3 runtime ADS","9.8","CRITICAL","Remote code execution ADS protocol","N/A",48898),
    # Phoenix Contact
    ("CVE-2022-31217","Phoenix Contact","AUTOMATIONWORX","9.8","CRITICAL","Path traversal RCE","N/A",80),
    ("CVE-2019-9201","Phoenix Contact","PLCnext Control","9.8","CRITICAL","Remote code execution PLCnext","N/A",1962),
    # Tridium
    ("CVE-2023-30838","Tridium","Niagara 4 Framework","9.8","CRITICAL","Remote code execution auth bypass","N/A",4911),
    # Emerson additional
    ("CVE-2022-29963","Emerson","DeltaV EWS firmware update","7.4","HIGH","Insecure firmware update OT:ICEFALL","ICSA-22-167-06",502),
    # Log4Shell ICS
    ("CVE-2022-22965","VMware Spring","Spring4Shell in Spring-based MES","9.8","CRITICAL","ClassLoader RCE in Spring-based MES","N/A",8080),
    # Digi
    ("CVE-2022-40765","Digi","ConnectPort X2 gateway","9.8","CRITICAL","Command injection unauthenticated","N/A",4800),
    # Inductive Automation additional
    ("CVE-2023-39473","Inductive Automation","Ignition 8.1 AbstractGatewayFunction","8.8","HIGH","Java deserialization authenticated RCE","N/A",8088),
    ("CVE-2025-13913","Inductive Automation","Ignition 8.x project import","7.2","HIGH","Malicious project import code execution","N/A",8088),
    # Yokogawa
    ("CVE-2023-35985","Yokogawa","CENTUM VP engineering tool","7.5","HIGH","Path traversal arbitrary file access","N/A",80),
    ("CVE-2024-1182","Yokogawa","Vnet/IP engineering tool broadcast","7.5","HIGH","Denial of service broadcast","N/A",80),
    # GE Vernova
    ("CVE-2024-4609","GE Vernova","Grid Solutions Modbus","7.5","HIGH","Denial of service Modbus protocol","N/A",502),
    # ABB additional
    ("CVE-2024-48843","ABB","ACS880 drives firmware","7.5","HIGH","Denial of service remote","N/A",502),
    # Honeywell additional
    ("CVE-2024-33045","Honeywell","Niagara IQ Pro door controller","9.1","CRITICAL","Authentication bypass door access control","N/A",4911),
    # DELMIA additional
    ("CVE-2025-6204","Dassault Systemes","DELMIA Apriso portal upload","8.8","HIGH","File upload path traversal webshell","N/A",80),
    ("CVE-2025-6205","Dassault Systemes","DELMIA Apriso SOAP","9.8","CRITICAL","SOAP unauthenticated account creation","N/A",80),
    # Rockwell ThinManager additional
    ("CVE-2023-46290","Rockwell Automation","FactoryTalk Services Platform","8.8","HIGH","Path traversal information disclosure","N/A",44818),
    ("CVE-2023-46289","Rockwell Automation","FactoryTalk Remote Access","9.8","CRITICAL","Improper authentication bypass","N/A",443),
    ("CVE-2024-21912","Rockwell Automation","Allen-Bradley Power Monitor 1000E","9.8","CRITICAL","Authentication bypass remote","N/A",80),
    # AVEVA additional
    ("CVE-2022-23854","AVEVA","AVEVA InTouch Access Anywhere","9.8","CRITICAL","Remote code execution path traversal","N/A",443),
    ("CVE-2024-7049","AVEVA","AVEVA Edge HMI","9.8","CRITICAL","Remote code execution auth bypass","N/A",80),
    # Siemens more 2024-2025
    ("CVE-2024-43641","Siemens","SIMATIC S7-1500 CPU DoS","7.5","HIGH","Denial of service unhandled exception","N/A",102),
    ("CVE-2024-43647","Siemens","SIMATIC CP 1543SP-1 auth","9.8","CRITICAL","Authentication bypass remote","N/A",443),
    ("CVE-2024-56181","Siemens","SINEMA Server V14 SQLi","9.8","CRITICAL","SQL injection RCE","N/A",80),
    ("CVE-2025-27393","Siemens","SIMATIC S7-1500 CPU PROFINET","7.5","HIGH","Denial of service via PROFINET","N/A",34962),
    # Schneider more
    ("CVE-2023-27975","Schneider Electric","EcoStruxure Power Automation","9.8","CRITICAL","Improper authentication RCE","N/A",80),
    ("CVE-2023-29412","Schneider Electric","APC Easy UPS Online","9.8","CRITICAL","Filename bypass RCE","N/A",80),
    ("CVE-2024-0571","Schneider Electric","Easergy Studio software","7.8","HIGH","Arbitrary code execution","N/A",502),
    ("CVE-2025-0327","Schneider Electric","Modicon M340 M580","9.8","CRITICAL","Authentication bypass","N/A",502),
    # Rockwell more
    ("CVE-2021-27476","Rockwell Automation","Studio 5000 View Designer","7.8","HIGH","Code execution malicious VSD file","N/A",44818),
    ("CVE-2024-40619","Rockwell Automation","ControlLogix 5580 5480","8.8","HIGH","Improper input validation","N/A",44818),
    ("CVE-2024-7947","Rockwell Automation","FactoryTalk View Site Edition","7.7","HIGH","Path traversal file disclosure","N/A",80),
    ("CVE-2025-0477","Rockwell Automation","Arena Simulation Software","7.8","HIGH","Arbitrary code execution crafted file","N/A",80),
    ("CVE-2024-5643","Rockwell Automation","DataMosaix Private Cloud","9.8","CRITICAL","SQL injection RCE","N/A",443),
    # ABB more
    ("CVE-2020-24676","ABB","Panel Builder 800","8.8","HIGH","Remote code execution","N/A",80),
    ("CVE-2022-0228","ABB","Cyber Security Configurator","7.8","HIGH","Privilege escalation","N/A",443),
    ("CVE-2022-26412","ABB","Symphony Plus Operations","8.8","HIGH","SQL injection vulnerability","N/A",1433),
    ("CVE-2024-51550","ABB","Data manager industrial IoT","9.8","CRITICAL","Remote code execution","N/A",80),
    # GE more
    ("CVE-2020-6994","GE","SRTP protocol implementation","9.8","CRITICAL","Remote code execution unauthenticated SRTP","N/A",18245),
    ("CVE-2021-27452","GE","MU320E RTU controller","9.8","CRITICAL","Hard-coded credentials bypass","N/A",80),
    ("CVE-2022-29957","GE","Proficy Historian server","9.8","CRITICAL","Improper authentication bypass","N/A",5450),
    # Emerson
    ("CVE-2020-10640","Emerson","OpenEnterprise SCADA","9.8","CRITICAL","Remote code execution unauthenticated","N/A",502),
    ("CVE-2022-30267","Emerson","Ovation OCR400 controller","9.8","CRITICAL","Authentication bypass OT:ICEFALL","ICSA-22-167-04",502),
]

def main():
    created = 0
    for row in BATCH:
        cve_id, vendor, product, cvss, sev, et, cisa, port = row
        vs = sl(vendor)[:20]
        out_dir = MODULES_CVE / vs
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "__init__.py").touch()
        fname = out_dir / (cve_id.lower().replace("-","_") + ".py")
        if fname.exists():
            continue
        impact = {"CRITICAL":"CRITICAL","HIGH":"HIGH","MEDIUM":"MEDIUM"}.get(sev,"MEDIUM")
        content = make_stub(cve_id, vendor, product, cvss, sev, et, cisa, port, impact)
        fname.write_text(content, encoding="utf-8")
        created += 1

    print(f"[extra_cve_batch] Created {created} extra CVE stubs")
    sys.path.insert(0, str(PROJECT_ROOT))
    from industrialxpl.core.exploit.utils import index_modules
    mods = index_modules()
    print(f"[extra_cve_batch] IXF total modules: {len(mods)}")


if __name__ == "__main__":
    main()
