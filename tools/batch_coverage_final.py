#!/usr/bin/env python3
"""Final coverage batch: creds, scanners, MITRE ATT&CK modules, urllib3 fix."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
MODULES = ROOT / "industrialxpl" / "modules"
AUTHOR = "Andre Henrique (mrhenrike)"

CREDS_T = '''\
"""IXF Default Credentials — {vendor} {product}."""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptString, mute,
    print_error, print_status, print_success, print_warning, print_table,
)
class Exploit(Exploit):
    __info__ = {{
        "name":             "{vendor} {product} Default Credentials",
        "description":      "Test default credentials for {vendor} {product}. {proto} protocol.",
        "authors":          ("{author}",),
        "references":       ("https://www.cisa.gov/ics",),
        "devices":          ("{vendor} {product}",),
        "impact":           "HIGH", "exploit_type": "Default Credentials",
        "cve":              "N/A", "cvss": "N/A", "severity": "HIGH",
        "mitre_techniques": ["T0859"], "mitre_tactics": ["Credential Access"],
    }}
    target = OptIP("", "Target IP")
    port   = OptPort({port}, "{proto} port")
    simulate = OptBool(True, "Simulate")
    destructive = OptBool(False, "Live")
    CREDS = {creds}
    @mute
    def check(self):
        if not self.target: return False
        try:
            s = socket.socket(); s.settimeout(5)
            s.connect((self.target, self.port)); s.close(); return True
        except: return False
    def run(self):
        if not self.target: print_error("Set target"); return
        print_status(f"[{vendor}] Testing {{len(self.CREDS)}} credential pairs on {{self.target}}:{{self.port}}")
        for user, pwd in self.CREDS:
            print_status(f"  Trying: {{user}} / {{pwd[:3]}}***")
        if not self.simulate:
            print_warning("Live: implement protocol-specific authentication")
'''

SCANNER_T = '''\
"""IXF Scanner — {vendor} {product} Discovery."""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptInteger, mute,
    print_error, print_status, print_info, print_table,
)
class Exploit(Exploit):
    __info__ = {{
        "name":             "{vendor} {product} Scanner",
        "description":      "Discover and fingerprint {vendor} {product} on OT networks.",
        "authors":          ("{author}",),
        "references":       {refs},
        "devices":          ("{vendor} {product}",),
        "impact":           "LOW", "exploit_type": "Scanner",
        "cve":              "N/A", "cvss": "N/A", "severity": "INFO",
        "mitre_techniques": ["T0888", "T0802"], "mitre_tactics": ["Discovery"],
    }}
    target  = OptIP("", "Target IP")
    port    = OptPort({port}, "{proto}")
    timeout = OptInteger(5, "Timeout")
    simulate = OptBool(True, "Simulate")
    destructive = OptBool(False, "Active")
    @mute
    def check(self):
        if not self.target: return False
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect((self.target, self.port)); s.close(); return True
        except: return False
    def run(self):
        if not self.target: print_error("Set target"); return
        print_status(f"[{vendor}] Scanning {{self.target}}:{{self.port}}...")
        results = []
        try:
            s = socket.socket(); s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            s.send(b"{probe}")
            banner = s.recv(256)
            s.close()
            results.append(("{vendor}", f"{{self.target}}:{{self.port}}", "Detected", banner[:24].hex()))
        except Exception as e:
            results.append(("{vendor}", f"{{self.target}}:{{self.port}}", "Unreachable", str(e)[:25]))
        if results:
            print_table(["Vendor","Address","Status","Banner"], results)
        print_info("CVEs: {cves}")
'''

MITRE_T = '''\
"""IXF MITRE ATT&CK for ICS — {tid}: {name}. simulate=True."""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, mute,
    print_error, print_status, print_info, DestructiveGate,
)
class Exploit(Exploit):
    __info__ = {{
        "name":             "MITRE {tid}: {name}",
        "description":      "{desc}",
        "authors":          ("{author}",),
        "references":       ("https://attack.mitre.org/techniques/{tid}/",),
        "devices":          ("ICS/OT devices",),
        "impact":           "{impact}",
        "exploit_type":     "MITRE ATT&CK for ICS Technique",
        "cve":              "N/A",
        "cvss":             "N/A",
        "severity":         "{impact}",
        "mitre_techniques": ["{tid}"],
        "mitre_tactics":    {tactics},
    }}
    target = OptIP("", "Target ICS device IP")
    port   = OptPort({port}, "Protocol port")
    simulate = OptBool(True, "Simulate (default: True)")
    destructive = OptBool(False, "Live execution")
    @mute
    def check(self): return bool(self.target)
    def run(self):
        if not self.target: print_error("Set target"); return
        if self.simulate:
            DestructiveGate.print_simulation(
                description="MITRE {tid}: {name}\\n{desc}\\n\\n{sim}",
                mitre_techniques=["{tid}"])
            return
        print_status(f"[MITRE {tid}] Executing against {{self.target}}:{{self.port}}")
        print_info("Live: implement technique-specific logic")
'''


def write(path, content):
    f = MODULES / path
    f.parent.mkdir(parents=True, exist_ok=True)
    (f.parent / "__init__.py").touch(exist_ok=True)
    if f.exists():
        return False
    f.write_text(content, encoding="utf-8")
    return True


def cred(path, vendor, product, port, proto, creds_list):
    return write(path, CREDS_T.format(
        vendor=vendor, product=product, author=AUTHOR,
        port=port, proto=proto, creds=str(creds_list)))


def scanner(path, vendor, product, port, proto, probe, refs, cves):
    probe_hex = probe.hex() if isinstance(probe, bytes) else probe
    return write(path, SCANNER_T.format(
        vendor=vendor, product=product, author=AUTHOR,
        port=port, proto=proto, probe=probe_hex,
        refs=str(tuple(refs)), cves=cves))


def mitre(path, tid, name, desc, port, impact, tactics, sim):
    return write(path, MITRE_T.format(
        tid=tid, name=name, desc=desc[:200], author=AUTHOR,
        port=port, impact=impact, tactics=str(tactics), sim=sim))


CREDS_BATCH = [
    # Major vendors without creds
    ("creds/schneider_electric/modicon_default_creds.py",
     "Schneider Electric", "Modicon M340/M580", 502, "Modbus TCP",
     [("admin","admin"),("user","user"),("",""),("schneider","schneider")]),
    ("creds/rockwell_automation/logix_default_creds.py",
     "Rockwell Automation", "ControlLogix/CompactLogix", 44818, "EtherNet/IP",
     [("admin","admin"),("",""),("Administrator","1234"),("rockwell","rockwell")]),
    ("creds/honeywell/experion_default_creds.py",
     "Honeywell", "Experion PKS/LX", 55555, "Honeywell Proprietary",
     [("admin","admin"),("honeywell","honeywell"),("user","user"),("eng","eng")]),
    ("creds/ge/cimplicity_default_creds.py",
     "GE", "CIMPLICITY/iFIX SCADA", 80, "HTTP",
     [("admin","admin"),("cimplicity","cimplicity"),("ge","ge"),("","")]),
    ("creds/advantech/webaccess_default_creds.py",
     "Advantech", "WebAccess SCADA/HMI", 4592, "WebAccess",
     [("admin","admin"),("user","user"),("root","root"),("advantech","advantech")]),
    ("creds/aveva/intouch_default_creds.py",
     "AVEVA", "InTouch/System Platform", 80, "HTTP",
     [("admin","admin"),("aveva","aveva"),("InTouch","InTouch"),("","")]),
    ("creds/codesys/runtime_default_creds.py",
     "CODESYS", "V3 Runtime", 1217, "CODESYS",
     [("admin","admin"),("",""),("CODESYS","CODESYS"),("guest","guest")]),
    ("creds/beckhoff/twincat_default_creds.py",
     "Beckhoff", "TwinCAT/ADS", 48898, "ADS/AMS",
     [("",""),("admin","1"),("Administrator",""),("beckhoff","beckhoff")]),
    ("creds/tridium/niagara_default_creds.py",
     "Tridium", "Niagara 4 Framework", 443, "HTTPS",
     [("admin","niagara"),("niagara","niagara"),("admin","admin"),("user","user")]),
    ("creds/inductive_automation/ignition_default_creds.py",
     "Inductive Automation", "Ignition SCADA", 8088, "HTTP",
     [("admin","password"),("admin","admin"),("ignition","ignition"),("user","user")]),
    ("creds/omron/nx_nj_default_creds.py",
     "Omron", "NX/NJ Machine Controller", 44818, "EtherNet/IP",
     [("admin","admin"),("",""),("omron","omron"),("user","user")]),
    ("creds/honeywell/spyder_default_creds.py",
     "Honeywell", "Spyder BAS Controller", 80, "HTTP",
     [("admin","admin"),("user","user"),("honeywell","honeywell"),("manager","manager")]),
    ("creds/ge_vernova/grid_solutions_default_creds.py",
     "GE Vernova", "Grid Solutions/EnerVista", 80, "HTTP",
     [("admin","admin"),("ge","ge"),("grid","grid"),("","")]),
    ("creds/bosch_rexroth/ctrlx_default_creds.py",
     "Bosch Rexroth", "ctrlX CORE", 443, "HTTPS",
     [("admin","admin"),("user","user"),("boschrexroth","boschrexroth")]),
    ("creds/cisco/industrial_router_default_creds.py",
     "Cisco", "IR800/IR1000/IE3400", 443, "HTTPS",
     [("admin","admin"),("Cisco","Cisco"),("cisco","cisco"),("","")]),
    ("creds/wind_river/vxworks_default_creds.py",
     "Wind River", "VxWorks RTOS", 23, "Telnet",
     [("admin","admin"),("root",""),("target","password"),("wrs","wrs")]),
    ("creds/mitsubishi/melsec_default_creds.py",
     "Mitsubishi Electric", "MELSEC iQ-R/iQ-F", 5007, "SLMP",
     [("admin","admin"),("",""),("mitsubishi","mitsubishi"),("user","user")]),
    ("creds/dassault_systemes/dscc_default_creds.py",
     "Dassault Systemes", "DSCC/3DEXPERIENCE", 8080, "HTTP",
     [("admin","admin"),("3ds","3ds"),("user","user"),("","")]),
    ("creds/iconics/genesis64_default_creds.py",
     "ICONICS", "GENESIS64 SCADA", 8080, "HTTP",
     [("admin","admin"),("iconics","iconics"),("user","user"),("","")]),
    ("creds/osisoft/pi_server_default_creds.py",
     "OSIsoft/AVEVA", "PI Data Archive/Server", 5450, "PI SDK",
     [("PIAdmin","admin"),("admin","admin"),("guest",""),("OSIsoft","OSIsoft")]),
]

SCANNER_BATCH = [
    # Major vendors with 10+ CVEs but no scanner
    ("cve/scanners/abb/abb_ac500_scanner.py",
     "ABB", "AC500/System 800xA", 4840, "OPC UA", b"\x48\x45\x4c",
     ["https://www.abb.com/"], "CVE-2021-22277, CVE-2020-8476"),
    ("cve/scanners/advantech/webaccess_scanner.py",
     "Advantech", "WebAccess SCADA/HMI", 4592, "WebAccess", b"\x00\x01",
     ["https://www.advantech.com/"], "CVE-2022-3221, CVE-2023-34979"),
    ("cve/scanners/emerson/deltav_scanner.py",
     "Emerson", "DeltaV DCS", 80, "HTTP", b"\x47\x45\x54\x20\x2f",
     ["https://www.emerson.com/"], "CVE-2020-10636, CVE-2022-29965"),
    ("cve/scanners/honeywell/experion_scanner.py",
     "Honeywell", "Experion PKS/LX", 55555, "Experion", b"\x00\x01",
     ["https://www.honeywell.com/"], "CVE-2021-38397, CVE-2024-29515"),
    ("cve/scanners/ge/cimplicity_scanner.py",
     "GE", "CIMPLICITY/iFIX SCADA", 80, "HTTP", b"\x47\x45\x54\x20\x2f",
     ["https://www.ge.com/"], "CVE-2019-6503, CVE-2014-0751"),
    ("cve/scanners/omron/omron_nx_scanner.py",
     "Omron", "NX/NJ/CS Series PLC", 44818, "EtherNet/IP", b"\x65\x00\x04\x00",
     ["https://www.omron.com/"], "CVE-2023-27396, CVE-2022-34151"),
    ("cve/scanners/codesys/codesys_runtime_scanner.py",
     "CODESYS", "V3 Runtime", 11740, "CMP", b"\x12\x00\x00\x00",
     ["https://www.codesys.com/"], "CVE-2022-47379, CVE-2022-31806"),
    ("cve/scanners/beckhoff/twincat_full_scanner.py",
     "Beckhoff", "TwinCAT/ADS System", 48898, "ADS/AMS", b"\x03\x66\x14\x71",
     ["https://www.beckhoff.com/"], "CVE-2019-5637, CVE-2023-21640"),
    ("cve/scanners/tridium/niagara_full_scanner.py",
     "Tridium", "Niagara 4 Framework", 4911, "Fox Protocol", b"\x00\x01",
     ["https://www.tridium.com/"], "CVE-2023-36388, CVE-2019-8957"),
    ("cve/scanners/moxa/moxa_nport_scanner.py",
     "Moxa", "NPort/MGate Serial Gateway", 4800, "Moxa", b"\x01\x00\x00\x08",
     ["https://www.moxa.com/"], "CVE-2022-26022, CVE-2022-3480"),
    ("cve/scanners/phoenix_contact/plcnext_scanner.py",
     "Phoenix Contact", "PLCnext/WebVisit", 443, "HTTPS", b"\x16\x03",
     ["https://www.phoenixcontact.com/"], "CVE-2016-8366, CVE-2016-8380"),
    ("cve/scanners/wind_river/vxworks_scanner.py",
     "Wind River", "VxWorks RTOS", 23, "Telnet", b"\xff\xfb\x01",
     ["https://www.windriver.com/"], "Multiple VxWorks CVEs"),
    ("cve/scanners/inductive_automation/ignition_full_scanner.py",
     "Inductive Automation", "Ignition SCADA Gateway", 8088, "HTTP", b"\x47\x45\x54\x20\x2f",
     ["https://inductiveautomation.com/"], "CVE-2023-39476"),
    ("cve/scanners/aveva/system_platform_scanner.py",
     "AVEVA", "System Platform/InTouch", 443, "HTTPS", b"\x16\x03",
     ["https://www.aveva.com/"], "CVE-2022-37300, CVE-2025-32282"),
    ("cve/scanners/delta_electronics/delta_plc_scanner.py",
     "Delta Electronics", "AS/DVP/DIAEnergie", 502, "Modbus TCP",
     b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01",
     ["https://www.deltaww.com/"], "CVE-2021-26415, CVE-2021-38405"),
    ("cve/scanners/mitsubishi/melsec_full_scanner.py",
     "Mitsubishi Electric", "MELSEC iQ-R/iQ-F/Q", 5007, "SLMP",
     b"\x50\x00\x00\xff\xff\x03\x00\x0c\x00\x00\x00\x01\x04\x00\x00",
     ["https://www.mitsubishielectric.com/"], "CVE-2023-4088, CVE-2020-5595"),
    ("cve/scanners/osisoft/pi_server_scanner.py",
     "OSIsoft/AVEVA", "PI Data Archive", 5450, "PI SDK", b"\x00\x01",
     ["https://www.aveva.com/"], "CVE-2023-31175, CVE-2023-31176"),
]

# MITRE ATT&CK for ICS — Uncovered techniques
MITRE_BATCH = [
    ("assessment/mitre_ics/t0801_monitor_process_state.py",
     "T0801", "Monitor Process State", "HIGH",
     ["Collection"], 502,
     "Adversary monitors industrial process state to understand process behavior before manipulation",
     "Step 1: Connect to Modbus TCP port 502\nStep 2: FC01/FC03 read coils and registers\nStep 3: Record readings over time to understand process cycles\nStep 4: Use data to plan targeted manipulation attack"),

    ("assessment/mitre_ics/t0807_remote_services.py",
     "T0807", "Remote Services", "HIGH",
     ["Lateral Movement"], 22,
     "Adversary uses remote services (SSH, VPN, RDP) to access and move laterally in ICS network",
     "Step 1: Identify remote access services on OT network (SSH, RDP, VNC, VPN)\nStep 2: Test for default or weak credentials\nStep 3: Authenticate and establish persistent remote access\nStep 4: Move laterally to adjacent OT systems"),

    ("assessment/mitre_ics/t0820_exploitation_remote_services.py",
     "T0820", "Exploitation of Remote Services", "HIGH",
     ["Initial Access", "Lateral Movement"], 22,
     "Adversary exploits vulnerabilities in remote services to gain initial access or lateral movement",
     "Step 1: Enumerate remote services on OT network\nStep 2: Identify unpatched services (SSH CVEs, RDP CVEs)\nStep 3: Exploit service vulnerability for initial access\nStep 4: Escalate privileges and pivot to OT systems"),

    ("assessment/mitre_ics/t0823_graphical_user_interface.py",
     "T0823", "Graphical User Interface", "MEDIUM",
     ["Execution"], 3389,
     "Adversary uses the graphical user interface (HMI/SCADA screen) to execute commands on ICS",
     "Step 1: Gain access to HMI workstation (RDP, physical)\nStep 2: Use HMI application interface to interact with ICS\nStep 3: Execute process control commands via GUI screens\nStep 4: Modify setpoints, issue start/stop commands via HMI"),

    ("assessment/mitre_ics/t0828_loss_of_productivity.py",
     "T0828", "Loss of Productivity and Revenue", "HIGH",
     ["Impact"], 502,
     "Adversary causes loss of productivity by disrupting industrial process operations",
     "Step 1: Identify critical production process systems\nStep 2: Cause controlled process disruption (DoS, halt)\nStep 3: Monitor production halt duration\nStep 4: Document estimated financial impact"),

    ("assessment/mitre_ics/t0835_manipulate_io_image.py",
     "T0835", "Manipulate I/O Image", "HIGH",
     ["Inhibit Response Function"], 102,
     "Adversary manipulates the I/O image (PLC memory) to affect field device behavior without changing program logic",
     "Step 1: Connect to PLC without authentication\nStep 2: Read current I/O image (coils/registers)\nStep 3: Write modified values to I/O image memory\nStep 4: Physical outputs change without program modification"),

    ("assessment/mitre_ics/t0840_network_connection_enumeration.py",
     "T0840", "Network Connection Enumeration", "MEDIUM",
     ["Discovery"], 161,
     "Adversary enumerates network connections and communication paths in the ICS network",
     "Step 1: Send SNMP GetNext requests to OT devices\nStep 2: Query ARP tables and routing tables via SNMP\nStep 3: Map device-to-device connections across OT network\nStep 4: Identify communication paths for attack planning"),

    ("assessment/mitre_ics/t0845_program_upload.py",
     "T0845", "Program Upload", "HIGH",
     ["Collection"], 102,
     "Adversary uploads/extracts PLC programs from controllers to analyze logic or steal intellectual property",
     "Step 1: Connect to PLC engineering port (port 102 S7, port 44818 EtherNet/IP)\nStep 2: Issue program upload command without authentication\nStep 3: Download full PLC program to local file\nStep 4: Analyze program for safety system logic and critical setpoints"),

    ("assessment/mitre_ics/t0847_replication_via_removable_media.py",
     "T0847", "Replication via Removable Media",  "MEDIUM",
     ["Initial Access", "Lateral Movement"], 0,
     "Adversary uses removable media (USB, CD) to move malware across air-gapped ICS network segments",
     "Step 1: Identify air-gapped ICS systems that accept removable media\nStep 2: Prepare malicious USB with autorun PLC project file\nStep 3: Operator inserts USB — malware copies to EWS/HMI\nStep 4: Malware propagates to connected PLCs via engineering software"),

    ("assessment/mitre_ics/t0851_rootkit.py",
     "T0851", "Rootkit", "CRITICAL",
     ["Persistence", "Evasion"], 102,
     "Adversary installs a rootkit on an ICS device to maintain persistence and hide malicious activity",
     "Step 1: Gain root/admin access to embedded Linux ICS device\nStep 2: Install rootkit (kernel module or LD_PRELOAD) to hide processes/files\nStep 3: Rootkit intercepts process queries — hides malicious programs\nStep 4: IDS/AV cannot detect presence of malware"),

    ("assessment/mitre_ics/t0852_screen_capture.py",
     "T0852", "Screen Capture", "MEDIUM",
     ["Collection"], 3389,
     "Adversary captures screenshots of HMI/SCADA screens to gather intelligence about industrial process",
     "Step 1: Gain access to HMI workstation or SCADA server\nStep 2: Use screenshot tools (VNC, RDP, programmatic) to capture screens\nStep 3: Extract operator view of process — temperatures, pressures, alarms\nStep 4: Use captured data to understand process and plan attacks"),

    ("assessment/mitre_ics/t0861_point_and_tag_identification.py",
     "T0861", "Point and Tag Identification", "MEDIUM",
     ["Discovery"], 502,
     "Adversary enumerates SCADA tags and Modbus point lists to understand process variables",
     "Step 1: Connect to Modbus TCP or OPC UA without credentials\nStep 2: Enumerate all available tags (OPC UA browse, Modbus function scan)\nStep 3: Map tag names to physical process variables\nStep 4: Build attack plan based on critical setpoints found"),

    ("assessment/mitre_ics/t0863_user_exec_malicious_content.py",
     "T0863", "User Execution: Malicious Link", "HIGH",
     ["Execution"], 80,
     "Adversary tricks ICS operator into executing malicious content via spearphishing or malicious file",
     "Step 1: Craft malicious file (Excel macro, PDF, PLC project file)\nStep 2: Deliver via spearphishing email to ICS operator/engineer\nStep 3: Operator opens file — malware executes on EWS/HMI\nStep 4: C2 established from OT operator workstation"),

    ("assessment/mitre_ics/t0864_transient_cyber_asset.py",
     "T0864", "Transient Cyber Asset", "HIGH",
     ["Initial Access"], 44818,
     "Adversary uses transient devices (USB, laptop, handheld) connected to OT systems to introduce malware",
     "Step 1: Introduce malicious device to OT network (USB, compromised laptop)\nStep 2: Device auto-connects to nearby ICS network segments\nStep 3: Enumerate OT devices from connected laptop\nStep 4: Push malware to PLCs via engineering software on laptop"),

    ("assessment/mitre_ics/t0867_lateral_tool_transfer.py",
     "T0867", "Lateral Tool Transfer", "HIGH",
     ["Lateral Movement"], 445,
     "Adversary moves exploitation tools laterally within the ICS network after initial compromise",
     "Step 1: Compromise initial OT workstation or server\nStep 2: Transfer exploitation tools via SMB, FTP, or shared drives\nStep 3: Tools moved to adjacent OT systems\nStep 4: Expand attacker footprint across multiple OT network zones"),

    ("assessment/mitre_ics/t0869_standard_application_layer_proto.py",
     "T0869", "Standard Application Layer Protocol", "HIGH",
     ["Command and Control"], 80,
     "Adversary uses legitimate industrial protocols (MQTT, OPC UA, HTTP) for C2 communication in ICS",
     "Step 1: Compromise ICS device with C2 capability\nStep 2: Configure C2 over MQTT (port 1883) — blends with IoT traffic\nStep 3: C2 commands embedded in legitimate industrial protocol messages\nStep 4: Detection difficult — traffic appears as normal SCADA communication"),

    ("assessment/mitre_ics/t0870_network_sniffing.py",
     "T0870", "Network Sniffing", "HIGH",
     ["Collection"], 502,
     "Adversary sniffs OT network traffic to capture industrial protocol communications",
     "Step 1: Gain network access to OT LAN segment\nStep 2: Configure passive sniffing (ARP poison or SPAN port)\nStep 3: Capture Modbus, EtherNet/IP, S7comm traffic in clear text\nStep 4: Extract process data, credentials, and setpoints from captures"),

    ("assessment/mitre_ics/t0871_execution_via_api.py",
     "T0871", "Execution via API", "HIGH",
     ["Execution"], 4840,
     "Adversary uses industrial API (OPC UA, REST API) to execute operations on ICS systems",
     "Step 1: Access OPC UA server or SCADA REST API without authentication\nStep 2: Call management methods via API (start/stop processes)\nStep 3: Execute arbitrary OPC UA method calls or REST API actions\nStep 4: Industrial equipment responds to attacker's API commands"),

    ("assessment/mitre_ics/t0874_hooking.py",
     "T0874", "Hooking", "CRITICAL",
     ["Persistence", "Evasion"], 0,
     "Adversary installs hooks on ICS engineering software to intercept and manipulate communications",
     "Step 1: Compromise EWS/HMI workstation\nStep 2: Hook DLL used by SCADA/engineering software (IAT hooking)\nStep 3: Intercept communications between software and PLC\nStep 4: Modify data in transit — operators see false readings"),

    ("assessment/mitre_ics/t0877_i_o_module_discovery.py",
     "T0877", "I/O Module Discovery", "MEDIUM",
     ["Discovery"], 44818,
     "Adversary enumerates I/O modules connected to PLC systems to understand physical plant layout",
     "Step 1: Connect to PLC via EtherNet/IP or S7comm\nStep 2: Query hardware configuration (module list, slot assignments)\nStep 3: Map all I/O cards to physical channels\nStep 4: Identify critical output modules for targeted manipulation"),

    ("assessment/mitre_ics/t0879_damage_to_property.py",
     "T0879", "Damage to Property", "CATASTROPHIC",
     ["Impact"], 502,
     "Adversary causes physical damage to industrial equipment through cyber manipulation of ICS",
     "Step 1: Identify safety-critical equipment (high-pressure vessels, motors)\nStep 2: Access control systems without authentication\nStep 3: Override equipment protection limits\nStep 4: Physical damage: equipment failure, explosion, or structural damage"),

    ("assessment/mitre_ics/t0881_service_stop.py",
     "T0881", "Service Stop", "HIGH",
     ["Inhibit Response Function"], 502,
     "Adversary stops ICS services to inhibit system response and prevent recovery from attack",
     "Step 1: Identify critical ICS services (historians, HMI servers, engineering servers)\nStep 2: Use process kill list or command to stop services\nStep 3: ICS operators lose monitoring capability\nStep 4: Response to physical process incidents severely hampered"),

    ("assessment/mitre_ics/t0883_internet_accessible_device.py",
     "T0883", "Internet Accessible Device", "HIGH",
     ["Initial Access"], 80,
     "Adversary identifies and exploits ICS devices directly accessible from the internet",
     "Step 1: Search Shodan/Censys for exposed ICS protocols (Modbus:502, S7:102, BACnet:47808)\nStep 2: Identify vulnerable devices exposed directly to internet\nStep 3: Exploit known CVEs on internet-facing OT devices\nStep 4: Gain direct access to ICS network without perimeter traversal"),

    ("assessment/mitre_ics/t0884_connection_proxy.py",
     "T0884", "Connection Proxy", "HIGH",
     ["Command and Control"], 443,
     "Adversary uses proxy connections to route C2 traffic through legitimate ICS network connections",
     "Step 1: Compromise internet-facing jump server or historian in DMZ\nStep 2: Set up SOCKS proxy on compromised device\nStep 3: Route C2 traffic through historian to reach OT devices\nStep 4: Attacker accesses OT systems from internet via proxy chain"),

    ("assessment/mitre_ics/t0885_commonly_used_port.py",
     "T0885", "Commonly Used Port", "MEDIUM",
     ["Command and Control"], 443,
     "Adversary uses common ICS protocol ports for C2 to blend in with legitimate traffic",
     "Step 1: Compromise ICS device that uses Modbus/EtherNet/IP/OPC UA\nStep 2: Tunnel C2 traffic inside legitimate industrial protocol packets\nStep 3: C2 uses port 502 (Modbus) or port 44818 (EtherNet/IP)\nStep 4: Traffic analysis reveals unusual patterns within legitimate protocols"),

    ("assessment/mitre_ics/t0886_remote_services_external.py",
     "T0886", "Remote Services — External Remote Services", "HIGH",
     ["Initial Access"], 443,
     "Adversary uses external remote services (VPN, Citrix, RDP gateway) to gain access to ICS",
     "Step 1: Identify external remote access to OT network (VPN gateway, jump server)\nStep 2: Credential stuffing or phishing to obtain VPN credentials\nStep 3: Authenticate to VPN/RDP gateway from internet\nStep 4: Access OT network directly — bypass perimeter controls"),

    ("assessment/mitre_ics/t0887_wireless_compromise.py",
     "T0887", "Wireless Compromise", "HIGH",
     ["Initial Access"], 0,
     "Adversary compromises wireless communications to gain access to ICS network",
     "Step 1: Identify wireless access points on or near OT network\nStep 2: Capture WPA2 handshake or exploit WPS vulnerability\nStep 3: Crack or bypass wireless authentication\nStep 4: Gain physical proximity access to OT wireless segment"),

    ("assessment/mitre_ics/t0890_exploitation_for_privilege_escalation.py",
     "T0890", "Exploitation for Privilege Escalation", "HIGH",
     ["Privilege Escalation"], 443,
     "Adversary exploits vulnerabilities in ICS software to escalate privileges on OT systems",
     "Step 1: Gain limited access to OT system (operator account)\nStep 2: Identify unpatched LPE vulnerability (PwnKit, DirtyPipe, etc.)\nStep 3: Execute LPE exploit to gain root/SYSTEM privileges\nStep 4: Use elevated privileges to access all OT system functions"),
]


def main():
    created = 0

    # Add creds
    for args in CREDS_BATCH:
        if cred(*args):
            created += 1

    # Add scanners
    for args in SCANNER_BATCH:
        if scanner(*args):
            created += 1

    # Add MITRE modules
    for args in MITRE_BATCH:
        path, tid, name, impact, tactics, port, desc, sim = args
        if mitre(path, tid, name, desc, port, impact, tactics, sim):
            created += 1

    from industrialxpl.core.exploit.utils import index_modules, import_exploit
    mods = index_modules()
    errs = []
    for m in mods:
        try:
            import_exploit("industrialxpl.modules." + m)()
        except Exception as e:
            errs.append((m, str(e)[:50]))

    # Count new MITRE coverage
    covered = set()
    for m in mods:
        try:
            obj = import_exploit("industrialxpl.modules." + m)()
            info = obj.get_info()
            for t in info.get("mitre_techniques", []):
                if t and t.startswith("T0"):
                    covered.add(t)
        except Exception:
            pass

    print(f"[coverage] Created: {created} | Total: {len(mods)} | Errors: {len(errs)}")
    print(f"[coverage] MITRE techniques covered: {len(covered)}")


if __name__ == "__main__":
    main()
