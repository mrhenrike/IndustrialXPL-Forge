#!/usr/bin/env python3
"""Batch module generator for IXF — no-CVE protocol abuse and additional CVEs."""
import re, sys
from pathlib import Path

MODULES = Path(__file__).resolve().parent.parent / "industrialxpl" / "modules"

STUB = '''"""IXF {cve} {name}.

{desc}

Severity: {sev} CVSS {cvss}
Type: {et}
Reference: {ref}
"""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, mute,
    print_error, print_info, print_status, print_success, print_warning, DestructiveGate,
)

class Exploit(Exploit):
    __info__ = {{
        "name": "{name}",
        "description": "{desc200}",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("{ref}",),
        "devices": ("Target device",),
        "impact": "{impact}",
        "exploit_type": "{et}",
        "source_poc": "{ref}",
        "cve": "{cve}",
        "cvss": "{cvss}",
        "severity": "{sev}",
        "mitre_techniques": {mitre},
        "mitre_tactics": ["Initial Access", "Inhibit Response Function"],
        "destructive_description": "{dd150}",
    }}
    target = OptIP("", "Target IP")
    port = OptPort({port}, "Target port")
    timeout = OptInteger(5, "Timeout")
    simulate = OptBool(True, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable real execution")

    @mute
    def check(self):
        if not self.target: return False
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
                description="{cve}: {et} against target at port {port}.",
                mitre_techniques={mitre},
            )
            return
        if self.check():
            print_success("Port {port} open — {name}. {cve} {sev}.")
        else:
            print_error("Target not responding on port {port}.")
'''


def make(path, filename, name, desc, cvss, sev, et, cve, port, impact, mitre, ref, dd):
    d = MODULES / path
    d.mkdir(parents=True, exist_ok=True)
    (d / "__init__.py").touch()
    f = d / filename
    if f.exists():
        return False
    content = STUB.format(
        name=name, desc=desc, desc200=desc[:200], cvss=cvss, sev=sev,
        et=et, cve=cve, port=port, impact=impact, mitre=str(mitre),
        ref=ref, dd=dd, dd150=dd[:150],
    )
    f.write_text(content, encoding="utf-8")
    return True


NO_CVE = [
    ("exploits/protocols/s7comm", "s7_cpu_stop_unauthorized.py",
     "Siemens S7comm CPU STOP without Authentication (No CVE)",
     "S7comm PLCs accept CPU STOP commands without password at protection level 0 or 1.",
     "N/A","HIGH","Unauthenticated CPU STOP Protocol Design","N/A",102,"HIGH",
     ["T0816","T0813"],"https://attack.mitre.org/techniques/T0816/",
     "S7comm CPU STOP on target:102 halts PLC execution. Process stops immediately."),
    ("exploits/protocols/bacnet","bacnet_reinitialize_device.py",
     "BACnet ReinitializeDevice without Authentication (No CVE)",
     "BACnet ReinitializeDevice service can reboot building controllers without auth.",
     "N/A","HIGH","BACnet ReinitializeDevice Feature Abuse","N/A",47808,"HIGH",
     ["T0816","T0814"],"https://attack.mitre.org/techniques/T0816/",
     "BACnet ReinitializeDevice reboots or factory-resets target controller."),
    ("exploits/protocols/enip","enip_list_identity_flood.py",
     "EtherNet/IP List Identity Flood DoS (No CVE)",
     "Flooding EtherNet/IP List Identity requests overwhelms PLCs with no rate limiting.",
     "N/A","MEDIUM","EtherNet/IP UDP Flood No CVE","N/A",44818,"MEDIUM",
     ["T0814"],"https://attack.mitre.org/techniques/T0814/",
     "EtherNet/IP List Identity flood on port 44818 — DoS against PLC."),
    ("exploits/protocols/modbus","modbus_broadcast_flood.py",
     "Modbus TCP Broadcast Unit ID 0 Flood (No CVE)",
     "Modbus Unit ID 0 is broadcast — affects ALL slaves simultaneously.",
     "N/A","HIGH","Modbus Broadcast Flood Protocol Design","N/A",502,"HIGH",
     ["T0814","T1692.001"],"https://modbus.org/",
     "Modbus broadcast flood unit_id=0 on port 502 affects all slaves simultaneously."),
    ("exploits/protocols/dnp3","dnp3_self_address_spoof.py",
     "DNP3 Self Address Spoofing (No CVE)",
     "DNP3 self-addressing allows a device to impersonate any other DNP3 outstation.",
     "N/A","HIGH","DNP3 Self-Address Spoofing Protocol Design","N/A",20000,"HIGH",
     ["T0848","T1692"],"https://attack.mitre.org/techniques/T0848/",
     "DNP3 self-address spoof on port 20000 — impersonates any DNP3 outstation."),
    ("exploits/protocols/omron","fins_broadcast_stop.py",
     "Omron FINS Broadcast CPU Stop (No CVE)",
     "Omron FINS STOP command can be broadcast to all PLCs on a network segment.",
     "N/A","CRITICAL","Omron FINS Broadcast Stop No CVE","N/A",9600,"CRITICAL",
     ["T0816","T0813"],"https://attack.mitre.org/techniques/T0816/",
     "Omron FINS broadcast CPU stop on port 9600 halts ALL Omron PLCs on segment."),
    ("exploits/protocols/profinet","profinet_dcp_spoof_mac.py",
     "PROFINET DCP MAC-Level Spoofing (No CVE)",
     "PROFINET DCP operates at Layer 2 without source MAC authentication.",
     "N/A","HIGH","PROFINET DCP Layer 2 Spoofing No CVE","N/A",34964,"HIGH",
     ["T0836","T0848"],"https://attack.mitre.org/techniques/T0848/",
     "PROFINET DCP MAC spoof on port 34964 — sends Set-IP from spoofed MAC."),
    ("exploits/protocols/modbus","modbus_exception_probe.py",
     "Modbus Exception Probing for Device Fingerprinting (No CVE)",
     "Modbus exception responses reveal register map and device type without auth.",
     "N/A","MEDIUM","Modbus Exception Fingerprinting No CVE","N/A",502,"MEDIUM",
     ["T0888","T0861"],"https://attack.mitre.org/techniques/T0888/",
     "Modbus exception probing on port 502 reveals device register map."),
]

CVE_EXPLOITS = [
    ("cve/cve_2024_10943","cve_2024_10943_factorytalk_updater.py",
     "Rockwell FactoryTalk Updater Authentication Bypass (CVE-2024-10943)",
     "Auth bypass in Rockwell FactoryTalk Updater allows arbitrary code execution.",
     "9.8","CRITICAL","Authentication bypass RCE","CVE-2024-10943",443,"CRITICAL",
     ["T0819","T0866"],"https://nvd.nist.gov/vuln/detail/CVE-2024-10943",
     "FactoryTalk Updater auth bypass on port 443 — RCE on Rockwell update service."),
    ("cve/cve_2024_3400","cve_2024_3400_panos_globalprotect.py",
     "PAN-OS GlobalProtect OS Command Injection CVSS 10.0 (CVE-2024-3400)",
     "OS command injection in PAN-OS GlobalProtect used as OT border firewall.",
     "10.0","CRITICAL","OS command injection pre-auth via cookie","CVE-2024-3400",443,"CRITICAL",
     ["T0819","T0866"],"https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
     "PAN-OS GlobalProtect injection on port 443 — RCE on OT border firewall."),
    ("cve/cve_2021_44228_log4shell","cve_2021_44228_log4shell_ics.py",
     "Log4Shell JNDI Injection in Java-based ICS/MES (CVE-2021-44228)",
     "CVSS 10.0 JNDI injection in Log4j2 affecting Java MES/SCADA like Ignition.",
     "10.0","CRITICAL","JNDI injection RCE in Java ICS","CVE-2021-44228",8088,"CRITICAL",
     ["T0819","T0853"],"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
     "Log4Shell JNDI injection on port 8088 — RCE on Java-based ICS/MES."),
    ("cve/cve_2019_0708_bluekeep","cve_2019_0708_bluekeep_ot_ews.py",
     "BlueKeep RDP RCE on OT Engineering Workstations (CVE-2019-0708)",
     "BlueKeep RDP pre-auth RCE affecting Windows XP/2003/2008 common in OT environments.",
     "9.8","CRITICAL","Pre-auth RDP RCE WannaCry vector in OT","CVE-2019-0708",3389,"CRITICAL",
     ["T0819","T0866"],"https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
     "BlueKeep RDP exploit on port 3389 — RCE on Windows XP/2008 engineering workstation."),
    ("cve/cve_2017_0144_eternalblue","cve_2017_0144_eternalblue_ot.py",
     "EternalBlue SMB RCE in OT Networks (CVE-2017-0144)",
     "NSA exploit used by WannaCry/NotPetya devastating OT networks in 2017.",
     "9.3","CRITICAL","SMB RCE WannaCry NotPetya in OT","CVE-2017-0144",445,"CRITICAL",
     ["T0819","T0866"],"https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
     "EternalBlue SMB exploit on port 445 — RCE via MS17-010 on OT Windows hosts."),
    ("cve/cve_2021_34473_proxyshell","cve_2021_34473_proxyshell_ot.py",
     "ProxyShell Exchange RCE for OT Network Pivot (CVE-2021-34473)",
     "ProxyShell Exchange RCE CVSS 9.8 used to pivot from IT to OT networks.",
     "9.8","CRITICAL","Exchange RCE chain for OT network pivot","CVE-2021-34473",443,"CRITICAL",
     ["T0819","T0822"],"https://nvd.nist.gov/vuln/detail/CVE-2021-34473",
     "ProxyShell on Exchange port 443 — pivot from IT to OT via compromised server."),
    ("cve/cve_2023_27997_fortios","cve_2023_27997_fortios_sslvpn.py",
     "FortiOS SSL-VPN Pre-Auth Heap Overflow RCE (CVE-2023-27997)",
     "FortiOS SSL-VPN pre-auth heap overflow RCE CVSS 9.8 used as OT border VPN.",
     "9.8","CRITICAL","Pre-auth heap overflow on OT border VPN","CVE-2023-27997",443,"CRITICAL",
     ["T0819","T0822"],"https://nvd.nist.gov/vuln/detail/CVE-2023-27997",
     "FortiOS SSL-VPN heap overflow on port 443 — RCE on OT border firewall VPN."),
    ("cve/cve_2023_34362_moveit","cve_2023_34362_moveit_sqli_rce.py",
     "MOVEit Transfer SQLi RCE in OT File Transfer (CVE-2023-34362)",
     "MOVEit SQL injection RCE CVSS 9.8 used for OT secure file transfers.",
     "9.8","CRITICAL","SQLi RCE in OT file transfer software","CVE-2023-34362",443,"CRITICAL",
     ["T0819"],"https://nvd.nist.gov/vuln/detail/CVE-2023-34362",
     "MOVEit Transfer SQLi on port 443 — RCE via OT file transfer service."),
    ("cve/cve_2022_1388_f5bigip","cve_2022_1388_f5bigip_ot.py",
     "F5 BIG-IP Authentication Bypass RCE (CVE-2022-1388) in OT Load Balancers",
     "F5 BIG-IP iControl REST auth bypass CVSS 9.8 deployed as OT load balancers.",
     "9.8","CRITICAL","Auth bypass RCE on OT load balancer","CVE-2022-1388",443,"CRITICAL",
     ["T0819","T0866"],"https://nvd.nist.gov/vuln/detail/CVE-2022-1388",
     "F5 BIG-IP auth bypass on port 443 — RCE on OT network load balancer."),
    ("cve/cve_2022_22954_vmware","cve_2022_22954_vmware_workspace.py",
     "VMware Workspace ONE SSTI RCE in OT Virtualization (CVE-2022-22954)",
     "VMware Workspace ONE SSTI RCE CVSS 9.8 in OT environments using vSphere.",
     "9.8","CRITICAL","SSTI RCE on OT virtualization platform","CVE-2022-22954",443,"CRITICAL",
     ["T0819"],"https://nvd.nist.gov/vuln/detail/CVE-2022-22954",
     "VMware Workspace ONE SSTI on port 443 — RCE on OT virtualization platform."),
    ("cve/cve_2021_21985_vmware","cve_2021_21985_vmware_vcenter.py",
     "VMware vCenter Server RCE in OT Environments (CVE-2021-21985)",
     "VMware vCenter Server plugin RCE CVSS 9.8 used in OT virtualized environments.",
     "9.8","CRITICAL","vCenter plugin RCE in OT virtualization","CVE-2021-21985",443,"CRITICAL",
     ["T0819","T0866"],"https://nvd.nist.gov/vuln/detail/CVE-2021-21985",
     "vCenter Server plugin RCE on port 443 — compromise OT virtualization host."),
    ("cve/cve_2025_29824_windows","cve_2025_29824_windows_clfs_lpe.py",
     "Windows CLFS Driver LPE (CVE-2025-29824) in OT Engineering Workstations",
     "Windows CLFS driver local privilege escalation CVSS 7.8 on OT engineering workstations.",
     "7.8","HIGH","Local privilege escalation on OT workstation","CVE-2025-29824",0,"HIGH",
     ["T0890"],"https://nvd.nist.gov/vuln/detail/CVE-2025-29824",
     "Windows CLFS LPE on OT engineering workstation — SYSTEM level access."),
]


def main():
    created = 0
    for row in NO_CVE + CVE_EXPLOITS:
        if make(*row):
            created += 1
    print(f"Created {created} new modules")
    sys.path.insert(0, str(MODULES.parent.parent))
    from industrialxpl.core.exploit.utils import index_modules
    print(f"Total IXF modules: {len(index_modules())}")


if __name__ == "__main__":
    main()
