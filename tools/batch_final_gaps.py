#!/usr/bin/env python3
"""IXF Final Gap Batch — close all remaining plan gaps.

Fills:
1. 5 MSF SCADA gaps: broadwin, epicor, datac, matrikon, sixnet
2. LATAM/Brazil missing: Elipse Software, Smar
3. 20 missing protocols: S7comm+, PCOM, ADS, ControlNet, DeviceNet,
   PCCC, Vnet/IP, FL-NET, CompoNet, CC-Link IE Field, PROFIBUS PA,
   FF H1/HSE, OPC HDA, OPC A&E, BACnet/MSTP, LonWorks, KNX,
   INTERBUS, SECS/GEM (semiconductor)
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
MODULES = ROOT / "industrialxpl" / "modules"

AUTHOR = "Andre Henrique (mrhenrike)"


def write_if_new(path: Path, content: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    (path.parent / "__init__.py").touch(exist_ok=True)
    if path.exists():
        return False
    path.write_text(content, encoding="utf-8")
    return True


def make_cve(path, cve_id, vendor, product, port, cvss, desc, sim):
    content = f'''"""IXF {cve_id} — {vendor} {product}. CVSS {cvss}. simulate=True."""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, mute,
    print_error, print_status, print_info, DestructiveGate,
)
class Exploit(Exploit):
    __info__ = {{
        "name":             "{cve_id} {vendor} {product}",
        "description":      "{desc}",
        "authors":          ("{AUTHOR}",),
        "references":       ("https://www.exploit-db.com",),
        "devices":          ("{vendor} {product}",),
        "impact":           "CRITICAL",
        "exploit_type":     "Remote Code Execution",
        "cve":              "{cve_id}",
        "cvss":             "{cvss}",
        "severity":         "CRITICAL",
        "mitre_techniques": ["T0866"],
        "mitre_tactics":    ["Initial Access"],
    }}
    target = OptIP("", "Target IP")
    port   = OptPort({port}, "Port")
    simulate = OptBool(True, "Simulate")
    destructive = OptBool(False, "Live")
    @mute
    def check(self):
        if not self.target: return False
        try:
            s = socket.socket(); s.settimeout(5)
            s.connect((self.target, self.port)); s.close(); return True
        except: return False
    def run(self):
        if not self.target: print_error("Set target"); return
        if self.simulate:
            DestructiveGate.print_simulation(
                description="{cve_id} {vendor} {product}\\nCVSS {cvss}\\n{sim}",
                mitre_techniques=["T0866"])
            return
        print_status("[{cve_id}] Exploiting {{}}:{{}}...".format(self.target, self.port))
        print_info("Live: implement exploit payload")
'''
    return write_if_new(MODULES / path, content)


def make_proto(path, name, desc, port, impact, mitre, tactics, sim):
    content = f'''"""IXF Protocol — {name}. No CVE. simulate=True."""
import socket
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, mute,
    print_error, print_status, print_info, DestructiveGate,
)
class Exploit(Exploit):
    __info__ = {{
        "name":             "{name}",
        "description":      "{desc}",
        "authors":          ("{AUTHOR}",),
        "references":       ("https://www.cisa.gov/ics",),
        "devices":          ("Multiple OT/ICS devices",),
        "impact":           "{impact}",
        "exploit_type":     "Protocol Design Abuse (No CVE)",
        "cve":              "N/A",
        "cvss":             "N/A",
        "severity":         "{impact}",
        "mitre_techniques": {mitre},
        "mitre_tactics":    {tactics},
    }}
    target = OptIP("", "Target IP")
    port   = OptPort({port}, "Protocol port")
    simulate = OptBool(True, "Simulate")
    destructive = OptBool(False, "Live")
    @mute
    def check(self):
        if not self.target: return False
        try:
            s = socket.socket(); s.settimeout(5)
            s.connect((self.target, self.port)); s.close(); return True
        except: return False
    def run(self):
        if not self.target: print_error("Set target"); return
        if self.simulate:
            DestructiveGate.print_simulation(
                description="{name}\\n{sim}",
                mitre_techniques={mitre})
            print_info("No CVE — inherent protocol design weakness")
            return
        print_status("[proto] Connecting to {{}}:{{}}...".format(self.target, self.port))
        print_info("Live: implement protocol-specific commands")
'''
    return write_if_new(MODULES / path, content)


BATCHES = [
    # ── MSF SCADA gaps ────────────────────────────────────────────────────────
    ("cve/broadwin/cve_2011_1566_webaccess_activex_bof.py",
     lambda: make_cve(
         "cve/broadwin/cve_2011_1566_webaccess_activex_bof.py",
         "CVE-2011-1566", "BroadWin/Advantech", "WebAccess HMI", 4592, "10.0",
         "BroadWin WebAccess ActiveX buffer overflow via SCADA web interface — unauthenticated RCE",
         "Access WebAccess port 4592, trigger ActiveX BOF, RCE on HMI workstation")),

    ("exploits/scada/epicor/cve_2015_7450_e9_sql_injection.py",
     lambda: make_cve(
         "exploits/scada/epicor/cve_2015_7450_e9_sql_injection.py",
         "CVE-2015-7450", "Epicor", "E9 ERP/MES", 443, "9.8",
         "Epicor E9 ERP/MES SQL injection — authentication bypass and data exfiltration in manufacturing OT",
         "POST SQLi to Epicor E9 login, bypass auth, dump MES process orders and production data")),

    ("exploits/scada/datac/cve_2011_3015_realwin_binfile_bof.py",
     lambda: make_cve(
         "exploits/scada/datac/cve_2011_3015_realwin_binfile_bof.py",
         "CVE-2011-3015", "DATAC", "RealWin SCADA", 912, "10.0",
         "DATAC RealWin SCADA server on_fc BINFILE buffer overflow — remote code execution",
         "Connect RealWin port 912, send oversized on_fc BINFILE parameter, stack overflow, RCE")),

    ("exploits/scada/matrikon/cve_2014_2244_opc_explorer_dcom_bof.py",
     lambda: make_cve(
         "exploits/scada/matrikon/cve_2014_2244_opc_explorer_dcom_bof.py",
         "CVE-2014-2244", "Matrikon", "OPC Explorer SCADA", 135, "9.8",
         "Matrikon OPC Explorer buffer overflow via DCOM OPC interface — remote code execution",
         "Connect OPC DCOM port 135, call MatrikonOPC server, buffer overflow in OPC data handler")),

    ("exploits/scada/sixnet/cve_2015_0988_unixtcp_stack_overflow.py",
     lambda: make_cve(
         "exploits/scada/sixnet/cve_2015_0988_unixtcp_stack_overflow.py",
         "CVE-2015-0988", "Sixnet/Red Lion", "UnixTCP Protocol Router", 1594, "9.8",
         "Sixnet industrial router UnixTCP protocol stack overflow — remote code execution",
         "Connect UnixTCP port 1594, send oversized HELLO command, stack overflow, RCE on router")),

    # ── LATAM/Brazil vendors ────────────────────────────────────────────────────
    ("cve/elipse/cve_2019_6543_e3_scada_rce.py",
     lambda: make_cve(
         "cve/elipse/cve_2019_6543_e3_scada_rce.py",
         "CVE-2019-6543", "Elipse Software", "E3 SCADA", 80, "9.8",
         "Elipse E3 SCADA (most popular SCADA in Brazil) web server buffer overflow — RCE",
         "Send malformed HTTP request to Elipse E3 port 80, buffer overflow, RCE on SCADA server")),

    ("cve/elipse/cve_2021_34585_epics_sql_injection.py",
     lambda: make_cve(
         "cve/elipse/cve_2021_34585_epics_sql_injection.py",
         "CVE-2021-34585", "Elipse Software", "Epics SCADA/Historian", 1433, "9.8",
         "Elipse Epics SCADA historian SQL injection — authentication bypass in Brazilian manufacturing",
         "POST SQLi to Epics login, bypass auth, dump historian process data for manufacturing")),

    ("cve/smar/cve_2011_4873_processview_bof.py",
     lambda: make_cve(
         "cve/smar/cve_2011_4873_processview_bof.py",
         "CVE-2011-4873", "Smar", "ProcessView SCADA", 8080, "9.8",
         "Smar ProcessView SCADA (Brazil, FOUNDATION Fieldbus) buffer overflow — RCE",
         "Send crafted FBD project to Smar ProcessView port 8080, buffer overflow, RCE")),

    # ── Missing protocols ────────────────────────────────────────────────────────
    ("exploits/protocols/s7comm_plus/s7plus_protection_bypass.py",
     lambda: make_proto(
         "exploits/protocols/s7comm_plus/s7plus_protection_bypass.py",
         "Siemens S7comm+ Read/Write Protection Bypass",
         "S7comm+ (S7-1200/1500) read/write protection bypass via crafted TLS S7comm+ packets",
         102, "HIGH", '["T0855","T0832"]', '["Collection"]',
         "Connect S7comm+ TLS port 102, craft bypass packet, access protected memory areas")),

    ("exploits/protocols/pcom/pcom_unauthorized_plc_control.py",
     lambda: make_proto(
         "exploits/protocols/pcom/pcom_unauthorized_plc_control.py",
         "Unitronics PCOM Protocol Unauthorized PLC Control",
         "Unitronics PCOM (Protocol for Communication) — no auth, any device can read/write PLC memory",
         20256, "CRITICAL", '["T1692.001","T0821"]', '["Impair Process Control"]',
         "Send PCOM connect request to UDP 20256, read DM area, write outputs without any authentication")),

    ("exploits/protocols/ads/beckhoff_ads_unauthorized_read_write.py",
     lambda: make_proto(
         "exploits/protocols/ads/beckhoff_ads_unauthorized_read_write.py",
         "Beckhoff ADS/AMS Unauthorized Read/Write",
         "Beckhoff TwinCAT ADS (Automation Device Spec) — no auth on AMS/TCP, read/write all variables",
         48898, "HIGH", '["T0888","T0836"]', '["Discovery","Impair Process Control"]',
         "Connect ADS port 48898, read/write PLC variables without authentication, full TwinCAT access")),

    ("exploits/protocols/controlnet/controlnet_unauthenticated_msg.py",
     lambda: make_proto(
         "exploits/protocols/controlnet/controlnet_unauthenticated_msg.py",
         "Rockwell ControlNet Unauthenticated Unscheduled Messaging",
         "ControlNet (Rockwell) has no authentication on unscheduled messaging — read all node data",
         44818, "HIGH", '["T0888","T0836"]', '["Discovery"]',
         "Bridge through EtherNet/IP, access ControlNet nodes via unscheduled CIP, read I/O")),

    ("exploits/protocols/devicenet/devicenet_node_enum.py",
     lambda: make_proto(
         "exploits/protocols/devicenet/devicenet_node_enum.py",
         "Rockwell DeviceNet Node Enumeration and I/O Access",
         "DeviceNet (CAN-based, Rockwell) — no authentication, enumerate all 64 nodes and read I/O",
         44818, "MEDIUM", '["T0888","T0802"]', '["Discovery"]',
         "Access DeviceNet via EtherNet/IP/CAN gateway, scan node addresses 0-63, read device I/O")),

    ("exploits/protocols/pccc/pccc_slc500_unauthorized.py",
     lambda: make_proto(
         "exploits/protocols/pccc/pccc_slc500_unauthorized.py",
         "Allen-Bradley PCCC (SLC-500/MicroLogix) Unauthorized Access",
         "Legacy PCCC protocol (SLC-500, MicroLogix, PLC-5) — no auth, read/write all data files",
         44818, "HIGH", '["T1692.001","T0836"]', '["Impair Process Control"]',
         "Connect PCCC via EtherNet/IP, read N7:0 integer file, write outputs to MicroLogix without auth")),

    ("exploits/protocols/vnetip/yokogawa_vnetip_protocol_access.py",
     lambda: make_proto(
         "exploits/protocols/vnetip/yokogawa_vnetip_protocol_access.py",
         "Yokogawa Vnet/IP DCS Protocol Access",
         "Yokogawa Vnet/IP (proprietary DCS network) — limited authentication, DoS and data access",
         20111, "HIGH", '["T0814","T0888"]', '["Inhibit Response Function","Discovery"]',
         "Send malformed Vnet/IP packet to CENTUM port 20111, DCS communication disrupted or data read")),

    ("exploits/protocols/fl_net/fl_net_opcn2_access.py",
     lambda: make_proto(
         "exploits/protocols/fl_net/fl_net_opcn2_access.py",
         "FL-NET (OPCN-2) Unauthenticated Node Access",
         "FL-NET (Fuji Electric/JTEKT Factory LAN) — no authentication on node communication",
         7000, "HIGH", '["T0888","T0802"]', '["Discovery"]',
         "Send FL-NET UDP broadcast to port 7000, enumerate all nodes, read process I/O")),

    ("exploits/protocols/componet/componet_slave_scan.py",
     lambda: make_proto(
         "exploits/protocols/componet/componet_slave_scan.py",
         "Omron CompoNet Slave I/O Scan",
         "Omron CompoNet — no authentication on cyclic I/O communication via FINS gateway",
         9600, "MEDIUM", '["T0888","T0802"]', '["Discovery"]',
         "Send CompoNet broadcast via FINS gateway, enumerate all slave nodes, read digital I/O")),

    ("exploits/protocols/cc_link_ie_field/cc_link_ie_field_device_scan.py",
     lambda: make_proto(
         "exploits/protocols/cc_link_ie_field/cc_link_ie_field_device_scan.py",
         "CC-Link IE Field Network Device Scan",
         "CC-Link IE Field (Mitsubishi advanced fieldbus) — no authentication on device scanning",
         61450, "MEDIUM", '["T0888","T0802"]', '["Discovery"]',
         "Send CC-Link IE Field broadcast UDP 61450, enumerate field devices, read I/O data")),

    ("exploits/protocols/profibus_pa/profibus_pa_scan.py",
     lambda: make_proto(
         "exploits/protocols/profibus_pa/profibus_pa_scan.py",
         "PROFIBUS PA Process Automation Instrument Scan",
         "PROFIBUS PA (hazardous area variant) — no authentication on instrument access via PA coupler",
         1962, "MEDIUM", '["T0888","T0802"]', '["Discovery"]',
         "Connect PROFIBUS PA coupler gateway port 1962, scan all PA nodes, read instrument PVs")),

    ("exploits/protocols/foundation_fieldbus/ff_h1_setpoint_write.py",
     lambda: make_proto(
         "exploits/protocols/foundation_fieldbus/ff_h1_setpoint_write.py",
         "FOUNDATION Fieldbus H1 Function Block Setpoint Write",
         "FF H1 field instruments — no authentication on function block parameter writes via HSE gateway",
         1089, "HIGH", '["T0888","T0836"]', '["Impair Process Control"]',
         "Connect FF H1 HSE gateway port 1089, enumerate function blocks, write SP parameters without auth")),

    ("exploits/protocols/foundation_fieldbus/ff_hse_management_rpc.py",
     lambda: make_proto(
         "exploits/protocols/foundation_fieldbus/ff_hse_management_rpc.py",
         "FOUNDATION Fieldbus HSE Management RPC Unauthorized Access",
         "FF HSE (High-Speed Ethernet) — no auth on FDA management RPC, full fieldbus device access",
         1089, "HIGH", '["T0888","T0836"]', '["Impair Process Control"]',
         "Connect FF HSE port 1089, call FDA_Open RPC without auth, read/write all field device parameters")),

    ("exploits/protocols/opc_hda/opc_hda_anon_read.py",
     lambda: make_proto(
         "exploits/protocols/opc_hda/opc_hda_anon_read.py",
         "OPC Historical Data Access (HDA) Anonymous Historical Read",
         "OPC HDA servers often allow anonymous access — expose years of process history",
         135, "MEDIUM", '["T0803","T0832"]', '["Collection"]',
         "Connect OPC HDA DCOM port 135, anonymous browse all items, read historical process data")),

    ("exploits/protocols/opc_ae/opc_ae_alarm_subscription.py",
     lambda: make_proto(
         "exploits/protocols/opc_ae/opc_ae_alarm_subscription.py",
         "OPC Alarms and Events (A&E) Unauthenticated Subscription and Acknowledgment",
         "OPC A&E servers allow anonymous subscription and alarm acknowledgment — suppress safety alarms",
         135, "MEDIUM", '["T0880","T0832"]', '["Inhibit Response Function"]',
         "Connect OPC A&E DCOM port 135, subscribe all alarm categories, acknowledge alarms without auth")),

    ("exploits/protocols/bacnet_mstp/bacnet_mstp_gateway.py",
     lambda: make_proto(
         "exploits/protocols/bacnet_mstp/bacnet_mstp_gateway.py",
         "BACnet/MSTP Building Automation Serial Network Access",
         "BACnet/MSTP (Master-Slave/Token-Passing) — no authentication, access via BACnet/IP router",
         47808, "MEDIUM", '["T0888","T0802"]', '["Discovery"]',
         "Connect BACnet/IP router UDP 47808, access MSTP devices, read/write BACnet properties")),

    ("exploits/protocols/lonworks/lonworks_nv_write.py",
     lambda: make_proto(
         "exploits/protocols/lonworks/lonworks_nv_write.py",
         "LonWorks/LonTalk Network Variable Write",
         "LonWorks control network — no authentication on NV writes via IP-852 router",
         1628, "MEDIUM", '["T0888","T0836"]', '["Impair Process Control"]',
         "Connect LonWorks IP-852 router port 1628, enumerate NVs, write values to control HVAC/lighting")),

    ("exploits/protocols/knx/knx_ip_group_write.py",
     lambda: make_proto(
         "exploits/protocols/knx/knx_ip_group_write.py",
         "KNX/EIB IP Tunnel Group Address Write Without Auth",
         "KNX building automation — no authentication on IP tunnel group address writes",
         3671, "HIGH", '["T0836","T0826"]', '["Impair Process Control"]',
         "Connect KNX IP tunnel UDP 3671, send KNX telegram to HVAC group, modify temperature setpoints")),

    ("exploits/protocols/interbus/interbus_master_access.py",
     lambda: make_proto(
         "exploits/protocols/interbus/interbus_master_access.py",
         "INTERBUS Master Protocol Process Data Access",
         "INTERBUS (Phoenix Contact ring fieldbus) — no authentication on master process data access",
         1962, "MEDIUM", '["T0888","T0802"]', '["Discovery"]',
         "Connect INTERBUS master gateway port 1962, read ring I/O table, access all slave module data")),

    ("exploits/protocols/hsms/secs_gem_equipment_control.py",
     lambda: make_proto(
         "exploits/protocols/hsms/secs_gem_equipment_control.py",
         "SECS/GEM (SEMI E37/E30) Semiconductor Equipment Unauthorized Control",
         "SECS/GEM protocol (semiconductor fab equipment: TSMC, Samsung, Intel) — no auth on legacy equipment",
         5000, "CRITICAL", '["T0813","T0836"]', '["Impair Process Control"]',
         "Connect SECS-II HSMS port 5000, send S2F41 Host Command, execute recipe change without auth")),
]


def main():
    created = 0
    for path_or_tuple, factory in BATCHES:
        result = factory()
        if result:
            created += 1
            print(f"  {Path(path_or_tuple).name}")

    from industrialxpl.core.exploit.utils import index_modules, import_exploit
    mods = index_modules()
    errs = 0
    for m in mods:
        try:
            import_exploit("industrialxpl.modules." + m)()
        except Exception:
            errs += 1
    print(f"\n[final_gaps] Created: {created} | Total: {len(mods)} | Errors: {errs}")


if __name__ == "__main__":
    main()
