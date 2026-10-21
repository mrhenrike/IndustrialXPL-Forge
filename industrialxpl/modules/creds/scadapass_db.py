"""SCADAPASS: Default credentials database for ICS/SCADA/OT devices.

Comprehensive database of factory-default credentials for industrial
control systems, PLCs, RTUs, HMIs, SCADA servers, engineering workstations,
network switches, gateways, IIoT appliances, and OT-adjacent devices.

Sources:
  - SCADAPASS project by SCADA StrangeLove (public domain ICS credential lists)
  - Vendor documentation, manuals, and security advisories
  - ICS-CERT / CISA advisories on default credentials
  - CISA ICS-CERT Alert TA17-156A (Default Credentials)
  - CVE entries with hardcoded/default credential references
  - Mirai botnet source code (scanner.c credential table)
  - SecLists project (danielmiessler/SecLists)
  - Nessus/Tenable ICS default credential plugins
  - Shodan/Censys ICS exposure research

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import csv
import io
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptString,
    print_error, print_info, print_status, print_success, print_warning,
)

log = logging.getLogger(__name__)


class CredCategory(str, Enum):
    PLC = "plc"
    RTU = "rtu"
    DCS = "dcs"
    HMI = "hmi"
    SCADA = "scada"
    EWS = "ews"
    SWITCH = "switch"
    ROUTER = "router"
    GATEWAY = "gateway"
    FIREWALL_OT = "firewall_ot"
    IED = "ied"
    RELAY = "relay"
    METER = "meter"
    DRIVE = "drive"
    ROBOT = "robot"
    IIOT = "iiot"
    HISTORIAN = "historian"
    PROTOCOL = "protocol"
    SNMP = "snmp"
    BOTNET = "botnet"
    BMS = "bms"
    UPS = "ups"
    SERIAL = "serial_device"
    CAMERA = "camera"
    NAS = "nas"
    PRINTER = "printer"


@dataclass
class DefaultCredential:
    """A single default credential entry."""
    vendor: str
    product: str
    protocol: str
    port: int
    username: str
    password: str
    access_level: str = "admin"
    notes: str = ""
    cve: str = ""
    verified: bool = True
    category: str = ""


# ---------------------------------------------------------------------------
# Embedded credential database: ICS/SCADA/OT manufacturers
# ---------------------------------------------------------------------------

CREDENTIAL_DB: list[DefaultCredential] = [

    # ===================================================================
    # SIEMENS
    # ===================================================================
    DefaultCredential("Siemens", "S7-300/400", "S7comm", 102, "", "", "full",
                      "No auth by default; full PLC memory R/W", category="plc"),
    DefaultCredential("Siemens", "S7-1200 Web", "HTTP", 80, "admin", "admin", "admin",
                      category="plc"),
    DefaultCredential("Siemens", "S7-1200 Web", "HTTP", 80, "Everybody", "", "read",
                      "Read-only user; Siemens default", category="plc"),
    DefaultCredential("Siemens", "S7-1500 Web", "HTTPS", 443, "admin", "", "admin",
                      "Empty password on factory reset", category="plc"),
    DefaultCredential("Siemens", "S7-1500 OPC-UA", "OPC-UA", 4840, "", "", "read",
                      "Anonymous OPC-UA access enabled by default", category="plc"),
    DefaultCredential("Siemens", "WinCC", "HTTP", 80, "administrator", "", "admin",
                      category="scada"),
    DefaultCredential("Siemens", "WinCC OA", "HTTP", 4999, "root", "", "admin",
                      category="scada"),
    DefaultCredential("Siemens", "WinCC Flexible", "HTTP", 80, "admin", "admin", "admin",
                      category="scada"),
    DefaultCredential("Siemens", "SCALANCE X-200", "HTTP", 80, "admin", "admin", "admin",
                      "Industrial Ethernet switch", category="switch"),
    DefaultCredential("Siemens", "SCALANCE X-300", "HTTP", 80, "admin", "admin", "admin",
                      "Managed industrial switch", category="switch"),
    DefaultCredential("Siemens", "SCALANCE X-400", "HTTPS", 443, "admin", "admin", "admin",
                      "Modular industrial switch", category="switch"),
    DefaultCredential("Siemens", "SCALANCE XR-500", "HTTPS", 443, "admin", "admin", "admin",
                      "Rack switch", category="switch"),
    DefaultCredential("Siemens", "SCALANCE W", "HTTP", 80, "admin", "admin", "admin",
                      "Industrial WLAN AP", category="switch"),
    DefaultCredential("Siemens", "SCALANCE M", "HTTPS", 443, "admin", "admin", "admin",
                      "Industrial router 3G/4G", category="router"),
    DefaultCredential("Siemens", "SCALANCE SC-600", "HTTPS", 443, "admin", "admin", "admin",
                      "Industrial security appliance", category="firewall_ot"),
    DefaultCredential("Siemens", "RUGGEDCOM ROS", "SSH", 22, "admin", "admin", "admin",
                      "Ruggedized switch/router", category="switch"),
    DefaultCredential("Siemens", "RUGGEDCOM ROS", "HTTPS", 443, "admin", "admin", "admin",
                      category="switch"),
    DefaultCredential("Siemens", "RUGGEDCOM ROX II", "SSH", 22, "admin", "admin", "admin",
                      "Ruggedized router", category="router"),
    DefaultCredential("Siemens", "RUGGEDCOM APE", "SSH", 22, "admin", "admin", "admin",
                      "Application Processing Engine", category="gateway"),
    DefaultCredential("Siemens", "SINEMA Server", "HTTPS", 443, "admin", "admin", "admin",
                      "Network management", category="scada"),
    DefaultCredential("Siemens", "SINEMA Remote Connect", "HTTPS", 443, "admin", "admin", "admin",
                      "Remote access platform", category="gateway"),
    DefaultCredential("Siemens", "TIA Portal", "OPC-UA", 4840, "", "", "read",
                      "OPC-UA anonymous access", category="ews"),
    DefaultCredential("Siemens", "LOGO!", "HTTP", 80, "admin", "admin", "admin",
                      "Micro PLC", category="plc"),
    DefaultCredential("Siemens", "LOGO! 8", "HTTP", 80, "admin", "admin", "admin",
                      category="plc"),
    DefaultCredential("Siemens", "SIPROTEC 4", "HTTP", 80, "admin", "admin", "admin",
                      "Protection relay; CVE-2015-5374", "CVE-2015-5374", category="relay"),
    DefaultCredential("Siemens", "SIPROTEC 5", "HTTPS", 443, "admin", "", "admin",
                      "Protection relay", category="relay"),
    DefaultCredential("Siemens", "SICAM A8000", "HTTPS", 443, "admin", "admin", "admin",
                      "RTU/automation controller", category="rtu"),
    DefaultCredential("Siemens", "SICAM PAS", "HTTP", 80, "admin", "admin", "admin",
                      "Power Automation System", category="scada"),
    DefaultCredential("Siemens", "SIMATIC ET 200SP", "HTTP", 80, "admin", "admin", "admin",
                      "Distributed I/O", category="plc"),
    DefaultCredential("Siemens", "SIMATIC HMI Comfort", "HTTP", 80, "admin", "admin", "admin",
                      "HMI panel", category="hmi"),
    DefaultCredential("Siemens", "SINAMICS G120", "HTTP", 80, "admin", "admin", "admin",
                      "Variable frequency drive", category="drive"),
    DefaultCredential("Siemens", "SIMATIC IPC", "SSH", 22, "root", "root", "admin",
                      "Industrial PC (some firmware)", category="ews"),
    DefaultCredential("Siemens", "SIMATIC PDM", "HTTP", 80, "admin", "admin", "admin",
                      "Process Device Manager", category="ews"),
    DefaultCredential("Siemens", "Desigo CC", "HTTPS", 443, "admin", "admin", "admin",
                      "Building management", category="bms"),

    # ===================================================================
    # ROCKWELL AUTOMATION / ALLEN-BRADLEY
    # ===================================================================
    DefaultCredential("Rockwell", "ControlLogix L7x", "EtherNet/IP", 44818, "", "", "full",
                      "No auth default; CIP unconnected messaging", category="plc"),
    DefaultCredential("Rockwell", "ControlLogix L8x", "EtherNet/IP", 44818, "", "", "full",
                      "CIP Security optional; off by default", category="plc"),
    DefaultCredential("Rockwell", "CompactLogix L3x", "EtherNet/IP", 44818, "", "", "full",
                      "No auth default", category="plc"),
    DefaultCredential("Rockwell", "CompactLogix 5380", "EtherNet/IP", 44818, "", "", "full",
                      category="plc"),
    DefaultCredential("Rockwell", "MicroLogix 1100", "HTTP", 80, "admin", "1234", "admin",
                      category="plc"),
    DefaultCredential("Rockwell", "MicroLogix 1400", "HTTP", 80, "admin", "1234", "admin",
                      "LCD default master key", category="plc"),
    DefaultCredential("Rockwell", "MicroLogix 1400 SNMP", "SNMP", 161, "public", "", "read",
                      "CVE-2016-5645; hardcoded RO", "CVE-2016-5645", category="plc"),
    DefaultCredential("Rockwell", "MicroLogix 1400 SNMP", "SNMP", 161, "private", "", "write",
                      "CVE-2016-5645; hardcoded RW", "CVE-2016-5645", category="plc"),
    DefaultCredential("Rockwell", "MicroLogix 1400 SNMP", "SNMP", 161, "wheel", "", "write",
                      "Undocumented hardcoded RW community; Talos report", "CVE-2016-5645",
                      category="plc"),
    DefaultCredential("Rockwell", "PanelView Plus", "HTTP", 80, "admin", "", "admin",
                      "HMI terminal", category="hmi"),
    DefaultCredential("Rockwell", "PanelView Plus 7", "HTTP", 80, "admin", "", "admin",
                      category="hmi"),
    DefaultCredential("Rockwell", "FactoryTalk View SE", "HTTP", 80, "admin", "", "admin",
                      "SCADA/HMI server", category="scada"),
    DefaultCredential("Rockwell", "FactoryTalk Linx", "HTTP", 80, "admin", "", "admin",
                      category="ews"),
    DefaultCredential("Rockwell", "Stratix 5700", "SSH", 22, "admin", "admin", "admin",
                      "Managed industrial switch (Cisco IOS)", category="switch"),
    DefaultCredential("Rockwell", "Stratix 5700", "HTTP", 80, "admin", "admin", "admin",
                      category="switch"),
    DefaultCredential("Rockwell", "Stratix 5400", "SSH", 22, "admin", "admin", "admin",
                      "Layer 3 switch", category="switch"),
    DefaultCredential("Rockwell", "1756-EN2T", "EtherNet/IP", 44818, "", "", "full",
                      "Communication module; no auth", category="plc"),
    DefaultCredential("Rockwell", "ArmorStart", "EtherNet/IP", 44818, "", "", "full",
                      "Motor controller", category="drive"),

    # ===================================================================
    # SCHNEIDER ELECTRIC
    # ===================================================================
    DefaultCredential("Schneider", "Modicon M340", "Modbus", 502, "", "", "full",
                      "No Modbus auth", category="plc"),
    DefaultCredential("Schneider", "Modicon M340 FTP", "FTP", 21, "USER", "USER", "engineer",
                      "FactoryCast FTP default", category="plc"),
    DefaultCredential("Schneider", "Modicon M340 Web", "HTTP", 80, "USER", "USER", "engineer",
                      "FactoryCast WebServer", category="plc"),
    DefaultCredential("Schneider", "Modicon M580", "Modbus", 502, "", "", "full",
                      "No Modbus auth", category="plc"),
    DefaultCredential("Schneider", "Modicon M580 Web (fw>=4.02)", "HTTPS", 443, "webuser", "webuser",
                      "admin", "Default web credentials post firmware 4.02", category="plc"),
    DefaultCredential("Schneider", "Modicon M580 FTP", "FTP", 21, "USER", "USER", "engineer",
                      category="plc"),
    DefaultCredential("Schneider", "Modicon M340/M580 FW Download", "FTP", 21, "", "fwdownload",
                      "firmware", "Firmware download password (no username)", category="plc"),
    DefaultCredential("Schneider", "Modicon M340/M580 Data Storage", "FTP", 21, "", "datadownload",
                      "data", "Data storage password (no username)", category="plc"),
    DefaultCredential("Schneider", "Modicon Migration FW V3.99", "FTP", 21, "loader", "fwdownload",
                      "firmware", "Migration device authentication", category="plc"),
    DefaultCredential("Schneider", "Quantum", "Modbus", 502, "", "", "full",
                      category="plc"),
    DefaultCredential("Schneider", "Quantum FTP", "FTP", 21, "USER", "USER", "admin",
                      category="plc"),
    DefaultCredential("Schneider", "Quantum Telnet", "Telnet", 23, "USER", "USER", "admin",
                      category="plc"),
    DefaultCredential("Schneider", "Premium", "Modbus", 502, "", "", "full",
                      "Legacy PLC; no Modbus auth", category="plc"),
    DefaultCredential("Schneider", "Unity Pro / EcoStruxure", "HTTP", 80, "USER", "USER",
                      "engineer", category="ews"),
    DefaultCredential("Schneider", "ClearSCADA / GeoSCADA", "HTTPS", 443, "admin", "admin",
                      "admin", category="scada"),
    DefaultCredential("Schneider", "ION 7650", "HTTP", 80, "ADMIN", "0", "admin",
                      "Power meter", category="meter"),
    DefaultCredential("Schneider", "ION 8800", "HTTP", 80, "ADMIN", "0", "admin",
                      "Power quality meter", category="meter"),
    DefaultCredential("Schneider", "PowerLogic PM800", "HTTP", 80, "admin", "admin", "admin",
                      category="meter"),
    DefaultCredential("Schneider", "PowerLogic PM5500", "HTTP", 80, "admin", "admin", "admin",
                      category="meter"),
    DefaultCredential("Schneider", "Magelis HMI", "HTTP", 80, "USER", "USER", "operator",
                      category="hmi"),
    DefaultCredential("Schneider", "Magelis iPC", "HTTP", 80, "USER", "USER", "operator",
                      category="hmi"),
    DefaultCredential("Schneider", "APC UPS NMC (AP9630/31)", "HTTP", 80, "apc", "apc", "admin",
                      "Network Management Card", category="ups"),
    DefaultCredential("Schneider", "APC UPS NMC", "SSH", 22, "apc", "apc", "admin",
                      category="ups"),
    DefaultCredential("Schneider", "APC UPS NMC", "SNMP", 161, "public", "", "read",
                      "SNMP default community", category="ups"),
    DefaultCredential("Schneider", "APC UPS NMC", "Telnet", 23, "apc", "apc", "admin",
                      category="ups"),
    DefaultCredential("Schneider", "APC Rack PDU", "HTTP", 80, "apc", "apc", "admin",
                      category="ups"),
    DefaultCredential("Schneider", "Triconex TriStation", "TriStation", 1502, "", "", "full",
                      "No auth; TRITON/TRISIS target protocol", category="plc"),
    DefaultCredential("Schneider", "Trio Q Data Radio", "HTTP", 80, "admin", "admin", "admin",
                      "Radio modem for SCADA", category="gateway"),
    DefaultCredential("Schneider", "ConneXium (TCSESM)", "HTTP", 80, "admin", "admin", "admin",
                      "Industrial Ethernet switch", category="switch"),
    DefaultCredential("Schneider", "Altivar Drive ATV", "HTTP", 80, "USER", "USER", "admin",
                      "Variable frequency drive web", category="drive"),
    DefaultCredential("Schneider", "EcoStruxure Building", "HTTPS", 443, "admin", "admin",
                      "admin", "Building management", category="bms"),
    DefaultCredential("Schneider", "SCADAPack RTU", "HTTP", 80, "admin", "admin", "admin",
                      "Telemetry RTU", category="rtu"),

    # ===================================================================
    # ABB
    # ===================================================================
    DefaultCredential("ABB", "AC500", "HTTP", 80, "admin", "admin", "admin",
                      "PLC web interface", category="plc"),
    DefaultCredential("ABB", "AC500 SSH", "SSH", 22, "admin", "admin", "admin",
                      category="plc"),
    DefaultCredential("ABB", "AC800M", "OPC-UA", 4840, "", "", "read",
                      "DCS controller; OPC-UA anonymous", category="dcs"),
    DefaultCredential("ABB", "Freelance", "HTTP", 80, "admin", "admin", "admin",
                      "DCS web interface", category="dcs"),
    DefaultCredential("ABB", "REF615", "HTTP", 80, "admin", "admin", "admin",
                      "Protection relay", category="relay"),
    DefaultCredential("ABB", "REF615 SSH", "SSH", 22, "admin", "admin", "admin",
                      category="relay"),
    DefaultCredential("ABB", "REF630", "HTTP", 80, "admin", "admin", "admin",
                      "Bay control relay", category="relay"),
    DefaultCredential("ABB", "Relion 670", "HTTP", 80, "admin", "admin", "admin",
                      "High-voltage protection relay", category="relay"),
    DefaultCredential("ABB", "RTU560", "HTTP", 80, "admin", "admin", "admin",
                      "Remote Terminal Unit", category="rtu"),
    DefaultCredential("ABB", "RTU560 SSH", "SSH", 22, "admin", "admin", "admin",
                      category="rtu"),
    DefaultCredential("ABB", "RTU520", "HTTP", 80, "admin", "admin", "admin",
                      category="rtu"),
    DefaultCredential("ABB", "Symphony Plus", "HTTP", 80, "ADMIN", "ADMIN", "admin",
                      "DCS system", category="dcs"),
    DefaultCredential("ABB", "800xA", "HTTP", 80, "admin", "admin", "admin",
                      "DCS platform", category="dcs"),
    DefaultCredential("ABB", "ACS880 Drive", "HTTP", 80, "admin", "admin", "admin",
                      "Variable frequency drive", category="drive"),
    DefaultCredential("ABB", "IRC5 Robot Controller", "HTTP", 80, "admin", "", "admin",
                      "Robot controller FlexPendant", category="robot"),
    DefaultCredential("ABB", "AFS Ethernet Module", "HTTP", 80, "admin", "admin", "admin",
                      category="gateway"),
    DefaultCredential("ABB", "FOX515 RTU", "HTTP", 80, "admin", "admin", "admin",
                      category="rtu"),

    # ===================================================================
    # GE / GE VERNOVA
    # ===================================================================
    DefaultCredential("GE", "Mark VIe", "HTTP", 80, "admin", "admin", "admin",
                      "Turbine control system", category="dcs"),
    DefaultCredential("GE", "Mark VIe SSH", "SSH", 22, "admin", "admin", "admin",
                      category="dcs"),
    DefaultCredential("GE", "PACSystems RX3i", "SRTP", 18245, "", "", "full",
                      "No SRTP auth by default", category="plc"),
    DefaultCredential("GE", "PACSystems RX3i Web", "HTTP", 80, "admin", "admin", "admin",
                      category="plc"),
    DefaultCredential("GE", "PACSystems RSTi-EP", "HTTP", 80, "admin", "", "admin",
                      category="plc"),
    DefaultCredential("GE", "Cimplicity", "HTTP", 80, "admin", "", "admin",
                      "HMI/SCADA", category="scada"),
    DefaultCredential("GE", "iFIX", "HTTP", 80, "admin", "", "admin",
                      "HMI/SCADA", category="scada"),
    DefaultCredential("GE", "Historian", "HTTP", 80, "admin", "admin", "admin",
                      "OSIsoft-based historian", category="historian"),
    DefaultCredential("GE", "Multilin 850", "HTTP", 80, "admin", "admin", "admin",
                      "Feeder protection relay", category="relay"),
    DefaultCredential("GE", "Multilin 489", "HTTP", 80, "admin", "admin", "admin",
                      "Generator protection relay", category="relay"),
    DefaultCredential("GE", "UR Series (B30/C60/G60)", "HTTP", 80, "admin", "admin", "admin",
                      "Universal relay", category="relay"),
    DefaultCredential("GE", "D20MX RTU", "Telnet", 23, "root", "root", "admin",
                      "Substation gateway", category="rtu"),
    DefaultCredential("GE", "D400 Substation Gateway", "HTTP", 80, "admin", "admin", "admin",
                      category="gateway"),

    # ===================================================================
    # HONEYWELL
    # ===================================================================
    DefaultCredential("Honeywell", "Experion PKS", "HTTP", 80, "ADMIN", "ADMIN", "admin",
                      "DCS platform", category="dcs"),
    DefaultCredential("Honeywell", "Experion PKS SSH", "SSH", 22, "admin", "admin", "admin",
                      category="dcs"),
    DefaultCredential("Honeywell", "C300 Controller", "HTTP", 80, "admin", "1234", "admin",
                      category="plc"),
    DefaultCredential("Honeywell", "Safety Manager (SC)", "Serial", 0, "", "", "full",
                      "CVE-2022-30314; hardcoded credentials in ROM", "CVE-2022-30314",
                      category="plc"),
    DefaultCredential("Honeywell", "Safety Manager (SC) DCOM", "DCOM", 135, "", "", "full",
                      "CVE-2022-30314; hardcoded ROM credentials", "CVE-2022-30314",
                      category="plc"),
    DefaultCredential("Honeywell", "Spyder BMS Controller", "HTTP", 80, "admin", "admin", "admin",
                      "Building controller; BACnet/IP", category="bms"),
    DefaultCredential("Honeywell", "Spyder BMS Controller", "BACnet", 47808, "", "", "full",
                      "No BACnet auth", category="bms"),
    DefaultCredential("Honeywell", "Tuxedo Touch", "HTTP", 80, "admin", "admin", "admin",
                      "Security/BMS panel", category="bms"),
    DefaultCredential("Honeywell", "Niagara (Tridium)", "HTTPS", 443, "admin", "admin", "admin",
                      "Framework for BMS", category="bms"),
    DefaultCredential("Honeywell", "ControlEdge RTU", "HTTP", 80, "admin", "admin", "admin",
                      category="rtu"),
    DefaultCredential("Honeywell", "ControlEdge PLC", "HTTP", 80, "admin", "admin", "admin",
                      category="plc"),
    DefaultCredential("Honeywell", "Falcon XL", "HTTP", 80, "admin", "honeywell", "admin",
                      "Gas chromatograph", category="iiot"),
    DefaultCredential("Honeywell", "Enraf CIU", "HTTP", 80, "admin", "admin", "admin",
                      "Tank gauging", category="iiot"),

    # ===================================================================
    # EMERSON (Fisher, ROC, DeltaV, Ovation)
    # ===================================================================
    DefaultCredential("Emerson", "DeltaV", "HTTP", 80, "admin", "admin", "admin",
                      "DCS platform", category="dcs"),
    DefaultCredential("Emerson", "DeltaV SIS", "HTTP", 80, "admin", "deltav", "admin",
                      "Safety Instrumented System", category="dcs"),
    DefaultCredential("Emerson", "ROC800", "Serial", 0, "LOI", "1000", "engineer",
                      "Flow computer; serial console", category="rtu"),
    DefaultCredential("Emerson", "ROC800 (sw<=3.50)", "Serial", 0, "", "", "full",
                      "CVE-2013-0694; hardcoded ROM credentials", "CVE-2013-0694", category="rtu"),
    DefaultCredential("Emerson", "ROC800 Telnet", "Telnet", 23, "ROC", "ROC", "admin",
                      category="rtu"),
    DefaultCredential("Emerson", "FloBoss 107", "HTTP", 80, "admin", "admin", "admin",
                      "Flow computer", category="rtu"),
    DefaultCredential("Emerson", "OpenBSI", "HTTP", 80, "admin", "", "admin",
                      "SCADA server", category="scada"),
    DefaultCredential("Emerson", "Ovation DCS", "HTTP", 80, "admin", "admin", "admin",
                      "Power generation DCS", category="dcs"),
    DefaultCredential("Emerson", "Fisher DVC6200", "HART", 0, "", "", "full",
                      "HART field device; no auth", category="iiot"),
    DefaultCredential("Emerson", "Rosemount 3051S", "HART", 0, "", "", "full",
                      "Pressure transmitter; HART no auth", category="iiot"),
    DefaultCredential("Emerson", "AMS Device Manager", "HTTP", 80, "admin", "admin", "admin",
                      category="ews"),
    DefaultCredential("Emerson", "Wireless Gateway 1420", "HTTP", 80, "admin", "admin", "admin",
                      "WirelessHART gateway", category="gateway"),

    # ===================================================================
    # YOKOGAWA
    # ===================================================================
    DefaultCredential("Yokogawa", "CENTUM VP", "HTTP", 20171, "admin", "admin", "admin",
                      "DCS platform", category="dcs"),
    DefaultCredential("Yokogawa", "CENTUM VP HIS", "HTTP", 80, "CENTUM", "", "operator",
                      "Predefined user accounts", category="dcs"),
    DefaultCredential("Yokogawa", "CENTUM VP FCS", "Vnet/IP", 0, "", "", "full",
                      "No Vnet/IP auth by design", category="dcs"),
    DefaultCredential("Yokogawa", "ProSafe-RS", "HTTP", 80, "admin", "admin", "admin",
                      "Safety Instrumented System", category="dcs"),
    DefaultCredential("Yokogawa", "STARDOM", "HTTP", 80, "admin", "admin", "admin",
                      "RTU/PLC; YSAR-18-0004 hardcoded pw", category="rtu"),
    DefaultCredential("Yokogawa", "STARDOM (hardcoded)", "HTTP", 80, "admin", "Yoko2018!", "admin",
                      "Hardcoded in some firmware versions", category="rtu"),
    DefaultCredential("Yokogawa", "e-RT3 (FA-M3)", "HTTP", 80, "admin", "admin", "admin",
                      "Range-free controller", category="plc"),
    DefaultCredential("Yokogawa", "FAST/TOOLS", "HTTP", 80, "admin", "admin", "admin",
                      "SCADA platform", category="scada"),
    DefaultCredential("Yokogawa", "Exaquantum", "HTTP", 80, "admin", "admin", "admin",
                      "Plant information management", category="historian"),
    DefaultCredential("Yokogawa", "AQ1000 Analyzer", "HTTP", 80, "admin", "admin", "admin",
                      "Water quality analyzer", category="iiot"),

    # ===================================================================
    # MITSUBISHI ELECTRIC
    # ===================================================================
    DefaultCredential("Mitsubishi", "MELSEC-Q", "MELSEC", 5007, "", "", "full",
                      "No MELSEC binary protocol auth", category="plc"),
    DefaultCredential("Mitsubishi", "MELSEC iQ-R", "MELSEC", 5007, "", "", "full",
                      "No auth unless SLMP secure mode", category="plc"),
    DefaultCredential("Mitsubishi", "MELSEC iQ-F (FX5U)", "MELSEC", 5007, "", "", "full",
                      category="plc"),
    DefaultCredential("Mitsubishi", "MELSEC-L", "MELSEC", 5007, "", "", "full",
                      category="plc"),
    DefaultCredential("Mitsubishi", "GOT2000 HMI", "HTTP", 80, "admin", "", "admin",
                      category="hmi"),
    DefaultCredential("Mitsubishi", "GOT2000 HMI VNC", "VNC", 5900, "", "0000", "view",
                      "Default VNC password", category="hmi"),
    DefaultCredential("Mitsubishi", "MELSOFT GX Works3", "HTTP", 80, "admin", "", "admin",
                      "Engineering workstation", category="ews"),
    DefaultCredential("Mitsubishi", "CC-Link IE Field", "CC-Link", 61450, "", "", "full",
                      "No auth; industrial fieldbus", category="plc"),
    DefaultCredential("Mitsubishi", "MR-J5 Servo", "CC-Link", 61450, "", "", "full",
                      "Servo amplifier; no auth", category="drive"),

    # ===================================================================
    # OMRON
    # ===================================================================
    DefaultCredential("Omron", "CJ2M", "FINS", 9600, "", "", "full",
                      "No FINS authentication", category="plc"),
    DefaultCredential("Omron", "CP1L", "FINS", 9600, "", "", "full",
                      "Compact PLC; no auth", category="plc"),
    DefaultCredential("Omron", "NJ/NX Series", "HTTP", 80, "admin", "admin", "admin",
                      "Machine controller web", category="plc"),
    DefaultCredential("Omron", "NX1P2", "HTTP", 80, "admin", "", "admin",
                      "Compact machine controller", category="plc"),
    DefaultCredential("Omron", "NA Series HMI", "HTTP", 80, "admin", "", "admin",
                      "Programmable terminal", category="hmi"),
    DefaultCredential("Omron", "NS Series HMI", "HTTP", 80, "admin", "", "admin",
                      category="hmi"),
    DefaultCredential("Omron", "Sysmac Studio", "HTTP", 80, "", "", "full",
                      "Engineering workstation; no default auth on NJ/NX target", category="ews"),

    # ===================================================================
    # BECKHOFF
    # ===================================================================
    DefaultCredential("Beckhoff", "TwinCAT (ADS)", "ADS", 48898, "", "", "full",
                      "No ADS auth by default; direct PLC memory access", category="plc"),
    DefaultCredential("Beckhoff", "CX Series (Windows CE)", "HTTP", 80, "Administrator", "1",
                      "admin", "Windows CE Embedded", category="plc"),
    DefaultCredential("Beckhoff", "CX Series (Windows CE)", "Telnet", 23, "Administrator", "1",
                      "admin", category="plc"),
    DefaultCredential("Beckhoff", "CX Series (BSD/Linux)", "SSH", 22, "Administrator", "1",
                      "admin", category="plc"),
    DefaultCredential("Beckhoff", "C6015 IPC", "SSH", 22, "administrator", "1", "admin",
                      "Industrial PC", category="ews"),
    DefaultCredential("Beckhoff", "EK9000 Coupler", "HTTP", 80, "admin", "admin", "admin",
                      "EtherCAT bus coupler", category="gateway"),

    # ===================================================================
    # CODESYS (platform, multiple OEMs)
    # ===================================================================
    DefaultCredential("CODESYS", "Runtime V3", "HTTP", 8080, "admin", "", "admin",
                      "Web visualization; affects 500+ OEMs", category="plc"),
    DefaultCredential("CODESYS", "Runtime V3 Gateway", "TCP", 11740, "", "", "full",
                      "Gateway port; no auth", category="gateway"),
    DefaultCredential("CODESYS", "Runtime V2 (<2.4.7.57)", "TCP", 1200, "", "", "full",
                      "CVE-2022-31806; no auth on control port", "CVE-2022-31806",
                      category="plc"),
    DefaultCredential("CODESYS", "Runtime V3 Web (some OEMs)", "HTTP", 8080, "admin", "admin",
                      "admin", "OEM-specific default", category="plc"),

    # ===================================================================
    # WAGO
    # ===================================================================
    DefaultCredential("WAGO", "PFC200 (750-8212)", "HTTP", 80, "admin", "wago", "admin",
                      category="plc"),
    DefaultCredential("WAGO", "PFC200", "SSH", 22, "admin", "wago", "admin",
                      category="plc"),
    DefaultCredential("WAGO", "PFC100 (750-8101)", "HTTP", 80, "admin", "wago", "admin",
                      category="plc"),
    DefaultCredential("WAGO", "PFC100", "SSH", 22, "admin", "wago", "admin",
                      category="plc"),
    DefaultCredential("WAGO", "750-881 Ethernet Controller", "HTTP", 80, "admin", "wago", "admin",
                      "CVE-2019-5080; defaults restored on factory reset", "CVE-2019-5080",
                      category="plc"),
    DefaultCredential("WAGO", "750-352 Coupler", "HTTP", 80, "admin", "wago", "admin",
                      "Fieldbus coupler", category="gateway"),
    DefaultCredential("WAGO", "Touch Panel TP600", "HTTP", 80, "admin", "wago", "admin",
                      "HMI panel", category="hmi"),

    # ===================================================================
    # PHOENIX CONTACT
    # ===================================================================
    DefaultCredential("Phoenix Contact", "ILC 2050 BI", "HTTP", 80, "admin", "admin", "admin",
                      "Inline controller", category="plc"),
    DefaultCredential("Phoenix Contact", "AXC F 2152", "HTTP", 80, "admin", "", "admin",
                      "PLCnext controller", category="plc"),
    DefaultCredential("Phoenix Contact", "AXC F 2152", "SSH", 22, "admin", "", "admin",
                      "PLCnext SSH; empty password on first boot", category="plc"),
    DefaultCredential("Phoenix Contact", "AXC F 3152", "HTTPS", 443, "admin", "", "admin",
                      category="plc"),
    DefaultCredential("Phoenix Contact", "RFC 4072S", "HTTP", 80, "admin", "admin", "admin",
                      "Safety controller", category="plc"),
    DefaultCredential("Phoenix Contact", "FL SWITCH", "HTTP", 80, "admin", "admin", "admin",
                      "Industrial switch", category="switch"),
    DefaultCredential("Phoenix Contact", "FL SWITCH", "SSH", 22, "admin", "admin", "admin",
                      category="switch"),
    DefaultCredential("Phoenix Contact", "FL MGUARD", "HTTPS", 443, "admin", "admin", "admin",
                      "Industrial firewall/VPN", category="firewall_ot"),
    DefaultCredential("Phoenix Contact", "TC ROUTER", "HTTP", 80, "admin", "admin", "admin",
                      "Industrial 3G/4G router", category="router"),
    DefaultCredential("Phoenix Contact", "EEM-MA600", "HTTP", 80, "admin", "admin", "admin",
                      "Energy meter", "CVE-2016-8366", category="meter"),

    # ===================================================================
    # MOXA
    # ===================================================================
    DefaultCredential("Moxa", "NPort 5100/5200", "HTTP", 80, "admin", "", "admin",
                      "Serial device server", category="serial"),
    DefaultCredential("Moxa", "NPort 5100/5200", "Telnet", 23, "admin", "", "admin",
                      category="serial"),
    DefaultCredential("Moxa", "NPort 5100/5200", "SSH", 22, "admin", "", "admin",
                      category="serial"),
    DefaultCredential("Moxa", "NPort 5600", "HTTP", 80, "admin", "moxa", "admin",
                      "Rack serial server; hardening guide ref", category="serial"),
    DefaultCredential("Moxa", "NPort 5600", "SSH", 22, "admin", "moxa", "admin",
                      category="serial"),
    DefaultCredential("Moxa", "NPort 6000", "HTTPS", 443, "admin", "moxa", "admin",
                      "Secure serial server", category="serial"),
    DefaultCredential("Moxa", "EDS-408A/508A", "HTTP", 80, "admin", "", "admin",
                      "Industrial Ethernet switch", category="switch"),
    DefaultCredential("Moxa", "EDS-G4000 Series", "HTTP", 80, "admin", "moxa", "admin",
                      "Managed switch", category="switch"),
    DefaultCredential("Moxa", "IKS-G6824A", "HTTP", 80, "admin", "moxa", "admin",
                      "24-port managed switch", category="switch"),
    DefaultCredential("Moxa", "EDR-G903", "HTTPS", 443, "admin", "moxa", "admin",
                      "Industrial secure router", category="router"),
    DefaultCredential("Moxa", "EDR-810", "HTTPS", 443, "admin", "moxa", "admin",
                      "Firewall/VPN router", category="firewall_ot"),
    DefaultCredential("Moxa", "MGate 5105-MB-EIP", "HTTP", 80, "admin", "", "admin",
                      "Modbus/EtherNet/IP gateway", category="gateway"),
    DefaultCredential("Moxa", "MGate 5217", "HTTP", 80, "admin", "moxa", "admin",
                      "Protocol gateway", category="gateway"),
    DefaultCredential("Moxa", "ioLogik E1210", "HTTP", 80, "admin", "", "admin",
                      "Ethernet I/O", category="iiot"),
    DefaultCredential("Moxa", "ioLogik E2210", "HTTP", 80, "admin", "moxa", "admin",
                      category="iiot"),
    DefaultCredential("Moxa", "UC-8100", "SSH", 22, "moxa", "moxa", "admin",
                      "IIoT gateway/edge computer", category="gateway"),
    DefaultCredential("Moxa", "VPort 06EC-2V", "HTTP", 80, "admin", "", "admin",
                      "Industrial IP camera", category="camera"),
    DefaultCredential("Moxa", "AWK-3131A", "HTTP", 80, "admin", "moxa", "admin",
                      "Industrial wireless AP", category="switch"),

    # ===================================================================
    # ADVANTECH
    # ===================================================================
    DefaultCredential("Advantech", "WebAccess/SCADA", "HTTP", 8080, "admin", "", "admin",
                      "SCADA/HMI platform", category="scada"),
    DefaultCredential("Advantech", "ADAM-6000 Series", "HTTP", 80, "admin", "00000000", "admin",
                      "CVE-2008-5848; data acquisition module", "CVE-2008-5848", category="iiot"),
    DefaultCredential("Advantech", "ADAM-6000 Modbus", "Modbus", 502, "", "", "full",
                      "No Modbus auth", category="iiot"),
    DefaultCredential("Advantech", "WISE-4000 Series", "HTTP", 80, "admin", "admin", "admin",
                      "IoT wireless I/O", category="iiot"),
    DefaultCredential("Advantech", "EKI-1524 Serial", "HTTP", 80, "admin", "", "admin",
                      "Serial device server", category="serial"),
    DefaultCredential("Advantech", "EKI-7000 Switch", "HTTP", 80, "admin", "admin", "admin",
                      "Industrial managed switch", category="switch"),
    DefaultCredential("Advantech", "UNO-2484G IPC", "SSH", 22, "root", "root", "admin",
                      "Industrial PC / Edge", category="ews"),

    # ===================================================================
    # UNITRONICS
    # ===================================================================
    DefaultCredential("Unitronics", "Vision/Samba PLC", "PCOM", 20256, "admin", "1111", "admin",
                      "CVE-2023-6448; CISA advisory; Water/Wastewater targets",
                      "CVE-2023-6448", category="plc"),
    DefaultCredential("Unitronics", "Vision/Samba Web", "HTTP", 80, "admin", "1111", "admin",
                      "CVE-2023-6448", "CVE-2023-6448", category="plc"),
    DefaultCredential("Unitronics", "UniStream", "HTTP", 80, "admin", "admin", "admin",
                      "Next-gen PLC+HMI", category="plc"),
    DefaultCredential("Unitronics", "UniStream SSH", "SSH", 22, "root", "root", "admin",
                      "Linux-based OS", category="plc"),

    # ===================================================================
    # DELTA ELECTRONICS
    # ===================================================================
    DefaultCredential("Delta", "DVP Series PLC", "Modbus", 502, "", "", "full",
                      "No Modbus auth", category="plc"),
    DefaultCredential("Delta", "DOP Series HMI", "HTTP", 80, "admin", "admin", "admin",
                      category="hmi"),
    DefaultCredential("Delta", "AS Series PLC", "Modbus", 502, "", "", "full",
                      category="plc"),
    DefaultCredential("Delta", "AS Series Web", "HTTP", 80, "admin", "admin", "admin",
                      category="plc"),
    DefaultCredential("Delta", "InfraSuite Device Master", "HTTP", 80, "admin", "admin", "admin",
                      "Device management; CVE-2023-1133 series", category="scada"),
    DefaultCredential("Delta", "CNCSoft-G2 HMI", "HTTP", 80, "admin", "admin", "admin",
                      category="hmi"),

    # ===================================================================
    # PILZ
    # ===================================================================
    DefaultCredential("Pilz", "PSS 4000 (PSSuniversal PLC)", "HTTP", 80, "admin", "admin",
                      "admin", "Safety PLC", category="plc"),
    DefaultCredential("Pilz", "PMCprimo", "HTTP", 80, "admin", "admin", "admin",
                      "Motion controller", category="plc"),
    DefaultCredential("Pilz", "SecurityBridge", "HTTPS", 443, "admin", "admin", "admin",
                      "OT firewall", category="firewall_ot"),
    DefaultCredential("Pilz", "PITreader", "HTTP", 80, "admin", "admin", "admin",
                      "RFID access system", category="iiot"),

    # ===================================================================
    # TRIDIUM (Honeywell/Tridium Niagara)
    # ===================================================================
    DefaultCredential("Tridium", "Niagara AX", "HTTPS", 443, "admin", "admin", "admin",
                      "Building automation framework", category="bms"),
    DefaultCredential("Tridium", "Niagara 4 (N4)", "HTTPS", 443, "admin", "admin", "admin",
                      category="bms"),
    DefaultCredential("Tridium", "JACE 8000", "HTTPS", 443, "admin", "admin", "admin",
                      "Java Application Control Engine", category="bms"),
    DefaultCredential("Tridium", "JACE 8000 SSH", "SSH", 22, "admin", "admin", "admin",
                      category="bms"),

    # ===================================================================
    # LANTRONIX
    # ===================================================================
    DefaultCredential("Lantronix", "XPort", "Telnet", 9999, "", "", "admin",
                      "Serial-to-Ethernet; no password", category="serial"),
    DefaultCredential("Lantronix", "XPort", "HTTP", 80, "", "", "admin",
                      "No default credentials", category="serial"),
    DefaultCredential("Lantronix", "UDS1100", "HTTP", 80, "admin", "PASS", "admin",
                      "Device server", category="serial"),
    DefaultCredential("Lantronix", "UDS1100", "Telnet", 9999, "", "PASS", "admin",
                      category="serial"),
    DefaultCredential("Lantronix", "EDS-MD", "HTTP", 80, "admin", "admin", "admin",
                      "Medical device server", category="serial"),
    DefaultCredential("Lantronix", "SLC8000", "SSH", 22, "sysadmin", "PASS", "admin",
                      "Console manager", category="serial"),

    # ===================================================================
    # HMS NETWORKS / EWON / ANYBUS
    # ===================================================================
    DefaultCredential("HMS/eWON", "eWON Flexy", "HTTPS", 443, "adm", "adm", "admin",
                      "Industrial VPN router", category="gateway"),
    DefaultCredential("HMS/eWON", "eWON Flexy", "SSH", 22, "adm", "adm", "admin",
                      category="gateway"),
    DefaultCredential("HMS/eWON", "eWON Cosy", "HTTPS", 443, "adm", "adm", "admin",
                      "Remote access VPN", category="gateway"),
    DefaultCredential("HMS/eWON", "Anybus CompactCom", "HTTP", 80, "admin", "admin", "admin",
                      "Communication module", category="gateway"),
    DefaultCredential("HMS/eWON", "Anybus X-gateway", "HTTP", 80, "admin", "admin", "admin",
                      "Protocol converter", category="gateway"),

    # ===================================================================
    # HIRSCHMANN (Belden)
    # ===================================================================
    DefaultCredential("Hirschmann", "MACH Series Switch", "HTTP", 80, "admin", "private", "admin",
                      "Industrial switch", category="switch"),
    DefaultCredential("Hirschmann", "MACH Series Switch", "SSH", 22, "admin", "private", "admin",
                      category="switch"),
    DefaultCredential("Hirschmann", "RSP/RSPS", "HTTP", 80, "admin", "private", "admin",
                      "Rail switch", category="switch"),
    DefaultCredential("Hirschmann", "EAGLE Firewall", "HTTPS", 443, "admin", "private", "admin",
                      "Industrial firewall", category="firewall_ot"),
    DefaultCredential("Hirschmann", "OpenBAT WLAN", "HTTP", 80, "admin", "private", "admin",
                      "Industrial wireless", category="switch"),

    # ===================================================================
    # SEL (Schweitzer Engineering Laboratories)
    # ===================================================================
    DefaultCredential("SEL", "SEL-2740S Switch", "SSH", 22, "admin", "TAIL", "admin",
                      "Software-Defined Networking switch", category="switch"),
    DefaultCredential("SEL", "SEL-2740S", "HTTPS", 443, "admin", "TAIL", "admin",
                      category="switch"),
    DefaultCredential("SEL", "SEL-3530 RTAC", "SSH", 22, "admin", "TAIL", "admin",
                      "Real-time automation controller", category="rtu"),
    DefaultCredential("SEL", "SEL-3530 RTAC", "HTTPS", 443, "admin", "TAIL", "admin",
                      category="rtu"),
    DefaultCredential("SEL", "SEL-351/SEL-421 Relay", "Serial", 0, "2AC", "2AC", "engineer",
                      "Protection relay; Level 2 password", category="relay"),
    DefaultCredential("SEL", "SEL-751 Relay", "HTTP", 80, "admin", "TAIL", "admin",
                      "Feeder protection", category="relay"),

    # ===================================================================
    # BOSCH REXROTH
    # ===================================================================
    DefaultCredential("Bosch Rexroth", "ctrlX CORE", "HTTPS", 443, "boschrexroth", "boschrexroth",
                      "admin", "Automation platform", category="plc"),
    DefaultCredential("Bosch Rexroth", "IndraControl XM", "HTTP", 80, "admin", "admin", "admin",
                      "Motion controller", category="plc"),
    DefaultCredential("Bosch Rexroth", "IndraMotion MLC", "HTTP", 80, "admin", "admin", "admin",
                      category="plc"),
    DefaultCredential("Bosch Rexroth", "IndraWorks", "HTTP", 80, "admin", "admin", "admin",
                      "Engineering environment", category="ews"),

    # ===================================================================
    # FANUC
    # ===================================================================
    DefaultCredential("FANUC", "R-30iB Controller", "HTTP", 80, "admin", "", "admin",
                      "Robot controller (iRVision)", category="robot"),
    DefaultCredential("FANUC", "R-30iB Plus", "HTTP", 80, "admin", "", "admin",
                      category="robot"),
    DefaultCredential("FANUC", "0i-TF CNC", "HTTP", 80, "admin", "", "admin",
                      "CNC controller", category="plc"),
    DefaultCredential("FANUC", "ROBOGUIDE", "HTTP", 80, "", "", "read",
                      "Simulation software", category="ews"),

    # ===================================================================
    # KUKA
    # ===================================================================
    DefaultCredential("KUKA", "KR C4 Controller", "HTTP", 80, "admin", "", "admin",
                      "Robot controller", category="robot"),
    DefaultCredential("KUKA", "KR C4 VNC", "VNC", 5900, "", "kuka", "view",
                      "VNC access to smartPAD", category="robot"),
    DefaultCredential("KUKA", "Sunrise Controller", "HTTP", 80, "admin", "admin", "admin",
                      "LBR iiwa collaborative robot", category="robot"),

    # ===================================================================
    # CISCO (ICS-specific appliances)
    # ===================================================================
    DefaultCredential("Cisco", "IE 2000/3000 Switch", "SSH", 22, "cisco", "cisco", "admin",
                      "Industrial Ethernet switch", category="switch"),
    DefaultCredential("Cisco", "IE 2000/3000 Switch", "HTTP", 80, "cisco", "cisco", "admin",
                      category="switch"),
    DefaultCredential("Cisco", "IE 4000/5000 Switch", "SSH", 22, "cisco", "cisco", "admin",
                      category="switch"),
    DefaultCredential("Cisco", "IC3000 Gateway", "SSH", 22, "admin", "admin", "admin",
                      "Industrial compute gateway", category="gateway"),
    DefaultCredential("Cisco", "IR829/IR1101 Router", "SSH", 22, "cisco", "cisco", "admin",
                      "Industrial router", category="router"),

    # ===================================================================
    # RUGGEDCOM (Siemens subsidiary, separate product line)
    # ===================================================================
    DefaultCredential("Ruggedcom", "RX1500/RX5000 Router", "SSH", 22, "admin", "admin", "admin",
                      category="router"),
    DefaultCredential("Ruggedcom", "RS900 Switch", "HTTP", 80, "admin", "admin", "admin",
                      "Ruggedized switch", category="switch"),
    DefaultCredential("Ruggedcom", "ROX II", "SSH", 22, "admin", "admin", "admin",
                      category="router"),

    # ===================================================================
    # WIND RIVER / VxWorks
    # ===================================================================
    DefaultCredential("Wind River", "VxWorks (generic)", "Telnet", 23, "admin", "admin", "admin",
                      "RTOS; varies by OEM", category="plc"),
    DefaultCredential("Wind River", "VxWorks Debug", "WDB", 17185, "", "", "full",
                      "WDB debug agent; remote code exec if enabled", category="plc"),

    # ===================================================================
    # DIGI INTERNATIONAL
    # ===================================================================
    DefaultCredential("Digi", "TransPort WR Series", "HTTP", 80, "admin", "admin", "admin",
                      "Cellular router", category="router"),
    DefaultCredential("Digi", "TransPort WR Series", "SSH", 22, "admin", "admin", "admin",
                      category="router"),
    DefaultCredential("Digi", "Connect ME/SP", "Telnet", 23, "root", "dbps", "admin",
                      "Embedded device server", category="serial"),
    DefaultCredential("Digi", "PortServer TS", "Telnet", 23, "root", "dbps", "admin",
                      "Terminal server", category="serial"),
    DefaultCredential("Digi", "IX20 Router", "SSH", 22, "admin", "admin", "admin",
                      "Industrial router", category="router"),

    # ===================================================================
    # OSISOFT / AVEVA (Historian)
    # ===================================================================
    DefaultCredential("OSIsoft", "PI Server", "PI API", 5450, "piadmin", "", "admin",
                      "PI Data Archive; no password", category="historian"),
    DefaultCredential("OSIsoft", "PI Server", "PI API", 5450, "piworld", "piworld", "read",
                      "Read-only demo user", category="historian"),
    DefaultCredential("OSIsoft", "PI Web API", "HTTPS", 443, "admin", "", "admin",
                      category="historian"),
    DefaultCredential("AVEVA", "InTouch HMI", "HTTP", 80, "admin", "admin", "admin",
                      "Wonderware InTouch", category="hmi"),
    DefaultCredential("AVEVA", "System Platform", "HTTP", 80, "admin", "admin", "admin",
                      "Wonderware", category="scada"),
    DefaultCredential("AVEVA", "Historian", "HTTPS", 443, "admin", "admin", "admin",
                      "Wonderware Historian", category="historian"),

    # ===================================================================
    # INDUCTIVE AUTOMATION (Ignition)
    # ===================================================================
    DefaultCredential("Inductive Automation", "Ignition SCADA", "HTTPS", 8088, "admin", "password",
                      "admin", "Default during initial setup", category="scada"),
    DefaultCredential("Inductive Automation", "Ignition Gateway", "HTTPS", 8043, "admin", "password",
                      "admin", "Gateway commissioning", category="gateway"),

    # ===================================================================
    # ICONICS
    # ===================================================================
    DefaultCredential("ICONICS", "GENESIS64", "HTTP", 80, "admin", "admin", "admin",
                      "SCADA/BMS platform", category="scada"),
    DefaultCredential("ICONICS", "Hyper Historian", "HTTP", 80, "admin", "admin", "admin",
                      category="historian"),

    # ===================================================================
    # VARIOUS OT VENDORS (smaller/niche)
    # ===================================================================
    # LS Electric (formerly LG Industrial Systems)
    DefaultCredential("LS Electric", "XGK PLC", "HTTP", 80, "admin", "admin", "admin",
                      category="plc"),
    DefaultCredential("LS Electric", "XGT Panel", "HTTP", 80, "admin", "admin", "admin",
                      category="hmi"),

    # JTEKT (Toyoda)
    DefaultCredential("JTEKT", "TOYOPUC Series", "HTTP", 80, "admin", "admin", "admin",
                      "Machine control PLC", category="plc"),

    # Hitachi
    DefaultCredential("Hitachi", "MACH Controller", "HTTP", 80, "admin", "admin", "admin",
                      category="plc"),
    DefaultCredential("Hitachi", "Ops Center OT", "HTTPS", 443, "admin", "admin", "admin",
                      "SCADA platform", category="scada"),

    # Hollysys
    DefaultCredential("Hollysys", "LK Series PLC", "HTTP", 80, "admin", "admin", "admin",
                      "Chinese industrial PLC", category="plc"),
    DefaultCredential("Hollysys", "MACS DCS", "HTTP", 80, "admin", "admin", "admin",
                      "DCS platform", category="dcs"),

    # WEG
    DefaultCredential("WEG", "CFW500 Drive", "HTTP", 80, "admin", "admin", "admin",
                      "Variable frequency drive", category="drive"),
    DefaultCredential("WEG", "Motor Scan", "HTTP", 80, "admin", "admin", "admin",
                      "IoT motor monitor", category="iiot"),

    # Grundfos
    DefaultCredential("Grundfos", "CIM Module", "HTTP", 80, "admin", "admin", "admin",
                      "Pump communication module", category="iiot"),
    DefaultCredential("Grundfos", "CUE Drive", "HTTP", 80, "admin", "admin", "admin",
                      category="drive"),

    # SICK AG
    DefaultCredential("SICK", "FX0/FLX Series", "HTTP", 80, "admin", "admin", "admin",
                      "Safety controller", category="plc"),
    DefaultCredential("SICK", "Inspector Sensor", "HTTP", 80, "admin", "admin", "admin",
                      "Vision sensor", category="iiot"),

    # ProSoft Technology
    DefaultCredential("ProSoft", "PLX31 Gateway", "HTTP", 80, "admin", "admin", "admin",
                      "Protocol gateway for Rockwell", category="gateway"),
    DefaultCredential("ProSoft", "ICX35 Gateway", "HTTP", 80, "admin", "admin", "admin",
                      category="gateway"),

    # PTC/Kepware
    DefaultCredential("PTC", "Kepware KEPServerEX", "HTTP", 80, "Administrator", "", "admin",
                      "OPC UA/DA server", category="gateway"),

    # Dassault Systemes
    DefaultCredential("Dassault", "DelmiaWorks", "HTTP", 80, "admin", "admin", "admin",
                      "MES/MOM system", category="scada"),

    # FATEK
    DefaultCredential("FATEK", "FBs Series PLC", "Modbus", 502, "", "", "full",
                      "Taiwanese PLC; no Modbus auth", category="plc"),
    DefaultCredential("FATEK", "FBs Series Web", "HTTP", 80, "admin", "admin", "admin",
                      category="plc"),

    # Fuji Electric
    DefaultCredential("Fuji Electric", "SPB Controller", "HTTP", 80, "admin", "admin", "admin",
                      category="plc"),
    DefaultCredential("Fuji Electric", "FRENIC Drive", "HTTP", 80, "admin", "admin", "admin",
                      "Variable frequency drive", category="drive"),

    # Motorola Solutions (SCADA radios)
    DefaultCredential("Motorola Solutions", "ACE3600 RTU", "HTTP", 80, "admin", "admin", "admin",
                      "SCADA RTU", category="rtu"),
    DefaultCredential("Motorola Solutions", "MOSCAD RTU", "Telnet", 23, "admin", "admin", "admin",
                      category="rtu"),

    # Krohne
    DefaultCredential("Krohne", "OPTIFLUX Flowmeter", "HTTP", 80, "admin", "admin", "admin",
                      "Process instrumentation", category="iiot"),

    # Altus (Brazilian vendor)
    DefaultCredential("Altus", "DUO PLC", "HTTP", 80, "admin", "admin", "admin",
                      "Brazilian industrial PLC", category="plc"),
    DefaultCredential("Altus", "Nexto PLC", "HTTP", 80, "admin", "admin", "admin",
                      category="plc"),

    # Endress+Hauser
    DefaultCredential("Endress+Hauser", "Memograph M RSG45", "HTTP", 80, "admin", "admin", "admin",
                      "Graphic data manager", category="iiot"),
    DefaultCredential("Endress+Hauser", "Netilion", "HTTPS", 443, "admin", "admin", "admin",
                      "IIoT cloud edge", category="iiot"),

    # Pepperl+Fuchs
    DefaultCredential("Pepperl+Fuchs", "FieldConnex", "HTTP", 80, "admin", "admin", "admin",
                      "Fieldbus infrastructure", category="gateway"),

    # Turck
    DefaultCredential("Turck", "TX500 Gateway", "HTTP", 80, "admin", "admin", "admin",
                      "Multiprotocol gateway", category="gateway"),
    DefaultCredential("Turck", "TBEN-S Module", "HTTP", 80, "admin", "admin", "admin",
                      "Compact I/O module", category="iiot"),

    # ===================================================================
    # SNMP DEFAULT COMMUNITIES (OT devices)
    # ===================================================================
    DefaultCredential("(SNMP)", "Generic OT Device (RO)", "SNMP", 161, "public", "", "read",
                      "Default SNMP v1/v2c read-only community", category="snmp"),
    DefaultCredential("(SNMP)", "Generic OT Device (RW)", "SNMP", 161, "private", "", "write",
                      "Default SNMP v1/v2c read-write community", category="snmp"),
    DefaultCredential("(SNMP)", "Rockwell Undocumented RW", "SNMP", 161, "wheel", "", "write",
                      "Undocumented hardcoded RW community on Rockwell PLCs", category="snmp"),
    DefaultCredential("(SNMP)", "Siemens SCALANCE", "SNMP", 161, "public", "", "read",
                      "Default on SCALANCE switches", category="snmp"),
    DefaultCredential("(SNMP)", "Moxa EDS", "SNMP", 161, "public", "", "read",
                      category="snmp"),
    DefaultCredential("(SNMP)", "Generic Trap Target", "SNMP", 162, "public", "", "trap",
                      "Default trap community", category="snmp"),
    DefaultCredential("(SNMP)", "Legacy OT Printer/UPS", "SNMP", 161, "internal", "", "read",
                      "Common alternative community", category="snmp"),
    DefaultCredential("(SNMP)", "Network Equipment", "SNMP", 161, "cable-docsis", "", "read",
                      category="snmp"),
    DefaultCredential("(SNMP)", "Cisco IOS Devices", "SNMP", 161, "ILMI", "", "read",
                      "ATM ILMI community", category="snmp"),

    # ===================================================================
    # PROTOCOL-SPECIFIC (no authentication by design)
    # ===================================================================
    DefaultCredential("(Protocol)", "Modbus TCP", "Modbus", 502, "", "", "full",
                      "No auth in protocol spec; any node can R/W", category="protocol"),
    DefaultCredential("(Protocol)", "Modbus RTU (Serial)", "Modbus", 0, "", "", "full",
                      "Serial bus; broadcast addressing", category="protocol"),
    DefaultCredential("(Protocol)", "S7comm", "S7comm", 102, "", "", "full",
                      "No auth in standard mode; PLC memory R/W", category="protocol"),
    DefaultCredential("(Protocol)", "S7comm Plus", "S7comm+", 102, "", "", "varies",
                      "S7-1500; password protection optional, off by default", category="protocol"),
    DefaultCredential("(Protocol)", "BACnet/IP", "BACnet", 47808, "", "", "full",
                      "No auth; R/W any object property", category="protocol"),
    DefaultCredential("(Protocol)", "BACnet MS/TP", "BACnet", 0, "", "", "full",
                      "Serial bus; no authentication", category="protocol"),
    DefaultCredential("(Protocol)", "EtherNet/IP CIP", "CIP", 44818, "", "", "full",
                      "No implicit message auth", category="protocol"),
    DefaultCredential("(Protocol)", "DNP3 (pre-SA)", "DNP3", 20000, "", "", "full",
                      "Pre-Secure Authentication has no auth; inject commands", category="protocol"),
    DefaultCredential("(Protocol)", "IEC 60870-5-104", "IEC104", 2404, "", "", "full",
                      "No auth; STARTDT accepted; telecontrol", category="protocol"),
    DefaultCredential("(Protocol)", "IEC 61850 MMS", "MMS", 102, "", "", "full",
                      "Manufacturing Message Specification; substation automation",
                      category="protocol"),
    DefaultCredential("(Protocol)", "IEC 61850 GOOSE", "GOOSE", 0, "", "", "full",
                      "Multicast L2; no authentication", category="protocol"),
    DefaultCredential("(Protocol)", "OPC DA/Classic", "DCOM", 135, "", "", "varies",
                      "DCOM-based; often misconfigured", category="protocol"),
    DefaultCredential("(Protocol)", "OPC UA (anonymous)", "OPC-UA", 4840, "", "", "read",
                      "Anonymous access often left enabled", category="protocol"),
    DefaultCredential("(Protocol)", "PROFINET IO", "PROFINET", 34964, "", "", "full",
                      "No auth on IO data exchange", category="protocol"),
    DefaultCredential("(Protocol)", "PROFIBUS DP", "PROFIBUS", 0, "", "", "full",
                      "Serial fieldbus; no authentication", category="protocol"),
    DefaultCredential("(Protocol)", "FINS (Omron)", "FINS", 9600, "", "", "full",
                      "No auth on FINS commands", category="protocol"),
    DefaultCredential("(Protocol)", "MELSEC (Mitsubishi)", "MELSEC", 5007, "", "", "full",
                      "No auth on binary protocol", category="protocol"),
    DefaultCredential("(Protocol)", "ADS (Beckhoff)", "ADS", 48898, "", "", "full",
                      "No auth; direct PLC memory access", category="protocol"),
    DefaultCredential("(Protocol)", "MQTT (unauth)", "MQTT", 1883, "", "", "varies",
                      "Often deployed without auth in OT", category="protocol"),
    DefaultCredential("(Protocol)", "CoAP", "CoAP", 5683, "", "", "varies",
                      "UDP REST-like; often no auth", category="protocol"),
    DefaultCredential("(Protocol)", "GE SRTP", "SRTP", 18245, "", "", "full",
                      "Service Request Transfer Protocol; no auth", category="protocol"),
    DefaultCredential("(Protocol)", "TriStation (Schneider)", "TriStation", 1502, "", "", "full",
                      "Safety controller protocol; no auth", category="protocol"),
    DefaultCredential("(Protocol)", "PCCC (AB DF1)", "PCCC", 2222, "", "", "full",
                      "Allen-Bradley DF1/PCCC; no auth", category="protocol"),
    DefaultCredential("(Protocol)", "CC-Link IE Field", "CC-Link", 61450, "", "", "full",
                      "No auth on fieldbus", category="protocol"),
    DefaultCredential("(Protocol)", "EtherCAT", "EtherCAT", 0, "", "", "full",
                      "Layer 2; no authentication", category="protocol"),
    DefaultCredential("(Protocol)", "HART-IP", "HART-IP", 5094, "", "", "full",
                      "Process field instruments; no auth", category="protocol"),
    DefaultCredential("(Protocol)", "SECS/GEM (HSMS)", "HSMS", 5000, "", "", "full",
                      "Semiconductor equipment; minimal auth", category="protocol"),
    DefaultCredential("(Protocol)", "CANopen", "CANopen", 0, "", "", "full",
                      "CAN bus; no authentication", category="protocol"),
    DefaultCredential("(Protocol)", "DeviceNet", "DeviceNet", 0, "", "", "full",
                      "CAN-based fieldbus; no auth", category="protocol"),

    # ===================================================================
    # MIRAI BOTNET WORDLIST (from scanner.c source code)
    # Targets: IP cameras, DVRs, routers, NAS, IoT devices in OT networks
    # Source: SecLists/Passwords/Malware/mirai-botnet.txt (61 unique pairs)
    # ===================================================================
    DefaultCredential("(Mirai)", "root:xc3511", "Telnet", 23, "root", "xc3511", "admin",
                      "Mirai; Xiongmai/HiSilicon IP cameras", category="botnet"),
    DefaultCredential("(Mirai)", "root:vizxv", "Telnet", 23, "root", "vizxv", "admin",
                      "Mirai; Dahua DVR", category="botnet"),
    DefaultCredential("(Mirai)", "root:admin", "Telnet", 23, "root", "admin", "admin",
                      "Mirai; multiple vendors", category="botnet"),
    DefaultCredential("(Mirai)", "admin:admin", "Telnet", 23, "admin", "admin", "admin",
                      "Mirai; generic default", category="botnet"),
    DefaultCredential("(Mirai)", "root:888888", "Telnet", 23, "root", "888888", "admin",
                      "Mirai; Dahua cameras", category="botnet"),
    DefaultCredential("(Mirai)", "root:xmhdipc", "Telnet", 23, "root", "xmhdipc", "admin",
                      "Mirai; Xiongmai NVR/DVR", category="botnet"),
    DefaultCredential("(Mirai)", "root:default", "Telnet", 23, "root", "default", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "root:juantech", "Telnet", 23, "root", "juantech", "admin",
                      "Mirai; Guangzhou Juan Optical", category="botnet"),
    DefaultCredential("(Mirai)", "root:123456", "Telnet", 23, "root", "123456", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "root:54321", "Telnet", 23, "root", "54321", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "support:support", "Telnet", 23, "support", "support", "admin",
                      "Mirai; ZyXEL routers", category="botnet"),
    DefaultCredential("(Mirai)", "root:(empty)", "Telnet", 23, "root", "", "admin",
                      "Mirai; multiple embedded devices", category="botnet"),
    DefaultCredential("(Mirai)", "admin:password", "Telnet", 23, "admin", "password", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "root:root", "Telnet", 23, "root", "root", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "root:12345", "Telnet", 23, "root", "12345", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "user:user", "Telnet", 23, "user", "user", "user",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "admin:(empty)", "Telnet", 23, "admin", "", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "root:pass", "Telnet", 23, "root", "pass", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "admin:admin1234", "Telnet", 23, "admin", "admin1234", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "root:1111", "Telnet", 23, "root", "1111", "admin",
                      "Mirai; Unitronics PLCs also", category="botnet"),
    DefaultCredential("(Mirai)", "admin:smcadmin", "Telnet", 23, "admin", "smcadmin", "admin",
                      "Mirai; SMC routers", category="botnet"),
    DefaultCredential("(Mirai)", "admin:1111", "Telnet", 23, "admin", "1111", "admin",
                      "Mirai; generic / Unitronics", category="botnet"),
    DefaultCredential("(Mirai)", "root:666666", "Telnet", 23, "root", "666666", "admin",
                      "Mirai; Dahua cameras", category="botnet"),
    DefaultCredential("(Mirai)", "root:password", "Telnet", 23, "root", "password", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "root:1234", "Telnet", 23, "root", "1234", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "root:klv123", "Telnet", 23, "root", "klv123", "admin",
                      "Mirai; HiSilicon devices", category="botnet"),
    DefaultCredential("(Mirai)", "Administrator:admin", "Telnet", 23, "Administrator", "admin",
                      "admin", "Mirai; Windows CE/embedded", category="botnet"),
    DefaultCredential("(Mirai)", "service:service", "Telnet", 23, "service", "service", "service",
                      "Mirai; generic service account", category="botnet"),
    DefaultCredential("(Mirai)", "supervisor:supervisor", "Telnet", 23, "supervisor", "supervisor",
                      "admin", "Mirai; generic supervisor", category="botnet"),
    DefaultCredential("(Mirai)", "guest:guest", "Telnet", 23, "guest", "guest", "guest",
                      "Mirai; generic guest", category="botnet"),
    DefaultCredential("(Mirai)", "guest:12345", "Telnet", 23, "guest", "12345", "guest",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "admin1:password", "Telnet", 23, "admin1", "password", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "administrator:1234", "Telnet", 23, "administrator", "1234",
                      "admin", "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "666666:666666", "Telnet", 23, "666666", "666666", "admin",
                      "Mirai; Dahua IP cameras", category="botnet"),
    DefaultCredential("(Mirai)", "888888:888888", "Telnet", 23, "888888", "888888", "admin",
                      "Mirai; Dahua cameras", category="botnet"),
    DefaultCredential("(Mirai)", "ubnt:ubnt", "Telnet", 23, "ubnt", "ubnt", "admin",
                      "Mirai; Ubiquiti devices", category="botnet"),
    DefaultCredential("(Mirai)", "root:klv1234", "Telnet", 23, "root", "klv1234", "admin",
                      "Mirai; HiSilicon DVR", category="botnet"),
    DefaultCredential("(Mirai)", "root:Zte521", "Telnet", 23, "root", "Zte521", "admin",
                      "Mirai; ZTE routers", category="botnet"),
    DefaultCredential("(Mirai)", "root:hi3518", "Telnet", 23, "root", "hi3518", "admin",
                      "Mirai; HiSilicon Hi3518 SoC cameras", category="botnet"),
    DefaultCredential("(Mirai)", "root:jvbzd", "Telnet", 23, "root", "jvbzd", "admin",
                      "Mirai; HiSilicon NVR", category="botnet"),
    DefaultCredential("(Mirai)", "root:anko", "Telnet", 23, "root", "anko", "admin",
                      "Mirai; Anko IP cameras", category="botnet"),
    DefaultCredential("(Mirai)", "root:zlxx.", "Telnet", 23, "root", "zlxx.", "admin",
                      "Mirai; Chinese IP cameras", category="botnet"),
    DefaultCredential("(Mirai)", "root:7ujMko0vizxv", "Telnet", 23, "root", "7ujMko0vizxv",
                      "admin", "Mirai; Dahua cameras (variant)", category="botnet"),
    DefaultCredential("(Mirai)", "root:7ujMko0admin", "Telnet", 23, "root", "7ujMko0admin",
                      "admin", "Mirai; Dahua cameras (variant)", category="botnet"),
    DefaultCredential("(Mirai)", "root:system", "Telnet", 23, "root", "system", "admin",
                      "Mirai; IPC/NVR systems", category="botnet"),
    DefaultCredential("(Mirai)", "root:ikwb", "Telnet", 23, "root", "ikwb", "admin",
                      "Mirai; Toshiba IP cameras", category="botnet"),
    DefaultCredential("(Mirai)", "root:dreambox", "Telnet", 23, "root", "dreambox", "admin",
                      "Mirai; Dreambox receivers", category="botnet"),
    DefaultCredential("(Mirai)", "root:user", "Telnet", 23, "root", "user", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "root:realtek", "Telnet", 23, "root", "realtek", "admin",
                      "Mirai; Realtek SDK based devices", category="botnet"),
    DefaultCredential("(Mirai)", "root:00000000", "Telnet", 23, "root", "00000000", "admin",
                      "Mirai; generic / Advantech ADAM", category="botnet"),
    DefaultCredential("(Mirai)", "admin:1111111", "Telnet", 23, "admin", "1111111", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "admin:1234", "Telnet", 23, "admin", "1234", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "admin:12345", "Telnet", 23, "admin", "12345", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "admin:54321", "Telnet", 23, "admin", "54321", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "admin:123456", "Telnet", 23, "admin", "123456", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "admin:7ujMko0admin", "Telnet", 23, "admin", "7ujMko0admin",
                      "admin", "Mirai; Dahua admin", category="botnet"),
    DefaultCredential("(Mirai)", "admin:pass", "Telnet", 23, "admin", "pass", "admin",
                      "Mirai; generic", category="botnet"),
    DefaultCredential("(Mirai)", "admin:meinsm", "Telnet", 23, "admin", "meinsm", "admin",
                      "Mirai; Mobotix cameras", category="botnet"),
    DefaultCredential("(Mirai)", "tech:tech", "Telnet", 23, "tech", "tech", "admin",
                      "Mirai; Sagem routers", category="botnet"),
    DefaultCredential("(Mirai)", "mother:fucker", "Telnet", 23, "mother", "fucker", "admin",
                      "Mirai; ZTE routers (variant)", category="botnet"),
]


# ---------------------------------------------------------------------------
# Search / query functions
# ---------------------------------------------------------------------------

def search_by_vendor(vendor: str) -> list[DefaultCredential]:
    """Find credentials by vendor name (case-insensitive partial match)."""
    v = vendor.lower()
    return [c for c in CREDENTIAL_DB if v in c.vendor.lower()]


def search_by_product(product: str) -> list[DefaultCredential]:
    """Find credentials by product name (case-insensitive partial match)."""
    p = product.lower()
    return [c for c in CREDENTIAL_DB if p in c.product.lower()]


def search_by_protocol(protocol: str) -> list[DefaultCredential]:
    """Find credentials by protocol (case-insensitive partial match)."""
    p = protocol.lower()
    return [c for c in CREDENTIAL_DB if p in c.protocol.lower()]


def search_by_port(port: int) -> list[DefaultCredential]:
    """Find credentials by port number."""
    return [c for c in CREDENTIAL_DB if c.port == port]


def search_by_category(category: str) -> list[DefaultCredential]:
    """Find credentials by device category (plc, rtu, hmi, switch, etc.)."""
    cat = category.lower()
    return [c for c in CREDENTIAL_DB if cat in c.category.lower()]


def search_by_cve(cve_id: str) -> list[DefaultCredential]:
    """Find credentials associated with a specific CVE."""
    cve = cve_id.upper()
    return [c for c in CREDENTIAL_DB if cve in c.cve.upper()]


def get_all_vendors() -> list[str]:
    """Return sorted list of unique vendors."""
    return sorted(set(c.vendor for c in CREDENTIAL_DB))


def get_all_categories() -> list[str]:
    """Return sorted list of unique categories."""
    return sorted(set(c.category for c in CREDENTIAL_DB if c.category))


def get_mirai_wordlist() -> list[tuple[str, str]]:
    """Return the Mirai botnet credential pairs as (username, password) tuples."""
    return [(c.username, c.password) for c in CREDENTIAL_DB
            if c.vendor == "(Mirai)"]


def get_snmp_communities() -> list[str]:
    """Return all SNMP community strings from the database."""
    return [c.username for c in CREDENTIAL_DB
            if c.protocol == "SNMP" and c.username]


def get_stats() -> dict[str, int]:
    """Return database statistics."""
    vendors = set(c.vendor for c in CREDENTIAL_DB
                  if not c.vendor.startswith("("))
    return {
        "total_entries": len(CREDENTIAL_DB),
        "unique_vendors": len(vendors),
        "unique_products": len(set(c.product for c in CREDENTIAL_DB)),
        "protocols_with_no_auth": sum(1 for c in CREDENTIAL_DB
                                      if c.vendor == "(Protocol)"),
        "mirai_pairs": sum(1 for c in CREDENTIAL_DB
                           if c.vendor == "(Mirai)"),
        "snmp_communities": sum(1 for c in CREDENTIAL_DB
                                if c.category == "snmp"),
        "entries_with_cve": sum(1 for c in CREDENTIAL_DB if c.cve),
    }


def export_csv() -> str:
    """Export the credential database as CSV string."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Vendor", "Product", "Protocol", "Port",
                     "Username", "Password", "Access Level", "Notes",
                     "CVE", "Category"])
    for c in CREDENTIAL_DB:
        writer.writerow([c.vendor, c.product, c.protocol, c.port,
                         c.username, c.password, c.access_level, c.notes,
                         c.cve, c.category])
    return out.getvalue()


# ---------------------------------------------------------------------------
# Exploit module interface
# ---------------------------------------------------------------------------

class SCADAPassDB(Exploit):
    """ICS/SCADA default credential database lookup."""

    __info__ = {
        "name": "SCADAPASS DB",
        "description": (
            "Default credential database for ICS/SCADA/OT devices, protocols, "
            "SNMP communities, and IoT botnet wordlists (Mirai). "
            "Covers 60+ manufacturers, 30+ protocols, and 350+ credential entries."
        ),
        "authors": ["Andre Henrique (@mrhenrike)"],
        "references": [
            "CISA ICS-CERT Alert TA17-156A",
            "ICS-CERT Advisory ICSA-15-258-01",
            "SCADAPASS project (SCADA StrangeLove)",
            "CVE-2023-6448 (Unitronics Vision/Samba)",
            "CVE-2022-31806 (CODESYS V2 no auth)",
            "CVE-2022-30314 (Honeywell Safety Manager hardcoded)",
            "CVE-2013-0694 (Emerson ROC800 hardcoded)",
            "CVE-2016-5645 (Rockwell MicroLogix SNMP)",
            "Mirai botnet source (scanner.c credential table)",
        ],
        "mitre_techniques": ["T0812", "T0859", "T0886"],
        "mitre_tactics": ["Credential Access", "Initial Access"],
    }

    query = OptString("", "Search query (vendor, product, protocol, category, or CVE)")
    search_type = OptString("vendor",
                            "Search by: vendor, product, protocol, port, category, cve, "
                            "mirai, snmp, stats, all")
    export = OptBool(False, "Export full database as CSV")

    def run(self) -> list[DefaultCredential]:
        if self.export:
            csv_data = export_csv()
            stats = get_stats()
            print_info(f"Exported {stats['total_entries']} entries "
                       f"({stats['unique_vendors']} vendors)")
            return CREDENTIAL_DB

        q = self.query
        stype = self.search_type.lower()

        if stype == "stats":
            stats = get_stats()
            print_status("SCADAPASS Database Statistics:")
            for key, val in stats.items():
                print_info(f"  {key}: {val}")
            return []

        if stype == "mirai":
            results = [c for c in CREDENTIAL_DB if c.vendor == "(Mirai)"]
        elif stype == "snmp":
            results = [c for c in CREDENTIAL_DB if c.category == "snmp"]
        elif stype == "all" or not q:
            results = CREDENTIAL_DB
        elif stype == "vendor":
            results = search_by_vendor(q)
        elif stype == "product":
            results = search_by_product(q)
        elif stype == "protocol":
            results = search_by_protocol(q)
        elif stype == "port":
            results = search_by_port(int(q))
        elif stype == "category":
            results = search_by_category(q)
        elif stype == "cve":
            results = search_by_cve(q)
        else:
            results = search_by_vendor(q) + search_by_product(q)

        print_status(f"SCADAPASS: {len(results)} credential entries found for '{q}'")
        for c in results:
            user = c.username if c.username else "(empty)"
            pwd = c.password if c.password else "(empty)"
            cat = f" ({c.category})" if c.category else ""
            cve_tag = f" [{c.cve}]" if c.cve else ""
            print_info(f"  {c.vendor:20s} {c.product:30s} {c.protocol:12s} "
                       f":{c.port:<6d} {user}:{pwd} [{c.access_level}]"
                       f"{cat}{cve_tag}")
            if c.notes:
                print_info(f"    Note: {c.notes}")

        return results


MANIFEST = {
    "name": "scadapass_db",
    "category": "creds",
    "entry_count": len(CREDENTIAL_DB),
    "vendors": len(set(c.vendor for c in CREDENTIAL_DB if not c.vendor.startswith("("))),
    "mitre_ics": ["T0812", "T0859", "T0886"],
}
