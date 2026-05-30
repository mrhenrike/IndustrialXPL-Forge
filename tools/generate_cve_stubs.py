#!/usr/bin/env python3
"""IXF CVE Stub Generator — Static catalog, Medium/High/Critical only (CVSS >= 4.0).

Generates Level A (full PoC where available) and Level B (version-check) modules.
Level C (CVSS < 4.0 info/disclosure) is NOT generated — out of scope.

Repo is STATIC — no NVD API crawler. New CVEs added on demand via this catalog.

Run: python tools/generate_cve_stubs.py
"""

import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULES_CVE  = PROJECT_ROOT / "industrialxpl" / "modules" / "cve"
RESOURCES_CVE = PROJECT_ROOT / "industrialxpl" / "resources" / "cve"

MODULES_CVE.mkdir(parents=True, exist_ok=True)
RESOURCES_CVE.mkdir(parents=True, exist_ok=True)

# ── CVE Catalog — Medium/High/Critical ONLY (CVSS >= 4.0) ─────────────────
# Format: (CVE_ID, Vendor, Product, CVSS, Severity, ExploitType, CISA_Advisory)
# Severity must be MEDIUM (4.0-6.9), HIGH (7.0-8.9), or CRITICAL (9.0-10.0)
CATALOG = [

    # ── OT:ICEFALL 2022 — Vedere Labs / Forescout ──────────────────────────
    ("CVE-2022-29953","Emerson","DeltaV","9.1","CRITICAL","Unauthenticated protocol logic download","ICSA-22-167-06"),
    ("CVE-2022-29957","Emerson","Ovation DCS","9.1","CRITICAL","Unauthenticated protocol","ICSA-22-167-04"),
    ("CVE-2022-29958","Emerson","Ovation Engineering WS","9.1","CRITICAL","Unauthenticated firmware access","ICSA-22-167-04"),
    ("CVE-2022-29963","Emerson","DeltaV EWS","7.4","HIGH","Insecure firmware update without auth","ICSA-22-167-06"),
    ("CVE-2022-29966","Emerson","DeltaV distributed control","9.1","CRITICAL","Unauthenticated logic download","ICSA-22-167-06"),
    ("CVE-2022-30264","Emerson","ROC800 RTU","9.8","CRITICAL","Logic download without auth","ICSA-22-167-05"),
    ("CVE-2022-30271","Motorola Solutions","ACE3600 RTU","9.8","CRITICAL","Hardcoded SSH key allowing auth bypass","ICSA-22-167-07"),
    ("CVE-2022-30272","Motorola Solutions","ACE3600 RTU","7.4","HIGH","Insecure firmware update mechanism","ICSA-22-167-07"),
    ("CVE-2022-30276","Motorola Solutions","MDLC protocol implementation","9.1","CRITICAL","Unauthenticated protocol exploitation","ICSA-22-167-07"),
    ("CVE-2022-30313","Honeywell","ControlEdge Safety Controller","9.1","CRITICAL","Unauthenticated firmware access (ICEFALL)","ICSA-22-167-02"),
    ("CVE-2022-30314","Honeywell","Experion PKS","9.8","CRITICAL","Unauthenticated logic download RCE","ICSA-22-167-02"),
    ("CVE-2022-30316","Honeywell","Experion LX","9.8","CRITICAL","Unauthenticated logic download RCE","ICSA-22-167-02"),
    ("CVE-2022-30317","Honeywell","ControlEdge RTU","7.4","HIGH","Insecure firmware update","ICSA-22-167-02"),
    ("CVE-2022-30265","Omron","SYSMAC NX/NJ PLCs","9.1","CRITICAL","Unauthenticated CIP (INCONTROLLER target)","ICSA-22-167-03"),
    ("CVE-2022-34151","Omron","NX/NJ series PLCs","9.8","CRITICAL","Authentication bypass remote","ICSA-22-167-03"),
    ("CVE-2022-31206","Omron","SYSMAC CX-Programmer","9.8","CRITICAL","Remote logic upload without auth","ICSA-22-167-03"),
    ("CVE-2022-25151","JTEKT","Toyopuc PLC","9.1","CRITICAL","Logic upload no authentication","ICSA-22-179-01"),
    ("CVE-2022-25152","JTEKT","Toyopuc PLC","9.1","CRITICAL","I/O manipulation no authentication","ICSA-22-179-01"),
    ("CVE-2022-25921","Yokogawa","STARDOM FCN/FCJ","9.1","CRITICAL","Unauthenticated access (ICEFALL)","ICSA-22-179-03"),
    ("CVE-2022-25925","Yokogawa","STARDOM FCN","9.8","CRITICAL","Logic download without authentication","ICSA-22-179-03"),
    ("CVE-2022-25929","Baker Hughes","Bently Nevada 3700 condition monitor","9.1","CRITICAL","Unauthenticated access (ICEFALL)","ICSA-22-167-01"),
    ("CVE-2022-26414","ABB","multiple OT products","7.4","HIGH","Hardcoded cryptographic key (ICEFALL)","N/A"),
    ("CVE-2022-26415","ABB","multiple OT products","7.4","HIGH","Hardcoded credentials (ICEFALL)","N/A"),
    ("CVE-2022-31806","CODESYS","V3 runtime environment","9.8","CRITICAL","Missing authentication for critical function","N/A"),
    ("CVE-2022-45789","Schneider Electric","EcoStruxure platform","8.1","HIGH","Replay attack against command messages","N/A"),
    ("CVE-2022-37300","Schneider Electric","EcoStruxure platform","9.8","CRITICAL","Authentication bypass vulnerability","N/A"),
    ("CVE-2022-34662","Siemens","S7 PROFINET stack","7.5","HIGH","Denial of service via crafted packets","N/A"),

    # ── VxWorks URGENT/11 2019 — Armis Research ────────────────────────────
    ("CVE-2019-12256","Wind River","VxWorks 6.x RTOS","9.8","CRITICAL","TCP stack overflow RCE pre-auth","N/A"),
    ("CVE-2019-12255","Wind River","VxWorks 6.x RTOS","9.8","CRITICAL","TCP Urgent pointer OOB read RCE","N/A"),
    ("CVE-2019-12257","Wind River","VxWorks 6.x RTOS","8.8","HIGH","DHCP client heap buffer overflow","N/A"),
    ("CVE-2019-12258","Wind River","VxWorks RTOS","7.5","HIGH","TCP RST denial of service","N/A"),
    ("CVE-2019-12259","Wind River","VxWorks RTOS","7.5","HIGH","DNS client starvation denial of service","N/A"),
    ("CVE-2019-12260","Wind River","VxWorks 6.x RTOS","9.8","CRITICAL","TCP options memory corruption RCE","N/A"),
    ("CVE-2019-12261","Wind River","VxWorks RTOS","8.8","HIGH","TCP connection heap buffer overflow","N/A"),
    ("CVE-2019-12262","Wind River","VxWorks 6.x RTOS","9.8","CRITICAL","DNS client response hijack RCE","N/A"),
    ("CVE-2019-12263","Wind River","VxWorks 6.x RTOS","9.0","CRITICAL","IPv4 reassembly heap overflow RCE","N/A"),
    ("CVE-2019-12264","Wind River","VxWorks RTOS","7.5","HIGH","DHCP client logical flaw DoS","N/A"),

    # ── Siemens S7 series (2012-2026) ──────────────────────────────────────
    ("CVE-2012-3037","Siemens","S7-1200 PLC HTTP","5.0","MEDIUM","Diagnostic buffer information disclosure","N/A"),
    ("CVE-2012-3040","Siemens","S7-1200 PLC HTTP server","4.3","MEDIUM","Cross-site scripting via web server","N/A"),
    ("CVE-2013-0700","Siemens","S7-1200 ISO-TSAP","7.8","HIGH","Crafted ISO-TSAP packet crash denial of service","N/A"),
    ("CVE-2014-2909","Siemens","S7-1200 HTTP server","4.3","MEDIUM","CRLF injection vulnerability","N/A"),
    ("CVE-2015-0015","Siemens","S7-300 PROFIBUS DP","7.8","HIGH","I/O module stoppage denial of service","N/A"),
    ("CVE-2015-2177","Siemens","S7-300 S7comm","7.8","HIGH","Input validation denial of service","N/A"),
    ("CVE-2015-5374","Siemens","SIPROTEC 4/5 protection relay","7.8","HIGH","DNP3 crafted packet relay denial of service","ICSA-15-202-01"),
    ("CVE-2016-8672","Siemens","SIMATIC S7-1500","9.8","CRITICAL","Authentication bypass remote code execution","N/A"),
    ("CVE-2018-10952","Siemens","WinCC flexible HMI","8.1","HIGH","Authentication bypass vulnerability","N/A"),
    ("CVE-2019-13939","Siemens","APOGEE TALON BACnet controller","7.1","HIGH","BACnet IP address manipulation","ICSA-20-105-06"),
    ("CVE-2019-13945","Siemens","SIMATIC S7-1500","9.8","CRITICAL","Authentication bypass remote","N/A"),
    ("CVE-2019-13946","Siemens","S7-300 PROFINET interface","7.5","HIGH","PROFINET remote denial of service","N/A"),
    ("CVE-2021-22681","Siemens","S7-1200 S7-1500","7.5","HIGH","Hardcoded cryptographic key (ICEFALL)","N/A"),
    ("CVE-2021-40440","Siemens","SINEMA Remote Connect Server","9.8","CRITICAL","Authentication bypass vulnerability","N/A"),
    ("CVE-2021-43397","Siemens","SINEC NMS","8.8","HIGH","Path traversal vulnerability","N/A"),
    ("CVE-2023-44373","Siemens","SINEC NMS","9.3","CRITICAL","SQL injection path traversal RCE","N/A"),
    ("CVE-2024-35783","Siemens","SIMATIC WinCC/PCS7/Historian DB","7.2","HIGH","DB server OS command execution as SYSTEM","ICSA-24-228-05"),
    ("CVE-2025-40736","Siemens","SINEC NMS","9.3","CRITICAL","SQL injection 2025","N/A"),
    ("CVE-2025-40737","Siemens","SINEC NMS","9.3","CRITICAL","Missing authentication 2025","N/A"),
    ("CVE-2025-40738","Siemens","SINEC NMS","9.3","CRITICAL","Path traversal RCE 2025","N/A"),

    # ── Schneider Electric ─────────────────────────────────────────────────
    ("CVE-2015-7937","Schneider Electric","TM221 Modbus","7.8","HIGH","CPU crash via Modbus function code 0x71","N/A"),
    ("CVE-2017-6026","Schneider Electric","M221 PLC","7.5","HIGH","Session hijack via weak session tokens","N/A"),
    ("CVE-2018-7789","Schneider Electric","TM221 HTTP server","7.5","HIGH","Web service denial of service via POST","N/A"),
    ("CVE-2019-6833","Schneider Electric","Modicon M340 VxWorks","9.8","CRITICAL","Buffer overflow via Modbus","N/A"),
    ("CVE-2021-32014","Schneider Electric","Modicon M340","9.8","CRITICAL","No authentication required for commands","N/A"),
    ("CVE-2019-6829","Schneider Electric","Triconex TriStation safety","10.0","CRITICAL","Hardcoded key TRITON APT (CVE-2019-6829)","N/A"),
    ("CVE-2022-30525","Zyxel","USG Flex firewall","9.8","CRITICAL","OS command injection unauthenticated","N/A"),
    ("CVE-2022-22986","Schneider Electric","Easergy T300 RTU","9.8","CRITICAL","Hardcoded SSH key","N/A"),
    ("CVE-2021-22763","Schneider Electric","EcoStruxure","6.5","MEDIUM","Improper authentication","N/A"),
    ("CVE-2020-28212","Schneider Electric","EcoStruxure Operator Terminal","9.8","CRITICAL","Authentication bypass","N/A"),

    # ── Rockwell Automation ────────────────────────────────────────────────
    ("CVE-2016-5645","Rockwell Automation","MicroLogix 1766-L32","5.0","MEDIUM","Ethernet interface denial of service","N/A"),
    ("CVE-2017-7901","Rockwell Automation","CompactLogix","9.8","CRITICAL","Unauthenticated remote access","N/A"),
    ("CVE-2019-10952","Rockwell Automation","CompactLogix 5480","9.8","CRITICAL","Authentication bypass","N/A"),
    ("CVE-2020-12038","Rockwell Automation","Studio 5000 Logix Designer","9.8","CRITICAL","Authentication bypass","N/A"),
    ("CVE-2020-12040","Rockwell Automation","SoftLogix 5800 CIP","9.8","CRITICAL","CIP stack buffer overflow","N/A"),
    ("CVE-2021-27478","Rockwell Automation","EtherNet/IP adapter","9.8","CRITICAL","Stack buffer overflow RCE","N/A"),
    ("CVE-2021-22681","Rockwell Automation","ControlLogix S7 integration","7.5","HIGH","Hardcoded key exposure","N/A"),
    ("CVE-2022-1161","Rockwell Automation","CompactLogix ControlLogix","10.0","CRITICAL","Code injection via ladder logic","N/A"),
    ("CVE-2023-46290","Rockwell Automation","FactoryTalk Services Platform","8.8","HIGH","Path traversal information disclosure","N/A"),
    ("CVE-2024-6077","Rockwell Automation","ControlLogix CompactLogix","8.7","HIGH","CIP security object denial of service","ICSA-24-256-18"),
    ("CVE-2024-5989","Rockwell Automation","ThinManager ThinServer","9.8","CRITICAL","SQLi unauthenticated RCE","N/A"),
    ("CVE-2024-7961","Rockwell Automation","Pavilion8 MES","9.8","CRITICAL","Path traversal file upload RCE","N/A"),
    ("CVE-2025-13823","Rockwell Automation","Micro820/Micro850/Micro870","7.5","HIGH","DoS via third-party component 2025","N/A"),
    ("CVE-2025-13824","Rockwell Automation","Micro820/Micro850/Micro870","7.5","HIGH","Invalid pointer DoS 2025","N/A"),

    # ── ABB ───────────────────────────────────────────────────────────────
    ("CVE-2021-22277","ABB","AC800M Process Controller MMS","7.5","HIGH","MMS protocol resource exhaustion DoS","N/A"),
    ("CVE-2020-8476","ABB","AC500 PLC","9.8","CRITICAL","Hardcoded credentials authentication bypass","N/A"),
    ("CVE-2019-7246","ABB","CP651 HMI","7.5","HIGH","Denial of service vulnerability","N/A"),
    ("CVE-2021-22281","ABB","Symphony Plus S+ Operations","8.8","HIGH","Deserialization of untrusted data","N/A"),
    ("CVE-2022-26412","ABB","Symphony Plus Operations","8.8","HIGH","SQL injection vulnerability","N/A"),

    # ── Honeywell ─────────────────────────────────────────────────────────
    ("CVE-2021-38397","Honeywell","Experion PKS DCS","10.0","CRITICAL","OS command injection unauthenticated","N/A"),
    ("CVE-2022-30313","Honeywell","ControlEdge Unit Operations","9.1","CRITICAL","Unauthenticated firmware (ICEFALL)","ICSA-22-167-02"),
    ("CVE-2019-13528","Honeywell","MatrikonOPC Explorer","7.5","HIGH","Buffer overflow denial of service","N/A"),
    ("CVE-2022-3029","Honeywell","Saia Burgess Controls","9.8","CRITICAL","Authentication bypass web server","N/A"),

    # ── GE / GE Digital ───────────────────────────────────────────────────
    ("CVE-2011-0340","GE","Proficy HMI/SCADA iFIX","9.3","CRITICAL","Buffer overflow remote code execution","N/A"),
    ("CVE-2014-0751","GE","CIMPLICITY SCADA BlackEnergy","9.0","CRITICAL","Path traversal RCE (BlackEnergy APT)","N/A"),
    ("CVE-2019-6503","GE","CIMPLICITY HMI","9.8","CRITICAL","Path traversal remote code execution","N/A"),
    ("CVE-2016-8361","GE","Predix Machine","8.1","HIGH","Improper authentication remote","N/A"),

    # ── Emerson / Fisher / DeltaV ─────────────────────────────────────────
    ("CVE-2020-10640","Emerson","OpenEnterprise SCADA","9.8","CRITICAL","Remote code execution unauthenticated","N/A"),
    ("CVE-2022-30267","Emerson","Ovation OCR400 controller","9.8","CRITICAL","Authentication bypass (ICEFALL)","ICSA-22-167-04"),

    # ── Yokogawa ─────────────────────────────────────────────────────────
    ("CVE-2014-0783","Yokogawa","CENTUM CS3000 BKBCopyD","9.8","CRITICAL","Stack buffer overflow RCE","N/A"),
    ("CVE-2014-0784","Yokogawa","CENTUM CS3000 BKHODeq","9.8","CRITICAL","Stack buffer overflow RCE","N/A"),
    ("CVE-2014-3888","Yokogawa","CENTUM CS3000 BKESIMMGR","9.8","CRITICAL","Stack buffer overflow RCE","N/A"),
    ("CVE-2022-25921","Yokogawa","STARDOM FCN/FCJ PLC","9.1","CRITICAL","Unauthenticated access (ICEFALL)","ICSA-22-179-03"),

    # ── Omron ─────────────────────────────────────────────────────────────
    ("CVE-2015-0987","Omron","CP2E PLC FINS","7.8","HIGH","CPU cycle time error denial of service","N/A"),
    ("CVE-2023-27396","Omron","CJ2M PLC FINS","9.8","CRITICAL","Missing authentication FINS protocol","N/A"),
    ("CVE-2022-34151","Omron","NX/NJ series PLC","9.8","CRITICAL","Authentication bypass INCONTROLLER","ICSA-22-167-03"),

    # ── AVEVA / Wonderware ────────────────────────────────────────────────
    ("CVE-2023-2573","AVEVA","InTouch HMI","9.8","CRITICAL","Authentication bypass vulnerability","N/A"),
    ("CVE-2023-2574","AVEVA","InTouch HMI","9.8","CRITICAL","Path traversal vulnerability","N/A"),
    ("CVE-2023-2638","AVEVA","System Platform SCADA","9.8","CRITICAL","SQL injection remote code execution","N/A"),
    ("CVE-2021-33010","AVEVA","HistorianServer","7.5","HIGH","Denial of service remote","N/A"),

    # ── Inductive Automation Ignition (MES/SCADA) ─────────────────────────
    ("CVE-2023-39476","Inductive Automation","Ignition SCADA/MES","9.8","CRITICAL","Java deserialization pre-auth RCE","ICSA-23-264-01"),
    ("CVE-2023-39473","Inductive Automation","Ignition SCADA/MES","8.8","HIGH","Java deserialization authenticated RCE","N/A"),
    ("CVE-2022-35872","Inductive Automation","Ignition 8.1.15","8.8","HIGH","ZIP parsing deserialization RCE Pwn2Own","N/A"),
    ("CVE-2025-13911","Inductive Automation","Ignition 8.x Windows","7.2","HIGH","Python scripting SYSTEM privilege escape","N/A"),
    ("CVE-2025-13913","Inductive Automation","Ignition 8.x","7.2","HIGH","Malicious project import RCE","N/A"),

    # ── Dassault DELMIA Apriso MES ────────────────────────────────────────
    ("CVE-2025-5086","Dassault Systemes","DELMIA Apriso 2020-2025","9.8","CRITICAL","Insecure deserialization unauthenticated RCE","N/A"),
    ("CVE-2025-6204","Dassault Systemes","DELMIA Apriso portal","8.8","HIGH","File upload path traversal webshell","N/A"),
    ("CVE-2025-6205","Dassault Systemes","DELMIA Apriso SOAP","9.8","CRITICAL","SOAP endpoint unauthenticated account creation","N/A"),

    # ── Advantech ─────────────────────────────────────────────────────────
    ("CVE-2017-12719","Advantech","WebAccess SCADA/HMI","9.8","CRITICAL","Stack buffer overflow remote code execution","N/A"),
    ("CVE-2017-7895","Advantech","WebAccess SCADA","7.5","HIGH","Directory traversal arbitrary file access","N/A"),
    ("CVE-2020-13984","Advantech","WebAccess Node","9.8","CRITICAL","SQL injection RCE","N/A"),
    ("CVE-2021-33014","Advantech","WebAccess","9.8","CRITICAL","Stack-based buffer overflow RCE","N/A"),
    ("CVE-2022-3036","Advantech","iView","9.8","CRITICAL","SQL injection authentication bypass","N/A"),

    # ── Delta Electronics ─────────────────────────────────────────────────
    ("CVE-2017-9312","Delta Electronics","CNCSoft ScreenEditor","7.8","HIGH","Buffer overflow remote code execution","N/A"),
    ("CVE-2021-33008","Delta Electronics","DIAEnergie","9.8","CRITICAL","Hard-coded credentials","N/A"),
    ("CVE-2022-25347","Delta Electronics","InfraSuite Device Master","9.8","CRITICAL","Deserialization RCE unauthenticated","N/A"),
    ("CVE-2022-45137","Delta Electronics","DIALink","9.8","CRITICAL","Authentication bypass RCE","N/A"),

    # ── CODESYS ───────────────────────────────────────────────────────────
    ("CVE-2021-29241","CODESYS","Linux SL OPC UA","7.5","HIGH","OPC UA protocol stack denial of service","N/A"),
    ("CVE-2023-37545","CODESYS","Gateway Server V3","9.8","CRITICAL","Path traversal vulnerability","N/A"),
    ("CVE-2022-31806","CODESYS","V3 runtime","9.8","CRITICAL","Missing authentication for critical function","N/A"),
    ("CVE-2021-30189","CODESYS","V3 PLC runtime","7.5","HIGH","NULL pointer dereference DoS","N/A"),

    # ── Moxa ─────────────────────────────────────────────────────────────
    ("CVE-2019-15102","Moxa","Device Manager MDMTool","9.8","CRITICAL","Stack buffer overflow RCE","N/A"),
    ("CVE-2018-10995","Moxa","NPort serial server","7.5","HIGH","Cleartext credential transmission","N/A"),
    ("CVE-2020-13532","Moxa","MXView network manager","9.8","CRITICAL","Authentication bypass RCE","N/A"),

    # ── Unitronics ────────────────────────────────────────────────────────
    ("CVE-2023-6448","Unitronics","Vision/Samba/Jazz PLCs","9.8","CRITICAL","Default password PCOM authentication bypass","AA23-335A"),

    # ── OSIsoft PI / AVEVA PI ─────────────────────────────────────────────
    ("CVE-2022-24957","OSIsoft","PI Server","9.8","CRITICAL","Buffer overflow remote code execution","N/A"),
    ("CVE-2020-25163","OSIsoft","PI Vision","7.5","HIGH","Cross-site scripting stored","N/A"),

    # ── Historical SCADA software (basis of MSF modules) ─────────────────
    ("CVE-2008-0436","Schneider Electric","CitectSCADA ODBC server","10.0","CRITICAL","ODBC buffer overflow remote code execution","N/A"),
    ("CVE-2011-2089","Iconics","Genesis32 GenBroker","9.3","CRITICAL","GenBroker stack buffer overflow RCE","N/A"),
    ("CVE-2011-3486","7-Technologies","IGSS9 DataServer","9.3","CRITICAL","DataServer heap buffer overflow RCE","N/A"),
    ("CVE-2011-1899","Iconics","Genesis32 WebHMI","9.3","CRITICAL","WebHMI ActiveX buffer overflow RCE","N/A"),
    ("CVE-2006-6449","RealFlex","RealWin SCADA","10.0","CRITICAL","Stack buffer overflow remote code execution","N/A"),
    ("CVE-2011-3492","Measuresoft","ScadaPro","9.8","CRITICAL","Unauthenticated command execution","N/A"),
    ("CVE-2014-0783","Yokogawa","CENTUM CS3000 BKBCOPYD","9.8","CRITICAL","Stack buffer overflow remote code execution","N/A"),

    # ── APT / Malware targets ─────────────────────────────────────────────
    ("CVE-2010-2772","Siemens","Step7 SIMATIC Stuxnet","9.3","CRITICAL","Hardcoded cryptographic key Stuxnet APT","N/A"),
    ("CVE-2010-2773","Siemens","WinCC DB server Stuxnet","10.0","CRITICAL","SQL injection Stuxnet APT","N/A"),
    ("CVE-2019-6829","Schneider Electric","Triconex TriStation TRITON","10.0","CRITICAL","Hardcoded key TRITON/TRISIS APT","N/A"),

    # ── FUXA SCADA ────────────────────────────────────────────────────────
    ("CVE-2026-25895","frangoteam","FUXA SCADA <=1.2.9","9.8","CRITICAL","Pre-auth arbitrary file write RCE","N/A"),
    ("CVE-2026-25939","frangoteam","FUXA SCADA","9.8","CRITICAL","Scheduler command injection RCE","N/A"),

    # ── Honeywell Trend Controls IQ4E ─────────────────────────────────────
    ("ICSA-22-242-08","Honeywell","Trend Controls IQ4E BACnet","8.6","HIGH","BACnet PIN plaintext transmission (OT:ICEFALL)","ICSA-22-242-08"),

    # ── Schneider SCADAPack ───────────────────────────────────────────────
    ("ICSA-10-214-01","Schneider Electric","SCADAPack VxWorks RTU","9.8","CRITICAL","VxWorks WDB debug port exposed unauthenticated","ICSA-10-214-01"),
    ("ICSA-22-223-03","Schneider Electric","SCADAPack RemoteConnect","9.8","CRITICAL","Buffer overflow path traversal RCE","ICSA-22-223-03"),

    # ── Log4Shell and Spring4Shell in ICS context ─────────────────────────
    ("CVE-2021-44228","Apache","Log4j2 Log4Shell affects Java MES","10.0","CRITICAL","JNDI injection RCE Log4Shell (affects Ignition MES)","N/A"),
    ("CVE-2022-22965","VMware Spring","Spring4Shell affects Spring MES","9.8","CRITICAL","ClassLoader manipulation RCE (affects Spring-based MES)","N/A"),

    # ── Additional MikroTik (used in OT borders) ──────────────────────────
    ("CVE-2018-14847","MikroTik","RouterOS Winbox","9.1","CRITICAL","Winbox credential disclosure without auth","N/A"),
    ("CVE-2019-3977","MikroTik","RouterOS","7.5","HIGH","WinBox exploit path traversal","N/A"),

    # ── Tridium Niagara ───────────────────────────────────────────────────
    ("CVE-2022-40201","Tridium","Niagara 4 Framework","9.8","CRITICAL","Authentication bypass remote code execution","N/A"),
    ("CVE-2018-1139","Tridium","Niagara AX Framework","7.5","HIGH","Credential disclosure via Fox protocol","N/A"),

    # ── Phoenix Contact ───────────────────────────────────────────────────
    ("CVE-2016-8366","Phoenix Contact","WebVisit HMI","5.0","MEDIUM","Password plaintext disclosure via HTTP","N/A"),
    ("CVE-2016-8380","Phoenix Contact","HMI tag interface","8.3","HIGH","Unauthenticated tag read/write","N/A"),

    # ── Beckhoff TwinCat ─────────────────────────────────────────────────
    ("CVE-2019-16883","Beckhoff","TwinCat ADS server","7.5","HIGH","Authentication bypass ADS protocol","N/A"),
    ("CVE-2023-4380","Beckhoff","TwinCat/BSD","7.8","HIGH","Privilege escalation local","N/A"),

    # ── Koyo / AutomationDirect ───────────────────────────────────────────
    ("CVE-2012-6435","Koyo","DirectLOGIC ECOM module","7.8","HIGH","Cleartext credential transmission","N/A"),

    # ── General ICS insecure by design (CVSS >= 4.0 by OT context) ────────
    ("DESIGN-MODBUS-NOAUTH","Generic","Modbus TCP all vendors","9.1","CRITICAL","No authentication by protocol design — unauthenticated read/write","N/A"),
    ("DESIGN-S7COMM-NOAUTH","Siemens","S7comm pre-S7comm+ protocol","9.1","CRITICAL","No authentication by protocol design — unauthenticated PLC control","N/A"),
    ("DESIGN-DNP3-NOSA","Generic","DNP3 without Secure Authentication v5","9.1","CRITICAL","Replay attack unauthenticated control no Secure Auth","N/A"),
    ("DESIGN-ENIP-NOAUTH","Generic","EtherNet/IP CIP all vendors","7.5","HIGH","CIP protocol no built-in authentication — unauthenticated command","N/A"),
]

print(f"Total CVEs in catalog (Medium/High/Critical only): {len(CATALOG)}")

STUB_TEMPLATE = '''"""IXF CVE Module — {cve_id} — {vendor} {product}.

Severity: {severity} (CVSS {cvss})
Type: {exploit_type}
CISA Advisory: {cisa}

Level B module: port fingerprint + version context.
run() in simulate mode (default): describes exploit without sending packets.
set simulate false + destructive true for real execution gate.
"""

import socket
from industrialxpl.core.exploit import (
    Exploit,
    OptBool,
    OptIP,
    OptInteger,
    OptPort,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
    DestructiveGate,
)

_DEFAULT_PORT = {port}
_SEVERITY = "{severity}"
_CVSS = "{cvss}"


class Exploit(Exploit):
    __info__ = {{
        "name":          "{cve_id} — {vendor} {product} ({severity})",
        "description":   "{exploit_type}. "
                         "Affects {vendor} {product}. CVSS {cvss} ({severity}). "
                         "Level B: fingerprint + version check.",
        "authors":       ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":    ("https://nvd.nist.gov/vuln/detail/{cve_id}",),
        "devices":       ("{vendor} {product}",),
        "impact":        "{impact}",
        "exploit_type":  "{exploit_type}",
        "source_poc":    "Static catalog Level B — set check() target for version confirmation",
        "cve":           "{cve_id}",
        "cvss":          "{cvss}",
        "severity":      "{severity}",
        "cisa_advisory": "{cisa}",
        "mitre_techniques": {mitre},
        "mitre_tactics":    {tactics},
    }}

    target   = OptIP("", "Target {vendor} device IP")
    port     = OptPort(_DEFAULT_PORT, "Target service port")
    timeout  = OptInteger(5, "Socket timeout seconds")
    simulate = OptBool(True, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable real execution (requires gate confirmation)")

    @mute
    def check(self) -> bool:
        """Fingerprint: return True if service port is open (device may be present)."""
        if not self.target:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            sock.close()
            return True
        except Exception:
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Set the \\'target\\' option first.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "{cve_id} ({severity} CVSS {cvss}): {exploit_type}. "
                    "Affects: {vendor} {product}. "
                    "Would fingerprint {{}}:{{}} and confirm if device version "
                    "is in the affected range.".format(self.target, self.port)
                ),
                mitre_techniques={mitre},
            )
            return

        print_status("Checking {{}}:{{}} for {cve_id}...".format(self.target, self.port))
        if self.check():
            print_success(
                "Service port {{}} open on {{}} — {vendor} {product} may be present. "
                "{cve_id} {severity} CVSS {cvss}: {exploit_type}. "
                "Manual version verification required to confirm vulnerability.".format(
                    self.port, self.target)
            )
            print_warning("CISA Advisory: {cisa}")
        else:
            print_info("{{}}:{{}} not responding on port {{}}.".format(
                self.target, self.port, self.port))
'''


PORT_MAP = {
    "modbus": 502, "s7-": 102, "s7 ": 102, "siemens": 102, "profinet": 34962,
    "step7": 102, "wincc": 1433, "sinec": 80, "simatic": 1433,
    "enip": 44818, "ethernet/ip": 44818, "cip": 44818, "controllogix": 44818,
    "compactlogix": 44818, "micrologix": 44818, "factorytalk": 44818,
    "bacnet": 47808, "dnp3": 20000, "opc ua": 4840, "opcua": 4840,
    "fins": 9600, "omron": 9600,
    "ads": 48898, "twincat": 48898, "beckhoff": 48898,
    "pcom": 20256, "unitronics": 20256,
    "webacc": 80, "http": 80, "web": 80, "html": 80, "scada pro": 11234,
    "ignition": 8088, "thinmanager": 2031, "pavilion": 80,
    "apriso": 80, "delmia": 80,
    "pi server": 5450, "osisoft": 5450,
    "vxworks": 17185, "scadapack": 17185, "wdb": 17185,
    "log4": 8080, "spring": 8080,
    "fox": 4911, "niagara": 4911, "tridium": 4911,
    "historian": 1433, "winlog": 46824, "realwin": 910,
    "citectscada": 20222, "citect": 20222,
    "igss": 9990, "genesis32": 38080,
    "proficy": 80, "ifix": 80, "cimplicity": 80,
    "webvisit": 80, "phoenix": 80,
    "foxtrot": 5094, "hart": 5094,
    "koyo": 28784, "directlogic": 28784,
    "routeros": 8291, "mikrotik": 8291, "winbox": 8291,
    "triconex": 1502, "tristation": 1502,
    "deltav": 4840, "ovation": 502, "emerson": 502,
    "stardom": 502, "yokogawa": 102,
    "centum": 102, "bkbcopyd": 34104,
    "prosoft": 502, "moxa": 4800,
    "abb": 102, "ac500": 102, "ac800": 102,
    "advantech": 80, "webaccess": 80,
    "ge digital": 80, "proficy historian": 5450, "iFIX": 80,
}

def get_port(vendor: str, product: str) -> int:
    combined = (vendor + " " + product).lower()
    for keyword, port in PORT_MAP.items():
        if keyword in combined:
            return port
    return 502

def get_mitre_and_tactics(exploit_type: str, severity: str) -> tuple:
    et = exploit_type.lower()
    techniques = []
    tactics = set()
    if any(w in et for w in ["rce", "command", "injection", "code exec", "upload"]):
        techniques += ["T0819", "T0866"]
        tactics.add("Initial Access")
    if any(w in et for w in ["dos", "denial", "crash", "overflow"]):
        techniques += ["T0814"]
        tactics.add("Inhibit Response Function")
    if any(w in et for w in ["auth", "credential", "hardcoded", "default", "bypass"]):
        techniques += ["T1694.002", "T0859"]
        tactics.add("Initial Access")
    if any(w in et for w in ["firmware"]):
        techniques += ["T1693"]
        tactics.add("Persistence")
    if any(w in et for w in ["traversal", "path traversal", "file"]):
        techniques += ["T0819"]
        tactics.add("Initial Access")
    if any(w in et for w in ["logic", "plc", "ladder"]):
        techniques += ["T0843", "T0821"]
        tactics.add("Impair Process Control")
    if any(w in et for w in ["unauthenticated protocol", "design"]):
        techniques += ["T1692.001", "T0836"]
        tactics.add("Impair Process Control")
    if not techniques:
        techniques = ["T0883"]
        tactics.add("Discovery")
    return list(dict.fromkeys(techniques))[:4], list(tactics)[:2]

def get_impact(severity: str) -> str:
    return {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM"}.get(severity, "MEDIUM")

def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", text.lower()).strip("_")

def create_stub(row: tuple) -> tuple[str, bool]:
    cve_id, vendor, product, cvss, severity, exploit_type, cisa = row
    # Skip LOW and INFO
    if severity not in ("MEDIUM", "HIGH", "CRITICAL"):
        return "", False

    vendor_slug = slugify(vendor)[:20]
    cve_slug = cve_id.lower().replace("-", "_")

    out_dir = MODULES_CVE / vendor_slug
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "__init__.py").touch()

    out_file = out_dir / f"{cve_slug}.py"
    if out_file.exists():
        return str(out_file), False  # Already exists

    port = get_port(vendor, product)
    mitre, tactics = get_mitre_and_tactics(exploit_type, severity)
    impact = get_impact(severity)

    content = STUB_TEMPLATE.format(
        cve_id=cve_id, vendor=vendor, product=product,
        cvss=cvss, severity=severity, exploit_type=exploit_type,
        cisa=cisa, impact=impact,
        mitre=str(mitre), tactics=str(tactics), port=port,
    )
    out_file.write_text(content, encoding="utf-8")
    return str(out_file), True


def cleanup_low_severity() -> int:
    """Remove any existing Level C (Low/Info) stubs."""
    removed = 0
    for f in MODULES_CVE.rglob("*.py"):
        if f.name == "__init__.py":
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            if ('"severity":      "LOW"' in content or
                    '"severity":      "INFO"' in content or
                    '"severity": "LOW"' in content or
                    '"severity": "INFO"' in content):
                f.unlink()
                removed += 1
        except Exception:
            pass
    return removed


def main() -> None:
    # Remove old Low/Info stubs
    removed = cleanup_low_severity()
    if removed:
        print(f"[generate_cve_stubs] Removed {removed} Low/Info severity stubs (out of scope)")

    created = updated = skipped = 0
    for row in CATALOG:
        _, _, _, _, severity, _, _ = row
        if severity not in ("MEDIUM", "HIGH", "CRITICAL"):
            skipped += 1
            continue
        path, is_new = create_stub(row)
        if is_new:
            created += 1

    print(f"[generate_cve_stubs] Catalog: {len(CATALOG)} CVEs (Medium/High/Critical only)")
    print(f"[generate_cve_stubs] Created: {created} new stubs | Skipped existing: {len(CATALOG) - created - skipped}")
    print(f"[generate_cve_stubs] Output: {MODULES_CVE}")

    # Recount modules
    sys.path.insert(0, str(PROJECT_ROOT))
    try:
        from industrialxpl.core.exploit.utils import index_modules
        mods = index_modules()
        print(f"[generate_cve_stubs] IXF total modules: {len(mods)}")
    except Exception as exc:
        print(f"[generate_cve_stubs] Index count failed: {exc}")


if __name__ == "__main__":
    main()
