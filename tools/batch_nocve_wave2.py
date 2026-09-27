#!/usr/bin/env python3
"""Wave 2 — No-CVE protocol abuse exploits for IXF.

Covers inherent design vulnerabilities in:
  - IEC 61850 GOOSE/MMS (no auth in legacy)
  - OPC UA (unauthenticated session)
  - PROFIBUS (no auth)
  - CC-Link (broadcast flooding)
  - EtherNet/IP (CIP multi-request abuse)
  - DNP3 advanced attacks
  - Modbus advanced
  - IEC 104 direct control
  - Wireless HART (key brute)
  - Serial-to-Ethernet gateway attacks
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
MODULES_DIR = ROOT / "industrialxpl" / "modules" / "exploits" / "protocols"

TEMPLATE = '''"""IXF Protocol Abuse Exploit (No CVE) — {name}.

{description}

Protocol design limitation / missing authentication by design.
NOT a CVE — inherent protocol weakness exploitable without patching.

simulate=True (default). Live execution requires explicit authorization.
"""
import socket
import struct
import time

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, OptString, mute,
    print_error, print_info, print_status, print_success, print_warning,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {{
        "name":             "{name}",
        "description":      "{short_desc}",
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":       {refs},
        "devices":          {devices},
        "impact":           "{impact}",
        "exploit_type":     "Protocol Design Abuse (No CVE)",
        "source_poc":       "IXF native implementation",
        "cve":              "N/A",
        "cvss":             "N/A — design weakness",
        "severity":         "{impact}",
        "mitre_techniques": {mitre},
        "mitre_tactics":    {tactics},
    }}

    target      = OptIP("", "Target device IP")
    port        = OptPort({port}, "Protocol port")
    simulate    = OptBool(True, "Simulate only (default: True)")
    destructive = OptBool(False, "Enable live protocol commands")

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
                description="{name}\\n{simulation_steps}",
                mitre_techniques={mitre},
            )
            print_info("No CVE — inherent protocol design weakness")
            return
        print_status("[{proto}] Sending to {{}}:{{}}...".format(self.target, self.port))
        {live_code}
'''


def make(subdir, filename, name, short_desc, description, proto,
         port, impact, refs, devices, mitre, tactics,
         simulation_steps, live_code="print_info('Live exploit: send protocol-specific commands')"):
    d = MODULES_DIR / subdir
    d.mkdir(parents=True, exist_ok=True)
    (d / "__init__.py").touch(exist_ok=True)
    f = d / filename
    if f.exists():
        return False
    content = TEMPLATE.format(
        name=name, short_desc=short_desc[:200], description=description,
        proto=proto, port=port, impact=impact,
        refs=str(tuple(refs)), devices=str(tuple(devices)),
        mitre=str(mitre), tactics=str(tactics),
        simulation_steps=simulation_steps.replace("\n", "\\n"),
        live_code=live_code,
    )
    f.write_text(content, encoding="utf-8")
    return True


BATCH = [
    dict(
        subdir="iec61850", filename="goose_spoofing_injection.py",
        name="IEC 61850 GOOSE Message Spoofing",
        short_desc="IEC 61850 GOOSE (Generic Object Oriented Substation Event) spoofing — inject false protection relay events without authentication.",
        description="IEC 61850 GOOSE uses Ethernet multicast with no authentication or encryption by default in legacy deployments. "
                    "Attacker on same LAN segment can inject spoofed GOOSE messages to trip circuit breakers or block legitimate events.",
        proto="GOOSE/L2", port=102,
        impact="CRITICAL",
        refs=["https://www.ietf.org/proceedings/88/slides/slides-88-saag-3.pdf"],
        devices=["IEC 61850 protection relays", "Digital substations", "IEC 61850 circuit breakers"],
        mitre=["T0856","T0830","T0827"],
        tactics=["Impair Process Control"],
        simulation_steps=(
            "Phase 1: Capture legitimate GOOSE multicast (dst: 01:0C:CD:01:00:XX)\n"
            "Phase 2: Forge GOOSE PDU with allData stNum increment (+1 from current)\n"
            "Phase 3: Send spoofed GOOSE with goID matching target relay\n"
            "Phase 4: Relay processes forged event — trips circuit breaker or blocks trip\n"
            "Requires: Layer 2 access to substation LAN (IED network)"
        ),
    ),
    dict(
        subdir="iec61850", filename="goose_flooding_dos.py",
        name="IEC 61850 GOOSE Flooding DoS",
        short_desc="IEC 61850 GOOSE multicast flood — overwhelm protection relay processing, delay or block legitimate protection events.",
        description="Flooding IEC 61850 GOOSE multicast frames to protection relays can overwhelm their processing capacity, "
                    "causing delays in legitimate protection events and potentially leading to equipment damage.",
        proto="GOOSE/L2", port=102,
        impact="HIGH",
        refs=["https://ieeexplore.ieee.org/document/7084633"],
        devices=["IEC 61850 protection relays", "Substation automation systems"],
        mitre=["T0814","T0815"],
        tactics=["Inhibit Response Function"],
        simulation_steps=(
            "Phase 1: Craft minimum-size GOOSE frame targeting relay multicast group\n"
            "Phase 2: Send at line rate (~100,000 frames/sec on 100Mbps)\n"
            "Phase 3: Relay CPU saturated processing GOOSE flood\n"
            "Phase 4: Legitimate protection GOOSE events delayed/dropped\n"
            "Risk: Relay fails to respond to real fault — equipment damage"
        ),
    ),
    dict(
        subdir="iec61850", filename="mms_unauthorized_control.py",
        name="IEC 61850 MMS Unauthorized Control",
        short_desc="IEC 61850 MMS (Manufacturing Message Specification) direct control without authentication on legacy substations.",
        description="Legacy IEC 61850 MMS deployments may not enforce authentication on control operations. "
                    "An attacker can issue MMS Initiate + control service calls to operate circuit breakers.",
        proto="MMS/TCP", port=102,
        impact="CRITICAL",
        refs=["https://www.iec.ch/homepage"],
        devices=["IEC 61850 RTUs", "Substation automation units", "Power grid switchgear"],
        mitre=["T0813","T0827"],
        tactics=["Impair Process Control"],
        simulation_steps=(
            "Phase 1: Establish MMS Initiate on TCP/102 (no credentials required in legacy)\n"
            "Phase 2: MMS Identify — enumerate logical nodes and data objects\n"
            "Phase 3: MMS Write — setVal on XCBR1.Pos.ctlVal (circuit breaker position)\n"
            "Phase 4: Circuit breaker opens/closes — localized power outage\n"
            "Affects: Substations using IEC 61850 ed.1 without access control"
        ),
    ),
    dict(
        subdir="opcua", filename="opcua_session_hijack.py",
        name="OPC UA Unauthenticated Session Abuse",
        short_desc="OPC UA server with None security mode — read/write nodes without authentication. Design flaw in misconfigured deployments.",
        description="OPC UA servers configured with SecurityMode=None (anonymous) allow any client to connect "
                    "without credentials and read/write all nodes including process setpoints and safety parameters.",
        proto="OPC UA", port=4840,
        impact="CRITICAL",
        refs=["https://reference.opcfoundation.org/Core/Part2/v105/docs/"],
        devices=["OPC UA servers", "SCADA gateways", "DCS historian bridges"],
        mitre=["T1692.001","T0836"],
        tactics=["Impair Process Control"],
        simulation_steps=(
            "Phase 1: Connect to OPC UA port 4840 with SecurityMode=None\n"
            "Phase 2: CreateSession — anonymous, no credentials\n"
            "Phase 3: Browse namespace — list all nodes and their NodeIds\n"
            "Phase 4: ReadValue on process tags — extract all setpoints\n"
            "Phase 5: WriteValue on writable nodes — modify setpoints\n"
            "Common: Many Kepware/Matrikon OPC UA servers ship with None mode"
        ),
    ),
    dict(
        subdir="opcua", filename="opcua_node_enumeration.py",
        name="OPC UA Anonymous Node Enumeration",
        short_desc="OPC UA anonymous browse — enumerate all server nodes, tags, and metadata without credentials.",
        description="OPC UA anonymous browsing reveals complete industrial plant topology including all process tags, "
                    "alarm setpoints, device descriptions, and network addresses.",
        proto="OPC UA", port=4840,
        impact="MEDIUM",
        refs=["https://reference.opcfoundation.org/Core/Part4/v105/docs/5.8"],
        devices=["OPC UA servers", "Industrial IoT gateways"],
        mitre=["T0888","T0802"],
        tactics=["Collection"],
        simulation_steps=(
            "Phase 1: Connect OPC UA TCP port 4840 anonymous\n"
            "Phase 2: GetEndpoints — discover all available endpoints\n"
            "Phase 3: BrowseRequest from RootFolder — recursive tree walk\n"
            "Phase 4: Extract all NodeIds, BrowseNames, DataTypes\n"
            "Phase 5: Read all Variable nodes — complete process data map\n"
            "Output: Full OPC UA namespace in JSON/CSV format"
        ),
    ),
    dict(
        subdir="dnp3", filename="dnp3_data_spoofing.py",
        name="DNP3 Response Spoofing / False Data Injection",
        short_desc="DNP3 lacks authentication in many deployments — spoof unsolicited response packets to inject false sensor readings.",
        description="DNP3 protocol without Secure Authentication v5 allows spoofed unsolicited responses. "
                    "Attacker can inject false analog input values, making operators see incorrect sensor data.",
        proto="DNP3", port=20000,
        impact="HIGH",
        refs=["https://www.cisa.gov/uscert/ics/alerts/ICS-ALERT-12-046-01"],
        devices=["DNP3 outstations", "RTUs without SAv5", "SCADA front-end processors"],
        mitre=["T0856","T0832"],
        tactics=["Collection","Impair Process Control"],
        simulation_steps=(
            "Phase 1: Capture legitimate DNP3 unsolicited response from RTU\n"
            "Phase 2: Craft spoofed response with source=RTU address, dest=master\n"
            "Phase 3: Set analog inputs to false values (pressure=0, flow=9999)\n"
            "Phase 4: Inject via UDP or TCP man-in-the-middle\n"
            "Phase 5: SCADA master displays false data — operators misled\n"
            "Requires: DNP3 without SAv5 (still common in legacy SCADA)"
        ),
    ),
    dict(
        subdir="dnp3", filename="dnp3_replay_command.py",
        name="DNP3 Command Replay Attack",
        short_desc="Replay captured DNP3 control commands against RTUs without sequence replay protection.",
        description="DNP3 legacy deployments without SAv5 nonces allow replay of captured control frames. "
                    "Attacker replays previously captured open/close commands to trip circuit breakers.",
        proto="DNP3", port=20000,
        impact="HIGH",
        refs=["https://www.cisa.gov/uscert/ics/alerts/ICS-ALERT-12-046-01"],
        devices=["DNP3 RTUs without SAv5", "Power grid controllers"],
        mitre=["T0848","T0827"],
        tactics=["Impair Process Control"],
        simulation_steps=(
            "Phase 1: Capture DNP3 CROB (Control Relay Output Block) command to RTU\n"
            "Phase 2: Record full TCP/UDP session with control frame\n"
            "Phase 3: Replay captured frame against same or different RTU\n"
            "Phase 4: RTU executes replayed command — opens circuit breaker\n"
            "Requires: No SAv5 challenge-response authentication"
        ),
    ),
    dict(
        subdir="enip", filename="cip_read_all_tags.py",
        name="EtherNet/IP CIP Tag Enumeration (No Auth)",
        short_desc="EtherNet/IP CIP tag enumeration without authentication — list and read all controller tags.",
        description="Allen-Bradley/Rockwell PLCs expose all tag data via CIP List Tags service without authentication. "
                    "Attacker can enumerate entire tag database and read all process values.",
        proto="EtherNet/IP", port=44818,
        impact="MEDIUM",
        refs=["https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm004_-en-p.pdf"],
        devices=["Allen-Bradley ControlLogix/CompactLogix PLCs", "Rockwell PLCs"],
        mitre=["T0888","T0802"],
        tactics=["Collection"],
        simulation_steps=(
            "Phase 1: Register EtherNet/IP session on port 44818\n"
            "Phase 2: Send CIP List Tags service (service code 0x55)\n"
            "Phase 3: Receive full tag database — all tag names, types, dimensions\n"
            "Phase 4: Send CIP Read Tag service for each tag — read all values\n"
            "Reveals: Complete process state, setpoints, counts, status bits"
        ),
    ),
    dict(
        subdir="enip", filename="cip_multi_request_dos.py",
        name="EtherNet/IP CIP Multi-Request DoS",
        short_desc="EtherNet/IP CIP Multiple Service Packet abuse — send oversized multi-request to crash EIP stack.",
        description="The CIP Multiple Service Packet (service 0x0A) allows bundling multiple requests. "
                    "Crafted malformed multi-request can overflow CIP stack on susceptible PLCs.",
        proto="EtherNet/IP", port=44818,
        impact="HIGH",
        refs=["https://www.cisa.gov/uscert/ics/advisories/ICSA-12-018-01"],
        devices=["Rockwell PLCs", "Generic EtherNet/IP devices"],
        mitre=["T0814"],
        tactics=["Inhibit Response Function"],
        simulation_steps=(
            "Phase 1: Register EtherNet/IP session on port 44818\n"
            "Phase 2: Build CIP Multiple Service Packet (0x0A) with 100+ nested services\n"
            "Phase 3: Set malformed service count causing buffer overread\n"
            "Phase 4: PLC EIP stack crashes or enters fault state\n"
            "Recovery: PLC requires power cycle to restore communications"
        ),
    ),
    dict(
        subdir="modbus", filename="modbus_write_coil_flood.py",
        name="Modbus Write Single Coil Flood",
        short_desc="Flood Modbus FC05 (Write Single Coil) to rapidly toggle digital outputs — physical process disruption.",
        description="Rapidly toggling digital output coils via Modbus FC05 can damage field equipment (solenoids, relays, actuators) "
                    "through excessive switching cycles and cause process instability.",
        proto="Modbus", port=502,
        impact="HIGH",
        refs=["https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf"],
        devices=["Any Modbus TCP device", "PLCs", "RTUs"],
        mitre=["T0836","T0814"],
        tactics=["Impair Process Control"],
        simulation_steps=(
            "Phase 1: Connect to Modbus TCP port 502\n"
            "Phase 2: Send FC05 Write Single Coil: coil=0, value=0xFF00 (ON)\n"
            "Phase 3: Immediately send FC05: coil=0, value=0x0000 (OFF)\n"
            "Phase 4: Repeat at 1000 Hz — 1000 toggles/second\n"
            "Physical damage: Solenoid/relay burnout, actuator wear, valve damage"
        ),
    ),
    dict(
        subdir="modbus", filename="modbus_unauthorized_coil_set.py",
        name="Modbus Unauthorized Output Coil Write",
        short_desc="Modbus FC05/FC15 coil write without authentication — set PLC digital outputs to arbitrary state.",
        description="Modbus TCP has no authentication. Any host on the network can write any coil/register. "
                    "This allows unauthorized control of PLC digital outputs controlling physical actuators.",
        proto="Modbus", port=502,
        impact="CRITICAL",
        refs=["https://www.cisa.gov/sites/default/files/recommended_practices/NCCIC_ICS-CERT_Defense_in_Depth_2016_S508C.pdf"],
        devices=["Any Modbus TCP PLC/RTU", "Process control systems"],
        mitre=["T1692.001","T0836"],
        tactics=["Impair Process Control"],
        simulation_steps=(
            "Phase 1: Connect TCP to port 502 (no auth)\n"
            "Phase 2: FC01 Read Coils — determine current coil states\n"
            "Phase 3: FC05 Write Single Coil — set output coil to target state\n"
            "Phase 4: FC03 Verify write — confirm state change\n"
            "Impact: Actuators, valves, motors controlled by attacker"
        ),
    ),
    dict(
        subdir="cc_link", filename="cc_link_ie_broadcast_stop.py",
        name="CC-Link IE Field Network Broadcast Stop",
        short_desc="CC-Link IE Field Network cyclic communication stop via broadcast — Mitsubishi PLC communication disruption.",
        description="CC-Link IE Field Network (Mitsubishi) uses cyclic communication without authentication. "
                    "Broadcast frames with station address 0xFF can disrupt all connected stations.",
        proto="CC-Link IE", port=61450,
        impact="HIGH",
        refs=["https://www.cc-link.org/en/cclink/index.html"],
        devices=["Mitsubishi iQ-R PLCs", "CC-Link IE Field stations", "Mitsubishi servo drives"],
        mitre=["T0814"],
        tactics=["Inhibit Response Function"],
        simulation_steps=(
            "Phase 1: Connect to CC-Link IE Field master on UDP/61450\n"
            "Phase 2: Send cyclic data request with broadcast station number (0xFF)\n"
            "Phase 3: All slave stations receive conflicting cyclic data\n"
            "Phase 4: CC-Link IE network enters error state\n"
            "Phase 5: Mitsubishi PLCs stop receiving input data — outputs hold last state"
        ),
    ),
    dict(
        subdir="s7", filename="s7_cpu_time_manipulate.py",
        name="Siemens S7 CPU Clock Manipulation",
        short_desc="Siemens S7comm SET_DATETIME without authentication — manipulate PLC real-time clock, disrupt time-based logic.",
        description="S7comm allows setting the PLC system clock without authentication on S7-300/400. "
                    "Time-based logic (schedules, time stamps, alarms) can be disrupted by setting clock forward/backward.",
        proto="S7comm", port=102,
        impact="MEDIUM",
        refs=["https://scadahacker.com/resources/s7comm.html"],
        devices=["Siemens S7-300", "Siemens S7-400", "Legacy S7 PLCs"],
        mitre=["T0836","T0832"],
        tactics=["Impair Process Control"],
        simulation_steps=(
            "Phase 1: Establish S7comm connection on TCP/102 (COTP + S7comm)\n"
            "Phase 2: Send SET_DATETIME request with manipulated timestamp\n"
            "Phase 3: PLC system clock set to target date/time\n"
            "Phase 4: Time-based scheduled events trigger at wrong time\n"
            "Phase 5: Alarm timestamps incorrect — forensic audit trails corrupted"
        ),
    ),
    dict(
        subdir="s7", filename="s7_read_system_status.py",
        name="Siemens S7 System Status Read",
        short_desc="S7comm read system status without authentication — enumerate PLC CPU, firmware, memory, running modules.",
        description="Siemens S7comm allows extensive system information read without authentication: "
                    "CPU type, firmware version, memory usage, loaded modules, and network configuration.",
        proto="S7comm", port=102,
        impact="LOW",
        refs=["https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-s7comm.c"],
        devices=["All Siemens S7 PLCs"],
        mitre=["T0888","T0802"],
        tactics=["Discovery"],
        simulation_steps=(
            "Phase 1: Connect to S7 on port 102 via COTP\n"
            "Phase 2: S7comm Read SZL (System Status List) 0x0011 — CPU ID\n"
            "Phase 3: SZL 0x0131 — diagnostic buffer\n"
            "Phase 4: SZL 0x0174 — module info (firmware, serial, order no.)\n"
            "Phase 5: SZL 0x0232 — communication info\n"
            "Output: Complete PLC fingerprint for targeted attack planning"
        ),
    ),
    dict(
        subdir="serial", filename="serial_to_ethernet_pass_replay.py",
        name="Serial-to-Ethernet Gateway Protocol Replay",
        short_desc="Serial-to-Ethernet gateways (Moxa, Lantronix, Digi) forward raw Modbus/DNP3 serial frames without validation.",
        description="Serial-to-Ethernet converters used in OT act as transparent tunnels — they do not validate "
                    "or authenticate the serial protocol frames. Attacker with TCP access can replay or inject "
                    "any Modbus RTU or DNP3 serial frame to the connected field device.",
        proto="Raw TCP (serial tunnel)", port=4001,
        impact="HIGH",
        refs=["https://www.moxa.com/getmedia/"],
        devices=["Moxa NPort 5xxx", "Lantronix UDS/WiPort", "Digi PortServer"],
        mitre=["T0848","T0836"],
        tactics=["Impair Process Control"],
        simulation_steps=(
            "Phase 1: Connect TCP to serial-to-Ethernet gateway port 4001\n"
            "Phase 2: Send raw Modbus RTU frame (with CRC) directly over TCP\n"
            "Phase 3: Gateway forwards frame transparently to serial RS485 bus\n"
            "Phase 4: Modbus slave device responds to attacker's command\n"
            "Phase 5: Replay captured legitimate frames — complete process control"
        ),
    ),
]


def main():
    created = 0
    for item in BATCH:
        if make(**item):
            created += 1
            print(f"  Created: {item['filename']}")
    
    from industrialxpl.core.exploit.utils import index_modules
    mods = index_modules()
    print(f"\n[batch_nocve_wave2] Created: {created} | Total: {len(mods)} modules")


if __name__ == "__main__":
    main()
