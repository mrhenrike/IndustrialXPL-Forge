"""OT Hunt Scanner — OSINT-based OT/ICS Device Detection.

Implements targeted probes for three device categories identified in
ZeronTek OT Hunt research reports:

  1. Honeywell IQ4E — BACnet/IP probe (UDP 47808) checking for controller
     identification in the Who-Is / I-Am exchange.

  2. Schneider SCADAPack — dual probe:
     - VxWorks debug interface (UDP 17185) used in the 2023 CISA advisory
     - Modbus TCP banner (TCP 502) for SCADAPack identification.

  3. Unitronics PCOM — TCP 20256 probe using the PCOM ASCII GET_ID command,
     as documented in CISA advisory AA23-335A (2023 IRGC cyberattacks on US water).

All probes are read-only. Simulate mode describes what would be probed
without sending any packets.

References:
    CISA ICSA-22-242-08 (Honeywell IQ4E)
    CISA ICSA-10-214-01 (Schneider SCADAPack)
    CISA AA23-335A (Unitronics PCOM — 2023 water sector attacks)
    ZeronTek OT Hunt reports
"""

import socket
import struct

from industrialxpl.core.exploit import (
    Exploit,
    OptBool,
    OptIP,
    OptInteger,
    OptPort,
    OptString,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
    DestructiveGate,
)

# ---- BACnet Who-Is probe (Honeywell IQ4E) ----
_BACNET_PORT = 47808
_BACNET_WHO_IS = bytes([
    0x81, 0x0B, 0x00, 0x0C,  # BVLC: BACnet/IP, Original-Broadcast-NPDU, len=12
    0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF,  # NPDU
    0x10, 0x08,  # APDU: Unconfirmed-Req, Who-Is
])

# ---- VxWorks WDB debug probe (Schneider SCADAPack) ----
_VXWORKS_PORT = 17185
# WDB (Wind River Debug Agent) RPC ping: portmapper-style probe
_VXWORKS_PROBE = bytes([
    0x72, 0x70, 0x63, 0x00,  # magic "rpc\x00"
    0x00, 0x00, 0x00, 0x01,  # call (1)
    0x00, 0x00, 0x00, 0x02,  # version 2
    0x00, 0x01, 0x86, 0xA5,  # WDB program 100005
    0x00, 0x00, 0x00, 0x01,  # version 1
    0x00, 0x00, 0x00, 0x00,  # NULLPROC
    0x00, 0x00, 0x00, 0x00,  # credentials
    0x00, 0x00, 0x00, 0x00,  # verifier
])

# ---- Modbus device ID request (port 502) ----
_MODBUS_PORT = 502
_MODBUS_READ_ID = struct.pack(">HHHBBBB", 0x0001, 0, 4, 0xFF, 0x2B, 0x0E, 0x01)

# ---- Unitronics PCOM GET_ID probe (port 20256) ----
_PCOM_PORT = 20256
# PCOM ASCII command: /UNITID001CC5A  (unit 1, checksum placeholder)
# Format: '/' + PLCID(3) + 'UNI' + 'TID' + unit(2) + checksum(2) + '\r'
_PCOM_PROBE = b"/001UNLGTELID\r"  # simplified GET_ID (UNLGT = Get PLC type)


class Exploit(Exploit):
    __info__ = {
        "name":         "OT Hunt Scanner — Honeywell IQ4E / Schneider SCADAPack / Unitronics PCOM",
        "description":  "Read-only OT/ICS device scanner implementing three targeted probes "
                        "from ZeronTek OT Hunt research: (1) Honeywell IQ4E via BACnet Who-Is "
                        "broadcast on UDP 47808, (2) Schneider SCADAPack via VxWorks debug "
                        "probe on UDP 17185 and Modbus banner on TCP 502, "
                        "(3) Unitronics Vision/Samba via PCOM GET_ID on TCP 20256. "
                        "All probes are read-only — no configuration change or disruption.",
        "authors":      ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":   (
            "https://www.cisa.gov/news-events/ics-advisories/icsa-22-242-08",
            "https://www.cisa.gov/news-events/ics-advisories/icsa-10-214-01",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a",
            "https://attack.mitre.org/techniques/T0846/",
        ),
        "devices":      (
            "Honeywell IQ4E building controller",
            "Schneider SCADAPack RTU",
            "Unitronics Vision / Samba PLC (PCOM protocol)",
        ),
        "impact":       "INFO",
        "exploit_type": "OSINT / Read-only Device Discovery",
        "source_poc":   "ZeronTek OT Hunt + CISA advisories (Python native)",
        "cve":          "N/A",
        "cvss":         "N/A",
        "severity":     "INFO",
        "mitre_techniques": ["T0846", "T0888"],
        "mitre_tactics":    ["Discovery"],
        "destructive_description": "Read-only probes — no device disruption expected.",
    }

    target      = OptIP("", "Target IP to probe")
    check_type  = OptString("ALL", "Probe type: HONEYWELL | SCADAPACK | UNITRONICS | ALL")
    timeout     = OptInteger(3, "Socket timeout in seconds")
    simulate    = OptBool(True, "Simulate mode (default: True)")
    destructive = OptBool(False, "Not applicable — probes are read-only")

    @mute
    def check(self) -> bool:
        """Return True if any targeted port is reachable."""
        if not self.target:
            return False
        for port, proto in [(_BACNET_PORT, "UDP"), (_MODBUS_PORT, "TCP"), (_PCOM_PORT, "TCP")]:
            try:
                if proto == "TCP":
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                if proto == "TCP":
                    s.connect((self.target, port))
                else:
                    s.sendto(_BACNET_WHO_IS, (self.target, port))
                    s.recvfrom(256)
                s.close()
                return True
            except Exception:
                pass
        return False

    def _probe_honeywell(self) -> None:
        """Probe Honeywell IQ4E via BACnet Who-Is on UDP 47808."""
        print_status("  [Honeywell IQ4E] BACnet Who-Is -> {}:{}/UDP ...".format(
            self.target, _BACNET_PORT
        ))
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(_BACNET_WHO_IS, (self.target, _BACNET_PORT))
            try:
                data, addr = sock.recvfrom(512)
                hex_resp = data[:16].hex()
                if len(data) > 4 and data[0] == 0x81:
                    print_success(
                        "  [Honeywell IQ4E] BACnet I-Am from {} ({} bytes): {} ...".format(
                            addr[0], len(data), hex_resp
                        )
                    )
                    print_info(
                        "  CISA ICSA-22-242-08: Honeywell IQ4E responded — "
                        "potential unauthenticated BACnet exposure."
                    )
                else:
                    print_info("  [Honeywell IQ4E] Response from {} (non-BACnet): {} bytes".format(
                        addr[0], len(data)
                    ))
            except socket.timeout:
                print_info("  [Honeywell IQ4E] No BACnet response (timeout).")
            sock.close()
        except Exception as exc:
            print_error("  [Honeywell IQ4E] Error: {}".format(exc))

    def _probe_scadapack(self) -> None:
        """Probe Schneider SCADAPack via VxWorks debug (UDP 17185) and Modbus (TCP 502)."""
        print_status("  [SCADAPack] VxWorks WDB probe -> {}:{}/UDP ...".format(
            self.target, _VXWORKS_PORT
        ))
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(_VXWORKS_PROBE, (self.target, _VXWORKS_PORT))
            try:
                data, addr = sock.recvfrom(512)
                print_success(
                    "  [SCADAPack] VxWorks WDB response from {} ({} bytes) — "
                    "exposed debug agent (ICSA-10-214-01)!".format(addr[0], len(data))
                )
            except socket.timeout:
                print_info("  [SCADAPack] No VxWorks WDB response.")
            sock.close()
        except Exception as exc:
            print_error("  [SCADAPack] VxWorks probe error: {}".format(exc))

        print_status("  [SCADAPack] Modbus banner -> {}:{}/TCP ...".format(
            self.target, _MODBUS_PORT
        ))
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, _MODBUS_PORT))
            sock.send(_MODBUS_READ_ID)
            try:
                data = sock.recv(256)
                print_success(
                    "  [SCADAPack] Modbus response ({} bytes): {}".format(
                        len(data), data[:16].hex()
                    )
                )
            except socket.timeout:
                print_info("  [SCADAPack] No Modbus response.")
            sock.close()
        except Exception as exc:
            print_error("  [SCADAPack] Modbus probe error: {}".format(exc))

    def _probe_unitronics(self) -> None:
        """Probe Unitronics PLC via PCOM GET_ID on TCP 20256."""
        print_status("  [Unitronics PCOM] GET_ID probe -> {}:{}/TCP ...".format(
            self.target, _PCOM_PORT
        ))
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, _PCOM_PORT))
            sock.send(_PCOM_PROBE)
            try:
                data = sock.recv(256)
                if data:
                    decoded = data.decode("ascii", errors="replace").strip()
                    print_success(
                        "  [Unitronics PCOM] Response from {} ({} bytes): '{}'".format(
                            self.target, len(data), decoded[:80]
                        )
                    )
                    print_info(
                        "  CISA AA23-335A: Unitronics PCOM exposed on TCP 20256 — "
                        "no authentication required (IRGC 2023 water sector attack vector)."
                    )
            except socket.timeout:
                print_info("  [Unitronics PCOM] No PCOM response.")
            sock.close()
        except Exception as exc:
            print_error("  [Unitronics PCOM] Error: {}".format(exc))

    def run(self) -> None:
        if not self.target:
            print_error("Set 'target' option first.")
            return

        check = self.check_type.upper()

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "Would run OT Hunt probes against {target} (type={check}): "
                    "(1) Honeywell IQ4E: BACnet Who-Is to UDP {b_port} — "
                    "checks for unauthenticated BACnet exposure (ICSA-22-242-08); "
                    "(2) Schneider SCADAPack: VxWorks WDB to UDP {v_port} and "
                    "Modbus banner to TCP {m_port} (ICSA-10-214-01); "
                    "(3) Unitronics PCOM: GET_ID to TCP {p_port} — "
                    "2023 IRGC water utility attack vector (AA23-335A). "
                    "All probes are read-only.".format(
                        target=self.target,
                        check=check,
                        b_port=_BACNET_PORT,
                        v_port=_VXWORKS_PORT,
                        m_port=_MODBUS_PORT,
                        p_port=_PCOM_PORT,
                    )
                ),
                payload_hex=" ".join("{:02X}".format(b) for b in _BACNET_WHO_IS),
                payload_human="BACnet Who-Is (example probe — read-only)",
                mitre_techniques=["T0846", "T0888"],
            )
            print_info("\nProbes that would be executed:")
            print_info("  Honeywell IQ4E : BACnet Who-Is -> UDP {} (ICSA-22-242-08)".format(_BACNET_PORT))
            print_info("  SCADAPack      : VxWorks WDB   -> UDP {} (ICSA-10-214-01)".format(_VXWORKS_PORT))
            print_info("  SCADAPack      : Modbus banner -> TCP {}".format(_MODBUS_PORT))
            print_info("  Unitronics     : PCOM GET_ID   -> TCP {} (AA23-335A)".format(_PCOM_PORT))
            return

        print_status("OT Hunt scanner targeting {} (type={}) ...".format(self.target, check))

        if check in ("HONEYWELL", "ALL"):
            self._probe_honeywell()

        if check in ("SCADAPACK", "ALL"):
            self._probe_scadapack()

        if check in ("UNITRONICS", "ALL"):
            self._probe_unitronics()

        print_status("OT Hunt scan complete.")
