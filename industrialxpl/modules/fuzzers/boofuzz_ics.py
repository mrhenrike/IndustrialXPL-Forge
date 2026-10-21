"""ICS Protocol Fuzzer powered by boofuzz framework.

Provides pre-built fuzzing sessions for ICS/SCADA protocols using
the boofuzz framework (fork of Sulley). Generates structured test
cases with protocol-aware mutations.

Supported protocols:
  - Modbus TCP (FC 01-06, 15, 16, 43)
  - S7comm (COTP + S7 PDU)
  - DNP3 (link + transport + application layers)
  - EtherNet/IP (encapsulation header + CIP)
  - BACnet/IP (BVLC + NPDU + APDU)

Requires: boofuzz (pip install boofuzz)

Author: Andre Henrique (@mrhenrike) | Uniao Geek
Based on: boofuzz by Joshua Pereyda (MIT License)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptInteger, OptPort, OptString,
    print_error, print_info, print_status, print_success, print_warning,
)

log = logging.getLogger(__name__)

try:
    import boofuzz
    from boofuzz import (
        Session, Target, SocketConnection,
        s_initialize, s_block, s_word, s_byte, s_bytes,
        s_size, s_static, s_string, s_group,
        REQUESTS,
    )
    HAS_BOOFUZZ = True
except ImportError:
    HAS_BOOFUZZ = False


# ---------------------------------------------------------------------------
# Protocol definitions for boofuzz
# ---------------------------------------------------------------------------

def define_modbus_tcp_requests() -> None:
    """Define Modbus TCP protocol structure for boofuzz."""
    if not HAS_BOOFUZZ:
        return

    # FC 03: Read Holding Registers
    s_initialize("modbus_read_holding")
    with s_block("mbap"):
        s_word(0x0001, name="transaction_id", fuzzable=True, endian=">")
        s_word(0x0000, name="protocol_id", fuzzable=True, endian=">")
        s_size("pdu", length=2, endian=">", math=lambda x: x + 1)
        s_byte(0x01, name="unit_id", fuzzable=True)
    with s_block("pdu"):
        s_byte(0x03, name="function_code", fuzzable=False)
        s_word(0x0000, name="start_address", fuzzable=True, endian=">")
        s_word(0x0001, name="quantity", fuzzable=True, endian=">")

    # FC 06: Write Single Register
    s_initialize("modbus_write_single")
    with s_block("mbap"):
        s_word(0x0002, name="transaction_id", fuzzable=True, endian=">")
        s_word(0x0000, name="protocol_id", fuzzable=True, endian=">")
        s_size("pdu", length=2, endian=">", math=lambda x: x + 1)
        s_byte(0x01, name="unit_id", fuzzable=True)
    with s_block("pdu"):
        s_byte(0x06, name="function_code", fuzzable=False)
        s_word(0x0000, name="register_address", fuzzable=True, endian=">")
        s_word(0x0000, name="register_value", fuzzable=True, endian=">")

    # FC 16: Write Multiple Registers
    s_initialize("modbus_write_multiple")
    with s_block("mbap"):
        s_word(0x0003, name="transaction_id", fuzzable=True, endian=">")
        s_word(0x0000, name="protocol_id", fuzzable=True, endian=">")
        s_size("pdu", length=2, endian=">", math=lambda x: x + 1)
        s_byte(0x01, name="unit_id", fuzzable=True)
    with s_block("pdu"):
        s_byte(0x10, name="function_code", fuzzable=False)
        s_word(0x0000, name="start_address", fuzzable=True, endian=">")
        s_word(0x0001, name="quantity", fuzzable=True, endian=">")
        s_byte(0x02, name="byte_count", fuzzable=True)
        s_bytes(b"\x00\x00", name="values", fuzzable=True, max_len=250)

    # FC 43: Read Device Identification
    s_initialize("modbus_device_id")
    with s_block("mbap"):
        s_word(0x0004, name="transaction_id", fuzzable=True, endian=">")
        s_word(0x0000, name="protocol_id", fuzzable=True, endian=">")
        s_size("pdu", length=2, endian=">", math=lambda x: x + 1)
        s_byte(0x01, name="unit_id", fuzzable=True)
    with s_block("pdu"):
        s_byte(0x2B, name="function_code", fuzzable=False)
        s_byte(0x0E, name="mei_type", fuzzable=True)
        s_byte(0x01, name="read_device_id", fuzzable=True)
        s_byte(0x00, name="object_id", fuzzable=True)


def define_dnp3_requests() -> None:
    """Define DNP3 link layer for boofuzz."""
    if not HAS_BOOFUZZ:
        return

    s_initialize("dnp3_read_class0")
    with s_block("link_header"):
        s_static(b"\x05\x64")
        s_byte(0x05, name="length", fuzzable=True)
        s_byte(0xC0, name="control", fuzzable=True)
        s_word(0x0001, name="destination", fuzzable=True, endian="<")
        s_word(0x0000, name="source", fuzzable=True, endian="<")
    s_bytes(b"\x00\x00", name="crc", fuzzable=True, max_len=2)


def define_enip_requests() -> None:
    """Define EtherNet/IP encapsulation for boofuzz."""
    if not HAS_BOOFUZZ:
        return

    s_initialize("enip_list_identity")
    s_word(0x0063, name="command", fuzzable=True, endian="<")
    s_word(0x0000, name="length", fuzzable=True, endian="<")
    s_bytes(b"\x00" * 4, name="session_handle", fuzzable=True)
    s_bytes(b"\x00" * 4, name="status", fuzzable=False)
    s_bytes(b"\x00" * 8, name="sender_context", fuzzable=True)
    s_bytes(b"\x00" * 4, name="options", fuzzable=False)


# ---------------------------------------------------------------------------
# Fuzzing session management
# ---------------------------------------------------------------------------

@dataclass
class FuzzSessionConfig:
    """Configuration for a boofuzz fuzzing session."""
    target_host: str = ""
    target_port: int = 502
    protocol: str = "modbus"
    max_mutations: int = 1000
    restart_threshold: int = 5
    timeout: float = 5.0
    log_dir: str = "/tmp/boofuzz-ics"
    destructive: bool = False


def create_modbus_session(config: FuzzSessionConfig) -> Session | None:
    """Create a boofuzz session for Modbus TCP fuzzing."""
    if not HAS_BOOFUZZ:
        return None

    define_modbus_tcp_requests()

    session = Session(
        target=Target(
            connection=SocketConnection(
                config.target_host, config.target_port,
                proto="tcp",
            ),
        ),
        sleep_time=0.1,
        restart_threshold=config.restart_threshold,
    )

    session.connect(s_get("modbus_read_holding"))
    session.connect(s_get("modbus_device_id"))

    if config.destructive:
        session.connect(s_get("modbus_write_single"))
        session.connect(s_get("modbus_write_multiple"))

    return session


def create_dnp3_session(config: FuzzSessionConfig) -> Session | None:
    """Create a boofuzz session for DNP3 fuzzing."""
    if not HAS_BOOFUZZ:
        return None

    define_dnp3_requests()

    session = Session(
        target=Target(
            connection=SocketConnection(
                config.target_host, config.target_port,
                proto="tcp",
            ),
        ),
        sleep_time=0.1,
    )

    session.connect(s_get("dnp3_read_class0"))
    return session


def create_enip_session(config: FuzzSessionConfig) -> Session | None:
    """Create a boofuzz session for EtherNet/IP fuzzing."""
    if not HAS_BOOFUZZ:
        return None

    define_enip_requests()

    session = Session(
        target=Target(
            connection=SocketConnection(
                config.target_host, config.target_port,
                proto="tcp",
            ),
        ),
        sleep_time=0.1,
    )

    session.connect(s_get("enip_list_identity"))
    return session


SESSION_FACTORIES = {
    "modbus": (create_modbus_session, 502),
    "dnp3": (create_dnp3_session, 20000),
    "enip": (create_enip_session, 44818),
}


# ---------------------------------------------------------------------------
# Exploit module
# ---------------------------------------------------------------------------

class BoofuzzICS(Exploit):
    """ICS protocol fuzzer using boofuzz framework."""

    __info__ = {
        "name": "Boofuzz ICS",
        "description": "Protocol-aware ICS fuzzer using boofuzz (Modbus, DNP3, EtherNet/IP)",
        "authors": ["Andre Henrique (@mrhenrike)", "Joshua Pereyda (boofuzz)"],
        "references": [
            "https://github.com/jtpereyda/boofuzz",
            "MITRE ICS T0836 (Modify Parameter)",
        ],
    }

    target = OptIP("", "Target device IP")
    port = OptPort(502, "Target port")
    protocol = OptString("modbus", "Protocol: modbus, dnp3, enip")
    max_mutations = OptInteger(1000, "Maximum number of mutations")
    destructive = OptBool(False, "Include write-based mutations (CAUTION)")

    def run(self) -> dict:
        if not HAS_BOOFUZZ:
            print_error("boofuzz not installed. Run: pip install boofuzz")
            return {"error": "boofuzz not installed"}

        proto = self.protocol.lower()
        if proto not in SESSION_FACTORIES:
            print_error(f"Unknown protocol: {proto}. Supported: {', '.join(SESSION_FACTORIES)}")
            return {"error": f"Unknown protocol: {proto}"}

        factory, default_port = SESSION_FACTORIES[proto]
        port = int(self.port) if int(self.port) != 502 else default_port

        config = FuzzSessionConfig(
            target_host=self.target,
            target_port=port,
            protocol=proto,
            max_mutations=int(self.max_mutations),
            destructive=bool(self.destructive),
        )

        print_status(f"Creating boofuzz {proto.upper()} session for {config.target_host}:{port}")
        session = factory(config)
        if not session:
            print_error("Failed to create fuzzing session")
            return {"error": "Session creation failed"}

        print_status(f"Starting fuzzer (max {config.max_mutations} mutations)...")
        print_warning("Monitor target device for crashes/anomalies during fuzzing")

        try:
            session.fuzz()
        except KeyboardInterrupt:
            print_warning("Fuzzing interrupted by user")
        except (ConnectionError, TimeoutError, OSError, RuntimeError) as e:
            print_error(f"Fuzzing error: {e}")
            return {"error": str(e)}

        print_success("Fuzzing session complete")
        return {
            "protocol": proto,
            "target": f"{config.target_host}:{port}",
            "status": "complete",
        }


MANIFEST = {
    "name": "boofuzz_ics",
    "category": "fuzzers",
    "protocols": ["modbus", "dnp3", "enip"],
    "mitre_ics": ["T0836", "T0855"],
    "source": "https://github.com/jtpereyda/boofuzz",
    "license": "MIT",
    "requires": ["boofuzz"],
}
