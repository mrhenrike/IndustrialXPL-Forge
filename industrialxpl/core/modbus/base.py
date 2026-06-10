"""ModbusBaseExploit — base class for all IXF Modbus scanner/exploit modules.

Provides common options:
  target     — IP / hostname
  port       — single port OR range (502, 500-510, 502,510)
  unit_id    — Modbus Unit ID / slave address (1-247)
  registers  — address expression: 10, 14-20, 40001-40010, 40001,41000
  fc         — function code override (0 = use module default)
  timing     — T0-T5 timing profile (default T3 = Normal, like Nmap -T3)
  timeout    — per-socket timeout in seconds (overrides timing.socket_timeout)
"""

from __future__ import annotations

from typing import List, Optional

from industrialxpl.core.exploit.exploit import Exploit
from industrialxpl.core.exploit.option import (
    OptIP, OptString, OptInteger, OptBool,
)
from industrialxpl.core.exploit.printer import print_info, print_warning
from industrialxpl.core.modbus.address import (
    ModbusAddressSet, parse_modbus_addresses,
)
from industrialxpl.core.modbus.timing import (
    ModbusTiming, TimingProfile, DEFAULT_TIMING, TIMING_PROFILES,
)
from industrialxpl.core.modbus.transport import (
    ModbusTCPSocket, parse_port_expression,
)

# Default Modbus data registers for when no expression is provided
_DEFAULT_REGISTER_EXPR = "0-9"
_DEFAULT_COIL_EXPR     = "0-7"


class _OptTiming(OptString):
    """Option descriptor for Modbus timing profile (T0-T5 or name)."""

    def validate(self, value) -> str:
        try:
            ModbusTiming.resolve(value)
        except ValueError as exc:
            from industrialxpl.core.exploit.exceptions import OptionValidationError
            raise OptionValidationError(str(exc))
        return str(value)


class _OptPortExpr(OptString):
    """Option descriptor for port expression (single, list, range)."""

    def validate(self, value) -> str:
        try:
            parse_port_expression(str(value))
        except ValueError as exc:
            from industrialxpl.core.exploit.exceptions import OptionValidationError
            raise OptionValidationError(str(exc))
        return str(value)


class _OptRegisterExpr(OptString):
    """Option descriptor for Modbus address/register expression."""

    def validate(self, value) -> str:
        if not str(value).strip():
            return ""  # empty = use module default
        try:
            parse_modbus_addresses(str(value))
        except ValueError as exc:
            from industrialxpl.core.exploit.exceptions import OptionValidationError
            raise OptionValidationError(str(exc))
        return str(value)


class ModbusBaseExploit(Exploit):
    """Base class for Modbus scanner and exploit modules.

    Subclasses should override:
      - _DEFAULT_FC   : int  — default function code when fc=0
      - _DEFAULT_REGS : str  — default register expression when registers is empty
      - run()         : implement the actual module logic
      - check()       : optional read-only fingerprint

    Common pattern in run():

        for port in self._get_ports():
            with ModbusTCPSocket(self.target, port, self.unit_id, self._get_timing()) as sock:
                addr_set = self._get_addresses()
                fc = self._resolve_fc()
                start, qty = addr_set.as_bulk()
                data = sock.send_fc(fc, start, qty)
                ...
    """

    _DEFAULT_FC:   int = 3    # FC3 Read Holding Registers
    _DEFAULT_REGS: str = "0-9"

    # ── Options ───────────────────────────────────────────────────────────────
    target    = OptIP("",    "Target Modbus TCP device IP or hostname")
    port      = _OptPortExpr("502",
                    "Port(s): single (502), list (502,510), range (500-510)")
    unit_id   = OptInteger(1,
                    "Modbus Unit ID / slave address (1-247)",
                    min_value=0, max_value=247)
    registers = _OptRegisterExpr("",
                    "Register/coil address(es): 0-9, 40001-40010, 10,14-20,100\n"
                    "           Schneider/Modicon notation accepted (40001 = HR1, 00001 = coil1)\n"
                    "           Empty = use module default range")
    fc        = OptInteger(0,
                    "Function code override (0 = module default):\n"
                    "           FC1=Read Coils  FC2=Discrete Inputs  FC3=Hold Regs  FC4=Input Regs\n"
                    "           FC5=Write Coil  FC6=Write Register")
    timing    = _OptTiming("T3",
                    "Timing profile T0-T5 (like Nmap -T<n>):\n"
                    "           T0=Paranoid T1=Sneaky T2=Polite T3=Normal T4=Aggressive T5=Insane")
    timeout   = OptInteger(0,
                    "Socket timeout override in seconds (0 = use timing profile default)")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_timing(self) -> TimingProfile:
        """Resolve timing profile and apply timeout override if set."""
        profile = ModbusTiming.resolve(self.timing)
        if self.timeout and int(self.timeout) > 0:
            # Build a copy with overridden socket_timeout
            import dataclasses
            profile = dataclasses.replace(
                profile,
                socket_timeout=float(self.timeout),
                max_rtt_timeout=float(self.timeout),
            )
        return profile

    def _get_ports(self) -> List[int]:
        """Return list of ports from the port expression."""
        return parse_port_expression(str(self.port))

    def _get_addresses(self, default: str = "") -> ModbusAddressSet:
        """Parse register expression; fall back to module or caller default."""
        expr = str(self.registers).strip()
        if not expr:
            expr = default or self._DEFAULT_REGS
        return parse_modbus_addresses(expr)

    def _resolve_fc(self, implied_fc: Optional[int] = None) -> int:
        """Return the effective function code.

        Priority: explicit set fc > implied_fc from address notation > _DEFAULT_FC
        """
        if int(self.fc) != 0:
            return int(self.fc)
        if implied_fc is not None:
            return implied_fc
        return self._DEFAULT_FC

    def _print_timing(self) -> None:
        profile = self._get_timing()
        print_info("  Timing  : {}".format(profile))

    def _print_address_plan(self, addr_set: ModbusAddressSet, fc: int) -> None:
        start, qty = addr_set.as_bulk()
        print_info(
            "  FC{:02d}    : addresses {} ({} addr), bulk start={} qty={}".format(
                fc,
                ", ".join(str(a.offset) for a in list(addr_set)[:8])
                + ("…" if len(addr_set) > 8 else ""),
                len(addr_set),
                start,
                qty,
            )
        )

    @staticmethod
    def timing_help() -> str:
        from industrialxpl.core.modbus.timing import ModbusTiming
        return ModbusTiming.describe_all()
