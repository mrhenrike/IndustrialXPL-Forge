"""ModbusBaseExploit - base class for all IXF Modbus scanner/exploit modules.

Common options (all displayed in UPPERCASE in show options):
  TARGET     - IP / hostname of the Modbus device
  PORT       - single port or range: 502 | 502,510 | 500-510
  UNIT_ID    - Modbus Unit ID / slave address (0-247)
  REGISTERS  - register/holding address expression: 0-9 | 40001-40010 | 10,14-20
  COILS      - coil/discrete-input address expression: 0-7 | 00001-00100
  FC         - function code override (0=auto, 1-4=read, 5-6=write)
  TIMING     - T0-T5 scan timing profile (like Nmap -T<n>)
  TIMEOUT    - socket timeout override in seconds (0=use TIMING default)

Options are case-insensitive: 'set TARGET', 'set target', and 'set Target' all work.
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

    # --- Options (displayed in UPPERCASE by the CLI) ---
    target    = OptIP("",    "Target Modbus TCP device IP or hostname")
    port      = _OptPortExpr("502",
                    "Port(s): 502 | 502,510 | 500-510 (set PORT ? for help)")
    unit_id   = OptInteger(1,
                    "Modbus Unit ID / slave address 0-247 (set UNIT_ID ? for help)",
                    min_value=0, max_value=247)
    registers = _OptRegisterExpr("",
                    "Holding/input register addresses: 0-9 | 40001-40010 | 10,14-20\n"
                    "           Modicon 5-digit notation: 40001=HR1(FC3), 30001=IR1(FC4)\n"
                    "           Empty = module default  (set REGISTERS ? for full syntax)")
    coils     = _OptRegisterExpr("",
                    "Coil / discrete-input addresses: 0-7 | 0-100 | 10,20-30\n"
                    "           Modicon notation: 00001=coil1(FC1), 10001=DI1(FC2)\n"
                    "           When set, FC is forced to 1 (or 2 for discrete inputs)\n"
                    "           Takes precedence over REGISTERS if both are set\n"
                    "           Empty = not used  (set COILS ? for full syntax)")
    fc        = OptInteger(0,
                    "Function code override (0=auto):\n"
                    "           FC1=Read Coils  FC2=Discrete Inputs  FC3=Hold Regs  FC4=Input Regs\n"
                    "           FC5=Write Coil  FC6=Write Register   (set FC ? for help)")
    timing    = _OptTiming("T3",
                    "Scan timing: T<n> number OR slug name (like Nmap -T<n>):\n"
                    "           T0/paranoid  T1/sneaky  T2/polite  T3/normal  T4/aggressive  T5/insane\n"
                    "           Both 'set TIMING T3' and 'set TIMING normal' are accepted.\n"
                    "           (set TIMING ? for full table)")
    timeout   = OptInteger(0,
                    "Socket timeout override in seconds (0 = use TIMING profile default)")

    # --- Helpers ---

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
        """Resolve address set from COILS or REGISTERS option.

        COILS takes precedence when set; implied FC is 1 (coils).
        Falls back to REGISTERS, then module default.
        """
        coils_expr = str(self.coils).strip()
        if coils_expr:
            addr_set = parse_modbus_addresses(coils_expr)
            # Force implied FC to 1 if not already specified by notation
            if addr_set.implied_fc is None:
                for a in addr_set.addresses:
                    if a.implied_fc is None:
                        a.implied_fc = 1
                        a.data_type = "coil"
                addr_set.implied_fc = 1
            return addr_set

        reg_expr = str(self.registers).strip()
        if not reg_expr:
            reg_expr = default or self._DEFAULT_REGS
        return parse_modbus_addresses(reg_expr)

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
        _FC_NAMES = {
            1: "Read Coils",           2: "Read Discrete Inputs",
            3: "Read Holding Regs",    4: "Read Input Regs",
            5: "Write Single Coil",    6: "Write Single Register",
            17: "Report Server ID",    43: "Read Device ID (MEI)",
        }
        src = "COILS" if str(self.coils).strip() else "REGISTERS"
        fc_label = _FC_NAMES.get(fc, "FC{:02d}".format(fc))
        addr_preview = ", ".join(str(a.offset) for a in list(addr_set)[:8])
        if len(addr_set) > 8:
            addr_preview += "..."
        print_info("  FC{:02d} ({}) via {}: {} addresses [{}], start={} qty={}".format(
            fc, fc_label, src, len(addr_set), addr_preview, start, qty
        ))

    @staticmethod
    def timing_help() -> str:
        from industrialxpl.core.modbus.timing import ModbusTiming
        return ModbusTiming.describe_all()
