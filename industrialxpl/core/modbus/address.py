"""Modbus address parser for IXF.

Suporta:
- Decimais simples:              10        -> [10]
- Ranges:                        14-20     -> [14,15,...,20]
- Listas mistas:                 10,14-20,100
- Notacao Schneider/Modicon 5 digitos:
    0xxxx  -> coils           (FC 1/5/15)  offset = addr - 1
    1xxxx  -> discrete inputs  (FC 2)       offset = addr - 10001
    3xxxx  -> input registers  (FC 4)       offset = addr - 30001
    4xxxx  -> holding registers (FC 3/6/16) offset = addr - 40001
- Notacao Modicon 6 digitos (prefixo 0-4 + 5 digitos):
    000001-065536, 100001-165536, 300001-365536, 400001-465536
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# FC implied by Modicon 5-digit prefix
_MODICON_5_FC = {
    "0": (1, "coil"),
    "1": (2, "discrete_input"),
    "3": (4, "input_register"),
    "4": (3, "holding_register"),
}

# FC implied by Modicon 6-digit prefix
_MODICON_6_FC = {
    "0": (1,  "coil"),
    "1": (2,  "discrete_input"),
    "3": (4,  "input_register"),
    "4": (3,  "holding_register"),
}

MAX_ADDR = 65535


@dataclass
class ModbusAddress:
    """A single resolved Modbus address."""

    raw: str
    offset: int
    implied_fc: Optional[int] = None
    data_type: Optional[str] = None

    def __repr__(self) -> str:
        fc_str = " (FC{})".format(self.implied_fc) if self.implied_fc else ""
        return "{}@{}{}".format(self.raw, self.offset, fc_str)


@dataclass
class ModbusAddressSet:
    """Collection of resolved Modbus addresses."""

    addresses: List[ModbusAddress] = field(default_factory=list)
    implied_fc: Optional[int] = None  # unanimous FC if all addresses agree

    def __len__(self) -> int:
        return len(self.addresses)

    def offsets(self) -> List[int]:
        return [a.offset for a in self.addresses]

    def __iter__(self):
        return iter(self.addresses)

    @property
    def min(self) -> int:
        return min(a.offset for a in self.addresses)

    @property
    def max(self) -> int:
        return max(a.offset for a in self.addresses)

    @property
    def span(self) -> int:
        """Contiguous quantity needed to cover min..max (for bulk FC read)."""
        return self.max - self.min + 1

    def as_bulk(self) -> Tuple[int, int]:
        """Return (start_address, quantity) for a single bulk read covering all addresses."""
        return self.min, self.span


def _parse_single(token: str) -> ModbusAddress:
    """Parse one address token (no comma, no range)."""
    token = token.strip()
    if not token:
        raise ValueError("Empty address token")

    # Modicon 6-digit: 000001..065536 / 100001..165536 / 300001..365536 / 400001..465536
    if re.fullmatch(r"[01234]\d{5}", token):
        prefix = token[0]
        num = int(token[1:])
        fc, dtype = _MODICON_6_FC.get(prefix, (None, None))
        if fc is None:
            raise ValueError("Unrecognized Modicon 6-digit prefix '{}' in '{}'".format(prefix, token))
        offset = num - 1  # 1-based -> 0-based
        return ModbusAddress(raw=token, offset=offset, implied_fc=fc, data_type=dtype)

    # Modicon 5-digit: 00001..09999 (coils), 10001..19999 (DI), 30001..39999 (IR), 40001..49999 (HR)
    if re.fullmatch(r"[01234]\d{4}", token):
        prefix = token[0]
        num = int(token[1:])
        fc, dtype = _MODICON_5_FC.get(prefix, (None, None))
        if fc is None:
            raise ValueError("Unrecognized Modicon 5-digit prefix '{}' in '{}'".format(prefix, token))
        offset = num - 1
        return ModbusAddress(raw=token, offset=offset, implied_fc=fc, data_type=dtype)

    # Plain decimal
    if re.fullmatch(r"\d+", token):
        offset = int(token)
        if offset > MAX_ADDR:
            raise ValueError("Address {} exceeds Modbus maximum ({})".format(offset, MAX_ADDR))
        return ModbusAddress(raw=token, offset=offset)

    raise ValueError("Cannot parse address token '{}'".format(token))


def parse_modbus_addresses(expr: str) -> ModbusAddressSet:
    """Parse an address expression into a ModbusAddressSet.

    Args:
        expr: Address expression, e.g.:
            "10"               -> offset 10
            "14-20"            -> offsets 14..20
            "10,14-20,100"     -> offsets 10, 14..20, 100
            "40001"            -> holding register 1 (FC3, offset 0)
            "40001-40010"      -> holding registers 1-10
            "40001,40005,41000" -> specific holding registers
            "00001-00100"      -> coils 1-100

    Returns:
        ModbusAddressSet with all resolved addresses.

    Raises:
        ValueError: If any token is invalid or ranges are nonsensical.
    """
    if not expr or not expr.strip():
        raise ValueError("Address expression cannot be empty")

    addresses: List[ModbusAddress] = []
    tokens = [t.strip() for t in expr.split(",") if t.strip()]

    for token in tokens:
        if "-" in token:
            # Range: detect separator vs sign (addresses are always non-negative)
            # Split on the LAST dash that follows a digit (to handle 14-20 correctly)
            parts = re.split(r"-", token, maxsplit=1)
            if len(parts) != 2:
                raise ValueError("Invalid range expression: '{}'".format(token))
            start_addr = _parse_single(parts[0])
            end_addr   = _parse_single(parts[1])
            if start_addr.offset > end_addr.offset:
                raise ValueError(
                    "Range start {} > end {} in '{}'".format(
                        start_addr.offset, end_addr.offset, token
                    )
                )
            # Both must have consistent FC if Modicon-typed
            if (start_addr.implied_fc is not None and end_addr.implied_fc is not None
                    and start_addr.implied_fc != end_addr.implied_fc):
                raise ValueError(
                    "Range '{}' spans different Modicon data types "
                    "(FC{} vs FC{})".format(token, start_addr.implied_fc, end_addr.implied_fc)
                )
            ref_fc = start_addr.implied_fc or end_addr.implied_fc
            ref_dtype = start_addr.data_type or end_addr.data_type
            for offset in range(start_addr.offset, end_addr.offset + 1):
                addresses.append(
                    ModbusAddress(
                        raw=str(offset),
                        offset=offset,
                        implied_fc=ref_fc,
                        data_type=ref_dtype,
                    )
                )
        else:
            addresses.append(_parse_single(token))

    if not addresses:
        raise ValueError("No addresses resolved from '{}'".format(expr))

    # Determine unanimous implied FC
    fcs = {a.implied_fc for a in addresses if a.implied_fc is not None}
    unanimous_fc = fcs.pop() if len(fcs) == 1 else None

    return ModbusAddressSet(addresses=addresses, implied_fc=unanimous_fc)
