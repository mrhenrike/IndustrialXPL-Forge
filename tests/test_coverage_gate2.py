"""Gate-2 coverage tests for IndustrialXPL-Forge core modules."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# industrialxpl.core.exploit.exceptions
# ---------------------------------------------------------------------------

def test_ixf_exception_hierarchy() -> None:
    from industrialxpl.core.exploit.exceptions import (
        DestructiveOperationAborted,
        ExploitRunError,
        IXFException,
        OptionValidationError,
    )
    from industrialxpl.core.exploit.exceptions import (
        ModuleNotFoundError as IXFModuleNotFound,
    )
    assert issubclass(OptionValidationError, IXFException)
    assert issubclass(IXFModuleNotFound, IXFException)
    assert issubclass(ExploitRunError, IXFException)
    assert issubclass(DestructiveOperationAborted, IXFException)


def test_ixf_exception_message() -> None:
    from industrialxpl.core.exploit.exceptions import IXFException
    e = IXFException("test message")
    assert str(e) == "test message"


# ---------------------------------------------------------------------------
# industrialxpl.core.exploit.option — Option descriptors
# ---------------------------------------------------------------------------

def test_option_base_default() -> None:
    from industrialxpl.core.exploit.option import Option
    opt = Option("default_val", "A description")
    assert opt.default == "default_val"
    assert opt.description == "A description"
    assert opt.advanced is False


def test_option_advanced_flag() -> None:
    from industrialxpl.core.exploit.option import Option
    opt = Option(42, "desc", advanced=True)
    assert opt.advanced is True


def test_optip_valid_ipv4() -> None:
    from industrialxpl.core.exploit.option import OptIP
    opt = OptIP("", "target")
    assert opt.validate("192.168.1.1") == "192.168.1.1"


def test_optip_valid_hostname() -> None:
    from industrialxpl.core.exploit.option import OptIP
    opt = OptIP("", "target")
    assert opt.validate("plc-01.local") == "plc-01.local"


def test_optip_empty_allowed() -> None:
    from industrialxpl.core.exploit.option import OptIP
    opt = OptIP("", "target")
    assert opt.validate("") == ""


def test_optip_invalid_raises() -> None:
    from industrialxpl.core.exploit.exceptions import OptionValidationError
    from industrialxpl.core.exploit.option import OptIP
    opt = OptIP("", "target")
    with pytest.raises(OptionValidationError):
        opt.validate("not a valid!address")


def test_optport_valid() -> None:
    from industrialxpl.core.exploit.option import OptPort
    opt = OptPort(502, "port")
    assert opt.validate(502) == 502
    assert opt.validate("80") == 80


def test_optport_invalid_range() -> None:
    from industrialxpl.core.exploit.exceptions import OptionValidationError
    from industrialxpl.core.exploit.option import OptPort
    opt = OptPort(502, "port")
    with pytest.raises(OptionValidationError):
        opt.validate(0)
    with pytest.raises(OptionValidationError):
        opt.validate(70000)


def test_optinteger_bounds() -> None:
    from industrialxpl.core.exploit.exceptions import OptionValidationError
    from industrialxpl.core.exploit.option import OptInteger
    opt = OptInteger(1, "unit id", min_value=1, max_value=255)
    assert opt.validate(1) == 1
    assert opt.validate(255) == 255
    with pytest.raises(OptionValidationError):
        opt.validate(0)
    with pytest.raises(OptionValidationError):
        opt.validate(256)


def test_optfloat_valid() -> None:
    from industrialxpl.core.exploit.option import OptFloat
    opt = OptFloat(1.0, "timeout")
    assert opt.validate("3.14") == pytest.approx(3.14)


def test_optstring_coercion() -> None:
    from industrialxpl.core.exploit.option import OptString
    opt = OptString("", "data")
    assert opt.validate(12345) == "12345"


def test_optbool_true_values() -> None:
    from industrialxpl.core.exploit.option import OptBool
    opt = OptBool(True, "flag")
    for v in (True, "true", "yes", "1", "on"):
        assert opt.validate(v) is True


def test_optbool_false_values() -> None:
    from industrialxpl.core.exploit.option import OptBool
    opt = OptBool(False, "flag")
    for v in (False, "false", "no", "0", "off"):
        assert opt.validate(v) is False


def test_optbool_invalid() -> None:
    from industrialxpl.core.exploit.exceptions import OptionValidationError
    from industrialxpl.core.exploit.option import OptBool
    opt = OptBool(False, "flag")
    with pytest.raises(OptionValidationError):
        opt.validate("maybe")


def test_optmac_valid() -> None:
    from industrialxpl.core.exploit.option import OptMAC
    opt = OptMAC("", "mac")
    assert opt.validate("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


def test_optmac_invalid() -> None:
    from industrialxpl.core.exploit.exceptions import OptionValidationError
    from industrialxpl.core.exploit.option import OptMAC
    opt = OptMAC("", "mac")
    with pytest.raises(OptionValidationError):
        opt.validate("not-a-mac")


def test_opttransport_valid() -> None:
    from industrialxpl.core.exploit.option import OptTransport
    opt = OptTransport()
    assert opt.validate("tcp") == "tcp"
    assert opt.validate("UDP") == "udp"
    assert opt.validate("both") == "both"


def test_opttransport_invalid() -> None:
    from industrialxpl.core.exploit.exceptions import OptionValidationError
    from industrialxpl.core.exploit.option import OptTransport
    opt = OptTransport()
    with pytest.raises(OptionValidationError):
        opt.validate("serial")


def test_optencoder_passthrough() -> None:
    from industrialxpl.core.exploit.option import OptEncoder
    opt = OptEncoder("", "encoder")
    assert opt.validate("  xor_basic  ") == "xor_basic"


# ---------------------------------------------------------------------------
# industrialxpl.core.modbus.address — Modbus address parser
# ---------------------------------------------------------------------------

def test_parse_single_decimal() -> None:
    from industrialxpl.core.modbus.address import parse_modbus_addresses
    result = parse_modbus_addresses("10")
    assert len(result) == 1
    assert result.addresses[0].offset == 10


def test_parse_range() -> None:
    from industrialxpl.core.modbus.address import parse_modbus_addresses
    result = parse_modbus_addresses("14-20")
    assert len(result) == 7
    assert result.offsets() == list(range(14, 21))


def test_parse_mixed() -> None:
    from industrialxpl.core.modbus.address import parse_modbus_addresses
    result = parse_modbus_addresses("10,14-16,100")
    assert len(result) == 5
    assert result.offsets() == [10, 14, 15, 16, 100]


def test_parse_modicon_5_holding() -> None:
    from industrialxpl.core.modbus.address import parse_modbus_addresses
    result = parse_modbus_addresses("40001")
    assert len(result) == 1
    addr = result.addresses[0]
    assert addr.offset == 0
    assert addr.implied_fc == 3
    assert addr.data_type == "holding_register"


def test_parse_modicon_5_coil() -> None:
    from industrialxpl.core.modbus.address import parse_modbus_addresses
    result = parse_modbus_addresses("00001")
    assert len(result) == 1
    assert result.addresses[0].implied_fc == 1


def test_parse_modicon_6_digit() -> None:
    from industrialxpl.core.modbus.address import parse_modbus_addresses
    result = parse_modbus_addresses("400001")
    assert len(result) == 1
    assert result.addresses[0].implied_fc == 3


def test_address_set_properties() -> None:
    from industrialxpl.core.modbus.address import parse_modbus_addresses
    result = parse_modbus_addresses("10,20,30")
    assert result.min == 10
    assert result.max == 30
    assert result.span == 21
    assert result.as_bulk() == (10, 21)


def test_parse_empty_raises() -> None:
    from industrialxpl.core.modbus.address import parse_modbus_addresses
    with pytest.raises(ValueError):
        parse_modbus_addresses("")


def test_parse_invalid_token_raises() -> None:
    from industrialxpl.core.modbus.address import parse_modbus_addresses
    with pytest.raises(ValueError):
        parse_modbus_addresses("abc")


def test_modbus_address_repr() -> None:
    from industrialxpl.core.modbus.address import ModbusAddress
    a = ModbusAddress(raw="40001", offset=0, implied_fc=3)
    assert "40001" in repr(a)
    assert "FC3" in repr(a)


# ---------------------------------------------------------------------------
# industrialxpl.core.modbus.timing — Timing profiles
# ---------------------------------------------------------------------------

def test_timing_profiles_complete() -> None:
    from industrialxpl.core.modbus.timing import TIMING_PROFILES
    assert len(TIMING_PROFILES) == 6
    for i in range(6):
        assert i in TIMING_PROFILES


def test_timing_default_is_t3() -> None:
    from industrialxpl.core.modbus.timing import DEFAULT_TIMING
    assert DEFAULT_TIMING.level == 3
    assert DEFAULT_TIMING.name == "Normal"


def test_timing_resolve_int() -> None:
    from industrialxpl.core.modbus.timing import ModbusTiming
    p = ModbusTiming.resolve(0)
    assert p.name == "Paranoid"


def test_timing_resolve_string_t4() -> None:
    from industrialxpl.core.modbus.timing import ModbusTiming
    p = ModbusTiming.resolve("T4")
    assert p.name == "Aggressive"


def test_timing_resolve_name() -> None:
    from industrialxpl.core.modbus.timing import ModbusTiming
    p = ModbusTiming.resolve("insane")
    assert p.level == 5


def test_timing_resolve_invalid() -> None:
    from industrialxpl.core.modbus.timing import ModbusTiming
    with pytest.raises(ValueError):
        ModbusTiming.resolve(99)


def test_timing_profile_str() -> None:
    from industrialxpl.core.modbus.timing import TIMING_PROFILES
    s = str(TIMING_PROFILES[3])
    assert "T3" in s
    assert "Normal" in s


def test_timing_describe_all() -> None:
    from industrialxpl.core.modbus.timing import ModbusTiming
    desc = ModbusTiming.describe_all()
    assert "T0" in desc
    assert "T5" in desc
    assert "default" in desc.lower()


# ---------------------------------------------------------------------------
# industrialxpl.core.mitre.tactics — MITRE ATT&CK for ICS
# ---------------------------------------------------------------------------

def test_tactics_has_12_entries() -> None:
    from industrialxpl.core.mitre.tactics import TACTICS
    assert len(TACTICS) == 12


def test_tactics_all_ta_prefixed() -> None:
    from industrialxpl.core.mitre.tactics import TACTICS
    for tid in TACTICS:
        assert tid.startswith("TA0")


def test_tactic_aliases_resolve() -> None:
    from industrialxpl.core.mitre.tactics import TACTIC_ALIASES
    assert TACTIC_ALIASES["execution"] == "TA0104"
    assert TACTIC_ALIASES["c2"] == "TA0101"
    assert TACTIC_ALIASES["privesc"] == "TA0111"


def test_tactic_tids_nonempty() -> None:
    from industrialxpl.core.mitre.tactics import TACTIC_TIDS, TACTICS
    for ta_id in TACTICS:
        assert ta_id in TACTIC_TIDS
        assert len(TACTIC_TIDS[ta_id]) > 0


# ---------------------------------------------------------------------------
# industrialxpl.core.exploit.safety — IMPACT_LEVELS constant
# ---------------------------------------------------------------------------

def test_impact_levels_constant() -> None:
    from industrialxpl.core.exploit.safety import IMPACT_LEVELS
    assert "INFO" in IMPACT_LEVELS
    assert "CATASTROPHIC" in IMPACT_LEVELS
    assert len(IMPACT_LEVELS) == 7


def test_confirmation_string_constant() -> None:
    from industrialxpl.core.exploit.safety import CONFIRMATION_STRING
    assert len(CONFIRMATION_STRING) > 20


def test_destructive_gate_simulate(capsys) -> None:
    from industrialxpl.core.exploit.safety import DestructiveGate
    DestructiveGate.print_simulation(
        "Test simulation",
        payload_hex="deadbeef",
        payload_human="Write coil 100",
        mitre_techniques=["T0831"],
    )


# ---------------------------------------------------------------------------
# industrialxpl.core.exploit.utils — utility functions
# ---------------------------------------------------------------------------

def test_pythonize_path() -> None:
    from industrialxpl.core.exploit.utils import pythonize_path
    assert pythonize_path("exploits/protocols/modbus") == "exploits.protocols.modbus"


def test_humanize_path() -> None:
    from industrialxpl.core.exploit.utils import humanize_path
    assert humanize_path("exploits.protocols.modbus") == "exploits/protocols/modbus"


# ---------------------------------------------------------------------------
# industrialxpl.core.api.server — basic importability
# ---------------------------------------------------------------------------

def test_api_server_importable() -> None:
    import industrialxpl.api.server as srv
    assert hasattr(srv, "__file__")
