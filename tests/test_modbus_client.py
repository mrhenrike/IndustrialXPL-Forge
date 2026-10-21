"""Tests for the Modbus TCP Client module.

Validates that the Modbus exploit class is properly structured and
that connection attempts to unreachable hosts fail gracefully.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from industrialxpl.modules.exploits.protocols.modbus import modbus_client

# The module redefines Exploit from the base class
ModbusExploit = modbus_client.Exploit


class TestModbusExploitStructure:
    def _get_info(self):
        # __info__ is name-mangled to _Exploit__info__ since the class is named Exploit
        return getattr(ModbusExploit, "_Exploit__info__", {})

    def test_info_keys(self):
        info = self._get_info()
        assert "name" in info
        assert "description" in info
        assert "authors" in info
        assert "references" in info
        assert "devices" in info

    def test_info_name_contains_modbus(self):
        assert "Modbus" in self._get_info()["name"]

    def test_has_run_method(self):
        assert callable(getattr(ModbusExploit, "run", None))

    def test_has_check_method(self):
        assert callable(getattr(ModbusExploit, "check", None))

    def test_fc_names_mapping(self):
        from industrialxpl.modules.exploits.protocols.modbus.modbus_client import _FC_NAMES
        assert _FC_NAMES[1] == "Read Coils"
        assert _FC_NAMES[3] == "Read Holding Registers"
        assert _FC_NAMES[5] == "Write Single Coil"
        assert _FC_NAMES[16] == "Write Multiple Registers"

    def test_write_fcs_set(self):
        from industrialxpl.modules.exploits.protocols.modbus.modbus_client import WRITE_FCS
        assert {5, 6, 15, 16} == WRITE_FCS

    def test_fc_map_read_actions(self):
        fc_map = ModbusExploit._fc_map
        assert fc_map["READ_COILS"] == (1, False)
        assert fc_map["READ_HOLDING_REGISTERS"] == (3, False)

    def test_fc_map_write_actions(self):
        fc_map = ModbusExploit._fc_map
        assert fc_map["WRITE_COIL"] == (5, True)
        assert fc_map["WRITE_REGISTER"] == (6, True)


class TestModbusConnectionFailure:
    def test_modbus_request_connection_refused(self):
        """_modbus_request should raise OSError on unreachable target."""
        exploit = ModbusExploit.__new__(ModbusExploit)
        exploit.target = "127.0.0.99"
        exploit.port = 10502
        exploit.unit_id = 1
        exploit.timeout = 0.1

        raised = False
        try:
            exploit._modbus_request(3, 0, 10)
        except OSError:
            raised = True
        assert raised, "_modbus_request should raise OSError on connection failure"

    def test_check_returns_false_on_unreachable(self):
        """check() should return False when target is unreachable."""
        exploit = ModbusExploit.__new__(ModbusExploit)
        exploit.target = "127.0.0.99"
        exploit.port = 10502
        exploit.unit_id = 1
        exploit.address = 0
        exploit.timeout = 0.1

        assert exploit.check() is False

    def test_build_pdu_hex_returns_string(self):
        """_build_pdu_hex should return a hex string."""
        exploit = ModbusExploit.__new__(ModbusExploit)
        exploit.address = 0
        exploit.count = 10
        exploit.value = 0
        exploit.unit_id = 1
        result = exploit._build_pdu_hex(3)
        assert isinstance(result, str)
        assert len(result) > 0
