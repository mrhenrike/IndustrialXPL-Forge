"""Tests for Moxa ADDP Device Discovery module."""

import pytest
from unittest.mock import patch, MagicMock

from industrialxpl.modules.scanners.asset.moxa_udp_discover import Exploit as MoxaDiscover


class TestMoxaMetadata:
    def test_info_name(self):
        e = MoxaDiscover()
        info = e.get_info()
        assert "Moxa" in info.get("name", "")

    def test_info_mitre(self):
        e = MoxaDiscover()
        info = e.get_info()
        techniques = info.get("mitre_techniques", info.get("mitre", []))
        assert any("T0846" in t for t in techniques)

    def test_default_port(self):
        e = MoxaDiscover()
        assert e.port == 4800

    def test_default_target_broadcast(self):
        e = MoxaDiscover()
        assert e.target == "255.255.255.255"

    def test_default_timeout(self):
        e = MoxaDiscover()
        assert e.timeout == 3


class TestMoxaProbe:
    def test_probe_constant(self):
        e = MoxaDiscover()
        assert e._PROBE == b"\x01\x00\x00\x08\x00\x00\x00\x00"
        assert len(e._PROBE) == 8

    def test_probe_function_code(self):
        e = MoxaDiscover()
        assert e._PROBE[0] == 0x01  # ADDP Identify


class TestMoxaCheck:
    def test_check_returns_true(self):
        e = MoxaDiscover()
        assert e.check() is True


class TestMoxaSimulate:
    def test_run_simulate_mode(self):
        e = MoxaDiscover()
        e.simulate = True
        # Should not open a real socket
        with patch("industrialxpl.modules.scanners.asset.moxa_udp_discover.DestructiveGate") as dg:
            dg.print_simulation = MagicMock()
            e.run()
            dg.print_simulation.assert_called_once()
