"""Tests for ICS protocol security assessment modules (DNP3, OPC UA, IEC 61850)."""

import pytest
from unittest.mock import patch

from industrialxpl.modules.assessment.protocols.dnp3_security_audit import (
    Exploit as Dnp3Audit,
)
from industrialxpl.modules.assessment.protocols.opcua_security_audit import (
    Exploit as OpcuaAudit,
)
from industrialxpl.modules.assessment.protocols.iec61850_security_audit import (
    Exploit as Iec61850Audit,
)


class TestDnp3SecurityAudit:
    def test_info_name(self):
        e = Dnp3Audit()
        info = e.get_info()
        assert "DNP3" in info["name"]

    def test_default_port(self):
        e = Dnp3Audit()
        assert e.port == 20000

    def test_check_no_target(self):
        e = Dnp3Audit()
        e.target = ""
        assert not e.check()

    def test_check_with_target(self):
        e = Dnp3Audit()
        e.target = "10.0.0.1"
        assert e.check()

    def test_mitre_techniques(self):
        e = Dnp3Audit()
        info = e.get_info()
        assert "T0888" in info.get("mitre_techniques", [])

    def test_run_no_target(self):
        e = Dnp3Audit()
        e.target = ""
        # Should not raise, just print error
        with patch("industrialxpl.modules.assessment.protocols.dnp3_security_audit.print_error"):
            e.run()

    def test_run_with_target(self):
        e = Dnp3Audit()
        e.target = "10.0.0.1"
        with patch("industrialxpl.modules.assessment.protocols.dnp3_security_audit.print_status"), \
             patch("industrialxpl.modules.assessment.protocols.dnp3_security_audit.print_table"), \
             patch("industrialxpl.modules.assessment.protocols.dnp3_security_audit.print_info"):
            e.run()


class TestOpcuaSecurityAudit:
    def test_info_name(self):
        e = OpcuaAudit()
        info = e.get_info()
        assert "OPC UA" in info["name"]

    def test_default_port(self):
        e = OpcuaAudit()
        assert e.port == 4840

    def test_check_no_target(self):
        e = OpcuaAudit()
        e.target = ""
        assert not e.check()

    def test_check_with_target(self):
        e = OpcuaAudit()
        e.target = "10.0.0.1"
        assert e.check()

    def test_mitre_techniques(self):
        e = OpcuaAudit()
        info = e.get_info()
        assert "T0888" in info.get("mitre_techniques", [])

    def test_run_no_target(self):
        e = OpcuaAudit()
        e.target = ""
        with patch("industrialxpl.modules.assessment.protocols.opcua_security_audit.print_error"):
            e.run()

    def test_run_with_target(self):
        e = OpcuaAudit()
        e.target = "10.0.0.1"
        with patch("industrialxpl.modules.assessment.protocols.opcua_security_audit.print_status"), \
             patch("industrialxpl.modules.assessment.protocols.opcua_security_audit.print_table"), \
             patch("industrialxpl.modules.assessment.protocols.opcua_security_audit.print_info"):
            e.run()


class TestIec61850SecurityAudit:
    def test_info_name(self):
        e = Iec61850Audit()
        info = e.get_info()
        assert "IEC 61850" in info["name"]

    def test_default_port(self):
        e = Iec61850Audit()
        assert e.port == 102

    def test_check_no_target(self):
        e = Iec61850Audit()
        e.target = ""
        assert not e.check()

    def test_check_with_target(self):
        e = Iec61850Audit()
        e.target = "10.0.0.1"
        assert e.check()

    def test_mitre_techniques(self):
        e = Iec61850Audit()
        info = e.get_info()
        assert "T0856" in info.get("mitre_techniques", [])

    def test_run_no_target(self):
        e = Iec61850Audit()
        e.target = ""
        with patch("industrialxpl.modules.assessment.protocols.iec61850_security_audit.print_error"):
            e.run()

    def test_run_with_target(self):
        e = Iec61850Audit()
        e.target = "10.0.0.1"
        with patch("industrialxpl.modules.assessment.protocols.iec61850_security_audit.print_status"), \
             patch("industrialxpl.modules.assessment.protocols.iec61850_security_audit.print_table"), \
             patch("industrialxpl.modules.assessment.protocols.iec61850_security_audit.print_info"):
            e.run()
