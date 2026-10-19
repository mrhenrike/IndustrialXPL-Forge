"""Tests for OT/ICS protocol stubs."""

from __future__ import annotations

import pytest

from industrialxpl.core.protocols.ethernetip import (
    ENIP_TCP_PORT,
    CipIdentity,
    CipService,
    EnipClient,
    Tag,
    build_register_session,
)
from industrialxpl.core.protocols.hartip import (
    HART_IP_PORT,
    HartCommand,
    HartDevice,
    HartIpClient,
    ProcessVariable,
    build_hart_ip_header,
)
from industrialxpl.core.protocols.iec61850 import (
    GOOSE_ETHERTYPE,
    IED,
    MMS_PORT,
    SV_ETHERTYPE,
    DataAttribute,
    GooseSubscriber,
    MmsClient,
    SvSubscriber,
)


class TestIEC61850:
    def test_ied_defaults(self):
        ied = IED(name="IED01", ip="192.168.1.10")
        assert ied.port == MMS_PORT
        assert ied.logical_devices == []

    def test_data_attribute(self):
        da = DataAttribute(
            reference="XCBR1/XCBR1.Pos.stVal",
            value=True,
            quality="good",
        )
        assert da.value is True

    def test_mms_client_not_implemented(self):
        ied = IED(name="IED01", ip="10.0.0.1")
        client = MmsClient(ied)
        with pytest.raises(NotImplementedError):
            client.connect()
        with pytest.raises(NotImplementedError):
            client.read("ref")
        with pytest.raises(NotImplementedError):
            client.write("ref", 1)

    def test_goose_not_implemented(self):
        sub = GooseSubscriber()
        with pytest.raises(NotImplementedError):
            sub.start()

    def test_sv_not_implemented(self):
        sub = SvSubscriber()
        with pytest.raises(NotImplementedError):
            sub.start()

    def test_constants(self):
        assert MMS_PORT == 102
        assert GOOSE_ETHERTYPE == 0x88B8
        assert SV_ETHERTYPE == 0x88BA


class TestEtherNetIP:
    def test_cip_services(self):
        assert CipService.READ_TAG == 0x4C
        assert CipService.WRITE_TAG == 0x4D

    def test_cip_identity_defaults(self):
        ident = CipIdentity()
        assert ident.vendor_id == 0
        assert ident.product_name == ""

    def test_tag(self):
        t = Tag(name="Motor1_Speed", value=1750.0, data_type=0xC1)
        assert t.name == "Motor1_Speed"
        assert t.dimensions == []

    def test_enip_client_not_implemented(self):
        client = EnipClient("10.0.0.1")
        assert client.port == ENIP_TCP_PORT
        with pytest.raises(NotImplementedError):
            client.connect()
        with pytest.raises(NotImplementedError):
            client.read_tag("tag")
        with pytest.raises(NotImplementedError):
            client.write_tag("tag", 1)

    def test_build_register_session(self):
        pkt = build_register_session()
        assert isinstance(pkt, bytes)
        assert len(pkt) > 0


class TestHartIP:
    def test_constants(self):
        assert HART_IP_PORT == 5094

    def test_hart_commands(self):
        assert HartCommand.READ_UNIQUE_ID == 0
        assert HartCommand.READ_PRIMARY_VAR == 1
        assert HartCommand.READ_DYNAMIC_VARS == 3

    def test_hart_device_defaults(self):
        dev = HartDevice()
        assert dev.tag == ""
        assert dev.unique_id == b""

    def test_process_variable(self):
        pv = ProcessVariable(name="Temperature", value=25.5, unit="C")
        assert pv.status == "good"

    def test_client_not_implemented(self):
        client = HartIpClient("10.0.0.1")
        with pytest.raises(NotImplementedError):
            client.connect()
        with pytest.raises(NotImplementedError):
            client.read_unique_id()
        with pytest.raises(NotImplementedError):
            client.read_primary_variable()

    def test_build_header(self):
        hdr = build_hart_ip_header(msg_type=0, command=0)
        assert isinstance(hdr, bytes)
        assert len(hdr) >= 8
