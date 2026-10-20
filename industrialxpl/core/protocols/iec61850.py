"""IEC 61850 (MMS/GOOSE/SV) protocol stub.

Provides skeleton classes for communication with IEC 61850
substations and IEDs. Production implementation requires
libiec61850 bindings or a pure-Python MMS stack.
"""


import logging
import struct
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

MMS_PORT = 102
GOOSE_ETHERTYPE = 0x88B8
SV_ETHERTYPE = 0x88BA


@dataclass
class IED:
    name: str
    ip: str
    port: int = MMS_PORT
    logical_devices: list[str] = field(default_factory=list)
    vendor: str = ""
    model: str = ""


@dataclass
class DataAttribute:
    reference: str
    value: Any = None
    quality: str = "good"
    timestamp: float = 0.0


class MmsClient:
    """Skeleton MMS client for reading/writing IED data objects."""

    def __init__(self, ied: IED) -> None:
        self.ied = ied
        self._connected = False

    def connect(self) -> bool:
        logger.info("MMS connect to %s:%d", self.ied.ip, self.ied.port)
        raise NotImplementedError("MMS stack binding required")

    def disconnect(self) -> None:
        self._connected = False

    def read(self, reference: str) -> DataAttribute:
        raise NotImplementedError("MMS read not implemented")

    def write(self, reference: str, value: Any) -> bool:
        raise NotImplementedError("MMS write not implemented")

    def get_logical_devices(self) -> list[str]:
        raise NotImplementedError("MMS getServerDirectory not implemented")

    def get_data_directory(self, ld: str) -> list[str]:
        raise NotImplementedError("MMS getLogicalDeviceDirectory not implemented")


class GooseSubscriber:
    """Skeleton GOOSE subscriber for capturing multicast frames."""

    def __init__(self, interface: str = "eth0") -> None:
        self.interface = interface
        self._running = False

    def start(self, gocb_ref: str | None = None) -> None:
        raise NotImplementedError("GOOSE capture requires raw socket or libiec61850")

    def stop(self) -> None:
        self._running = False

    def on_message(self, callback) -> None:
        raise NotImplementedError


class SvSubscriber:
    """Skeleton Sampled Values subscriber."""

    def __init__(self, interface: str = "eth0") -> None:
        self.interface = interface

    def start(self, sv_id: str | None = None) -> None:
        raise NotImplementedError("SV capture requires raw socket or libiec61850")

    def stop(self) -> None:
        pass
