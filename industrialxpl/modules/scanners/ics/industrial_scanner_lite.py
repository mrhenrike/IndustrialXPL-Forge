"""Wrapper stub for IndustrialScanner-Lite.

Source: https://github.com/frangelbarrera/IndustrialScanner-Lite
License: verify
SRC-ID: SRC-991
Category: ICS scanner, Modbus/S7Comm/DNP3, PCAP analysis

IndustrialScanner-Lite provides lightweight scanning for Modbus,
S7Comm, and DNP3 protocols with integrated PCAP analysis capabilities.
"""

from dataclasses import dataclass


@dataclass
class IndustrialScannerConfig:
    target: str = ""
    protocol: str = "modbus"  # modbus, s7comm, dnp3
    pcap_output: str | None = None
    timeout: int = 5
