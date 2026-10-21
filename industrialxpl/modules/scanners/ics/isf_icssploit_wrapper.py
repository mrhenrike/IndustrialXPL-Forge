"""Wrapper stub for ISF/ICSSPLOIT ICS exploitation framework.

Source: https://github.com/dark-lbp/isf
License: verify
SRC-ID: SRC-653
Category: ICS exploitation, S7-300/400, Modbus, Python framework

ISF (ICSSPLOIT) is a Python-based ICS exploitation framework with
modules for Siemens S7-300/400, Modbus TCP, and other industrial
protocols. Provides scanner, exploit, and auxiliary modules.
"""

from dataclasses import dataclass


@dataclass
class ISFConfig:
    target: str = ""
    port: int = 502
    protocol: str = "modbus"  # modbus, s7comm
    module: str | None = None
    timeout: int = 10
