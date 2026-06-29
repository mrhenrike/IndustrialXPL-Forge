"""Shell transport engines for IndustrialXPL-Forge.

Provides pluggable shell transports (TCP, UDP, ICMP, DNS, MQTT, HTTP,
Meterpreter, IWP) that share a common ShellEngine interface.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from industrialxpl.core.shells.shell_engine import (
    ShellEngine,
    ShellError,
    ShellConnectionError,
    ShellIOError,
    ShellMode,
    ShellStatus,
    ShellTimeoutError,
)
from industrialxpl.core.shells.raw_tcp_shell import RawTCPShell
from industrialxpl.core.shells.raw_udp_shell import RawUDPShell
from industrialxpl.core.shells.icmp_covert_shell import ICMPCovertShell
from industrialxpl.core.shells.dns_tunnel_shell import DNSTunnelShell
from industrialxpl.core.shells.mqtt_shell import MQTTShell
from industrialxpl.core.shells.http_poll_shell import HTTPPollShell
from industrialxpl.core.shells.meterpreter_bridge import MeterpreterBridge
from industrialxpl.core.shells.internal_shell import InternalShell

__all__ = [
    "ShellEngine",
    "ShellError",
    "ShellConnectionError",
    "ShellIOError",
    "ShellMode",
    "ShellStatus",
    "ShellTimeoutError",
    "RawTCPShell",
    "RawUDPShell",
    "ICMPCovertShell",
    "DNSTunnelShell",
    "MQTTShell",
    "HTTPPollShell",
    "MeterpreterBridge",
    "InternalShell",
]
