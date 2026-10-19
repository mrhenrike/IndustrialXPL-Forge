"""IndustrialXPL-Forge shell shim -- re-exports from xpl-core canonical package.

All shell infrastructure now lives in xpl_core.shells. This module
re-exports the public API so that existing ``from industrialxpl.core.shells
import ...`` statements continue to work unchanged.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from xpl_core.shells import (
    # Engine ABC + types
    ShellEngine,
    ShellError,
    ShellConnectionError,
    ShellIOError,
    ShellTimeoutError,
    ShellMode,
    ShellStatus,
    # Concrete engines
    RawTCPShell,
    RawUDPShell,
    ICMPCovertShell,
    DNSTunnelShell,
    HTTPPollShell,
    MQTTShell,
    MeterpreterBridge,
    InternalShell,
    # Handler
    ShellHandler,
    reverse_shell_payload,
    tty_upgrade_commands,
    # Stager
    SHELL_TYPES,
    generate_payload,
    generate_msf_rc,
    ShellStagingMixin,
    # Listener
    ReverseListener,
    start_listener,
    pty_interact,
    simple_interact,
    # Session manager (new)
    SessionManager,
    SessionState,
    ShellSession,
)

__all__ = [
    "SHELL_TYPES",
    "DNSTunnelShell",
    "HTTPPollShell",
    "ICMPCovertShell",
    "InternalShell",
    "MQTTShell",
    "MeterpreterBridge",
    "RawTCPShell",
    "RawUDPShell",
    "ReverseListener",
    "SessionManager",
    "SessionState",
    "ShellConnectionError",
    "ShellEngine",
    "ShellError",
    "ShellHandler",
    "ShellIOError",
    "ShellMode",
    "ShellSession",
    "ShellStagingMixin",
    "ShellStatus",
    "ShellTimeoutError",
    "generate_msf_rc",
    "generate_payload",
    "pty_interact",
    "reverse_shell_payload",
    "simple_interact",
    "start_listener",
    "tty_upgrade_commands",
]
