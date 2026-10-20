"""IXF platform requirements - Linux-only runtime."""


import platform
import sys


def is_linux() -> bool:
    return sys.platform == "linux"


def require_linux(exit_code: int = 2) -> None:
    """Abort unless running on Linux (kernel + userland lab stack)."""
    if is_linux():
        return
    sys.stderr.write(
        "\nIndustrialXPL-Forge (IXF) requires Linux.\n"
        "Cross-compilers, Mirai CNC, C2 daemons and vendor malware builds are not supported on "
        f"{platform.system()} ({sys.platform}).\n"
        "Use a Linux VM or container for lab operations.\n\n"
    )
    sys.exit(exit_code)
