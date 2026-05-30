#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://uniaogeek.com.br/

import logging.handlers
import platform
import sys

if sys.version_info.major < 3:
    print("IndustrialXPL-Forge requires Python 3. Rerun in a Python 3 environment.")
    sys.exit(1)
if sys.version_info < (3, 9):
    print(
        "IndustrialXPL-Forge requires Python 3.9+ (detected: {}).".format(
            platform.python_version()
        )
    )
    sys.exit(1)

_log_handler = logging.handlers.RotatingFileHandler(
    filename="industrialxpl.log", maxBytes=500_000, backupCount=3
)
_log_formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s  %(message)s")
_log_handler.setFormatter(_log_formatter)
_LOGGER = logging.getLogger()
_LOGGER.setLevel(logging.DEBUG)
_LOGGER.addHandler(_log_handler)


def industrialxpl(argv: list) -> None:
    """Bootstrap and launch the IXF interactive shell."""
    try:
        from industrialxpl.interpreter import IXFInterpreter
    except ModuleNotFoundError as err:
        print("IndustrialXPL bootstrap error: missing Python dependency: {}".format(err))
        print("Run: python -m pip install -r requirements.txt")
        print("Diagnostics: python tools/env_doctor.py")
        raise SystemExit(1)

    ixf = IXFInterpreter()
    if len(argv[1:]):
        ixf.nonInteractive(argv)
    else:
        ixf.start()


if __name__ == "__main__":
    try:
        industrialxpl(sys.argv)
    except (KeyboardInterrupt, SystemExit):
        pass
