#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://uniaogeek.com.br/

import logging.handlers
import platform
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

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


def _launcher(argv):
    try:
        from industrialxpl.interpreter import IXFInterpreter
    except ModuleNotFoundError as err:
        print("IndustrialXPL bootstrap error: missing Python dependency: {}".format(err))
        print("Run: pip install -r requirements.txt")
        print("Check: ixf --doctor")
        raise SystemExit(1)

    ixf = IXFInterpreter()
    if len(argv[1:]):
        ixf.nonInteractive(argv)
    else:
        ixf.start()


def industrialxpl(argv):
    from tools.xpl_cli import ProductInfo, bootstrap

    try:
        import tomllib
        _ver = tomllib.loads((_ROOT / "pyproject.toml").read_text())["project"]["version"]
    except Exception:
        _ver = "1.0.40"

    product = ProductInfo(
        name="IndustrialXPL-Forge",
        slug="industrialxpl-forge",
        version=_ver,
        cli_name="ixf",
        min_python=(3, 9),
        pip_package="industrialxpl-forge",
        setup_hint="pip install -r requirements.txt",
    )
    bootstrap(argv, product, _launcher)


if __name__ == "__main__":
    try:
        industrialxpl(sys.argv)
    except (KeyboardInterrupt, SystemExit):
        pass
