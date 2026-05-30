"""IndustrialXPL-Forge entry point for 'python -m industrialxpl' and console script 'ixf'."""

import sys


def main() -> None:
    """Launch the IXF interactive shell."""
    from industrialxpl.interpreter import IXFInterpreter

    interpreter = IXFInterpreter()
    if len(sys.argv[1:]):
        interpreter.nonInteractive(sys.argv)
    else:
        interpreter.start()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        pass
