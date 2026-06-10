"""IndustrialXPL-Forge entry point.

Usage modes:
  ixf                           — interactive shell
  ixf -r /path/script.rc       — execute resource file, then interactive shell
  ixf --read /path/script.rc   — same as -r
  ixf -r /path/script.rc -x    — execute resource file, then exit (non-interactive)
  ixf -e "use scanners/ics/modbus_scanner; set TARGET 10.0.0.1; run"
  ixf --exec "command string"  — execute inline commands (semicolons separate)
  ixf -q                       — quiet mode (suppress banner)
"""

import sys
import argparse
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ixf",
        description="IndustrialXPL-Forge — OT/ICS/SCADA Security Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Resource file format (.rc):
  # Lines starting with # are comments
  setg TIMING T2
  setg TARGET 192.168.1.100
  use scanners/ics/modbus_scanner
  set PORT 502
  run
  back
  use scanners/ics/modbus_detect
  set TARGET 10.0.0.50
  check

Examples:
  ixf -r scan_modbus.rc
  ixf -r scan_modbus.rc -x
  ixf -r setup.rc -r scan.rc
  ixf -e "setg timing T2; use scanners/ics/modbus_scanner; set target 10.0.0.1; run"
  ixf -q -r /opt/scripts/daily_ot_scan.rc -x
        """,
    )
    p.add_argument(
        "-r", "--read",
        dest="resource_files",
        metavar="FILE",
        action="append",
        default=[],
        help="Execute commands from resource file on startup (can be repeated: -r a.rc -r b.rc)",
    )
    p.add_argument(
        "-e", "--exec",
        dest="exec_cmds",
        metavar="COMMANDS",
        action="append",
        default=[],
        help="Execute inline commands (separated by semicolons)",
    )
    p.add_argument(
        "-x", "--exit",
        dest="no_interactive",
        action="store_true",
        default=False,
        help="Exit after executing resource files / inline commands (non-interactive)",
    )
    p.add_argument(
        "-q", "--quiet",
        dest="quiet",
        action="store_true",
        default=False,
        help="Suppress banner output",
    )
    p.add_argument(
        "--output", "-o",
        dest="output",
        metavar="FILE",
        default=None,
        help="Tee all output to file",
    )
    p.add_argument(
        "--loglevel",
        dest="loglevel",
        choices=["debug", "info", "warning", "error"],
        default=None,
        help="Set output verbosity",
    )
    p.add_argument(
        "--version", "-v",
        action="store_true",
        dest="show_version",
        default=False,
        help="Print version and exit",
    )
    return p


def main() -> None:
    """Launch IXF in the appropriate mode based on CLI arguments."""
    from industrialxpl.interpreter import IXFInterpreter, VERSION

    # Legacy: if first arg is not a flag, treat as single command (backward compat)
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        interp = IXFInterpreter()
        interp.nonInteractive(sys.argv)
        return

    parser = build_parser()
    args = parser.parse_args()

    if args.show_version:
        print("IndustrialXPL-Forge v{}".format(VERSION))
        return

    interp = IXFInterpreter()

    # Apply CLI-level global options before any resource file runs
    if args.loglevel:
        from industrialxpl.core.exploit.printer import set_log_level
        set_log_level(args.loglevel)
        interp._global_opts["loglevel"] = args.loglevel

    if args.output:
        interp._global_opts["output"] = args.output

    # Collect all command lines to execute in order
    all_rc_lines: list = []

    for rc_path_str in args.resource_files:
        rc_path = Path(rc_path_str)
        if not rc_path.exists():
            from industrialxpl.core.exploit.printer import print_error
            print_error("Resource file not found: {}".format(rc_path))
            sys.exit(1)
        if not rc_path.is_file():
            from industrialxpl.core.exploit.printer import print_error
            print_error("Not a file: {}".format(rc_path))
            sys.exit(1)
        try:
            lines = rc_path.read_text(encoding="utf-8").splitlines()
            all_rc_lines.extend(lines)
            all_rc_lines.append("")  # separator between files
        except OSError as exc:
            from industrialxpl.core.exploit.printer import print_error
            print_error("Cannot read '{}': {}".format(rc_path, exc))
            sys.exit(1)

    # Inline commands via -e (expand semicolons)
    for cmd_block in args.exec_cmds:
        for part in cmd_block.split(";"):
            all_rc_lines.append(part.strip())

    if args.quiet or all_rc_lines:
        # Print banner only when interactive (or not quiet)
        if not args.quiet:
            from industrialxpl.interpreter import _BANNER
            print(_BANNER)
    else:
        from industrialxpl.interpreter import _BANNER
        print(_BANNER)

    # Execute collected commands
    if all_rc_lines:
        interp.run_resource_lines(all_rc_lines, echo=True)

    # Drop into interactive shell unless -x was given
    if not args.no_interactive:
        interp.start(show_banner=False)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        pass
