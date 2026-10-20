class BaseInterpreter:
    """Readline-based interactive shell loop."""

    history_file: str = os.path.expanduser("~/.ixf_history")
    raw_prompt_template: str    = "\033[1;36m{host}\033[0m > "
    module_prompt_template: str = "\033[1;36m{host}\033[0m (\033[1;33m{module}\033[0m) > "

    def __init__(self) -> None:
        self.current_module: object | None = None
        self._global_opts: dict = {}
        self._setup_readline()

    def _setup_readline(self) -> None:
        if not _HAS_READLINE or readline is None:
            return
        try:
            readline.read_history_file(self.history_file)
        except (FileNotFoundError, OSError):
            pass
        try:
            readline.set_history_length(1000)
            readline.parse_and_bind("tab: complete")
            readline.set_completer_delims(" \t\n;")
        except Exception:
            pass

    def _bind_completer(self) -> None:
        if not _HAS_READLINE or readline is None:
            return
        try:
            from industrialxpl.cli.completer import IXFCompleter
            self._completer = IXFCompleter(self)
            readline.set_completer(self._completer.complete)
        except Exception:
            pass

    @property
    def prompt(self) -> str:
        if self.current_module:
            name = self.current_module.get_info().get("name", str(self.current_module))
            return self.module_prompt_template.format(
                host="ixf", module=name[:40]
            )
        return self.raw_prompt_template.format(host="ixf")

    def parse_line(self, line: str) -> tuple:
        line = line.strip()
        if not line:
            return "", "", {}
        command, _, args = line.partition(" ")
        return command.lower().replace("-", "_"), args.strip(), {}

    def get_command_handler(self, command: str):
        handler = getattr(self, f"command_{command}", None)
        if handler is None:
            raise IXFException(f"Unknown command: '{command}'")
        return handler

    def _dispatch(self, raw: str) -> bool:
        """Parse and execute one command line. Returns False if 'exit' was issued."""
        raw = raw.strip()
        if not raw:
            return True
        command, args, kwargs = self.parse_line(raw)
        if not command:
            return True
        if command in ("exit", "quit"):
            return False
        try:
            handler = self.get_command_handler(command)
            handler(args, **kwargs)
        except IXFException as exc:
            print_error(str(exc))
        except Exception as exc:
            print_error(f"Unexpected error: {exc}")
        return True

    def run_resource_lines(self, lines: list, echo: bool = True) -> None:
        """Execute a list of command strings (resource file or -e inline).

        Args:
            lines: Raw text lines (comments, blank lines, commands).
            echo:  Print each command before executing (like msfconsole -r).
        """
        for raw in lines:
            line = raw.strip()
            # Skip blank lines and comments
            if not line or line.startswith("#"):
                continue
            if echo:
                # Show what is being executed, similar to msfconsole resource echo
                prompt = self.prompt
                print(f"{prompt}{line}\033[0m")
            keep_going = self._dispatch(line)
            if not keep_going:
                break

    def _startup_update_check(self) -> None:
        """Check PyPI for a newer version and notify the user non-intrusively."""
        import json as _json
        import urllib.request
        try:
            req = urllib.request.Request(
                "https://pypi.org/pypi/industrialxpl-forge/json",
                headers={"User-Agent": f"IXF/{VERSION}/startup-check"},
            )
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = _json.loads(resp.read().decode())
            latest = data["info"]["version"]

            def _v(s):
                try:
                    return tuple(int(x) for x in s.split("."))
                except ValueError:
                    return (0,)

            if _v(latest) > _v(VERSION):
                print_warning(
                    f"New version available: v{VERSION} -> v{latest}  (run 'update' to upgrade)"
                )
                notes_url = data["info"]["project_urls"].get(
                    "Changelog", "https://github.com/mrhenrike/IndustrialXPL-Forge/releases"
                )
                print_info(f"  Release notes: {notes_url}")
                print_info("  'update' -- check details and upgrade interactively")
                print_info("  'update --silent' -- upgrade without confirmation")
                print_info("")
        except Exception:
            # Update check failures are silent -- never block startup
            pass

    def start(self, show_banner: bool = True) -> None:
        """Start the interactive REPL loop.

        Args:
            show_banner: Print the ASCII banner (default True). Set False when
                         the banner was already printed by __main__.py.
        """
        if show_banner:
            print(_BANNER)

        # Non-blocking update check (best-effort, 4s timeout, silent on error)
        self._startup_update_check()
        try:
            while True:
                try:
                    raw = input(self.prompt)
                except (EOFError, KeyboardInterrupt):
                    print()
                    break

                if not raw.strip():
                    continue

                if _HAS_READLINE and readline is not None:
                    try:
                        readline.write_history_file(self.history_file)
                    except OSError:
                        pass

                keep_going = self._dispatch(raw)
                if not keep_going:
                    break
        finally:
            if _HAS_READLINE and readline is not None:
                try:
                    readline.write_history_file(self.history_file)
                except OSError:
                    pass

    def nonInteractive(self, argv: list) -> None:
        """Execute a single command from command-line arguments (legacy mode)."""
        if len(argv) < 2:
            return
        cmd = argv[1].lower().replace("-", "_")
        args = " ".join(argv[2:])
        try:
            handler = self.get_command_handler(cmd)
            handler(args)
        except IXFException as exc:
            print_error(str(exc))
            sys.exit(1)


