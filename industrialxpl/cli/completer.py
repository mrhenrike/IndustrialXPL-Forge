"""Context-aware readline tab completer for IXF interactive shell.

Provides Metasploit-style completions:
- Top-level commands (use, set, show, search, ...)
- Module paths after 'use' (scanners/ics/modbus_detect)
- Option names after 'set' / 'setg' (TARGET, PORT, ...)
- Show subcommands (info, options, advanced, global)
- Malware / ics_tools subcommands
- MITRE technique IDs after 'mitre' / 'ttp'
"""


from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from industrialxpl.interpreter import IXFInterpreter

_GLOBAL_COMMANDS: list[str] = [
    "help", "use", "back", "exit", "quit",
    "search", "modules", "show", "set", "setg", "unsetg",
    "run", "check", "info", "options", "global",
    "cve", "cve_scan", "mitre", "mitre_list", "mitre_scan",
    "mitre_all", "mitre_coverage", "mitre_report", "mitre_tactic",
    "ttp", "ttp_check", "ttp_simulate", "ttp_list",
    "malware", "ics_tools", "assess", "nse",
    "report", "discover", "exec",
    "stats", "vendors", "protocols",
    "update", "upgrade",
]

_SHOW_SUBCOMMANDS: list[str] = [
    "info", "options", "advanced", "devices",
    "global", "sectors", "types",
]

_MALWARE_SUBCOMMANDS: list[str] = [
    "list", "analyze", "build", "compile",
    "exec", "deploy", "shell", "firmware",
]

_ICS_TOOLS_SUBCOMMANDS: list[str] = [
    "list", "run", "info",
]

_GLOBAL_OPTIONS: list[str] = [
    "TARGET", "LOGLEVEL", "VERBOSE", "OUTPUT", "REPORT_FMT",
    "TIMING", "THREADS", "HOST_TIMEOUT", "MAX_RETRIES",
    "SCAN_DELAY", "MAX_RATE", "PROBE_LEVEL",
    "PING_FIRST", "SKIP_PING", "SIMULATE", "DESTRUCTIVE",
    "LHOST", "LPORT",
]


class IXFCompleter:
    """Readline completer bound to an IXFInterpreter instance."""

    def __init__(self, interpreter: IXFInterpreter) -> None:
        self._interp = interpreter
        self._matches: list[str] = []
        self._module_cache: list[str] | None = None

    @property
    def _module_paths(self) -> list[str]:
        if self._module_cache is None:
            self._module_cache = []
            for mod in getattr(self._interp, "modules", []):
                path = getattr(mod, "path", "") or ""
                if path:
                    self._module_cache.append(path)
        return self._module_cache

    def invalidate_cache(self) -> None:
        self._module_cache = None

    def _current_options(self) -> list[str]:
        mod = self._interp.current_module
        if mod is None:
            return []
        opts = getattr(mod, "options", {})
        if isinstance(opts, dict):
            return [k.upper() for k in opts]
        return []

    def complete(self, text: str, state: int) -> str | None:
        if state == 0:
            try:
                import readline
                buf = readline.get_line_buffer()
            except Exception:
                buf = text
            self._matches = self._get_matches(buf, text)
        try:
            return self._matches[state]
        except IndexError:
            return None

    def _get_matches(self, line: str, text: str) -> list[str]:
        stripped = line.lstrip()
        parts = stripped.split()

        if len(parts) == 0 or (len(parts) == 1 and not line.endswith(" ")):
            return [c + " " for c in _GLOBAL_COMMANDS if c.startswith(text)]

        cmd = parts[0].lower()

        if cmd == "use":
            return self._complete_module(text)

        if cmd in ("set", "setg"):
            if len(parts) == 1 and line.endswith(" "):
                opts = self._current_options() if cmd == "set" else _GLOBAL_OPTIONS
                return [o + " " for o in opts]
            if len(parts) == 2 and not line.endswith(" "):
                opts = self._current_options() if cmd == "set" else _GLOBAL_OPTIONS
                return [o + " " for o in opts if o.lower().startswith(text.lower())]
            return self._complete_option_value(parts)

        if cmd == "unsetg":
            return [o + " " for o in _GLOBAL_OPTIONS if o.lower().startswith(text.lower())]

        if cmd == "show":
            return [s + " " for s in _SHOW_SUBCOMMANDS if s.startswith(text)]

        if cmd == "malware":
            return [s + " " for s in _MALWARE_SUBCOMMANDS if s.startswith(text)]

        if cmd == "ics_tools":
            return [s + " " for s in _ICS_TOOLS_SUBCOMMANDS if s.startswith(text)]

        if cmd == "help":
            topics = list(_GLOBAL_COMMANDS) + ["sector", "type", "global", "simulate", "destructive"]
            return [t + " " for t in topics if t.startswith(text)]

        if cmd in ("search",):
            prefixes = ["type=", "sector=", "vendor=", "cve=", "protocol="]
            return [p for p in prefixes if p.startswith(text)]

        if cmd in ("cve",):
            return [t for t in ["CVE-"] if t.startswith(text.upper())]

        return []

    def _complete_module(self, text: str) -> list[str]:
        text_lower = text.lower()
        matches: list[str] = []
        dirs_seen: set[str] = set()

        for path in self._module_paths:
            if path.lower().startswith(text_lower):
                rest = path[len(text):]
                slash = rest.find("/")
                if slash >= 0:
                    dir_match = text + rest[: slash + 1]
                    if dir_match not in dirs_seen:
                        dirs_seen.add(dir_match)
                        matches.append(dir_match)
                else:
                    matches.append(path + " ")

        return sorted(matches)

    def _complete_option_value(self, parts: list[str]) -> list[str]:
        if len(parts) < 2:
            return []
        opt = parts[1].upper()
        if opt == "TIMING":
            return [t + " " for t in ["T0", "T1", "T2", "T3", "T4", "T5"]]
        if opt == "LOGLEVEL":
            return [lv + " " for lv in ["debug", "info", "warning", "error"]]
        if opt in ("SIMULATE", "DESTRUCTIVE", "VERBOSE", "PING_FIRST", "SKIP_PING"):
            return ["true ", "false "]
        if opt == "REPORT_FMT":
            return [f + " " for f in ["json", "html", "markdown", "csv"]]
        return []
