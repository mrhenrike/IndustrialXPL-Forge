"""LLM key management and SAST analysis commands (mixin)."""


from industrialxpl.core.exploit.printer import print_error, print_info, print_success, print_table


class SASTCommandsMixin:
    """LLM provider config and PLC SAST analysis commands."""

    def command_llm_key(self, args: str, **kwargs) -> None:
        parts = args.strip().split(None, 1)
        if len(parts) < 2:
            print_error("Usage: llm-key openai|anthropic|gemini|deepseek|grok API_KEY")
            return
        provider, api_key = parts[0].lower(), parts[1].strip()
        try:
            from industrialxpl.modules.assessment.sast.plc_source_analyzer import _llm_manager
            _llm_manager.set_key(provider, api_key)
            print_success(f"LLM key configured: provider={provider} len={len(api_key)}")
        except ValueError as exc:
            print_error(str(exc))

    def command_llm_status(self, args: str = "", **kwargs) -> None:
        try:
            from industrialxpl.modules.assessment.sast.plc_source_analyzer import _llm_manager
            status = _llm_manager.status()
            active = _llm_manager.get_active_provider() or "(none)"
            rows = [(p, s) for p, s in status.items()]
            print_table(["Provider", "Status"], rows, title="LLM Providers")
            print_info(f"Active: {active}")
        except Exception as exc:
            print_error(f"Error: {exc}")

    def command_sast(self, args: str, **kwargs) -> None:
        parts = args.strip().split()
        if not parts:
            print_error("Usage: sast PATH [--mode sast|reverse|diff|exploit-gen]")
            return
        target_path = parts[0]
        mode = "sast"
        diff_with = ""
        i = 1
        while i < len(parts):
            if parts[i] == "--mode" and i + 1 < len(parts):
                mode = parts[i + 1]
                i += 2
            elif parts[i] == "--diff" and i + 1 < len(parts):
                diff_with = parts[i + 1]
                i += 2
            else:
                i += 1
        self.command_use("assessment/sast/plc_source_analyzer")
        if self.current_module:
            self.command_set("target " + target_path)
            self.command_set("mode " + mode)
            self.command_set("simulate false")
            if diff_with:
                self.command_set("diff_with " + diff_with)
            self.command_run("")
