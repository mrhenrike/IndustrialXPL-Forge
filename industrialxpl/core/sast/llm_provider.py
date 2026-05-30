"""IXF LLM Provider Manager for SAST analysis.

Supports up to 5 providers: OpenAI, Anthropic, Gemini, DeepSeek, Grok.
Default provider: OpenAI (when multiple keys set and OpenAI is one of them).
If no key is set: informs user to add API key.
If key fails: informs user to check and update the key.

Usage:
    provider = LLMProviderManager()
    provider.set_key("openai", "sk-...")
    response = provider.complete(prompt, system_prompt)
"""

import json
import os
import urllib.error
import urllib.request
from typing import Optional

from industrialxpl.core.exploit.printer import print_error, print_info, print_warning


PROVIDER_NAMES = ("openai", "anthropic", "gemini", "deepseek", "grok")

_PROVIDER_CONFIG = {
    "openai": {
        "url":   "https://api.openai.com/v1/chat/completions",
        "model": "gpt-4o",
        "auth":  "Bearer",
        "key_header": "Authorization",
        "format": "openai",
    },
    "anthropic": {
        "url":   "https://api.anthropic.com/v1/messages",
        "model": "claude-3-5-sonnet-20241022",
        "auth":  None,
        "key_header": "x-api-key",
        "format": "anthropic",
        "extra_headers": {"anthropic-version": "2023-06-01"},
    },
    "gemini": {
        "url":   "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
        "model": "gemini-1.5-pro",
        "auth":  None,
        "key_header": None,  # key as query param
        "format": "gemini",
    },
    "deepseek": {
        "url":   "https://api.deepseek.com/chat/completions",
        "model": "deepseek-chat",
        "auth":  "Bearer",
        "key_header": "Authorization",
        "format": "openai",
    },
    "grok": {
        "url":   "https://api.x.ai/v1/chat/completions",
        "model": "grok-2-latest",
        "auth":  "Bearer",
        "key_header": "Authorization",
        "format": "openai",
    },
}

_ENV_KEYS = {
    "openai":    "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini":    "GOOGLE_AI_STUDIO_API_KEY",
    "deepseek":  "DEEPSEEK_API_KEY",
    "grok":      "XAI_API_KEY",
}


class LLMProviderManager:
    """Manages API keys and requests for up to 5 LLM providers."""

    def __init__(self, timeout: int = 120) -> None:
        self._keys: dict[str, str] = {}
        self._timeout = timeout
        self._load_env_keys()

    def _load_env_keys(self) -> None:
        """Load API keys from environment variables."""
        for provider, env_var in _ENV_KEYS.items():
            val = os.environ.get(env_var, "").strip()
            if val:
                self._keys[provider] = val

    def set_key(self, provider: str, api_key: str) -> None:
        """Set (or update) an API key for a provider."""
        provider = provider.lower()
        if provider not in PROVIDER_NAMES:
            raise ValueError("Unknown provider: {}. Choose from: {}".format(
                provider, ", ".join(PROVIDER_NAMES)
            ))
        self._keys[provider] = api_key.strip()

    def get_active_provider(self) -> Optional[str]:
        """Return the active provider name (OpenAI preferred)."""
        if not self._keys:
            return None
        if "openai" in self._keys:
            return "openai"
        # Return first available
        for p in PROVIDER_NAMES:
            if p in self._keys:
                return p
        return None

    def has_any_key(self) -> bool:
        return bool(self._keys)

    def status(self) -> dict:
        """Return status of all providers."""
        return {
            p: "configured" if p in self._keys else "not configured"
            for p in PROVIDER_NAMES
        }

    def complete(
        self,
        user_prompt: str,
        system_prompt: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> str:
        """Send a completion request to the active LLM provider.

        Returns the assistant's response text.
        Raises LLMKeyMissingError if no key is configured.
        Raises LLMKeyInvalidError if the key is rejected.
        Raises LLMRequestError for other failures.
        """
        provider = self.get_active_provider()
        if not provider:
            raise LLMKeyMissingError(
                "No LLM API key configured. "
                "Add a key with: ixf > llm-key <provider> <api-key>\n"
                "Supported providers: {}".format(", ".join(PROVIDER_NAMES))
            )

        api_key = self._keys[provider]
        config  = _PROVIDER_CONFIG[provider]
        fmt     = config["format"]

        try:
            if fmt == "openai":
                return self._request_openai(provider, api_key, config, user_prompt, system_prompt, max_tokens, temperature)
            elif fmt == "anthropic":
                return self._request_anthropic(api_key, config, user_prompt, system_prompt, max_tokens, temperature)
            elif fmt == "gemini":
                return self._request_gemini(api_key, config, user_prompt, system_prompt, max_tokens, temperature)
            else:
                raise LLMRequestError("Unknown format: {}".format(fmt))
        except LLMKeyInvalidError:
            raise
        except LLMKeyMissingError:
            raise
        except Exception as exc:
            raise LLMRequestError(
                "LLM request failed (provider={}): {}".format(provider, exc)
            ) from exc

    def _request_openai(self, provider, api_key, config, user_prompt, system_prompt, max_tokens, temperature):
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})

        body = json.dumps({
            "model":       config["model"],
            "messages":    messages,
            "max_tokens":  max_tokens,
            "temperature": temperature,
        }).encode()

        headers = {
            "Content-Type": "application/json",
            config["key_header"]: "{} {}".format(config["auth"], api_key),
        }
        return self._http_post(config["url"], headers, body, provider)

    def _request_anthropic(self, api_key, config, user_prompt, system_prompt, max_tokens, temperature):
        body_dict = {
            "model":      config["model"],
            "max_tokens": max_tokens,
            "messages":   [{"role": "user", "content": user_prompt}],
        }
        if system_prompt:
            body_dict["system"] = system_prompt

        headers = {
            "Content-Type":       "application/json",
            config["key_header"]: api_key,
        }
        headers.update(config.get("extra_headers", {}))
        return self._http_post(config["url"], headers, json.dumps(body_dict).encode(), "anthropic")

    def _request_gemini(self, api_key, config, user_prompt, system_prompt, max_tokens, temperature):
        url = "{}?key={}".format(config["url"], api_key)
        parts = []
        if system_prompt:
            parts.append({"text": "SYSTEM: {}\n\nUSER: {}".format(system_prompt, user_prompt)})
        else:
            parts.append({"text": user_prompt})

        body = json.dumps({
            "contents": [{"parts": parts}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": temperature,
            },
        }).encode()

        headers = {"Content-Type": "application/json"}
        return self._http_post(url, headers, body, "gemini")

    def _http_post(self, url: str, headers: dict, body: bytes, provider: str) -> str:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode(errors="replace")
            if exc.code in (401, 403):
                raise LLMKeyInvalidError(
                    "API key rejected by {} (HTTP {}). "
                    "Check the key and update with: ixf > llm-key {} <new-key>\n"
                    "Details: {}".format(provider, exc.code, provider, error_body[:200])
                )
            raise LLMRequestError(
                "{} API error HTTP {}: {}".format(provider, exc.code, error_body[:300])
            )

        # Extract text from response
        if provider in ("openai", "deepseek", "grok"):
            return data["choices"][0]["message"]["content"]
        elif provider == "anthropic":
            return data["content"][0]["text"]
        elif provider == "gemini":
            return data["candidates"][0]["content"]["parts"][0]["text"]
        return str(data)


class LLMKeyMissingError(Exception):
    """Raised when no API key is configured."""


class LLMKeyInvalidError(Exception):
    """Raised when the API key is rejected by the provider."""


class LLMRequestError(Exception):
    """Raised for general LLM request failures."""
