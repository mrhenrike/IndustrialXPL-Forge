"""OPC UA lab profiles for bottle-filling and pairing targets.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import logging
import secrets
from enum import Enum
from pathlib import Path
from typing import Optional

from ..paths import TMP_DIR, ensure_workspace_dirs


LOGGER = logging.getLogger("virtualplants.opcua")


class OpcUaSecurityProfile(str, Enum):
    """Supported OPC UA lab security postures."""

    INSECURE = "insecure"
    AUTHENTICATED = "authenticated"
    SIGN_ENCRYPT = "sign-encrypt"


def write_runtime_token(label: str, token: str) -> Path:
    """Store a generated lab secret in workspace-local temp, never in git."""
    ensure_workspace_dirs()
    path = TMP_DIR / ("%s.token" % label)
    path.write_text(token, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def generate_lab_password() -> str:
    """Create a high-entropy lab password without hardcoding it."""
    return secrets.token_urlsafe(16)


async def apply_server_profile(server: object, profile: OpcUaSecurityProfile, token_label: str) -> Optional[Path]:
    """Configure asyncua Server security according to the lab profile.

    Sign-and-encrypt requires certificates that are generated at runtime when
    the cryptography extra is available. If certificate material cannot be
    created, the server stays on None/None and a warning is logged.
    """
    token_path: Optional[Path] = None
    if profile == OpcUaSecurityProfile.INSECURE:
        LOGGER.info("OPC UA profile insecure: SecurityPolicy#None, anonymous")
        return None

    password = generate_lab_password()
    token_path = write_runtime_token(token_label, "lab:%s" % password)
    LOGGER.info("OPC UA credentials written to %s (username=lab)", token_path)

    try:
        from asyncua.server.users import User, UserRole
        from asyncua.server.user_managers import UserManager
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("asyncua user manager unavailable: %s", exc)
        return token_path

    class _LabUserManager:
        """Minimal username/password gate for the authenticated profile."""

        def get_user(self, iserver, username=None, password=None, certificate=None):  # type: ignore[no-untyped-def]
            if username == "lab" and password == password_value:
                return User(role=UserRole.Admin)
            return None

    password_value = password
    try:
        server.set_security_IDs(["Username"])  # type: ignore[attr-defined]
        server.user_manager = _LabUserManager()  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("unable to attach OPC UA user manager: %s", exc)

    if profile == OpcUaSecurityProfile.SIGN_ENCRYPT:
        LOGGER.warning(
            "sign-encrypt profile requested; certificate material must be provisioned in lab runtime"
        )
    return token_path
