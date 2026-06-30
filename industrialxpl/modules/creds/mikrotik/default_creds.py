"""Default credentials — mikrotik (issue #5)."""
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        **HttpDefault.__info__,
        "name": "Mikrotik RouterOS Default Credentials",
        "devices": ("Mikrotik RouterOS",),
    }

    port = HttpDefault.port
    defaults = HttpDefault.defaults
