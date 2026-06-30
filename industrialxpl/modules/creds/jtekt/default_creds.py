"""Default credentials — jtekt (issue #5)."""
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        **HttpDefault.__info__,
        "name": "JTEKT TOYOPUC Default Credentials",
        "devices": ("JTEKT TOYOPUC",),
    }

    port = HttpDefault.port
    defaults = HttpDefault.defaults
