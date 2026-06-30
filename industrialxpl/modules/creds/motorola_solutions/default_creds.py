"""Default credentials — motorola_solutions (issue #5)."""
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        **HttpDefault.__info__,
        "name": "Motorola ACE3600 Default Credentials",
        "devices": ("Motorola ACE3600",),
    }

    port = HttpDefault.port
    defaults = HttpDefault.defaults
