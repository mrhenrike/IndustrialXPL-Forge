"""Default credentials — fanuc (issue #5)."""
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        **HttpDefault.__info__,
        "name": "Fanuc CNC Default Credentials",
        "devices": ("Fanuc CNC",),
    }

    port = HttpDefault.port
    defaults = HttpDefault.defaults
