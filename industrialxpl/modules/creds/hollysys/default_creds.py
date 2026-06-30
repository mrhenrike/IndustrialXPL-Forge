"""Default credentials — hollysys (issue #5)."""
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        **HttpDefault.__info__,
        "name": "Hollysys LK Default Credentials",
        "devices": ("Hollysys LK",),
    }

    port = HttpDefault.port
    defaults = HttpDefault.defaults
