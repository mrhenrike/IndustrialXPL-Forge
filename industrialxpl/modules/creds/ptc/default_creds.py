"""Default credentials — ptc (issue #5)."""
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        **HttpDefault.__info__,
        "name": "PTC Kepware Default Credentials",
        "devices": ("PTC Kepware",),
    }

    port = HttpDefault.port
    defaults = HttpDefault.defaults
