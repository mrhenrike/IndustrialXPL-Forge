"""Default credentials — hms_networks (issue #5)."""
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        **HttpDefault.__info__,
        "name": "HMS Ewon Default Credentials",
        "devices": ("HMS Ewon",),
    }

    port = HttpDefault.port
    defaults = HttpDefault.defaults
