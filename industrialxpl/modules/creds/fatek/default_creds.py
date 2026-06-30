"""Default credentials — fatek (issue #5)."""
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        **HttpDefault.__info__,
        "name": "Fatek PLC Default Credentials",
        "devices": ("Fatek PLC",),
    }

    port = HttpDefault.port
    defaults = HttpDefault.defaults
