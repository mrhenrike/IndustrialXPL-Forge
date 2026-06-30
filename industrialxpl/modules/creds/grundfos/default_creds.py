"""Default credentials — grundfos (issue #5)."""
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        **HttpDefault.__info__,
        "name": "Grundfos SmartConnect Default Credentials",
        "devices": ("Grundfos SmartConnect",),
    }

    port = HttpDefault.port
    defaults = HttpDefault.defaults
