"""Default credentials — sick_ag (issue #5)."""
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        **HttpDefault.__info__,
        "name": "SICK Sensor Default Credentials",
        "devices": ("SICK Sensor",),
    }

    port = HttpDefault.port
    defaults = HttpDefault.defaults
