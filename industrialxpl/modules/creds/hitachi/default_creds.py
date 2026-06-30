"""Default credentials — hitachi (issue #5)."""
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        **HttpDefault.__info__,
        "name": "Hitachi HMI Default Credentials",
        "devices": ("Hitachi HMI",),
    }

    port = HttpDefault.port
    defaults = HttpDefault.defaults
