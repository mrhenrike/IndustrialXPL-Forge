"""Default credentials — prosoft (issue #5)."""
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        **HttpDefault.__info__,
        "name": "ProSoft MVI Default Credentials",
        "devices": ("ProSoft MVI",),
    }

    port = HttpDefault.port
    defaults = HttpDefault.defaults
