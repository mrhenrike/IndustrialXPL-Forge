"""Default credentials — ruggedcom (issue #5)."""
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        **HttpDefault.__info__,
        "name": "RuggedCom RS Default Credentials",
        "devices": ("RuggedCom RS",),
    }

    port = HttpDefault.port
    defaults = HttpDefault.defaults
