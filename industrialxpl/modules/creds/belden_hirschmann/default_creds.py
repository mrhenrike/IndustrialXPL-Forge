"""Default credentials — belden_hirschmann (issue #5)."""
from industrialxpl.modules.creds.generic.http_default import Exploit as HttpDefault


class Exploit(HttpDefault):
    __info__ = {
        **HttpDefault.__info__,
        "name": "Belden Hirschmann Default Credentials",
        "devices": ("Belden Hirschmann",),
    }

    port = HttpDefault.port
    defaults = HttpDefault.defaults
