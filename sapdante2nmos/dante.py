"""Dante-Steuerprotokoll: Kommando-Builder (Reverse Engineering aus pcap-Captures).

Quelle: Dante.pcapng / dante2.pcapng / Dante3.pcapng. Protokoll 0x2809 (AES67),
Port 4440 (ARC). Ansatz: Template-and-Patch -- unverstandene Bytes bleiben wie im
Original.

Feldkarte 0x3201 (112 B) "Quellkanal -> Ziel-Dante-Kanal mappen":
     @4:6    Transaction-ID
     @52:54  Begleitfeld des Ziel-Dante-Kanals   [bestaetigt fuer ch1/ch2, s.u.]
     @68:72  Source-IP (Sender, unicast)          [bestaetigt]
     @96:98  Ziel-Dante-RX-Kanal                  [BESTAETIGT via Dante3.pcapng]
     @102    Quell-Stream-Kanal (1 Byte)          [bestaetigt: 1..6 beobachtet]
     @106:108 RTP-Port                            [bestaetigt]
     @108:112 Multicast-Adresse                   [bestaetigt]

Das @52:54-Begleitfeld korreliert mit dem Ziel-Kanal:
     Dante-ch 1 -> 0x0002,  Dante-ch 2 -> 0x0008   (byte-genau aus Captures).
Fuer Kanaele >2 ist der Wert extrapoliert (1 << (2*ch-1)) und UNVERIFIZIERT.

0x3410 (28 B) "Flow-Bindung": @20:22 Ziel-Dante-RX-Kanal [HYPOTHESE]. In
Dante3.pcapng tauchte 0x3410 nicht auf (nur 0x3400-Queries), die Rolle des Bind
ist damit weiter offen; wir senden ihn wie in der funktionierenden ch1-Sequenz.
"""
from __future__ import annotations

import socket

ARC_PORT = 4440

TPL_3201 = bytes.fromhex(
    "280900700020320100000101001000000000420200000000000000000001000000"
    "000068000000000000000000030040000000000002006000000000000000001000"
    "000bc0a80164000000000001e2400000000000000000000000000000000000010002"
    "000001000802138cef010101"
)
TPL_3410 = bytes.fromhex("2809001c002034100000000000000000080001010001000300000000")
assert len(TPL_3201) == 112 and len(TPL_3410) == 28

O_TXID, O_SRC, O_STREAMCH, O_PORT, O_MCAST = 4, 68, 102, 106, 108
O_DESTENC, O_DESTCH = 52, 96          # 16-bit dest-channel fields in 0x3201
O_TXID2, O_DANTECH = 4, 20            # 0x3410 (O_DANTECH: HYPOTHESE)

# @52:54 companion value per destination Dante RX channel. Channels 1 and 2 are
# byte-exact from captures; higher channels are extrapolated and unverified.
_DEST_ENC = {1: 0x0002, 2: 0x0008}


def dest_channel_enc(dante_channel: int) -> int:
    if dante_channel in _DEST_ENC:
        return _DEST_ENC[dante_channel]
    return 1 << (2 * dante_channel - 1)  # UNVERIFIED for ch > 2


def build_bind(dante_channel: int, txid: int = 0x20) -> bytes:
    """0x3410: bindet den Flow an einen Ziel-Dante-RX-Kanal."""
    p = bytearray(TPL_3410)
    p[O_TXID2:O_TXID2 + 2] = txid.to_bytes(2, "big")
    p[O_DANTECH:O_DANTECH + 2] = dante_channel.to_bytes(2, "big")  # HYPOTHESE
    return bytes(p)


def build_map_channel(source_ip: str, multicast_ip: str, rtp_port: int,
                      stream_channel: int, dante_channel: int = 1,
                      txid: int = 0x20) -> bytes:
    """0x3201: mappt einen Quell-Stream-Kanal auf einen Ziel-Dante-RX-Kanal."""
    p = bytearray(TPL_3201)
    p[O_TXID:O_TXID + 2] = txid.to_bytes(2, "big")
    p[O_SRC:O_SRC + 4] = socket.inet_aton(source_ip)
    if not 0 <= stream_channel <= 0xFF:
        raise ValueError("stream_channel muss 0..255 sein")
    if not 1 <= dante_channel <= 0xFFFF:
        raise ValueError("dante_channel muss 1..65535 sein")
    p[O_STREAMCH] = stream_channel
    p[O_DESTCH:O_DESTCH + 2] = dante_channel.to_bytes(2, "big")
    p[O_DESTENC:O_DESTENC + 2] = dest_channel_enc(dante_channel).to_bytes(2, "big")
    p[O_PORT:O_PORT + 2] = rtp_port.to_bytes(2, "big")
    p[O_MCAST:O_MCAST + 4] = socket.inet_aton(multicast_ip)
    return bytes(p)


def strip_txid(pkt: bytes) -> bytes:
    """Transaction-ID auf 0 setzen -- fuer stabile Byte-Vergleiche."""
    b = bytearray(pkt)
    b[O_TXID:O_TXID + 2] = b"\x00\x00"
    return bytes(b)


# ---------------------------------------------------------------------------
# AES67 multicast address prefix (per device): the range is 239.<prefix>.x.x.
# Reverse engineered from Dante Controller (prefix_l.pcap, 2026-07-16):
#   WRITE 0x1101 (20 B): byte @17 = prefix, preceded by 0xEF (=239).
#   READ  0x1100 query -> response ends in "ef <prefix> 00 00 00 1e 84 80";
#         prefix is the byte at len-7 (guarded by the 0xEF + trailer).
# ---------------------------------------------------------------------------

TPL_1101_PREFIX = bytes.fromhex("2809001400e211010000010180600010ef450000")  # ef,69
O_PREFIX = 17
TPL_1100_INFO_QUERY = bytes.fromhex(
    "2809003e00df1100000000190201820482050210021182188219830183028306"
    "031003110303802100f08060002200630064006502220212832100660214"
)
_PREFIX_TRAILER = b"\x1e\x84\x80"


def build_set_aes67_prefix(prefix: int, txid: int = 0xE2) -> bytes:
    """0x1101: setzt den AES67-Multicast-Prefix (239.<prefix>.x.x)."""
    if not 0 <= prefix <= 255:
        raise ValueError("prefix muss 0..255 sein")
    p = bytearray(TPL_1101_PREFIX)
    p[O_TXID:O_TXID + 2] = txid.to_bytes(2, "big")
    p[O_PREFIX] = prefix
    return bytes(p)


def parse_aes67_prefix(response: bytes):
    """Prefix aus einer 0x1100-Info-Antwort lesen (None wenn nicht enthalten)."""
    if len(response) >= 8 and response[-8] == 0xEF \
            and response[-3:] == _PREFIX_TRAILER:
        return response[-7]
    return None


def read_aes67_prefix(device_ip: str, txid: int = 0xDF, timeout: float = 2.0):
    """Fragt den AES67-Multicast-Prefix eines Geraets ab."""
    q = bytearray(TPL_1100_INFO_QUERY)
    q[O_TXID:O_TXID + 2] = txid.to_bytes(2, "big")
    resp = send(device_ip, bytes(q), timeout=timeout)
    return parse_aes67_prefix(resp) if resp else None


def set_aes67_prefix(device_ip: str, prefix: int, timeout: float = 2.0):
    """Schreibt den AES67-Multicast-Prefix. Gibt True bei ACK zurueck."""
    resp = send(device_ip, build_set_aes67_prefix(prefix), timeout=timeout)
    return bool(resp and resp[6:8].hex() == "1101")


def send(device_ip: str, pkt: bytes, timeout: float = 2.0):
    """Sendet ein Kommando an das Geraet (UDP, Port 4440) und wartet auf Antwort."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (device_ip, ARC_PORT))
        return s.recvfrom(2048)[0]
    except socket.timeout:
        return None
    finally:
        s.close()
