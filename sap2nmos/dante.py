"""Dante-Steuerprotokoll: Kommando-Builder (Reverse Engineering aus pcap-Captures).

Quelle: Dante.pcapng / dante2.pcapng. Protokoll 0x2809 (AES67), Port 4440 (ARC).
Ansatz: Template-and-Patch -- unverstandene Bytes bleiben wie im Original.

Bekannte Felder:
  0x3201 (112 B) "Quellkanal in Flow mappen"
     @4:6   Transaction-ID
     @68:72 Source-IP (Sender, unicast)          [bestaetigt]
     @102   Quellkanal im Stream (1 Byte)         [bestaetigt: 1..6 beobachtet]
     @106:108 RTP-Port                            [bestaetigt]
     @108:112 Multicast-Adresse                   [bestaetigt]
  0x3410 (28 B) "Flow-Bindung"
     @4:6   Transaction-ID
     @20:22 Ziel-Dante-RX-Kanal                   [HYPOTHESE -- gegen Testgeraet pruefen]
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
O_TXID2, O_DANTECH = 4, 20  # O_DANTECH: HYPOTHESE


def build_bind(dante_channel: int, txid: int = 0x20) -> bytes:
    """0x3410: bindet den Flow an einen Ziel-Dante-RX-Kanal."""
    p = bytearray(TPL_3410)
    p[O_TXID2:O_TXID2 + 2] = txid.to_bytes(2, "big")
    p[O_DANTECH:O_DANTECH + 2] = dante_channel.to_bytes(2, "big")  # HYPOTHESE
    return bytes(p)


def build_map_channel(source_ip: str, multicast_ip: str, rtp_port: int,
                      stream_channel: int, txid: int = 0x20) -> bytes:
    """0x3201: mappt einen Quell-Stream-Kanal in den Flow."""
    p = bytearray(TPL_3201)
    p[O_TXID:O_TXID + 2] = txid.to_bytes(2, "big")
    p[O_SRC:O_SRC + 4] = socket.inet_aton(source_ip)
    if not 0 <= stream_channel <= 0xFF:
        raise ValueError("stream_channel muss 0..255 sein")
    p[O_STREAMCH] = stream_channel
    p[O_PORT:O_PORT + 2] = rtp_port.to_bytes(2, "big")
    p[O_MCAST:O_MCAST + 4] = socket.inet_aton(multicast_ip)
    return bytes(p)


def strip_txid(pkt: bytes) -> bytes:
    """Transaction-ID auf 0 setzen -- fuer stabile Byte-Vergleiche."""
    b = bytearray(pkt)
    b[O_TXID:O_TXID + 2] = b"\x00\x00"
    return bytes(b)


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
