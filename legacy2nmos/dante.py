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

import re
import socket

ARC_PORT = 4440

TPL_3201 = bytes.fromhex(
    "280900700020320100000101001000000000420200000000000000000001000000"
    "000068000000000000000000030040000000000002006000000000000000001000"
    "000bc0a80164000000000001e2400000000000000000000000000000000000010002"
    "000001000802138cef010101"
)
# 0x3410 bind: 36-byte form from the real Dante Controller stereo capture
# (rx_stereo.pcap). @20:22 = target Dante RX channel. One bind per channel.
TPL_3410 = bytes.fromhex(
    "2809002400203410000000000000000008000201000100030000000000000000"
    "00000000"
)
assert len(TPL_3201) == 112 and len(TPL_3410) == 36

O_TXID, O_SRC, O_STREAMCH, O_PORT, O_MCAST = 4, 68, 102, 106, 108
O_DESTCH = 96                        # 16-bit dest Dante RX channel in 0x3201
O_TXID2, O_DANTECH = 4, 20           # 0x3410 target channel @20:22
# @52:54 in 0x3201 is a flow-level field (constant across the flow's channels,
# NOT the dest channel) — left at the template value.


def build_bind(dante_channel: int, txid: int = 0x20) -> bytes:
    """0x3410: bindet einen Ziel-Dante-RX-Kanal (ein Bind pro Kanal)."""
    p = bytearray(TPL_3410)
    p[O_TXID2:O_TXID2 + 2] = txid.to_bytes(2, "big")
    p[O_DANTECH:O_DANTECH + 2] = dante_channel.to_bytes(2, "big")
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
    p[O_PORT:O_PORT + 2] = rtp_port.to_bytes(2, "big")
    p[O_MCAST:O_MCAST + 4] = socket.inet_aton(multicast_ip)
    return bytes(p)


def build_clear_channel(dante_channel: int, txid: int = 0x20) -> bytes:
    """Best-effort clear of a Dante RX channel's subscription: a 0x3201 map with
    a zeroed source/multicast/port and stream-channel 0. TODO replace with the
    byte-exact unsubscribe once captured from Dante Controller."""
    p = bytearray(TPL_3201)
    p[O_TXID:O_TXID + 2] = txid.to_bytes(2, "big")
    p[O_SRC:O_SRC + 4] = b"\x00\x00\x00\x00"
    p[O_STREAMCH] = 0
    p[O_DESTCH:O_DESTCH + 2] = dante_channel.to_bytes(2, "big")
    p[O_PORT:O_PORT + 2] = b"\x00\x00"
    p[O_MCAST:O_MCAST + 4] = b"\x00\x00\x00\x00"
    return bytes(p)


def clear_subscription(device_ip: str, dante_channel: int, txid: int = 0x20,
                       timeout: float = 2.0):
    """Send the clear for one RX channel; returns the raw device response."""
    return send(device_ip, build_clear_channel(dante_channel, txid), timeout=timeout)


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


# ---------------------------------------------------------------------------
# AES67 multicast TX flow creation (0x2601) — RE'd from tx_ch.pcap (2026-07-16,
# Dante Controller creating flows on an AVIO USB). Controlled captures with the
# same multicast (239.69.236.153:5004): CH1, CH2 and CH1+2.
#   1-channel flow (112 B): source TX channel @96:98, port @106:108, mcast @108:112
#   2-channel flow (116 B): channel ids @96:98 and @98:100, port @110:112,
#                           mcast @112:116
# The internal count/length fields differ between the 1- and 2-channel templates
# but depend only on the channel COUNT (CH1 and CH2 captures are byte-identical
# except @97), so patching channel ids + mcast + port is byte-exact.
# ---------------------------------------------------------------------------

TPL_2601_1CH = bytes.fromhex(
    "2809007001252601000000000000000001010014162a0000000000030002000000000006000000000000000000000000000000000000000000000000000000000a14000000000000000300000000000000000000040a0100006800000406000100010000020000300802138cef45ec99"
)
TPL_2601_2CH = bytes.fromhex(
    "2809007401372601000000000000000001010014162b0000000000030002000000000006000000000000000000000000000000000000000000000000000000000a15000000000000000300000000000000000000040b0100006c0000050700020001000200000200003000000802138cef45ec99"
)
assert len(TPL_2601_1CH) == 112 and len(TPL_2601_2CH) == 116


def build_create_tx_flow(channels, multicast_ip: str, rtp_port: int = 5004,
                         txid: int = 0x0125) -> bytes:
    """0x2601: legt einen AES67-Multicast-TX-Flow an (1 oder 2 Quellkanaele).

    multicast_ip muss im AES67-Bereich des Geraets liegen (239.<prefix>.x.x).
    """
    chans = [int(c) for c in channels]
    if not chans or len(chans) > 2:
        raise ValueError("nur 1 oder 2 Kanaele werden unterstuetzt")
    if any(not 1 <= c <= 0xFFFF for c in chans):
        raise ValueError("Kanalnummern muessen 1..65535 sein")
    if len(chans) == 1:
        p = bytearray(TPL_2601_1CH)
        p[96:98] = chans[0].to_bytes(2, "big")
        p[106:108] = rtp_port.to_bytes(2, "big")
        p[108:112] = socket.inet_aton(multicast_ip)
    else:
        p = bytearray(TPL_2601_2CH)
        p[96:98] = chans[0].to_bytes(2, "big")
        p[98:100] = chans[1].to_bytes(2, "big")
        p[110:112] = rtp_port.to_bytes(2, "big")
        p[112:116] = socket.inet_aton(multicast_ip)
    p[O_TXID:O_TXID + 2] = txid.to_bytes(2, "big")
    return bytes(p)


# The AES67-flow create (0x2601 / proto 0x2809) is used by Brooklyn/AVIO-based
# devices. Others (e.g. Neutrik) use the classic flow create (0x2201 / proto
# 0x2801). Both echo their opcode on success. This 0x2201 template is byte-exact
# for a 2-channel (ch1+2) flow from a real capture; only txid, port and the
# multicast are patched, so it currently covers the stereo case.
TPL_2201_2CH = bytes.fromhex(
    "280100440000220100000101001000000010000600000000000000000001000200"
    "3c0001000200280a000000000000000030000000000000000300000802138cef440000"
)
assert len(TPL_2201_2CH) == 68


def build_create_tx_flow_classic(multicast_ip: str, rtp_port: int = 5004,
                                 txid: int = 0x2d) -> bytes:
    """0x2201 classic multicast TX flow (2 channels), proto 0x2801."""
    p = bytearray(TPL_2201_2CH)
    p[O_TXID:O_TXID + 2] = txid.to_bytes(2, "big")
    p[62:64] = rtp_port.to_bytes(2, "big")
    p[64:68] = socket.inet_aton(multicast_ip)
    return bytes(p)


def _create_ok(resp, opcode: str) -> bool:
    """A create succeeded if the device echoes the opcode with a full response.
    An unsupported opcode gets a 10-byte error stub (header + 2-byte error code),
    e.g. Neutrik answers 0x2601 with `2809 000a <txid> 2601 0030`."""
    return bool(resp and resp[6:8].hex() == opcode and len(resp) > 10)


def create_tx_flow(device_ip: str, channels, multicast_ip: str,
                   rtp_port: int = 5004, timeout: float = 2.0):
    """Create a multicast TX flow. Tries the AES67 variant (0x2601), then the
    classic variant (0x2201) for devices that speak it. Returns (ok, variant)."""
    pkt = build_create_tx_flow(channels, multicast_ip, rtp_port)
    if _create_ok(send(device_ip, pkt, timeout=timeout), "2601"):
        return True, "aes67"
    # Fall back to the classic flow create (e.g. Neutrik devices).
    resp = send(device_ip, build_create_tx_flow_classic(multicast_ip, rtp_port),
                timeout=timeout)
    if _create_ok(resp, "2201"):
        return True, "classic"
    return False, None


# -- delete / query a multicast TX flow (confirmed via delete_flow_neutrik.pcapng)
# Flow management uses the classic proto 0x2801 for every device (even AES67
# flows created via 0x2601): 0x2200 flow-summary, 0x2204 flow-SDP, 0x2202 delete.
TPL_2202_DELETE = bytes.fromhex("28010010000022020000000100000000")
assert len(TPL_2202_DELETE) == 16
O_DEL_FLOWID = 12                        # 32-bit flow id @12:16

TPL_2204_QUERY = bytes.fromhex("28010010000022040000000100000000")
assert len(TPL_2204_QUERY) == 16
O_Q_SLOT = 12                            # 32-bit flow slot @12:16


def build_delete_tx_flow(flow_id: int, txid: int = 0x91) -> bytes:
    """0x2202 delete of a multicast TX flow by its device flow id."""
    p = bytearray(TPL_2202_DELETE)
    p[O_TXID:O_TXID + 2] = txid.to_bytes(2, "big")
    p[O_DEL_FLOWID:O_DEL_FLOWID + 4] = flow_id.to_bytes(4, "big")
    return bytes(p)


def build_query_flow_sdp(slot: int, txid: int = 0x90) -> bytes:
    """0x2204 query the SDP of the flow in a given slot (1-based)."""
    p = bytearray(TPL_2204_QUERY)
    p[O_TXID:O_TXID + 2] = txid.to_bytes(2, "big")
    p[O_Q_SLOT:O_Q_SLOT + 4] = slot.to_bytes(4, "big")
    return bytes(p)


def _delete_ok(resp) -> bool:
    """Delete succeeded if the device echoes 0x2202 with the OK status word.
    Capture: request `... 2202 0000 0001 0000 0010`, ACK `2801 000a <txid> 2202
    0001 …` — the 0x0001 at bytes 8:10 is the generic ARC success marker."""
    return bool(resp and resp[6:8].hex() == "2202" and resp[8:10] == b"\x00\x01")


def flow_id_from_name(name: str):
    """Dante labels a multicast flow 'DeviceName : <flowid>' in its SDP session
    name; that trailing number is the flow id used to delete it. Confirmed:
    's=Neutrik2IN2OUT-2 : 16' <-> delete flow id 16."""
    if not name:
        return None
    m = re.search(r":\s*(\d+)\s*$", name)
    return int(m.group(1)) if m else None


def query_flow_sdp(device_ip: str, slot: int, timeout: float = 1.0):
    """Return the SDP text of the flow in `slot`, or None if empty/unreachable."""
    resp = send(device_ip, build_query_flow_sdp(slot), timeout=timeout)
    if not resp or resp[6:8].hex() != "2204":
        return None
    i = resp.find(b"v=0")
    if i < 0:
        return None
    return resp[i:].split(b"\x00", 1)[0].decode("ascii", "replace")


def find_flow_id(device_ip: str, multicast_ip: str, max_slots: int = 16,
                 timeout: float = 1.0):
    """Ask the device (not SAP) which flow id carries a multicast, by walking its
    flow slots and matching the SDP's c= line. Returns the flow id or None."""
    want = f"IN IP4 {multicast_ip}"
    for slot in range(1, max_slots + 1):
        sdp = query_flow_sdp(device_ip, slot, timeout=timeout)
        if not sdp:
            continue
        if want in sdp:
            for line in sdp.splitlines():
                if line.startswith("s="):
                    fid = flow_id_from_name(line[2:])
                    if fid is not None:
                        return fid
    return None


def delete_tx_flow(device_ip: str, flow_id: int, txid: int = 0x91,
                   timeout: float = 2.0) -> bool:
    """Delete a multicast TX flow on the device; True iff the device ACKs."""
    return _delete_ok(send(device_ip, build_delete_tx_flow(flow_id, txid),
                           timeout=timeout))


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
