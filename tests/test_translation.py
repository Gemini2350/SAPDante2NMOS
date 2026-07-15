"""Offline-Tests: SDP-Parsing und Dante-Uebersetzung gegen Capture-Werte."""
from sapdante2nmos import dante
from sapdante2nmos.dante_sdp import parse_aes67_sdp
from sapdante2nmos.translate import ReceiverMap, translate

SDP = (
    "v=0\r\no=- 123456 11 IN IP4 192.168.1.100\r\ns=Dante\r\n"
    "c=IN IP4 239.1.1.1/32\r\nt=0 0\r\nm=audio 5004 RTP/AVP 96\r\n"
    "a=rtpmap:96 L24/48000/2\r\n"
    "a=source-filter: incl IN IP4 239.1.1.1 192.168.1.100\r\na=ptime:1\r\n"
)


def test_sdp_parse():
    p = parse_aes67_sdp(SDP)
    assert p.source_ip == "192.168.1.100"
    assert p.multicast_ip == "239.1.1.1"
    assert p.port == 5004
    assert p.channels == 2
    assert p.sample_rate == 48000


def test_bind_matches_capture():
    rx = ReceiverMap("RX 1-2", "192.168.97.101", 1, 2)
    res = translate(rx, parse_aes67_sdp(SDP))
    b0 = bytes.fromhex(res[0]["hex"])
    assert dante.strip_txid(b0) == dante.strip_txid(dante.TPL_3410)


def test_first_map_matches_capture():
    rx = ReceiverMap("RX 1-2", "192.168.97.101", 1, 2)
    res = translate(rx, parse_aes67_sdp(SDP))
    b1 = bytes.fromhex(res[1]["hex"])
    assert dante.strip_txid(b1) == dante.strip_txid(dante.TPL_3201)


def test_channel_field_increments():
    rx = ReceiverMap("RX 1-2", "192.168.97.101", 1, 2)
    res = translate(rx, parse_aes67_sdp(SDP))
    assert bytes.fromhex(res[1]["hex"])[dante.O_STREAMCH] == 1
    assert bytes.fromhex(res[2]["hex"])[dante.O_STREAMCH] == 2


def test_bind_dest_channel_patch():
    assert dante.build_bind(8)[dante.O_DANTECH:dante.O_DANTECH + 2] == b"\x00\x08"
