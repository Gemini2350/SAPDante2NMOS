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


# Byte-exact ground truth from Dante3.pcapng #544: source stream channel 6 mapped
# to Dante RX channel 2 (sender 192.168.1.100 / 239.1.1.1:5004).
CAPTURE_CH2 = bytes.fromhex(
    "280900700058320100000101001000000000420200000000000000000001000000"
    "000068000000000000000000030040000000000008006000000000000000001000"
    "000bc0a80164000000000001e2400000000000000000000000000000000000020002"
    "000006000802138cef010101"
)


def test_map_channel_2_matches_capture():
    pkt = dante.build_map_channel("192.168.1.100", "239.1.1.1", 5004,
                                  stream_channel=6, dante_channel=2, txid=0x58)
    assert pkt == CAPTURE_CH2


def test_aes67_prefix_write_matches_capture():
    # Byte-exact ground truth from prefix_l.pcap (Dante Controller):
    #   #0 set prefix 99 (0x63), txid 0x00de
    #   #8 set prefix 69 (0x45), txid 0x00e2
    assert dante.build_set_aes67_prefix(99, 0x00de).hex() == \
        "2809001400de11010000010180600010ef630000"
    assert dante.build_set_aes67_prefix(69, 0x00e2).hex() == \
        "2809001400e211010000010180600010ef450000"


def test_aes67_prefix_parse():
    # Tail of a real 0x1100 response with prefix 69.
    resp = bytes.fromhex("00" * 148)[:-12] + bytes.fromhex("00000000ef450000001e8480")
    assert dante.parse_aes67_prefix(resp) == 69
    assert dante.parse_aes67_prefix(b"\x00" * 20) is None


def test_map_targets_distinct_dante_channels():
    # A stereo receiver must map stream ch1->dante ch1 and ch2->dante ch2,
    # not both to channel 1 (the "only channel 1 switched" bug).
    rx = ReceiverMap("RX 1-2", "192.168.97.101", 1, 2)
    res = translate(rx, parse_aes67_sdp(SDP))
    map1 = bytes.fromhex(res[1]["hex"])
    map2 = bytes.fromhex(res[2]["hex"])
    assert map1[dante.O_DESTCH:dante.O_DESTCH + 2] == b"\x00\x01"
    assert map2[dante.O_DESTCH:dante.O_DESTCH + 2] == b"\x00\x02"
    assert map1[dante.O_DESTENC:dante.O_DESTENC + 2] == b"\x00\x02"
    assert map2[dante.O_DESTENC:dante.O_DESTENC + 2] == b"\x00\x08"
