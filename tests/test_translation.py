"""Offline-Tests: SDP-Parsing und Dante-Uebersetzung gegen Capture-Werte."""
from legacy2nmos import dante
from legacy2nmos.dante_sdp import parse_aes67_sdp
from legacy2nmos.translate import ReceiverMap, translate

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


# Byte-exact 0x3410 binds from the real Dante Controller stereo capture
# (rx_stereo.pcap): #32 binds Dante RX channel 1, #126 binds channel 2.
BIND_CH1 = bytes.fromhex(
    "28090024001c341000000000000000000800020100010003000000000000000000000000")
BIND_CH2 = bytes.fromhex(
    "280900240037341000000000000000000800020100020003000000000000000000000000")


def test_bind_matches_capture():
    assert dante.build_bind(1, 0x1c) == BIND_CH1
    assert dante.build_bind(2, 0x37) == BIND_CH2


def test_bind_dest_channel_patch():
    assert dante.build_bind(8)[dante.O_DANTECH:dante.O_DANTECH + 2] == b"\x00\x08"


def test_stereo_sequence_binds_and_maps_each_channel():
    # A 2-channel receiver: one 0x3410 bind PER channel, then one 0x3201 map per
    # channel — previously only the base channel was bound (only ch1 received).
    rx = ReceiverMap("RX 1-2", "192.168.97.101", 1, 2)
    res = translate(rx, parse_aes67_sdp(SDP))
    assert [s["step"] for s in res] == [
        "bind -> dante-ch 1", "bind -> dante-ch 2",
        "map stream-ch 1 -> dante-ch 1", "map stream-ch 2 -> dante-ch 2"]
    bind1, bind2, map1, map2 = (bytes.fromhex(s["hex"]) for s in res)
    assert bind1[dante.O_DANTECH:dante.O_DANTECH + 2] == b"\x00\x01"
    assert bind2[dante.O_DANTECH:dante.O_DANTECH + 2] == b"\x00\x02"
    # maps: dest Dante channel @96:98 and source stream channel @102
    assert map1[dante.O_DESTCH:dante.O_DESTCH + 2] == b"\x00\x01"
    assert map2[dante.O_DESTCH:dante.O_DESTCH + 2] == b"\x00\x02"
    assert map1[dante.O_STREAMCH] == 1 and map2[dante.O_STREAMCH] == 2


def test_map_matches_capture_channel_fields():
    # Byte-exact against rx_stereo #100 except the flow-level @52:54 field.
    pkt = dante.build_map_channel("192.168.1.100", "239.1.1.1", 5004,
                                  stream_channel=1, dante_channel=1, txid=0x2a)
    assert pkt[dante.O_DESTCH:dante.O_DESTCH + 2] == b"\x00\x01"
    assert pkt[dante.O_STREAMCH] == 1
    assert pkt[dante.O_MCAST:dante.O_MCAST + 4] == bytes([239, 1, 1, 1])


def test_aes67_prefix_write_matches_capture():
    # Byte-exact ground truth from prefix_l.pcap (Dante Controller):
    #   #0 set prefix 99 (0x63), txid 0x00de
    #   #8 set prefix 69 (0x45), txid 0x00e2
    assert dante.build_set_aes67_prefix(99, 0x00de).hex() == \
        "2809001400de11010000010180600010ef630000"
    assert dante.build_set_aes67_prefix(69, 0x00e2).hex() == \
        "2809001400e211010000010180600010ef450000"


def test_create_tx_flow_matches_capture():
    # Byte-exact ground truth from tx_ch.pcap (Dante Controller, AVIO USB),
    # all with multicast 239.69.236.153:5004.
    mc, port = "239.69.236.153", 5004
    assert dante.build_create_tx_flow([1], mc, port, 0x0125).hex() == \
        dante.TPL_2601_1CH.hex()
    ch2 = dante.build_create_tx_flow([2], mc, port, 0x012d)
    assert ch2[96:98] == b"\x00\x02"
    assert dante.build_create_tx_flow([1, 2], mc, port, 0x0137).hex() == \
        dante.TPL_2601_2CH.hex()


def test_create_tx_flow_patches_channels_and_mcast():
    pkt = dante.build_create_tx_flow([3, 4], "239.69.10.20", 5004, 0x0140)
    assert pkt[96:98] == b"\x00\x03" and pkt[98:100] == b"\x00\x04"
    assert pkt[-4:] == bytes([239, 69, 10, 20])


def test_create_tx_flow_rejects_too_many_channels():
    import pytest
    with pytest.raises(ValueError):
        dante.build_create_tx_flow([1, 2, 3], "239.69.1.1")


def test_aes67_prefix_parse():
    # Tail of a real 0x1100 response with prefix 69.
    resp = bytes.fromhex("00" * 148)[:-12] + bytes.fromhex("00000000ef450000001e8480")
    assert dante.parse_aes67_prefix(resp) == 69
    assert dante.parse_aes67_prefix(b"\x00" * 20) is None


