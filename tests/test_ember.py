"""Offline tests for the Ember+ consumer (S101 framing + BER/Glow)."""
from legacy2nmos import ember
from legacy2nmos.ember import (
    S101Decoder, s101_encode, keepalive_response, CMD_PAYLOAD, CMD_KEEPALIVE_RSP,
    _crc16_ccitt, _enc_len, enc_reloid, _oid_to_str, parse_glow_elements,
    APPLICATION, CONTEXT, CONSTRUCTED, U_INT, U_UTF8, _enc_tlv, enc_context,
    G_ROOT_ELEMENT_COLLECTION, G_NODE, G_PARAMETER,
)


def test_crc16_ccitt_false_known_vector():
    # CRC-16/CCITT-FALSE("123456789") == 0x29B1
    assert _crc16_ccitt(b"123456789") == 0x29B1


def test_ber_length_encoding():
    assert _enc_len(0) == b"\x00"
    assert _enc_len(127) == b"\x7f"
    assert _enc_len(128) == b"\x81\x80"
    assert _enc_len(300) == b"\x82\x01\x2c"


def test_reloid_roundtrip():
    for path in ("1", "1.2", "1.2.30", "10.200.3000"):
        assert _oid_to_str(enc_reloid(path)) == path


def test_s101_frame_roundtrip_with_escaping():
    # Payload includes bytes that must be escaped (>= 0xF8: FE, FF, FD).
    payload = bytes([0x30, 0xFE, 0xFF, 0xFD, 0xF8, 0x01, 0x02])
    frame = s101_encode(payload)
    assert frame[0] == 0xFE and frame[-1] == 0xFF
    # No raw framing/escape bytes leak into the middle of the frame.
    assert 0xFE not in frame[1:-1] and 0xFF not in frame[1:-1]
    got = S101Decoder().feed(frame)
    assert got == [(CMD_PAYLOAD, payload)]


def test_s101_split_across_reads():
    payload = b"\x60\x03\x02\x01\x2a"
    frame = s101_encode(payload)
    dec = S101Decoder()
    out = []
    for i in range(0, len(frame), 3):        # feed in chunks
        out += dec.feed(frame[i:i + 3])
    assert out == [(CMD_PAYLOAD, payload)]


def test_bad_crc_is_dropped():
    frame = bytearray(s101_encode(b"\x60\x00"))
    frame[3] ^= 0xFF  # corrupt a body byte -> CRC mismatch
    assert S101Decoder().feed(bytes(frame)) == []


def test_keepalive_response_decodes():
    got = S101Decoder().feed(keepalive_response())
    assert got == [(CMD_KEEPALIVE_RSP, b"")]


def _build_glow_response():
    """Root collection with a Node(1,'core') and a Parameter(2,'gain'=42)."""
    def numbered(app_tag, number, identifier, extra=b""):
        inner = enc_context(0, _enc_tlv(U_INT, ember._enc_int(number)))
        contents = enc_context(0, _enc_tlv(U_UTF8, identifier.encode())) + extra
        inner += enc_context(1, contents)
        return _enc_tlv(APPLICATION | CONSTRUCTED | app_tag, inner)

    node = numbered(G_NODE, 1, "core")
    gain_val = enc_context(2, _enc_tlv(U_INT, ember._enc_int(42)))
    param = numbered(G_PARAMETER, 2, "gain", extra=gain_val)
    coll = _enc_tlv(CONTEXT | CONSTRUCTED | 0, node) \
        + _enc_tlv(CONTEXT | CONSTRUCTED | 0, param)
    return _enc_tlv(APPLICATION | CONSTRUCTED | G_ROOT_ELEMENT_COLLECTION, coll)


def test_parse_glow_nodes_and_parameters():
    els = parse_glow_elements(_build_glow_response())
    by_id = {e.identifier: e for e in els}
    assert by_id["core"].kind == "node" and by_id["core"].path == "1"
    assert by_id["gain"].kind == "parameter" and by_id["gain"].value == 42
