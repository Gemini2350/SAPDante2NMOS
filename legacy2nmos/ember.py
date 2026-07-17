"""Minimal Ember+ consumer: S101 framing + BER/Glow over TCP.

Ember+ is Lawo's open control protocol. Transport is S101 (a HDLC-like framing
with byte stuffing and a CRC-16/CCITT) over TCP (default port 9000); the payload
is a BER-encoded "Glow" tree of Nodes, Parameters and Commands.

This is a from-scratch consumer implementation (no maintained PyPI library
exists). It supports what the gateway needs:
  - connect / keepalive
  - GetDirectory to walk the tree (lazy, node by node)
  - read parameter values
  - set a parameter value

The Glow encoding follows the Ember+ / libember "GlowDTD": application tags on
[APPLICATION n] with universal SEQUENCE/SET containers.
"""

from __future__ import annotations

import socket
import struct

# --- S101 framing ---------------------------------------------------------

_BOF = 0xFE          # begin of frame
_EOF = 0xFF          # end of frame
_CE = 0xFD           # escape
_XOR = 0x20
_INV = 0xF8          # bytes >= this must be escaped

S101_SLOT = 0x00
MSG_EMBER = 0x0E
CMD_PAYLOAD = 0x00
CMD_KEEPALIVE_REQ = 0x01
CMD_KEEPALIVE_RSP = 0x02
DTD_GLOW = 0x01


def _crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT-FALSE as used by S101 (poly 0x1021, init 0xFFFF)."""
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _escape(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b >= _INV:
            out.append(_CE)
            out.append(b ^ _XOR)
        else:
            out.append(b)
    return bytes(out)


def s101_encode(payload: bytes, command: int = CMD_PAYLOAD,
                glow_ver=(0x02, 0x1F)) -> bytes:
    """Wrap a BER payload in a single S101/EmBER frame."""
    body = bytearray()
    body.append(S101_SLOT)
    body.append(MSG_EMBER)
    body.append(command)
    body.append(0x01)              # version
    if command == CMD_PAYLOAD:
        body.append(0xC0)          # flags: first+last packet (single frame)
        body.append(DTD_GLOW)
        body.append(0x02)          # app-bytes count
        body.append(glow_ver[0])
        body.append(glow_ver[1])
        body += payload
    # CRC over the (unescaped) body
    crc = _crc16_ccitt(body) ^ 0xFFFF
    framed = _escape(bytes(body)) + _escape(struct.pack("<H", crc))
    return bytes([_BOF]) + framed + bytes([_EOF])


def keepalive_response() -> bytes:
    return s101_encode(b"", command=CMD_KEEPALIVE_RSP)


class S101Decoder:
    """Reassembles S101 frames from a TCP byte stream. Yields BER payloads."""

    def __init__(self):
        self._buf = bytearray()
        self._in_frame = False
        self._escape = False

    def feed(self, data: bytes):
        frames = []
        for b in data:
            if b == _BOF:
                self._buf.clear()
                self._in_frame = True
                self._escape = False
                continue
            if not self._in_frame:
                continue
            if b == _EOF:
                frame = bytes(self._buf)
                self._in_frame = False
                out = self._parse_frame(frame)
                if out is not None:
                    frames.append(out)
                continue
            if b == _CE:
                self._escape = True
                continue
            self._buf.append(b ^ _XOR if self._escape else b)
            self._escape = False
        return frames

    @staticmethod
    def _parse_frame(frame: bytes):
        """Return (command, payload) or None. CRC already stripped/checked."""
        if len(frame) < 4:
            return None
        body, crc_bytes = frame[:-2], frame[-2:]
        got = struct.unpack("<H", crc_bytes)[0]
        if (_crc16_ccitt(body) ^ 0xFFFF) != got:
            return None
        # body: slot, msg, command, version, [flags, dtd, appbytes.., payload]
        command = body[2]
        if command != CMD_PAYLOAD:
            return (command, b"")
        appbytes = body[6] if len(body) > 6 else 0
        payload = body[7 + appbytes:]
        return (command, payload)


# --- BER (subset for Glow) ------------------------------------------------

# BER tag classes
UNIVERSAL, APPLICATION, CONTEXT = 0x00, 0x40, 0x80
CONSTRUCTED = 0x20

# Universal tags
U_INT, U_OCTSTR, U_NULL, U_OID, U_REAL = 2, 4, 5, 6, 9
U_BOOL, U_UTF8, U_RELOID = 1, 12, 13
U_SEQ, U_SET = 16, 16  # both constructed containers here


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _enc_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(value)) + value


def _enc_int(v: int) -> bytes:
    if v == 0:
        return b"\x00"
    n = v.to_bytes((v.bit_length() + 8) // 8, "big", signed=True)
    return n


def enc_context(number: int, inner: bytes) -> bytes:
    """[context number] constructed wrapper around one inner TLV."""
    return _enc_tlv(CONTEXT | CONSTRUCTED | number, inner)


def enc_int_value(number: int, v: int) -> bytes:
    return enc_context(number, _enc_tlv(U_INT, _enc_int(v)))


def _read_len(buf: bytes, i: int):
    first = buf[i]
    i += 1
    if first < 0x80:
        return first, i
    nb = first & 0x7F
    n = int.from_bytes(buf[i:i + nb], "big")
    return n, i + nb


def ber_parse(buf: bytes, i: int = 0, end: int | None = None):
    """Yield (tag, is_constructed, number, value_bytes, next_index)."""
    if end is None:
        end = len(buf)
    items = []
    while i < end:
        tag = buf[i]
        i += 1
        cls = tag & 0xC0
        constructed = bool(tag & CONSTRUCTED)
        number = tag & 0x1F
        length, i = _read_len(buf, i)
        value = buf[i:i + length]
        items.append((cls, constructed, number, value))
        i += length
    return items


def dec_int(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=True) if value else 0


def dec_utf8(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def dec_value(number: int, value: bytes):
    """Decode a Glow parameter value (universal-typed inner)."""
    if number == U_INT:
        return dec_int(value)
    if number == U_UTF8:
        return dec_utf8(value)
    if number == U_BOOL:
        return bool(value and value[0])
    if number == U_OCTSTR:
        return value
    if number == U_REAL:
        return _dec_real(value)
    return value


def _dec_real(value: bytes) -> float:
    if not value:
        return 0.0
    first = value[0]
    if first & 0x80:  # binary encoding
        sign = -1 if first & 0x40 else 1
        exp_len = (first & 0x03) + 1
        exp = int.from_bytes(value[1:1 + exp_len], "big", signed=True)
        mant = int.from_bytes(value[1 + exp_len:], "big")
        return sign * mant * (2.0 ** exp)
    try:
        return float(value.decode("ascii"))
    except ValueError:
        return 0.0


# --- Glow application tags (from GlowDTD) ---------------------------------

G_PARAMETER = 1
G_COMMAND = 2
G_NODE = 3
G_ELEMENT_COLLECTION = 4
G_STRING_INT_PAIR = 7
G_QUALIFIED_PARAMETER = 9
G_QUALIFIED_NODE = 10
G_ROOT_ELEMENT_COLLECTION = 11
G_FUNCTION = 19
G_QUALIFIED_FUNCTION = 20


def _oid_to_str(value: bytes) -> str:
    # RELATIVE-OID: base-128 encoded sub-identifiers
    parts, n = [], 0
    for b in value:
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(n))
            n = 0
    return ".".join(parts)


def enc_reloid(path: str) -> bytes:
    out = bytearray()
    for part in path.split("."):
        n = int(part)
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.insert(0, (n & 0x7F) | 0x80)
            n >>= 7
        out += bytes(chunk)
    return bytes(out)


def cmd_getdirectory() -> bytes:
    """A Command(number=32 GetDirectory) element."""
    # Command ::= [APPLICATION 2] SEQUENCE { number [0] INTEGER, ... }
    inner = enc_int_value(0, 32)  # number = GetDirectory
    return _enc_tlv(APPLICATION | CONSTRUCTED | G_COMMAND, inner)


def root_getdirectory() -> bytes:
    """Root collection carrying a single GetDirectory command."""
    element = _enc_tlv(CONTEXT | CONSTRUCTED | 0, cmd_getdirectory())
    return _enc_tlv(APPLICATION | CONSTRUCTED | G_ROOT_ELEMENT_COLLECTION, element)


def qualified_getdirectory(path: str) -> bytes:
    """GetDirectory on a QualifiedNode at `path` (dotted, e.g. "1.2")."""
    qn_inner = bytearray()
    qn_inner += enc_context(0, _enc_tlv(U_RELOID, enc_reloid(path)))  # path
    children = _enc_tlv(APPLICATION | CONSTRUCTED | G_ELEMENT_COLLECTION,
                        _enc_tlv(CONTEXT | CONSTRUCTED | 0, cmd_getdirectory()))
    qn_inner += enc_context(2, children)  # children [2]
    qn = _enc_tlv(APPLICATION | CONSTRUCTED | G_QUALIFIED_NODE, bytes(qn_inner))
    element = _enc_tlv(CONTEXT | CONSTRUCTED | 0, qn)
    return _enc_tlv(APPLICATION | CONSTRUCTED | G_ROOT_ELEMENT_COLLECTION, element)


def qualified_set_parameter(path: str, value, value_tag: int) -> bytes:
    """Set a QualifiedParameter's value at `path`."""
    contents = enc_context(1, _enc_tlv(value_tag, _encode_scalar(value, value_tag)))
    qp_inner = bytearray()
    qp_inner += enc_context(0, _enc_tlv(U_RELOID, enc_reloid(path)))
    qp_inner += enc_context(1, _enc_tlv(U_SET | CONSTRUCTED, contents))  # contents [1] SET
    qp = _enc_tlv(APPLICATION | CONSTRUCTED | G_QUALIFIED_PARAMETER, bytes(qp_inner))
    element = _enc_tlv(CONTEXT | CONSTRUCTED | 0, qp)
    return _enc_tlv(APPLICATION | CONSTRUCTED | G_ROOT_ELEMENT_COLLECTION, element)


def _encode_scalar(value, tag: int) -> bytes:
    if tag == U_INT:
        return _enc_int(int(value))
    if tag == U_UTF8:
        return str(value).encode("utf-8")
    if tag == U_BOOL:
        return b"\xff" if value else b"\x00"
    if tag == U_OCTSTR:
        return bytes(value)
    raise ValueError(f"unsupported value tag {tag}")


class EmberError(Exception):
    pass


class EmberClient:
    """Blocking Ember+ consumer over TCP."""

    def __init__(self, host: str, port: int = 9000, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.decoder = S101Decoder()

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock.settimeout(self.timeout)

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *a):
        self.close()

    def _send(self, ber_payload: bytes):
        self.sock.sendall(s101_encode(ber_payload))

    def _recv_payloads(self, deadline_reads: int = 40):
        """Read frames until a payload arrives; answer keepalive requests."""
        payloads = []
        for _ in range(deadline_reads):
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            for command, payload in self.decoder.feed(data):
                if command == CMD_KEEPALIVE_REQ:
                    self.sock.sendall(keepalive_response())
                elif command == CMD_PAYLOAD and payload:
                    payloads.append(payload)
            if payloads:
                break
        return payloads

    def get_directory(self, path: str | None = None):
        """Return the child elements at `path` (None = root)."""
        req = root_getdirectory() if not path else qualified_getdirectory(path)
        self._send(req)
        elements = []
        for payload in self._recv_payloads():
            elements += parse_glow_elements(payload, base_path=path)
        return elements

    def set_parameter(self, path: str, value, value_tag: int = U_INT):
        self._send(qualified_set_parameter(path, value, value_tag))
        self._recv_payloads(deadline_reads=4)  # drain the acknowledgement


# --- Glow tree parsing ----------------------------------------------------

class GlowElement:
    def __init__(self, kind, number, path, identifier=None, description=None,
                 value=None, is_online=None):
        self.kind = kind              # 'node' | 'parameter' | 'function'
        self.number = number
        self.path = path              # dotted absolute path
        self.identifier = identifier
        self.description = description
        self.value = value
        self.is_online = is_online

    def as_dict(self):
        return {"kind": self.kind, "number": self.number, "path": self.path,
                "identifier": self.identifier, "description": self.description,
                "value": self.value if not isinstance(self.value, bytes)
                else self.value.hex()}


def _join(base, number):
    return str(number) if not base else f"{base}.{number}"


def parse_glow_elements(payload: bytes, base_path=None):
    """Parse a RootElementCollection payload into a flat list of GlowElements."""
    out = []
    for cls, cons, num, val in ber_parse(payload):
        if cls == APPLICATION and num in (G_ROOT_ELEMENT_COLLECTION,
                                          G_ELEMENT_COLLECTION):
            for c2, cc2, n2, v2 in ber_parse(val):
                # each is a [context 0] wrapping the actual element
                if c2 == CONTEXT and cons:
                    for c3, cc3, n3, v3 in ber_parse(v2):
                        _parse_element(c3, n3, v3, base_path, out)
        else:
            _parse_element(cls, num, val, base_path, out)
    return out


def _parse_element(cls, num, val, base_path, out):
    if cls != APPLICATION:
        return
    if num in (G_NODE, G_PARAMETER, G_FUNCTION):
        _parse_numbered(num, val, base_path, out)
    elif num in (G_QUALIFIED_NODE, G_QUALIFIED_PARAMETER, G_QUALIFIED_FUNCTION):
        _parse_qualified(num, val, out)


def _parse_numbered(num, val, base_path, out):
    number = None
    contents = None
    for cls, cons, n, v in ber_parse(val):
        if cls == CONTEXT and n == 0:
            for _, _, tn, tv in ber_parse(v):
                number = dec_int(tv)
        elif cls == CONTEXT and n == 1:
            contents = v
    if number is None:
        return
    path = _join(base_path, number)
    out.append(_build_element(num, number, path, contents))


def _parse_qualified(num, val, out):
    path = None
    contents = None
    for cls, cons, n, v in ber_parse(val):
        if cls == CONTEXT and n == 0:
            for _, _, tn, tv in ber_parse(v):
                path = _oid_to_str(tv)
        elif cls == CONTEXT and n == 1:
            contents = v
    if path is None:
        return
    number = int(path.split(".")[-1])
    kind = {G_QUALIFIED_NODE: G_NODE, G_QUALIFIED_PARAMETER: G_PARAMETER,
            G_QUALIFIED_FUNCTION: G_FUNCTION}[num]
    out.append(_build_element(kind, number, path, contents))


def _build_element(kind_tag, number, path, contents):
    identifier = description = value = is_online = None
    if contents:
        for cls, cons, n, v in ber_parse(contents):
            if cls != CONTEXT:
                continue
            inner = ber_parse(v)
            if not inner:
                continue
            _, _, tn, tv = inner[0]
            if n == 0:
                identifier = dec_utf8(tv)
            elif n == 1:
                description = dec_utf8(tv)
            elif n == 2 and kind_tag == G_PARAMETER:
                value = dec_value(tn, tv)      # parameter value
            elif n == 5 and kind_tag == G_NODE:
                is_online = bool(tv and tv[0])
    kind = {G_NODE: "node", G_PARAMETER: "parameter",
            G_FUNCTION: "function"}[kind_tag]
    return GlowElement(kind, number, path, identifier, description, value,
                       is_online)
