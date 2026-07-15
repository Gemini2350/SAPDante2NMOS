import re

RTPMAP_RE = re.compile(r"a=rtpmap:\d+\s+L(\d+)/(\d+)(?:/(\d+))?", re.IGNORECASE)


def parse_sdp(sdp):
    """Extract the fields we care about from an SDP text blob."""
    data = {}
    for line in sdp.splitlines():
        line = line.strip()
        if line.startswith("s="):
            data["name"] = line[2:].strip()
        elif line.startswith("o="):
            parts = line.split()
            if len(parts) >= 6:
                data["src_ip"] = parts[5]
        elif line.startswith("c=IN IP4"):
            parts = line.split()
            if len(parts) >= 3:
                data["ip"] = parts[2].split("/")[0]
        elif line.startswith("m=audio"):
            parts = line.split()
            if len(parts) >= 2 and "port" not in data:
                try:
                    data["port"] = int(parts[1])
                except ValueError:
                    pass
        else:
            m = RTPMAP_RE.match(line)
            if m and "bit" not in data:
                data["bit"] = int(m.group(1))
                data["rate"] = int(m.group(2))
                if m.group(3):
                    data["ch"] = int(m.group(3))
    return data


def build_match_key(parsed):
    """Key used to detect senders already present in the registry."""
    ip = parsed.get("ip")
    if not ip:
        return None
    return f"{ip}|{parsed.get('src_ip') or 'any'}"


def format_string(parsed):
    bit = parsed.get("bit")
    rate = parsed.get("rate")
    ch = parsed.get("ch")
    if not bit:
        return ""
    s = f"L{bit}"
    if rate:
        s += f" / {rate / 1000:g} kHz"
    if ch:
        s += f" / {ch}ch"
    return s


def parse_sap(data):
    """Parse a SAP packet (RFC 2974). Returns (sdp_text_or_None, is_deletion)."""
    if len(data) < 8:
        return None, False

    flags = data[0]
    ipv6 = bool(flags & 0x10)
    deletion = bool(flags & 0x04)
    encrypted = bool(flags & 0x02)
    compressed = bool(flags & 0x01)

    if encrypted or compressed:
        return None, deletion

    auth_len = data[1]
    offset = 4 + (16 if ipv6 else 4) + auth_len * 4
    if offset >= len(data):
        return None, deletion

    payload = data[offset:]
    if not payload.startswith(b"v="):
        # Optional null-terminated MIME type precedes the SDP.
        nul = payload.find(b"\x00", 0, 64)
        if nul != -1 and payload[nul + 1:nul + 3] == b"v=":
            payload = payload[nul + 1:]
        else:
            idx = data.find(b"application/sdp\x00")
            if idx == -1:
                return None, deletion
            payload = data[idx + len(b"application/sdp\x00"):]

    return payload.decode("utf-8", errors="ignore"), deletion
