"""Minimaler AES67 / ST 2110-30 SDP-Parser (RFC 4566) fuer die Uebersetzung."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class SdpParams:
    multicast_ip: str = ""
    source_ip: str = ""
    port: int = 5004
    channels: int = 2
    payload_type: int = 96
    sample_rate: int = 48000
    ptime: float = 1.0


def parse_aes67_sdp(sdp: str) -> SdpParams:
    p = SdpParams()
    for raw in sdp.splitlines():
        line = raw.strip()
        if line.startswith("m=audio"):
            m = re.match(r"m=audio\s+(\d+)\s+RTP/AVP\s+(\d+)", line)
            if m:
                p.port = int(m.group(1))
                p.payload_type = int(m.group(2))
        elif line.startswith("c=IN IP4"):
            p.multicast_ip = line.split()[2].split("/")[0]
        elif line.startswith("a=source-filter:"):
            parts = line.split()
            if len(parts) >= 6:
                p.source_ip = parts[-1]
        elif line.startswith("o="):
            parts = line.split()
            if len(parts) >= 6 and not p.source_ip:
                p.source_ip = parts[5]
        elif line.startswith("a=rtpmap:"):
            m = re.search(r"L(?:16|24)/(\d+)(?:/(\d+))?", line)
            if m:
                p.sample_rate = int(m.group(1))
                if m.group(2):
                    p.channels = int(m.group(2))
        elif line.startswith("a=ptime:"):
            try:
                p.ptime = float(line.split(":", 1)[1])
            except ValueError:
                pass
    return p
