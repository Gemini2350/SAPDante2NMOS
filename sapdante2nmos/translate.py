"""Uebersetzung: NMOS-Verbindung (SDP) -> Dante-Steuerkommandos.

Modell: 1 NMOS-Receiver = N Dante-RX-Kanaele (Default 2).
  1x 0x3410 (Bind auf Basis-Kanal) + je Quellkanal 1x 0x3201.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from . import dante
from .dante_sdp import SdpParams


@dataclass
class ReceiverMap:
    label: str
    dante_device_ip: str
    dante_base_channel: int
    channels: int = 2
    nmos_id: str = field(default_factory=lambda: str(uuid.uuid4()))


def translate(rx: ReceiverMap, sdp: SdpParams, apply: bool = False):
    """Baut (und sendet optional) die Dante-Kommandos fuer eine Verbindung."""
    packets = [("bind -> dante-ch %d" % rx.dante_base_channel,
                dante.build_bind(rx.dante_base_channel, 0x20))]
    txid = 0x20
    for i in range(min(rx.channels, sdp.channels)):
        stream_ch = i + 1
        txid += 5
        packets.append((
            "map stream-ch %d -> dante-ch %d" % (stream_ch, rx.dante_base_channel + i),
            dante.build_map_channel(sdp.source_ip, sdp.multicast_ip, sdp.port,
                                    stream_ch, txid)))
    out = []
    for label, pkt in packets:
        e = {"step": label, "hex": pkt.hex()}
        if apply:
            resp = dante.send(rx.dante_device_ip, pkt)
            e["response"] = resp.hex() if resp else None
            e["ack"] = bool(resp and resp[6:8].hex() in ("3201", "3410", "2801"))
        out.append(e)
    return out


def params_to_sdp(transport_params) -> SdpParams:
    """Fallback, wenn IS-05 nur transport_params (kein SDP) liefert."""
    tp = transport_params or [{}]
    leg0 = tp[0] if tp else {}
    return SdpParams(
        multicast_ip=leg0.get("multicast_ip", ""),
        source_ip=leg0.get("source_ip", ""),
        port=int(leg0.get("destination_port", 5004)),
        channels=len(tp),
    )
