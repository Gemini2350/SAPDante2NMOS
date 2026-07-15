"""Discovery AES67-faehiger Dante-Geraete (Lese-Pfad).

Nutzt netaudio (falls installiert), das den reverse-engineerten Lese-Pfad
'get_aes67_configured' bereitstellt. Ohne netaudio wird eine leere Liste geliefert
und man arbeitet rein config-basiert.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DanteDevice:
    name: str
    ip: str
    aes67_enabled: bool
    rx_channels: int = 0
    tx_channels: int = 0


def discover_aes67_devices():
    """Gibt alle im Netz gefundenen Dante-Geraete mit AES67-Status zurueck."""
    try:
        import asyncio
        from netaudio.dante.browser import DanteBrowser
    except Exception:
        print("[dante] netaudio nicht installiert -- config-basiert arbeiten.")
        return []

    async def _run():
        browser = DanteBrowser(mdns_timeout=2.0)
        devices = await browser.get_devices()
        out = []
        for _, dev in devices.items():
            try:
                await dev.get_controls()
            except Exception:
                pass
            aes = bool(getattr(dev, "aes67_configured", False))
            out.append(DanteDevice(
                name=getattr(dev, "name", "?"),
                ip=getattr(dev, "ipv4", "?"),
                aes67_enabled=aes,
                rx_channels=len(getattr(dev, "rx_channels", {}) or {}),
                tx_channels=len(getattr(dev, "tx_channels", {}) or {}),
            ))
        return out

    return asyncio.run(_run())
