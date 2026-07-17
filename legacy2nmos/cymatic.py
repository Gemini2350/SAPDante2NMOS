"""Cymatic / Archwave AES67 device side.

Archwave AES67 devices (e.g. uNet2500, used by Cymatic) expose a simple
HTTP + JSON configuration protocol (Archwave "AES67 Configuration Protocol",
2017). Endpoints under the device URL:

  GET  /status          sources[] (TX) + outputs[] (RX) with status + SDP, PTP
  GET  /stream_list     AES67 streams on the network (name, channelCount)
  GET  /device_list     AES67 devices on the network
  GET  /general         global config (name, IP, PTP{ipTTL}, SAP{...})
  GET  /sources         TX streams (name, streamEnable, multicastAddress, RTPTTL)
  GET  /outputs         RX channels (name, streamPath | manualSDP + channel)
  POST /general /sources /outputs /command   write config / reboot

Mapping to NMOS:
  Cymatic "source"  (TX) -> NMOS sender   (has multicastAddress + SDP)
  Cymatic "output"  (RX) -> NMOS receiver (set manualSDP on IS-05 activate)

Multicast TTL lives in two places and both default to 1 — we force 64:
  /general -> config.PTP.ipTTL         (device global)
  /sources -> each source.RTPTTL       (per TX stream)
"""

import threading

import requests

WANT_TTL = 64
STREAM_STATUS = {0: "idle", 1: "starting", 2: "transmitting", 3: "collision",
                 4: "waiting", 5: "receiving", 6: "error", 7: "no decoders"}


class CymaticManager:
    def __init__(self, config, log):
        self.config = config
        self.log = log
        self.lock = threading.RLock()

    # ------------------------------------------------------------- devices

    def devices(self):
        with self.lock:
            return list(self.config["cymatic_devices"])

    def _url(self, host):
        return host if host.startswith("http") else f"http://{host}"

    def add_device(self, host, label=""):
        host = (host or "").strip()
        if not host:
            return False, "enter a host/IP (optionally with :port)"
        entry = {"host": host, "label": label.strip() or host}
        info = self._probe(host)
        with self.lock:
            if not any(d["host"] == host for d in self.config["cymatic_devices"]):
                self.config["cymatic_devices"].append(entry)
                self.config.save()
        self.log(f"Cymatic device added: {host}"
                 + ("" if info else " (no HTTP response yet)"))
        return True, info or ("added, but no HTTP response — check the address")

    def remove_device(self, host):
        with self.lock:
            before = len(self.config["cymatic_devices"])
            self.config["cymatic_devices"] = [
                d for d in self.config["cymatic_devices"] if d["host"] != host]
            if len(self.config["cymatic_devices"]) != before:
                self.config.save()
                self.log(f"Cymatic device removed: {host}")
                return True
        return False

    def _get(self, host, path):
        r = requests.get(f"{self._url(host)}{path}", timeout=3)
        r.raise_for_status()
        return r.json()

    def _post(self, host, path, obj):
        r = requests.post(f"{self._url(host)}{path}", json=obj, timeout=4)
        r.raise_for_status()
        return r

    def _probe(self, host):
        try:
            st = self._get(host, "/status").get("ArchwaveAES67", {})
            return (f"connected — {st.get('manufacturer', '?')} "
                    f"{st.get('model', '')}").strip()
        except (requests.RequestException, ValueError):
            return ""

    # ------------------------------------------------------------- read

    def snapshot(self, host):
        """Combined view of one device for the UI."""
        out = {"host": host, "reachable": False, "model": "", "sources": [],
               "outputs": [], "ttl_ok": None}
        try:
            status = self._get(host, "/status").get("ArchwaveAES67", {})
            sources_cfg = self._get(host, "/sources").get("ArchwaveAES67", {}).get("sources", [])
            outputs_cfg = self._get(host, "/outputs").get("ArchwaveAES67", {}).get("outputs", [])
            general = self._get(host, "/general").get("ArchwaveAES67", {}).get("config", {})
        except (requests.RequestException, ValueError) as e:
            out["error"] = str(e)
            return out
        out["reachable"] = True
        out["model"] = f"{status.get('manufacturer', '')} {status.get('model', '')}".strip()
        st_sources = status.get("sources", [])
        st_outputs = status.get("outputs", [])
        for i, s in enumerate(sources_cfg):
            stat = st_sources[i]["status"] if i < len(st_sources) else None
            out["sources"].append({
                "index": i, "name": s.get("name", f"Source {i}"),
                "multicast": s.get("multicastAddress", ""),
                "enabled": bool(s.get("streamEnable")),
                "ttl": s.get("RTPTTL"), "status": STREAM_STATUS.get(stat, stat),
                "sdp": st_sources[i].get("SDP", "") if i < len(st_sources) else ""})
        for i, o in enumerate(outputs_cfg):
            stat = st_outputs[i]["status"] if i < len(st_outputs) else None
            out["outputs"].append({
                "index": i, "name": o.get("name", f"Output {i}"),
                "stream_path": o.get("streamPath", ""),
                "manual_sdp": o.get("manualSDP", ""),
                "status": STREAM_STATUS.get(stat, stat)})
        ip_ttl = (general.get("PTP") or {}).get("ipTTL")
        src_ttls = [s.get("RTPTTL") for s in sources_cfg]
        out["ttl_ok"] = (ip_ttl == WANT_TTL and all(t == WANT_TTL for t in src_ttls))
        return out

    # ------------------------------------------------------------- write

    def set_output_sdp(self, host, index, sdp, channel=0):
        """Connect an RX output to a source by SDP (IS-05 activate)."""
        cfg = self._get(host, "/outputs").get("ArchwaveAES67", {})
        outputs = cfg.get("outputs", [])
        if index >= len(outputs):
            raise IndexError("output index out of range")
        outputs[index]["manualSDP"] = sdp
        outputs[index]["streamPath"] = ""   # manualSDP + streamPath are exclusive
        outputs[index]["manualSDPChannel"] = int(channel)
        self._post(host, "/outputs", {"ArchwaveAES67": {"version": 1,
                                                        "outputs": outputs}})
        self.log(f"Cymatic {host} output {index}: manualSDP set")

    def set_ttl(self, host, ttl=WANT_TTL):
        """Force ipTTL (global) and RTPTTL (per source) to `ttl`."""
        changed = []
        general = self._get(host, "/general").get("ArchwaveAES67", {})
        cfg = general.get("config", {})
        if (cfg.get("PTP") or {}).get("ipTTL") != ttl:
            cfg.setdefault("PTP", {})["ipTTL"] = ttl
            self._post(host, "/general", {"ArchwaveAES67": {"version": 1,
                                                           "config": cfg}})
            changed.append("ipTTL")
        srccfg = self._get(host, "/sources").get("ArchwaveAES67", {})
        sources = srccfg.get("sources", [])
        if any(s.get("RTPTTL") != ttl for s in sources):
            for s in sources:
                s["RTPTTL"] = ttl
            self._post(host, "/sources", {"ArchwaveAES67": {"version": 1,
                                                          "sources": sources}})
            changed.append(f"RTPTTL x{len(sources)}")
        if changed:
            self.log(f"Cymatic {host}: TTL -> {ttl} ({', '.join(changed)})")
        return changed

    # ------------------------------------------------------------- UI data

    def as_api(self):
        return {"devices": self.devices()}
