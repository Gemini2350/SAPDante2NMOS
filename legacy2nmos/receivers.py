"""Dante receiver side: config-backed receiver maps, IS-05 state, activation.

One NMOS receiver = N Dante RX channels (default 2). On IS-05 activation the
SDP (or transport_params) is translated into Dante control commands and sent
to the device (the gateway always operates live).
"""

import threading
import time
from dataclasses import asdict

from .dante_sdp import parse_aes67_sdp
from .translate import ReceiverMap, translate, params_to_sdp


def empty_staged():
    return {
        "receiver_id": None,
        "sender_id": None,
        "master_enable": False,
        "activation": {"mode": None, "requested_time": None, "activation_time": None},
        "transport_file": {"data": None, "type": None},
        "transport_params": [{}],
    }


def _fresh_state():
    return {
        "staged": empty_staged(),
        "active": empty_staged(),
        "summary": {"active": False, "source": "", "sender_id": None},
        "last_result": [],       # translate() steps of the last activation
        "last_ack": None,        # True/False: did the device ACK the commands
        "last_activation": 0,
        "stream_health": "none",  # 'connected' | 'no_audio' | 'none'
    }


class ReceiverManager:
    """Holds the configured Dante receivers and their IS-05 state."""

    def __init__(self, config, log):
        self.config = config
        self.log = log
        self.lock = threading.RLock()
        self.receivers = {}   # nmos_id -> ReceiverMap
        self.state = {}       # nmos_id -> state dict
        self.devices = []     # discovered Dante devices (dataclasses)
        self.devices_updated = 0.0
        self._netaudio_missing_logged = False
        self._status_listeners = []  # fns(nmos_id) — engine + IS-12 monitors
        for r in config["receivers"]:
            rx = ReceiverMap(**r)
            self.receivers[rx.nmos_id] = rx
            self.state[rx.nmos_id] = _fresh_state()

    # ------------------------------------------------------------- config

    def add(self, label, dante_device_ip, dante_base_channel, channels=2):
        rx = ReceiverMap(label=label, dante_device_ip=dante_device_ip,
                         dante_base_channel=int(dante_base_channel),
                         channels=int(channels))
        with self.lock:
            self.receivers[rx.nmos_id] = rx
            self.state[rx.nmos_id] = _fresh_state()
            self.config["receivers"].append(asdict(rx))
            self.config.save()
        self.log(f"Receiver added: {rx.label} -> {rx.dante_device_ip} "
                 f"ch{rx.dante_base_channel}+{rx.channels}")
        return rx

    def remove(self, nmos_id):
        with self.lock:
            rx = self.receivers.pop(nmos_id, None)
            self.state.pop(nmos_id, None)
            if rx:
                self.config["receivers"] = [
                    r for r in self.config["receivers"]
                    if r.get("nmos_id") != nmos_id]
                self.config.save()
        if rx:
            self.log(f"Receiver removed: {rx.label}")
        return rx

    # ------------------------------------------------------------- IS-05

    def get(self, nmos_id):
        return self.receivers.get(nmos_id)

    def add_status_listener(self, fn):
        self._status_listeners.append(fn)

    def _notify_status(self, nmos_id):
        for fn in self._status_listeners:
            try:
                fn(nmos_id)
            except Exception as e:  # noqa: BLE001
                self.log(f"status listener error: {e}")

    def subscription(self, nmos_id):
        """Current IS-04 subscription {sender_id, active} for a receiver."""
        with self.lock:
            s = self.state[nmos_id]["summary"]
            return {"sender_id": s.get("sender_id") if s["active"] else None,
                    "active": bool(s["active"])}

    def staged(self, nmos_id):
        with self.lock:
            return self.state[nmos_id]["staged"]

    def active(self, nmos_id):
        with self.lock:
            return self.state[nmos_id]["active"]

    def patch_staged(self, nmos_id, body):
        """Apply an IS-05 PATCH; activate immediately if requested.

        Returns the staged state. Activation runs the SDP -> Dante translation
        and sends the commands to the device (always live).
        """
        rx = self.receivers[nmos_id]
        with self.lock:
            st = self.state[nmos_id]["staged"]
            if body.get("transport_file"):
                st["transport_file"] = body["transport_file"]
            if "transport_params" in body:
                st["transport_params"] = body["transport_params"]
            if "sender_id" in body:
                st["sender_id"] = body["sender_id"]
            if body.get("master_enable") is not None:
                st["master_enable"] = body["master_enable"]
            st["activation"] = body.get("activation") or {}

        act = st["activation"]
        if act.get("mode") == "activate_immediate" and st.get("master_enable", True):
            self._activate(rx, st)
        elif body.get("master_enable") is False and act.get("mode") == "activate_immediate":
            self._deactivate(rx)
            with self.lock:
                self.state[nmos_id]["summary"] = {"active": False, "source": "",
                                                  "sender_id": None}
                self.state[nmos_id]["stream_health"] = "none"
                self.state[nmos_id]["active"] = dict(st, master_enable=False)
                st["activation"] = {"mode": None, "requested_time": None,
                                    "activation_time": _now_ts()}
            self._notify_status(nmos_id)
        return st

    def _deactivate(self, rx):
        """IS-05 disconnect: clear the Dante RX-channel subscriptions on the
        device so it actually stops receiving — not just flip the NMOS state."""
        from . import dante
        n = rx.channels
        steps = []
        for i in range(n):
            dante_ch = rx.dante_base_channel + i
            resp = dante.clear_subscription(rx.dante_device_ip, dante_ch)
            ok = bool(resp and resp[6:8].hex() in ("3201", "3410", "2801"))
            steps.append({"step": f"clear dante-ch {dante_ch}",
                          "hex": "", "ack": ok,
                          "response": resp.hex() if resp else None})
            self.log(f"IS-05 deactivate {rx.label}: clear dante-ch {dante_ch} "
                     f"{'ACK' if ok else 'no ACK'}")
        with self.lock:
            self.state[rx.nmos_id]["last_result"] = steps
            self.state[rx.nmos_id]["last_ack"] = (
                all(s["ack"] for s in steps) if steps else None)

    def _activate(self, rx, st):
        sdp_text = (st.get("transport_file") or {}).get("data") or ""
        sdp = parse_aes67_sdp(sdp_text) if sdp_text \
            else params_to_sdp(st.get("transport_params"))
        self.log(f"IS-05 activate {rx.label}: {sdp.source_ip} -> "
                 f"{sdp.multicast_ip}:{sdp.port} ({sdp.channels}ch)")
        # The Dante device only receives an AES67 multicast whose prefix matches
        # its configured AES67 range — so align the prefix BEFORE the mapping.
        self._sync_prefix(rx, sdp.multicast_ip)
        steps = translate(rx, sdp, send=True)
        acks = [s.get("ack") for s in steps if "ack" in s]
        with self.lock:
            state = self.state[rx.nmos_id]
            state["last_result"] = steps
            state["last_ack"] = all(acks) if acks else None
            state["last_activation"] = time.time()
            state["active"] = dict(st, master_enable=True)
            state["summary"] = {
                "active": True,
                "sender_id": st.get("sender_id"),
                "mcast": sdp.multicast_ip,
                "source": f"{sdp.source_ip} -> {sdp.multicast_ip}:{sdp.port} "
                          f"({sdp.channels}ch)",
            }
            st["activation"] = {"mode": None, "requested_time": None,
                                "activation_time": _now_ts()}
        for s in steps:
            self.log(f"  -> {s['step']}"
                     + ("" if "ack" not in s else f" ack={s['ack']}"))
        self._notify_status(rx.nmos_id)

    def _sync_prefix(self, rx, multicast_ip):
        """Align the device's AES67 prefix to the patched multicast's second
        octet (239.<prefix>.x.x). Always runs — the device won't receive the
        stream otherwise."""
        try:
            prefix = int(multicast_ip.split(".")[1])
        except (IndexError, ValueError):
            return
        from . import dante
        try:
            current = dante.read_aes67_prefix(rx.dante_device_ip, timeout=1.0)
            if current == prefix:
                return
            ok = dante.set_aes67_prefix(rx.dante_device_ip, prefix)
        except OSError as e:
            self.log(f"Prefix set for {rx.dante_device_ip} failed: {e}")
            return
        self.log(f"Prefix: {rx.dante_device_ip} -> 239.{prefix}.x.x "
                 f"(matches {multicast_ip}) {'ACK' if ok else 'no ACK'}")

    # ------------------------------------------------------------- devices

    def refresh_devices(self):
        try:
            from .dante_devices import discover_aes67_devices, query_manual_device
            devices = discover_aes67_devices()
        except Exception as e:
            self.log(f"Dante device scan failed: {e}")
            return
        # Add manually configured devices (cross-subnet) not found via mDNS.
        found = {d.ip for d in devices}
        for ip in self.config["manual_devices"]:
            if ip not in found:
                try:
                    devices.append(query_manual_device(ip))
                except Exception as e:  # noqa: BLE001
                    self.log(f"Manual device {ip} query failed: {e}")
        with self.lock:
            self.devices = devices
            self.devices_updated = time.time()
        self._update_stream_health()

    def add_manual_device(self, ip):
        from .dante_devices import query_manual_device
        dev = query_manual_device(ip)
        with self.lock:
            if ip not in self.config["manual_devices"]:
                self.config["manual_devices"].append(ip)
                self.config.save()
            # show it immediately (unless already discovered via mDNS)
            if not any(d.ip == ip for d in self.devices):
                self.devices.append(dev)
        self.log(f"Manual device added: {ip}"
                 + ("" if dev.reachable else " (no response yet)"))
        return dev

    def remove_manual_device(self, ip):
        with self.lock:
            if ip in self.config["manual_devices"]:
                self.config["manual_devices"].remove(ip)
                self.config.save()
                self.devices = [d for d in self.devices if not (d.manual and d.ip == ip)]
                self.log(f"Manual device removed: {ip}")
                return True
        return False

    def _update_stream_health(self):
        """Recompute each active receiver's RTP flow health from the scan and
        push a status update when it changed (feeds the BCP-008 monitors)."""
        from .dante_devices import stream_health
        by_ip = {}
        with self.lock:
            for d in self.devices:
                by_ip[d.ip] = d
            changed = []
            for rid, rx in self.receivers.items():
                state = self.state[rid]
                if not state["summary"]["active"]:
                    continue
                dev = by_ip.get(rx.dante_device_ip)
                if dev is None:
                    health = "unknown"
                else:
                    codes = [dev.rx_status.get(rx.dante_base_channel + i)
                             for i in range(rx.channels)]
                    healths = {stream_health(c) for c in codes}
                    if "no_audio" in healths:
                        health = "no_audio"
                    elif healths == {"connected"}:
                        health = "connected"
                    elif "connected" in healths:
                        health = "no_audio"  # some channels missing audio
                    else:
                        health = "none"
                if health != state["stream_health"]:
                    state["stream_health"] = health
                    changed.append(rid)
        for rid in changed:
            self.log(f"RTP flow health for {self.receivers[rid].label}: "
                     f"{self.state[rid]['stream_health']}")
            self._notify_status(rid)

    def stream_health(self, nmos_id):
        with self.lock:
            return self.state[nmos_id]["stream_health"]

    def scan_available(self):
        try:
            import netaudio  # noqa: F401
            return True
        except ImportError:
            if not self._netaudio_missing_logged:
                self._netaudio_missing_logged = True
                self.log("netaudio not installed - Dante device scan disabled "
                         "(pip install netaudio)")
            return False

    # ------------------------------------------------------------- UI data

    def as_api(self):
        with self.lock:
            receivers = []
            for rid, rx in self.receivers.items():
                s = self.state[rid]
                receivers.append({
                    "nmos_id": rid,
                    "label": rx.label,
                    "dante_device_ip": rx.dante_device_ip,
                    "dante_base_channel": rx.dante_base_channel,
                    "channels": rx.channels,
                    "active": s["summary"]["active"],
                    "source": s["summary"]["source"],
                    "sender_id": s["summary"].get("sender_id"),
                    "stream_health": s["stream_health"],
                    "last_ack": s["last_ack"],
                    "last_activation": s["last_activation"],
                    "last_result": s["last_result"],
                })
            devices = [asdict(d) for d in self.devices]
            return {
                "receivers": receivers,
                "devices": devices,
                "devices_updated": self.devices_updated,
            }


def _now_ts():
    ns = time.time_ns()
    return f"{ns // 1_000_000_000}:{ns % 1_000_000_000}"
