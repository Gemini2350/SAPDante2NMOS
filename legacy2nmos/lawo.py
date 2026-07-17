"""Lawo device side: manage devices controlled over Ember+.

Mirrors the Dante UX — add devices by IP, browse them, and (later) expose their
AES67 streams as NMOS senders/receivers. Ember+ trees are device-model specific,
so the Lawo tab ships a tree browser to locate the stream/routing parameters on
a real device before we map them to NMOS.
"""

import threading

from . import ember


class LawoManager:
    def __init__(self, config, log):
        self.config = config
        self.log = log
        self.lock = threading.RLock()

    # ------------------------------------------------------------- devices

    def devices(self):
        with self.lock:
            return list(self.config["lawo_devices"])

    def add_device(self, host, port=9000, label=""):
        host = host.strip()
        if not host:
            return False, "enter a host/IP"
        entry = {"host": host, "port": int(port or 9000),
                 "label": label.strip() or host}
        ok, info = self._probe(entry)
        with self.lock:
            if not any(d["host"] == host and d["port"] == entry["port"]
                       for d in self.config["lawo_devices"]):
                self.config["lawo_devices"].append(entry)
                self.config.save()
        self.log(f"Lawo device added: {host}:{entry['port']}"
                 + ("" if ok else " (no Ember+ response yet)"))
        return True, (info if ok else "added, but no Ember+ response on "
                      f"{host}:{entry['port']} — check routing/port")

    def remove_device(self, host, port):
        with self.lock:
            before = len(self.config["lawo_devices"])
            self.config["lawo_devices"] = [
                d for d in self.config["lawo_devices"]
                if not (d["host"] == host and int(d["port"]) == int(port))]
            if len(self.config["lawo_devices"]) != before:
                self.config.save()
                self.log(f"Lawo device removed: {host}:{port}")
                return True
        return False

    def _probe(self, entry):
        try:
            with ember.EmberClient(entry["host"], entry["port"], timeout=2.5) as c:
                els = c.get_directory(None)
            names = ", ".join(e.identifier or f"#{e.number}" for e in els[:4])
            return True, f"connected — root: {names or 'empty'}"
        except (OSError, ember.EmberError):
            return False, ""

    # ------------------------------------------------------------- browse

    def browse(self, host, port, path=None):
        """Return the child elements at `path` (None = root) of a device."""
        with ember.EmberClient(host, int(port), timeout=3.0) as c:
            els = c.get_directory(path or None)
        return [e.as_dict() for e in els]

    def set_value(self, host, port, path, value, value_type="int"):
        tag = {"int": ember.U_INT, "string": ember.U_UTF8,
               "bool": ember.U_BOOL}.get(value_type, ember.U_INT)
        if tag == ember.U_INT:
            value = int(value)
        elif tag == ember.U_BOOL:
            value = bool(value)
        with ember.EmberClient(host, int(port), timeout=3.0) as c:
            c.set_parameter(path, value, tag)
        self.log(f"Lawo set {host}:{port} {path} = {value!r}")

    # ------------------------------------------------------------- A__line ops
    # Documented Ember+ API (A__line User Guide v1.8, ch. 9). Functions live
    # under /ravenna/routing/functions; paths are resolved by identifier so we
    # don't depend on numeric OIDs (which vary per device).

    _FUNC_BASE = ("ravenna", "routing", "functions")

    def _resolve(self, client, names):
        """Resolve a path of identifiers to a dotted numeric Ember+ path."""
        path = None
        for name in names:
            children = client.get_directory(path)
            match = next((e for e in children if e.identifier == name), None)
            if match is None:
                raise ember.EmberError(f"Ember+ node '{name}' not found under "
                                       f"{path or 'root'}")
            path = match.path
        return path

    def _invoke_func(self, host, port, func_name, args):
        with ember.EmberClient(host, int(port), timeout=4.0) as c:
            fpath = self._resolve(c, self._FUNC_BASE + (func_name,))
            success, result = c.invoke(fpath, args)
        return success, result

    S = ember.U_UTF8
    I = ember.U_INT
    B = ember.U_BOOL

    def create_input_stream(self, host, port, interface, stream_id,
                            delay=32, syntonized=False):
        return self._invoke_func(host, port, "createInputStream",
                                 [(interface, self.S), (stream_id, self.S),
                                  (delay, self.I), (syntonized, self.B)])

    def set_input_sdp(self, host, port, interface, stream_id, sdp):
        """Subscribe an existing Rx stream to a source by SDP (IS-05 activate)."""
        with ember.EmberClient(host, int(port), timeout=4.0) as c:
            path = self._resolve(c, ("ravenna", "routing", "inputs", interface,
                                     "streams", stream_id, "sourceSDP"))
            c.set_parameter(path, sdp, ember.U_UTF8)

    def create_output_stream(self, host, port, interface, stream_id, channels):
        return self._invoke_func(host, port, "createOutputStream",
                                 [(interface, self.S), (stream_id, self.S),
                                  (int(channels), self.I)])

    def create_output_sender(self, host, port, interface, stream_id, sender_id,
                             multicast, rtp_port=5004, codec=1, frame_size=48,
                             ttl=64):
        # codec: 0=L16, 1=L24, 2=L32, 3=AM824
        return self._invoke_func(host, port, "createOutputStreamSender",
                                 [(interface, self.S), (stream_id, self.S),
                                  (sender_id, self.S), (multicast, self.S),
                                  (int(rtp_port), self.I), (True, self.B),
                                  ("", self.S), (0, self.I), (False, self.B),
                                  (0, self.I), (int(codec), self.I),
                                  (int(frame_size), self.I), (int(ttl), self.I)])

    def connect_channel(self, host, port, output_path, input_path):
        return self._invoke_func(host, port, "connectChannel",
                                 [(output_path, self.S), (input_path, self.S)])

    # ------------------------------------------------------------- UI data

    def as_api(self):
        return {"devices": self.devices()}
