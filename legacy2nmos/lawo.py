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

    # ------------------------------------------------------------- UI data

    def as_api(self):
        return {"devices": self.devices()}
