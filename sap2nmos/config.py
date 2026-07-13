import json
import os
import sys
import uuid

DEFAULTS = {
    "registrar": "",
    "auto_registrar": True,
    "dns_sd_domain": "",
    "dns_sd_nameserver": "",
    "interface_ip": "",
    "http_port": 8085,
    "sap_group": "239.255.255.255",
    "sap_port": 9875,
    "stream_timeout": 120,
    "node_id": "",
    "device_id": "",
    "manual_sdps": [],
}


def config_dir():
    if sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    elif sys.platform == "win32":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
    else:
        base = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    return os.path.join(base, "SAP-2-NMOS")


def config_path():
    return os.path.join(config_dir(), "config.json")


class Config:
    def __init__(self, data):
        self.data = dict(DEFAULTS)
        self.data.update(data or {})
        # Node/device IDs must survive restarts, otherwise every launch
        # leaves orphaned resources in the registry.
        changed = False
        if not self.data["node_id"]:
            self.data["node_id"] = str(uuid.uuid4())
            changed = True
        if not self.data["device_id"]:
            self.data["device_id"] = str(uuid.uuid4())
            changed = True
        if changed:
            self.save()

    @classmethod
    def load(cls):
        try:
            with open(config_path(), "r", encoding="utf-8") as f:
                return cls(json.load(f))
        except (OSError, ValueError):
            return cls({})

    def save(self):
        os.makedirs(config_dir(), exist_ok=True)
        tmp = config_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        os.replace(tmp, config_path())

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value

    def public(self):
        return {k: v for k, v in self.data.items() if k != "manual_sdps"}
