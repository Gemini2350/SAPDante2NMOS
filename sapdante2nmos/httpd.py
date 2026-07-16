import json
import mimetypes
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .engine import list_interfaces


def ui_dir():
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return os.path.join(base, "sapdante2nmos", "ui")
    return os.path.join(os.path.dirname(__file__), "ui")


def make_server(engine, config):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass

        # ---- helpers ----

        def send_json(self, data, status=200):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def send_text(self, text, content_type="text/plain", status=200):
            body = text.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def read_body(self):
            length = int(self.headers.get("Content-Length", 0))
            return self.rfile.read(length) if length else b""

        def send_file(self, relpath):
            path = os.path.normpath(os.path.join(ui_dir(), relpath))
            if not path.startswith(ui_dir()) or not os.path.isfile(path):
                return self.send_json({"error": "not found"}, 404)
            ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
            with open(path, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # ---- routing ----

        def do_GET(self):
            path = self.path.split("?")[0].rstrip("/")

            if path in ("", "/ui", "/ui/index.html"):
                return self.send_file("index.html")
            if path.startswith("/ui/"):
                return self.send_file(path[len("/ui/"):])

            if path == "/api/state":
                return self.send_json(engine.state())
            if path == "/api/interfaces":
                return self.send_json(list_interfaces())
            if path == "/api/config":
                return self.send_json(config.public())
            if path == "/api/discover":
                qs = parse_qs(urlparse(self.path).query)
                domain = qs.get("domain", [config["dns_sd_domain"]])[0]
                try:
                    from .discovery import discover_registries, system_search_domains
                    candidates = discover_registries(domain, config["dns_sd_nameserver"])
                    domains = [domain] if domain else system_search_domains()
                except ImportError:
                    return self.send_json({"error": "dnspython not installed"}, 501)
                except Exception as e:
                    return self.send_json({"error": str(e)}, 502)
                return self.send_json({"domains": domains, "candidates": candidates})
            if path.startswith("/api/sdp/"):
                sdp = engine.get_sdp(path[len("/api/sdp/"):])
                if sdp is None:
                    return self.send_json({"error": "not found"}, 404)
                return self.send_text(sdp, "application/sdp")

            return self.nmos_get(path)

        def do_POST(self):
            path = self.path.split("?")[0].rstrip("/")
            try:
                if path == "/api/sdp":
                    body = json.loads(self.read_body() or b"{}")
                    h = engine.add_manual_sdp(body.get("sdp", ""))
                    return self.send_json({"ok": True, "hash": h})
                if path == "/api/config":
                    body = json.loads(self.read_body() or b"{}")
                    allowed = ("registrar", "auto_registrar", "dns_sd_domain",
                               "dns_sd_nameserver", "interface_ip", "sap_group",
                               "sap_port", "stream_timeout", "http_port",
                               "apply_mode", "device_scan_interval",
                               "registry_recheck_interval")
                    for key in allowed:
                        if key in body:
                            config[key] = body[key]
                    config.save()
                    engine.restart()
                    return self.send_json({"ok": True})
                if path == "/api/start":
                    engine.start()
                    return self.send_json({"ok": True})
                if path == "/api/stop":
                    engine.stop()
                    return self.send_json({"ok": True})
                if path == "/api/receivers":
                    body = json.loads(self.read_body() or b"{}")
                    label = (body.get("label") or "").strip()
                    ip = (body.get("dante_device_ip") or "").strip()
                    base_ch = int(body.get("dante_base_channel") or 0)
                    channels = int(body.get("channels") or 2)
                    if not label or not ip or base_ch < 1:
                        raise ValueError("label, dante_device_ip and "
                                         "dante_base_channel (>=1) are required")
                    rx = engine.add_receiver(label, ip, base_ch, channels)
                    return self.send_json({"ok": True, "nmos_id": rx.nmos_id})
                if path == "/api/devices/refresh":
                    import threading
                    threading.Thread(target=engine.receivers.refresh_devices,
                                     daemon=True).start()
                    return self.send_json({"ok": True})
                if path == "/api/devices/prefix":
                    body = json.loads(self.read_body() or b"{}")
                    ip = (body.get("ip") or "").strip()
                    prefix = int(body.get("prefix"))
                    ok, msg = engine.set_device_prefix(ip, prefix)
                    return self.send_json({"ok": ok, "message": msg},
                                          200 if ok else 400)
                if path == "/api/devices/auto_prefix":
                    body = json.loads(self.read_body() or b"{}")
                    engine.receivers.set_auto_prefix((body.get("ip") or "").strip(),
                                                     bool(body.get("enabled")))
                    return self.send_json({"ok": True})
            except ValueError as e:
                return self.send_json({"error": str(e)}, 400)
            return self.send_json({"error": "not found"}, 404)

        def do_DELETE(self):
            path = self.path.split("?")[0].rstrip("/")
            if path.startswith("/api/stream/"):
                ok = engine.remove_stream(path[len("/api/stream/"):])
                return self.send_json({"ok": ok}, 200 if ok else 404)
            if path.startswith("/api/receiver/"):
                ok = engine.remove_receiver(path[len("/api/receiver/"):])
                return self.send_json({"ok": ok}, 200 if ok else 404)
            return self.send_json({"error": "not found"}, 404)

        def do_PATCH(self):
            path = self.path.split("?")[0].rstrip("/")
            rx_prefix = "/x-nmos/connection/v1.1/single/receivers/"
            if path.startswith(rx_prefix) and path.endswith("/staged"):
                rid = path[len(rx_prefix):-len("/staged")]
                if rid not in engine.receivers.receivers:
                    return self.send_json({"error": "unknown receiver"}, 404)
                try:
                    body = json.loads(self.read_body() or b"{}")
                    staged = engine.receivers.patch_staged(rid, body)
                except ValueError as e:
                    return self.send_json({"error": str(e)}, 400)
                except Exception as e:
                    return self.send_json({"error": str(e)}, 500)
                return self.send_json(staged)
            return self.send_json({"error": "not found"}, 404)

        # ---- NMOS node + connection API ----

        def nmos_get(self, path):
            res = engine.node_resources()

            if path == "/x-nmos/node/v1.3":
                return self.send_json(["self/", "devices/", "sources/", "flows/",
                                       "senders/", "receivers/"])
            if path == "/x-nmos/node/v1.3/self":
                return self.send_json(res["node"])
            if path == "/x-nmos/node/v1.3/devices":
                return self.send_json(res["devices"])
            if path == "/x-nmos/node/v1.3/sources":
                return self.send_json(res["sources"])
            if path == "/x-nmos/node/v1.3/flows":
                return self.send_json(res["flows"])
            if path == "/x-nmos/node/v1.3/senders":
                return self.send_json(res["senders"])
            if path == "/x-nmos/node/v1.3/receivers":
                return self.send_json(res["receivers"])

            if path == "/x-nmos/connection/v1.1/single":
                return self.send_json(["senders/", "receivers/"])
            if path == "/x-nmos/connection/v1.1/single/senders":
                return self.send_json([f"{s['id']}/" for s in res["senders"]])
            if path == "/x-nmos/connection/v1.1/single/receivers":
                return self.send_json([f"{rid}/" for rid in engine.receivers.receivers])

            rx_prefix = "/x-nmos/connection/v1.1/single/receivers/"
            if path.startswith(rx_prefix):
                parts = path[len(rx_prefix):].split("/")
                rid = parts[0]
                sub = parts[1] if len(parts) > 1 else ""
                if rid not in engine.receivers.receivers:
                    return self.send_json({"error": "unknown receiver"}, 404)
                if sub == "constraints":
                    return self.send_json([{}])
                if sub == "staged":
                    return self.send_json(engine.receivers.staged(rid))
                if sub == "active":
                    return self.send_json(engine.receivers.active(rid))
                if sub == "transporttype":
                    return self.send_json("urn:x-nmos:transport:rtp.mcast")
                if sub == "":
                    return self.send_json(["constraints/", "staged/", "active/",
                                           "transporttype/"])

            prefix = "/x-nmos/connection/v1.1/single/senders/"
            if path.startswith(prefix):
                rest = path[len(prefix):]
                parts = rest.split("/")
                sender_id = parts[0]
                sub = parts[1] if len(parts) > 1 else ""
                if sub == "active":
                    data = engine.connection_active(sender_id)
                    if data:
                        return self.send_json(data)
                elif sub == "transportfile":
                    sdp = engine.sender_sdp(sender_id)
                    if sdp:
                        return self.send_text(sdp, "application/sdp")

            if path.startswith("/x-manifest/senders/") and path.endswith("/manifest"):
                sender_id = path[len("/x-manifest/senders/"):-len("/manifest")]
                sdp = engine.sender_sdp(sender_id)
                if sdp:
                    return self.send_text(sdp, "application/sdp")

            return self.send_json({"error": "not found"}, 404)

    server = ThreadingHTTPServer(("0.0.0.0", config["http_port"]), Handler)
    server.daemon_threads = True
    return server
