import hashlib
import socket
import struct
import threading
import time
import uuid
from collections import deque

import requests

from .receivers import ReceiverManager
from .sdp import parse_sdp, parse_sap, build_match_key, format_string

HB_INTERVAL = 5
QUERY_CACHE_TTL = 10


def gen_id():
    return str(uuid.uuid4())


def now_ts():
    ns = time.time_ns()
    return f"{ns // 1_000_000_000}:{ns % 1_000_000_000}"


def sdp_hash(sdp):
    return hashlib.sha256(sdp.encode()).hexdigest()


def list_interfaces():
    """Return [{ip, name}] of usable IPv4 interfaces."""
    result = []
    try:
        import ifaddr
        for adapter in ifaddr.get_adapters():
            for ip in adapter.ips:
                if isinstance(ip.ip, str) and not ip.ip.startswith("169.254."):
                    result.append({"ip": ip.ip, "name": adapter.nice_name})
    except ImportError:
        pass
    if not result:
        result.append({"ip": _default_ip(), "name": "default"})
    return result


def _default_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class Engine:
    """SAP discovery + NMOS IS-04 registration, GUI-friendly."""

    def __init__(self, config):
        self.config = config
        self.lock = threading.RLock()
        self.streams = {}  # hash -> stream dict
        self.log = deque(maxlen=300)
        self.running = False
        self.registry_ok = False
        self.registry_error = ""
        self.discovered_registrar = ""
        self.sap_packets = 0
        self._threads = []
        self._node = None
        self._device = None
        self._rx_device = None
        self.receivers = ReceiverManager(config, self._log)
        from .lawo import LawoManager
        self.lawo = LawoManager(config, self._log)
        from .cymatic import CymaticManager
        self.cymatic = CymaticManager(config, self._log)
        self.receivers.add_status_listener(self._on_receiver_status)
        self._receivers_synced = False
        self.on_receivers_changed = None  # set by the IS-12 server
        self._sources = {}
        self._flows = {}
        self._senders = {}
        self._node_registered = False
        self._orphans_cleaned = False
        self._query_cache = {}
        self._query_cache_ts = 0
        self._last_discovery = 0
        self._last_recheck = 0

    # ------------------------------------------------------------------
    # lifecycle

    def start(self):
        with self.lock:
            if self.running:
                return
            self.running = True
        self._node = self._build_node()
        self._device = self._build_device()
        self._rx_device = self._build_rx_device()
        self._node_registered = False
        self._receivers_synced = False
        for sdp in self.config["manual_sdps"]:
            self._ingest(sdp, origin="manual")
        t1 = threading.Thread(target=self._sap_loop, daemon=True, name="sap")
        t2 = threading.Thread(target=self._maintenance_loop, daemon=True, name="maint")
        self._threads = [t1, t2]
        t1.start()
        t2.start()
        # Scan runs for mDNS discovery (netaudio) and/or manual cross-subnet devices.
        if self.receivers.scan_available() or self.config["manual_devices"]:
            t3 = threading.Thread(target=self._device_scan_loop, daemon=True,
                                  name="dantescan")
            self._threads.append(t3)
            t3.start()
        self._log("Engine started")

    def stop(self):
        with self.lock:
            self.running = False
        for t in self._threads:
            t.join(timeout=3)
        self._threads = []
        self._log("Engine stopped")

    def restart(self):
        self.stop()
        with self.lock:
            self.streams.clear()
            self._sources.clear()
            self._flows.clear()
            self._senders.clear()
        self.registry_ok = False
        self._orphans_cleaned = False
        self._query_cache_ts = 0
        self._last_discovery = 0
        if self.config["registrar"]:
            self.discovered_registrar = ""
        self.start()

    # ------------------------------------------------------------------
    # public API for the GUI

    def state(self):
        with self.lock:
            streams = sorted(self.streams.values(), key=lambda s: (s["name"] or "").lower())
            return {
                "running": self.running,
                "registry_ok": self.registry_ok,
                "registry_error": self.registry_error,
                "registrar": self._registrar(),
                "registrar_source": "manual" if self.config["registrar"]
                                    else ("discovered" if self.discovered_registrar else "none"),
                "auto_registrar": bool(self.config["auto_registrar"]),
                "sap_packets": self.sap_packets,
                "streams": [
                    {k: v for k, v in s.items() if k != "sdp"} for s in streams
                ],
                "dante": self.receivers.as_api(),
                "lawo": self.lawo.as_api(),
                "cymatic": self.cymatic.as_api(),
                "log": list(self.log),
            }

    def get_sdp(self, h):
        with self.lock:
            s = self.streams.get(h)
            return s["sdp"] if s else None

    def add_manual_sdp(self, sdp):
        sdp = sdp.replace("\r\n", "\n").strip() + "\n"
        parsed = parse_sdp(sdp)
        if not parsed.get("ip") or not parsed.get("port"):
            raise ValueError("SDP is missing a connection address (c=) or media port (m=audio)")
        h = self._ingest(sdp, origin="manual")
        with self.lock:
            if sdp not in self.config["manual_sdps"]:
                self.config["manual_sdps"].append(sdp)
                self.config.save()
        return h

    def remove_stream(self, h):
        with self.lock:
            s = self.streams.pop(h, None)
        if not s:
            return False
        if s["origin"] == "manual":
            with self.lock:
                if s["sdp"] in self.config["manual_sdps"]:
                    self.config["manual_sdps"].remove(s["sdp"])
                    self.config.save()
        self._unregister_stream(s)
        self._log(f"Removed {s['name'] or h[:8]}")
        return True

    # ------------------------------------------------------------------
    # NMOS node API data (served by httpd)

    def node_resources(self):
        with self.lock:
            return {
                "node": self._node,
                "devices": [self._device, self._rx_device],
                "sources": list(self._sources.values()),
                "flows": list(self._flows.values()),
                "senders": list(self._senders.values()),
                "receivers": [self._build_receiver(rx)
                              for rx in self.receivers.receivers.values()],
            }

    def sender_sdp(self, sender_id):
        with self.lock:
            for s in self.streams.values():
                if s["sender_id"] == sender_id:
                    return s["sdp"]
        return None

    def connection_active(self, sender_id):
        with self.lock:
            stream = next((s for s in self.streams.values() if s["sender_id"] == sender_id), None)
        if not stream:
            return None
        return {
            "activation": {"activation_time": now_ts(), "mode": None, "requested_time": None},
            "master_enable": True,
            "receiver_id": None,
            "transport_params": [{
                "destination_port": stream["port"] or 5004,
                "source_port": stream["port"] or 5004,
                "source_ip": stream["src_ip"] or self._ip(),
                "destination_ip": stream["mcast"],
                "rtp_enabled": True,
            }],
        }

    # ------------------------------------------------------------------
    # internals

    def _log(self, msg):
        line = f"{time.strftime('%H:%M:%S')}  {msg}"
        with self.lock:
            self.log.append(line)
        print(line, flush=True)

    def _ip(self):
        return self.config["interface_ip"] or _default_ip()

    def _registrar(self):
        # A manually configured URL always wins over the discovered one.
        return (self.config["registrar"] or self.discovered_registrar).rstrip("/")

    # -- SAP listener ---------------------------------------------------

    def _sap_loop(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            sock.bind(("0.0.0.0", self.config["sap_port"]))
            group = socket.inet_aton(self.config["sap_group"])
            # Join the SAP group on EVERY local interface, not just the default
            # route — a multi-homed gateway must catch announcements on all
            # subnets (e.g. Dante devices in another VLAN).
            if self.config["interface_ip"]:
                ifaces = [self.config["interface_ip"]]
            else:
                ifaces = [i["ip"] for i in list_interfaces()
                          if not i["ip"].startswith("127.")] or [None]
            joined = []
            for ip in ifaces:
                iface = socket.inet_aton(ip) if ip else struct.pack("=I", socket.INADDR_ANY)
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                    group + iface)
                    joined.append(ip or "default")
                except OSError:
                    pass
            sock.settimeout(1.0)
        except OSError as e:
            self._log(f"SAP listener failed to start: {e}")
            return

        self._log(f"SAP listening on {self.config['sap_group']}:{self.config['sap_port']}"
                  f" via {', '.join(joined) or 'default'}")

        while self.running:
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                self.sap_packets += 1
            sdp, deletion = parse_sap(data)
            if not sdp:
                continue
            if deletion:
                self._handle_deletion(sdp)
            else:
                self._ingest(sdp, origin="sap")
        sock.close()

    def _handle_deletion(self, sdp):
        h = sdp_hash(sdp)
        with self.lock:
            s = self.streams.get(h)
            if not s:
                # Deletion packets sometimes only carry the o= line; match on it.
                origin_line = next((l for l in sdp.splitlines() if l.startswith("o=")), None)
                if origin_line:
                    s = next((x for x in self.streams.values()
                              if x["origin"] == "sap" and origin_line in x["sdp"]), None)
        if s and s["origin"] == "sap":
            self._log(f"SAP deletion for {s['name'] or s['hash'][:8]}")
            self.remove_stream(s["hash"])

    # -- stream ingest / registration ------------------------------------

    def _ingest(self, sdp, origin):
        h = sdp_hash(sdp)
        with self.lock:
            existing = self.streams.get(h)
            if existing:
                existing["last_seen"] = time.time()
                existing["stale"] = False
                return h

        parsed = parse_sdp(sdp)
        # De-duplicate the same flow arriving from different sources: a flow we
        # created (origin "dante-tx") is superseded by the device's own SAP
        # announcement (real name/channel count). Key on multicast + port.
        flow_key = (parsed.get("ip"), parsed.get("port"))
        if flow_key[0]:
            with self.lock:
                dupes = [s for s in self.streams.values()
                         if (s["mcast"], s["port"]) == flow_key]
            for dup in dupes:
                if origin == "sap" and dup["origin"] == "dante-tx":
                    self._log(f"SAP superseded created flow {flow_key[0]} "
                              f"({dup['name'] or ''} -> {parsed.get('name', '')})")
                    self.remove_stream(dup["hash"])
                elif origin == "dante-tx" and dup["origin"] in ("sap", "dante-tx"):
                    return dup["hash"]   # already known, don't duplicate
        stream = {
            "hash": h,
            "sdp": sdp,
            "origin": origin,
            "name": parsed.get("name", ""),
            "mcast": parsed.get("ip", ""),
            "port": parsed.get("port"),
            "src_ip": parsed.get("src_ip", ""),
            "format": format_string(parsed),
            "first_seen": time.time(),
            "last_seen": time.time(),
            "stale": False,
            "registered": False,
            "external": False,
            "sender_id": None,
            "source_id": None,
            "flow_id": None,
        }
        with self.lock:
            self.streams[h] = stream
        self._log(f"Discovered {origin} stream: {stream['name'] or stream['mcast']}"
                  f" ({stream['mcast']}:{stream['port']})")
        self._try_register(stream)
        return h

    def _try_register(self, stream):
        if not self._registrar():
            return
        try:
            existing = self._find_existing_sender(stream["sdp"])
        except requests.RequestException:
            existing = None
        if existing:
            with self.lock:
                stream["sender_id"] = existing["id"]
                stream["external"] = True
                stream["registered"] = True
            self._log(f"Sender already in registry, reusing {existing['id'][:8]}…")
            return

        if not self._ensure_node_registered():
            return

        sid, fid, seid = gen_id(), gen_id(), gen_id()
        source = self._build_source(sid, stream)
        flow = self._build_flow(fid, sid, stream)
        sender = self._build_sender(seid, fid, stream)

        ok = (self._post("source", source)
              and self._post("flow", flow)
              and self._post("sender", sender))
        if not ok:
            return

        with self.lock:
            self._sources[sid] = source
            self._flows[fid] = flow
            self._senders[seid] = sender
            stream["source_id"] = sid
            stream["flow_id"] = fid
            stream["sender_id"] = seid
            stream["registered"] = True
            if seid not in self._device["senders"]:
                self._device["senders"].append(seid)
            self._device["version"] = now_ts()
        self._post("device", self._device)
        self._log(f"Registered sender for {stream['name'] or stream['mcast']}")

    def _unregister_stream(self, stream):
        if stream["external"] or not stream["registered"] or not self._registrar():
            return
        base = self._registrar()
        for rtype, rid in (("senders", stream["sender_id"]),
                           ("flows", stream["flow_id"]),
                           ("sources", stream["source_id"])):
            if not rid:
                continue
            try:
                requests.delete(f"{base}/resource/{rtype}/{rid}", timeout=2)
            except requests.RequestException:
                pass
        with self.lock:
            self._sources.pop(stream["source_id"], None)
            self._flows.pop(stream["flow_id"], None)
            self._senders.pop(stream["sender_id"], None)
            if stream["sender_id"] in self._device["senders"]:
                self._device["senders"].remove(stream["sender_id"])
                self._device["version"] = now_ts()
        if self._node_registered:
            self._post("device", self._device)

    # -- registry client --------------------------------------------------

    def _post(self, rtype, data):
        try:
            r = requests.post(f"{self._registrar()}/resource",
                              json={"type": rtype, "data": data}, timeout=2)
            if r.status_code in (200, 201):
                return True
            self._log(f"Registry rejected {rtype}: {r.status_code} {r.text[:120]}")
        except requests.RequestException as e:
            self._log(f"Registry unreachable ({e.__class__.__name__})")
            self.registry_ok = False
        return False

    def _ensure_node_registered(self):
        if self._node_registered:
            return True
        if not self._registrar():
            return False
        if self._post("node", self._node) and self._post("device", self._device) \
                and self._post("device", self._rx_device):
            self._node_registered = True
            self._sync_receivers()
            return True
        return False

    def _sync_receivers(self):
        """(Re-)register all configured Dante receivers with the registry."""
        with self.lock:
            receivers = list(self.receivers.receivers.values())
            self._rx_device["receivers"] = [rx.nmos_id for rx in receivers]
            self._rx_device["version"] = now_ts()
        ok = True
        for rx in receivers:
            ok = self._post("receiver", self._build_receiver(rx)) and ok
        ok = self._post("device", self._rx_device) and ok
        self._receivers_synced = ok
        return ok

    def add_manual_device(self, ip):
        import socket as _s
        try:
            _s.inet_aton(ip)
        except OSError:
            return False, "invalid IP address"
        dev = self.receivers.add_manual_device(ip)
        threading.Thread(target=self.receivers.refresh_devices, daemon=True).start()
        if not dev.reachable:
            return True, ("added, but the device did not answer on UDP 4440 — "
                          "check routing to its subnet")
        return True, f"added — AES67 range 239.{dev.mcast_prefix}.x.x"

    def remove_manual_device(self, ip):
        return self.receivers.remove_manual_device(ip)

    def set_device_prefix(self, ip, prefix):
        """Write a device's AES67 multicast prefix."""
        if not 0 <= prefix <= 255:
            return False, "prefix must be 0..255"
        from . import dante
        try:
            ok = dante.set_aes67_prefix(ip, prefix)
        except OSError as e:
            return False, str(e)
        self._log(f"Set AES67 prefix of {ip} to 239.{prefix}.x.x "
                  f"({'ACK' if ok else 'no ACK'})")
        threading.Thread(target=self.receivers.refresh_devices, daemon=True).start()
        return ok, ("device acknowledged" if ok else "no acknowledgement from device")

    def create_tx_flow(self, ip, channels, multicast, port=5004):
        """Create a multicast TX flow on a Dante device and register it as an
        NMOS sender directly from the device's ARC acknowledgement (no SAP)."""
        if not channels or len(channels) > 2:
            return False, "select 1 or 2 channels"
        try:
            import socket as _s
            _s.inet_aton(multicast)
        except OSError:
            return False, "invalid multicast address"
        from . import dante
        try:
            ok, variant = dante.create_tx_flow(ip, channels, multicast, port)
        except (OSError, ValueError) as e:
            return False, str(e)
        self._log(f"Create TX flow on {ip}: ch{'+'.join(map(str, channels))} "
                  f"-> {multicast}:{port} "
                  f"({variant + ' ACK' if ok else 'no ACK'})")
        if not ok:
            return False, ("no acknowledgement from device (neither AES67 nor "
                           "classic flow create was accepted)")
        # The device confirmed the flow over ARC — register it as an NMOS sender
        # straight away, no waiting for a SAP announcement.
        sdp = self._dante_tx_sdp(ip, multicast, port, len(channels))
        self._ingest(sdp, origin="dante-tx")
        return True, f"created ({variant} flow) and registered as an NMOS sender"

    def _dante_tx_sdp(self, device_ip, multicast, port, channels):
        return (
            f"v=0\r\no=- 1 1 IN IP4 {device_ip}\r\n"
            f"s=Dante TX {multicast}\r\n"
            f"c=IN IP4 {multicast}/64\r\n"          # /64 = multicast TTL 64
            f"t=0 0\r\nm=audio {port} RTP/AVP 96\r\n"
            f"a=rtpmap:96 L24/48000/{channels}\r\n"
            f"a=source-filter: incl IN IP4 {multicast} {device_ip}\r\n"
            f"a=ptime:1\r\n")

    def _on_receiver_status(self, nmos_id):
        """A receiver's connection changed — update its IS-04 subscription
        (sender_id / active) in the registry so controllers see the link."""
        rx = self.receivers.get(nmos_id)
        if rx and self._node_registered and self._registrar():
            self._post("receiver", self._build_receiver(rx))

    def add_receiver(self, label, dante_device_ip, dante_base_channel, channels=2):
        rx = self.receivers.add(label, dante_device_ip, dante_base_channel, channels)
        if self._node_registered:
            self._sync_receivers()
        if self.on_receivers_changed:
            self.on_receivers_changed()
        return rx

    def remove_receiver(self, nmos_id):
        rx = self.receivers.remove(nmos_id)
        if not rx:
            return False
        if self._node_registered and self._registrar():
            try:
                requests.delete(f"{self._registrar()}/resource/receivers/{nmos_id}",
                                timeout=2)
            except requests.RequestException:
                pass
            self._sync_receivers()
        if self.on_receivers_changed:
            self.on_receivers_changed()
        return True

    def _find_existing_sender(self, sdp):
        key = build_match_key(parse_sdp(sdp))
        if not key:
            return None
        now = time.time()
        if now - self._query_cache_ts > QUERY_CACHE_TTL:
            self._query_cache = self._fetch_sender_keys()
            self._query_cache_ts = now
        return self._query_cache.get(key)

    def _fetch_sender_keys(self):
        query = self._registrar().replace("registration", "query")
        senders, until = [], None
        while True:
            url = f"{query}/senders?paging.limit=100&paging.order=update"
            if until:
                url += f"&paging.until={until}"
            r = requests.get(url, timeout=2)
            if r.status_code != 200:
                break
            batch = r.json()
            if not batch:
                break
            senders.extend(batch)
            link = r.headers.get("Link", "")
            if 'rel="next"' not in link:
                break
            nxt = link.split(";")[0].strip("<> ")
            if "paging.until=" not in nxt:
                break
            until = nxt.split("paging.until=")[1].split("&")[0]

        keys = {}
        own = {s["id"] for s in self._senders.values()}
        for s in senders:
            if s.get("id") in own or not s.get("manifest_href"):
                continue
            try:
                r = requests.get(s["manifest_href"], timeout=2)
                if r.status_code != 200:
                    continue
                key = build_match_key(parse_sdp(r.text))
                if key:
                    keys[key] = s
            except requests.RequestException:
                continue
        return keys

    # -- maintenance -------------------------------------------------------

    def _maintenance_loop(self):
        while self.running:
            if self.config["auto_registrar"]:
                self._auto_discover()
            if self._registrar():
                self._heartbeat()
                self._retry_pending()
                self._recheck_registry()
            self._expire_streams()
            for _ in range(HB_INTERVAL * 2):
                if not self.running:
                    return
                time.sleep(0.5)

    def _recheck_registry(self):
        """Periodically check whether streams we registered ourselves have
        meanwhile appeared natively in the registry (device gained NMOS). If so,
        step back: unregister our duplicate and defer to the real sender."""
        interval = int(self.config["registry_recheck_interval"])
        if interval <= 0:
            return
        now = time.time()
        if now - self._last_recheck < interval:
            return
        self._last_recheck = now
        with self.lock:
            owned = [s for s in self.streams.values()
                     if s["registered"] and not s["external"]]
        if not owned:
            return
        self._query_cache_ts = 0  # force a fresh registry read
        for stream in owned:
            try:
                existing = self._find_existing_sender(stream["sdp"])
            except requests.RequestException:
                return
            if existing and existing["id"] != stream["sender_id"]:
                self._log(f"Stream now native in registry: "
                          f"{stream['name'] or stream['mcast']} -> deferring to "
                          f"{existing['id'][:8]}…, removing our duplicate")
                self._unregister_stream(stream)
                with self.lock:
                    stream["external"] = True
                    stream["sender_id"] = existing["id"]
                    stream["source_id"] = None
                    stream["flow_id"] = None

    def _auto_discover(self):
        """Find the registry via unicast DNS-SD when none is reachable."""
        if self.config["registrar"]:
            return  # manual override active
        if self.discovered_registrar and self.registry_ok:
            return
        now = time.time()
        if now - self._last_discovery < 30:
            return
        self._last_discovery = now
        try:
            from .discovery import discover_registries
        except ImportError:
            self._log("DNS-SD discovery needs the dnspython package")
            return
        try:
            candidates = discover_registries(self.config["dns_sd_domain"],
                                             self.config["dns_sd_nameserver"])
        except Exception as e:
            self._log(f"DNS-SD discovery failed: {e}")
            return
        if not candidates:
            return
        best = candidates[0]
        if best["url"] != self.discovered_registrar:
            self._log(f"DNS-SD discovered registry: {best['name']} -> {best['url']}")
            self.discovered_registrar = best["url"]
            self._node_registered = False
            self._orphans_cleaned = False
            self._query_cache_ts = 0

    def _heartbeat(self):
        try:
            r = requests.post(f"{self._registrar()}/health/nodes/{self.config['node_id']}",
                              timeout=2)
            if r.status_code == 200:
                if not self.registry_ok:
                    self._log("Registry connection OK")
                self.registry_ok = True
                self.registry_error = ""
                if not self._orphans_cleaned:
                    self._cleanup_orphans()
                    self._orphans_cleaned = True
            elif r.status_code == 404:
                self._log("Registry lost our node, re-registering")
                self._node_registered = False
                self.registry_ok = self._reregister_all()
            else:
                self.registry_ok = False
                self.registry_error = f"HTTP {r.status_code}"
        except requests.RequestException as e:
            if self.registry_ok or not self.registry_error:
                self._log(f"Registry unreachable ({e.__class__.__name__})")
            self.registry_ok = False
            self.registry_error = "unreachable"

    def _reregister_all(self):
        if not self._ensure_node_registered():
            return False
        with self.lock:
            resources = (list(self._sources.values()), list(self._flows.values()),
                         list(self._senders.values()))
        for rtype, items in zip(("source", "flow", "sender"), resources):
            for item in items:
                self._post(rtype, item)
        self._sync_receivers()
        return True

    def _cleanup_orphans(self):
        """Delete registry resources of our device left over from a previous run.

        The node ID persists across restarts and we keep heartbeating, so the
        registry never garbage-collects resources we no longer know about.
        """
        base = self._registrar()
        query = base.replace("registration", "query")
        with self.lock:
            known = {
                "senders": (set(self._senders), self.config["device_id"]),
                "flows": (set(self._flows), self.config["device_id"]),
                "sources": (set(self._sources), self.config["device_id"]),
                "receivers": (set(self.receivers.receivers),
                              self.config["rx_device_id"]),
            }
        for rtype, (known_ids, device_id) in known.items():
            try:
                r = requests.get(f"{query}/{rtype}?device_id={device_id}", timeout=2)
                if r.status_code != 200:
                    continue
                for item in r.json():
                    rid = item.get("id")
                    if rid and rid not in known_ids \
                            and item.get("device_id") == device_id:
                        requests.delete(f"{base}/resource/{rtype}/{rid}", timeout=2)
                        self._log(f"Removed orphaned {rtype[:-1]} {rid[:8]}… from registry")
            except requests.RequestException:
                return

    def _retry_pending(self):
        with self.lock:
            pending = [s for s in self.streams.values() if not s["registered"]]
        for s in pending:
            self._try_register(s)

    def _expire_streams(self):
        timeout = self.config["stream_timeout"]
        now = time.time()
        with self.lock:
            sap_streams = [s for s in self.streams.values() if s["origin"] == "sap"]
        for s in sap_streams:
            age = now - s["last_seen"]
            if age > timeout * 5:
                self._log(f"Stream expired: {s['name'] or s['mcast']}")
                self.remove_stream(s["hash"])
            elif age > timeout:
                s["stale"] = True

    # -- NMOS resource builders ---------------------------------------------

    def _build_node(self):
        ip = self._ip()
        port = self.config["http_port"]
        return {
            "id": self.config["node_id"],
            "version": now_ts(),
            "label": "Legacy2NMOS",
            "description": "SAP-to-NMOS senders + NMOS-to-Dante receivers",
            "tags": {},
            "href": f"http://{ip}:{port}/x-nmos/node/v1.3/",
            "hostname": socket.gethostname().split(".")[0] or "legacy2nmos",
            "api": {
                "versions": ["v1.3"],
                "endpoints": [{"host": ip, "port": port, "protocol": "http"}],
            },
            "caps": {},
            "services": [],
            "clocks": [{"name": "clk0", "ref_type": "internal"}],
            "interfaces": [{
                "name": "eth0",
                "chassis_id": "00-00-00-00-00-00",
                "port_id": "00-00-00-00-00-00",
            }],
        }

    def _build_device(self):
        ip = self._ip()
        port = self.config["http_port"]
        return {
            "id": self.config["device_id"],
            "version": now_ts(),
            "label": "SAP Senders",
            "description": "SAP discovered streams",
            "tags": {},
            "type": "urn:x-nmos:device:generic",
            "node_id": self.config["node_id"],
            "senders": [],
            "receivers": [],
            "controls": [{
                "href": f"http://{ip}:{port}/x-nmos/connection/v1.1/",
                "type": "urn:x-nmos:control:sr-ctrl/v1.1",
            }],
        }

    def _build_rx_device(self):
        ip = self._ip()
        port = self.config["http_port"]
        return {
            "id": self.config["rx_device_id"],
            "version": now_ts(),
            "label": "Dante RX",
            "description": "AES67 Dante devices exposed as NMOS receivers",
            "tags": {},
            "type": "urn:x-nmos:device:audio",
            "node_id": self.config["node_id"],
            "senders": [],
            "receivers": [rx.nmos_id for rx in self.receivers.receivers.values()],
            "controls": [{
                "href": f"http://{ip}:{port}/x-nmos/connection/v1.1/",
                "type": "urn:x-nmos:control:sr-ctrl/v1.1",
            }, {
                "href": f"ws://{ip}:{self.config['ncp_port']}/x-nmos/ncp/v1.0",
                "type": "urn:x-nmos:control:ncp/v1.0",
            }],
        }

    def _build_receiver(self, rx):
        return {
            "id": rx.nmos_id,
            "version": now_ts(),
            "label": rx.label,
            "description": f"{rx.channels}ch -> {rx.dante_device_ip} "
                           f"ch{rx.dante_base_channel}",
            "tags": {},
            "device_id": self.config["rx_device_id"],
            "transport": "urn:x-nmos:transport:rtp.mcast",
            "format": "urn:x-nmos:format:audio",
            "caps": {
                "media_types": ["audio/L24", "audio/L16"],
                "constraint_sets": [{
                    "urn:x-nmos:cap:format:channel_count": {"enum": [rx.channels]},
                    "urn:x-nmos:cap:format:sample_rate": {
                        "enum": [{"numerator": 48000, "denominator": 1}]},
                }],
            },
            "subscription": self.receivers.subscription(rx.nmos_id),
            "interface_bindings": ["eth0"],
        }

    def _device_scan_loop(self):
        idle = max(10, int(self.config["device_scan_interval"]))
        active = min(idle, 10)  # poll faster while a receiver is patched
        while self.running:
            self.receivers.refresh_devices()
            any_active = any(s["summary"]["active"]
                             for s in self.receivers.state.values())
            interval = active if any_active else idle
            for _ in range(interval * 2):
                if not self.running:
                    return
                time.sleep(0.5)

    def _build_source(self, sid, stream):
        parsed = parse_sdp(stream["sdp"])
        ch = parsed.get("ch", 2)
        return {
            "id": sid,
            "version": now_ts(),
            "label": stream["name"] or f"SAP Source {sid[:8]}",
            "description": "SAP discovered source",
            "tags": {},
            "device_id": self.config["device_id"],
            "format": "urn:x-nmos:format:audio",
            "clock_name": "clk0",
            "channels": [{"label": f"Ch{i + 1}"} for i in range(ch)],
            "parents": [],
            "caps": {},
        }

    def _build_flow(self, fid, sid, stream):
        parsed = parse_sdp(stream["sdp"])
        bit = parsed.get("bit", 24)
        return {
            "id": fid,
            "version": now_ts(),
            "label": stream["name"] or f"SAP Flow {fid[:8]}",
            "description": "SAP flow",
            "tags": {},
            "device_id": self.config["device_id"],
            "source_id": sid,
            "format": "urn:x-nmos:format:audio",
            "media_type": f"audio/L{bit}",
            "bit_depth": bit,
            "sample_rate": {"numerator": parsed.get("rate", 48000), "denominator": 1},
            "parents": [],
        }

    def _build_sender(self, seid, fid, stream):
        ip = self._ip()
        port = self.config["http_port"]
        return {
            "id": seid,
            "version": now_ts(),
            "label": stream["name"] or f"SAP Sender {seid[:8]}",
            "description": "SAP sender",
            "tags": {},
            "device_id": self.config["device_id"],
            "flow_id": fid,
            "transport": "urn:x-nmos:transport:rtp.mcast",
            "manifest_href": f"http://{ip}:{port}/x-manifest/senders/{seid}/manifest",
            "interface_bindings": ["eth0"],
            "subscription": {"active": True, "receiver_id": None},
        }
