"""IS-12 (NMOS Control Protocol) server with BCP-008-01 receiver monitors.

One NcReceiverMonitor per configured Dante receiver, fed from the IS-05
activation results (command ACKs). Device model:

    oid 1  root NcBlock
    oid 2  NcDeviceManager
    oid 3  NcClassManager (stub)
    oid 10+  NcReceiverMonitor per receiver

Implementation notes (verified against nmos-js / the AMWA mock in earlier work):
- NcMethodStatus is HTTP-style (OK=200).
- NcBlock.members is 2p1; NcObject 1p6 userLabel, 1p7 touchpoints.
- Receiver monitor domains 4p1/4p4/4p7/4p11 (+ messages, + transition
  counters 4p3/4p6/4p9/4p13); ResetCountersAndMessages is 4m3.
- Domain properties are notified BEFORE overallStatus (3p1) so clients that
  compare full state never lag a transition behind.
"""

import asyncio
import json
import threading

# --- class ids ---------------------------------------------------------------
CID_BLOCK = [1, 1]
CID_DEVICE_MANAGER = [1, 3, 1]
CID_CLASS_MANAGER = [1, 3, 2]
CID_RECEIVER_MONITOR = [1, 2, 2, 1]

# --- message types -----------------------------------------------------------
MT_COMMAND = 0
MT_COMMAND_RESPONSE = 1
MT_NOTIFICATION = 2
MT_SUBSCRIPTION = 3
MT_SUBSCRIPTION_RESPONSE = 4
MT_ERROR = 5

OK = 200

# --- BCP-008 status enums ----------------------------------------------------
INACTIVE, HEALTHY, PARTIALLY_HEALTHY, UNHEALTHY = 0, 1, 2, 3
LINK_ALL_UP, LINK_SOME_DOWN, LINK_ALL_DOWN = 1, 2, 3
SYNC_NOT_USED = 0

DOMAIN_PROPS = {
    # domain: (status, message, counter)
    "link": ((4, 1), (4, 2), (4, 3)),
    "connection": ((4, 4), (4, 5), (4, 6)),
    "sync": ((4, 7), (4, 8), (4, 9)),
    "stream": ((4, 11), (4, 12), (4, 13)),
}


def _monitor_status(rx_state, apply_mode):
    """Derive the four BCP-008 domain statuses from the IS-05/Dante state."""
    active = rx_state["summary"]["active"]
    ack = rx_state["last_ack"]  # True/False after --apply, None in DRY-RUN

    if not active:
        return {
            "link": (LINK_ALL_UP, ""),
            "connection": (INACTIVE, ""),
            "sync": (SYNC_NOT_USED, "PTP status not monitored yet"),
            "stream": (INACTIVE, ""),
        }
    if not apply_mode or ack is None:
        return {
            "link": (LINK_ALL_UP, ""),
            "connection": (HEALTHY, "dry-run: no Dante commands sent"),
            "sync": (SYNC_NOT_USED, "PTP status not monitored yet"),
            "stream": (INACTIVE, "dry-run: no Dante commands sent"),
        }
    if ack:
        return {
            "link": (LINK_ALL_UP, ""),
            "connection": (HEALTHY, "Dante device acknowledged all commands"),
            "sync": (SYNC_NOT_USED, "PTP status not monitored yet"),
            "stream": (HEALTHY, "assumed from command ACK (no RX polling yet)"),
        }
    return {
        "link": (LINK_ALL_DOWN, "Dante device did not respond"),
        "connection": (UNHEALTHY, "Dante device did not acknowledge commands"),
        "sync": (SYNC_NOT_USED, "PTP status not monitored yet"),
        "stream": (UNHEALTHY, "commands not acknowledged"),
    }


def _overall(domains):
    conn = domains["connection"][0]
    if conn == INACTIVE:
        return INACTIVE, ""
    worst = conn
    if domains["stream"][0] != INACTIVE:
        worst = max(worst, domains["stream"][0])
    worst = max(worst, {LINK_ALL_UP: HEALTHY, LINK_SOME_DOWN: PARTIALLY_HEALTHY,
                        LINK_ALL_DOWN: UNHEALTHY}[domains["link"][0]])
    msg = "" if worst == HEALTHY else \
        next((m for s, m in domains.values() if s not in (INACTIVE, HEALTHY,
                                                          SYNC_NOT_USED) and m), "")
    return worst, msg


class Monitor:
    """Property state of one NcReceiverMonitor."""

    def __init__(self, oid, nmos_id, label):
        self.oid = oid
        self.nmos_id = nmos_id
        self.label = label
        self.props = {
            (1, 1): CID_RECEIVER_MONITOR, (1, 2): oid, (1, 3): True,
            (1, 4): 1, (1, 5): f"monitor-{oid}", (1, 6): f"Monitor {label}",
            (1, 7): [{"contextNamespace": "x-nmos",
                      "resource": {"resourceType": "receiver", "id": nmos_id}}],
            (1, 8): None,
            (2, 1): True,                      # NcWorker.enabled
            (3, 1): INACTIVE, (3, 2): "",      # overallStatus / message
            (4, 10): None,                     # synchronizationSourceId
            (4, 14): False,                    # autoResetCountersAndMessages
        }
        for status_id, msg_id, counter_id in DOMAIN_PROPS.values():
            self.props[status_id] = INACTIVE
            self.props[msg_id] = ""
            self.props[counter_id] = 0
        self.props[DOMAIN_PROPS["link"][0]] = LINK_ALL_UP
        self.props[DOMAIN_PROPS["sync"][0]] = SYNC_NOT_USED

    def update(self, rx_state, apply_mode):
        """Recompute statuses; returns notifications (domains first, overall last)."""
        changes = []
        domains = _monitor_status(rx_state, apply_mode)
        for domain, (value, msg) in domains.items():
            status_id, msg_id, counter_id = DOMAIN_PROPS[domain]
            old = self.props[status_id]
            if value != old:
                self.props[status_id] = value
                changes.append((status_id, value))
                healthy_values = (INACTIVE, HEALTHY, SYNC_NOT_USED) \
                    if domain != "link" else (LINK_ALL_UP,)
                if value not in healthy_values:
                    self.props[counter_id] += 1
                    changes.append((counter_id, self.props[counter_id]))
            if msg != self.props[msg_id]:
                self.props[msg_id] = msg
                changes.append((msg_id, msg))
        value, msg = _overall(domains)
        if msg != self.props[(3, 2)]:
            self.props[(3, 2)] = msg
            changes.append(((3, 2), msg))
        if value != self.props[(3, 1)]:
            self.props[(3, 1)] = value
            changes.append(((3, 1), value))   # overall status LAST
        return changes

    def reset_counters(self):
        changes = []
        for _, msg_id, counter_id in DOMAIN_PROPS.values():
            if self.props[counter_id]:
                self.props[counter_id] = 0
                changes.append((counter_id, 0))
            if self.props[msg_id]:
                self.props[msg_id] = ""
                changes.append((msg_id, ""))
        return changes

    def descriptor(self):
        return {"role": self.props[(1, 5)], "oid": self.oid, "constantOid": True,
                "classId": CID_RECEIVER_MONITOR,
                "userLabel": self.props[(1, 6)], "owner": 1}


class Is12Server:
    """Minimal IS-12 server: root block, managers, receiver monitors."""

    def __init__(self, engine, config):
        self.engine = engine
        self.config = config
        self.port = config["ncp_port"]
        self.monitors = {}        # nmos_id -> Monitor
        self._next_oid = 10
        self.lock = threading.RLock()
        self.loop = None
        self._clients = {}        # ws -> set(subscribed oids)
        self._stop = None
        self._thread = None
        self.sync_monitors(notify=False)
        engine.on_receivers_changed = lambda: self.sync_monitors(notify=True)
        engine.receivers.on_status = self.receiver_status_changed

    # ------------------------------------------------------------ lifecycle

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="is12")
        self._thread.start()

    def _run(self):
        import websockets

        async def main():
            self._stop = asyncio.get_event_loop().create_future()
            async with websockets.serve(self._handler, "0.0.0.0", self.port):
                self.engine._log(f"IS-12 control on ws://0.0.0.0:{self.port}"
                                 f"/x-nmos/ncp/v1.0")
                await self._stop

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(main())
        except OSError as e:
            self.engine._log(f"IS-12 server failed to start: {e}")

    def stop(self):
        if self.loop and self._stop:
            self.loop.call_soon_threadsafe(
                lambda: self._stop.done() or self._stop.set_result(None))

    # ------------------------------------------------------------ model sync

    def sync_monitors(self, notify=True):
        with self.lock:
            current = self.engine.receivers.receivers
            added_or_removed = False
            for nmos_id, rx in current.items():
                if nmos_id not in self.monitors:
                    self.monitors[nmos_id] = Monitor(self._next_oid, nmos_id,
                                                     rx.label)
                    self._next_oid += 1
                    added_or_removed = True
            for nmos_id in list(self.monitors):
                if nmos_id not in current:
                    del self.monitors[nmos_id]
                    added_or_removed = True
        if added_or_removed and notify:
            self._notify(1, (2, 1), self._root_members())

    def receiver_status_changed(self, nmos_id):
        with self.lock:
            mon = self.monitors.get(nmos_id)
            if not mon:
                return
            state = self.engine.receivers.state.get(nmos_id)
            if state is None:
                return
            changes = mon.update(state, bool(self.config["apply_mode"]))
        for prop_id, value in changes:
            self._notify(mon.oid, prop_id, value)

    def _root_members(self):
        with self.lock:
            members = [
                {"role": "DeviceManager", "oid": 2, "constantOid": True,
                 "classId": CID_DEVICE_MANAGER, "userLabel": "Device Manager",
                 "owner": 1},
                {"role": "ClassManager", "oid": 3, "constantOid": True,
                 "classId": CID_CLASS_MANAGER, "userLabel": "Class Manager",
                 "owner": 1},
            ]
            members += [m.descriptor() for m in self.monitors.values()]
            return members

    # ------------------------------------------------------------ properties

    def _get_property(self, oid, level, index):
        key = (level, index)
        if oid == 1:
            root = {(1, 1): CID_BLOCK, (1, 2): 1, (1, 3): True, (1, 4): None,
                    (1, 5): "root", (1, 6): "SAPDante2NMOS", (1, 7): None,
                    (1, 8): None, (2, 1): self._root_members()}
            return root.get(key, KeyError)
        if oid == 2:
            dm = {(1, 1): CID_DEVICE_MANAGER, (1, 2): 2, (1, 3): True,
                  (1, 4): 1, (1, 5): "DeviceManager",
                  (1, 6): "Device Manager", (1, 7): None, (1, 8): None,
                  (3, 1): "v1.0",
                  (3, 2): {"name": "Gemini2350"},
                  (3, 3): {"name": "SAPDante2NMOS", "key": "sapdante2nmos",
                           "revisionLevel": "1.0.0"},
                  (3, 4): self.config["node_id"][:13],
                  (3, 5): None, (3, 6): "SAPDante2NMOS", (3, 7): None,
                  (3, 8): {"generic": 0, "detail": None}, (3, 9): 0}
            return dm.get(key, KeyError)
        if oid == 3:
            cm = {(1, 1): CID_CLASS_MANAGER, (1, 2): 3, (1, 3): True,
                  (1, 4): 1, (1, 5): "ClassManager",
                  (1, 6): "Class Manager", (1, 7): None, (1, 8): None}
            return cm.get(key, KeyError)
        with self.lock:
            for mon in self.monitors.values():
                if mon.oid == oid:
                    return mon.props.get(key, KeyError)
        return None  # unknown oid

    # ------------------------------------------------------------ commands

    def _handle_command(self, cmd):
        handle = cmd.get("handle")
        oid = cmd.get("oid")
        method = cmd.get("methodId") or {}
        args = cmd.get("arguments") or {}
        level, index = method.get("level"), method.get("index")

        def result(status, value=None, error=None):
            r = {"status": status}
            if value is not None or status == OK:
                r["value"] = value
            if error:
                r["errorMessage"] = error
            return {"handle": handle, "result": r}

        # NcObject 1m1 Get
        if (level, index) == (1, 1):
            pid = args.get("id") or {}
            value = self._get_property(oid, pid.get("level"), pid.get("index"))
            if value is None:
                return result(404, error="unknown oid")
            if value is KeyError:
                return result(502, error="property not implemented")
            return result(OK, value)

        # NcObject 1m2 Set — only userLabel is writable
        if (level, index) == (1, 2):
            pid = args.get("id") or {}
            if (pid.get("level"), pid.get("index")) == (1, 6):
                with self.lock:
                    for mon in self.monitors.values():
                        if mon.oid == oid:
                            mon.props[(1, 6)] = args.get("value")
                            break
                self._notify(oid, (1, 6), args.get("value"))
                return result(OK)
            return result(405, error="property is read-only")

        # NcBlock 2m1 GetMemberDescriptors
        if (level, index) == (2, 1) and oid == 1:
            return result(OK, self._root_members())

        # NcReceiverMonitor 4m3 ResetCountersAndMessages
        if (level, index) == (4, 3):
            with self.lock:
                mon = next((m for m in self.monitors.values() if m.oid == oid),
                           None)
                changes = mon.reset_counters() if mon else None
            if changes is None:
                return result(404, error="unknown oid")
            for prop_id, value in changes:
                self._notify(oid, prop_id, value)
            return result(OK)

        return result(501, error="method not implemented")

    # ------------------------------------------------------------ websocket

    async def _handler(self, ws):
        self._clients[ws] = set()
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except ValueError:
                    await ws.send(json.dumps({
                        "protocolVersion": "1.0", "messageType": MT_ERROR,
                        "status": 400, "errorMessage": "invalid JSON"}))
                    continue
                mtype = msg.get("messageType")
                if mtype == MT_COMMAND:
                    responses = [self._handle_command(c)
                                 for c in msg.get("commands", [])]
                    await ws.send(json.dumps({
                        "protocolVersion": "1.0",
                        "messageType": MT_COMMAND_RESPONSE,
                        "responses": responses}))
                elif mtype == MT_SUBSCRIPTION:
                    subs = set(msg.get("subscriptions", []))
                    self._clients[ws] = subs
                    await ws.send(json.dumps({
                        "protocolVersion": "1.0",
                        "messageType": MT_SUBSCRIPTION_RESPONSE,
                        "subscriptions": sorted(subs)}))
        finally:
            self._clients.pop(ws, None)

    def _notify(self, oid, prop_id, value):
        """Send a PropertyChanged notification to subscribed clients."""
        if not self.loop:
            return
        payload = json.dumps({
            "protocolVersion": "1.0", "messageType": MT_NOTIFICATION,
            "notifications": [{
                "oid": oid,
                "eventId": {"level": 1, "index": 1},
                "eventData": {
                    "propertyId": {"level": prop_id[0], "index": prop_id[1]},
                    "changeType": 0,
                    "value": value,
                    "sequenceItemIndex": None,
                },
            }],
        })

        def broadcast():
            for ws, subs in list(self._clients.items()):
                if oid in subs:
                    asyncio.ensure_future(ws.send(payload))

        self.loop.call_soon_threadsafe(broadcast)
