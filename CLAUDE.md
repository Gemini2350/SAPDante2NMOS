# CLAUDE.md — Legacy2NMOS

Bidirektionales Dante/AES67 ↔ NMOS Gateway. Entstanden aus dem Merge von SAP2NMOS
(Sender-Seite) und dem Dante2NMOS-RX-Projekt (Receiver-Seite, Reverse Engineering).

## Architektur

Ein Prozess, ein NMOS-Node, zwei Devices ("SAP Senders" + "Dante RX"):

- `legacy2nmos/engine.py` — Kern: SAP-Listener, IS-04-Registrierung (persistente IDs,
  Orphan-Cleanup, Heartbeat), Registry-Auto-Discovery, Receiver-Sync
- `legacy2nmos/receivers.py` — ReceiverManager: Dante-Receiver-Mappings (Config-basiert),
  IS-05-State, Aktivierung → Übersetzung → optional senden
- `legacy2nmos/dante.py` — reverse-engineerte Kommando-Builder (Template-and-Patch)
- `legacy2nmos/translate.py` / `dante_sdp.py` — SDP → Dante (1 Receiver = N Kanäle)
- `legacy2nmos/is12.py` — IS-12/BCP-008-01: NcReceiverMonitor je Receiver (ws :8086)
- `legacy2nmos/httpd.py` — Node-API, IS-05 (Sender + Receiver), UI, JSON-API
- `legacy2nmos/discovery.py` — Registry via Unicast-DNS-SD (Default an)
- `legacy2nmos/dante_devices.py` — AES67-Geräte-Scan (netaudio, optional)
- `tests/test_translation.py` — Offline-Tests gegen die Capture-Werte (CI-Gate)

## Das reverse-engineerte Dante-Protokoll (Kern-Wissen)

Protokoll `0x2809` (AES67), Port 4440/UDP (ARC). Framing:
`[proto:2][len:2][txid:2][opcode:2][0000][body]`.

- `0x3410` (28 B) — Flow-Bindung, einmal je Flow.
  - `@20:22` Ziel-Dante-RX-Kanal — **HYPOTHESE** (war `0001` = "dante ch1")
- `0x3201` (112 B) — Quell-Stream-Kanal in Flow mappen, je Kanal einmal.
  - `@68:72` Source-IP — bestätigt; `@102` Quellkanal — bestätigt (1..6);
    `@106:108` RTP-Port — bestätigt; `@108:112` Multicast — bestätigt

Belegt durch Captures Dante.pcapng (2 Kanäle) und dante2.pcapng (Kanäle 1–6);
vollständige Analyse in `docs/dante-protocol-reverse-engineering.md`.

## Status Reverse Engineering / BCP-008 (Stand 2026-07-16)

- **Ziel-Kanal 0x3201 bestätigt** (Dante3.pcapng): `@96:98` = Ziel-Dante-RX-Kanal,
  `@52:54` = Begleitwert (ch1→0x0002, ch2→0x0008), `@102` = QUELL-Stream-Kanal.
  `build_map_channel` patcht alle drei; byte-genauer Test gegen den Capture. Für
  Ziel-Kanäle >2 ist `@52:54` extrapoliert (`1<<(2*ch-1)`) und UNVERIFIZIERT — bei
  4-/8-Kanal-Empfängern Capture nachliefern.
- **BCP-008 streamStatus** kommt aus dem Dante-RTP-Flow-Monitor (Subscription-
  Status-Code je RX-Kanal, via netaudio gepollt). Kalibriert an echten Geräten:
  **10 = Audio (grün), 14 = kein Audio (rot), 0 = keine Subscription**. Läuft auch
  im DRY-RUN (echter Gerätestatus). connectionStatus kommt weiter aus den ACKs.
- **sender_id-Feedback**: Bei IS-05-Aktivierung wird `subscription.sender_id/active`
  gesetzt und der Receiver re-registriert (Controller sieht den verbundenen Sender).

## OFFENE PUNKTE

1. **`0x3410`-Bind**: In Dante3.pcapng nicht enthalten (nur 0x3400-Queries). Rolle
   weiter offen; wir senden ihn wie in der funktionierenden ch1-Sequenz. `@20:22`
   (Zielkanal) bleibt Hypothese.
2. **Live-Test** nur gegen ein TESTGERÄT (AES67 an, 48 kHz, PTP gelockt).
3. **Sync-Domain (PTP)** noch NotUsed — PTP-Lock über netaudio ergänzen.
4. **`@52:54` für Ziel-Kanäle >2** verifizieren (Capture mit 4/8 Kanälen).
5. Unklare Felder: `0x3201 @16` (`4202`) und `@76` (`0x1E240`) — bleiben Template.

## Sicherheit / Betrieb

- Das Gateway arbeitet **immer live**: eine IS-05-Schaltung sendet die Dante-Kommandos
  direkt und setzt den AES67-Prefix passend zur Multicast. Teile des Empfangspfads
  sind noch reverse-engineert — nur gegen Testgeräte verifizieren.
- Docker braucht `network_mode: host` (SAP-Multicast, mDNS, erreichbare Manifest-IPs).
- Config (Node-IDs! manuelle SDPs, Receiver) liegt im OS-Config-Verzeichnis
  `Legacy2NMOS/` und migriert automatisch von den alten Pfaden (SAPDante2NMOS/Dante2NMOS/SAP-2-NMOS).

## Befehle

```bash
.venv/bin/python -m pytest -q        # Offline-Tests
.venv/bin/python app.py              # Desktop (pywebview); --headless / --browser
docker compose up -d --build         # Container; Image: gemini2350/legacy2nmos
```

CI (`.github/workflows/docker-publish.yml`): pytest-Gate, dann Multi-Arch-Build
(amd64+arm64) nach Docker Hub. Secret `DOCKERHUB_TOKEN` ist im Repo hinterlegt.
