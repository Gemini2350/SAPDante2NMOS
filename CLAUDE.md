# CLAUDE.md — SAPDante2NMOS

Bidirektionales Dante/AES67 ↔ NMOS Gateway. Entstanden aus dem Merge von SAP2NMOS
(Sender-Seite) und dem SAPDante2NMOS-RX-Projekt (Receiver-Seite, Reverse Engineering).

## Architektur

Ein Prozess, ein NMOS-Node, zwei Devices ("SAP Senders" + "Dante RX"):

- `sapdante2nmos/engine.py` — Kern: SAP-Listener, IS-04-Registrierung (persistente IDs,
  Orphan-Cleanup, Heartbeat), Registry-Auto-Discovery, Receiver-Sync
- `sapdante2nmos/receivers.py` — ReceiverManager: Dante-Receiver-Mappings (Config-basiert),
  IS-05-State, Aktivierung → Übersetzung → optional senden
- `sapdante2nmos/dante.py` — reverse-engineerte Kommando-Builder (Template-and-Patch)
- `sapdante2nmos/translate.py` / `dante_sdp.py` — SDP → Dante (1 Receiver = N Kanäle)
- `sapdante2nmos/is12.py` — IS-12/BCP-008-01: NcReceiverMonitor je Receiver (ws :8086)
- `sapdante2nmos/httpd.py` — Node-API, IS-05 (Sender + Receiver), UI, JSON-API
- `sapdante2nmos/discovery.py` — Registry via Unicast-DNS-SD (Default an)
- `sapdante2nmos/dante_devices.py` — AES67-Geräte-Scan (netaudio, optional)
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

## OFFENE PUNKTE

1. **`0x3410`-Zielfeld bestätigen** — Capture nötig, die denselben Quellkanal auf
   einen ANDEREN Dante-RX-Kanal routet (Erwartung: `@20:22` springt mit).
2. **Live-Test mit ARMED** nur gegen ein TESTGERÄT (AES67 an, 48 kHz, PTP gelockt).
3. **BCP-008 vertiefen** — PTP-Lock + RX-Subscription-Status über den
   netaudio-Lesepfad pollen; aktuell speisen nur die Kommando-ACKs die Monitore
   (Sync-Domain steht auf NotUsed).
4. Unklare Felder: `0x3201 @16` (`4202`) und `@76` (`0x1E240`) — bleiben Template.

## Sicherheit / Betrieb

- **DRY-RUN ist Default** (`apply_mode` in der Config bzw. ARMED-Checkbox in den
  Settings). Ohne bestätigtes `0x3410`-Zielfeld nicht produktiv scharf schalten.
- Docker braucht `network_mode: host` (SAP-Multicast, mDNS, erreichbare Manifest-IPs).
- Config (Node-IDs! manuelle SDPs, Receiver) liegt im OS-Config-Verzeichnis
  `SAPDante2NMOS/` und migriert automatisch vom alten `SAP-2-NMOS/`-Pfad.

## Befehle

```bash
.venv/bin/python -m pytest -q        # Offline-Tests
.venv/bin/python app.py              # Desktop (pywebview); --headless / --browser
docker compose up -d --build         # Container; Image: gemini2350/sapdante2nmos
```

CI (`.github/workflows/docker-publish.yml`): pytest-Gate, dann Multi-Arch-Build
(amd64+arm64) nach Docker Hub. Secret `DOCKERHUB_TOKEN` ist im Repo hinterlegt.
