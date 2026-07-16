# Legacy2NMOS

[![Docker](https://github.com/Gemini2350/Legacy2NMOS/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/Gemini2350/Legacy2NMOS/actions/workflows/docker-publish.yml)
[![Docker Hub](https://img.shields.io/docker/v/gemini2350/legacy2nmos?label=docker%20hub)](https://hub.docker.com/r/gemini2350/legacy2nmos)

Bidirectional Dante/AES67 ↔ NMOS gateway with a GUI (desktop app for Windows/macOS or
Docker container):

- **Sender side (SAP → NMOS):** listens to SAP/SDP announcements
  (239.255.255.255:9875) and registers the discovered streams as senders in an NMOS
  IS-04 registry; manual SDP entry included.
- **Receiver side (NMOS → Dante):** exposes AES67-enabled Dante devices as NMOS
  receivers and turns IS-05 patches into Dante control commands — with BCP-008-01
  receiver monitoring over IS-12 so controllers see whether the patch worked.

## Quick start (Docker, Linux host)

```sh
docker run -d --name legacy2nmos \
  --network host --restart always \
  -v legacy2nmos-config:/config \
  gemini2350/legacy2nmos:latest
```

Open the UI at `http://<host>:8085/ui/` — the NMOS registry is found automatically via
unicast DNS-SD; discovered SAP streams appear in the table and get registered. To update:

```sh
docker pull gemini2350/legacy2nmos:latest && docker rm -f legacy2nmos
# then re-run the docker run command above
```

## Features

### Sender side (SAP → NMOS)

- Live table of all SAP-discovered streams: name, multicast address, port, format
  (bit depth / sample rate / channels), source IP, registration status
- **Manual SDP entry** — paste an SDP or load a `.sdp` file; manual streams persist
  across restarts
- Registers streams as NMOS Node/Device/Source/Flow/Sender (IS-04 v1.3), serves the
  SDP manifest and an IS-05 connection API for controllers
- Detects senders that are already in the registry (multicast + source IP match) and
  does not register duplicates
- Handles SAP deletion packets and stream timeouts (stale streams are greyed out,
  expired streams are unregistered)
- Persistent node/device IDs + orphan cleanup: restarting the app never leaves stale
  resources in the registry
- **Registry auto-discovery via unicast DNS-SD** (IS-04 `_nmos-register._tcp` /
  `_nmos-registration._tcp` PTR/SRV/TXT lookup) — **on by default**: leave the registrar
  URL empty and the app finds the registry itself (configurable search domain, optional
  DNS server override, *Discover* button in the settings). Entering a URL manually
  always overrides discovery.
- Selectable network interface for the SAP listener
- Works without a registry too — discovery keeps running, registration resumes when
  the registry becomes reachable

### Receiver side (NMOS → Dante)

- Exposes AES67-enabled Dante devices as **NMOS receivers** (IS-04) and hosts the
  **IS-05 Connection API**: an NMOS controller patches a sender to the receiver and
  the SDP is translated into reverse-engineered Dante control commands (`0x3410` +
  `0x3201`, UDP 4440) — see `docs/dante-protocol-reverse-engineering.md`
- The gateway operates live: on an IS-05 patch it sends the Dante control commands
  directly and aligns the device's AES67 prefix to the patched multicast. ⚠️ Parts
  of the receive path are still reverse-engineered — verify against a test device.
- **BCP-008-01 receiver monitoring via IS-12**: one NcReceiverMonitor per receiver
  (WebSocket control endpoint `urn:x-nmos:control:ncp/v1.0`, port 8086). Connection
  status is fed from the Dante command ACKs, so NMOS controllers can see whether a
  patch actually reached the device.
- Dante device inventory in the UI (requires the optional `netaudio` package)

## Run from source

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
```

Options:

```
--registrar URL   NMOS Registration API, e.g. http://10.1.200.100:8010/x-nmos/registration/v1.3
--headless        run without a window (server/daemon mode)
--browser         open the UI in the default browser instead of a native window
--port N          HTTP port for the UI and the NMOS node API (default 8085)
```

The registrar can also be set in the GUI under **Settings**. Configuration is stored in
`~/Library/Application Support/Legacy2NMOS/` (macOS) or `%APPDATA%\Legacy2NMOS\` (Windows).

## Build a standalone app

```sh
pip install pyinstaller
./build-macos.sh        # -> dist/Legacy2NMOS.app
build-windows.bat       # -> dist\Legacy2NMOS\Legacy2NMOS.exe  (run on Windows)
```

## Linux (Ubuntu)

The headless and browser modes work out of the box:

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements-docker.txt
.venv/bin/python app.py --browser     # UI in the default browser
.venv/bin/python app.py --headless    # daemon mode, UI at http://<host>:8085/ui/
```

For a native window install the WebKit2GTK bindings first
(`sudo apt install python3-gi gir1.2-webkit2-4.1`, then `pip install pywebview`).

## Docker

CI publishes `gemini2350/legacy2nmos` (amd64 + arm64) to Docker Hub on every push to main:

```sh
docker compose pull && docker compose up -d    # use the CI image
docker compose up -d --build                   # or build locally
# UI: http://<host>:8085/ui/
```

The container runs headless; the web UI works from any browser. **Host networking is
required** (already set in `docker-compose.yml`): the SAP listener needs the host's
multicast traffic and the announced manifest URLs must carry a reachable IP. This only
works on Linux hosts — Docker Desktop on macOS/Windows isolates the host network.
Configuration (node IDs, manual SDPs, settings) persists in the `legacy2nmos-config` volume.

## Legacy CLI

The original single-file script is kept as `SAP2NMOS.py`:

```sh
python SAP2NMOS.py --registrar http://10.1.200.100:8010/x-nmos/registration/v1.3
```
