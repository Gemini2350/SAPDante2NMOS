# SAP-2-NMOS

Desktop tool (Windows / macOS) that listens to **SAP/SDP announcements** (AES67 style,
239.255.255.255:9875) and registers the discovered streams as **senders in an NMOS IS-04
registry** — including a GUI that shows every discovered stream and lets you add streams
manually by pasting an SDP.

## Features

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
`~/Library/Application Support/SAP-2-NMOS/` (macOS) or `%APPDATA%\SAP-2-NMOS\` (Windows).

## Build a standalone app

```sh
pip install pyinstaller
./build-macos.sh        # -> dist/SAP-2-NMOS.app
build-windows.bat       # -> dist\SAP-2-NMOS\SAP-2-NMOS.exe  (run on Windows)
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

```sh
docker compose up -d --build
# UI: http://<host>:8085/ui/
```

The container runs headless; the web UI works from any browser. **Host networking is
required** (already set in `docker-compose.yml`): the SAP listener needs the host's
multicast traffic and the announced manifest URLs must carry a reachable IP. This only
works on Linux hosts — Docker Desktop on macOS/Windows isolates the host network.
Configuration (node IDs, manual SDPs, settings) persists in the `sap2nmos-config` volume.

## Legacy CLI

The original single-file script is kept as `SAP2NMOS.py`:

```sh
python SAP2NMOS.py --registrar http://10.1.200.100:8010/x-nmos/registration/v1.3
```
