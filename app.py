#!/usr/bin/env python3
"""SAPDante2NMOS desktop app entry point."""

import argparse
import threading
import time

from sapdante2nmos.config import Config
from sapdante2nmos.engine import Engine
from sapdante2nmos.httpd import make_server


def main():
    parser = argparse.ArgumentParser(description="SAPDante2NMOS: SAP-to-NMOS senders + NMOS-to-Dante receivers")
    parser.add_argument("--registrar", help="NMOS Registration API URL (overrides saved config)")
    parser.add_argument("--headless", action="store_true", help="run without a window")
    parser.add_argument("--browser", action="store_true", help="open in the default browser instead of a native window")
    parser.add_argument("--port", type=int, help="HTTP port for UI and NMOS node API")
    args = parser.parse_args()

    config = Config.load()
    if args.registrar:
        config["registrar"] = args.registrar
        config.save()
    if args.port:
        config["http_port"] = args.port

    engine = Engine(config)
    server = make_server(engine, config)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    from sapdante2nmos.is12 import Is12Server
    is12 = Is12Server(engine, config)
    is12.start()

    engine.start()

    url = f"http://127.0.0.1:{config['http_port']}/ui/"
    print(f"UI: {url}")

    try:
        if args.headless:
            while True:
                time.sleep(1)
        elif args.browser:
            import webbrowser
            webbrowser.open(url)
            while True:
                time.sleep(1)
        else:
            try:
                import webview
            except ImportError:
                print("pywebview not installed, falling back to browser")
                import webbrowser
                webbrowser.open(url)
                while True:
                    time.sleep(1)
            webview.create_window("SAPDante2NMOS", url, width=1100, height=720,
                                  min_size=(760, 480))
            webview.start()
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        is12.stop()
        server.shutdown()


if __name__ == "__main__":
    main()
