#!/bin/sh
# Build SAPDante2NMOS.app for macOS. Requires: pip install pyinstaller
set -e
cd "$(dirname "$0")"
pyinstaller --noconfirm --clean --windowed \
  --name "SAPDante2NMOS" \
  --add-data "sapdante2nmos/ui:sapdante2nmos/ui" \
  app.py
echo "Done: dist/SAPDante2NMOS.app"
