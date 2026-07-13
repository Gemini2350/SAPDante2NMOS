#!/bin/sh
# Build SAP-2-NMOS.app for macOS. Requires: pip install pyinstaller
set -e
cd "$(dirname "$0")"
pyinstaller --noconfirm --clean --windowed \
  --name "SAP-2-NMOS" \
  --add-data "sap2nmos/ui:sap2nmos/ui" \
  app.py
echo "Done: dist/SAP-2-NMOS.app"
