#!/bin/sh
# Build Dante2NMOS.app for macOS. Requires: pip install pyinstaller
set -e
cd "$(dirname "$0")"
pyinstaller --noconfirm --clean --windowed \
  --name "Dante2NMOS" \
  --add-data "dante2nmos/ui:dante2nmos/ui" \
  app.py
echo "Done: dist/Dante2NMOS.app"
