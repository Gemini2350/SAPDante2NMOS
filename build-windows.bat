@echo off
rem Build Dante2NMOS.exe for Windows. Requires: pip install pyinstaller
cd /d "%~dp0"
pyinstaller --noconfirm --clean --windowed ^
  --name "Dante2NMOS" ^
  --add-data "dante2nmos/ui;dante2nmos/ui" ^
  app.py
echo Done: dist\Dante2NMOS\Dante2NMOS.exe
