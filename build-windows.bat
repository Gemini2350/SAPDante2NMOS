@echo off
rem Build SAPDante2NMOS.exe for Windows. Requires: pip install pyinstaller
cd /d "%~dp0"
pyinstaller --noconfirm --clean --windowed ^
  --name "SAPDante2NMOS" ^
  --add-data "sapdante2nmos/ui;sapdante2nmos/ui" ^
  app.py
echo Done: dist\SAPDante2NMOS\SAPDante2NMOS.exe
