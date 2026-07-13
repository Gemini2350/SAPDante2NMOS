@echo off
rem Build SAP-2-NMOS.exe for Windows. Requires: pip install pyinstaller
cd /d "%~dp0"
pyinstaller --noconfirm --clean --windowed ^
  --name "SAP-2-NMOS" ^
  --add-data "sap2nmos/ui;sap2nmos/ui" ^
  app.py
echo Done: dist\SAP-2-NMOS\SAP-2-NMOS.exe
