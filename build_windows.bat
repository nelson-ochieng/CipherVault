@echo off
py -m pip install -r requirements-build.txt
py -m PyInstaller --noconfirm --clean --onefile --windowed --name CipherVault app.py
if errorlevel 1 exit /b 1
echo Built dist\CipherVault.exe
