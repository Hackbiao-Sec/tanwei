@echo off
rem Double-click to start the local recon backend and open the console.
cd /d "%~dp0"
start "arlx backend" powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\run-server.ps1"
timeout /t 8 >nul
start "" "http://127.0.0.1:5399/"
