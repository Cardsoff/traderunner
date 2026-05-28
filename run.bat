@echo off
title Crypto Trading Planner

echo ============================================================
echo   Crypto Trading Planner - launching
echo ============================================================
echo.

cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found in PATH.
    echo Install Python 3.10+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [setup] Creating virtual environment...
    python -m venv .venv
    echo [setup] Installing dependencies...
    .venv\Scripts\python.exe -m pip install --upgrade pip
    .venv\Scripts\python.exe -m pip install -r requirements.txt
)

start "" cmd /c "timeout /t 2 >nul && start http://localhost:5000"

.venv\Scripts\python.exe app.py

pause
