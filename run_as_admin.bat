@echo off
title Attack Surface Reduction - Admin Launcher
echo ========================================================
echo Starting Attack Surface Reduction with Admin Privileges...
echo ========================================================

:: Check for administrative rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator elevation...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/k cd /d \"\"%~dp0\"\" && python app.py' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
python app.py
pause
