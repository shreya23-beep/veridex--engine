@echo off
title VeriDex AI - Background Protection Starter
color 0A
cls
echo =====================================================================
echo    VERIDEX AI - AUTONOMOUS ON-DEVICE SCAM PROTECTION ENGINE
echo =====================================================================
echo.
echo [*] Launching VeriDex in background mode...
echo [*] Spawning silent always-on-top window companion (pythonw.exe)...
echo [*] Starting local encrypted web dashboard (http://127.0.0.1:8484)...
echo.
wscript.exe "%~dp0run_background.vbs"
timeout /t 2 /nobreak >nul
echo [OK] VeriDex AI is now running seamlessly in the background!
echo.
echo Protection Features Active:
echo   - Universal Window Companion: Appears on every app window you open
echo   - Browser Inspector: Shows whether visited website URLs are safe
echo   - App Inspector: Identifies and verifies desktop applications
echo   - WhatsApp Scam Interceptor: Detects fake recharge / lottery links
echo   - Culprit IP Tracing: Automatically resolves server IP of scam sites
echo   - Cyber Helpline 1930: 1-click dial and cybercrime.gov.in complaint
echo.
echo To manage VeriDex:
echo   - Double-click the floating "V" badge to open the Web Dashboard
echo   - Right-click the floating "V" badge to configure or exit
echo   - Run stop_background.bat to stop the background engine anytime
echo =====================================================================
echo.
pause
