@echo off
title VeriDex AI - Background Protection Stopper
color 0C
cls
echo =====================================================================
echo    VERIDEX AI - STOPPING BACKGROUND SERVICES
echo =====================================================================
echo.
echo [*] Terminating background VeriDex overlay and web services...
powershell -NoProfile -Command "Get-Process pythonw, python -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*Python314*' -or $_.CommandLine -like '*veridex*' -or $_.CommandLine -like '*run_floating*' -or $_.CommandLine -like '*run_web*' } | Stop-Process -Force -ErrorAction SilentlyContinue"
echo [OK] All VeriDex AI background processes terminated.
echo =====================================================================
echo.
pause
