@echo off
title VeriDex AI - Background Protection Status
color 0B
cls
echo =====================================================================
echo    VERIDEX AI - BACKGROUND SERVICE STATUS
echo =====================================================================
echo.
powershell -NoProfile -Command "
$procs = Get-Process pythonw, python -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*Python314*' }
if ($procs) {
    Write-Host '[STATUS: ACTIVE] VeriDex AI is running in the background!' -ForegroundColor Green
    Write-Host 'Active Processes:'
    $procs | Format-Table Id, ProcessName, WorkingSet64 -AutoSize
} else {
    Write-Host '[STATUS: STOPPED] VeriDex AI is not currently running.' -ForegroundColor Yellow
    Write-Host 'Run start_background.bat to start real-time scam protection.'
}
"
echo =====================================================================
echo.
pause
