Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "   VERIDEX AI - AUTONOMOUS ON-DEVICE SCAM PROTECTION ENGINE" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Launching VeriDex in background mode..." -ForegroundColor Yellow
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Start background processes using pythonw (windowless)
Start-Process -FilePath "pythonw.exe" -ArgumentList "run_floating_overlay.py" -WorkingDirectory $scriptDir
Start-Process -FilePath "pythonw.exe" -ArgumentList "run_web_dashboard.py" -WorkingDirectory $scriptDir

Start-Sleep -Seconds 2
Write-Host "[OK] VeriDex AI is now running seamlessly in the background!" -ForegroundColor Green
Write-Host ""
Write-Host "Protection Features Active:"
Write-Host "  - Universal Window Companion: Appears on every app window you open"
Write-Host "  - Browser Inspector: Shows whether visited website URLs are safe"
Write-Host "  - App Inspector: Identifies and verifies desktop applications"
Write-Host "  - WhatsApp Scam Interceptor: Detects fake recharge / lottery links"
Write-Host "  - Culprit IP Tracing: Automatically resolves server IP of scam sites"
Write-Host "  - Cyber Helpline 1930: 1-click dial and cybercrime.gov.in complaint"
Write-Host ""
Write-Host "To manage VeriDex:"
Write-Host "  - Double-click the floating 'V' badge to open the Web Dashboard"
Write-Host "  - Right-click the floating 'V' badge to configure or exit"
Write-Host "  - Run .\stop_background.bat or .\stop_background.ps1 to stop"
Write-Host "=====================================================================" -ForegroundColor Cyan
