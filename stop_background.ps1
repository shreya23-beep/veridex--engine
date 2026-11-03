Write-Host "=====================================================================" -ForegroundColor Red
Write-Host "   VERIDEX AI - STOPPING BACKGROUND SERVICES" -ForegroundColor Red
Write-Host "=====================================================================" -ForegroundColor Red
Write-Host ""
Write-Host "[*] Terminating background VeriDex overlay and web services..." -ForegroundColor Yellow
Get-Process pythonw, python -ErrorAction SilentlyContinue | Where-Object { 
    $_.Path -like "*Python314*" -or $_.CommandLine -like "*veridex*" -or $_.CommandLine -like "*run_floating*" -or $_.CommandLine -like "*run_web*"
} | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "[OK] All VeriDex AI background processes terminated." -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Red
