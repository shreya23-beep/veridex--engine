Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "   VERIDEX AI - BACKGROUND SERVICE STATUS" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
$procs = Get-Process pythonw, python -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*Python314*" }
if ($procs) {
    Write-Host "[STATUS: ACTIVE] VeriDex AI is running in the background!" -ForegroundColor Green
    Write-Host "Active Processes:"
    $procs | Format-Table Id, ProcessName, WorkingSet64 -AutoSize
} else {
    Write-Host "[STATUS: STOPPED] VeriDex AI is not currently running." -ForegroundColor Yellow
    Write-Host "Run .\start_background.bat or .\start_background.ps1 to start real-time scam protection."
}
Write-Host "=====================================================================" -ForegroundColor Cyan
