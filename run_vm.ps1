# Script untuk menjalankan Live Log Collector dan Streamlit Dashboard di VM Windows
# Run: powershell -ExecutionPolicy Bypass -File run_vm.ps1

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Network RCA System - VM Setup" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Check if files exist
if (-not (Test-Path "live_log_collector.py")) {
    Write-Host "ERROR: live_log_collector.py not found!" -ForegroundColor Red
    Write-Host "Please run this script from the project root directory." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

if (-not (Test-Path "dashboard.py")) {
    Write-Host "ERROR: dashboard.py not found!" -ForegroundColor Red
    Write-Host "Please run this script from the project root directory." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Starting background processes..." -ForegroundColor Green
Write-Host ""

# Get VM IP Address
$ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -ne "Loopback" } | Select-Object -First 1).IPAddress
Write-Host "VM IP Address: $ipAddress" -ForegroundColor Yellow
Write-Host ""

# Start Live Log Collector in background
Write-Host "[1] Starting Live Log Collector (live_log_collector.py)" -ForegroundColor Yellow
Start-Process python -ArgumentList "live_log_collector.py" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Streamlit Dashboard (this will stay in foreground)
Write-Host "[2] Starting Streamlit Dashboard (dashboard.py)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Streamlit will start at: http://localhost:8501" -ForegroundColor Green
Write-Host "To access from Host, use: http://$($ipAddress):8501" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop the dashboard (live collector will continue in background)" -ForegroundColor Cyan
Write-Host ""

python -m streamlit run dashboard.py
