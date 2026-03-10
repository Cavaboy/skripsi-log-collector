@echo off
echo =========================================
echo Starting Live Network RCA System
echo =========================================

set /p topology="Enter topology name (e.g., topologi_Simulasi) [Press Enter for default]: "
if "%topology%"=="" set topology=topologi_Simulasi

echo.
echo Using topology configuration: %topology%.json
echo.

REM 1. Start the Collector in a new independent window
echo [1/2] Launching Live Log Collector (%topology%.json)...
start "Live Log Collector" cmd /k "python live_log_collector.py --topology %topology%.json"

REM 2. Start the Dashboard in the current window
echo [2/2] Launching Streamlit Dashboard...
echo.
python -m streamlit run dashboard.py

pause
