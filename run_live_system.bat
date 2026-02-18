@echo off
echo =========================================
echo Starting Live Network RCA System
echo =========================================

REM 1. Start the Collector in a new independent window
echo [1/2] Launching Live Log Collector...
start "Live Log Collector" cmd /k "python live_log_collector.py"

REM 2. Start the Dashboard in the current window
echo [2/2] Launching Streamlit Dashboard...
echo.
streamlit run dashboard.py

pause
