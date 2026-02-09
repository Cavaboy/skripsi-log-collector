@echo off
REM Script untuk menjalankan Live Log Collector dan Streamlit Dashboard di VM Windows

echo =========================================
echo Network RCA System - VM Setup
echo =========================================
echo.

REM Check if live_log_collector.py exists
if not exist "live_log_collector.py" (
    echo ERROR: live_log_collector.py not found!
    echo Please run this script from the project root directory.
    pause
    exit /b 1
)

if not exist "dashboard.py" (
    echo ERROR: dashboard.py not found!
    echo Please run this script from the project root directory.
    pause
    exit /b 1
)

echo Starting background processes...
echo.

REM Start Live Log Collector di background
echo [1] Starting Live Log Collector (live_log_collector.py)
start "Live Log Collector" python live_log_collector.py
timeout /t 2 /nobreak

REM Start Streamlit Dashboard
echo [2] Starting Streamlit Dashboard (dashboard.py)
echo Streamlit will open at: http://localhost:8501
echo.
echo To access from Host, use: http://^<VM-IP^>:8501
echo.
python -m streamlit run dashboard.py

REM If streamlit closes, keep the window open for debugging
pause
