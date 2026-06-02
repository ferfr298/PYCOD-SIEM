@echo off
REM ============================================
REM SIEM ML Launcher Script
REM Click to run SIEM anomaly detection
REM ============================================

cd /d "%~dp0"

REM Activate virtual environment and run SIEM
call .venv\Scripts\activate.bat

echo.
echo ========================================
echo   SIEM Anomaly Detection System
echo ========================================
echo.
echo Processing logs from: logs\
echo Report will be saved to: reports\
echo.

python siem_ml.py --logs-only --top 3

echo.
echo ========================================
echo   Analysis Complete!
echo ========================================
echo.
pause
