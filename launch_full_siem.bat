@echo off
REM =============================================================================
REM  launch_full_siem.bat
REM  Root launcher for the complete SIEM pipeline:
REM    1) Ensure support virtual environment exists (or create it)
REM    2) Fetch logs
REM    3) Run ML analyzer
REM    4) Launch Streamlit dashboard
REM =============================================================================

setlocal
cd /d "%~dp0"

echo ============================================================
echo  SIEM Root Launcher
echo ============================================================
echo.

if not exist "siem_support_final\run_full_siem_dashboard.bat" (
    echo [ERROR] Missing launcher: siem_support_final\run_full_siem_dashboard.bat
    echo         Ensure this file exists inside siem_support_final\
    pause
    exit /b 1
)

if not exist "siem_support_final\.venv\Scripts\activate.bat" (
    echo [INFO] No support virtual environment found.
    echo [INFO] Running siem_support_final\setup_env.bat ...
    echo.
    call "siem_support_final\setup_env.bat"
    if errorlevel 1 (
        echo.
        echo [ERROR] Environment setup failed. Aborting.
        pause
        exit /b 1
    )
)

echo.
echo [INFO] Starting full SIEM pipeline and dashboard ...
echo.
call "siem_support_final\run_full_siem_dashboard.bat"

if errorlevel 1 (
    echo.
    echo [ERROR] Pipeline exited with an error.
    pause
    exit /b 1
)

exit /b 0