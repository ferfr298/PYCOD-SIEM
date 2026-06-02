@echo off
REM =============================================================================
REM  setup_env.bat — Create and populate the Python virtual environment
REM  Run this once from the siem_support_final\ folder.
REM =============================================================================

setlocal

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

echo ============================================================
echo  SIEM Support — Environment Setup
echo ============================================================
echo.

REM Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found on PATH.
    echo         Install Python 3.10+ from https://www.python.org/
    pause
    exit /b 1
)

echo [1/3] Creating virtual environment in .venv ...
python -m venv .venv
if errorlevel 1 (
    echo [ERROR] Failed to create virtual environment.
    pause
    exit /b 1
)

echo [2/3] Installing ML dependencies from SIEM_ML-main\requirements.txt ...
if exist "..\SIEM_ML-main\requirements.txt" (
    .venv\Scripts\pip install -r "..\SIEM_ML-main\requirements.txt"
) else (
    echo [WARN] SIEM_ML-main\requirements.txt not found — skipping ML deps.
    echo        Ensure the ML project is at the path set in config\sources.ini.
)

echo [3/3] Installing support dependencies from requirements-support.txt ...
.venv\Scripts\pip install -r requirements-support.txt

if errorlevel 1 (
    echo [ERROR] pip install failed.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  Setup complete!
echo  Run run_full_siem_dashboard.bat to start the pipeline.
echo ============================================================
pause
