@echo off
REM =============================================================================
REM  run_full_siem_dashboard.bat
REM  Full SIEM pipeline — one click:
REM    1. Activate the .venv virtual environment
REM    2. Run fetcher.py        (copy new log lines into ML logs/)
REM    3. Run runner.py         (ML engine — generates report CSV)
REM    4. Start Streamlit dashboard (keeps this window open)
REM
REM  Run setup_env.bat once before using this script.
REM =============================================================================

setlocal

REM --- Always run from the directory that contains this bat file ---------------
cd /d "%~dp0"

echo ============================================================
echo  SIEM Full Pipeline ^& Dashboard
echo ============================================================
echo.

REM --- Check for virtual environment ------------------------------------------
if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found.
    echo         Run setup_env.bat first to create it.
    pause
    exit /b 1
)

REM --- Activate virtual environment -------------------------------------------
echo [Step 0] Activating virtual environment ...
call .venv\Scripts\activate.bat
set "VENV_PYTHON=.venv\Scripts\python.exe"
if not exist "%VENV_PYTHON%" (
    echo [ERROR] Virtual environment python not found: %VENV_PYTHON%
    pause
    exit /b 1
)
echo.

REM --- Check for config file --------------------------------------------------
if not exist "config\sources.ini" (
    echo [ERROR] Config file not found: config\sources.ini
    echo         Copy config\sources.ini.example to config\sources.ini and edit it.
    pause
    exit /b 1
)

REM --- Step 1: Fetch new log lines --------------------------------------------
echo [Step 1] Fetching new log lines ...
"%VENV_PYTHON%" fetcher.py --config config\sources.ini
if errorlevel 1 (
    echo.
    echo [ERROR] Fetcher failed. Check the output above.
    pause
    exit /b 1
)
echo.

REM --- Step 2: Run ML pipeline ------------------------------------------------
echo [Step 2] Running ML engine via runner.py --skip-fetch ...
"%VENV_PYTHON%" runner.py --config config\sources.ini --skip-fetch
if errorlevel 1 (
    echo.
    echo [ERROR] ML run failed. Check the output above.
    pause
    exit /b 1
)
echo.

REM --- Step 3: Launch Streamlit dashboard -------------------------------------
echo [Step 3] Starting Streamlit dashboard ...
echo          Open http://localhost:8501 in your browser.
echo          Press Ctrl+C in this window to stop the dashboard.
echo.
"%VENV_PYTHON%" -m streamlit run dashboard.py

echo.
echo Dashboard stopped.
pause
