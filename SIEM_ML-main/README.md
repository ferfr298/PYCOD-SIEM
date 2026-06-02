# SIEM_ML

SIEM-oriented anomaly detection on authentication logs using Isolation Forest.

## What this project does
- Loads events from CSV or raw log files
- Supports syslog-style logs, SSH auth logs, and web access logs
- Builds behavior features from login activity
- Trains an Isolation Forest model
- Saves the trained model in `memory/` and reloads it on later runs
- Prints top anomalous events as SIEM-style alerts

## Input formats
1. CSV with columns:
timestamp,user,success,country_risk,source_ip
2. Raw .log files in one of these formats:
- Syslog lines (systemd/sshd/sudo style)
- SSH auth lines (failed/accepted login)
- Nginx/Apache-style access log lines

If you do not pass --input, the script checks:
1. auth_logs.csv in this folder
2. Any .log files in this folder
3. Any .log files inside logs/

## Requirements
- Windows with Python launcher (py) installed
- Python 3.10+ recommended

## Quick start (Windows)
1. Double-click setup_env.bat
2. Add your logs (CSV or .log files)
3. Double-click start_siem_ml.bat

Or run in terminal:

```powershell
cd SIEM_ML
.\setup_env.bat
.\start_siem_ml.bat
```

Use custom input paths:

```powershell
.\.venv\Scripts\python.exe siem_ml.py --input auth_logs.csv
.\.venv\Scripts\python.exe siem_ml.py --input ssh.log web.log syslog.log
.\.venv\Scripts\python.exe siem_ml.py --input logs
```

To force a fresh model and overwrite the saved copy in `memory/`:

```powershell
.\.venv\Scripts\python.exe siem_ml.py --input normal_syslog_1000.log --retrain
```

## Manual setup
```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe siem_ml.py
```

## Dependencies
See requirements.txt:
- numpy
- pandas
- scikit-learn

## Sharing this folder
You can share this folder as-is. The receiver only needs to:
1. Run setup_env.bat
2. Provide either auth_logs.csv or compatible .log files
3. Run start_siem_ml.bat

The .venv directory is excluded by .gitignore, so it can be recreated on any machine.
