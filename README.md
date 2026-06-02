# SIEM Project

This workspace contains two related parts:

- `SIEM_ML-main/` - the original SIEM anomaly detection project that reads authentication and log data, trains an Isolation Forest model, and writes reports.
- `siem_support_final/` - the support layer that fetches new log lines, runs the ML pipeline, and provides a Streamlit dashboard over the generated reports.

## What is included

- CSV and log ingestion for SIEM-style authentication data
- Incremental log fetching into the ML project `logs/` folder
- Batch runner for fetch + model execution
- Streamlit dashboard for report browsing and incident review

## Recommended repo contents

Commit the source code, docs, configuration templates, and tests. Keep generated files out of Git, especially:

- virtual environments such as `.venv/`
- Python caches such as `__pycache__/`
- generated reports under `SIEM_ML-main/reports/`
- the saved model and fetch checkpoints under `SIEM_ML-main/memory/`
- local support config in `siem_support_final/config/sources.ini`

## Quick start

### 1. Set up the support environment

```powershell
cd siem_support_final
setup_env.bat
```

### 2. Configure source paths

Copy `siem_support_final/config/sources.ini.example` to `siem_support_final/config/sources.ini` and update the paths for your machine.

### 3. Run the pipeline

```powershell
run_full_siem_dashboard.bat
```

## Project notes

- The ML project can also be run directly with `siem_ml.py` and the sample `auth_logs.csv` file.
- The support project is designed to sit beside `SIEM_ML-main/` and should not modify `siem_ml.py`.
- See `SIEM_ML-main/README.md` and `siem_support_final/README-support.md` for component-level details.