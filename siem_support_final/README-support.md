# SIEM Support

This project sits **beside** an existing `SIEM_ML-main` folder and adds:

| File | Role |
|------|------|
| `fetcher.py` | Scans source directories for `*.log` files and incrementally copies new lines into the ML `logs/` folder |
| `runner.py` | Calls the fetcher, then invokes `siem_ml.py --logs-only` as a subprocess |
| `dashboard.py` | Streamlit dashboard — reads `reports/*.csv` directly, no ML code imported |

`siem_ml.py` is **never modified or imported**.

---

## Folder layout

Place `siem_support_final/` next to `SIEM_ML-main/`:

```
parent_folder/
├── SIEM_ML-main/          ← ML project (untouched)
│   ├── siem_ml.py
│   ├── logs/              ← fetcher writes here
│   ├── memory/
│   │   └── fetcher_checkpoints.json   ← created automatically
│   └── reports/           ← dashboard reads from here
│
└── siem_support_final/    ← this project
    ├── config/
    │   ├── sources.ini
    │   └── sources.ini.example
    ├── sample_source_logs/
    ├── tests/
    ├── fetcher.py
    ├── runner.py
    ├── dashboard.py
    ├── requirements-support.txt
    ├── setup_env.bat
    └── run_full_siem_dashboard.bat
```

---

## Quick start (Windows)

**1. Set up the virtual environment (once):**
```bat
setup_env.bat
```

**2. Edit `config/sources.ini`** — set `project_dir` to your `SIEM_ML-main` path and point `[source_dirs]` at your real log directories.

**3. Run the full pipeline:**
```bat
run_full_siem_dashboard.bat
```
This activates the venv, fetches new log lines, runs the ML engine (generating a report CSV), then starts the Streamlit dashboard at `http://localhost:8501`. The dashboard opens with whatever reports already exist; re-run this script (or run `fetcher.py` + `runner.py` manually) to ingest new log data and create a fresh report.

---

## Configure sources.ini

```ini
[ml]
project_dir     = ../SIEM_ML-main   ; path to SIEM_ML-main
logs_dir        = logs
reports_dir     = reports
checkpoint_file = memory/fetcher_checkpoints.json

[source_dirs]
paths = C:/MyApp/logs, D:/Server/logs   ; directories to scan recursively for *.log

# Optional: list exact files instead of scanning directories
# [source_files]
# files = C:/path/to/syslog.log, C:/path/to/auth.log
```

> **Do NOT** point `source_dirs` or `source_files` at the ML `logs/` folder — the fetcher reads from those paths and writes to `logs/`, so pointing them at the same place creates a loop. The fetcher will detect and skip any such paths automatically.

---

## Individual commands

```powershell
# Fetch new lines only
python fetcher.py --config config/sources.ini

# Dry-run (preview without writing)
python fetcher.py --config config/sources.ini --dry-run

# Fetch + ML run
python runner.py --config config/sources.ini

# ML run only (skip fetch)
python runner.py --config config/sources.ini --skip-fetch

# Force full re-read (reset checkpoints)
python runner.py --config config/sources.ini --reset-fetch

# Dashboard only
streamlit run dashboard.py

# Run tests
pytest tests/
```

---

## How the fetcher works

- Scans `[source_dirs]` directories (and sub-directories) recursively for `*.log` files.
- Preserves original filenames in `logs/`. If two source dirs contain a file with the same name, a short hash of the source directory is added before the extension (e.g. `auth_a3f9b1c2.log`) — the mapping is deterministic.
- Tracks a byte-offset checkpoint per source file in `memory/fetcher_checkpoints.json`. Only bytes written since the last run are copied (incremental).
- Detects file rotation (identity change) and truncation (file shrank) and resets the offset automatically.

---

## Dashboard features

- **KPI cards**: Total events, Suspicious, Anomalies (IF), Rule Alerts, Worst Anomaly Score.
- **Charts**: Safety breakdown (donut via Altair), Top IPs, Top Countries, Top Users, Events by Source File.
- **Tabs**: Suspicious Events, Rule Alerts, Anomalies (sorted by score), Grouped Incidents, Full Report.
- **Grouped Incidents**: Summarise by `source_ip`, `user`, or `country` with totals and worst scores.
- **Filters**: Multiselect on `source_file`, `user`, `safety`, `country`, `source_ip`.
- All missing columns are handled gracefully.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Config file not found` | Copy `sources.ini.example` → `sources.ini` and edit paths |
| `ML project_dir does not exist` | Update `[ml] project_dir` in `sources.ini` |
| No files found by fetcher | Check `[source_dirs] paths` — must be directories containing `*.log` files |
| Dashboard: "No reports found" | Run `runner.py` to generate a report first |
| OneDrive file locks | Move the project outside OneDrive, or pause sync |
| PowerShell execution policy | `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |

> **Note on near-live ingestion:** The pipeline does not poll for new logs automatically. Re-run `run_full_siem_dashboard.bat` (or `fetcher.py` + `runner.py` manually) whenever you want to ingest new log data. The dashboard can list and display any new report CSVs once they exist.

See `WORKFLOW.md` for the full data-flow description.
