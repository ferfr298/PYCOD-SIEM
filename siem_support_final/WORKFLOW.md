# SIEM Support — Code Workflow

This document explains the step-by-step data flow through the support
project.  No ML code is modified; all interaction with `siem_ml.py` happens
through the filesystem and subprocess calls.

---

## Overview

```
[Real source logs]   ← directories listed in [source_dirs] scanned recursively
  any_name.log       ← filenames preserved; hash suffix added on collision
  subdir/other.log
        │
        │  Step 1 — fetcher.py reads new bytes (incremental, per-file checkpoint)
        ▼
[ML logs/ folder]
  SIEM_ML-main/logs/any_name.log
  SIEM_ML-main/logs/other.log
        │
        │  Step 2 — runner.py invokes siem_ml.py as subprocess
        ▼
  python siem_ml.py --logs-only   (cwd = SIEM_ML-main/)
        │
        │  Step 3 — siem_ml.py writes report
        ▼
  SIEM_ML-main/reports/siem_report_YYYYMMDD_HHMMSS.csv
        │
        │  Step 4 — dashboard.py reads CSV directly
        ▼
  Streamlit UI  (http://localhost:8501)
```

---

## Step 1 — Config loading

Both `fetcher.py` and `runner.py` start by reading `config/sources.ini`
using Python's built-in `configparser`.

Key values resolved:

| INI key | Purpose |
|---------|---------|
| `[ml] project_dir` | Absolute path to `SIEM_ML-main/` |
| `[ml] logs_dir` | Where `siem_ml.py` reads `*.log` files (default: `logs/` relative to `project_dir`) |
| `[ml] reports_dir` | Where `siem_ml.py` writes CSVs (default: `reports/` relative to `project_dir`) |
| `[ml] checkpoint_file` | Byte-offset store for incremental fetching (default: `memory/fetcher_checkpoints.json`) |
| `[source_dirs] paths` | Directories to scan for `*.log` files (recursive) |
| `[source_files] files` | Optional: exact source file paths |
| `[sources] syslog/ssh/web` | Legacy exact-file fallback (still supported) |

Relative paths in `[ml]` are resolved against `project_dir`.

---

## Step 2 — Fetcher discovers and reads source files

`fetcher.py` reads `[source_dirs]` from `sources.ini` and recursively
scans each listed directory for `*.log` files.  Exact paths from
`[source_files]` are also supported as a fallback.

For each discovered file:

1. **Existence check** — missing files are skipped with a warning.
2. **Loop prevention** — any file inside the ML `logs/` directory is
   automatically excluded before processing begins.
3. **Overlap guard** — if a resolved source path matches its destination,
   the run is aborted for that file.

---

## Step 3 — Checkpoint determines new bytes

`fetcher.py` maintains a JSON checkpoint file
(`memory/fetcher_checkpoints.json` by default) that stores per-source state:

```json
{
  "C:/MyApp/logs/auth.log": {
    "source_path": "C:/MyApp/logs/auth.log",
    "dest_path":   "C:/SIEM_ML-main/logs/auth.log",
    "offset":      18432,
    "identity":    "(2049, 123456789)",
    "last_run":    "2026-05-20T09:15:00+00:00"
  }
}
```

On each fetch run:

- **`offset`** — byte position from which reading starts.  Only bytes
  **after** the previous offset are read, so each line is fetched exactly
  once across multiple runs.
- **`identity`** — `(st_dev, st_ino)` on POSIX; `(st_dev, st_ctime_ns)`
  on Windows.  If the identity changes, the file has been rotated/replaced
  and the offset resets to 0.
- **Truncation detection** — if the current file size is smaller than the
  saved offset, the file was truncated (e.g., log rotation without rename);
  the offset resets to 0.

---

## Step 4 — Raw new lines appended into ML logs folder

New bytes are decoded as UTF-8 (with replacement for invalid sequences),
split into lines, and appended verbatim to the corresponding destination
file in `SIEM_ML-main/logs/`:

| Source type | Destination |
|-------------|-------------|
| `syslog` | `SIEM_ML-main/logs/syslog.log` |
| `ssh` | `SIEM_ML-main/logs/ssh.log` |
| `web` | `SIEM_ML-main/logs/web.log` |

No parsing or transformation is performed.  `siem_ml.py` receives the raw
lines exactly as they appear in the source files.

After writing, the checkpoint is updated with the new byte offset and saved
atomically (write to `.tmp`, then rename) to avoid corruption on crash.

---

## Step 5 — Runner invokes frozen siem_ml.py

`runner.py` calls `siem_ml.py` using `subprocess.run()` with:

```python
subprocess.run(
    [sys.executable, "siem_ml.py", "--logs-only", ...],
    cwd=project_dir,   # ← critical: siem_ml.py resolves all paths relative to cwd
)
```

Important details:
- **`cwd=project_dir`** is required because `siem_ml.py` resolves `logs/`
  and `reports/` relative to the directory containing the script, not the
  calling process's working directory.
- `siem_ml.py` is **never imported** — only run as a subprocess.  This
  avoids triggering any module-level side effects.
- Optional flags forwarded: `--top N` (print top N alerts to console),
  `--retrain` (force model retraining).

---

## Step 6 — ML processes logs and writes report CSV

`siem_ml.py` (unchanged) runs inside `SIEM_ML-main/`:

1. Discovers `*.log` files in `logs/` (because `--logs-only` is set).
2. Parses each log using its syslog/SSH or Apache format parsers.
3. Engineers features (hour, failed logins in last hour, country risk, etc.).
4. Runs the saved Isolation Forest model (or retrains if the model file is
   missing or `--retrain` is passed).
5. Applies the `rule_alert` deterministic rule (hour outside 8–20).
6. Assigns `safety = "suspicious"` where `rule_alert=1` OR `anomaly=-1`
   OR `country_risk >= 0.9`.
7. Writes `reports/siem_report_YYYYMMDD_HHMMSS.csv`.

`runner.py` scans `reports/` after the subprocess exits and prints the path
of the newest CSV.

---

## Step 7 — Dashboard reads CSV and displays it

`dashboard.py` (Streamlit) reads reports **directly** from `reports_dir`
using `pandas.read_csv()`.  No ML code is involved.

The dashboard:
- Lists all `siem_report_*.csv` files (newest first) in a sidebar selector.
- Computes KPIs from the raw DataFrame: total rows, suspicious count
  (`safety == "suspicious"`), anomaly count (`anomaly == -1`), rule alert
  count (`rule_alert == 1`).
- Provides multiselect filters on `source_file`, `user`, `safety`, `country`
  if those columns exist (gracefully skips missing columns).
- Displays tabs: Suspicious Events, Rule Alerts, Anomalies (sorted by
  `anomaly_score`), Full Report Viewer (with text search).
- Caches CSVs for 30 seconds; a Refresh button clears the cache.

---

## Error Handling Summary

| Scenario | Behaviour |
|----------|-----------|
| Source file missing | Skipped with warning; other sources proceed |
| Source == destination path | Aborted for that source; error printed |
| File truncated / rotated | Offset reset to 0; full file re-read |
| Checkpoint file corrupt | Fresh start (empty checkpoints) |
| ML project_dir missing | `runner.py` exits with error before running ML |
| `siem_ml.py` exits non-zero | `runner.py` exits with the same code |
| Missing CSV columns in dashboard | Gracefully skipped; affected KPI shows "N/A" |
| No reports in reports_dir | Dashboard shows a warning with instructions |
