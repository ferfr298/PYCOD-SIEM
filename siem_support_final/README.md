# SIEM Support (Minimal)

## What this tool is
A support layer around an existing SIEM_ML-main project.

## What it does
- Fetches new lines from source .log files into SIEM_ML-main/logs.
- Runs the existing ML pipeline (siem_ml.py) without modifying ML code.
- Shows results in a Streamlit dashboard.
- Allows dashboard upload of:
  - report .csv (view only)
  - raw .log (ingest + generate fresh report)

## How to run
1. From siem_support_final, run setup_env.bat (first time only).
2. Edit config/sources.ini for your paths.
3. Run one of:
   - run_full_siem_dashboard.bat
   - streamlit run dashboard.py

## Known bugs / limitations
- Existing test issue: tests/test_fetcher.py has one line-ending-related assertion that may fail on Windows in test_fetch_file_new_file.
- Large or very noisy uploaded logs can slow report generation.
- Project is often used inside OneDrive; file sync/locks can interfere while pipeline is writing.

## Disclaimer
- This project does not modify SIEM_ML-main/siem_ml.py.
- Uploaded files are treated as data, but you should still only use trusted files in production.
