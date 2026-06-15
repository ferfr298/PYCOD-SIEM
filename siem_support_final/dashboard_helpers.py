"""
dashboard_helpers.py — Pure helper functions for the SIEM dashboard.
No Streamlit imports — safe to import in tests without a running Streamlit context.
"""

import configparser
import io
from pathlib import Path

import pandas as pd


MAX_UPLOAD_BYTES = 25 * 1024 * 1024


def resolve_path(base: Path, rel_or_abs: str) -> Path:
    """Return absolute Path; resolve relative paths against base."""
    # If the config already gives an absolute path, keep it as-is.
    p = Path(rel_or_abs)
    # Otherwise treat it as relative to the provided base folder.
    return p if p.is_absolute() else base / p


def load_config(config_path: str) -> configparser.ConfigParser:
    # Enable inline comments in INI files so values like "path ; note" still parse.
    cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    cfg.read(config_path, encoding="utf-8")
    return cfg


def read_csv_source(source) -> pd.DataFrame:
    """Read a CSV from a path-like object or raw bytes."""
    if isinstance(source, (bytes, bytearray)):
        # Uploaded files arrive as bytes; wrap in memory buffer for pandas.
        return pd.read_csv(io.BytesIO(source), low_memory=False)
    # File path or file-like object path is read directly.
    return pd.read_csv(source, low_memory=False)


def validate_upload(upload_name: str, upload_bytes: bytes, expected_ext: str) -> str:
    """Validate an uploaded file before it is written to disk."""
    if not upload_name:
        raise ValueError("Uploaded file must have a name.")

    # Drop any folder components to prevent path traversal via file names.
    safe_name = Path(upload_name).name
    if Path(safe_name).suffix.lower() != expected_ext.lower():
        raise ValueError(f"Expected a {expected_ext} file.")

    if not upload_bytes:
        raise ValueError("Uploaded file is empty.")

    if len(upload_bytes) > MAX_UPLOAD_BYTES:
        raise ValueError(
            f"Uploaded file is too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
        )

    return safe_name


def list_reports(reports_dir: Path) -> list:
    """Return sorted list of siem_report_*.csv paths (newest first)."""
    if not reports_dir.exists():
        return []
    # Reverse sort keeps newest timestamped report first in the UI.
    return sorted(reports_dir.glob("siem_report_*.csv"), reverse=True)


def safe_col(df: pd.DataFrame, *names: str):
    """Return the first column name present in df, else None."""
    # This lets dashboard logic work even when column names vary slightly.
    for name in names:
        if name in df.columns:
            return name
    return None


def compute_kpis(df: pd.DataFrame) -> dict:
    """Return a dict of KPI values derived from a report DataFrame."""
    # Find the available column names first so missing columns are handled safely.
    s_col  = safe_col(df, "safety")
    a_col  = safe_col(df, "anomaly")
    r_col  = safe_col(df, "rule_alert", "rulealert")
    sc_col = safe_col(df, "anomaly_score")

    total   = len(df)
    susp    = int((df[s_col] == "suspicious").sum()) if s_col else None
    anomaly = int((df[a_col] == -1).sum())           if a_col else None
    alerts  = int(df[r_col].sum())                   if r_col else None
    worst   = float(df[sc_col].min())                if sc_col else None

    return {
        "total": total,
        "suspicious": susp,
        "anomalies": anomaly,
        "rule_alerts": alerts,
        "worst_anomaly_score": worst,
        "safety_col": s_col,
        "anomaly_col": a_col,
        "rule_col": r_col,
        "score_col": sc_col,
    }


def build_grouped(df: pd.DataFrame, group_col: str, kpis: dict):
    """
    Group df by group_col and return a summary DataFrame.
    Returns None if group_col is not in df.
    """
    if group_col not in df.columns:
        return None

    # Build aggregation rules dynamically based on which KPI columns exist.
    agg: dict = {"total_events": (group_col, "count")}
    if kpis["safety_col"]:
        agg["suspicious_events"] = (kpis["safety_col"], lambda s: (s == "suspicious").sum())
    if kpis["anomaly_col"]:
        agg["anomaly_events"] = (kpis["anomaly_col"], lambda s: (s == -1).sum())
    if kpis["rule_col"]:
        agg["rule_alert_events"] = (kpis["rule_col"], "sum")
    if kpis["score_col"]:
        agg["worst_anomaly_score"] = (kpis["score_col"], "min")

    grouped = df.groupby(group_col).agg(**agg).reset_index()
    grouped = grouped.sort_values("total_events", ascending=False)
    return grouped


def get_event_counts(df: pd.DataFrame, col: str, top_n: int = 10) -> pd.DataFrame:
    """
    Return a DataFrame of nonneg event counts for col (value_counts, top_n).
    Always uses row counts — never anomaly scores or signed values.
    Returns empty DataFrame if col not in df.
    """
    if col not in df.columns:
        return pd.DataFrame(columns=[col, "event_count"])
    # value_counts gives frequency of each category (true event counts).
    counts = (
        df[col]
        .dropna()
        .astype(str)
        .value_counts()
        .head(top_n)
        .reset_index()
    )
    counts.columns = [col, "event_count"]
    # Guarantee nonneg (should always be the case for value_counts, but be explicit)
    counts["event_count"] = counts["event_count"].clip(lower=0)
    return counts
