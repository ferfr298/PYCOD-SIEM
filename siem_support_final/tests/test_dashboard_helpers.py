"""
tests/test_dashboard_helpers.py
================================
Tests for pure helper functions in dashboard_helpers.py.
No Streamlit dependency — safe to run with plain pytest.
"""

import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from dashboard_helpers import (  # noqa: E402
    safe_col,
    compute_kpis,
    build_grouped,
    list_reports,
    resolve_path,
    get_event_counts,
    read_csv_source,
    validate_upload,
    MAX_UPLOAD_BYTES,
)


# ---------------------------------------------------------------------------
# safe_col
# ---------------------------------------------------------------------------

def _df(*cols):
    return pd.DataFrame({c: [] for c in cols})


def test_safe_col_first_match():
    df = _df("anomaly_score", "safety", "anomaly")
    assert safe_col(df, "safety") == "safety"


def test_safe_col_fallback():
    df = _df("rulealert", "anomaly")
    assert safe_col(df, "rule_alert", "rulealert") == "rulealert"


def test_safe_col_none():
    df = _df("timestamp", "user")
    assert safe_col(df, "safety", "anomaly") is None


# ---------------------------------------------------------------------------
# compute_kpis
# ---------------------------------------------------------------------------

def _sample_df():
    return pd.DataFrame({
        "safety":        ["safe", "suspicious", "suspicious", "safe"],
        "anomaly":       [1, -1, -1, 1],
        "anomaly_score": [0.1, -0.3, -0.5, 0.2],
        "rule_alert":    [0, 1, 0, 1],
        "source_ip":     ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"],
        "user":          ["alice", "bob", "charlie", "dave"],
        "country":       ["US", "CN", "RU", "DE"],
    })


def test_compute_kpis_counts():
    df = _sample_df()
    kpis = compute_kpis(df)
    assert kpis["total"] == 4
    assert kpis["suspicious"] == 2
    assert kpis["anomalies"] == 2
    assert kpis["rule_alerts"] == 2


def test_compute_kpis_worst_score():
    df = _sample_df()
    kpis = compute_kpis(df)
    assert kpis["worst_anomaly_score"] == pytest.approx(-0.5)


def test_compute_kpis_missing_columns():
    df = pd.DataFrame({"timestamp": ["2026-01-01"]})
    kpis = compute_kpis(df)
    assert kpis["suspicious"] is None
    assert kpis["anomalies"] is None
    assert kpis["rule_alerts"] is None
    assert kpis["worst_anomaly_score"] is None
    assert kpis["total"] == 1


# ---------------------------------------------------------------------------
# build_grouped
# ---------------------------------------------------------------------------

def test_build_grouped_by_source_ip():
    df = _sample_df()
    kpis = compute_kpis(df)
    grouped = build_grouped(df, "source_ip", kpis)
    assert grouped is not None
    assert "total_events" in grouped.columns
    assert len(grouped) == 4  # 4 unique IPs


def test_build_grouped_suspicious_counts():
    df = _sample_df()
    extra = pd.DataFrame({
        "safety":        ["suspicious"],
        "anomaly":       [-1],
        "anomaly_score": [-0.6],
        "rule_alert":    [1],
        "source_ip":     ["2.2.2.2"],
        "user":          ["bob"],
        "country":       ["CN"],
    })
    df2 = pd.concat([df, extra], ignore_index=True)
    kpis = compute_kpis(df2)
    grouped = build_grouped(df2, "user", kpis)
    assert grouped is not None
    bob_row = grouped[grouped["user"] == "bob"].iloc[0]
    assert bob_row["total_events"] == 2
    assert bob_row["suspicious_events"] == 2


def test_build_grouped_missing_col():
    df = _sample_df()
    kpis = compute_kpis(df)
    result = build_grouped(df, "nonexistent_col", kpis)
    assert result is None


# ---------------------------------------------------------------------------
# list_reports
# ---------------------------------------------------------------------------

def test_list_reports_found(tmp_path):
    (tmp_path / "siem_report_20260601_120000.csv").write_text("a,b\n1,2\n")
    (tmp_path / "siem_report_20260602_080000.csv").write_text("a,b\n3,4\n")
    (tmp_path / "other.csv").write_text("x\n")
    found = list_reports(tmp_path)
    assert len(found) == 2
    assert all(f.name.startswith("siem_report_") for f in found)


def test_list_reports_empty_dir(tmp_path):
    assert list_reports(tmp_path) == []


def test_list_reports_missing_dir(tmp_path):
    missing = tmp_path / "does_not_exist"
    assert list_reports(missing) == []


# ---------------------------------------------------------------------------
# resolve_path
# ---------------------------------------------------------------------------

def test_resolve_path_absolute(tmp_path):
    result = resolve_path(Path("/base"), str(tmp_path))
    assert result == tmp_path


def test_resolve_path_relative():
    base = Path("/some/project")
    result = resolve_path(base, "reports")
    assert result == Path("/some/project/reports")


# ---------------------------------------------------------------------------
# get_event_counts  (new QoL helper — always nonneg event counts)
# ---------------------------------------------------------------------------

def test_get_event_counts_basic():
    df = _sample_df()
    counts = get_event_counts(df, "country", top_n=10)
    assert set(counts.columns) == {"country", "event_count"}
    # All counts must be nonneg integers
    assert (counts["event_count"] >= 0).all()
    # 4 unique countries
    assert len(counts) == 4


def test_get_event_counts_top_n():
    df = pd.DataFrame({"country": ["US"] * 5 + ["CN"] * 3 + ["DE"] * 1})
    counts = get_event_counts(df, "country", top_n=2)
    assert len(counts) == 2
    assert counts.iloc[0]["country"] == "US"
    assert counts.iloc[0]["event_count"] == 5


def test_get_event_counts_missing_col():
    df = _sample_df()
    counts = get_event_counts(df, "nonexistent_col")
    assert counts.empty
    assert list(counts.columns) == ["nonexistent_col", "event_count"]


def test_get_event_counts_nonneg_invariant():
    """event_count must always be nonneg, even if df has negative numeric values elsewhere."""
    df = pd.DataFrame({
        "country":       ["US", "CN", "US", "RU"],
        "anomaly_score": [-0.5, -0.3, -0.8, 0.1],  # negative scores — must not bleed into count
    })
    counts = get_event_counts(df, "country", top_n=10)
    assert (counts["event_count"] >= 0).all()
    us_count = counts.loc[counts["country"] == "US", "event_count"].iloc[0]
    assert us_count == 2


# ---------------------------------------------------------------------------
# read_csv_source
# ---------------------------------------------------------------------------

def test_read_csv_source_from_path(tmp_path):
    csv_path = tmp_path / "report.csv"
    csv_path.write_text("a,b\n1,2\n")

    df = read_csv_source(csv_path)

    assert list(df.columns) == ["a", "b"]
    assert df.iloc[0]["a"] == 1


def test_read_csv_source_from_bytes():
    df = read_csv_source(b"x,y\n3,4\n")

    assert list(df.columns) == ["x", "y"]
    assert df.iloc[0]["y"] == 4


# ---------------------------------------------------------------------------
# validate_upload
# ---------------------------------------------------------------------------

def test_validate_upload_accepts_csv_and_sanitizes_name():
    name = validate_upload("..\\evil\\report.csv", b"a,b\n1,2\n", ".csv")
    assert name == "report.csv"


def test_validate_upload_rejects_wrong_extension():
    with pytest.raises(ValueError, match=r"Expected a \.csv file"):
        validate_upload("report.log", b"a,b\n1,2\n", ".csv")


def test_validate_upload_rejects_empty_file():
    with pytest.raises(ValueError, match="empty"):
        validate_upload("report.csv", b"", ".csv")


def test_validate_upload_rejects_oversized_file():
    payload = b"x" * (MAX_UPLOAD_BYTES + 1)
    with pytest.raises(ValueError, match="too large"):
        validate_upload("report.csv", payload, ".csv")
