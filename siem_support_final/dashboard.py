"""
dashboard.py — SIEM Support: Streamlit dashboard
==================================================
Reads siem_report_*.csv files directly from the ML project's reports/
directory. Displays KPI cards, charts, grouped incident views, filters,
and a full report explorer.

Run:
    streamlit run dashboard.py

The default config path is config/sources.ini (resolved relative to this
script's directory). You can override it in the sidebar.

QoL additions (v2):
  - "Run fetcher + ML from folder" sidebar control with text-input for source
    folder. Creates a temporary config, runs fetcher.py then runner.py
    --skip-fetch, and refreshes the report list.
  - Bar chart label-angle selector (Horizontal / 45° / Vertical) applied via
    Altair for charts with long category labels.
  - Category charts (country / user / IP / source_file) use event counts
    (value_counts) — never anomaly scores or signed values.
  - anomaly_score shown separately and clearly labelled.
"""

import configparser
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from dashboard_helpers import (
    resolve_path,
    load_config,
    list_reports,
    safe_col,
    compute_kpis,
    build_grouped,
)

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SIEM ML Dashboard",
    page_icon="\U0001f512",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Sidebar — configuration
# ---------------------------------------------------------------------------
st.sidebar.title("SIEM ML Dashboard")
st.sidebar.markdown("---")

default_config = str(Path(__file__).parent / "config" / "sources.ini")
config_path_input = st.sidebar.text_input(
    "sources.ini path",
    value=default_config,
    help="Absolute or relative path to sources.ini",
)

if not Path(config_path_input).exists():
    st.error(
        f"Config file not found: `{config_path_input}`\n\n"
        "Update the path in the sidebar or copy `config/sources.ini.example` "
        "to `config/sources.ini` and edit it."
    )
    st.stop()

cfg = load_config(config_path_input)

try:
    project_dir = Path(cfg.get("ml", "project_dir"))
    reports_dir = resolve_path(project_dir, cfg.get("ml", "reports_dir", fallback="reports"))
except (configparser.NoSectionError, configparser.NoOptionError) as exc:
    st.error(f"Config error: {exc}")
    st.stop()

st.sidebar.markdown(f"**ML project:** `{project_dir}`")
st.sidebar.markdown(f"**Reports dir:** `{reports_dir}`")
st.sidebar.markdown("---")

# ---------------------------------------------------------------------------
# Sidebar — Run fetcher + ML from folder
# ---------------------------------------------------------------------------
st.sidebar.subheader("Run Pipeline from Folder")

source_folder_input = st.sidebar.text_input(
    "Source log folder path",
    value="",
    help=(
        "Enter the absolute path to a folder containing *.log files. "
        "A temporary config will be created with this folder as the source. "
        "Fetcher then ML runner will be invoked."
    ),
    placeholder="e.g. /data/logs  or  C:\\logs",
)

run_clicked = st.sidebar.button("▶ Run fetcher + ML from folder")

if run_clicked:
    source_folder = source_folder_input.strip()

    if not source_folder:
        st.sidebar.error("Please enter a source folder path before running.")
    elif not Path(source_folder).exists():
        st.sidebar.error(f"Folder not found: `{source_folder}`")
    elif not Path(source_folder).is_dir():
        st.sidebar.error(f"Path is not a directory: `{source_folder}`")
    else:
        # Build a temporary config file identical to the real one but with
        # [source_dirs] paths overridden to the user-supplied folder.
        try:
            tmp_cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
            tmp_cfg.read(config_path_input, encoding="utf-8")

            if not tmp_cfg.has_section("source_dirs"):
                tmp_cfg.add_section("source_dirs")
            # Remove source_files so only source_dirs is active
            if tmp_cfg.has_section("source_files"):
                tmp_cfg.remove_section("source_files")
            tmp_cfg.set("source_dirs", "paths", source_folder)

            # Write to a temp file in the system temp directory
            tmp_cfg_fd, tmp_cfg_path = tempfile.mkstemp(
                prefix="siem_tmp_cfg_", suffix=".ini"
            )
            os.close(tmp_cfg_fd)
            with open(tmp_cfg_path, "w", encoding="utf-8") as fh:
                tmp_cfg.write(fh)

            support_dir = Path(__file__).parent
            fetcher_script = support_dir / "fetcher.py"
            runner_script  = support_dir / "runner.py"
            python_exe = sys.executable

            status_box = st.sidebar.status("Running pipeline…", expanded=True)

            with status_box:
                # Step 1: fetcher
                st.write("**Step 1/2 — Fetcher**")
                fetch_cmd = [
                    python_exe, str(fetcher_script),
                    "--config", tmp_cfg_path,
                ]
                fetch_result = subprocess.run(
                    fetch_cmd,
                    capture_output=True,
                    text=True,
                    cwd=str(support_dir),
                )
                if fetch_result.stdout:
                    with st.expander("Fetcher output", expanded=False):
                        st.code(fetch_result.stdout, language="text")
                if fetch_result.stderr:
                    with st.expander("Fetcher stderr", expanded=False):
                        st.code(fetch_result.stderr, language="text")
                if fetch_result.returncode != 0:
                    st.warning(
                        f"Fetcher exited with code {fetch_result.returncode} — "
                        "continuing to ML step."
                    )

                # Step 2: runner --skip-fetch
                st.write("**Step 2/2 — ML runner**")
                runner_cmd = [
                    python_exe, str(runner_script),
                    "--config", tmp_cfg_path,
                    "--skip-fetch",
                ]
                runner_result = subprocess.run(
                    runner_cmd,
                    capture_output=True,
                    text=True,
                    cwd=str(support_dir),
                )
                if runner_result.stdout:
                    with st.expander("Runner output", expanded=False):
                        st.code(runner_result.stdout, language="text")
                if runner_result.stderr:
                    with st.expander("Runner stderr", expanded=False):
                        st.code(runner_result.stderr, language="text")

                if runner_result.returncode != 0:
                    status_box.update(label="Pipeline failed — check output above.", state="error")
                else:
                    status_box.update(label="Pipeline complete!", state="complete")
                    st.cache_data.clear()

        except Exception as exc:
            st.sidebar.error(f"Pipeline error: {exc}")
        finally:
            try:
                os.unlink(tmp_cfg_path)
            except Exception:
                pass

st.sidebar.markdown("---")

# ---------------------------------------------------------------------------
# Sidebar — Bar chart label angle
# ---------------------------------------------------------------------------
label_angle_choice = st.sidebar.selectbox(
    "Bar chart label angle",
    options=["Horizontal", "45°", "Vertical"],
    index=1,
    help="Controls x-axis label rotation on category bar charts.",
)
_angle_map = {"Horizontal": 0, "45°": -45, "Vertical": -90}
label_angle = _angle_map[label_angle_choice]

st.sidebar.markdown("---")

# ---------------------------------------------------------------------------
# Report selector
# ---------------------------------------------------------------------------
reports = list_reports(reports_dir)

if not reports:
    st.warning(
        f"No `siem_report_*.csv` files found in `{reports_dir}`.\n\n"
        "Run the fetcher and ML pipeline first:\n"
        "```\npython runner.py --config config/sources.ini\n```"
    )
    st.stop()

report_names = [r.name for r in reports]
selected_name = st.sidebar.selectbox("Select report", report_names, index=0)
selected_path = reports_dir / selected_name

if st.sidebar.button("\U0001f504 Refresh"):
    st.cache_data.clear()

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------
@st.cache_data(ttl=30)
def _read_csv(path: str) -> pd.DataFrame:
    return pd.read_csv(path, low_memory=False)

try:
    df = _read_csv(str(selected_path))
except Exception as exc:
    st.error(f"Could not read report: {exc}")
    st.stop()

kpis = compute_kpis(df)

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.title("\U0001f512 SIEM ML Dashboard")
st.caption(f"Report: `{selected_path.name}`  •  {len(df):,} rows  •  `{selected_path}`")

# ---------------------------------------------------------------------------
# KPI cards
# ---------------------------------------------------------------------------
def _fmt(val) -> str:
    if val is None:
        return "N/A"
    if isinstance(val, float):
        return f"{val:.4f}"
    return f"{val:,}"

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Total Events",        _fmt(kpis["total"]))
k2.metric("Suspicious",          _fmt(kpis["suspicious"]))
k3.metric("Anomalies (IF)",      _fmt(kpis["anomalies"]))
k4.metric("Rule Alerts",         _fmt(kpis["rule_alerts"]))
k5.metric("Worst Anomaly Score", _fmt(kpis["worst_anomaly_score"]))

st.markdown("---")

# ---------------------------------------------------------------------------
# Filters (collapsed by default)
# ---------------------------------------------------------------------------
with st.expander("Filters", expanded=False):
    filter_cols = {}
    for col in ("source_file", "user", "safety", "country", "source_ip"):
        if col in df.columns:
            unique_vals = sorted(df[col].dropna().astype(str).unique().tolist())
            selected_vals = st.multiselect(f"Filter by `{col}`", unique_vals, default=[])
            filter_cols[col] = selected_vals

    filtered_df = df.copy()
    for col, vals in filter_cols.items():
        if vals:
            filtered_df = filtered_df[filtered_df[col].astype(str).isin(vals)]

    st.caption(f"{len(filtered_df):,} rows after filters")

view_df = filtered_df

# ---------------------------------------------------------------------------
# Chart helpers
# ---------------------------------------------------------------------------

def _altair_hbar(data: pd.DataFrame, x_col: str, y_col: str, title: str = "") -> alt.Chart:
    """Horizontal bar chart — avoids label-angle issues for long category names."""
    chart = (
        alt.Chart(data)
        .mark_bar()
        .encode(
            x=alt.X(f"{x_col}:Q", title=x_col),
            y=alt.Y(f"{y_col}:N", sort="-x", title=y_col),
            tooltip=[f"{y_col}:N", f"{x_col}:Q"],
        )
        .properties(height=max(200, len(data) * 28), title=title)
    )
    return chart


def _altair_vbar(
    data: pd.DataFrame, x_col: str, y_col: str, angle: int, title: str = ""
) -> alt.Chart:
    """Vertical bar chart with configurable label angle."""
    chart = (
        alt.Chart(data)
        .mark_bar()
        .encode(
            x=alt.X(
                f"{x_col}:N",
                sort="-y",
                title=x_col,
                axis=alt.Axis(labelAngle=angle, labelLimit=200),
            ),
            y=alt.Y(f"{y_col}:Q", title=y_col),
            tooltip=[f"{x_col}:N", f"{y_col}:Q"],
        )
        .properties(height=300, title=title)
    )
    return chart


def _count_chart(
    df_in: pd.DataFrame, cat_col: str, count_label: str = "count",
    top_n: int = 10, angle: int = -45, horizontal: bool = False,
) -> alt.Chart | None:
    """
    Build an Altair bar chart of event counts for cat_col.
    Uses value_counts() — always nonneg integer event counts, never anomaly scores.
    Returns None if cat_col not in df_in.
    """
    if cat_col not in df_in.columns:
        return None
    counts = (
        df_in[cat_col]
        .dropna()
        .astype(str)
        .value_counts()
        .head(top_n)
        .reset_index()
    )
    counts.columns = [cat_col, count_label]
    if horizontal or angle in (-90,):
        return _altair_hbar(counts, count_label, cat_col)
    return _altair_vbar(counts, cat_col, count_label, angle=angle)

# ---------------------------------------------------------------------------
# Charts section
# ---------------------------------------------------------------------------
with st.expander("Charts", expanded=True):
    chart_cols = st.columns(2)

    # Pie/donut: safety breakdown
    with chart_cols[0]:
        if kpis["safety_col"] and kpis["safety_col"] in view_df.columns:
            st.subheader("Safety Breakdown")
            safety_counts = view_df[kpis["safety_col"]].value_counts().reset_index()
            safety_counts.columns = ["safety", "count"]
            pie = (
                alt.Chart(safety_counts)
                .mark_arc(innerRadius=50)
                .encode(
                    theta=alt.Theta("count:Q"),
                    color=alt.Color(
                        "safety:N",
                        scale=alt.Scale(
                            domain=["safe", "suspicious"],
                            range=["#2ecc71", "#e74c3c"],
                        ),
                    ),
                    tooltip=["safety:N", "count:Q"],
                )
                .properties(height=220)
            )
            st.altair_chart(pie, use_container_width=True)
        else:
            st.info("Column `safety` not in this report.")

    # Bar: top source IPs (event counts, nonneg)
    with chart_cols[1]:
        ip_col = safe_col(view_df, "source_ip")
        if ip_col:
            st.subheader("Top Source IPs (event count)")
            chart = _count_chart(view_df, ip_col, count_label="event_count", angle=label_angle)
            if chart:
                st.altair_chart(chart, use_container_width=True)
        else:
            st.info("Column `source_ip` not in this report.")

    chart_cols2 = st.columns(2)

    # Top Countries — event counts (nonneg), NOT anomaly scores
    with chart_cols2[0]:
        if "country" in view_df.columns:
            st.subheader("Top Countries (event count)")
            chart = _count_chart(view_df, "country", count_label="event_count", angle=label_angle)
            if chart:
                st.altair_chart(chart, use_container_width=True)
        else:
            st.info("Column `country` not in this report.")

    # Top Users — event counts
    with chart_cols2[1]:
        user_col = safe_col(view_df, "user")
        if user_col:
            st.subheader("Top Users (event count)")
            chart = _count_chart(view_df, user_col, count_label="event_count", angle=label_angle)
            if chart:
                st.altair_chart(chart, use_container_width=True)
        else:
            st.info("Column `user` not in this report.")

    # Events by Source File — event counts
    if "source_file" in view_df.columns:
        st.subheader("Events by Source File")
        chart = _count_chart(
            view_df, "source_file", count_label="event_count",
            angle=label_angle, top_n=20,
        )
        if chart:
            st.altair_chart(chart, use_container_width=True)

    # Anomaly score distribution — labelled clearly as a score, separate chart
    score_col = kpis.get("score_col")
    if score_col and score_col in view_df.columns:
        st.subheader("Anomaly Score Distribution (score, not event count)")
        st.caption(
            "Lower (more negative) scores indicate stronger anomalies from Isolation Forest. "
            "This is NOT an event count."
        )
        score_hist_data = view_df[[score_col]].dropna().rename(columns={score_col: "anomaly_score"})
        hist = (
            alt.Chart(score_hist_data)
            .mark_bar(color="#e67e22")
            .encode(
                x=alt.X(
                    "anomaly_score:Q",
                    bin=alt.Bin(maxbins=40),
                    title="Anomaly Score (Isolation Forest)",
                ),
                y=alt.Y("count():Q", title="Number of events"),
                tooltip=[
                    alt.Tooltip("anomaly_score:Q", bin=True, title="Score range"),
                    alt.Tooltip("count():Q", title="Events"),
                ],
            )
            .properties(height=220, title="Anomaly Score Distribution (signed float; negative = more anomalous)")
        )
        st.altair_chart(hist, use_container_width=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs(
    ["Suspicious Events", "Rule Alerts", "Anomalies", "Grouped Incidents", "Full Report"]
)

with tab1:
    st.subheader("Suspicious Events")
    if kpis["safety_col"]:
        susp_df = view_df[view_df[kpis["safety_col"]] == "suspicious"]
        st.caption(f"{len(susp_df):,} suspicious events")
        if susp_df.empty:
            st.info("No suspicious events in this report (with current filters).")
        else:
            st.dataframe(susp_df, use_container_width=True, hide_index=True)
    else:
        st.info("Column `safety` not found in this report.")
        st.dataframe(view_df, use_container_width=True, hide_index=True)

with tab2:
    st.subheader("Rule Alerts")
    if kpis["rule_col"]:
        alert_df = view_df[view_df[kpis["rule_col"]] == 1]
        st.caption(f"{len(alert_df):,} rule alerts")
        if alert_df.empty:
            st.info("No rule alerts in this report (with current filters).")
        else:
            st.dataframe(alert_df, use_container_width=True, hide_index=True)
            if "hour" in alert_df.columns:
                st.subheader("Alerts by Hour")
                hour_counts = alert_df["hour"].value_counts().sort_index().reset_index()
                hour_counts.columns = ["hour", "count"]
                hour_chart = (
                    alt.Chart(hour_counts)
                    .mark_bar()
                    .encode(
                        x=alt.X("hour:O", title="Hour"),
                        y=alt.Y("count:Q", title="Alert count"),
                        tooltip=["hour:O", "count:Q"],
                    )
                    .properties(height=220)
                )
                st.altair_chart(hour_chart, use_container_width=True)
    else:
        st.info("Column `rule_alert` not found in this report.")

with tab3:
    st.subheader("Anomalies (Isolation Forest)")
    if kpis["anomaly_col"]:
        anom_df = view_df[view_df[kpis["anomaly_col"]] == -1].copy()
        if kpis["score_col"]:
            anom_df = anom_df.sort_values(kpis["score_col"], ascending=True)
        st.caption(
            f"{len(anom_df):,} anomalous events  "
            f"(anomaly_score is a signed float — more negative = more anomalous)"
        )
        if anom_df.empty:
            st.info("No anomalies in this report (with current filters).")
        else:
            st.dataframe(anom_df, use_container_width=True, hide_index=True)
    else:
        st.info("Column `anomaly` not found in this report.")

with tab4:
    st.subheader("Grouped Incidents")
    group_by = st.selectbox(
        "Group by", ["source_ip", "user", "country"], key="group_select"
    )
    grouped = build_grouped(view_df, group_by, kpis)
    if grouped is None:
        st.info(f"Column `{group_by}` not found in this report.")
    elif grouped.empty:
        st.info("No data to group.")
    else:
        st.caption(f"{len(grouped):,} unique {group_by} values")
        st.dataframe(grouped, use_container_width=True, hide_index=True)

with tab5:
    st.subheader("Full Report Viewer")
    search_term = st.text_input("Search (case-insensitive, any column)", "")
    display_df = view_df
    if search_term:
        mask = display_df.apply(
            lambda col: col.astype(str).str.contains(search_term, case=False, na=False)
        ).any(axis=1)
        display_df = display_df[mask]
        st.caption(f"{len(display_df):,} rows match '{search_term}'")
    st.dataframe(display_df, use_container_width=True, hide_index=True)

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown("---")
st.caption(
    "SIEM Support Dashboard \u00b7 Reads reports directly from `siem_ml.py` output \u00b7 "
    "ML code is never modified or imported."
)
