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
"""

import configparser
from pathlib import Path

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
            try:
                import altair as alt
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
            except ImportError:
                st.bar_chart(safety_counts.set_index("safety"))
        else:
            st.info("Column `safety` not in this report.")

    # Bar: top source IPs
    with chart_cols[1]:
        ip_col = safe_col(view_df, "source_ip")
        if ip_col:
            st.subheader("Top Source IPs")
            top_ips = view_df[ip_col].value_counts().head(10).reset_index()
            top_ips.columns = ["source_ip", "count"]
            st.bar_chart(top_ips.set_index("source_ip"))
        else:
            st.info("Column `source_ip` not in this report.")

    chart_cols2 = st.columns(2)

    with chart_cols2[0]:
        if "country" in view_df.columns:
            st.subheader("Top Countries")
            top_countries = view_df["country"].value_counts().head(10).reset_index()
            top_countries.columns = ["country", "count"]
            st.bar_chart(top_countries.set_index("country"))
        else:
            st.info("Column `country` not in this report.")

    with chart_cols2[1]:
        user_col = safe_col(view_df, "user")
        if user_col:
            st.subheader("Top Users")
            top_users = view_df[user_col].value_counts().head(10).reset_index()
            top_users.columns = ["user", "count"]
            st.bar_chart(top_users.set_index("user"))
        else:
            st.info("Column `user` not in this report.")

    if "source_file" in view_df.columns:
        st.subheader("Events by Source File")
        sf_counts = view_df["source_file"].value_counts().reset_index()
        sf_counts.columns = ["source_file", "count"]
        st.bar_chart(sf_counts.set_index("source_file"))

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
                hour_counts = alert_df["hour"].value_counts().sort_index()
                st.bar_chart(hour_counts)
    else:
        st.info("Column `rule_alert` not found in this report.")

with tab3:
    st.subheader("Anomalies (Isolation Forest)")
    if kpis["anomaly_col"]:
        anom_df = view_df[view_df[kpis["anomaly_col"]] == -1].copy()
        if kpis["score_col"]:
            anom_df = anom_df.sort_values(kpis["score_col"], ascending=True)
        st.caption(f"{len(anom_df):,} anomalous events")
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
