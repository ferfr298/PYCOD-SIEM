import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import timedelta
from pathlib import Path
import sys
import argparse
import re
from datetime import datetime
from ipaddress import ip_address
import pickle

REQUIRED_COLUMNS = {"timestamp", "user", "success", "country_risk", "source_ip"}
MODEL_FILENAME = "siem_anomaly_model.pkl"

# EU member states + common European countries considered safe
EU_COUNTRIES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "ES", "SE",  # 27 EU members
    "NO", "CH", "IS",  # EFTA/European Free Trade Association
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run SIEM anomaly detection on CSV or raw log files."
    )
    parser.add_argument(
        "--input",
        "-i",
        nargs="+",
        help=(
            "Input file(s) or folder(s). Supports CSV and .log files. "
            "If omitted, the script tries auth_logs.csv, then .log files in this folder and logs/."
        ),
    )
    parser.add_argument(
        "--retrain",
        action="store_true",
        help="Force a fresh model training pass and overwrite the saved model in memory/.",
    )
    parser.add_argument(
        "--top",
        "-t",
        type=int,
        default=10,
        help="Number of top anomalies to print. Use 0 to print all anomalies.",
    )
    parser.add_argument(
        "--logs-only",
        action="store_true",
        help="When no --input is provided, only search the logs/ directory for .log files.",
    )
    return parser.parse_args()


def get_country_code_from_ip(ip_str: str) -> str:
    """
    Determine country code from IP prefix.
    Returns ISO country code (e.g., 'DE' for Germany, 'FR' for France).
    For unknown/private IPs, returns 'XX'.
    """
    try:
        ip = ip_address(ip_str)
    except ValueError:
        return "XX"

    # Private/local/unspecified IPs
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        return "LU"  # Treat as local/safe (Luxembourg-based org)

    # Tor-like exit range (currently treated as Germany in sample data)
    if ip_str.startswith("185.220."):
        return "DE"

    # Test/documentation ranges
    if ip_str.startswith("198.51.100.") or ip_str.startswith("203.0.113.") or ip_str.startswith("192.0.2."):
        return "XX"  # Test range, neutral

    # Cloud/public hosting: varied international (assume non-EU for conservative risk)
    if ip_str.startswith(("3.", "13.", "18.", "20.", "34.", "35.", "40.", "44.", "52.", "54.", "104.")):
        return "US"  # Representative of cloud providers

    # Carrier-grade NAT
    if ip_str.startswith("100."):
        return "XX"

    return "US"  # Default to non-EU for unknown public IPs


def ip_risk(ip_str: str) -> float:
    """
    Assign risk score based on IP geolocation and EU membership.
    EU countries: 0.20 (safe)
    Non-EU countries: 0.95 (unsafe)
    """
    try:
        ip = ip_address(ip_str)
    except ValueError:
        return 0.5

    if ip.is_multicast:
        return 0.4

    country_code = get_country_code_from_ip(ip_str)

    # EU countries are safe (includes local IPs treated as LU)
    if country_code in EU_COUNTRIES:
        return 0.2

    # Non-EU countries are unsafe
    if country_code != "XX":  # Known non-EU country
        return 0.95

    # Test/unknown ranges: moderate risk
    return 0.6


def country_from_ip(ip_str: str) -> str:
    """
    Return country name from IP, with EU status indicator.
    """
    try:
        ip = ip_address(ip_str)
    except ValueError:
        return "Unknown"

    country_code = get_country_code_from_ip(ip_str)

    # Map country code to name
    country_names = {
        "DE": "Germany (EU - Safe)",
        "FR": "France (EU - Safe)",
        "IT": "Italy (EU - Safe)",
        "ES": "Spain (EU - Safe)",
        "NL": "Netherlands (EU - Safe)",
        "BE": "Belgium (EU - Safe)",
        "AT": "Austria (EU - Safe)",
        "PL": "Poland (EU - Safe)",
        "LU": "Luxembourg (Local/EU - Safe)",
        "US": "United States (Non-EU - Unsafe)",
        "CN": "China (Non-EU - Unsafe)",
        "RU": "Russia (Non-EU - Unsafe)",
        "KP": "North Korea (Non-EU - Unsafe)",
        "XX": "Unknown/Test Range (Neutral)",
    }

    return country_names.get(country_code, f"Country {country_code} (Non-EU - Unsafe)")



def apply_dynamic_risk_boost(df_events: pd.DataFrame) -> pd.Series:
    dynamic_risk = df_events["base_country_risk"].astype(float).copy()

    dynamic_risk += (df_events["success"] == 0).astype(float) * 0.10
    dynamic_risk += (df_events["unusual_hour"] == 1).astype(float) * 0.08
    dynamic_risk += df_events["failed_last_hour"].clip(lower=0).astype(float) * 0.03
    dynamic_risk += (df_events["logins_last_hour"] >= 10).astype(float) * 0.05

    return dynamic_risk.clip(lower=0.0, upper=0.99)


def normalize_csv(path: Path) -> list[dict]:
    df_csv = pd.read_csv(path)
    missing_columns = REQUIRED_COLUMNS - set(df_csv.columns)
    if missing_columns:
        raise ValueError(f"{path.name}: missing required columns {sorted(missing_columns)}")

    df_csv["timestamp"] = pd.to_datetime(df_csv["timestamp"], errors="coerce")
    df_csv["success"] = pd.to_numeric(df_csv["success"], errors="coerce")
    df_csv["country_risk"] = pd.to_numeric(df_csv["country_risk"], errors="coerce")
    df_csv = df_csv.dropna(subset=["timestamp", "success", "country_risk", "user", "source_ip"])

    rows: list[dict] = []
    for _, row in df_csv.iterrows():
        source_ip = str(row["source_ip"])
        csv_country = str(row["country"]).strip() if "country" in df_csv.columns else ""
        rows.append(
            {
                "timestamp": row["timestamp"],
                "user": str(row["user"]),
                "success": int(float(row["success"]) > 0),
                "country_risk": float(row["country_risk"]),
                "source_ip": source_ip,
                "country": csv_country if csv_country else country_from_ip(source_ip),
            }
        )
    return rows


def parse_syslog_line(line: str, year: int) -> dict | None:
    base = re.match(
        r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<proc>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$",
        line,
    )
    if not base:
        return None

    try:
        timestamp = datetime.strptime(
            f"{year} {base.group('month')} {base.group('day')} {base.group('time')}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None

    msg = base.group("msg")
    user = "system"
    success = 1
    source_ip = "0.0.0.0"

    ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", msg)
    if ip_match:
        source_ip = ip_match.group(1)

    user_match = re.search(r"for\s+(?:invalid user\s+)?([\w.-]+)", msg)
    if user_match:
        user = user_match.group(1)

    msg_lower = msg.lower()
    if "failed password" in msg_lower or "authentication failure" in msg_lower or "illegal user" in msg_lower:
        success = 0
    elif "accepted password" in msg_lower or "accepted publickey" in msg_lower:
        success = 1
    elif "sudo:" in line.lower():
        sudo_user = re.search(r"sudo:\s+(\w+)", line)
        if sudo_user:
            user = sudo_user.group(1)
        success = 1

    return {
        "timestamp": timestamp,
        "user": user,
        "success": success,
        "country_risk": ip_risk(source_ip),
        "source_ip": source_ip,
        "country": country_from_ip(source_ip),
    }


def parse_web_line(line: str) -> dict | None:
    match = re.match(
        r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(?P<ts>[^\]]+)\]\s+"
        r"\"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+\"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)",
        line,
    )
    if not match:
        return None

    try:
        timestamp = datetime.strptime(match.group("ts"), "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except ValueError:
        return None

    ip = match.group("ip")
    path = match.group("path")
    status = int(match.group("status"))

    success = 1 if status < 400 else 0
    if path.lower() in {"/wp-login.php", "/xmlrpc.php", "/admin"}:
        success = 0

    return {
        "timestamp": timestamp,
        "user": path,
        "success": success,
        "country_risk": ip_risk(ip),
        "source_ip": ip,
        "country": country_from_ip(ip),
    }


def parse_log_file(path: Path) -> list[dict]:
    rows: list[dict] = []
    current_year = datetime.now().year

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue

            row = parse_web_line(line)
            if row is None:
                row = parse_syslog_line(line, current_year)

            if row is not None:
                rows.append(row)

    return rows


def discover_input_paths(args: argparse.Namespace, script_dir: Path) -> list[Path]:
    candidates: list[Path] = []

    if args.input:
        for user_input in args.input:
            input_path = Path(user_input)
            if not input_path.is_absolute():
                input_path = (script_dir / input_path).resolve()

            if input_path.is_dir():
                candidates.extend(sorted(input_path.glob("*.log")))
                candidates.extend(sorted(input_path.glob("*.csv")))
            elif input_path.is_file():
                candidates.append(input_path)
    else:
        logs_dir = script_dir / "logs"
        # if --logs-only requested, only check logs/ for .log files
        if args.logs_only:
            if logs_dir.exists():
                candidates.extend(sorted(logs_dir.glob("*.log")))
        else:
            csv_default = script_dir / "auth_logs.csv"
            if csv_default.exists():
                candidates.append(csv_default)
            candidates.extend(sorted(script_dir.glob("*.log")))
            if logs_dir.exists():
                candidates.extend(sorted(logs_dir.glob("*.log")))

    deduped: list[Path] = []
    seen = set()
    for item in candidates:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)

    return deduped


def load_events(paths: list[Path]) -> pd.DataFrame:
    all_rows: list[dict] = []
    for path in paths:
        suffix = path.suffix.lower()
        parsed_rows: list[dict] = []
        if suffix == ".csv":
            parsed_rows = normalize_csv(path)
        elif suffix == ".log":
            parsed_rows = parse_log_file(path)

        # attach source file information so we can report per-file counts later
        for r in parsed_rows:
            r["source_file"] = path.name
        all_rows.extend(parsed_rows)

    if not all_rows:
        raise ValueError("No valid events were parsed from the provided input files.")

    df_loaded = pd.DataFrame(all_rows)
    df_loaded["timestamp"] = pd.to_datetime(df_loaded["timestamp"], errors="coerce")
    df_loaded["success"] = pd.to_numeric(df_loaded["success"], errors="coerce")
    df_loaded["country_risk"] = pd.to_numeric(df_loaded["country_risk"], errors="coerce")
    df_loaded = df_loaded.dropna(subset=["timestamp", "success", "country_risk", "user", "source_ip"])

    if df_loaded.empty:
        raise ValueError("Input parsed, but no valid rows remained after normalization.")

    df_loaded["success"] = (df_loaded["success"] > 0).astype(int)
    df_loaded["base_country_risk"] = df_loaded["country_risk"].astype(float)
    return df_loaded


def get_model_path(script_dir: Path) -> Path:
    memory_dir = script_dir / "memory"
    memory_dir.mkdir(exist_ok=True)
    return memory_dir / MODEL_FILENAME


def save_model_artifact(model_path: Path, model: IsolationForest, feature_cols: list[str]) -> None:
    artifact = {
        "model": model,
        "feature_cols": feature_cols,
        "saved_at": datetime.now(),
    }
    with model_path.open("wb") as handle:
        pickle.dump(artifact, handle)


def load_model_artifact(model_path: Path) -> tuple[IsolationForest, list[str]]:
    with model_path.open("rb") as handle:
        artifact = pickle.load(handle)

    model = artifact.get("model")
    feature_cols = artifact.get("feature_cols")

    if not isinstance(feature_cols, list) or model is None:
        raise ValueError("Saved model file is invalid or incomplete.")

    return model, feature_cols


# ------------------------------
# 1. LOAD LOGS (CSV OR RAW .LOG)
# ------------------------------
args = parse_args()
script_directory = Path(__file__).resolve().parent
input_paths = discover_input_paths(args, script_directory)

if not input_paths:
    print("ERROR: no input logs found.")
    print("Provide a CSV or .log file with --input, or place files in this folder.")
    sys.exit(1)

print("Loading logs from:")
for path in input_paths:
    print(f"- {path}")

try:
    df = load_events(input_paths)
except ValueError as error:
    print(f"ERROR: {error}")
    sys.exit(1)

# ------------------------------
# 2. FEATURE ENGINEERING
# ------------------------------
print("Creating features for ML...")

# Extract hour of day (0-23)
df["hour"] = df["timestamp"].dt.hour

# Count failed logins per user in last 1 hour (rolling window)
# For simplicity, we sort by time and compute a simple feature:
df = df.sort_values("timestamp")
df["failed_last_hour"] = 0

# For each row, look back 1 hour for same user and count failures
for idx, row in df.iterrows():
    user = row["user"]
    current_ts = row["timestamp"]
    one_hour_ago = current_ts - timedelta(hours=1)
    # Filter dataset (inefficient but clear for learning)
    mask = (df["user"] == user) & (df["timestamp"] >= one_hour_ago) & (df["timestamp"] < current_ts) & (df["success"] == 0)
    df.at[idx, "failed_last_hour"] = mask.sum()

# Compute login frequency per user (number of attempts in last hour)
df["logins_last_hour"] = 0
for idx, row in df.iterrows():
    user = row["user"]
    current_ts = row["timestamp"]
    one_hour_ago = current_ts - timedelta(hours=1)
    mask = (df["user"] == user) & (df["timestamp"] >= one_hour_ago) & (df["timestamp"] < current_ts)
    df.at[idx, "logins_last_hour"] = mask.sum()

# Feature: is it unusual hour for this user? (simplified: users normally work 8-20, flag outside 8-20)
df["unusual_hour"] = ((df["hour"] < 8) | (df["hour"] >= 21)).astype(int)

# Rule-level alert: unusual hour combined with failed login or non-EU base risk
# This is a lightweight, deterministic rule to ensure critical events are surfaced.
df["rule_alert"] = (df["unusual_hour"] == 1).astype(int)

# Keep base risk tier and then apply behavior-based dynamic boost.
df["country_risk"] = apply_dynamic_risk_boost(df)

# Final feature set for model
feature_cols = ["success", "country_risk", "hour", "failed_last_hour", "logins_last_hour", "unusual_hour"]
X = df[feature_cols].values
model_path = get_model_path(script_directory)

# ------------------------------
# 3. TRAIN ANOMALY DETECTION MODEL
# ------------------------------
if model_path.exists() and not args.retrain:
    print(f"Loading saved model from: {model_path}")
    try:
        model, saved_feature_cols = load_model_artifact(model_path)
        if saved_feature_cols != feature_cols:
            print("Saved model feature layout differs from the current script, retraining instead.")
            raise ValueError("feature mismatch")
    except Exception as error:
        if str(error) != "feature mismatch":
            print(f"Could not load saved model: {error}")
        print("Training a new Isolation Forest model...")
        model = IsolationForest(contamination=0.01, random_state=42)
        model.fit(X)
        save_model_artifact(model_path, model, feature_cols)
        print(f"Saved model to: {model_path}")
else:
    if args.retrain and model_path.exists():
        print("Retrain requested, so a new model will be created and saved.")
    else:
        print("Training new Isolation Forest model...")

    # contamination = expected proportion of anomalies (1% here)
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X)
    save_model_artifact(model_path, model, feature_cols)
    print(f"Saved model to: {model_path}")

# Predict: -1 = anomaly, 1 = normal
df["anomaly"] = model.predict(X)
df["anomaly_score"] = model.decision_function(X)  # lower = more anomalous

# ------------------------------
# 4. OUTPUT ALERTS (SIEM-READY)
# ------------------------------
def print_risk_distribution(df_events: pd.DataFrame) -> None:
    print("\nRISK DISTRIBUTION (base country risk tiers):")
    for level in [0.20, 0.60, 0.75, 0.95]:
        count = int((df_events["base_country_risk"].round(2) == level).sum())
        print(f"- base {level:.2f}: {count} row(s)")

    print("\nRISK DISTRIBUTION (dynamic risk after behavior boost):")
    boosted = df_events["country_risk"].round(2).value_counts().sort_index()
    for risk_value, count in boosted.items():
        print(f"- boosted {float(risk_value):.2f}: {int(count)} row(s)")


def save_csv_report(df_events: pd.DataFrame, script_dir: Path) -> Path:
    reports_dir = script_dir / "reports"
    reports_dir.mkdir(exist_ok=True)

    report_name = f"siem_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    report_path = reports_dir / report_name

    export_df = df_events.copy()
    export_df["anomaly_label"] = export_df["anomaly"].map({-1: "anomaly", 1: "normal"}).fillna("unknown")
    # Populate a human-readable reason for anomalous or rule-alerted rows.
    # Previously this only filled for model anomalies (anomaly == -1).
    # Include `rule_alert` so deterministic alerts also get an explanation.
    export_df["anomaly_reason"] = export_df.apply(
        lambda r: explain_anomaly(r)
        if (int(r.get("anomaly", 1)) == -1 or int(r.get("rule_alert", 0)) == 1)
        else "",
        axis=1,
    )
    export_df["anomaly_score"] = export_df["anomaly_score"].round(2)

    preferred_columns = [
        "timestamp",
        "source_file",
        "user",
        "source_ip",
        "country",
        "success",
        "rule_alert",
        "base_country_risk",
        "country_risk",
        "hour",
        "failed_last_hour",
        "logins_last_hour",
        "unusual_hour",
        "anomaly",
        "anomaly_label",
        "anomaly_score",
        "anomaly_reason",
    ]
    selected_columns = [c for c in preferred_columns if c in export_df.columns]
    # Sort so rule alerts appear first, then anomalies by anomaly_score
    sort_keys = []
    if "rule_alert" in export_df.columns:
        sort_keys.append("rule_alert")
        export_df = export_df.sort_values(by=["rule_alert", "anomaly", "anomaly_score"], ascending=[False, True, True])
    else:
        export_df = export_df[selected_columns].sort_values(["anomaly", "anomaly_score"], ascending=[True, True])
    # Add a simple safety label: rule alerts and anomalies => suspicious, low EU risk => safe, otherwise suspicious
    if "base_country_risk" in export_df.columns:
        def determine_safety(row):
            # If flagged by rule or anomaly, it's suspicious
            if row.get("rule_alert", 0) == 1 or row.get("anomaly", 1) == -1:
                return "suspicious"
            # Otherwise check country risk
            return "safe" if float(row.get("base_country_risk", 0.95)) <= 0.25 else "suspicious"
        export_df["safety"] = export_df.apply(determine_safety, axis=1)
        # Ensure 'safety' is the last column in the exported CSV
        if "safety" not in selected_columns:
            selected_columns.append("safety")
        export_df = export_df[selected_columns]

    export_df.to_csv(report_path, index=False, encoding="utf-8")
    return report_path


def explain_anomaly(r: dict) -> str:
    reasons: list[str] = []
    if r.get("unusual_hour"):
        reasons.append("Unusual hour (outside typical 8-20)")
    if r.get("failed_last_hour", 0) > 0:
        reasons.append(f"{int(r['failed_last_hour'])} recent failed login(s) in last hour")
    if r.get("country_risk", 0) > 0.8:
        reasons.append("High country risk (non-EU location)")
    if r.get("success") == 0:
        reasons.append("Failed login")
    if r.get("logins_last_hour", 0) > 20:
        reasons.append("Very high login frequency")
    base_risk = float(r.get("base_country_risk", r.get("country_risk", 0.0)))
    boosted_risk = float(r.get("country_risk", 0.0))
    if boosted_risk - base_risk >= 0.05:
        reasons.append(f"Dynamic risk boost applied ({base_risk:.2f} -> {boosted_risk:.2f})")
    if not reasons:
        reasons.append("Outlier in feature space")
    return ", ".join(reasons)

print("\nPER-FILE PARSED COUNTS AND ANOMALY REPORT:\n")
print_risk_distribution(df)
print()
all_anomalies = df[df["anomaly"] == -1].sort_values("anomaly_score")
report_path = save_csv_report(df, script_directory)
print(f"CSV report written to: {report_path}\n")
for path in input_paths:
    name = path.name
    parsed_count = int(df[df["source_file"] == name].shape[0])
    file_anoms = all_anomalies[all_anomalies["source_file"] == name]
    print(f"File: {name} — parsed rows: {parsed_count} — anomalies: {len(file_anoms)}")
    if len(file_anoms) == 0:
        print("  No anomalies detected in this file.\n")
        continue

    for idx, row in file_anoms.iterrows():
        reason = explain_anomaly(row)
        print(f"  [ALERT] {row['timestamp']} | User: {row['user']} | Success: {row['success']} | "
              f"Failed last hour: {row['failed_last_hour']} | Country: {row['country']} | Country risk: {row['country_risk']:.2f} | "
              f"Unusual hour: {row['unusual_hour']}")
        print(f"         Reason: {reason}; Anomaly score = {row['anomaly_score']:.2f}\n")

if args.top == 0:
    print(f"Summary: Total events analyzed: {len(df)}")
    # Safety is added to the exported CSV (export_df). Read it back to get accurate counts.
    try:
        rpt = pd.read_csv(report_path)
        suspicious_count = int((rpt['safety'] == 'suspicious').sum()) if 'safety' in rpt.columns else 0
    except Exception:
        suspicious_count = int((df['safety'] == 'suspicious').sum()) if 'safety' in df.columns else 0
    print(f"Total suspicious flagged (rules+model): {suspicious_count}\n")
else:
    print(f"\nALERTS (top {args.top} most anomalous events):\n")
    top_overall = all_anomalies.head(args.top)
    for idx, row in top_overall.iterrows():
        reason = explain_anomaly(row)
        print(f"[ALERT] {row['timestamp']} | User: {row['user']} | Success: {row['success']} | "
              f"Failed last hour: {row['failed_last_hour']} | Country: {row['country']} | Country risk: {row['country_risk']:.2f} | "
              f"Unusual hour: {row['unusual_hour']}")
        print(f"        Reason: {reason}; Anomaly score = {row['anomaly_score']:.2f}\n")

# ------------------------------
# 5. SUMMARY
# ------------------------------
print("\nModel summary:")
print(f"Total events analyzed: {len(df)}")
suspicious_count = 0
try:
    rpt = pd.read_csv(report_path)
    suspicious_count = int((rpt['safety'] == 'suspicious').sum()) if 'safety' in rpt.columns else 0
    rule_alerts_count = int((rpt['rule_alert'] == 1).sum()) if 'rule_alert' in rpt.columns else 0
except Exception:
    suspicious_count = int((df['safety'] == 'suspicious').sum()) if 'safety' in df.columns else 0
    rule_alerts_count = int((df['rule_alert'] == 1).sum()) if 'rule_alert' in df.columns else 0
print(f"Total suspicious flagged (rules+model): {suspicious_count}")
print(f"Total model anomalies flagged: {int((df['anomaly'] == -1).sum())}")
print(f"Total rule alerts: {rule_alerts_count}")

print("\nDone. Anomaly detection completed using your input logs.")