"""
runner.py — SIEM Support: Orchestration runner
================================================
Calls fetcher.py to pull fresh log lines, then invokes siem_ml.py --logs-only
inside the ML project directory as a subprocess.
After the ML run it prints the path to the latest report CSV.

Usage:
    python runner.py [--config CONFIG] [--skip-fetch] [--reset-fetch]
                     [--top N] [--retrain] [--dry-run]

Options:
    --config CONFIG   Path to sources.ini  (default: config/sources.ini)
    --skip-fetch      Skip the fetch step; invoke ML directly.
    --reset-fetch     Pass --reset to fetcher so all source files are re-read
                      from the beginning before the ML run.
    --top N           Pass --top N to siem_ml.py (print top N alerts).
    --retrain         Pass --retrain to siem_ml.py (force model retraining).
    --dry-run         Show what would be executed without running anything.
"""

import argparse
import configparser
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve(base: Path, rel_or_abs: str) -> Path:
    # Normalize config paths so callers can use either absolute or relative values.
    p = Path(rel_or_abs)
    return p if p.is_absolute() else base / p


def _latest_report(reports_dir: Path):
    """Return the most recently modified siem_report_*.csv in reports_dir."""
    if not reports_dir.exists():
        return None
    # Sort by file modification time to find the freshest report output.
    candidates = sorted(
        reports_dir.glob("siem_report_*.csv"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    # Parse CLI flags so this script can be used in manual runs and .bat launchers.
    parser = argparse.ArgumentParser(
        description="Orchestrate fetcher → siem_ml.py and report the latest output."
    )
    parser.add_argument(
        "--config",
        default="config/sources.ini",
        help="Path to sources.ini  (default: config/sources.ini)",
    )
    parser.add_argument(
        "--skip-fetch",
        action="store_true",
        help="Skip the fetch step; run ML directly on whatever is in logs/.",
    )
    parser.add_argument(
        "--reset-fetch",
        action="store_true",
        help="Pass --reset to fetcher so source files are re-read from byte 0.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=None,
        metavar="N",
        help="Print the top N most anomalous events to the console.",
    )
    parser.add_argument(
        "--retrain",
        action="store_true",
        help="Force siem_ml.py to retrain the Isolation Forest model.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the commands that would be executed without running them.",
    )
    args = parser.parse_args(argv)

    # --- Load config --------------------------------------------------
    # Read the same config used by fetcher and dashboard for consistent paths.
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[error] Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    cfg.read(config_path, encoding="utf-8")

    project_dir = Path(cfg.get("ml", "project_dir"))
    reports_dir = _resolve(project_dir, cfg.get("ml", "reports_dir", fallback="reports"))

    print("=" * 60)
    print("SIEM Runner")
    print("=" * 60)
    print(f"  Config      : {config_path.resolve()}")
    print(f"  Project dir : {project_dir}")
    print(f"  Reports dir : {reports_dir}")
    if args.dry_run:
        print("  Mode        : DRY RUN")
    print()

    # --- Validate ML project directory --------------------------------
    # Fail fast if the ML project path is wrong to avoid confusing subprocess errors.
    ml_script = project_dir / "siem_ml.py"
    if not project_dir.exists():
        print(
            f"[error] ML project_dir does not exist: {project_dir}\n"
            "        Update [ml] project_dir in sources.ini.",
            file=sys.stderr,
        )
        sys.exit(1)
    if not ml_script.exists():
        print(
            f"[error] siem_ml.py not found in project_dir: {ml_script}\n"
            "        Check [ml] project_dir in sources.ini.",
            file=sys.stderr,
        )
        sys.exit(1)

    python_exe = sys.executable

    # ----------------------------------------------------------------
    # Step 1: Fetch
    # ----------------------------------------------------------------
    if args.skip_fetch:
        print("Step 1: Fetch — SKIPPED (--skip-fetch)")
    else:
        fetcher_script = Path(__file__).with_name("fetcher.py")
        if not fetcher_script.exists():
            print(
                f"[warn] fetcher.py not found at {fetcher_script} — skipping fetch step.",
                file=sys.stderr,
            )
        else:
            fetch_cmd = [python_exe, str(fetcher_script), "--config", str(config_path)]
            if args.reset_fetch:
                fetch_cmd.append("--reset")
            if args.dry_run:
                fetch_cmd.append("--dry-run")

            print("Step 1: Fetch")
            print(f"  Command: {' '.join(fetch_cmd)}")
            if not args.dry_run:
                # Fetcher non-zero is treated as warning; ML may still run on existing logs.
                result = subprocess.run(fetch_cmd)
                if result.returncode != 0:
                    print(
                        "[warn] Fetcher exited with non-zero status — continuing to ML run.",
                        file=sys.stderr,
                    )
    print()

    # ----------------------------------------------------------------
    # Step 2: Run siem_ml.py
    # ----------------------------------------------------------------
    ml_cmd = [python_exe, "siem_ml.py", "--logs-only"]
    if args.top is not None:
        ml_cmd += ["--top", str(args.top)]
    if args.retrain:
        ml_cmd.append("--retrain")

    print("Step 2: Run siem_ml.py")
    print(f"  Command : {' '.join(ml_cmd)}")
    print(f"  CWD     : {project_dir}")

    if not args.dry_run:
        # Run from project_dir so siem_ml.py resolves logs/reports relative to itself.
        result = subprocess.run(ml_cmd, cwd=str(project_dir))
        ml_exit = result.returncode
        if ml_exit != 0:
            print(f"\n[error] siem_ml.py exited with code {ml_exit}.", file=sys.stderr)
            sys.exit(ml_exit)
    print()

    # ----------------------------------------------------------------
    # Step 3: Report latest output
    # ----------------------------------------------------------------
    print("Step 3: Latest report")
    if args.dry_run:
        print("  (dry run — no report written)")
    else:
        latest = _latest_report(reports_dir)
        if latest:
            print(f"  Latest report : {latest.resolve()}")
        else:
            print(f"  [warn] No siem_report_*.csv found in {reports_dir}")

    print()
    print("=" * 60)
    print("Runner complete.")


if __name__ == "__main__":
    main()
