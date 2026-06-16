"""
fetcher.py — SIEM Support: Incremental log fetcher
=====================================================
Scans one or more source directories (and sub-directories) for *.log files
and incrementally copies new lines into the ML project's logs/ folder.
Exact source file paths are also supported as an optional fallback.

Uses only the Python standard library.

Usage:
    python fetcher.py [--config CONFIG] [--reset] [--dry-run]

Options:
    --config CONFIG   Path to sources.ini  (default: config/sources.ini)
    --reset           Clear all checkpoints and re-read every source file
                      from the beginning on this run.
    --dry-run         Read new lines but do NOT write anything (preview mode).
"""

import argparse
import configparser
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve(base: Path, rel_or_abs: str) -> Path:
    """Return an absolute Path; resolve relative paths against base."""
    # Keep absolute paths unchanged; resolve relative values against project base.
    p = Path(rel_or_abs)
    return p if p.is_absolute() else base / p


def _safe_dest_name(source_path: Path, dest_dir: Path) -> Path:
    """
    Return a destination path for source_path inside dest_dir.

    Preserves the original filename.  If a collision would occur (two source
    files with the same name from different directories), a short hash of the
    source's parent path is inserted before the extension so the names remain
    deterministic and unique.

    Examples:
        /var/log/app/auth.log   → dest_dir/auth.log          (no collision)
        /opt/app/auth.log       → dest_dir/auth_a3f9b1c2.log (collision)
    """
    # Keep destination names deterministic so the same source always maps the same way.
    stem = source_path.stem
    suffix = source_path.suffix
    candidate = dest_dir / source_path.name

    # Build a short hash of the source parent directory (8 hex chars)
    parent_hash = hashlib.sha256(str(source_path.parent).encode()).hexdigest()[:8]
    hashed_name = dest_dir / f"{stem}_{parent_hash}{suffix}"

    # If the candidate isn't claimed yet, use the plain name.
    # We track claimed names in a module-level registry per run.
    registry = _safe_dest_name._registry  # type: ignore[attr-defined]
    src_str = str(source_path.resolve())

    if candidate not in registry or registry[candidate] == src_str:
        registry[candidate] = src_str
        return candidate

    # Collision: use hashed name
    registry[hashed_name] = src_str
    return hashed_name

_safe_dest_name._registry = {}  # type: ignore[attr-defined]


def _file_identity(path: Path):
    """
    Return a stable identity token for a file so we can detect truncation
    (log rotation / overwrite).

    On POSIX: (st_dev, st_ino) is reliable.
    On Windows: st_ino is 0 for most filesystems, so we fall back to
    (st_dev, st_ctime_ns) — imperfect but practical.
    """
    try:
        # Identity values let us detect rotation/truncation between runs.
        st = path.stat()
        if st.st_ino != 0:
            return (int(st.st_dev), int(st.st_ino))
        return (int(st.st_dev), int(st.st_ctime_ns))
    except OSError:
        return None


def _load_checkpoints(checkpoint_path: Path) -> dict:
    # Checkpoints store last-read byte offset per source file.
    if checkpoint_path.exists():
        try:
            with checkpoint_path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"  [warn] Could not load checkpoints ({exc}); starting fresh.")
    return {}


def _save_checkpoints(checkpoint_path: Path, data: dict) -> None:
    # Write to a temp file then replace, so partial writes do not corrupt state.
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = checkpoint_path.with_suffix(".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        tmp.replace(checkpoint_path)
    except OSError as exc:
        print(f"  [warn] Could not save checkpoints: {exc}")


def _scan_dirs(source_dirs: list[Path], ml_logs_resolved: Path | None) -> list[Path]:
    """
    Recursively find all *.log files under each directory in source_dirs.
    Skips any path that falls inside ml_logs_resolved (loop prevention).
    Returns a sorted, deduplicated list of absolute paths.
    """
    # seen avoids duplicate files when paths overlap.
    seen = set()
    found = []
    for d in source_dirs:
        if not d.is_dir():
            print(f"  [warn] Source directory not found or not a directory: {d}")
            continue
        for log_file in sorted(d.rglob("*.log")):
            try:
                resolved = log_file.resolve()
            except OSError:
                resolved = log_file
            # Loop prevention: skip anything inside the ML logs dir
            if ml_logs_resolved is not None:
                try:
                    resolved.relative_to(ml_logs_resolved)
                    print(f"  [skip] {log_file} is inside ML logs dir — skipping to prevent loop.")
                    continue
                except ValueError:
                    pass  # Not inside ml_logs_resolved — safe to include
            if resolved not in seen:
                seen.add(resolved)
                found.append(log_file)
    return found


# ---------------------------------------------------------------------------
# Core fetch logic
# ---------------------------------------------------------------------------

def fetch_file(
    source_path: Path,
    dest_path: Path,
    checkpoint_key: str,
    checkpoints: dict,
    dry_run: bool,
) -> dict:
    """
    Read new lines from source_path since the last checkpoint and append
    them to dest_path.  Returns a result summary dict.

    checkpoint_key is the key used inside the checkpoints dict (stable
    string derived from the resolved source path).
    """
    result = {
        "lines_added": 0,
        "bytes_read": 0,
        "skipped": False,
        "error": None,
    }

    if not source_path.exists():
        result["error"] = f"source file not found: {source_path}"
        return result

    file_size = source_path.stat().st_size
    identity = _file_identity(source_path)
    identity_key = str(identity) if identity is not None else "unknown"

    # Load previous state for this file (offset + identity).
    prev = checkpoints.get(checkpoint_key, {})
    prev_offset = int(prev.get("offset", 0))
    prev_identity = prev.get("identity", None)

    # Detect truncation / rotation
    if prev_identity is not None and prev_identity != identity_key:
        print(f"    File identity changed — likely rotated. Resetting offset.")
        prev_offset = 0
    elif prev_offset > file_size:
        print(f"    File shrank ({prev_offset} → {file_size} bytes) — likely truncated. Resetting.")
        prev_offset = 0

    # No new bytes means nothing changed since last run.
    if prev_offset == file_size:
        result["skipped"] = True
        return result

    # Read new bytes
    try:
        with source_path.open("rb") as fh:
            fh.seek(prev_offset)
            raw = fh.read()
            new_offset = prev_offset + len(raw)
    except OSError as exc:
        result["error"] = f"read error: {exc}"
        return result

    # Invalid bytes are replaced rather than crashing the pipeline.
    text = raw.decode("utf-8", errors="replace")
    new_lines = [ln for ln in text.splitlines(keepends=True) if ln.strip()]

    result["lines_added"] = len(new_lines)
    result["bytes_read"] = new_offset - prev_offset

    if new_lines and not dry_run:
        # Append only newly seen lines into the ML logs directory.
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with dest_path.open("a", encoding="utf-8") as fh:
                fh.writelines(new_lines)
        except OSError as exc:
            result["error"] = f"write error: {exc}"
            return result

    # Update checkpoint
    checkpoints[checkpoint_key] = {
        "source_path": str(source_path),
        "dest_path": str(dest_path),
        "offset": new_offset,
        "identity": identity_key,
        "last_run": datetime.now(timezone.utc).isoformat(),
    }

    return result


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _parse_multiline(raw: str) -> list[str]:
    """Split a comma-separated config value into a list of non-empty strings."""
    # Also accept multiline INI formatting by converting newlines to commas first.
    return [v.strip() for v in raw.replace("\n", ",").split(",") if v.strip()]


def _collect_sources(cfg: configparser.ConfigParser, config_dir: Path) -> list[Path]:
    """
    Build the full list of source *.log files from:
      1. [source_dirs] paths  — directory scan (recursive)
      2. [source_files] files — exact file paths (fallback)

    Returns a list of Path objects (may include duplicates if both sections
    name the same file; deduplication happens in the caller).
    """
    sources: list[Path] = []

    # Prefer directory mode when provided so new .log files are auto-discovered.
    # --- Directory-based discovery ---
    if cfg.has_section("source_dirs"):
        raw_dirs = cfg.get("source_dirs", "paths", fallback="").strip()
        if raw_dirs:
            dir_paths = [
                _resolve(config_dir, p) for p in _parse_multiline(raw_dirs)
            ]
            # Actual scan is deferred to the caller (needs ml_logs_resolved).
            # Store as a sentinel list and return separately.
            # Actually just return the dirs — the caller will scan.
            return ("dirs", dir_paths)  # type: ignore[return-value]

    # Fallback mode allows strict control over exact files to ingest.
    # --- Exact file paths fallback ---
    if cfg.has_section("source_files"):
        raw_files = cfg.get("source_files", "files", fallback="").strip()
        if raw_files:
            for fp in _parse_multiline(raw_files):
                sources.append(_resolve(config_dir, fp))

    # Legacy [sources] section (syslog/ssh/web)
    if cfg.has_section("sources"):
        for key in ("syslog", "ssh", "web"):
            val = cfg.get("sources", key, fallback="").strip()
            if val:
                sources.append(_resolve(config_dir, val))

    return ("files", sources)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    # CLI entry point for incremental ingestion into SIEM_ML-main/logs.
    parser = argparse.ArgumentParser(
        description="Incrementally fetch log sources into the SIEM ML logs/ folder."
    )
    parser.add_argument(
        "--config",
        default="config/sources.ini",
        help="Path to sources.ini  (default: config/sources.ini)",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Clear byte-offset checkpoints so the full source files are re-read.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be fetched without writing anything.",
    )
    args = parser.parse_args(argv)

    # --- Load config --------------------------------------------------
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[error] Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    cfg.read(config_path, encoding="utf-8")

    config_dir = config_path.parent.parent  # project root (parent of config/)

    # --- Resolve ML paths --------------------------------------------
    project_dir = Path(cfg.get("ml", "project_dir"))
    logs_dir = _resolve(project_dir, cfg.get("ml", "logs_dir", fallback="logs"))
    checkpoint_file = _resolve(
        project_dir,
        cfg.get("ml", "checkpoint_file", fallback="memory/fetcher_checkpoints.json"),
    )

    print("=" * 60)
    print("SIEM Fetcher")
    print("=" * 60)
    print(f"  Config       : {config_path.resolve()}")
    print(f"  Project dir  : {project_dir}")
    print(f"  ML logs dir  : {logs_dir}")
    print(f"  Checkpoint   : {checkpoint_file}")
    if args.dry_run:
        print("  Mode         : DRY RUN — nothing will be written")
    if args.reset:
        print("  Reset        : checkpoints will be cleared for this run")
    print()

    # Resolve once so we can quickly test if a source accidentally points into ML logs.
    # ML logs dir resolved for loop-prevention checks
    try:
        ml_logs_resolved = logs_dir.resolve() if logs_dir.exists() else None
    except OSError:
        ml_logs_resolved = None

    # --- Reset the per-run dest name registry -------------------------
    _safe_dest_name._registry = {}  # type: ignore[attr-defined]

    # --- Collect source files -----------------------------------------
    kind, payload = _collect_sources(cfg, config_dir)

    if kind == "dirs":
        source_dirs: list[Path] = payload
        print(f"  Source dirs  : {[str(d) for d in source_dirs]}")
        source_files = _scan_dirs(source_dirs, ml_logs_resolved)
        print(f"  Files found  : {len(source_files)}")
    else:
        source_files: list[Path] = payload
        print(f"  Source files : {len(source_files)} (exact paths)")

    if not source_files:
        print("\n[warn] No source log files found. Nothing to fetch.")
        print("  Check [source_dirs] paths or [source_files] files in sources.ini.")
        sys.exit(0)

    print()

    # --- Load checkpoints (optionally reset) --------------------------
    checkpoints = {} if args.reset else _load_checkpoints(checkpoint_file)

    # Walk each discovered source and copy only its newly appended content.
    # --- Process each source file ------------------------------------
    total_lines = 0
    any_error = False

    for source_path in source_files:
        dest_path = _safe_dest_name(source_path, logs_dir)
        # Use the resolved source path as the checkpoint key for stability
        try:
            ck_key = str(source_path.resolve())
        except OSError:
            ck_key = str(source_path)

        # Loop prevention: double-check dest is not inside source's own tree
        try:
            src_resolved = source_path.resolve()
            dest_resolved = dest_path.resolve()
            if src_resolved == dest_resolved:
                print(
                    f"  [ERROR] Source and destination are the same file!\n"
                    f"          source={src_resolved}\n"
                    f"          Do NOT point sources at the ML logs/ folder.",
                    file=sys.stderr,
                )
                any_error = True
                continue
        except OSError:
            pass

        label = source_path.name
        print(f"  [{label}]")
        print(f"    source : {source_path}")
        print(f"    dest   : {dest_path}")

        res = fetch_file(
            source_path=source_path,
            dest_path=dest_path,
            checkpoint_key=ck_key,
            checkpoints=checkpoints,
            dry_run=args.dry_run,
        )

        if res["error"]:
            print(f"    ERROR  : {res['error']}")
            any_error = True
        elif res["skipped"]:
            print(f"    result : no new data (file unchanged)")
        else:
            action = "would append" if args.dry_run else "appended"
            print(f"    result : {action} {res['lines_added']} lines  ({res['bytes_read']} bytes)")
            total_lines += res["lines_added"]
        print()

    # --- Persist checkpoints -----------------------------------------
    if not args.dry_run:
        _save_checkpoints(checkpoint_file, checkpoints)

    print("=" * 60)
    print(f"Fetcher done. Total lines appended: {total_lines}")
    if any_error:
        print("One or more sources had errors — check messages above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
