"""
tests/test_fetcher.py
=====================
Minimal pytest tests for fetcher.py support code.
Does NOT test or import siem_ml.py.
"""

import json
import sys
from pathlib import Path

import pytest

# Make the parent (project root) importable
sys.path.insert(0, str(Path(__file__).parent.parent))

import fetcher  # noqa: E402


# ---------------------------------------------------------------------------
# _safe_dest_name — collision-free destination naming
# ---------------------------------------------------------------------------

def test_safe_dest_name_no_collision(tmp_path):
    """Same filename from same dir → plain name, no hash."""
    fetcher._safe_dest_name._registry = {}
    src = tmp_path / "logs" / "auth.log"
    dest_dir = tmp_path / "ml_logs"
    result = fetcher._safe_dest_name(src, dest_dir)
    assert result == dest_dir / "auth.log"


def test_safe_dest_name_collision_adds_hash(tmp_path):
    """Two different directories with the same filename → second gets a hash suffix."""
    fetcher._safe_dest_name._registry = {}
    src_a = tmp_path / "app_a" / "auth.log"
    src_b = tmp_path / "app_b" / "auth.log"
    dest_dir = tmp_path / "ml_logs"

    result_a = fetcher._safe_dest_name(src_a, dest_dir)
    result_b = fetcher._safe_dest_name(src_b, dest_dir)

    # First file keeps the plain name
    assert result_a == dest_dir / "auth.log"
    # Second file must be different and contain a hash
    assert result_b != result_a
    assert "auth_" in result_b.stem


def test_safe_dest_name_same_source_idempotent(tmp_path):
    """The same source path always maps to the same destination."""
    fetcher._safe_dest_name._registry = {}
    src = tmp_path / "app" / "server.log"
    dest_dir = tmp_path / "ml_logs"

    r1 = fetcher._safe_dest_name(src, dest_dir)
    r2 = fetcher._safe_dest_name(src, dest_dir)
    assert r1 == r2


# ---------------------------------------------------------------------------
# _scan_dirs — directory discovery
# ---------------------------------------------------------------------------

def test_scan_dirs_finds_log_files(tmp_path):
    """Recursively discovers *.log files."""
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.log").write_text("line1\n")
    (tmp_path / "sub" / "b.log").write_text("line2\n")
    (tmp_path / "notes.txt").write_text("not a log\n")

    found = fetcher._scan_dirs([tmp_path], ml_logs_resolved=None)
    names = {f.name for f in found}
    assert "a.log" in names
    assert "b.log" in names
    assert "notes.txt" not in names


def test_scan_dirs_skips_ml_logs(tmp_path):
    """Files inside the ML logs dir are excluded (loop prevention)."""
    ml_logs = tmp_path / "ml_logs"
    ml_logs.mkdir()
    (ml_logs / "syslog.log").write_text("ml output\n")
    source_dir = tmp_path / "sources"
    source_dir.mkdir()
    (source_dir / "app.log").write_text("source data\n")

    found = fetcher._scan_dirs(
        [tmp_path],  # scans everything including ml_logs
        ml_logs_resolved=ml_logs.resolve(),
    )
    names = {f.name for f in found}
    assert "syslog.log" not in names  # inside ML logs — excluded
    assert "app.log" in names


def test_scan_dirs_missing_dir(tmp_path, capsys):
    """Non-existent source directory issues a warning and returns empty list."""
    missing = tmp_path / "does_not_exist"
    found = fetcher._scan_dirs([missing], ml_logs_resolved=None)
    assert found == []
    captured = capsys.readouterr()
    assert "not found" in captured.out.lower() or "warn" in captured.out.lower()


# ---------------------------------------------------------------------------
# _load_checkpoints / _save_checkpoints — round-trip
# ---------------------------------------------------------------------------

def test_checkpoint_roundtrip(tmp_path):
    cp_path = tmp_path / "memory" / "checkpoints.json"
    data = {
        "/var/log/auth.log": {
            "offset": 1024,
            "identity": "(2049, 999)",
            "last_run": "2026-01-01T00:00:00+00:00",
        }
    }
    fetcher._save_checkpoints(cp_path, data)
    loaded = fetcher._load_checkpoints(cp_path)
    assert loaded == data


def test_checkpoint_load_missing_file(tmp_path):
    cp_path = tmp_path / "missing.json"
    loaded = fetcher._load_checkpoints(cp_path)
    assert loaded == {}


def test_checkpoint_load_corrupt_file(tmp_path):
    cp_path = tmp_path / "corrupt.json"
    cp_path.write_text("not valid json {{{{")
    loaded = fetcher._load_checkpoints(cp_path)
    assert loaded == {}


# ---------------------------------------------------------------------------
# fetch_file — core incremental logic
# ---------------------------------------------------------------------------

def test_fetch_file_new_file(tmp_path):
    """First run on a new file copies all lines."""
    src = tmp_path / "source.log"
    src.write_text("line one\nline two\nline three\n")
    dest = tmp_path / "dest.log"
    checkpoints = {}
    ck_key = str(src.resolve())

    fetcher._safe_dest_name._registry = {}
    res = fetcher.fetch_file(src, dest, ck_key, checkpoints, dry_run=False)

    assert res["error"] is None
    assert res["lines_added"] == 3
    assert dest.read_text() == "line one\nline two\nline three\n"
    assert checkpoints[ck_key]["offset"] == src.stat().st_size


def test_fetch_file_incremental(tmp_path):
    """Second run only copies new lines appended since the last checkpoint."""
    src = tmp_path / "source.log"
    src.write_text("line one\nline two\n")
    dest = tmp_path / "dest.log"
    checkpoints = {}
    ck_key = str(src.resolve())

    fetcher._safe_dest_name._registry = {}
    fetcher.fetch_file(src, dest, ck_key, checkpoints, dry_run=False)

    # Append new lines
    with src.open("a") as fh:
        fh.write("line three\nline four\n")

    res2 = fetcher.fetch_file(src, dest, ck_key, checkpoints, dry_run=False)
    assert res2["lines_added"] == 2
    content = dest.read_text()
    assert content.count("line") == 4


def test_fetch_file_dry_run(tmp_path):
    """Dry run reads but does not write."""
    src = tmp_path / "source.log"
    src.write_text("hello\nworld\n")
    dest = tmp_path / "dest.log"
    checkpoints = {}
    ck_key = str(src.resolve())

    fetcher._safe_dest_name._registry = {}
    res = fetcher.fetch_file(src, dest, ck_key, checkpoints, dry_run=True)

    assert res["lines_added"] == 2
    assert not dest.exists()  # nothing written


def test_fetch_file_missing_source(tmp_path):
    """Missing source file returns an error."""
    src = tmp_path / "missing.log"
    dest = tmp_path / "dest.log"
    checkpoints = {}
    ck_key = str(src)

    fetcher._safe_dest_name._registry = {}
    res = fetcher.fetch_file(src, dest, ck_key, checkpoints, dry_run=False)
    assert res["error"] is not None


def test_fetch_file_no_new_data(tmp_path):
    """If file hasn't grown, result is skipped=True."""
    src = tmp_path / "source.log"
    src.write_text("same content\n")
    dest = tmp_path / "dest.log"
    checkpoints = {}
    ck_key = str(src.resolve())

    fetcher._safe_dest_name._registry = {}
    fetcher.fetch_file(src, dest, ck_key, checkpoints, dry_run=False)
    # Second call — nothing new
    res2 = fetcher.fetch_file(src, dest, ck_key, checkpoints, dry_run=False)
    assert res2["skipped"] is True
    assert res2["lines_added"] == 0


# ---------------------------------------------------------------------------
# _parse_multiline helper
# ---------------------------------------------------------------------------

def test_parse_multiline_comma():
    result = fetcher._parse_multiline("  /a/b , /c/d , /e/f  ")
    assert result == ["/a/b", "/c/d", "/e/f"]


def test_parse_multiline_empty():
    assert fetcher._parse_multiline("   ") == []
