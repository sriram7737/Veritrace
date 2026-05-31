"""Tests for the stdlib migration runner (SQLite)."""
import os
import sqlite3
import tempfile

import pytest

from veritrace.backends.migrations import (MIGRATIONS, Migration,
                                           MigrationRunner)


def _tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


def test_runner_applies_all_default_migrations():
    path = _tmp_db()
    try:
        runner = MigrationRunner(sqlite_path=path)
        applied = runner.run(MIGRATIONS)
        assert applied == [1, 2, 3]
        assert runner.current_version() == 3
        # tables exist
        conn = sqlite3.connect(path)
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert {"traces", "audit_chain", "schema_migrations"} <= names
        conn.close()
    finally:
        os.unlink(path)


def test_runner_is_idempotent():
    path = _tmp_db()
    try:
        runner = MigrationRunner(sqlite_path=path)
        runner.run(MIGRATIONS)
        # second run applies nothing
        assert runner.run(MIGRATIONS) == []
        assert runner.applied_versions() == [1, 2, 3]
    finally:
        os.unlink(path)


def test_runner_applies_only_new_migrations():
    path = _tmp_db()
    try:
        runner = MigrationRunner(sqlite_path=path)
        runner.run(MIGRATIONS)
        extra = Migration(version=4, name="add_col",
                          up_sql="ALTER TABLE traces ADD COLUMN note TEXT")
        assert runner.run(MIGRATIONS + [extra]) == [4]
        assert runner.current_version() == 4
    finally:
        os.unlink(path)


def test_runner_requires_exactly_one_target():
    with pytest.raises(ValueError):
        MigrationRunner()
    with pytest.raises(ValueError):
        MigrationRunner(sqlite_path="x", dsn="y")


def test_failed_migration_rolls_back_and_stops():
    path = _tmp_db()
    try:
        runner = MigrationRunner(sqlite_path=path)
        bad = Migration(version=1, name="bad", up_sql="THIS IS NOT SQL")
        with pytest.raises(Exception):
            runner.run([bad])
        assert runner.current_version() == 0
    finally:
        os.unlink(path)
