"""Repository syntax guard.

This catches the exact failure mode that hurt earlier zips: a Python file with
a syntax error causing pytest collection to explode before tests can run.
"""
from __future__ import annotations

import py_compile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_python_sources_compile():
    paths = [
        p for p in ROOT.rglob("*.py")
        if ".git" not in p.parts
        and "__pycache__" not in p.parts
        and ".venv" not in p.parts
        and "build" not in p.parts
    ]

    assert paths
    for path in paths:
        py_compile.compile(str(path), doraise=True)
