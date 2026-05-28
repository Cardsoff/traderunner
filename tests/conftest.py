"""
pytest fixtures для Crypto Trading Planner.
Каждый тест получает чистую инициализированную БД в /tmp (вне FUSE-моунта,
где у pytest tmp_path возникает RecursionError при cleanup'е прав).
"""
import sys
import tempfile
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest


@pytest.fixture(autouse=True)
def isolated_db(monkeypatch):
    fd, path = tempfile.mkstemp(prefix="planner_test_", suffix=".db", dir="/tmp")
    os.close(fd)
    db_path = Path(path)
    if db_path.exists():
        db_path.unlink()
    import database as d
    monkeypatch.setattr(d, "DB_PATH", db_path)
    d.init_db()
    yield db_path
    try:
        db_path.unlink()
    except FileNotFoundError:
        pass
