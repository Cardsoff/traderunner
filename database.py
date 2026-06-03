"""
SQLite-хранилище для TradeRunner v4.0 (multi-tenant).

Все функции автоматически фильтруют по user_id через Flask `g` объект.
Если вызывается вне Flask контекста — функции принимают user_id явно.
"""

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import os as _dbos
_db_env = _dbos.environ.get("PACEMAKER_DB", None)
DB_PATH = Path(_db_env) if _db_env else Path(__file__).parent / "planner.db"

DEFAULT_SETUPS = ['breakout', 'trend', 'scalp', 'swing', 'news']


def _current_user_id(user_id: int = None) -> int:
    """Возвращает user_id из явного аргумента или из flask.g."""
    if user_id is not None:
        return user_id
    try:
        from flask import g
        uid = getattr(g, "user_id", None)
        if uid is None:
            raise RuntimeError("Нет авторизованного пользователя (g.user_id is None)")
        return int(uid)
    except (ImportError, RuntimeError):
        raise RuntimeError("Нельзя вызывать database функции без user_id или Flask контекста")


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Создаёт таблицы при первом запуске + засевает дефолты.
    В v4.0 НЕ создаёт legacy таблицы — это делает migrate_to_v4.py."""
    with get_conn() as conn:
        # Только если миграция не была выполнена — пробуем создать legacy схему
        has_users = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        ).fetchone()
        if not has_users:
            # БД до миграции v4.0 — создаём legacy схему (для совместимости с v3.x)
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY, value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                external_id TEXT UNIQUE,
                ts TEXT NOT NULL, symbol TEXT NOT NULL, side TEXT NOT NULL,
                setup TEXT, entry_price REAL, exit_price REAL, qty REAL,
                pnl_usd REAL NOT NULL DEFAULT 0, pnl_pct REAL NOT NULL DEFAULT 0,
                fee_usd REAL NOT NULL DEFAULT 0,
                note TEXT DEFAULT '', source TEXT NOT NULL DEFAULT 'manual',
                funding_usd REAL NOT NULL DEFAULT 0,
                user_id INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS deposits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                external_id TEXT UNIQUE,
                ts TEXT NOT NULL, kind TEXT NOT NULL, amount_usd REAL NOT NULL,
                note TEXT DEFAULT '', source TEXT NOT NULL DEFAULT 'manual',
                user_id INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS equity_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL, equity_usd REAL NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual',
                user_id INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS goals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT, amount REAL NOT NULL,
                monthly_return_pct REAL NOT NULL DEFAULT 10,
                created_at TEXT NOT NULL, achieved_at TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                monthly_deposit REAL NOT NULL DEFAULT 0,
                user_id INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS setups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 1,
                name TEXT NOT NULL,
                UNIQUE(user_id, name)
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL, action TEXT NOT NULL,
                entity TEXT, entity_id TEXT, payload TEXT,
                user_id INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                UNIQUE(user_id, key)
            );
            CREATE INDEX IF NOT EXISTS idx_trades_user_ts ON trades(user_id, ts);
            CREATE INDEX IF NOT EXISTS idx_deposits_user_ts ON deposits(user_id, ts);
            CREATE INDEX IF NOT EXISTS idx_equity_user_ts ON equity_snapshots(user_id, ts);
            """)


# ---------- settings (PER-USER) ----------

ALLOWED_SETTINGS_KEYS = {
    "start_capital", "monthly_deposit", "monthly_return_pct",
    "start_date", "tracking_start_date", "tracking_end_date",
    "scenario", "currency", "last_sync_ts",
    "bitunix_api_key", "bitunix_api_secret",  # шифруются на уровне app.py
    "binance_api_key", "binance_api_secret",
    "bybit_api_key", "bybit_api_secret",
    "okx_api_key", "okx_api_secret", "okx_passphrase",
    "onboarding_done",
}

# Глобальные settings (не привязаны к юзеру) — flask_secret_key, версии и т.п.
GLOBAL_SETTINGS_KEYS = {"flask_secret_key"}


def get_settings(user_id: int = None) -> dict:
    """Возвращает все settings текущего юзера (per-user) + глобальные."""
    uid = _current_user_id(user_id)
    with get_conn() as conn:
        # Per-user
        rows = conn.execute(
            "SELECT key, value FROM user_settings WHERE user_id=?", (uid,)
        ).fetchall()
        result = {r["key"]: r["value"] for r in rows}
        # Глобальные (для совместимости)
        try:
            g_rows = conn.execute(
                "SELECT key, value FROM settings WHERE key IN ({})".format(
                    ",".join("?" * len(GLOBAL_SETTINGS_KEYS))
                ),
                tuple(GLOBAL_SETTINGS_KEYS),
            ).fetchall()
            for r in g_rows:
                result.setdefault(r["key"], r["value"])
        except sqlite3.OperationalError:
            pass
    return result


def update_settings(updates: dict, user_id: int = None):
    """Обновляет per-user settings. Только ALLOWED_SETTINGS_KEYS."""
    uid = _current_user_id(user_id)
    safe = {k: v for k, v in updates.items() if k in ALLOWED_SETTINGS_KEYS}
    if not safe:
        return
    with get_conn() as conn:
        for k, v in safe.items():
            conn.execute(
                "INSERT INTO user_settings(user_id, key, value) VALUES (?, ?, ?) "
                "ON CONFLICT(user_id, key) DO UPDATE SET value=excluded.value",
                (uid, k, str(v)),
            )


def _get_global_setting(key: str) -> str | None:
    """Для flask_secret_key и прочих глобальных. Без user_id."""
    with get_conn() as conn:
        try:
            r = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return r["value"] if r else None
        except sqlite3.OperationalError:
            return None


def _set_global_setting(key: str, value: str):
    """Только для GLOBAL_SETTINGS_KEYS."""
    if key not in GLOBAL_SETTINGS_KEYS:
        raise ValueError(f"Not a global setting: {key}")
    with get_conn() as conn:
        # Создаём таблицу settings если нет (для совместимости)
        conn.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


# ---------- goals ----------

def get_active_goal(user_id: int = None) -> dict | None:
    uid = _current_user_id(user_id)
    with get_conn() as conn:
        r = conn.execute(
            "SELECT * FROM goals WHERE is_active=1 AND user_id=? LIMIT 1", (uid,)
        ).fetchone()
    return dict(r) if r else None


def list_goals_archive(user_id: int = None) -> list[dict]:
    uid = _current_user_id(user_id)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM goals WHERE is_active=0 AND user_id=? ORDER BY achieved_at DESC", (uid,)
        ).fetchall()
    return [dict(r) for r in rows]


def update_active_goal(updates: dict, user_id: int = None):
    uid = _current_user_id(user_id)
    allowed = {"name", "amount", "monthly_return_pct", "monthly_deposit"}
    fields = {k: v for k, v in updates.items() if k in allowed}
    if not fields:
        return
    parts = ", ".join(f"{k}=?" for k in fields)
    with get_conn() as conn:
        conn.execute(
            f"UPDATE goals SET {parts} WHERE is_active=1 AND user_id=?",
            (*fields.values(), uid)
        )


def archive_active_and_create_new(new_amount: float, new_name: str = None,
                                  new_return_pct: float = 10, user_id: int = None):
    uid = _current_user_id(user_id)
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with get_conn() as conn:
        conn.execute(
            "UPDATE goals SET is_active=0, achieved_at=? WHERE is_active=1 AND user_id=?",
            (today, uid)
        )
        if not new_name:
            cnt = conn.execute("SELECT COUNT(*) FROM goals WHERE user_id=?", (uid,)).fetchone()[0]
            new_name = f"Цель {cnt + 1}"
        conn.execute(
            "INSERT INTO goals(name, amount, monthly_return_pct, created_at, is_active, user_id) "
            "VALUES (?, ?, ?, ?, 1, ?)",
            (new_name, new_amount, new_return_pct, today, uid),
        )


def delete_active_goal_and_create_empty(user_id: int = None):
    uid = _current_user_id(user_id)
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with get_conn() as conn:
        conn.execute("DELETE FROM goals WHERE is_active=1 AND user_id=?", (uid,))
        conn.execute(
            "INSERT INTO goals(name, amount, monthly_return_pct, created_at, is_active, user_id) "
            "VALUES (?, ?, ?, ?, 1, ?)",
            ("Новая цель", 1000, 10, today, uid),
        )


def ensure_default_goal_for_user(user_id: int):
    """Гарантирует что у юзера есть хотя бы одна активная цель (для новой регистрации)."""
    with get_conn() as conn:
        r = conn.execute(
            "SELECT id FROM goals WHERE is_active=1 AND user_id=? LIMIT 1", (user_id,)
        ).fetchone()
        if not r:
            today = datetime.utcnow().strftime("%Y-%m-%d")
            conn.execute(
                "INSERT INTO goals(name, amount, monthly_return_pct, created_at, is_active, user_id) "
                "VALUES (?, ?, ?, ?, 1, ?)",
                ("Первая цель", 10000, 10, today, user_id),
            )


def ensure_default_setups_for_user(user_id: int):
    """Гарантирует дефолтные setups для нового юзера."""
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT name FROM setups WHERE user_id=?", (user_id,)
        ).fetchall()
        if not existing:
            for s in DEFAULT_SETUPS:
                conn.execute(
                    "INSERT OR IGNORE INTO setups(user_id, name) VALUES (?, ?)",
                    (user_id, s),
                )


# ---------- setups ----------

def list_setups(user_id: int = None) -> list[str]:
    uid = _current_user_id(user_id)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT name FROM setups WHERE user_id=? ORDER BY name", (uid,)
        ).fetchall()
    return [r["name"] for r in rows]


def add_setup(name: str, user_id: int = None):
    uid = _current_user_id(user_id)
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO setups(user_id, name) VALUES (?, ?)",
            (uid, name.lower())
        )


def delete_setup(name: str, user_id: int = None):
    uid = _current_user_id(user_id)
    with get_conn() as conn:
        conn.execute(
            "UPDATE trades SET setup=NULL WHERE setup=? AND user_id=?", (name, uid)
        )
        conn.execute("DELETE FROM setups WHERE name=? AND user_id=?", (name, uid))


# ---------- trades ----------

def add_trade(trade: dict, user_id: int = None):
    uid = _current_user_id(user_id)
    ext_id = trade.get("external_id")
    if not ext_id:
        src = (trade.get("source") or "manual").lower()
        if src == "manual":
            ext_id = f"manual-{trade.get('ts','')}-{uuid.uuid4().hex[:8]}"
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO trades "
            "(external_id, ts, symbol, side, setup, entry_price, exit_price, qty, "
            " pnl_usd, pnl_pct, fee_usd, funding_usd, note, source, user_id, stop_loss) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ext_id, trade["ts"], trade["symbol"], trade["side"],
                trade.get("setup"), trade.get("entry_price"), trade.get("exit_price"),
                trade.get("qty"), trade.get("pnl_usd", 0), trade.get("pnl_pct", 0),
                trade.get("fee_usd", 0), trade.get("funding_usd", 0),
                trade.get("note", ""), trade.get("source", "manual"), uid,
                trade.get("stop_loss"),  # B2: NULL если не указан
            ),
        )


def list_trades(limit: int = 100000, user_id: int = None) -> list[dict]:
    uid = _current_user_id(user_id)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM trades WHERE user_id=? ORDER BY ts DESC LIMIT ?", (uid, limit)
        ).fetchall()
    return [dict(r) for r in rows]


def delete_trade(trade_id: int, user_id: int = None):
    uid = _current_user_id(user_id)
    with get_conn() as conn:
        conn.execute("DELETE FROM trades WHERE id=? AND user_id=?", (trade_id, uid))


def update_trade_fields(trade_id: int, fields: dict, user_id: int = None):
    uid = _current_user_id(user_id)
    allowed = {"note", "setup", "stop_loss"}  # B2: SL редактируется inline
    upd = {k: v for k, v in fields.items() if k in allowed}
    # B2: stop_loss пустая строка → NULL, число → float
    if "stop_loss" in upd:
        v = upd["stop_loss"]
        if v == "" or v is None:
            upd["stop_loss"] = None
        else:
            try:
                upd["stop_loss"] = float(v)
            except Exception:
                upd.pop("stop_loss")
    if not upd:
        return
    parts = ", ".join(f"{k}=?" for k in upd)
    with get_conn() as conn:
        conn.execute(
            f"UPDATE trades SET {parts} WHERE id=? AND user_id=?",
            (*upd.values(), trade_id, uid)
        )


# ---------- deposits ----------

def add_deposit(dep: dict, user_id: int = None):
    uid = _current_user_id(user_id)
    ext_id = dep.get("external_id")
    if not ext_id:
        src = (dep.get("source") or "manual").lower()
        if src == "manual":
            ext_id = f"manual-{dep.get('ts','')}-{uuid.uuid4().hex[:8]}"
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO deposits "
            "(external_id, ts, kind, amount_usd, note, source, user_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                ext_id, dep["ts"], dep["kind"], dep["amount_usd"],
                dep.get("note", ""), dep.get("source", "manual"), uid,
            ),
        )


def list_deposits(user_id: int = None) -> list[dict]:
    uid = _current_user_id(user_id)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM deposits WHERE user_id=? ORDER BY ts DESC", (uid,)
        ).fetchall()
    return [dict(r) for r in rows]


def delete_deposit(dep_id: int, user_id: int = None):
    uid = _current_user_id(user_id)
    with get_conn() as conn:
        conn.execute("DELETE FROM deposits WHERE id=? AND user_id=?", (dep_id, uid))


# ---------- equity ----------

def add_equity_snapshot(equity_usd: float, source: str = "manual",
                        dedup_eps: float = 0.005, user_id: int = None) -> bool:
    uid = _current_user_id(user_id)
    with get_conn() as conn:
        last = conn.execute(
            "SELECT equity_usd FROM equity_snapshots WHERE user_id=? "
            "ORDER BY ts DESC LIMIT 1", (uid,)
        ).fetchone()
        if last is not None:
            try:
                if abs(float(last["equity_usd"]) - float(equity_usd)) < dedup_eps:
                    return False
            except Exception:
                pass
        conn.execute(
            "INSERT INTO equity_snapshots(ts, equity_usd, source, user_id) VALUES (?, ?, ?, ?)",
            (datetime.utcnow().isoformat(timespec="seconds"), equity_usd, source, uid),
        )
    return True


def latest_equity(user_id: int = None) -> float | None:
    uid = _current_user_id(user_id)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT equity_usd FROM equity_snapshots WHERE user_id=? "
            "ORDER BY ts DESC LIMIT 1", (uid,)
        ).fetchone()
    return float(row["equity_usd"]) if row else None


def reset_all_data(user_id: int = None):
    """Reset all DATA для конкретного юзера. Settings/users остаются."""
    uid = _current_user_id(user_id)
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with get_conn() as conn:
        conn.execute("DELETE FROM trades WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM deposits WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM equity_snapshots WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM goals WHERE user_id=?", (uid,))
        conn.execute(
            "INSERT INTO goals(name, amount, monthly_return_pct, created_at, is_active, user_id) "
            "VALUES (?, ?, ?, ?, 1, ?)",
            ("Первая цель", 10000, 10, today, uid),
        )


# === Audit log ===

def log_audit(action: str, entity: str = None, entity_id=None,
              payload: dict = None, user_id: int = None):
    uid = _current_user_id(user_id)
    import json as _json
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_log (ts, action, entity, entity_id, payload, user_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                datetime.utcnow().isoformat(timespec="seconds"),
                action, entity,
                str(entity_id) if entity_id is not None else None,
                _json.dumps(payload, ensure_ascii=False) if payload else None,
                uid,
            ),
        )


def list_audit_log(limit: int = 100, user_id: int = None) -> list[dict]:
    uid = _current_user_id(user_id)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE user_id=? ORDER BY ts DESC LIMIT ?",
            (uid, limit)
        ).fetchall()
    return [dict(r) for r in rows]


# === Bulk update + auto-tag ===

def bulk_update_trades(ids: list, setup: str = None, note: str = None,
                       user_id: int = None) -> int:
    uid = _current_user_id(user_id)
    if not ids:
        return 0
    updates = {}
    if setup is not None:
        updates['setup'] = setup
    if note is not None:
        updates['note'] = note
    if not updates:
        return 0
    placeholders = ",".join("?" * len(ids))
    set_clause = ", ".join(f"{k}=?" for k in updates)
    with get_conn() as conn:
        cursor = conn.execute(
            f"UPDATE trades SET {set_clause} WHERE id IN ({placeholders}) AND user_id=?",
            (*updates.values(), *ids, uid),
        )
        affected = cursor.rowcount
    return affected


def auto_tag_trades(rules: list, user_id: int = None) -> int:
    uid = _current_user_id(user_id)
    if not rules:
        return 0
    affected = 0
    with get_conn() as conn:
        for r in rules:
            sym = (r.get('symbol') or '').upper().strip()
            side = (r.get('side') or '').upper().strip()
            setup = (r.get('setup') or '').strip()
            if not setup:
                continue
            conds = ["(setup IS NULL OR setup = '')", "user_id = ?"]
            params = [uid]
            if sym:
                conds.append("UPPER(symbol) LIKE ?")
                params.append(f"%{sym}%")
            if side:
                conds.append("UPPER(side) = ?")
                params.append(side)
            sql = f"UPDATE trades SET setup = ? WHERE {' AND '.join(conds)}"
            params = [setup] + params
            cur = conn.execute(sql, params)
            affected += cur.rowcount
    return affected
