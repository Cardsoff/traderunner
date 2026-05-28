"""Тесты на database.py — BUG-04 (snapshot dedup), BUG-08 (manual id), BUG-21 (whitelist)."""
import sqlite3
import database as d


class TestEquitySnapshotDedup:
    """BUG-04: подряд идущие одинаковые equity не записываются."""

    def test_dedup_same_value(self, isolated_db):
        assert d.add_equity_snapshot(100.0, "test") is True
        assert d.add_equity_snapshot(100.0, "test") is False  # дубль
        assert d.add_equity_snapshot(100.001, "test") is False  # внутри eps
        assert d.add_equity_snapshot(101.0, "test") is True   # отличие
        conn = sqlite3.connect(isolated_db)
        n = conn.execute("SELECT COUNT(*) FROM equity_snapshots").fetchone()[0]
        conn.close()
        # 2 в init_db default нет, добавляем 2 уникальные
        assert n == 2


class TestSettingsWhitelist:
    """BUG-21: update_settings игнорирует невалидные ключи."""

    def test_rejects_unknown_key(self, isolated_db):
        d.update_settings({"evil_key": "pwn", "start_capital": "777"})
        s = d.get_settings()
        assert "evil_key" not in s
        assert s.get("start_capital") == "777"

    def test_only_whitelisted_pass(self, isolated_db):
        d.update_settings({"hax": 1, "rm_rf": 2, "__class__": "x"})
        s = d.get_settings()
        for k in ("hax", "rm_rf", "__class__"):
            assert k not in s


class TestManualTradeExternalId:
    """BUG-08: ручные сделки не должны дублироваться при двойном клике."""

    def test_unique_external_id_for_identical_manual_trades(self, isolated_db):
        trade = {
            "ts": "2026-05-26T10:00:00",
            "symbol": "BTCUSDT",
            "side": "LONG",
            "source": "manual",
            "pnl_usd": 100,
        }
        d.add_trade(dict(trade))
        d.add_trade(dict(trade))
        d.add_trade(dict(trade))
        conn = sqlite3.connect(isolated_db); conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT external_id FROM trades WHERE symbol='BTCUSDT'").fetchall()
        conn.close()
        assert len(rows) == 3, "три добавления должны дать три уникальные записи"
        ext_ids = [r["external_id"] for r in rows]
        assert len(set(ext_ids)) == 3, "все external_id должны быть уникальны"
        assert all(eid.startswith("manual-") for eid in ext_ids)

    def test_bitunix_trade_keeps_provided_external_id(self, isolated_db):
        trade = {
            "ts": "2026-05-26T10:00:00",
            "symbol": "BTCUSDT",
            "side": "SHORT",
            "source": "bitunix",
            "external_id": "pos-12345",
        }
        d.add_trade(dict(trade))
        d.add_trade(dict(trade))  # тот же external_id → INSERT OR IGNORE
        conn = sqlite3.connect(isolated_db); conn.row_factory = sqlite3.Row
        n = conn.execute("SELECT COUNT(*) FROM trades WHERE external_id=?", ("pos-12345",)).fetchone()[0]
        conn.close()
        assert n == 1, "при одинаковом external_id должна быть одна запись"
