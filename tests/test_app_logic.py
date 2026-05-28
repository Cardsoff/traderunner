"""Тесты на бизнес-логику app.py — BUG-09 (calendar months), BUG-11 (MDD)."""
import importlib.util
from datetime import datetime
from pathlib import Path


def _load_app():
    """Импортируем app.py без запуска Flask."""
    spec = importlib.util.spec_from_file_location(
        "app_mod", str(Path(__file__).resolve().parent.parent / "app.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


app = _load_app()


class TestAddMonths:
    """BUG-09: календарные месяцы, а не 30 дней."""

    def test_zero_months_returns_same_date(self):
        d = datetime(2026, 5, 26)
        assert app._add_months(d, 0) == d

    def test_plus_one_month(self):
        assert app._add_months(datetime(2026, 1, 15), 1) == datetime(2026, 2, 15)

    def test_year_wrap(self):
        assert app._add_months(datetime(2026, 12, 5), 1) == datetime(2027, 1, 5)

    def test_jan_31_plus_1_clips_to_feb_28(self):
        # 31 января + 1 = 28 февраля (не 31 февраля, не 3 марта)
        assert app._add_months(datetime(2026, 1, 31), 1) == datetime(2026, 2, 28)

    def test_plus_12_months(self):
        assert app._add_months(datetime(2026, 5, 26), 12) == datetime(2027, 5, 26)


class TestComputeMaxDrawdown:
    """BUG-11: DD считается от cumulative net P&L, не от closing equity."""

    def test_no_months_returns_zero(self, monkeypatch, isolated_db):
        import database as d
        monkeypatch.setattr(app, "db", d)
        assert app.compute_max_drawdown([]) == 0.0

    def test_deposit_does_not_create_fake_peak(self, monkeypatch, isolated_db):
        """Главный кейс BUG-11: депозит +1000 не должен создавать пик."""
        import database as d
        monkeypatch.setattr(app, "db", d)
        d.update_settings({"start_capital": "1000"})
        # Месяцы: +100 PnL, +50 PnL (но в этом же месяце +1000 депозит), -80 PnL
        # Старая формула: closing скачет с 1100 до 2150 (из-за депозита) → peak=2150,
        #   потом 2070 → DD = (2150-2070)/2150 = 3.7%
        # Новая формула: cum_pnl = 100, 150, 70 → peak=150, max_dd_abs=80,
        #   denom = 1000+150 = 1150, pct = 80/1150*100 ≈ 6.96%
        # Важно: depозит не «зачёлся» как пик.
        months = [
            {"net_pnl": 100, "closing": 1100},
            {"net_pnl": 50,  "closing": 2150},
            {"net_pnl": -80, "closing": 2070},
        ]
        mdd = app.compute_max_drawdown(months)
        assert 6.5 < mdd < 7.5, f"expected ~6.96%, got {mdd}"

    def test_no_drawdown_when_only_growing(self, monkeypatch, isolated_db):
        import database as d
        monkeypatch.setattr(app, "db", d)
        d.update_settings({"start_capital": "1000"})
        months = [
            {"net_pnl": 100, "closing": 1100},
            {"net_pnl": 200, "closing": 1300},
            {"net_pnl": 50,  "closing": 1350},
        ]
        assert app.compute_max_drawdown(months) == 0.0

    def test_clipped_at_100_percent(self, monkeypatch, isolated_db):
        import database as d
        monkeypatch.setattr(app, "db", d)
        d.update_settings({"start_capital": "100"})
        # Большой выигрыш потом всё потерять — DD близок к 100%
        months = [
            {"net_pnl": 10000, "closing": 10100},
            {"net_pnl": -10000, "closing": 100},
        ]
        mdd = app.compute_max_drawdown(months)
        assert mdd <= 100.0
