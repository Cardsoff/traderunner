"""Тесты на нормализацию ответов Bitunix (BUG-01, BUG-02, BUG-03)."""
import pytest
from bitunix_client import BitunixClient, _resolve_side


class TestResolveSide:
    """BUG-02: правильное определение направления позиции."""

    def test_position_side_long(self):
        assert _resolve_side("LONG", "BUY") == "LONG"

    def test_position_side_short(self):
        assert _resolve_side("SHORT", "SELL") == "SHORT"

    def test_buy_open(self):
        # Открытие BUY (reduce_only=False) → LONG
        assert _resolve_side(None, "BUY", reduce_only=False) == "LONG"

    def test_buy_close_short(self):
        # BUY с reduceOnly=True закрывает SHORT
        assert _resolve_side(None, "BUY", reduce_only=True) == "SHORT"

    def test_sell_open(self):
        assert _resolve_side(None, "SELL", reduce_only=False) == "SHORT"

    def test_sell_close_long(self):
        assert _resolve_side(None, "SELL", reduce_only=True) == "LONG"

    def test_unknown(self):
        # Раньше дефолт был LONG (опасно). Теперь UNKNOWN.
        assert _resolve_side(None, None) == "UNKNOWN"
        assert _resolve_side("", "") == "UNKNOWN"


class TestNormalizePosition:
    """BUG-02 + BUG-03: реальный пример SHORT-позиции с биржи."""

    BTCUSDT_SHORT = {
        "positionId": "4465356755365164106",
        "symbol": "BTCUSDT",
        "side": "SELL",
        "positionSide": None,
        "maxQty": "0.0262",
        "entryPrice": "76524.2",
        "closePrice": "76943.9",
        "leverage": "200",
        "fee": "1.50788991",
        "funding": "0",
        "realizedPNL": "-18.26540991",
        "ctime": "1779638906000",
        "mtime": "1779660695000",
    }

    def test_side_is_short_not_long(self):
        n = BitunixClient._normalize_position(self.BTCUSDT_SHORT)
        # BUG-02: side=SELL должен преобразоваться в SHORT, не LONG
        assert n["side"] == "SHORT"

    def test_pnl_pct_from_margin(self):
        # BUG-03: pnl_pct считается от маржи (entry*qty/leverage), не от номинала
        n = BitunixClient._normalize_position(self.BTCUSDT_SHORT)
        margin = 76524.2 * 0.0262 / 200  # ~10.02$
        expected = -18.26540991 / margin * 100  # ~-182.2%
        assert abs(n["pnl_pct"] - expected) < 0.01

    def test_external_id_from_position_id(self):
        # BUG-01: ext_id из positionId, не из tradeId
        n = BitunixClient._normalize_position(self.BTCUSDT_SHORT)
        assert n["external_id"] == "4465356755365164106"


class TestNormalizeTrade:
    """BUG-02: trade-fill с reduceOnly=True должен правильно определять side."""

    def test_buy_reduce_only_closes_short(self):
        fill = {
            "tradeId": "9999",
            "symbol": "BTCUSDT",
            "side": "BUY",
            "reduceOnly": True,
            "qty": "0.0262",
            "price": "76943.9",
            "leverage": 200,
            "fee": "0.5",
            "realizedPNL": "-16.75",
            "ctime": "1779660695000",
        }
        n = BitunixClient._normalize_trade(fill)
        # Раньше bug мапил BUY → LONG, теперь корректно SHORT
        assert n["side"] == "SHORT"


class TestGetTradeHistoryNoDoubleCounting:
    """BUG-01: одна закрытая позиция не должна попасть в результат дважды."""

    def test_positions_only_no_trades_double_count(self):
        # Симулируем: одна позиция + один fill для неё. Должна быть одна запись.
        client = BitunixClient("k", "s")

        # Подменяем сетевые методы
        client._raw_position_history = lambda *a, **k: [TestNormalizePosition.BTCUSDT_SHORT]
        client._raw_trade_history = lambda *a, **k: [{
            "tradeId": "9999", "symbol": "BTCUSDT", "side": "BUY",
            "reduceOnly": True, "qty": "0.0262", "price": "76943.9",
            "leverage": 200, "fee": "0.5", "realizedPNL": "-16.75",
            "ctime": "1779660695000",
        }]
        result = client.get_trade_history(start_ms=0, end_ms=99999999999)
        assert len(result) == 1, f"BUG-01: expected 1 trade, got {len(result)}"
        assert result[0]["side"] == "SHORT"
        assert result[0]["external_id"] == "4465356755365164106"
