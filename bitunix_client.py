"""Bitunix REST API client (futures)."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

import requests

BASE_FUTURES = "https://fapi.bitunix.com"
EP_ACCOUNT = "/api/v1/futures/account"
EP_TRADE_HISTORY = "/api/v1/futures/trade/get_history_trades"
EP_POSITION_HISTORY = "/api/v1/futures/position/get_history_positions"
EP_POSITION_OPEN = "/api/v1/futures/position/get_pending_positions"
EP_TICKERS = "/api/v1/futures/market/tickers"
# Bitunix не описывает депозиты в фьючерс-доке открыто. Перебираем варианты.
# Каждый элемент — (path, params_strategy):
#   "full"   — limit + skip + coin + startTime + endTime
#   "no_coin" — limit + skip + startTime + endTime (без coin)
#   "minimal" — только startTime + endTime
#   "empty"  — без параметров вообще
EP_DEPOSIT_CANDIDATES = [
    ("/api/v1/futures/account/deposit_records", "minimal"),
    ("/api/v1/futures/account/deposit_records", "empty"),
    ("/api/v1/futures/account/deposit/records", "minimal"),
    ("/api/v1/futures/capital/deposit/records", "minimal"),
    ("/api/v1/futures/account/transfer_records", "minimal"),
    ("/api/v1/futures/account/transfer/records", "minimal"),
    ("/api/v1/spot/v1/account/deposit/records", "minimal"),
    ("/api/v1/private/account/deposit_records", "minimal"),
    ("/api/v1/account/deposit_records", "minimal"),
]
EP_WITHDRAW_CANDIDATES = [
    ("/api/v1/futures/account/withdraw_records", "minimal"),
    ("/api/v1/futures/account/withdraw_records", "empty"),
    ("/api/v1/futures/account/withdraw/records", "minimal"),
    ("/api/v1/futures/capital/withdraw/records", "minimal"),
    ("/api/v1/spot/v1/account/withdraw/records", "minimal"),
    ("/api/v1/private/account/withdraw_records", "minimal"),
    ("/api/v1/account/withdraw_records", "minimal"),
]


class BitunixError(RuntimeError):
    pass


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _resolve_side(position_side, order_side, reduce_only: bool = False) -> str:
    """
    Возвращает 'LONG' / 'SHORT' / 'UNKNOWN' — направление ПОЗИЦИИ.

    Логика (BUG-02, аудит 2026-05-26):
      1. Если есть positionSide (LONG/SHORT) — используем его, это самая точная инфа.
      2. Иначе смотрим на order side (BUY/SELL):
         - reduce_only=False (открытие):  BUY → LONG,  SELL → SHORT
         - reduce_only=True  (закрытие):  BUY → SHORT (закрываем шорт),
                                          SELL → LONG  (закрываем лонг)
      3. Иначе 'UNKNOWN' — лучше не врать, чем подставлять LONG по умолчанию.
    """
    ps = (str(position_side or "")).upper()
    if ps in ("LONG", "OPEN_LONG"):
        return "LONG"
    if ps in ("SHORT", "OPEN_SHORT"):
        return "SHORT"
    os_ = (str(order_side or "")).upper()
    if os_ in ("LONG", "OPEN_LONG"):
        return "LONG"
    if os_ in ("SHORT", "OPEN_SHORT"):
        return "SHORT"
    if os_ == "BUY":
        return "SHORT" if reduce_only else "LONG"
    if os_ == "SELL":
        return "LONG" if reduce_only else "SHORT"
    return "UNKNOWN"


class BitunixClient:
    def __init__(self, api_key: str, api_secret: str, base_url: str = BASE_FUTURES, timeout: int = 15):
        self.api_key = api_key.strip()
        self.api_secret = api_secret.strip()
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.call_log: list[dict] = []  # сохраняем все вызовы HTTP для отладки
        # BUG-16: явный флаг, поддерживает ли биржа депозитные endpoint'ы
        self.deposits_api_supported: bool | None = None
        self.withdraws_api_supported: bool | None = None

    def _sign(self, query_params_str: str, body: str, nonce: str, ts: str) -> str:
        digest = _sha256_hex(nonce + ts + self.api_key + query_params_str + body)
        return _sha256_hex(digest + self.api_secret)

    def _request(self, method: str, path: str, params: dict | None = None, body: dict | None = None) -> Any:
        params = params or {}
        body_str = json.dumps(body, separators=(",", ":")) if body else ""
        sorted_keys = sorted(params.keys())
        query_params_str = "".join(f"{k}{params[k]}" for k in sorted_keys)
        nonce = uuid.uuid4().hex
        ts = str(int(time.time() * 1000))
        sign = self._sign(query_params_str, body_str, nonce, ts)
        headers = {
            "api-key": self.api_key,
            "sign": sign,
            "nonce": nonce,
            "timestamp": ts,
            "language": "en-US",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url}{path}"
        # В лог пишем headers без секретов (маскировка для last_sync_debug.json)
        safe_headers = {k: ("***" if k.lower() in ("api-key", "sign") else v) for k, v in headers.items()}
        log_entry = {"method": method.upper(), "url": url, "params": dict(params), "headers": safe_headers}
        try:
            resp = self.session.request(method.upper(), url, params=params or None, data=body_str or None, headers=headers, timeout=self.timeout)
            log_entry["status"] = resp.status_code
            log_entry["raw"] = resp.text[:4000]
        except Exception as e:
            log_entry["error"] = str(e)
            self.call_log.append(log_entry)
            raise BitunixError(f"network: {e}")
        self.call_log.append(log_entry)
        try:
            payload = resp.json()
        except Exception:
            raise BitunixError(f"Bitunix returned non-JSON: {resp.status_code} {resp.text[:200]}")
        code = payload.get("code")
        if code not in (0, "0", 200):
            raise BitunixError(f"code={code}, msg={payload.get('msg')}")
        return payload.get("data")

    def get_account_balance(self, margin_coin: str = "USDT") -> float:
        """Equity = available + margin + crossUnrealizedPNL + isolationUnrealizedPNL + bonus."""
        data = self._request("GET", EP_ACCOUNT, params={"marginCoin": margin_coin})
        if isinstance(data, list):
            data = data[0] if data else {}
        if not isinstance(data, dict):
            raise BitunixError(f"unexpected account response: {data}")
        for key in ("equity", "accountEquity", "totalEquity"):
            v = data.get(key)
            if v is not None:
                return float(v)
        available = float(data.get("available") or 0)
        margin = float(data.get("margin") or 0)
        cross_pnl = float(data.get("crossUnrealizedPNL") or 0)
        iso_pnl = float(data.get("isolationUnrealizedPNL") or 0)
        bonus = float(data.get("bonus") or 0)
        return available + margin + cross_pnl + iso_pnl + bonus

    def get_open_positions(self) -> list[dict]:
        """
        ШАГ 5 (audit 2026-05-26): открытые позиции с unrealized PnL.
        GET /api/v1/futures/position/get_pending_positions.
        Если эндпоинт недоступен — пробуем альтернативные имена.
        """
        candidates = [
            EP_POSITION_OPEN,
            "/api/v1/futures/position/list",
            "/api/v1/futures/position/get_pos",
        ]
        for ep in candidates:
            try:
                data = self._request("GET", ep, params={})
            except BitunixError:
                continue
            page = []
            if isinstance(data, dict):
                page = data.get("positionList") or data.get("list") or data.get("positions") or []
            elif isinstance(data, list):
                page = data
            if isinstance(page, list):
                return [self._normalize_open_position(p) for p in page]
        return []

    @staticmethod
    def _normalize_open_position(p: dict) -> dict:
        """Нормализация ОТКРЫТОЙ позиции (без exit_price, есть markPrice и unrealizedPNL)."""
        entry = float(p.get("avgOpenPrice") or p.get("entryPrice") or p.get("openPrice") or 0)
        mark = float(p.get("markPrice") or p.get("indexPrice") or p.get("lastPrice") or 0)
        qty = float(p.get("qty") or p.get("positionAmt") or p.get("size") or 0)
        leverage = float(p.get("leverage") or 1) or 1
        unreal = float(p.get("unrealizedPNL") or p.get("unrealizedPnl") or p.get("upnl") or 0)
        # Если unrealizedPNL не пришёл — считаем через mark
        side = _resolve_side(p.get("positionSide"), p.get("side"), reduce_only=False)
        if not unreal and entry and mark and qty:
            unreal = (mark - entry) * qty if side == "LONG" else (entry - mark) * qty
        margin = float(p.get("margin") or 0)
        if not margin and entry and qty and leverage > 0:
            margin = entry * qty / leverage
        pnl_pct = (unreal / margin * 100) if margin else 0
        ts_ms = p.get("ctime") or p.get("createTime")
        ts_iso = ""
        if ts_ms:
            try:
                ts_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(int(ts_ms) / 1000))
            except Exception:
                ts_iso = str(ts_ms)
        return {
            "symbol": p.get("symbol", ""),
            "side": side,
            "qty": qty,
            "entry_price": entry,
            "mark_price": mark,
            "leverage": leverage,
            "margin_usd": round(margin, 2),
            "unrealized_pnl_usd": round(unreal, 4),
            "unrealized_pnl_pct": round(pnl_pct, 2),
            "opened_at": ts_iso,
        }

    def _raw_position_history(self, start_ms: int | None, end_ms: int | None, limit: int) -> list[dict]:
        """
        GET /api/v1/futures/position/get_history_positions
        Возвращает data.positionList (см. https://openapidoc.bitunix.com/doc/position/get_history_positions.html)
        Limit max 100 — гоним пагинацией через skip.
        """
        out: list[dict] = []
        skip = 0
        page_size = min(100, max(10, int(limit)))
        max_pages = 20  # 20 * 100 = 2000 макс
        for _ in range(max_pages):
            params: dict[str, Any] = {"limit": page_size, "skip": skip}
            if start_ms:
                params["startTime"] = start_ms
            if end_ms:
                params["endTime"] = end_ms
            try:
                data = self._request("GET", EP_POSITION_HISTORY, params=params)
            except BitunixError:
                break
            page: list = []
            if isinstance(data, dict):
                page = data.get("positionList") or data.get("list") or []
            elif isinstance(data, list):
                page = data
            if not page:
                break
            out.extend(page)
            if len(page) < page_size:
                break
            skip += page_size
        return out

    def _raw_trade_history(self, start_ms: int | None, end_ms: int | None, limit: int) -> list[dict]:
        """
        GET /api/v1/futures/trade/get_history_trades
        Возвращает data.tradeList (см. https://openapidoc.bitunix.com/doc/trade/get_history_trades.html)
        """
        out: list[dict] = []
        skip = 0
        page_size = min(100, max(10, int(limit)))
        max_pages = 20
        for _ in range(max_pages):
            params: dict[str, Any] = {"limit": page_size, "skip": skip}
            if start_ms:
                params["startTime"] = start_ms
            if end_ms:
                params["endTime"] = end_ms
            try:
                data = self._request("GET", EP_TRADE_HISTORY, params=params)
            except BitunixError:
                break
            page: list = []
            if isinstance(data, dict):
                page = data.get("tradeList") or data.get("list") or []
            elif isinstance(data, list):
                page = data
            if not page:
                break
            out.extend(page)
            if len(page) < page_size:
                break
            skip += page_size
        return out

    def get_trade_history(self, symbol: str | None = None, start_ms: int | None = None, end_ms: int | None = None, limit: int = 100) -> list[dict]:
        """
        ИСТОЧНИК ИСТИНЫ — position/get_history_positions: одна запись на закрытую
        позицию с правильным realizedPNL, fee и closePrice.

        trade/get_history_trades качается ТОЛЬКО для last_raw_trades (дебаг-дамп).
        В журнал сделок исполнения НЕ добавляются — иначе одна позиция учитывается
        дважды (BUG-01, аудит 2026-05-26).
        """
        positions = self._raw_position_history(start_ms, end_ms, limit)
        try:
            trades = self._raw_trade_history(start_ms, end_ms, limit)
        except Exception:
            trades = []
        merged: dict[str, dict] = {}
        for p in positions:
            n = self._normalize_position(p)
            if n.get("external_id"):
                merged[n["external_id"]] = n
        # сохраним сырой ответ для отладки
        self.last_raw_positions = positions
        self.last_raw_trades = trades
        return list(merged.values())

    @staticmethod
    def _normalize_position(p: dict) -> dict:
        """
        Нормализуем ответ /api/v1/futures/position/get_history_positions.

        BUG-02 (аудит 2026-05-26): positionSide точнее side — берём его в первую очередь.
        BUG-03 (единая формула PnL%): pnl_pct = realizedPNL / margin × 100,
          где margin = entry × qty / leverage. На большом плече цифры будут крупные —
          это корректно (% от вложенной маржи). UI клипит на ±999% для читаемости.
        """
        ts_ms = p.get("mtime") or p.get("ctime") or p.get("createTime") or p.get("closeTime")
        ts_iso = ""
        if ts_ms:
            try:
                ts_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(int(ts_ms) / 1000))
            except Exception:
                ts_iso = str(ts_ms)
        pnl = float(p.get("realizedPNL") or p.get("realisedPnl") or p.get("pnl") or 0)
        fee = float(p.get("fee") or p.get("commission") or p.get("totalFee") or 0)
        funding = float(p.get("funding") or 0)
        entry = float(p.get("entryPrice") or p.get("avgOpenPrice") or p.get("openPrice") or 0)
        exit_ = float(p.get("closePrice") or p.get("avgClosePrice") or p.get("exitPrice") or 0)
        qty = float(p.get("maxQty") or p.get("qty") or p.get("size") or p.get("positionAmt") or 0)
        leverage = float(p.get("leverage") or 1) or 1
        side = _resolve_side(p.get("positionSide"), p.get("side"), reduce_only=False)
        # Если exit_price не пришёл, но знаем entry, qty и pnl — реконструируем
        if not exit_ and entry and qty and pnl:
            try:
                if side == "LONG":
                    exit_ = entry + (pnl + fee) / qty
                else:
                    exit_ = entry - (pnl + fee) / qty
                if exit_ < 0:
                    exit_ = 0
            except Exception:
                exit_ = 0
        notional = entry * qty
        margin = notional / leverage if leverage > 0 else notional
        pnl_pct = (pnl / margin * 100) if margin else 0
        return {
            "external_id": str(p.get("positionId") or p.get("id") or p.get("orderId") or ""),
            "ts": ts_iso,
            "symbol": p.get("symbol", ""),
            "side": side,
            "entry_price": entry,
            "exit_price": exit_,
            "qty": qty,
            "pnl_usd": pnl,
            "pnl_pct": pnl_pct,
            "fee_usd": fee,
            "funding_usd": funding,  # #36 отдельно от fee
            "source": "bitunix",
        }

    @staticmethod
    def _normalize_trade(t: dict) -> dict:
        """
        Нормализация одиночного исполнения (fill).
        ВНИМАНИЕ: эта функция больше НЕ используется для записи в БД (см. get_trade_history,
        BUG-01). Оставлена для дебаг-дампа и потенциального matching-а с позициями.

        BUG-02: для fill side=BUY/SELL — это направление ордера. С reduceOnly=true
          BUY закрывает SHORT, SELL закрывает LONG. positionSide точнее.
        BUG-03: PnL% от маржи — единая формула на весь проект.
        """
        ts_ms = t.get("ctime") or t.get("createTime") or t.get("time") or t.get("updateTime")
        ts_iso = ""
        if ts_ms:
            try:
                ts_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(int(ts_ms) / 1000))
            except Exception:
                ts_iso = str(ts_ms)
        pnl = float(t.get("realizedPNL") or t.get("pnl") or t.get("profit") or 0)
        fee = float(t.get("fee") or t.get("commission") or 0)
        entry = float(t.get("avgPrice") or t.get("entryPrice") or t.get("price") or 0)
        exit_ = float(t.get("closePrice") or t.get("exitPrice") or 0)
        qty = float(t.get("qty") or t.get("size") or t.get("volume") or 0)
        leverage = float(t.get("leverage") or 1) or 1
        side = _resolve_side(
            t.get("positionSide"),
            t.get("side"),
            reduce_only=bool(t.get("reduceOnly")),
        )
        notional = entry * qty
        margin = notional / leverage if leverage > 0 else notional
        pnl_pct = (pnl / margin * 100) if margin else 0
        return {
            "external_id": str(t.get("tradeId") or t.get("orderId") or t.get("id") or ""),
            "ts": ts_iso,
            "symbol": t.get("symbol", ""),
            "side": side,
            "entry_price": entry,
            "exit_price": exit_,
            "qty": qty,
            "pnl_usd": pnl,
            "pnl_pct": pnl_pct,
            "fee_usd": fee,
            "source": "bitunix",
        }

    def _build_movement_params(self, strategy: str, start_ms: int | None, end_ms: int | None,
                               coin: str, skip: int, page_size: int) -> dict:
        """Собирает params под нужную стратегию endpoint-а."""
        if strategy == "empty":
            return {}
        p: dict[str, Any] = {}
        if strategy != "minimal":
            p["limit"] = page_size
            p["skip"] = skip
        if strategy == "full":
            p["coin"] = coin
        if start_ms:
            p["startTime"] = start_ms
        if end_ms:
            p["endTime"] = end_ms
        return p

    def _movement_history(self, endpoint_candidates: list, kind: str,
                          start_ms: int | None = None, end_ms: int | None = None,
                          coin: str = "USDT", page_size: int = 100, max_pages: int = 20) -> list[dict]:
        """
        Универсальный сборщик депозитов/выводов. Bitunix не описывает депозиты
        в публичной фьючерс-доке, поэтому перебираем (endpoint, params-стратегия).

        BUG-16 (аудит 2026-05-26): выставляем self.{kind}s_api_supported.
        True  — endpoint вернул данные или валидное пустое.
        False — все endpoint'ы вернули ошибку (биржа не поддерживает).
        """
        any_success_with_data = False
        any_success_empty = False
        for ep, strategy in endpoint_candidates:
            collected: list[dict] = []
            skip = 0
            success = False
            for _ in range(max_pages):
                params = self._build_movement_params(strategy, start_ms, end_ms, coin, skip, page_size)
                try:
                    data = self._request("GET", ep, params=params)
                    success = True
                except BitunixError:
                    success = False
                    break  # этот endpoint/стратегия не работает — пробуем следующий
                page: list = []
                if isinstance(data, dict):
                    page = (data.get("list") or data.get("records")
                            or data.get("depositList") or data.get("withdrawList") or [])
                elif isinstance(data, list):
                    page = data
                if not page:
                    break
                collected.extend(page)
                if len(page) < page_size:
                    break
                skip += page_size
            if success:
                if collected:
                    any_success_with_data = True
                    setattr(self, f"{kind}s_api_supported", True)
                    return [self._normalize_movement(m, kind) for m in collected]
                else:
                    any_success_empty = True
        setattr(self, f"{kind}s_api_supported", any_success_with_data or any_success_empty)
        return []

    def get_deposits(self, start_ms: int | None = None, end_ms: int | None = None,
                     coin: str = "USDT", limit: int = 100) -> list[dict]:
        return self._movement_history(EP_DEPOSIT_CANDIDATES, "deposit",
                                       start_ms=start_ms, end_ms=end_ms, coin=coin)

    def get_withdrawals(self, start_ms: int | None = None, end_ms: int | None = None,
                        coin: str = "USDT", limit: int = 100) -> list[dict]:
        return self._movement_history(EP_WITHDRAW_CANDIDATES, "withdraw",
                                       start_ms=start_ms, end_ms=end_ms, coin=coin)

    @staticmethod
    def _normalize_movement(m: dict, kind: str) -> dict:
        ts_ms = m.get("ctime") or m.get("createTime") or m.get("time")
        ts_iso = ""
        if ts_ms:
            try:
                ts_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(int(ts_ms) / 1000))
            except Exception:
                ts_iso = str(ts_ms)
        return {
            "external_id": str(m.get("id") or m.get("txId") or ""),
            "ts": ts_iso,
            "kind": kind,
            "amount_usd": float(m.get("amount") or m.get("value") or 0),
            "note": m.get("coin", ""),
            "source": "bitunix",
        }
