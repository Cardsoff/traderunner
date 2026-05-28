"""Crypto Trading Planner v3 - Flask backend."""
import configparser
import csv
import io
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


def _add_months(dt, months):
    """
    BUG-09 (audit 2026-05-26): прибавляем календарные месяцы вместо 30 дней,
    чтобы план совпадал с реальными месяцами факта. Если день не существует
    в целевом месяце (31 янв + 1 = 28/29 фев) — клипим к последнему дню.
    """
    if months == 0:
        return dt
    y = dt.year + (dt.month - 1 + months) // 12
    m = (dt.month - 1 + months) % 12 + 1
    if m == 12:
        next_first = datetime(y + 1, 1, 1)
    else:
        next_first = datetime(y, m + 1, 1)
    last_day = (next_first - timedelta(days=1)).day
    d = min(dt.day, last_day)
    return dt.replace(year=y, month=m, day=d)

from flask import Flask, jsonify, render_template, request, Response

import database as db
from bitunix_client import BitunixClient, BitunixError

APP_DIR = Path(__file__).parent
CONFIG_PATH = APP_DIR / "config.ini"
app = Flask(__name__, static_folder="static", template_folder="templates")
# Авто-перезагрузка templates и static без рестарта сервера
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True
# Не кешировать статику в development
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
# #28 CSRF: secret_key для session (генерится при первом запуске, сохраняется в settings)
import secrets as _csrf_secrets
import os as _envos
_sk = _envos.environ.get('FLASK_SECRET_KEY', '').strip()
if not _sk:
    try:
        _sk = db._get_global_setting('flask_secret_key')
    except Exception:
        _sk = None
if not _sk:
    _sk = _csrf_secrets.token_hex(32)
    try:
        db._set_global_setting('flask_secret_key', _sk)
    except Exception:
        pass
app.secret_key = _sk or 'dev-fallback-key'

# === PACEMAKER v4.0: SQLAlchemy + Flask-Login + DATABASE_URL ===
from flask import g, session, redirect, url_for
from flask_login import LoginManager, current_user, login_required as _login_required
from models import db as orm_db, User

import os as _os
_db_url = _os.environ.get('DATABASE_URL', f"sqlite:///{(APP_DIR / 'planner.db').as_posix()}")
if _db_url.startswith('postgres://'):
    _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
orm_db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth.login"
login_manager.login_message = "Войди чтобы продолжить"
login_manager.login_message_category = "info"


@login_manager.user_loader
def _load_user(user_id):
    return orm_db.session.get(User, int(user_id))


@app.before_request
def _set_g_user():
    if current_user.is_authenticated:
        g.user_id = current_user.id
    else:
        g.user_id = None


from auth import auth_bp
app.register_blueprint(auth_bp)


# === ФАЗА 2: LOGGING с rotation (2026-05-26) ===
import logging
from logging.handlers import RotatingFileHandler
LOGS_DIR = APP_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)
_log_handler = RotatingFileHandler(
    LOGS_DIR / "app.log",
    maxBytes=2_000_000,  # 2 MB на файл
    backupCount=5,        # храним 5 ротированных
    encoding="utf-8",
)
_log_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
))
_log_handler.setLevel(logging.INFO)
# Подключаем к Flask + к root
app.logger.addHandler(_log_handler)
app.logger.setLevel(logging.INFO)
logging.getLogger().addHandler(_log_handler)
logging.getLogger().setLevel(logging.INFO)


def _mask_secret(s: str, prefix: int = 4, suffix: int = 4) -> str:
    """Маскирует секрет для логов: 'abcdef...xyz' → 'abcd...wxyz'."""
    if not s:
        return "(empty)"
    if len(s) <= prefix + suffix + 4:
        return "***"
    return s[:prefix] + "..." + s[-suffix:]


# === ФАЗА 2: CSRF защита (2026-05-26) ===
# Простая реализация через проверку Origin для всех POST/PATCH/DELETE.
# localhost-only приложение — этого достаточно чтобы блокировать атаки
# с других сайтов через fetch().
ALLOWED_ORIGINS = {
    "http://localhost:5000",
    "http://127.0.0.1:5000",
}

@app.before_request
def _csrf_check():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    origin = request.headers.get("Origin") or ""
    referer = request.headers.get("Referer") or ""
    # 1) Origin в whitelist (localhost для dev)
    if origin in ALLOWED_ORIGINS:
        return
    # 2) Same-origin: динамически — работает на любом домене (Railway, Render, свой)
    try:
        host_url = request.host_url.rstrip("/")
        if origin == host_url:
            return
        if referer.startswith(host_url + "/") or referer == host_url:
            return
    except Exception:
        pass
    # 3) Referer начинается с whitelist
    if any(referer.startswith(o + "/") for o in ALLOWED_ORIGINS) or any(referer == o for o in ALLOWED_ORIGINS):
        return
    # 4) С localhost (для curl-тестов и same-origin без Origin)
    remote = (request.remote_addr or "").strip()
    if remote in ("127.0.0.1", "::1", "localhost"):
        return
    app.logger.warning(
        "CSRF blocked %s %s (origin=%r, referer=%r, host=%r, ip=%s)",
        request.method, request.path, origin, referer, request.host_url, remote
    )
    return jsonify({"ok": False, "error": "CSRF check failed"}), 403


@app.route("/api/csrf-token")
def api_csrf_token():
    """#28 CSRF token из session (можно слать в X-CSRF-Token header)."""
    from flask import session as _sess
    import secrets as _sec
    if "csrf_token" not in _sess:
        _sess["csrf_token"] = _sec.token_urlsafe(32)
    return jsonify({"token": _sess["csrf_token"]})


def load_api_creds():
    """v4.0: per-user encrypted credentials.
    Возвращает (key, secret) только если юзер залогинен И ключи расшифровываются."""
    try:
        from crypto_keys import decrypt_secret, session_get_fernet_key
        fk = session_get_fernet_key(session)
        if not fk:
            return None
        settings = db.get_settings()
        enc_key = settings.get("bitunix_api_key", "")
        enc_secret = settings.get("bitunix_api_secret", "")
        if not enc_key or not enc_secret:
            return None
        key = decrypt_secret(enc_key, fk)
        sec = decrypt_secret(enc_secret, fk)
        if not key or not sec:
            return None
        return key.strip(), sec.strip()
    except Exception as _e:
        try:
            app.logger.warning(f"load_api_creds error: {_e}")
        except Exception:
            pass
        return None


def month_key(ts):
    if not ts:
        return ""
    try:
        return datetime.fromisoformat(ts[:19]).strftime("%Y-%m")
    except Exception:
        return ts[:7]


def _parse_date(s):
    return datetime.strptime(s, "%Y-%m-%d")


def _resolved_scope():
    """Default scope: учитываем все сделки (фильтрация — на уровне endpoint-ов)."""
    return None, None


def _scope_from_request(req):
    """
    Универсальный парсер фильтра для /api/trades, /api/deposits, /api/dashboard.
    Принимает:
      ?from=YYYY-MM-DD
      ?to=YYYY-MM-DD
      ?goal_id=<int>  (диапазон [created_at..achieved_at]; для активной — [created_at..сегодня])
      ?goal_ids=<int>,<int>,... (объединение)
    Возвращает (start_dt | None, end_dt_exclusive | None).
    """
    if req is None:
        return None, None
    start_dt = None
    end_dt = None
    f = (req.args.get("from") or "").strip()
    t = (req.args.get("to") or "").strip()
    if f:
        try: start_dt = _parse_date(f)
        except Exception: start_dt = None
    if t:
        try: end_dt = _parse_date(t) + timedelta(days=1)
        except Exception: end_dt = None
    gid = (req.args.get("goal_id") or "").strip()
    gids = (req.args.get("goal_ids") or "").strip()
    chosen = []
    if gid:
        try: chosen.append(int(gid))
        except Exception: pass
    if gids:
        for x in gids.split(","):
            try: chosen.append(int(x.strip()))
            except Exception: pass
    if chosen:
        # объединяем диапазоны выбранных целей
        all_goals = []
        try:
            ag = db.get_active_goal()
            if ag: all_goals.append(ag)
        except Exception: pass
        try:
            for g in (db.list_goals_archive() or []):
                all_goals.append(g)
        except Exception: pass
        goals_map = {g["id"]: g for g in all_goals if g.get("id") is not None}
        starts = []
        ends = []
        for gid in chosen:
            g = goals_map.get(gid)
            if not g: continue
            try:
                s = _parse_date(g["created_at"]) if g.get("created_at") else None
                e = _parse_date(g["achieved_at"]) + timedelta(days=1) if g.get("achieved_at") else None
            except Exception:
                s = None; e = None
            if s: starts.append(s)
            if e: ends.append(e)
        if starts:
            gs = min(starts)
            if not start_dt or gs > start_dt: start_dt = gs
        if ends:
            ge = max(ends)
            if not end_dt or ge < end_dt: end_dt = ge
    return start_dt, end_dt


def _filter_by_scope(items, start_dt, end_dt):
    """Универсальный фильтр для trades/deposits — по ts."""
    out = []
    for it in items:
        ts_raw = it.get("ts") if isinstance(it, dict) else None
        if not ts_raw:
            continue
        try:
            ts = datetime.fromisoformat(ts_raw[:19])
        except Exception:
            continue
        if start_dt and ts < start_dt: continue
        if end_dt and ts >= end_dt: continue
        out.append(it)
    return out


def trades_in_scope():
    start_dt, end_dt = _resolved_scope()
    out = []
    for t in db.list_trades():
        if not t["ts"]:
            continue
        try:
            ts = datetime.fromisoformat(t["ts"][:19])
        except Exception:
            continue
        if start_dt and ts < start_dt:
            continue
        if end_dt and ts >= end_dt:
            continue
        out.append(t)
    return out


def deposits_in_scope():
    start_dt, end_dt = _resolved_scope()
    out = []
    for d in db.list_deposits():
        if not d.get("ts"):
            continue
        try:
            ts = datetime.fromisoformat(d["ts"][:19] if len(d["ts"]) > 10 else d["ts"])
        except Exception:
            continue
        if start_dt and ts < start_dt:
            continue
        if end_dt and ts >= end_dt:
            continue
        out.append(d)
    return out


def get_effective_start_capital():
    sc = float(db.get_settings().get("start_capital", 0) or 0)
    if sc > 0:
        return sc
    snap = db.latest_equity()
    return float(snap) if snap is not None else 0.0


def build_plan(scenario_pct):
    settings = db.get_settings()
    goal = db.get_active_goal()
    if not goal:
        return []
    start_cap = get_effective_start_capital()
    goal_amt = float(goal["amount"])
    # monthly_deposit живёт на цели (фоллбэк — settings для совместимости со старыми БД)
    try:
        dep = float(goal.get("monthly_deposit") if goal.get("monthly_deposit") is not None else 0)
    except Exception:
        dep = 0.0
    if not dep:
        try:
            dep = float(settings.get("monthly_deposit") or 0)
        except Exception:
            dep = 0.0
    r = float(scenario_pct) / 100
    # ПЕРЕРАБОТКА: план привязан к активной цели — start_dt = goal.created_at.
    # Если у цели нет даты — fallback на settings.start_date или сегодня.
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    start_dt = None
    try:
        if goal.get("created_at"):
            start_dt = _parse_date(goal["created_at"])
    except Exception:
        start_dt = None
    if not start_dt:
        try:
            start_dt = _parse_date(settings["start_date"])
        except Exception:
            start_dt = today
    if start_dt > today:
        start_dt = today
    plan = []
    cap = start_cap
    m = 0
    while m < 120:
        m += 1
        opening = cap
        deposit = dep if m > 1 else 0
        after = opening + deposit
        profit = after * r
        closing = after + profit
        d = _add_months(start_dt, m - 1)
        plan.append({
            "month": m,
            "date": d.strftime("%Y-%m-%d"),
            "label": d.strftime("%b %y"),
            "deposit": round(deposit, 2),
            "opening": round(opening, 2),
            "profit_usd": round(profit, 2),
            "return_pct": round(r * 100, 2),
            "closing": round(closing, 2),
            "pct_of_goal": round(closing / goal_amt * 100, 2) if goal_amt else 0,
        })
        cap = closing
        if closing >= goal_amt and m >= 6:
            break
    return plan


def compute_actual():
    settings = db.get_settings()
    goal = db.get_active_goal()
    start_cap = get_effective_start_capital()
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    # ПЕРЕРАБОТКА: actual привязан к активной цели — start_dt = goal.created_at.
    start_dt = None
    try:
        if goal and goal.get("created_at"):
            start_dt = _parse_date(goal["created_at"])
    except Exception:
        start_dt = None
    if not start_dt:
        try:
            start_dt = _parse_date(settings["start_date"])
        except Exception:
            start_dt = None
    if not start_dt or start_dt > today:
        # fallback: самая ранняя сделка или сегодня
        trades_all = db.list_trades()
        earliest_ts = None
        for t in trades_all:
            if t.get("ts"):
                try:
                    ts = datetime.fromisoformat(t["ts"][:19])
                    if earliest_ts is None or ts < earliest_ts:
                        earliest_ts = ts
                except Exception:
                    pass
        start_dt = earliest_ts if earliest_ts else today
    # ПРАВКА: фильтруем сделки/депозиты строго по датам активной цели.
    # Для первого месяца цели — берём только сделки начиная с goal.created_at (а не с 1-го числа).
    # Для месяца с achieved_at — только до achieved_at включительно.
    goal_start_dt = start_dt  # уже = goal.created_at (или fallback)
    goal_end_dt = None
    if goal and goal.get("achieved_at"):
        try:
            goal_end_dt = _parse_date(goal["achieved_at"]) + timedelta(days=1)  # включительно
        except Exception:
            goal_end_dt = None
    def _in_goal_range(ts_str):
        try:
            ts = datetime.fromisoformat(ts_str[:19])
        except Exception:
            return False
        if goal_start_dt and ts < goal_start_dt:
            return False
        if goal_end_dt and ts >= goal_end_dt:
            return False
        return True
    trades = [t for t in trades_in_scope() if t.get("ts") and _in_goal_range(t["ts"])]
    deposits = [d for d in deposits_in_scope() if d.get("ts") and _in_goal_range(d["ts"])]
    by_month = defaultdict(lambda: {"pnl": 0, "fee": 0, "count": 0, "wins": 0, "losses": 0, "dep": 0, "wd": 0})
    for t in trades:
        k = month_key(t["ts"])
        m = by_month[k]
        p = float(t["pnl_usd"] or 0)
        m["pnl"] += p
        m["fee"] += float(t["fee_usd"] or 0)
        m["count"] += 1
        if p > 0:
            m["wins"] += 1
        elif p < 0:
            m["losses"] += 1
    for d in deposits:
        k = month_key(d["ts"])
        m = by_month[k]
        if d["kind"] == "deposit":
            m["dep"] += float(d["amount_usd"] or 0)
        else:
            m["wd"] += float(d["amount_usd"] or 0)
    months = []
    eq = start_cap
    today = datetime.utcnow()
    cur = start_dt.replace(day=1)
    cap = today.replace(day=1)
    while cur <= cap:
        k = cur.strftime("%Y-%m")
        mm = by_month[k]
        opening = eq
        net = mm["pnl"] - mm["fee"]
        dep_net = mm["dep"] - mm["wd"]
        closing = opening + dep_net + net
        # return_pct: процент от опening + dep_net. Если знаменатель <=0, но есть прибыль —
        # считаем от closing (защита от opening=0 при стартовом капитале 0).
        denom = opening + dep_net
        if denom > 0:
            r_pct = net / denom * 100
        elif closing > 0:
            r_pct = net / closing * 100
        else:
            r_pct = 0
        decisive_m = mm["wins"] + mm["losses"]
        winrate = (mm["wins"] / decisive_m * 100) if decisive_m else 0
        months.append({
            "month_key": k,
            "label": cur.strftime("%b %y"),
            "deposit": round(dep_net, 2),
            "opening": round(opening, 2),
            "net_pnl": round(net, 2),
            "return_pct": round(r_pct, 2),
            "closing": round(closing, 2),
            "trades": mm["count"],
            "winrate": round(winrate, 1),
        })
        eq = closing
        if cur.month == 12:
            cur = cur.replace(year=cur.year + 1, month=1)
        else:
            cur = cur.replace(month=cur.month + 1)
        # ПЕРЕРАБОТКА: ограничиваем по achieved_at цели если есть
        if goal and goal.get("achieved_at"):
            try:
                ach_dt = _parse_date(goal["achieved_at"]).replace(day=1)
                if cur > ach_dt:
                    break
            except Exception:
                pass
    snap = db.latest_equity()
    current = snap if snap is not None else eq
    return {"current_equity": round(current, 2), "months": months}


def compute_stats(period):
    all_t = trades_in_scope()
    now = datetime.utcnow()
    cutoff = None
    if period == "D":
        cutoff = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == "W":
        cutoff = now - timedelta(days=7)
    elif period == "M":
        cutoff = now - timedelta(days=30)
    elif period == "Y":
        cutoff = now - timedelta(days=365)
    filt = [t for t in all_t if not cutoff or datetime.fromisoformat(t["ts"][:19]) >= cutoff]
    total = len(filt)
    wins = sum(1 for t in filt if (t["pnl_usd"] or 0) > 0)
    losses = sum(1 for t in filt if (t["pnl_usd"] or 0) < 0)
    pnl = sum(float(t["pnl_usd"] or 0) for t in filt)
    fee = sum(float(t["fee_usd"] or 0) for t in filt)
    net = pnl - fee
    best = max((float(t["pnl_usd"] or 0) for t in filt), default=0)
    worst = min((float(t["pnl_usd"] or 0) for t in filt), default=0)
    # Winrate считаем по сделкам с НЕНУЛЕВЫМ результатом (wins+losses), исключая break-even.
    # Это даёт согласованную метрику между основной статистикой и Win/Loss donut.
    decisive = wins + losses
    return {
        "total": total, "wins": wins, "losses": losses,
        "breakeven": total - decisive,
        "winrate": round(wins / decisive * 100, 1) if decisive else 0,
        "total_pnl": round(pnl, 2), "total_fee": round(fee, 2),
        "net_pnl": round(net, 2),
        "avg": round(net / total, 2) if total else 0,
        "best": round(best, 2), "worst": round(worst, 2),
    }


def compute_streak():
    """
    Возвращает три серии:
      - current: текущая серия от последней сделки (kind, count)
      - best_win:  лучшая серия побед подряд за период
      - best_loss: худшая серия поражений подряд за период
    UI показывает основную метрикой best_win, текущую — мелким шрифтом.
    """
    trades_desc = sorted(trades_in_scope(), key=lambda t: t["ts"], reverse=True)
    if not trades_desc:
        return {
            "kind": "none", "count": 0,
            "current_kind": "none", "current_count": 0,
            "best_win": 0, "best_loss": 0,
        }

    # ---- current (от самой свежей сделки) ----
    first_pnl = float(trades_desc[0]["pnl_usd"] or 0)
    if first_pnl == 0:
        cur_kind, cur_count = "none", 0
    else:
        cur_kind = "win" if first_pnl > 0 else "loss"
        cur_count = 0
        for t in trades_desc:
            p = float(t["pnl_usd"] or 0)
            if cur_kind == "win" and p > 0:
                cur_count += 1
            elif cur_kind == "loss" and p < 0:
                cur_count += 1
            else:
                break

    # ---- best series за всё время в scope (идём в хронологическом порядке) ----
    best_win = 0
    best_loss = 0
    run_win = 0
    run_loss = 0
    for t in reversed(trades_desc):  # от старых к новым
        p = float(t["pnl_usd"] or 0)
        if p > 0:
            run_win += 1
            run_loss = 0
            if run_win > best_win:
                best_win = run_win
        elif p < 0:
            run_loss += 1
            run_win = 0
            if run_loss > best_loss:
                best_loss = run_loss
        else:
            # break-even — серию не продолжает и не сбрасывает прямо противоположную,
            # но для простоты считаем как разрыв обеих серий
            run_win = 0
            run_loss = 0

    return {
        # legacy-поля для совместимости со старым фронтом
        "kind": cur_kind,
        "count": cur_count,
        # новые поля
        "current_kind": cur_kind,
        "current_count": cur_count,
        "best_win": best_win,
        "best_loss": best_loss,
    }


def compute_max_drawdown(months):
    """
    Max drawdown в % от пика КУМУЛЯТИВНОЙ ТОРГОВОЙ ПРИБЫЛИ (без депозитов).

    BUG-11 (audit 2026-05-26): раньше считали от closing equity, поэтому
    каждый депозит создавал «новый пик» и DD получался завышенным.
    Сейчас: накапливаем net_pnl (P&L − fee) по месяцам, ищем пик и
    максимальную просадку от пика. Это стандарт TradingView/MT5.

    Знаменатель для %: (стартовый капитал + пик cumulative net_pnl).
    Это даёт DD относительно базы трейдера, а не относительно нуля.
    """
    start = get_effective_start_capital()
    base = max(float(start or 0), 1.0)
    cum = 0.0
    peak = 0.0
    max_dd_abs = 0.0
    for m in months:
        cum += float(m.get("net_pnl") or 0)
        if cum > peak:
            peak = cum
        dd = peak - cum
        if dd > max_dd_abs:
            max_dd_abs = dd
    denom = base + peak
    if denom <= 0:
        return 0.0
    max_dd_pct = max_dd_abs / denom * 100
    max_dd_pct = min(max_dd_pct, 100.0)
    return round(max_dd_pct, 2)


def forecast_goal_date(current_eq):
    """
    Прогноз даты достижения цели. Возвращает:
      {date, months_left}                                  — нормально
      {date, months_left:0}                                — уже достигнута
      {unavailable: True, reason: 'no_goal' | 'no_capital_no_deposit' | 'no_growth' | 'too_far'}
    """
    settings = db.get_settings()
    goal = db.get_active_goal()
    if not goal:
        return {"unavailable": True, "reason": "no_goal"}
    goal_amt = float(goal.get("amount") or 0)
    if goal_amt <= 0:
        return {"unavailable": True, "reason": "no_goal"}
    # ШАГ-7 (audit fix): берём ТОЛЬКО goal.monthly_deposit, без fallback на settings.
    # settings.monthly_deposit — это «исторический» дефолт, к текущей цели может не относиться.
    try:
        dep = float(goal.get("monthly_deposit") if goal.get("monthly_deposit") is not None else 0)
    except Exception:
        dep = 0.0
    # r — берём только если ЯВНО задан, без fallback на 10
    r_raw = goal.get("monthly_return_pct")
    if r_raw is None or r_raw == "" or float(r_raw) <= 0:
        # Нет доходности — прогноз бессмысленный
        return {"unavailable": True, "reason": "no_growth"}
    r = float(r_raw) / 100
    if current_eq >= goal_amt:
        return {"date": datetime.utcnow().strftime("%Y-%m-%d"), "months_left": 0}
    # Если стартового капитала нет и взноса нет — расти неоткуда
    if current_eq <= 0 and dep <= 0:
        return {"unavailable": True, "reason": "no_capital_no_deposit"}
    cap = current_eq
    m = 0
    while cap < goal_amt and m < 600:
        m += 1
        new_cap = (cap + dep) * (1 + r)
        if new_cap <= cap:
            return {"unavailable": True, "reason": "no_growth"}
        cap = new_cap
    if m >= 600:
        return {"unavailable": True, "reason": "too_far"}
    d = _add_months(datetime.utcnow(), m)
    return {"date": d.strftime("%Y-%m-%d"), "months_left": m}


def discipline_for_month(actual_pct, plan_pct):
    if not plan_pct or plan_pct == 0:
        return {"tag": "none", "label": "-"}
    ratio = actual_pct / plan_pct
    if actual_pct < 0:
        return {"tag": "bad", "label": "loss"}
    if ratio < 0.5:
        return {"tag": "bad", "label": "behind"}
    if ratio > 1.5:
        return {"tag": "warn", "label": "high risk"}
    return {"tag": "ok", "label": "OK"}




def _trades_in_range(start_dt, end_dt):
    """Вернуть сделки в диапазоне [start_dt, end_dt] (end_dt включительно)."""
    out = []
    for t in db.list_trades():
        ts_raw = t.get("ts") or ""
        try:
            ts = datetime.fromisoformat(ts_raw[:19])
        except Exception:
            continue
        if start_dt and ts < start_dt:
            continue
        if end_dt and ts > end_dt:
            continue
        out.append(t)
    return out


def compute_streak_for_trades(trades_desc):
    """Та же логика что compute_streak, но на переданном списке (вместо trades_in_scope)."""
    if not trades_desc:
        return {"kind":"none","count":0,"current_kind":"none","current_count":0,
                "best_win":0,"best_loss":0}
    first_pnl = float(trades_desc[0]["pnl_usd"] or 0)
    if first_pnl == 0:
        cur_kind, cur_count = "none", 0
    else:
        cur_kind = "win" if first_pnl > 0 else "loss"
        cur_count = 0
        for t in trades_desc:
            p = float(t["pnl_usd"] or 0)
            if cur_kind == "win" and p > 0:
                cur_count += 1
            elif cur_kind == "loss" and p < 0:
                cur_count += 1
            else:
                break
    best_win = best_loss = run_win = run_loss = 0
    for t in reversed(trades_desc):
        p = float(t["pnl_usd"] or 0)
        if p > 0:
            run_win += 1; run_loss = 0
            if run_win > best_win: best_win = run_win
        elif p < 0:
            run_loss += 1; run_win = 0
            if run_loss > best_loss: best_loss = run_loss
        else:
            run_win = run_loss = 0
    return {"kind":cur_kind,"count":cur_count,"current_kind":cur_kind,
            "current_count":cur_count,"best_win":best_win,"best_loss":best_loss}


def compute_goal_metrics():
    """
    Метрики для карточки активной цели.
    Считается ТОЛЬКО за период [goal.created_at .. goal.achieved_at or today].
    Если сделок в этом периоде нет — is_empty_for_goal=True (UI покажет плейсхолдер).
    """
    goal = db.get_active_goal()
    if not goal or not goal.get("created_at"):
        return {"is_empty_for_goal": True, "reason": "no_goal"}
    try:
        start_dt = _parse_date(goal["created_at"])
    except Exception:
        return {"is_empty_for_goal": True, "reason": "bad_date"}
    if goal.get("achieved_at"):
        try:
            end_dt = _parse_date(goal["achieved_at"]) + timedelta(days=1)
        except Exception:
            end_dt = None
    else:
        end_dt = None  # активная — до сейчас
    trades = _trades_in_range(start_dt, end_dt)
    if not trades:
        return {"is_empty_for_goal": True, "reason": "no_trades_in_goal_range",
                "goal_start": goal.get("created_at")}
    # Stats
    wins = sum(1 for t in trades if (t["pnl_usd"] or 0) > 0)
    losses = sum(1 for t in trades if (t["pnl_usd"] or 0) < 0)
    pnl = sum(float(t["pnl_usd"] or 0) for t in trades)
    fee = sum(float(t["fee_usd"] or 0) for t in trades)
    net = pnl - fee
    total = len(trades)
    decisive = wins + losses
    winrate = (wins / decisive * 100) if decisive else 0
    # Streak (по сделкам в обратном порядке)
    trades_desc = sorted(trades, key=lambda t: t["ts"], reverse=True)
    streak = compute_streak_for_trades(trades_desc)
    # MDD по cumulative net pnl в рамках цели
    cum = 0.0; peak = 0.0; max_dd_abs = 0.0
    for t in sorted(trades, key=lambda x: x["ts"]):
        cum += float(t["pnl_usd"] or 0) - float(t["fee_usd"] or 0)
        if cum > peak: peak = cum
        dd = peak - cum
        if dd > max_dd_abs: max_dd_abs = dd
    base = max(float(get_effective_start_capital() or 0), 1.0)
    mdd_pct = min(max_dd_abs / (base + peak) * 100 if (base + peak) > 0 else 0, 100.0)
    return {
        "is_empty_for_goal": False,
        "goal_start": goal.get("created_at"),
        "total": total, "wins": wins, "losses": losses,
        "winrate": round(winrate, 1),
        "net_pnl": round(net, 2),
        "best_win": streak["best_win"], "best_loss": streak["best_loss"],
        "current_kind": streak["current_kind"], "current_count": streak["current_count"],
        "max_drawdown": round(mdd_pct, 2),
    }


@app.route("/")
@_login_required
def index():
    return render_template("index.html")


@app.route("/api/settings", methods=["GET", "POST"])
@_login_required
def api_settings():
    if request.method == "POST":
        payload = request.get_json(force=True) or {}
        # tracking_*_date больше не валидные ключи — игнорируем при записи
        payload.pop("tracking_start_date", None)
        payload.pop("tracking_end_date", None)
        # start_date в будущем — заменяем на сегодня
        sd = payload.get("start_date")
        if sd:
            try:
                today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                if _parse_date(sd) > today:
                    payload["start_date"] = today.strftime("%Y-%m-%d")
            except Exception:
                pass
        db.update_settings(payload)
    return jsonify(db.get_settings())


@app.route("/api/goal", methods=["GET", "PATCH", "DELETE"])
@_login_required
def api_goal():
    if request.method == "PATCH":
        db.update_active_goal(request.get_json(force=True) or {})
    elif request.method == "DELETE":
        db.delete_active_goal_and_create_empty()
    return jsonify(db.get_active_goal())


@app.route("/api/goal/archive", methods=["POST"])
@_login_required
def api_goal_archive():
    payload = request.get_json(force=True) or {}
    new_amt = float(payload.get("new_amount", 1000))
    new_name = payload.get("new_name")
    new_return = float(payload.get("new_return_pct", 10))
    db.archive_active_and_create_new(new_amt, new_name, new_return)
    return jsonify({"ok": True, "goal": db.get_active_goal()})


@app.route("/api/goals/archive", methods=["GET"])
@_login_required
def api_goals_archive_list():
    return jsonify(db.list_goals_archive())


@app.route("/api/setups", methods=["GET", "POST"])
@_login_required
def api_setups():
    if request.method == "POST":
        name = (request.get_json(force=True) or {}).get("name", "").strip().lower()
        if not name:
            return jsonify({"ok": False, "error": "empty"}), 400
        if len(name) > 20:
            return jsonify({"ok": False, "error": "too long"}), 400
        db.add_setup(name)
    return jsonify(db.list_setups())


@app.route("/api/setups/<name>", methods=["DELETE"])
@_login_required
def api_setup_delete(name):
    db.delete_setup(name)
    return jsonify(db.list_setups())


@app.route("/api/trades", methods=["GET", "POST"])
@_login_required
def api_trades():
    if request.method == "POST":
        payload = request.get_json(force=True) or {}
        if "ts" not in payload:
            payload["ts"] = datetime.utcnow().isoformat(timespec="seconds")
        db.add_trade(payload)
        return jsonify({"ok": True})
    start_dt, end_dt = _scope_from_request(request)
    trades = db.list_trades()
    if start_dt or end_dt:
        trades = _filter_by_scope(trades, start_dt, end_dt)
    # #29 pagination: ?limit=100&offset=0 (опционально)
    try:
        limit = int(request.args.get("limit") or 0)
    except Exception:
        limit = 0
    try:
        offset = int(request.args.get("offset") or 0)
    except Exception:
        offset = 0
    total = len(trades)
    if limit > 0:
        sliced = trades[offset:offset + limit]
        return jsonify({"items": sliced, "total": total, "offset": offset, "limit": limit})
    # Обратная совместимость — если лимита нет, возвращаем массив как раньше
    return jsonify(trades)


@app.route("/api/trades/<int:trade_id>", methods=["DELETE", "PATCH"])
@_login_required
def api_trade_one(trade_id):
    if request.method == "DELETE":
        db.delete_trade(trade_id)
    else:
        db.update_trade_fields(trade_id, request.get_json(force=True) or {})
    return jsonify({"ok": True})


@app.route("/api/trades/export.csv")
@_login_required
def api_trades_csv():
    trades = trades_in_scope()
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["ts", "symbol", "side", "setup", "entry_price", "exit_price", "qty", "pnl_usd", "pnl_pct", "fee_usd", "source", "note"]
    w.writerow(cols)
    for t in trades:
        w.writerow([t.get(c, "") if t.get(c) is not None else "" for c in cols])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=trades-" + datetime.utcnow().strftime('%Y-%m-%d') + ".csv"})


@app.route("/api/deposits", methods=["GET", "POST"])
@_login_required
def api_deposits():
    if request.method == "POST":
        payload = request.get_json(force=True) or {}
        # batch: список объектов через payload.batch
        if isinstance(payload.get("batch"), list):
            added = 0
            for d in payload["batch"]:
                if not d.get("ts"):
                    d["ts"] = datetime.utcnow().isoformat(timespec="seconds")
                if not d.get("kind"):
                    d["kind"] = "deposit"
                d.setdefault("source", "manual")
                d.setdefault("external_id", f"manual-{datetime.utcnow().timestamp()}-{added}")
                db.add_deposit(d); added += 1
            return jsonify({"ok": True, "added": added})
        if "ts" not in payload:
            payload["ts"] = datetime.utcnow().isoformat(timespec="seconds")
        db.add_deposit(payload)
        return jsonify({"ok": True})
    start_dt, end_dt = _scope_from_request(request)
    deps = db.list_deposits()
    if start_dt or end_dt:
        deps = _filter_by_scope(deps, start_dt, end_dt)
    return jsonify(deps)


@app.route("/api/deposits/<int:dep_id>", methods=["DELETE"])
@_login_required
def api_deposit_one(dep_id):
    db.delete_deposit(dep_id)
    return jsonify({"ok": True})


_DASHBOARD_CACHE = {"data": None, "ts": 0, "key": None}


@app.route("/api/dashboard")
@_login_required
def api_dashboard():
    # #32 Кэш на 10 сек по полному query-string
    import time as _t
    now = _t.time()
    cache_key = request.query_string.decode("utf-8")
    if (_DASHBOARD_CACHE["data"] is not None
            and _DASHBOARD_CACHE["key"] == cache_key
            and now - _DASHBOARD_CACHE["ts"] < 3):  # TTL 3 сек (было 10)
        return jsonify(_DASHBOARD_CACHE["data"])
    settings = db.get_settings()
    goal = db.get_active_goal()
    scenario = float(settings.get("scenario", settings.get("monthly_return_pct", 10)))
    # ?planfact_scope=active|all|archive — какие цели включить в План-vs-Факт
    planfact_scope = (request.args.get("planfact_scope") or "active").strip()
    plan = build_plan(scenario)
    actual = compute_actual()
    eq = actual["current_equity"]
    pct_to_goal = (eq / float(goal["amount"]) * 100) if goal and goal["amount"] else 0
    pf_rows = []
    months_above = 0
    months_below = 0
    total_dev = 0
    total_dev_pct = 0
    n = 0
    plan_pct_target = float(goal["monthly_return_pct"]) if goal else 10
    for i in range(max(len(plan), len(actual["months"]))):
        p = plan[i] if i < len(plan) else None
        a = actual["months"][i] if i < len(actual["months"]) else None
        if not p and not a:
            continue
        plan_close = p["closing"] if p else None
        fact_close = a["closing"] if a else None
        dev = None
        dev_pct = None
        if plan_close is not None and fact_close is not None:
            dev = fact_close - plan_close
            dev_pct = (dev / plan_close * 100) if plan_close else 0
            if dev > 0:
                months_above += 1
            elif dev < 0:
                months_below += 1
            total_dev += dev
            total_dev_pct += dev_pct
            n += 1
        disc = discipline_for_month(a["return_pct"], plan_pct_target) if a else {"tag": "none", "label": "-"}
        pf_rows.append({
            "label": (p["label"] if p else a["label"]),
            "plan_close": round(plan_close, 2) if plan_close is not None else None,
            "fact_close": round(fact_close, 2) if fact_close is not None else None,
            "dev": round(dev, 2) if dev is not None else None,
            "dev_pct": round(dev_pct, 2) if dev_pct is not None else None,
            "trades": a["trades"] if a else 0,
            "discipline": disc,
        })
    pf_summary = {
        "months_above": months_above,
        "months_below": months_below,
        "avg_dev": round(total_dev / n, 2) if n else 0,
        "avg_dev_pct": round(total_dev_pct / n, 2) if n else 0,
    }

    # === Фильтр pf_rows по диапазону целей (planfact_scope) ===
    if planfact_scope in ("active", "all", "archive"):
        ranges = []
        if planfact_scope in ("active", "all") and goal and goal.get("created_at"):
            try:
                gs = _parse_date(goal["created_at"])
                ge = _parse_date(goal["achieved_at"]) if goal.get("achieved_at") else None
                ranges.append((gs, ge))
            except Exception: pass
        if planfact_scope in ("all", "archive"):
            for ag in (db.list_goals_archive() or []):
                try:
                    gs = _parse_date(ag["created_at"]) if ag.get("created_at") else None
                    ge = _parse_date(ag["achieved_at"]) if ag.get("achieved_at") else None
                    if gs: ranges.append((gs, ge))
                except Exception: pass
        if ranges:
            def _in_range(row_label):
                try:
                    row_dt = datetime.strptime(row_label, "%b %y")
                except Exception:
                    return True
                for s, e in ranges:
                    if row_dt >= s.replace(day=1) and (not e or row_dt <= e):
                        return True
                return False
            pf_rows = [r for r in pf_rows if _in_range(r.get("label",""))]
            # пересчёт summary под отфильтрованные строки
            months_above = sum(1 for r in pf_rows if r.get("dev") and r["dev"] > 0)
            months_below = sum(1 for r in pf_rows if r.get("dev") and r["dev"] < 0)
            devs = [r["dev"] for r in pf_rows if r.get("dev") is not None]
            dev_pcts = [r["dev_pct"] for r in pf_rows if r.get("dev_pct") is not None]
            pf_summary = {
                "months_above": months_above,
                "months_below": months_below,
                "avg_dev": round(sum(devs)/len(devs), 2) if devs else 0,
                "avg_dev_pct": round(sum(dev_pcts)/len(dev_pcts), 2) if dev_pcts else 0,
            }

    _data_obj = {
        "settings": settings,
        "goal": goal,
        "plan": plan,
        "actual": actual,
        "stats": compute_stats("ALL"),
        "streak": compute_streak(),
        "max_drawdown": compute_max_drawdown(actual["months"]),
        "pct_to_goal": round(pct_to_goal, 2),
        "forecast": forecast_goal_date(eq),
        "pf_rows": pf_rows,
        "pf_summary": pf_summary,
        "setups": db.list_setups(),
        "goals_archive": db.list_goals_archive(),
        "api_connected": load_api_creds() is not None,
        "effective_start_capital": get_effective_start_capital(),
        "goal_metrics": compute_goal_metrics(),
    }
    _DASHBOARD_CACHE["data"] = _data_obj
    _DASHBOARD_CACHE["ts"] = now
    _DASHBOARD_CACHE["key"] = cache_key
    return jsonify(_data_obj)


@app.route("/api/stats")
@_login_required
def api_stats():
    # ?from=&to= — кастомный диапазон; ?period_from_goal=1 — взять диапазон активной цели
    f = (request.args.get("from") or "").strip()
    t = (request.args.get("to") or "").strip()
    use_goal = request.args.get("period_from_goal") in ("1", "true", "yes")
    if use_goal:
        try:
            g = db.get_active_goal()
            if g and g.get("created_at"):
                f = g["created_at"]
                t = g.get("achieved_at") or datetime.utcnow().strftime("%Y-%m-%d")
        except Exception:
            pass
    if f or t:
        return jsonify(compute_stats_range(f, t))
    return jsonify(compute_stats(request.args.get("period", "ALL")))


def compute_stats_range(from_str, to_str):
    """compute_stats для произвольного диапазона дат."""
    all_t = db.list_trades()
    start_dt = None; end_dt = None
    try:
        if from_str: start_dt = _parse_date(from_str)
    except Exception: pass
    try:
        if to_str: end_dt = _parse_date(to_str) + timedelta(days=1)
    except Exception: pass
    filt = []
    for t in all_t:
        if not t.get("ts"): continue
        try:
            ts = datetime.fromisoformat(t["ts"][:19])
        except Exception: continue
        if start_dt and ts < start_dt: continue
        if end_dt and ts >= end_dt: continue
        filt.append(t)
    total = len(filt)
    wins = sum(1 for t in filt if (t["pnl_usd"] or 0) > 0)
    losses = sum(1 for t in filt if (t["pnl_usd"] or 0) < 0)
    pnl = sum(float(t["pnl_usd"] or 0) for t in filt)
    fee = sum(float(t["fee_usd"] or 0) for t in filt)
    net = pnl - fee
    best = max((float(t["pnl_usd"] or 0) for t in filt), default=0)
    worst = min((float(t["pnl_usd"] or 0) for t in filt), default=0)
    decisive = wins + losses
    return {
        "total": total, "wins": wins, "losses": losses,
        "breakeven": total - decisive,
        "winrate": round(wins / decisive * 100, 1) if decisive else 0,
        "total_pnl": round(pnl, 2), "total_fee": round(fee, 2),
        "net_pnl": round(net, 2),
        "avg": round(net / total, 2) if total else 0,
        "best": round(best, 2), "worst": round(worst, 2),
    }


@app.route("/api/reset", methods=["POST"])
@_login_required
def api_reset():
    """ПРАВКА #3 + #24: автоматический бэкап БД + проверка PIN если установлен."""
    # #24: проверка PIN
    pin = request.headers.get("X-Confirm-PIN") or (request.get_json(silent=True) or {}).get("pin") or ""
    if not _check_pin(pin):
        return jsonify({"ok": False, "error": "Неверный PIN. Установлена защита /api/security/pin"}), 403
    import shutil
    try:
        backup_name = f"planner.db.backup-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        backup_path = APP_DIR / backup_name
        shutil.copy(db.DB_PATH, backup_path)
        app.logger.info("Reset: backup created %s", backup_name)
    except Exception as e:
        app.logger.error("Reset backup failed: %s", e)
        return jsonify({"ok": False, "error": "backup failed: " + str(e)}), 500
    db.reset_all_data()
    app.logger.info("Reset: all data wiped, defaults restored")
    return jsonify({"ok": True, "backup": backup_name})


@app.route("/api/credentials", methods=["GET", "POST"])
@_login_required
def api_credentials():
    """v4.0: per-user encrypted API ключи через crypto_keys + user_settings."""
    from crypto_keys import encrypt_secret, decrypt_secret, session_get_fernet_key
    fk = session_get_fernet_key(session)

    if request.method == "POST":
        if not fk:
            return jsonify({"ok": False, "error": "Залогинься заново"}), 401
        payload = request.get_json(force=True) or {}
        exchange = payload.get("exchange", "bitunix").lower()
        api_key = payload.get("api_key", "")
        api_secret = payload.get("api_secret", "")
        if not (api_key and api_secret):
            return jsonify({"ok": False, "error": "Введи api_key и api_secret"}), 400
        db.update_settings({
            f"{exchange}_api_key": encrypt_secret(api_key, fk),
            f"{exchange}_api_secret": encrypt_secret(api_secret, fk),
        })
        db.log_audit("update", "credentials", exchange)
        app.logger.info("API creds saved for user %s exchange %s key=%s",
                        current_user.id, exchange, _mask_secret(api_key))
        return jsonify({"ok": True})

    # GET: вернуть текущие ключи (per-user)
    settings = db.get_settings()
    creds = {"exchange": "bitunix", "api_key": "", "api_secret": ""}
    if fk:
        enc_key = settings.get("bitunix_api_key", "")
        enc_secret = settings.get("bitunix_api_secret", "")
        if enc_key:
            creds["api_key"] = decrypt_secret(enc_key, fk) or ""
        if enc_secret:
            creds["api_secret"] = decrypt_secret(enc_secret, fk) or ""
    creds["api_connected"] = bool(creds["api_key"] and creds["api_secret"])
    creds["age_days"] = None
    creds["rotate_recommended"] = False
    return jsonify(creds)


# (старый код api_credentials удалён — заменён выше)
def _legacy_credentials_removed():
    cp = None  # placeholder чтобы не сломать парсер
    if cp:
        pass
    pass  # legacy removed


def _tracking_end_ms():
    settings = db.get_settings()
    end_str = settings.get("tracking_end_date") or ""
    if not end_str:
        return None
    try:
        return int((_parse_date(end_str) + timedelta(days=1)).timestamp() * 1000)
    except Exception:
        return None


def _run_sync(start_ms, end_ms, limit, label):
    import json as _json
    creds = load_api_creds()
    if not creds:
        return {"ok": False, "error": "Bitunix API not configured"}, 400
    key, sec = creds
    client = BitunixClient(key, sec)
    result = {
        "mode": label, "trades_added": 0, "deposits_added": 0,
        "equity": None, "errors": [], "start_capital_set": False,
        "range_start_ms": start_ms, "range_end_ms": end_ms,
        "trades_fetched": 0, "raw_positions_count": 0, "raw_trades_count": 0,
    }
    settings = db.get_settings()
    # ШАГ 3: запоминаем equity И время последнего snapshot ДО sync — для auto-detect.
    prev_equity = None
    prev_snap_ts_ms = 0
    try:
        prev_equity = db.latest_equity()
        with db.get_conn() as _conn:
            _r = _conn.execute(
                "SELECT ts FROM equity_snapshots ORDER BY ts DESC LIMIT 1"
            ).fetchone()
            if _r:
                prev_snap_ts_ms = int(datetime.fromisoformat(_r[0][:19]).timestamp() * 1000)
    except Exception:
        prev_equity = None
        prev_snap_ts_ms = 0
    try:
        eq = client.get_account_balance()
        # BUG-04+ШАГ-1: snapshot пишем ВСЕГДА (включая 0). Дедуп защитит от спама
        # подряд идущих одинаковых значений. Это важно чтобы UI показывал
        # current_equity = последний snapshot (например 0 после вывода всего),
        # а не считал «start − loss» (что даёт отрицательные нереалистичные числа).
        db.add_equity_snapshot(eq, source="bitunix")
        result["equity"] = round(eq, 2)
        current_sc = float(settings.get("start_capital", 0) or 0)
        # BUG-05: start_capital выставляем ТОЛЬКО при реальном (>0) equity,
        # чтобы 0 не зафиксировался как стартовый капитал навсегда.
        if current_sc <= 0 and eq > 0:
            db.update_settings({"start_capital": str(round(eq, 2))})
            result["start_capital_set"] = True
    except BitunixError as e:
        result["errors"].append("equity: " + str(e))
    try:
        trades = client.get_trade_history(start_ms=start_ms, end_ms=end_ms, limit=limit)
        before = len(db.list_trades())
        for t in trades:
            if t.get("external_id"):
                db.add_trade(t)
        result["trades_added"] = len(db.list_trades()) - before
        result["trades_fetched"] = len(trades)
        result["raw_positions_count"] = len(getattr(client, "last_raw_positions", []) or [])
        result["raw_trades_count"] = len(getattr(client, "last_raw_trades", []) or [])
    except BitunixError as e:
        result["errors"].append("trades: " + str(e))
        trades = []
    deps_collected = []
    wds_collected = []
    try:
        deps_collected = client.get_deposits(start_ms=start_ms, end_ms=end_ms)
        wds_collected = client.get_withdrawals(start_ms=start_ms, end_ms=end_ms)
        before = len(db.list_deposits())
        for d in deps_collected + wds_collected:
            if d.get("external_id"):
                db.add_deposit(d)
        result["deposits_added"] = len(db.list_deposits()) - before
        result["deposits_fetched"] = len(deps_collected)
        result["withdrawals_fetched"] = len(wds_collected)
        # BUG-16 (audit 2026-05-26): пробрасываем флаг в UI, чтобы пользователь
        # видел «биржа не отдаёт депозиты — импортируй CSV» вместо ложного «пусто».
        result["deposits_api_supported"] = getattr(client, "deposits_api_supported", None)
        result["withdraws_api_supported"] = getattr(client, "withdraws_api_supported", None)
    except BitunixError as e:
        result["errors"].append("deposits: " + str(e))

    # ============================================================
    # ШАГ 3: AUTO-DETECT DEPOSITS/WITHDRAWALS через delta equity
    # ============================================================
    # Логика: реальный equity на бирже = prev_equity + сумма_новых_PnL + депозиты − выводы.
    # Если (eq − prev_equity) ≠ сумма PnL сделок МЕЖДУ snapshot'ами → необъяснённая
    # разница = депозит (если +) или вывод (если −). Запись с source='auto-detected'.
    # Порог $1, чтобы не реагировать на funding и округления.
    if (prev_equity is not None and result.get("equity") is not None
            and not result.get("errors")):
        try:
            new_eq = float(result["equity"])
            # сумма (pnl − fee) сделок ПОСЛЕ ts предыдущего snapshot (запомнили выше)
            trades_pnl = 0.0
            for t in db.list_trades(limit=100000):
                ts_raw = t.get("ts") or ""
                try:
                    ts_ms = int(datetime.fromisoformat(ts_raw[:19]).timestamp() * 1000)
                except Exception:
                    continue
                if ts_ms > prev_snap_ts_ms and ts_ms <= end_ms:
                    trades_pnl += float(t.get("pnl_usd") or 0) - float(t.get("fee_usd") or 0)
            # сумма депозитов/выводов после prev snapshot — их тоже надо учесть, иначе
            # ручной депозит в этом интервале превратится в дубль auto-detected
            deps_net = 0.0
            for d_ in db.list_deposits():
                ts_raw = d_.get("ts") or ""
                try:
                    ts_ms = int(datetime.fromisoformat(ts_raw[:19]).timestamp() * 1000)
                except Exception:
                    continue
                if ts_ms > prev_snap_ts_ms and ts_ms <= end_ms:
                    if d_.get("kind") == "deposit":
                        deps_net += float(d_.get("amount_usd") or 0)
                    else:
                        deps_net -= float(d_.get("amount_usd") or 0)
            delta = new_eq - float(prev_equity)
            unexplained = delta - trades_pnl - deps_net
            result["auto_detect"] = {
                "prev_equity": round(float(prev_equity), 2),
                "new_equity": round(new_eq, 2),
                "delta": round(delta, 2),
                "trades_net_pnl": round(trades_pnl, 2),
                "manual_deposits_net": round(deps_net, 2),
                "unexplained": round(unexplained, 2),
            }
            THRESHOLD = 1.0  # $1 порог
            if abs(unexplained) >= THRESHOLD:
                kind = "deposit" if unexplained > 0 else "withdraw"
                amount = abs(round(unexplained, 2))
                ts_iso = datetime.utcnow().isoformat(timespec="seconds")
                db.add_deposit({
                    "external_id": f"auto-{kind}-{int(datetime.utcnow().timestamp())}",
                    "ts": ts_iso,
                    "kind": kind,
                    "amount_usd": amount,
                    "note": f"авто-детект (delta equity)",
                    "source": "auto-detected",
                })
                result["auto_detect"]["created"] = {"kind": kind, "amount_usd": amount}
                result["deposits_added"] = (result.get("deposits_added") or 0) + 1
        except Exception as _e:
            result["auto_detect_error"] = str(_e)

    # debug-дамп со всеми HTTP-вызовами (после депозитов!)
    try:
        debug_path = Path(__file__).parent / "last_sync_debug.json"
        debug_path.write_text(_json.dumps({
            "label": label,
            "range_start_ms": start_ms,
            "range_end_ms": end_ms,
            "result": {k: v for k, v in result.items() if k != "errors"},
            "errors": result.get("errors", []),
            "raw_positions": getattr(client, "last_raw_positions", []),
            "raw_trades": getattr(client, "last_raw_trades", []),
            "raw_deposits": deps_collected,
            "raw_withdrawals": wds_collected,
            "http_calls": getattr(client, "call_log", []),
        }, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    except Exception as _e:
        result["errors"].append("debug-dump: " + str(_e))
    result["ok"] = not result["errors"]
    try:
        db.update_settings({"last_sync_ts": str(int(datetime.utcnow().timestamp() * 1000))})
    except Exception:
        pass
    # ФАЗА 2: лог результата
    app.logger.info(
        "sync[%s] ok=%s eq=%s trades_added=%s deposits_added=%s errors=%s",
        label, result.get("ok"), result.get("equity"),
        result.get("trades_added"), result.get("deposits_added"),
        len(result.get("errors", []))
    )
    return result, 200


_last_sync_at_ms = 0
_SYNC_MIN_INTERVAL_MS = 60_000  # #25 rate-limit: max 1 sync в минуту


@app.route("/api/sync", methods=["POST"])
@_login_required
def api_sync():
    """
    ШАГ 2: INCREMENTAL sync с rate-limit (max 1/мин).
    """
    # #25 Rate-limit
    global _last_sync_at_ms
    now_ms = int(datetime.utcnow().timestamp() * 1000)
    elapsed = now_ms - _last_sync_at_ms
    if elapsed < _SYNC_MIN_INTERVAL_MS:
        wait_sec = (_SYNC_MIN_INTERVAL_MS - elapsed) // 1000 + 1
        return jsonify({
            "ok": False,
            "error": f"rate_limit: подожди {wait_sec} сек до следующего sync (max 1 в минуту)",
            "wait_seconds": wait_sec,
        }), 429
    _last_sync_at_ms = now_ms
    settings = db.get_settings()
    last_sync_ts = settings.get("last_sync_ts")
    trades_count = 0
    try:
        trades_count = len(db.list_trades(limit=1))
    except Exception:
        trades_count = 0

    # Первый запуск / пустая БД → полная история
    if not last_sync_ts or trades_count == 0:
        return _api_sync_full_impl({})

    try:
        start_ms = int(last_sync_ts) - 24 * 60 * 60 * 1000  # -24h буфер
    except Exception:
        return _api_sync_full_impl({})

    end_ms = int(datetime.utcnow().timestamp() * 1000)
    body, code = _run_sync(start_ms, end_ms, 500, "incremental")
    body["mode"] = "incremental"
    body["used_range"] = {
        "start_iso": datetime.utcfromtimestamp(start_ms / 1000).strftime("%Y-%m-%d %H:%M"),
        "end_iso": datetime.utcfromtimestamp(end_ms / 1000).strftime("%Y-%m-%d %H:%M"),
    }
    return jsonify(body), code


@app.route("/api/sync/full", methods=["POST"])
@_login_required
def api_sync_full():
    """
    Полная история. Принимает из тела JSON:
      - start_date (YYYY-MM-DD, опц.)  → по умолчанию: 2020-01-01 (или самая ранняя цель)
      - end_date   (YYYY-MM-DD, опц.)  → по умолчанию: сегодня

    ШАГ 2: для полной выгрузки независимой от целей — рекомендую 2020-01-01.
    """
    payload = request.get_json(silent=True) or {}
    return _api_sync_full_impl(payload)


def _api_sync_full_impl(payload):
    """Реализация полной выгрузки. Возвращает (response, status_code)."""
    start_str = (payload.get("start_date") or "").strip()
    end_str = (payload.get("end_date") or "").strip()
    if start_str:
        try:
            start_ms = int(_parse_date(start_str).timestamp() * 1000)
        except Exception:
            start_ms = int(datetime(2020, 1, 1).timestamp() * 1000)
    else:
        # дефолт: самая ранняя цель (активная + архивные) или 2020-01-01
        earliest = None
        try:
            g = db.get_active_goal()
            if g and g.get("created_at"):
                earliest = g["created_at"]
        except Exception:
            pass
        try:
            arc = db.list_goals_archive() or []
            for ag in arc:
                d_ = ag.get("created_at") or ""
                if d_ and (earliest is None or d_ < earliest):
                    earliest = d_
        except Exception:
            pass
        if earliest:
            try:
                start_ms = int(_parse_date(earliest).timestamp() * 1000)
            except Exception:
                start_ms = int(datetime(2020, 1, 1).timestamp() * 1000)
        else:
            start_ms = int(datetime(2020, 1, 1).timestamp() * 1000)
    if end_str:
        try:
            end_ms = int((_parse_date(end_str) + timedelta(days=1)).timestamp() * 1000)
        except Exception:
            end_ms = int(datetime.utcnow().timestamp() * 1000)
    else:
        end_ms = int(datetime.utcnow().timestamp() * 1000)
    body, code = _run_sync(start_ms, end_ms, 1000, "full")
    body["used_range"] = {
        "start_iso": datetime.utcfromtimestamp(start_ms / 1000).strftime("%Y-%m-%d"),
        "end_iso": datetime.utcfromtimestamp(end_ms / 1000).strftime("%Y-%m-%d"),
    }
    body["mode"] = "full"
    return jsonify(body), code


def _migrate_bad_tracking_dates():
    # v4.0: noop (settings per-user)
    return




@app.route("/api/positions/open")
@_login_required
def api_positions_open():
    """
    ШАГ 5 (audit 2026-05-26): открытые позиции с unrealized PnL.
    Тянем напрямую с биржи, в БД НЕ кешируем (данные мгновенно устаревают).
    """
    creds = load_api_creds()
    if not creds:
        return jsonify({"ok": False, "error": "Bitunix API not configured", "positions": []}), 200
    key, sec = creds
    try:
        client = BitunixClient(key, sec)
        positions = client.get_open_positions()
        total_unrealized = sum(float(p.get("unrealized_pnl_usd") or 0) for p in positions)
        total_margin = sum(float(p.get("margin_usd") or 0) for p in positions)
        return jsonify({
            "ok": True,
            "positions": positions,
            "count": len(positions),
            "total_unrealized_usd": round(total_unrealized, 2),
            "total_margin_usd": round(total_margin, 2),
            "fetched_at": datetime.utcnow().isoformat(timespec="seconds"),
        })
    except BitunixError as e:
        return jsonify({"ok": False, "error": str(e), "positions": []}), 200




# ====================================================================
# ФАЗА 4: ПРОДВИНУТАЯ АНАЛИТИКА ТРЕЙДЕРА (2026-05-26)
# ====================================================================

import math as _math
from collections import defaultdict as _dd


def _trades_for_active_goal():
    """Возвращает сделки в рамках активной цели (от created_at до сейчас/achieved_at)."""
    goal = db.get_active_goal()
    if not goal:
        return []
    try:
        start = _parse_date(goal["created_at"]) if goal.get("created_at") else None
    except Exception:
        start = None
    try:
        end = _parse_date(goal["achieved_at"]) + timedelta(days=1) if goal.get("achieved_at") else None
    except Exception:
        end = None
    out = []
    for t in db.list_trades():
        ts_raw = t.get("ts") or ""
        try:
            ts = datetime.fromisoformat(ts_raw[:19])
        except Exception:
            continue
        if start and ts < start: continue
        if end and ts >= end: continue
        out.append(t)
    return out


def _sharpe_ratio(daily_returns, risk_free_rate=0.0):
    """
    Sharpe Ratio (annualized).
    daily_returns — список дневных returns (в долях, не процентах).
    risk_free_rate — годовая безрисковая ставка (по умолчанию 0).
    Формула: (mean(r) - rf/252) / std(r) * sqrt(252)
    """
    if len(daily_returns) < 2:
        return None
    mean_r = sum(daily_returns) / len(daily_returns)
    variance = sum((r - mean_r) ** 2 for r in daily_returns) / (len(daily_returns) - 1)
    std_r = _math.sqrt(variance)
    if std_r == 0:
        return None
    daily_rf = risk_free_rate / 252
    return round((mean_r - daily_rf) / std_r * _math.sqrt(252), 3)


def _sortino_ratio(daily_returns, target=0.0):
    """
    Sortino Ratio (annualized). Только negative deviation (downside risk).
    """
    if len(daily_returns) < 2:
        return None
    mean_r = sum(daily_returns) / len(daily_returns)
    neg = [(r - target) ** 2 for r in daily_returns if r < target]
    if not neg:
        return None
    downside = _math.sqrt(sum(neg) / len(daily_returns))
    if downside == 0:
        return None
    daily_target = target / 252
    return round((mean_r - daily_target) / downside * _math.sqrt(252), 3)




def _compute_streak_distribution(trades):
    """#5: Распределение серий по длине. Возвращает {win: {1: cnt, 2: cnt}, loss: {...}}."""
    if not trades:
        return {"win": {}, "loss": {}}
    sorted_t = sorted(trades, key=lambda t: t.get("ts", ""))
    win_dist = {}
    loss_dist = {}
    run_kind = None
    run_len = 0
    def _flush():
        if run_len > 0 and run_kind:
            d = win_dist if run_kind == "win" else loss_dist
            d[run_len] = d.get(run_len, 0) + 1
    for t in sorted_t:
        p = float(t.get("pnl_usd") or 0)
        cur = "win" if p > 0 else ("loss" if p < 0 else None)
        if cur is None:
            _flush(); run_kind, run_len = None, 0
            continue
        if cur == run_kind:
            run_len += 1
        else:
            _flush(); run_kind, run_len = cur, 1
    _flush()
    return {"win": win_dist, "loss": loss_dist}


def _compute_by_setup(trades):
    """#7: Метрики по каждому сетапу — количество, winrate, net P&L, sharpe (упрощённо)."""
    if not trades:
        return []
    by_setup = _dd(lambda: {"count": 0, "wins": 0, "losses": 0, "net_pnl": 0.0, "fees": 0.0, "pnls": []})
    for t in trades:
        s = t.get("setup") or "(без сетапа)"
        p = float(t.get("pnl_usd") or 0)
        f = float(t.get("fee_usd") or 0)
        by_setup[s]["count"] += 1
        by_setup[s]["fees"] += f
        by_setup[s]["net_pnl"] += (p - f)
        by_setup[s]["pnls"].append(p)
        if p > 0:
            by_setup[s]["wins"] += 1
        elif p < 0:
            by_setup[s]["losses"] += 1
    result = []
    for setup, v in by_setup.items():
        decisive = v["wins"] + v["losses"]
        winrate = (v["wins"] / decisive * 100) if decisive else 0
        # Упрощённый «sharpe-подобный»: mean / std
        n = len(v["pnls"])
        mean = sum(v["pnls"]) / n if n else 0
        if n >= 2:
            variance = sum((x - mean) ** 2 for x in v["pnls"]) / (n - 1)
            std = _math.sqrt(variance)
            ps = round(mean / std, 3) if std > 0 else None  # "PnL Sharpe"
        else:
            ps = None
        result.append({
            "setup": setup,
            "count": v["count"],
            "wins": v["wins"],
            "losses": v["losses"],
            "winrate": round(winrate, 1),
            "net_pnl": round(v["net_pnl"], 2),
            "avg_pnl": round(mean, 2),
            "pnl_sharpe": ps,
        })
    # сортируем по net_pnl
    result.sort(key=lambda x: -x["net_pnl"])
    return result



def compute_advanced_stats():
    """
    Возвращает продвинутую аналитику по сделкам активной цели:
    - sharpe / sortino
    - profit_factor (gross profit / gross loss)
    - avg_win / avg_loss / rr (risk-reward) / expectancy
    - histogram (распределение PnL по бакетам)
    - heatmap (PnL по часам × дням недели)
    """
    trades = _trades_for_active_goal()
    if not trades:
        return {"is_empty": True}

    wins = [float(t["pnl_usd"] or 0) for t in trades if (t["pnl_usd"] or 0) > 0]
    losses = [float(t["pnl_usd"] or 0) for t in trades if (t["pnl_usd"] or 0) < 0]

    gross_profit = sum(wins) if wins else 0
    gross_loss = abs(sum(losses)) if losses else 0
    profit_factor = (gross_profit / gross_loss) if gross_loss > 0 else None
    avg_win = (gross_profit / len(wins)) if wins else 0
    avg_loss = (gross_loss / len(losses)) if losses else 0
    rr = (avg_win / avg_loss) if avg_loss > 0 else None  # risk-reward
    total = len(trades)
    decisive = len(wins) + len(losses)
    winrate = (len(wins) / decisive) if decisive else 0
    loss_rate = 1 - winrate
    expectancy = winrate * avg_win - loss_rate * avg_loss  # ожидание $ на сделку

    # === Daily returns для Sharpe/Sortino ===
    # Считаем как (net_pnl_at_day / starting_capital). Без сильного капитала
    # как фоллбэк используем mean(|pnl|) * 10 как «база».
    start_cap = max(get_effective_start_capital() or 0, 1.0)
    daily_pnl = _dd(float)
    for t in trades:
        ts_raw = t.get("ts") or ""
        day = ts_raw[:10]
        if day:
            daily_pnl[day] += float(t["pnl_usd"] or 0) - float(t["fee_usd"] or 0)
    daily_returns = [v / start_cap for v in daily_pnl.values()]
    sharpe = _sharpe_ratio(daily_returns)
    sortino = _sortino_ratio(daily_returns)

    # === Histogram распределения PnL ===
    pnls = sorted([float(t["pnl_usd"] or 0) for t in trades])
    if pnls:
        lo, hi = pnls[0], pnls[-1]
        # 10 бакетов от lo до hi
        if hi == lo:
            histogram = [{"bucket_start": lo, "bucket_end": hi, "count": len(pnls)}]
        else:
            step = (hi - lo) / 10
            buckets = [0] * 10
            for p in pnls:
                idx = min(9, int((p - lo) / step))
                buckets[idx] += 1
            histogram = [
                {"bucket_start": round(lo + step * i, 2),
                 "bucket_end": round(lo + step * (i + 1), 2),
                 "count": buckets[i]}
                for i in range(10)
            ]
    else:
        histogram = []

    # === Heatmap: PnL по часу × дню недели (для тепловой карты) ===
    heatmap = [[0.0] * 24 for _ in range(7)]
    heatmap_count = [[0] * 24 for _ in range(7)]
    for t in trades:
        ts_raw = t.get("ts") or ""
        try:
            ts = datetime.fromisoformat(ts_raw[:19])
        except Exception:
            continue
        d = ts.weekday()
        h = ts.hour
        heatmap[d][h] += float(t["pnl_usd"] or 0)
        heatmap_count[d][h] += 1

    # === #4: median / mean PnL ===
    pnls_sorted = sorted([float(t["pnl_usd"] or 0) for t in trades])
    n = len(pnls_sorted)
    median_pnl = pnls_sorted[n // 2] if n % 2 == 1 else ((pnls_sorted[n//2 - 1] + pnls_sorted[n//2]) / 2)
    mean_pnl = sum(pnls_sorted) / n if n else 0

    # === #8: best/worst hour & day of week ===
    by_hour = _dd(lambda: {"pnl": 0.0, "count": 0})
    by_dow = _dd(lambda: {"pnl": 0.0, "count": 0})
    for t in trades:
        try:
            ts = datetime.fromisoformat((t.get("ts") or "")[:19])
        except Exception:
            continue
        p = float(t["pnl_usd"] or 0)
        by_hour[ts.hour]["pnl"] += p
        by_hour[ts.hour]["count"] += 1
        by_dow[ts.weekday()]["pnl"] += p
        by_dow[ts.weekday()]["count"] += 1
    dow_names = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]
    best_hour = max(by_hour.items(), key=lambda x: x[1]["pnl"], default=None)
    worst_hour = min(by_hour.items(), key=lambda x: x[1]["pnl"], default=None)
    best_dow = max(by_dow.items(), key=lambda x: x[1]["pnl"], default=None)
    worst_dow = min(by_dow.items(), key=lambda x: x[1]["pnl"], default=None)

    # === #9: best/worst symbol ===
    by_symbol = _dd(lambda: {"pnl": 0.0, "count": 0, "wins": 0})
    for t in trades:
        s = (t.get("symbol") or "?").upper()
        p = float(t["pnl_usd"] or 0)
        by_symbol[s]["pnl"] += p
        by_symbol[s]["count"] += 1
        if p > 0:
            by_symbol[s]["wins"] += 1
    best_symbol = max(by_symbol.items(), key=lambda x: x[1]["pnl"], default=None)
    worst_symbol = min(by_symbol.items(), key=lambda x: x[1]["pnl"], default=None)
    top_symbols = sorted(
        [(k, v) for k, v in by_symbol.items()],
        key=lambda x: -x[1]["pnl"]
    )[:5]

    # === #6: average holding time (entry_price/exit_price без timestamps закрытия, поэтому
    # используем разницу между timestamp'ами соседних сделок одного символа как proxy) ===
    # Если у нас нет open_ts — пропустим точный расчёт, оставим заглушку
    avg_holding_hours = None  # TODO: при добавлении open_ts на стороне нормализации

    # === #1: Calmar Ratio (annualized return / max drawdown) ===
    # Считаем annualized return из дневных returns
    annual_return = None
    calmar = None
    if daily_returns:
        avg_daily = sum(daily_returns) / len(daily_returns)
        annual_return = (1 + avg_daily) ** 252 - 1
        # MaxDD считаем здесь же из дневных returns
        cum = 1.0
        peak = 1.0
        max_dd = 0.0
        for r in daily_returns:
            cum *= (1 + r)
            if cum > peak:
                peak = cum
            dd = (peak - cum) / peak
            if dd > max_dd:
                max_dd = dd
        if max_dd > 0:
            calmar = round(annual_return / max_dd, 3)

    def _serialize_extr(item, name_resolver=None):
        if not item: return None
        k, v = item
        return {"key": (name_resolver(k) if name_resolver else k), "pnl": round(v["pnl"], 2), "count": v["count"]}

    return {
        "is_empty": False,
        "trades_count": total,
        "wins": len(wins),
        "losses": len(losses),
        "winrate": round(winrate * 100, 1),
        "gross_profit": round(gross_profit, 2),
        "gross_loss": round(gross_loss, 2),
        "profit_factor": round(profit_factor, 2) if profit_factor is not None else None,
        "avg_win": round(avg_win, 2),
        "avg_loss": round(avg_loss, 2),
        "rr": round(rr, 2) if rr is not None else None,
        "expectancy": round(expectancy, 2),
        "sharpe": sharpe,
        "sortino": sortino,
        "calmar": calmar,  # #1
        "annual_return_pct": round(annual_return * 100, 2) if annual_return is not None else None,
        "median_pnl": round(median_pnl, 2),  # #4
        "mean_pnl": round(mean_pnl, 2),       # #4
        "best_hour": _serialize_extr(best_hour, lambda h: f"{h:02d}:00"),    # #8
        "worst_hour": _serialize_extr(worst_hour, lambda h: f"{h:02d}:00"),  # #8
        "best_dow": _serialize_extr(best_dow, lambda d: dow_names[d]),       # #8
        "worst_dow": _serialize_extr(worst_dow, lambda d: dow_names[d]),     # #8
        "best_symbol": _serialize_extr(best_symbol),  # #9
        "worst_symbol": _serialize_extr(worst_symbol),  # #9
        "top_symbols": [{"symbol": s, "pnl": round(v["pnl"], 2), "count": v["count"],
                         "winrate": round(v["wins"]/v["count"]*100, 1) if v["count"] else 0}
                        for s, v in top_symbols],
        "avg_holding_hours": avg_holding_hours,
        "histogram": histogram,
        "heatmap": heatmap,
        "heatmap_count": heatmap_count,
        "streak_distribution": _compute_streak_distribution(trades),  # #5
        "by_setup": _compute_by_setup(trades),  # #7 Sharpe per setup
    }


@app.route("/api/advanced")
@_login_required
def api_advanced():
    """Эндпоинт продвинутой аналитики по активной цели."""
    return jsonify(compute_advanced_stats())





# ====================================================================
# ФАЗА 5: PDF-ОТЧЁТ МЕСЯЧНЫЙ (2026-05-26)
# ====================================================================

@app.route("/api/report/pdf")
@_login_required
def api_report_pdf():
    """
    Генерирует PDF-отчёт за месяц.
    Параметр ?period=YYYY-MM (по умолчанию текущий месяц).

    Если reportlab не установлен — возвращаем HTML, который пользователь
    может распечатать в PDF через браузер (Ctrl+P → Сохранить как PDF).
    """
    period = (request.args.get("period") or "").strip()
    if not period:
        period = datetime.utcnow().strftime("%Y-%m")
    try:
        year, month = map(int, period.split("-"))
        period_start = datetime(year, month, 1)
        if month == 12:
            period_end = datetime(year + 1, 1, 1)
        else:
            period_end = datetime(year, month + 1, 1)
    except Exception:
        return jsonify({"ok": False, "error": "bad period format, use YYYY-MM"}), 400

    # Собираем сделки за период
    trades = []
    for t in db.list_trades():
        try:
            ts = datetime.fromisoformat(t["ts"][:19])
        except Exception:
            continue
        if period_start <= ts < period_end:
            trades.append(t)
    trades.sort(key=lambda x: x["ts"])

    # Считаем статистику
    wins = [t for t in trades if (t["pnl_usd"] or 0) > 0]
    losses = [t for t in trades if (t["pnl_usd"] or 0) < 0]
    total = len(trades)
    decisive = len(wins) + len(losses)
    winrate = (len(wins) / decisive * 100) if decisive else 0
    gross_profit = sum(float(t["pnl_usd"] or 0) for t in wins)
    gross_loss = abs(sum(float(t["pnl_usd"] or 0) for t in losses))
    net = gross_profit - gross_loss
    total_fee = sum(float(t["fee_usd"] or 0) for t in trades)
    pf = (gross_profit / gross_loss) if gross_loss > 0 else None

    # Топ-5 лучших и худших
    top_wins = sorted(trades, key=lambda x: -float(x["pnl_usd"] or 0))[:5]
    top_losses = sorted(trades, key=lambda x: float(x["pnl_usd"] or 0))[:5]

    # Простой HTML-отчёт (юзер потом через Ctrl+P в PDF)
    goal = db.get_active_goal() or {}
    settings = db.get_settings()

    def fmt(v, d=2):
        if v is None:
            return "—"
        return f"${v:,.{d}f}"

    def trade_row(t):
        pnl = float(t["pnl_usd"] or 0)
        cls = "pos" if pnl > 0 else ("neg" if pnl < 0 else "")
        return f"<tr><td>{t['ts'][:19].replace('T', ' ')}</td>"                f"<td>{t['symbol']}</td>"                f"<td>{t['side']}</td>"                f"<td class='{cls}'>{fmt(pnl)}</td>"                f"<td>{(t.get('pnl_pct') or 0):.2f}%</td></tr>"

    period_name = period_start.strftime("%B %Y").upper()
    month_names = {
        "JANUARY": "ЯНВАРЬ", "FEBRUARY": "ФЕВРАЛЬ", "MARCH": "МАРТ",
        "APRIL": "АПРЕЛЬ", "MAY": "МАЙ", "JUNE": "ИЮНЬ",
        "JULY": "ИЮЛЬ", "AUGUST": "АВГУСТ", "SEPTEMBER": "СЕНТЯБРЬ",
        "OCTOBER": "ОКТЯБРЬ", "NOVEMBER": "НОЯБРЬ", "DECEMBER": "ДЕКАБРЬ",
    }
    for en, ru in month_names.items():
        period_name = period_name.replace(en, ru)

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Отчёт {period_name} — Crypto Trading Planner</title>
<style>
  @page {{ size: A4; margin: 1.5cm; }}
  body {{ font-family: Arial, sans-serif; color: #1a1f2e; max-width: 800px; margin: 0 auto; }}
  h1 {{ color: #2a3e66; border-bottom: 3px solid #7c5cff; padding-bottom: 10px; margin: 0 0 6px; }}
  h2 {{ color: #374b7a; margin-top: 24px; border-bottom: 1px solid #e2e6ee; padding-bottom: 6px; }}
  .subtitle {{ color: #5a6478; margin-bottom: 20px; font-size: 13px; }}
  .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 18px 0; }}
  .metric {{ padding: 12px; background: #f6f8fc; border-left: 3px solid #7c5cff; border-radius: 4px; }}
  .metric-label {{ font-size: 10px; color: #5a6478; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }}
  .metric-value {{ font-size: 18px; font-weight: 700; margin-top: 4px; font-family: 'Courier New', monospace; }}
  .pos {{ color: #0d7d3b; }}
  .neg {{ color: #b91d1d; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; }}
  th, td {{ padding: 6px 10px; text-align: left; border-bottom: 1px solid #e2e6ee; }}
  th {{ background: #f0f3f8; font-weight: 600; color: #2a3e66; }}
  .summary {{ padding: 14px; background: #eef3fb; border-left: 4px solid #4ea1ff; margin: 16px 0; border-radius: 4px; }}
  .footer {{ margin-top: 40px; padding-top: 14px; border-top: 1px solid #e2e6ee; font-size: 11px; color: #8a93a8; }}
  .no-print {{ background: #fff8e1; padding: 10px; margin-bottom: 16px; border: 1px solid #ffd54f; border-radius: 4px; font-size: 12px; }}
  @media print {{ .no-print {{ display: none; }} }}
</style>
</head>
<body>

<div class="no-print">
  📄 <b>Сохранить как PDF:</b> нажми <b>Ctrl+P</b> (или Cmd+P на Mac) → <b>«Сохранить как PDF»</b> в окне печати.
</div>

<h1>Отчёт за {period_name}</h1>
<div class="subtitle">Crypto Trading Planner v3.1 · Цель: <b>{goal.get('name', 'без названия')}</b> ({fmt(goal.get('amount'), 0)})</div>

<div class="summary">
  <b>{'🎉 Прибыльный месяц!' if net > 0 else ('📉 Убыточный месяц' if net < 0 else '⚖️ Безубыточный месяц')}</b><br>
  Net P&amp;L: <span class="{'pos' if net>0 else 'neg' if net<0 else ''}">{('+' if net>=0 else '')}{fmt(net)}</span>
  · Сделок: <b>{total}</b>
  · Winrate: <b>{winrate:.1f}%</b>
  · Profit Factor: <b>{(f'{pf:.2f}' if pf else '—')}</b>
</div>

<h2>📊 Метрики</h2>
<div class="metrics">
  <div class="metric"><div class="metric-label">Сделок</div><div class="metric-value">{total}</div></div>
  <div class="metric"><div class="metric-label">Прибыльных</div><div class="metric-value pos">{len(wins)}</div></div>
  <div class="metric"><div class="metric-label">Убыточных</div><div class="metric-value neg">{len(losses)}</div></div>
  <div class="metric"><div class="metric-label">Winrate</div><div class="metric-value">{winrate:.1f}%</div></div>
  <div class="metric"><div class="metric-label">Gross Profit</div><div class="metric-value pos">+{fmt(gross_profit)}</div></div>
  <div class="metric"><div class="metric-label">Gross Loss</div><div class="metric-value neg">−{fmt(gross_loss)}</div></div>
  <div class="metric"><div class="metric-label">Комиссии</div><div class="metric-value">−{fmt(total_fee)}</div></div>
  <div class="metric"><div class="metric-label">Net P&amp;L</div><div class="metric-value {'pos' if net>0 else 'neg'}">{('+' if net>=0 else '')}{fmt(net)}</div></div>
</div>

<h2>🏆 Топ-5 прибыльных сделок</h2>
{('<table><thead><tr><th>Дата</th><th>Пара</th><th>Side</th><th>P&amp;L $</th><th>P&amp;L %</th></tr></thead><tbody>' + ''.join(trade_row(t) for t in top_wins) + '</tbody></table>') if top_wins else '<p style="color:#8a93a8;">За месяц не было прибыльных сделок.</p>'}

<h2>📉 Топ-5 убыточных сделок</h2>
{('<table><thead><tr><th>Дата</th><th>Пара</th><th>Side</th><th>P&amp;L $</th><th>P&amp;L %</th></tr></thead><tbody>' + ''.join(trade_row(t) for t in top_losses) + '</tbody></table>') if top_losses else '<p style="color:#8a93a8;">За месяц не было убыточных сделок.</p>'}

<div class="footer">
  Сгенерировано {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} · Crypto Trading Planner v3.1 Audit Edition<br>
  Все цифры в долларах США. PnL рассчитывается по формуле: realizedPNL с биржи Bitunix.
</div>

</body>
</html>"""
    return Response(html, mimetype="text/html; charset=utf-8")





@app.route("/api/equity/daily")
@_login_required
def api_equity_daily():
    """
    #2 Equity curve по дням в рамках активной цели.
    Возвращает {dates: [...], equity: [...], drawdown_pct: [...]}.
    Логика:
      - Берём дату создания цели и идём по дням до сегодня
      - Стартовый капитал = settings.start_capital (или 0)
      - На каждый день: cumulative_pnl = sum(net pnl сделок в этот день)
        + net deposits в этот день
      - equity_for_day = start_cap + cumulative_pnl до этого дня (включительно)
      - drawdown_pct = (peak - equity) / peak * 100
    """
    goal = db.get_active_goal()
    if not goal or not goal.get("created_at"):
        return jsonify({"dates": [], "equity": [], "drawdown_pct": [], "is_empty": True})
    try:
        start_dt = _parse_date(goal["created_at"])
    except Exception:
        return jsonify({"dates": [], "equity": [], "drawdown_pct": [], "is_empty": True})
    end_dt = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    if goal.get("achieved_at"):
        try:
            end_dt = _parse_date(goal["achieved_at"])
        except Exception:
            pass
    start_cap = get_effective_start_capital()

    # Сгруппируем сделки и депозиты по дням
    daily_pnl = defaultdict(float)
    for t in db.list_trades():
        ts_raw = t.get("ts") or ""
        try:
            ts = datetime.fromisoformat(ts_raw[:19])
        except Exception:
            continue
        if ts < start_dt or ts > end_dt + timedelta(days=1):
            continue
        day = ts.strftime("%Y-%m-%d")
        daily_pnl[day] += float(t.get("pnl_usd") or 0) - float(t.get("fee_usd") or 0)
    for d_ in db.list_deposits():
        ts_raw = d_.get("ts") or ""
        try:
            ts = datetime.fromisoformat(ts_raw[:19])
        except Exception:
            continue
        if ts < start_dt or ts > end_dt + timedelta(days=1):
            continue
        day = ts.strftime("%Y-%m-%d")
        amt = float(d_.get("amount_usd") or 0)
        if d_.get("kind") == "deposit":
            daily_pnl[day] += amt
        else:
            daily_pnl[day] -= amt

    dates = []
    equities = []
    drawdowns = []
    cur_eq = start_cap
    peak = start_cap if start_cap > 0 else 0
    cur = start_dt
    while cur <= end_dt:
        day = cur.strftime("%Y-%m-%d")
        cur_eq += daily_pnl.get(day, 0.0)
        if cur_eq > peak:
            peak = cur_eq
        dd = ((peak - cur_eq) / peak * 100) if peak > 0 else 0
        dates.append(day)
        equities.append(round(cur_eq, 2))
        drawdowns.append(round(dd, 2))
        cur += timedelta(days=1)

    return jsonify({
        "dates": dates,
        "equity": equities,
        "drawdown_pct": drawdowns,
        "start_capital": round(start_cap, 2),
        "is_empty": len(dates) == 0,
    })





# === #47 Sharing-режим (read-only ссылка с замаскированными суммами) ===
import secrets as _secrets

_SHARE_TOKENS = {}  # token → {created_at, expires_at} (in-memory)


@app.route("/api/share/create", methods=["POST"])
@_login_required
def api_share_create():
    """Генерит токен для read-only ссылки. Действует 24 часа."""
    token = _secrets.token_urlsafe(16)
    now_ms = int(datetime.utcnow().timestamp() * 1000)
    _SHARE_TOKENS[token] = {
        "created_at": now_ms,
        "expires_at": now_ms + 24 * 3600 * 1000,
    }
    # Чистим старые токены
    _SHARE_TOKENS_KEYS = list(_SHARE_TOKENS.keys())
    for k in _SHARE_TOKENS_KEYS:
        if _SHARE_TOKENS[k]["expires_at"] < now_ms:
            del _SHARE_TOKENS[k]
    return jsonify({"token": token, "url": f"/share/{token}", "expires_in_hours": 24})


def _mask_amount(v):
    """Маскирует сумму: 12345.67 → 12k+"""
    try:
        v = float(v or 0)
    except Exception:
        return "—"
    sign = "-" if v < 0 else ("+" if v > 0 else "")
    v = abs(v)
    if v < 100: return sign + "<100"
    if v < 1000: return sign + f"~{int(v/100)*100}"
    if v < 10000: return sign + f"~{int(v/1000)}k"
    if v < 100000: return sign + f"~{int(v/1000)}k"
    return sign + f"~{int(v/1000)}k"


@app.route("/share/<token>")
def share_view(token):
    """Read-only view с замаскированными суммами."""
    if token not in _SHARE_TOKENS:
        return "Ссылка истекла или невалидна", 404
    if _SHARE_TOKENS[token]["expires_at"] < int(datetime.utcnow().timestamp() * 1000):
        return "Ссылка истекла", 410
    # Базовые данные с маскировкой
    goal = db.get_active_goal() or {}
    trades = db.list_trades(limit=1000)
    wins = sum(1 for t in trades if (t.get("pnl_usd") or 0) > 0)
    losses = sum(1 for t in trades if (t.get("pnl_usd") or 0) < 0)
    decisive = wins + losses
    winrate = (wins / decisive * 100) if decisive else 0
    net_pnl = sum(float(t.get("pnl_usd") or 0) - float(t.get("fee_usd") or 0) for t in trades)
    # HTML
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Trading Stats (shared)</title>
<style>
body {{ font-family: Arial, sans-serif; background: #0a0d14; color: #e6edf7; padding: 32px; max-width: 700px; margin: 0 auto; }}
h1 {{ color: #7c5cff; border-bottom: 2px solid #2d3548; padding-bottom: 8px; }}
.metric {{ display: flex; justify-content: space-between; padding: 10px 14px; background: #161b27; border-radius: 8px; margin: 8px 0; }}
.metric b {{ font-family: monospace; }}
.muted {{ color: #8a93a8; font-size: 12px; margin-top: 24px; }}
.pos {{ color: #10c98a; }} .neg {{ color: #ff5a6c; }}
</style></head><body>
<h1>📊 Trading Stats (shared)</h1>
<div class="metric"><span>Цель</span><b>{esc_html(goal.get('name', '—'))}</b></div>
<div class="metric"><span>Сделок</span><b>{len(trades)}</b></div>
<div class="metric"><span>Прибыльных</span><b class="pos">{wins}</b></div>
<div class="metric"><span>Убыточных</span><b class="neg">{losses}</b></div>
<div class="metric"><span>Winrate</span><b>{winrate:.1f}%</b></div>
<div class="metric"><span>Net P&L</span><b class="{'pos' if net_pnl>=0 else 'neg'}">{_mask_amount(net_pnl)}</b></div>
<div class="muted">Read-only · суммы замаскированы для приватности · ссылка истекает через 24 часа</div>
</body></html>"""
    return Response(html, mimetype="text/html; charset=utf-8")


def esc_html(s):
    if s is None: return ""
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")





@app.route("/api/trades/bulk-update", methods=["PATCH"])
@_login_required
def api_trades_bulk_update():
    """#11 Массовое присвоение сетапа/заметки выделенным сделкам."""
    payload = request.get_json(force=True) or {}
    ids = payload.get("ids") or []
    setup = payload.get("setup")
    note = payload.get("note")
    affected = db.bulk_update_trades(ids, setup=setup, note=note)
    try:
        db.log_audit("bulk_update_trades", "trades", None,
                     {"count": len(ids), "affected": affected, "setup": setup})
    except Exception:
        pass
    # Сбросим dashboard cache
    _DASHBOARD_CACHE["ts"] = 0
    return jsonify({"ok": True, "affected": affected})


@app.route("/api/auto-tag", methods=["POST"])
@_login_required
def api_auto_tag():
    """
    #12 Auto-tag по правилам.
    Тело: {"rules": [{"symbol": "BTC", "side": "LONG", "setup": "breakout"}, ...]}
    Применяется ТОЛЬКО к сделкам без тэга (setup IS NULL OR setup='').
    """
    payload = request.get_json(force=True) or {}
    rules = payload.get("rules") or []
    affected = db.auto_tag_trades(rules)
    try:
        db.log_audit("auto_tag", "trades", None, {"rules": rules, "affected": affected})
    except Exception:
        pass
    _DASHBOARD_CACHE["ts"] = 0
    return jsonify({"ok": True, "affected": affected, "rules_applied": len(rules)})


@app.route("/api/audit-log")
@_login_required
def api_audit_log():
    """#23 Просмотр последних 100 событий audit-log."""
    try:
        limit = int(request.args.get("limit") or 100)
    except Exception:
        limit = 100
    return jsonify(db.list_audit_log(limit=limit))





# === Батч 3 #38 #39: Background scheduler (hourly equity snapshots + auto-sync) ===
import threading as _threading

_SCHEDULER_RUNNING = False


def _background_scheduler():
    """В фоновом потоке: каждый час делать equity snapshot и инкрементальный sync."""
    import time as _t
    while _SCHEDULER_RUNNING:
        try:
            # Ждём 1 час
            for _ in range(3600):
                if not _SCHEDULER_RUNNING:
                    return
                _t.sleep(1)
            creds = load_api_creds()
            if not creds:
                continue
            # Снимок equity
            try:
                key, sec = creds
                client = BitunixClient(key, sec)
                eq = client.get_account_balance()
                db.add_equity_snapshot(eq, source="auto-hourly")
                app.logger.info("Scheduler: equity snapshot %.2f", eq)
            except Exception as e:
                app.logger.warning("Scheduler equity snapshot failed: %s", e)
            # Инкрементальный sync — только если давно не было
            try:
                settings = db.get_settings()
                last = int(settings.get("last_sync_ts") or 0)
                if int(datetime.utcnow().timestamp() * 1000) - last > 3500_000:  # >58 min
                    start_ms = max(last - 86_400_000, int(datetime(2020,1,1).timestamp()*1000))
                    end_ms = int(datetime.utcnow().timestamp() * 1000)
                    _run_sync(start_ms, end_ms, 500, "scheduler-auto")
                    app.logger.info("Scheduler: auto-sync done")
            except Exception as e:
                app.logger.warning("Scheduler auto-sync failed: %s", e)
        except Exception as e:
            app.logger.error("Scheduler crashed: %s", e)
            _t.sleep(60)


def start_scheduler():
    """v4.0: отключён — auto-sync требует per-user encryption_key."""
    app.logger.info("v4.0: scheduler отключён (per-user keys в session)")





# === #34: Gzip compression для статики ===
from flask import after_this_request
import gzip as _gzip
import io as _io


@app.after_request
def _gzip_response(response):
    """Сжимаем большие text/json ответы."""
    try:
        accept = request.headers.get("Accept-Encoding", "")
        if "gzip" not in accept.lower():
            return response
        if response.status_code < 200 or response.status_code >= 300:
            return response
        ct = response.content_type or ""
        if not any(ct.startswith(t) for t in ("text/", "application/json", "application/javascript")):
            return response
        data = response.get_data()
        if len(data) < 500:  # не сжимаем мелочёвку
            return response
        buf = _io.BytesIO()
        with _gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6) as gz:
            gz.write(data)
        response.set_data(buf.getvalue())
        response.headers["Content-Encoding"] = "gzip"
        response.headers["Content-Length"] = str(len(buf.getvalue()))
    except Exception as e:
        app.logger.warning("gzip failed: %s", e)
    return response

@app.after_request
def _invalidate_dashboard_cache_on_write(response):
    """Cache fix: сбрасываем dashboard cache на любом POST/PATCH/DELETE."""
    if request.method in ("POST", "PATCH", "DELETE", "PUT"):
        try:
            _DASHBOARD_CACHE["ts"] = 0
        except Exception:
            pass
    return response




# === #24 2FA PIN для опасных действий (reset) ===
@app.route("/api/security/pin", methods=["GET", "POST"])
@_login_required
def api_security_pin():
    """Получить статус PIN или установить новый. POST: {pin: '1234'}."""
    if request.method == "POST":
        payload = request.get_json(force=True) or {}
        pin = (payload.get("pin") or "").strip()
        if pin and not pin.isdigit():
            return jsonify({"ok": False, "error": "PIN должен быть цифры"}), 400
        # сохраним в settings (хешируем для безопасности)
        if pin:
            ph = hashlib.sha256(pin.encode()).hexdigest()
            with db.get_conn() as conn:
                conn.execute(
                    "INSERT INTO settings(key, value) VALUES ('security_pin', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (ph,))
        else:
            with db.get_conn() as conn:
                conn.execute("DELETE FROM settings WHERE key='security_pin'")
        return jsonify({"ok": True, "set": bool(pin)})
    # GET — есть ли PIN
    with db.get_conn() as conn:
        r = conn.execute("SELECT value FROM settings WHERE key='security_pin'").fetchone()
    return jsonify({"is_set": bool(r and r["value"])})


def _check_pin(provided: str) -> bool:
    """Проверка PIN. Если PIN не установлен — разрешено."""
    if not provided:
        provided = ""
    with db.get_conn() as conn:
        r = conn.execute("SELECT value FROM settings WHERE key='security_pin'").fetchone()
    if not r or not r["value"]:
        return True  # PIN не установлен
    expected = r["value"]
    return hashlib.sha256(provided.encode()).hexdigest() == expected


import hashlib


if __name__ == "__main__":
    db.init_db()
    app.logger.info("=== Pacemaker v4.0 started ===")
    print("=" * 60)
    print("  Pacemaker v4.0 — Multi-tenant")
    print("  Open: http://localhost:5000/login")
    print("  Logs:", str(LOGS_DIR / "app.log"))
    print("=" * 60)
    # v4.0: scheduler отключён (см. start_scheduler)
    try:
        start_scheduler()
    except Exception:
        pass
    app.run(host="127.0.0.1", port=5000, debug=False)
