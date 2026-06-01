/* Crypto Trading Planner v3 — frontend logic (production) */

// BUG-07 (audit 2026-05-26): XSS escape для пользовательских строк в innerHTML.
function esc(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);
const api = {
  get:   u => fetch(u).then(r => r.json()),
  post:  (u, d) => fetch(u, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(d||{})}).then(r => r.json()),
  patch: (u, d) => fetch(u, {method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify(d||{})}).then(r => r.json()),
  del:   u => fetch(u, {method:'DELETE'}).then(r => r.json()),
};

const fmtMoney = (v, d=0) => { if (v==null||isNaN(v)) return '$0'; const sign=v<0?'-':''; const a=Math.abs(v).toLocaleString('en-US',{minimumFractionDigits:d,maximumFractionDigits:d}); return `${sign}$${a}`; };
const fmtPct = (v, d=2) => v==null||isNaN(v) ? '0%' : `${v>=0?'+':''}${Number(v).toFixed(d)}%`;
const fmtDate = s => { if (!s) return '—'; try { const lc = (window.i18n && window.i18n.getLang()==='en') ? 'en-US' : 'ru-RU'; return new Date(s).toLocaleDateString(lc,{day:'2-digit',month:'short',year:'numeric'}); } catch { return s; } };
const fmtDateTime = s => { if (!s) return '—'; try { return new Date(s).toLocaleString('ru-RU',{day:'2-digit',month:'2-digit',year:'2-digit',hour:'2-digit',minute:'2-digit'}); } catch { return s; } };

function toast(msg, type='success', ms=3000) {
  const t = $('#toast'); t.textContent = msg; t.className = `toast show ${type}`;
  clearTimeout(toast._t); toast._t = setTimeout(() => t.className = 'toast', ms);
}

function animateValue(el, fromText, toText) {
  if (!el) return; if (fromText === toText) { el.textContent = toText; return; }
  const fromNum = parseFloat(String(fromText).replace(/[^\d.-]/g,'')) || 0;
  const toNum = parseFloat(String(toText).replace(/[^\d.-]/g,'')) || 0;
  if (!isFinite(toNum) || Math.abs(fromNum - toNum) < 0.01) { el.textContent = toText; return; }
  const prefix = String(toText).match(/^[^-\d]*/)[0] || '';
  const suffix = String(toText).match(/[^\d.,]*$/)[0] || '';
  const decimals = (toText.split('.')[1] || '').replace(/\D/g,'').length;
  const start = performance.now(), dur = 500;
  function step(t) {
    const p = Math.min(1, (t - start) / dur);
    const eased = 1 - Math.pow(1 - p, 3);
    const cur = fromNum + (toNum - fromNum) * eased;
    el.textContent = prefix + cur.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals }) + suffix;
    if (p < 1) requestAnimationFrame(step); else el.textContent = toText;
  }
  requestAnimationFrame(step);
}
function setVal(sel, val) {
  const el = $(sel); if (!el) return;
  const prev = el.dataset._prev || el.textContent;
  el.dataset._prev = val;
  animateValue(el, prev, val);
}

// ===== state cache (UI only) =====
let _trades = [];
let _data = null;
let _ui = { period: 'D', sort: { col: 'ts', dir: 'desc' }, filter_setup: null };

// ===== charts =====
Chart.defaults.color = '#8a93a8';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 11;
let growthChart, returnsChart;

function makeGrad(ctx, top, bottom) {
  const a = ctx.chart.chartArea; if (!a) return top;
  const g = ctx.chart.ctx.createLinearGradient(0, a.top, 0, a.bottom);
  g.addColorStop(0, top); g.addColorStop(1, bottom);
  return g;
}

function renderGrowthChart(plan, actual) {
  const labels = plan.map(p => p.label);
  const planS = plan.map(p => p.closing);
  const factS = plan.map((p, i) => actual[i] ? actual[i].closing : null);
  if (growthChart) growthChart.destroy();
  growthChart = new Chart($('#growthChart'), {
    type: 'line',
    data: { labels, datasets: [
      { label: t('equity.plan'), data:planS, borderColor:'#4ea1ff', backgroundColor:c=>makeGrad(c,'rgba(78,161,255,0.30)','rgba(78,161,255,0)'), fill:true, tension:0.35, borderWidth:2, pointRadius:0 },
      { label: t('equity.fact'), data:factS, borderColor:'#a96cff', backgroundColor:c=>makeGrad(c,'rgba(169,108,255,0.40)','rgba(169,108,255,0)'), fill:true, tension:0.35, borderWidth:2.5, pointRadius:0, spanGaps:true },
    ]},
    options: {
      responsive:true, maintainAspectRatio:false, interaction:{mode:'index',intersect:false},
      plugins:{legend:{display:false}, tooltip:{backgroundColor: getComputedStyle(document.documentElement).getPropertyValue('--bg-elev').trim() || '#11151f',borderColor: getComputedStyle(document.documentElement).getPropertyValue('--border-hi').trim() || '#2d3548',borderWidth:1,padding:10,callbacks:{label:c=>`${c.dataset.label}: ${fmtMoney(c.parsed.y,0)}`}}},
      scales:{x:{grid:{color:'rgba(255,255,255,0.04)'}},y:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{callback:v=>fmtMoney(v,0)}}}
    }
  });
}
function renderReturnsChart(plan, actual) {
  const labels = plan.map(p => p.label);
  const planS = plan.map(p => p.return_pct);
  const factSraw = plan.map((p, i) => actual[i] ? actual[i].return_pct : null);
  const CAP = 150;
  let factS = factSraw.map(v => v == null ? null : Math.max(-CAP, Math.min(CAP, v)));
  // ПРАВКА C: если все факт-значения null или 0 — не рисуем фактовую серию, чтобы не показывать плоскую линию
  const hasRealFact = factSraw.some(v => v != null && Math.abs(v) > 0.001);
  if (!hasRealFact) factS = null;
  if (returnsChart) returnsChart.destroy();
  returnsChart = new Chart($('#returnsChart'), {
    type: 'bar',
    data: { labels, datasets: [
      { label: t('equity.plan'), data:planS, backgroundColor:'rgba(78,161,255,0.55)', borderRadius:3 },
      ...(factS ? [{ label: t('equity.fact'), data:factS, backgroundColor:'rgba(169,108,255,0.85)', borderRadius:3 }] : []),
    ]},
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins:{
        legend:{display:false},
        tooltip:{
          backgroundColor: getComputedStyle(document.documentElement).getPropertyValue('--bg-elev').trim() || '#11151f',borderColor: getComputedStyle(document.documentElement).getPropertyValue('--border-hi').trim() || '#2d3548',borderWidth:1,padding:10,
          callbacks:{
            label: (c) => {
              if (c.parsed.y == null) return `${c.dataset.label}: —`;
              const raw = c.dataset.label === t('equity.fact') ? factSraw[c.dataIndex] : c.parsed.y;
              const clipped = Math.abs(raw) > CAP;
              return `${c.dataset.label}: ${raw.toFixed(2)}%` + (clipped ? ' (обрезано на графике)' : '');
            }
          }
        }
      },
      scales:{
        x:{grid:{display:false}},
        y:{
          grid:{color:'rgba(255,255,255,0.04)'},
          min: -CAP, max: CAP,
          ticks:{callback:v=>v+'%'}
        }
      }
    }
  });
}

// ===== main render =====
async function loadAll(opts = {}) {
  // BUG-14: грузим deposits параллельно (1 батч на загрузку, а не каждый render)
  const pfScope = window._planfactGoalScope || 'active';
  const [data, trades, deposits] = await Promise.all([
    api.get('/api/dashboard?planfact_scope=' + encodeURIComponent(pfScope)),
    api.get('/api/trades'),
    api.get('/api/deposits'),
  ]);
  _data = data;
  _trades = trades;
  window._deposits = deposits;
  render(opts);
}

function render(opts = {}) {
  if (!_data) return;
  const d = _data;
  const eq = d.actual.current_equity;
  const start = +d.settings.start_capital;
  const goal = d.goal || {};
  const goalAmt = +goal.amount || 0;

  // Hero equity
  setVal('#heroEquity', fmtMoney(eq, 2));
  if (opts.flash) { const el = $('#heroEquity'); el.classList.remove('flash'); void el.offsetWidth; el.classList.add('flash'); }
  // #heroDeltaPct удалён — общий % роста теперь видно по progress-bar и графику

  // Депозиты подгружаются в loadAll; #metaStart/#metaDepNet/#metaProfit удалены из UI

  // Goal
  $('#goalName').textContent = goal.name && goal.name.trim() ? goal.name : t('goal.no_name');
  setVal('#goalAmount', fmtMoney(goalAmt, 0));
  // #goalCur и #goalMax удалены из новой карточки цели (значения теперь в #heroEquity и #goalAmount)
  setVal('#goalPctBig', d.pct_to_goal.toFixed(1) + '%');
  $('#progressBar').style.width = Math.min(100, d.pct_to_goal) + '%';
  // Прогноз цели: учитываем unavailable — показываем CTA-баннер вместо мелкого текста
  const fcEl = $('#goalForecast');
  // banner host — в gcf-right (рядом с pace chip)
  const fcSlot = document.querySelector('.goal-card-footer .gcf-right');
  let fcBanner = document.getElementById('forecastBanner');
  if (d.forecast && d.forecast.unavailable) {
    const reasons = {
      no_goal: { msg: t('forecast.no_goal'), cta: t('forecast.cta_create') },
      no_capital_no_deposit: { msg: t('forecast.no_capital'), cta: t('forecast.cta_open_wizard') },
      no_growth: { msg: t('forecast.no_growth'), cta: t('forecast.cta_open_wizard') },
      too_far: { msg: t('forecast.too_far'), cta: t('forecast.cta_open_wizard') },
    };
    const r = reasons[d.forecast.reason] || { msg: t('forecast.unavailable'), cta: t('forecast.cta_open_wizard') };
    fcEl.textContent = '—';
    fcEl.style.color = 'var(--text-muted)';
    if (fcSlot && !fcBanner) {
      fcBanner = document.createElement('button');
      fcBanner.id = 'forecastBanner';
      fcBanner.className = 'forecast-cta';
      fcSlot.appendChild(fcBanner);
      fcBanner.addEventListener('click', () => {
        // Открываем модалку Goal Onboarding с текущими значениями
        (async () => {
          try {
            const s = await fetch('/api/settings').then(r => r.json());
            const dd = await fetch('/api/dashboard').then(r => r.json());
            const g = dd.goal || {};
            const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
            set('goalOnbAmount', g.amount || 100000);
            set('goalOnbDeposit', g.monthly_deposit || 0);
            set('goalOnbReturn', g.monthly_return_pct || 10);
            set('goalOnbName', g.name || 'Моя цель');
            set('goalOnbStartCap', s.start_capital || 0);
            set('goalOnbStartDate', s.start_date || new Date().toISOString().slice(0,10));
          } catch (e) {}
          document.getElementById('goalOnboardingModal')?.classList.add('open');
        })();
      });
    }
    if (fcBanner) {
      fcBanner.innerHTML = '<span class="fc-icon">⚠</span><span class="fc-msg">' + esc(r.msg) + '</span><span class="fc-cta">' + esc(r.cta) + ' →</span>';
      fcBanner.style.display = '';
    }
  } else if (d.forecast) {
    fcEl.textContent = fmtDate(d.forecast.date) + (d.forecast.months_left ? ' · ' + t('goal.forecast_months', d.forecast.months_left) : ' · ' + t('goal.forecast_already'));
    fcEl.style.color = '';
    if (fcBanner) fcBanner.style.display = 'none';
  } else {
    fcEl.textContent = '—';
    if (fcBanner) fcBanner.style.display = 'none';
  }
  $('#goalRemain').textContent = eq >= goalAmt ? '$0 — ✓' : fmtMoney(goalAmt - eq, 0);
  // #monthsTracked удалён из HTML — рендерим только если элемент есть (для обратной совместимости)
  const monthsEl = document.querySelector('#monthsTracked');
  if (monthsEl) monthsEl.textContent = d.actual.months.length;

  // Checkpoints
  const cps = $('#checkpoints'); cps.innerHTML = '';
  [25, 50, 75].forEach(p => {
    const cp = document.createElement('div');
    cp.className = 'checkpoint' + (d.pct_to_goal >= p ? ' passed' : '');
    cp.style.left = p + '%';
    cp.dataset.label = `${p}% · ${fmtMoney(goalAmt * p / 100, 0)}`;
    cps.appendChild(cp);
  });

  // Goal achieved banner
  const ban = $('#goalAchievedBanner');
  if (eq >= goalAmt && goalAmt > 0 && !goal.achieved_at) {
    ban.classList.add('show');
    $('#gaSub').textContent = `"${goal.name}" — ${fmtMoney(goalAmt, 0)} — взята!`;
  } else ban.classList.remove('show');

  // === Плашка «За всё время» под чипами периода (общая картина не теряется) ===
  if (d.stats) {
    const so = document.getElementById('soTotal');
    if (so) so.textContent = d.stats.total + ' сделок';
    const sw = document.getElementById('soWinrate');
    if (sw) sw.textContent = (d.stats.winrate || 0).toFixed(1) + '%';
    const sn = document.getElementById('soNet');
    if (sn) {
      sn.textContent = (d.stats.net_pnl >= 0 ? '+' : '') + fmtMoney(d.stats.net_pnl, 0);
      sn.style.color = d.stats.net_pnl > 0 ? 'var(--green)' : (d.stats.net_pnl < 0 ? 'var(--red)' : '');
    }
  }

  // === МЕТРИКИ В КАРТОЧКЕ ЦЕЛИ — ТОЛЬКО за период активной цели ===
  // Если в рамках цели нет сделок — показываем плейсхолдер.
  const gm = d.goal_metrics || { is_empty_for_goal: true };
  const metricsBlock = document.querySelector('.goal-card-metrics');
  let placeholder = document.getElementById('goalEmptyPlaceholder');

  if (gm.is_empty_for_goal) {
    // Прячем сетку метрик, показываем плейсхолдер
    if (metricsBlock) metricsBlock.style.display = 'none';
    if (!placeholder) {
      placeholder = document.createElement('div');
      placeholder.id = 'goalEmptyPlaceholder';
      placeholder.className = 'goal-empty-placeholder';
      metricsBlock?.parentNode?.insertBefore(placeholder, metricsBlock);
    }
    const msg = gm.reason === 'no_goal'
      ? t('goal.placeholder_no_goal')
      : t('goal.placeholder_no_trades');
    placeholder.innerHTML = `<div class="gep-msg">${esc(msg)}</div>` +
      (gm.goal_start ? `<div class="gep-sub">${esc(t('goal.active_since', fmtDate(gm.goal_start)))}</div>` : '');
  } else {
    if (metricsBlock) metricsBlock.style.display = '';
    if (placeholder) placeholder.remove();
    // Net P&L (за период цели)
    const npEl = document.getElementById('metricNetPnl');
    if (npEl) {
      npEl.textContent = (gm.net_pnl >= 0 ? '+' : '') + fmtMoney(gm.net_pnl, 2);
      npEl.classList.toggle('pos', gm.net_pnl > 0);
      npEl.classList.toggle('neg', gm.net_pnl < 0);
    }
    // Серия (за период цели)
    const stEl = document.getElementById('metricStreak');
    if (stEl) {
      const bestWin = +gm.best_win || 0;
      const bestLoss = +gm.best_loss || 0;
      if (bestWin > 0 || bestLoss > 0) {
        stEl.textContent = `${bestWin} / ❄${bestLoss}`;
        stEl.className = 'gcm-value pos';
        stEl.title = `Лучшая серия побед: ${bestWin}\nХудшая серия поражений: ${bestLoss}`;
      } else {
        stEl.textContent = '—';
        stEl.className = 'gcm-value';
      }
    }
    // Max DD (за период цели)
    const ddEl = document.getElementById('metricDrawdown');
    if (ddEl) {
      ddEl.textContent = (gm.max_drawdown || 0).toFixed(2) + '%';
      ddEl.classList.toggle('neg', (gm.max_drawdown || 0) > 0);
    }
    const trEl = document.getElementById('metricTrades');
    if (trEl) trEl.textContent = String(gm.total || 0);
    const wrEl = document.getElementById('metricWinrate');
    if (wrEl) wrEl.textContent = (gm.winrate || 0).toFixed(1) + '%';
    // Profit Factor (new in Iter 2)
    const pfEl = document.getElementById('metricProfitFactor');
    if (pfEl) {
      if (gm.profit_factor === null || gm.profit_factor === undefined) {
        pfEl.textContent = '∞';
        pfEl.classList.add('pos'); pfEl.classList.remove('neg');
      } else {
        const v = +gm.profit_factor || 0;
        pfEl.textContent = v.toFixed(2);
        pfEl.classList.toggle('pos', v >= 1.5);
        pfEl.classList.toggle('neg', v < 1.0 && v > 0);
      }
    }
  }

  // API status pill
  const ap = $('#apiStatus');
  ap.classList.toggle('ok', d.api_connected);
  $('#apiStatusText').textContent = d.api_connected ? t('header.bitunix_connected') : t('header.bitunix_not_set');

  // Stats (period from API)
  loadStats(_ui.period);

  // Plan/Fact
  renderPlanFact(d.pf_rows, d.pf_summary);
  // ПРАВКА #8: скрыть селектор «Цели в расчёте» если архива нет
  const pfGoalScopeEl = document.getElementById('planfactGoalScope');
  if (pfGoalScopeEl) {
    const archive = (d.goals_archive || []);
    const hasArchive = archive.length > 0;
    const wrap = pfGoalScopeEl.closest('.filter-bar');
    if (wrap) {
      // показываем селектор только если есть архив
      const lbl = wrap.querySelector('.fb-label');
      pfGoalScopeEl.style.display = hasArchive ? '' : 'none';
      if (lbl && lbl.textContent.includes('Цели')) lbl.style.display = hasArchive ? '' : 'none';
    }
  }

  // Tables
  renderTradesTable();
  renderDepositsTable();
  renderSetupsTab();
  renderArchive();

  // Setup dropdown in trade modal
  fillSetupDropdown(d.setups);
  renderSetupFilterChips(d.setups);

  // Charts
  renderGrowthChart(d.plan, d.actual.months);
  renderReturnsChart(d.plan, d.actual.months);

  // Settings prefills (safe: skip if element missing)
  const _set = (sel, v) => { const el = document.querySelector(sel); if (el) el.value = v; };
  _set('#setStart', d.settings.start_capital);
  _set('#setDeposit', d.settings.monthly_deposit);
  _set('#setStartDate', d.settings.start_date);
  _set('#goalAmountInput', goalAmt);
  _set('#goalReturnInput', goal.monthly_return_pct || 10);
  _set('#goalNameInput', goal.name || '');
  // monthly_deposit теперь живёт на цели; prefill в модалке цели
  _set('#goalDepositInput', (goal.monthly_deposit != null ? goal.monthly_deposit : d.settings.monthly_deposit) || 0);

  // Scenario chips
  const sc = +d.settings.scenario || 10;
  $$('.scenario-chip').forEach(c => c.classList.toggle('active',
    +c.dataset.s === sc || (c.dataset.s === 'custom' && ![5,10,15].includes(sc))));

  // Discipline indicator on planfact tab
  const lastDisc = d.pf_rows.length ? d.pf_rows[d.pf_rows.length - 1].discipline : null;
  const pfTab = document.querySelector('.tab[data-tab="planfact"]');
  const existingDot = pfTab.querySelector('.tab-dot');
  if (lastDisc && lastDisc.tag === 'bad') {
    if (!existingDot) { const dot = document.createElement('span'); dot.className = 'tab-dot'; pfTab.appendChild(dot); }
  } else if (existingDot) existingDot.remove();
}

function fetchDepositsForMeta(start, eq, trackStart) {
  // BUG-14: берём из кэша window._deposits (загружено в loadAll), без fetch на каждый render
  const deps = window._deposits || [];
  const filtered = trackStart
    ? deps.filter(d => new Date(d.ts) > trackStart)
    : deps;
  const net = filtered.reduce(
    (a, x) => a + (x.kind === 'deposit' ? +x.amount_usd : -+x.amount_usd),
    0
  );
  renderDepositsTable();
}

async function loadStats(period) {
  const s = await api.get('/api/stats?period=' + period);
  setVal('#statTotal', String(s.total));
  setVal('#statWins', String(s.wins));
  setVal('#statLosses', String(s.losses));
  setVal('#statWinrate', s.winrate.toFixed(1) + '%');
  setVal('#statAvg', fmtMoney(s.avg, 2));
  setVal('#statBest', fmtMoney(s.best, 2));
  setVal('#statWorst', fmtMoney(s.worst, 2));
  setVal('#statNet', fmtMoney(s.net_pnl, 2));
}

function fillSetupDropdown(setups) {
  const sel = $('#tradeSetup'); const cur = sel.value;
  sel.innerHTML = '<option value="">— нет —</option>' + setups.map(s => `<option value="${s}">${s}</option>`).join('');
  if (setups.includes(cur)) sel.value = cur;
}

function renderSetupFilterChips(setups) {
  const box = $('#setupFilterChips'); if (!box) return;
  const used = new Set(_trades.map(t => t.setup).filter(Boolean));
  box.innerHTML =
    `<button class="filter-chip ${_ui.filter_setup==null?'active':''}" data-setup="">${t('trades.filter_all_n', _trades.length)}</button>` +
    setups.filter(s => used.has(s)).map(s =>
      `<button class="filter-chip ${_ui.filter_setup===s?'active':''}" data-setup="${esc(s)}">${esc(s)} (${_trades.filter(t=>t.setup===s).length})</button>`
    ).join('');
  box.querySelectorAll('.filter-chip').forEach(c => c.addEventListener('click', () => {
    _ui.filter_setup = c.dataset.setup || null;
    _ui.tradesPage = 1;
    renderSetupFilterChips(setups);
    renderTradesTable();
  }));
}

// текущая страница списка сделок (1-индексация)
if (typeof _ui.tradesPage === 'undefined') _ui.tradesPage = 1;
const TRADES_PER_PAGE = 100;

// === Универсальный фильтр для журналов сделок и депозитов ===
function applyFilterBar(items, opts) {
  opts = opts || {};
  const { period, from, to, goalScope } = opts;
  let out = Array.isArray(items) ? [...items] : [];

  // Период (день/неделя/месяц/год)
  if (period && period !== 'ALL' && period !== 'CUSTOM') {
    const now = new Date();
    const cut = new Date(now);
    if (period === 'D') cut.setDate(now.getDate() - 1);
    else if (period === 'W') cut.setDate(now.getDate() - 7);
    else if (period === 'M') cut.setMonth(now.getMonth() - 1);
    else if (period === 'Y') cut.setFullYear(now.getFullYear() - 1);
    out = out.filter(x => x && x.ts && new Date(x.ts) >= cut);
  }

  // Кастомные даты
  if (from) {
    const f = new Date(from + 'T00:00:00');
    out = out.filter(x => x && x.ts && new Date(x.ts) >= f);
  }
  if (to) {
    const t = new Date(to + 'T23:59:59');
    out = out.filter(x => x && x.ts && new Date(x.ts) <= t);
  }

  // Фильтр по цели
  if (goalScope === 'active') {
    const g = _data && _data.goal;
    if (g && g.created_at) {
      const gs = new Date(g.created_at + 'T00:00:00');
      const ge = g.achieved_at ? new Date(g.achieved_at + 'T23:59:59') : null;
      out = out.filter(x => {
        if (!x || !x.ts) return false;
        const ts = new Date(x.ts);
        if (ts < gs) return false;
        if (ge && ts > ge) return false;
        return true;
      });
    }
  } else if (goalScope === 'archive') {
    const arc = (_data && _data.goals_archive) || [];
    if (arc.length) {
      // в диапазон ЛЮБОЙ архивной цели
      const ranges = arc.map(g => ({
        s: g.created_at ? new Date(g.created_at + 'T00:00:00').getTime() : -Infinity,
        e: g.achieved_at ? new Date(g.achieved_at + 'T23:59:59').getTime() : Infinity,
      }));
      out = out.filter(x => {
        if (!x || !x.ts) return false;
        const ts = new Date(x.ts).getTime();
        return ranges.some(r => ts >= r.s && ts <= r.e);
      });
    } else {
      out = [];  // архив пуст — ничего не показываем
    }
  }
  return out;
}

function renderTradesTable() {
  try {
    const searchEl = document.getElementById('tradeSearch');
    const q = searchEl ? searchEl.value.toLowerCase().trim() : '';
    let arr = Array.isArray(_trades) ? [..._trades] : [];
    if (_ui.filter_setup) arr = arr.filter(t => t && t.setup === _ui.filter_setup);

    // === Локальные фильтры filter-bar (период/даты/цель) ===
    arr = applyFilterBar(arr, {
      period: window._tradesPeriod,
      from: document.getElementById('tradesFrom') && document.getElementById('tradesFrom').value,
      to: document.getElementById('tradesTo') && document.getElementById('tradesTo').value,
      goalScope: window._tradesGoalScope,
    });
    const { col, dir } = _ui.sort;
    // BUG-15: явные компараторы по типу. Раньше смешивались String/Number через ||,
    // давало NaN-сравнения и непредсказуемый порядок.
    const NUMERIC = new Set(['entry_price','exit_price','qty','pnl_usd','pnl_pct','fee_usd']);
    const DATELIKE = new Set(['ts']);
    arr.sort((a, b) => {
      const va = (a||{})[col], vb = (b||{})[col];
      let cmp;
      if (DATELIKE.has(col)) {
        cmp = (new Date(va||0)).getTime() - (new Date(vb||0)).getTime();
      } else if (NUMERIC.has(col)) {
        const na = parseFloat(va); const nb = parseFloat(vb);
        cmp = (isNaN(na)?-Infinity:na) - (isNaN(nb)?-Infinity:nb);
      } else {
        cmp = String(va||'').localeCompare(String(vb||''));
      }
      return dir === 'asc' ? cmp : -cmp;
    });
    if (q) arr = arr.filter(t =>
      ((t||{}).symbol||'').toLowerCase().includes(q) ||
      ((t||{}).note||'').toLowerCase().includes(q) ||
      ((t||{}).setup||'').toLowerCase().includes(q));

    $$('#tradesTable th.sortable').forEach(th => {
      th.classList.remove('sort-asc','sort-desc');
      const arrow = th.querySelector('.sort-arrow');
      if (th.dataset.sort === col) {
        th.classList.add(dir === 'asc' ? 'sort-asc' : 'sort-desc');
        if (arrow) arrow.textContent = dir === 'asc' ? '▲' : '▼';
      } else if (arrow) arrow.textContent = '▼';
    });

    const body = $('#tradesBody');
    if (!body) return;
    if (!arr.length) {
      body.innerHTML = `<tr><td colspan="11" class="empty">
        <div class="empty-icon">📭</div>
        <div class="empty-title">${q ? t('trades.no_match') : t('trades.no_trades')}</div>
        <div class="empty-sub">${q ? t('trades.try_other_query') : t('trades.add_hint')}</div>
      </td></tr>`;
      renderTradesPager(0, 0, 1, 1);
      return;
    }

    // === Пагинация ===
    const total = arr.length;
    const pages = Math.max(1, Math.ceil(total / TRADES_PER_PAGE));
    if (_ui.tradesPage > pages) _ui.tradesPage = pages;
    if (_ui.tradesPage < 1) _ui.tradesPage = 1;
    const startIdx = (_ui.tradesPage - 1) * TRADES_PER_PAGE;
    const slice = arr.slice(startIdx, startIdx + TRADES_PER_PAGE);

    body.innerHTML = slice.map(t => {
      try {
        const pnl = +t.pnl_usd || 0;
        const cls = pnl > 0 ? 'cell-pos' : (pnl < 0 ? 'cell-neg' : '');
        const sideTag = t.side==='LONG'?'<span class="tag tag-long">LONG</span>':t.side==='SHORT'?'<span class="tag tag-short">SHORT</span>':'<span class="tag tag-manual">—</span>';
        const srcTag = t.source==='bitunix'?'<span class="tag tag-bitunix">Bitunix</span>':'<span class="tag tag-manual">Manual</span>';
        const setupTag = t.setup ? `<span class="tag tag-setup">${esc(t.setup)}</span>` : '<span class="muted">—</span>';
        return `<tr data-trade-id="${t.id}" data-trade-row="1" style="cursor:pointer;" title="Клик для графика монеты">
          <td>${fmtDateTime(t.ts)}</td>
          <td><b>${esc(t.symbol)||'—'}</b></td>
          <td>${sideTag}</td>
          <td>${setupTag}</td>
          <td class="cell-num">${t.entry_price?(+t.entry_price).toFixed(2):'—'}</td>
          <td class="cell-num">${t.exit_price?(+t.exit_price).toFixed(2):'—'}</td>
          <td class="cell-num ${cls}">${fmtMoney(pnl,2)}</td>
          <td class="cell-num ${cls}">${(+t.pnl_pct||0).toFixed(2)}%</td>
          <td>${srcTag}</td>
          <td class="trade-note-cell" data-trade-id="${t.id}" title="Двойной клик чтобы редактировать">${esc(t.note)}</td>
          <td><button class="icon-btn-mini" data-del-trade="${t.id}" title="Удалить">✕</button></td>
        </tr>`;
      } catch (e) {
        return `<tr><td colspan="11" class="muted">(битая строка #${t && t.id})</td></tr>`;
      }
    }).join('');

    renderTradesPager(total, slice.length, _ui.tradesPage, pages);
  } catch (e) {
    console.error('renderTradesTable failed:', e);
    if (typeof toast === 'function') toast('✗ Ошибка рендера таблицы: ' + e.message, 'error');
  }
}

function renderTradesPager(total, shown, page, pages) {
  let host = document.getElementById('tradesPager');
  const panel = document.getElementById('tab-trades');
  if (!host && panel) {
    host = document.createElement('div');
    host.id = 'tradesPager';
    host.style.cssText = 'display:flex; align-items:center; justify-content:space-between; padding: 10px 4px; gap:10px; font-size:12.5px; flex-wrap:wrap;';
    const tableWrap = panel.querySelector('.table-wrap');
    if (tableWrap && tableWrap.parentNode) {
      tableWrap.parentNode.insertBefore(host, tableWrap.nextSibling);
    } else {
      panel.appendChild(host);
    }
  }
  if (!host) return;
  if (total <= TRADES_PER_PAGE && pages <= 1) {
    host.innerHTML = total > 0
      ? `<span class="muted">${t('trades.pagination_full', total, total)}</span><span></span>`
      : '';
    return;
  }
  const btn = (label, p, disabled) =>
    `<button class="btn btn-ghost" data-trades-page="${p}" ${disabled?'disabled':''} style="padding:4px 10px; min-width:36px;">${label}</button>`;
  host.innerHTML =
    `<span class="muted">${t('trades.pagination_paged', shown, total, page, pages)}</span>` +
    `<span style="display:inline-flex; gap:6px; align-items:center;">` +
      btn('« 1', 1, page === 1) +
      btn('‹', Math.max(1, page-1), page === 1) +
      `<span style="padding:0 4px;">${page}</span>` +
      btn('›', Math.min(pages, page+1), page === pages) +
      btn(pages+' »', pages, page === pages) +
    `</span>`;
  host.querySelectorAll('[data-trades-page]').forEach(b => {
    b.addEventListener('click', () => {
      const p = parseInt(b.getAttribute('data-trades-page'), 10);
      if (!isNaN(p)) {
        _ui.tradesPage = p;
        renderTradesTable();
      }
    });
  });
}

function renderDepositsTable() {
  const allDeps = window._deposits || [];
  // Общий хелпер — тот же что у вкладки Сделки
  const deps = applyFilterBar(allDeps, {
    period: window._depositPeriod,
    from: document.getElementById('depositsFrom') && document.getElementById('depositsFrom').value,
    to: document.getElementById('depositsTo') && document.getElementById('depositsTo').value,
    goalScope: window._depositGoalScope,
  });
  const arr = [...deps].sort((a,b)=>String(b.ts).localeCompare(String(a.ts)));
  const depIn = deps.filter(d=>d.kind==='deposit').reduce((a,d)=>a+(+d.amount_usd||0),0);
  const depOut = deps.filter(d=>d.kind==='withdraw').reduce((a,d)=>a+(+d.amount_usd||0),0);
  setVal('#depTotalIn', '+' + fmtMoney(depIn, 2));
  setVal('#depTotalOut', '−' + fmtMoney(depOut, 2));
  setVal('#depNet', fmtMoney(depIn - depOut, 2));

  const body = $('#depositsBody');
  if (!arr.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty"><div class="empty-icon">💵</div><div class="empty-title">Депозитов пока нет</div><div class="empty-sub">Добавь первое пополнение</div></td></tr>`;
    return;
  }
  body.innerHTML = arr.map(d => {
    const kindTag = d.kind==='deposit'?'<span class="tag tag-dep">Пополнение</span>':'<span class="tag tag-wd">Вывод</span>';
    const srcTag = d.source==='bitunix'?'<span class="tag tag-bitunix">Bitunix</span>':'<span class="tag tag-manual">Manual</span>';
    const sign = d.kind==='deposit'?'+':'−';
    const cls = d.kind==='deposit'?'cell-pos':'cell-neg';
    return `<tr>
      <td>${fmtDateTime(d.ts)}</td><td>${kindTag}</td>
      <td class="cell-num ${cls}">${sign}${fmtMoney(Math.abs(d.amount_usd),2)}</td>
      <td>${srcTag}</td><td>${esc(d.note)}</td>
      <td><button class="icon-btn-mini" data-del-dep="${d.id}" title="Удалить">✕</button></td>
    </tr>`;
  }).join('');
}

function renderPlanFact(rows, summary) {
  $('#pfSummary').innerHTML = `
    <div class="pf-card"><div class="pf-card-label">Месяцев выше плана</div><div class="pf-card-value cell-pos">${summary.months_above}</div></div>
    <div class="pf-card"><div class="pf-card-label">Месяцев ниже плана</div><div class="pf-card-value cell-neg">${summary.months_below}</div></div>
    <div class="pf-card"><div class="pf-card-label">Avg отклонение</div><div class="pf-card-value ${summary.avg_dev>=0?'cell-pos':'cell-neg'}">${summary.avg_dev>=0?'+':''}${fmtMoney(summary.avg_dev,0)}</div></div>
    <div class="pf-card"><div class="pf-card-label">Avg % отклонение</div><div class="pf-card-value ${summary.avg_dev_pct>=0?'cell-pos':'cell-neg'}">${summary.avg_dev_pct>=0?'+':''}${summary.avg_dev_pct.toFixed(2)}%</div></div>
  `;
  const body = $('#planfactBody');
  if (!rows.length) { body.innerHTML = `<tr><td colspan="7" class="empty"><div class="empty-icon">📊</div><div class="empty-title">Данных нет</div></td></tr>`; return; }
  body.innerHTML = rows.map(r => {
    const rowCls = r.dev != null ? (r.dev > 0 ? 'row-above-plan' : (r.dev < 0 ? 'row-below-plan' : '')) : '';
    const devCls = r.dev > 0 ? 'cell-pos' : (r.dev < 0 ? 'cell-neg' : '');
    const dispCls = r.discipline.tag==='ok'?'tag-disc-ok':r.discipline.tag==='warn'?'tag-disc-warn':r.discipline.tag==='bad'?'tag-disc-bad':'tag-disc-none';
    return `<tr class="${rowCls}">
      <td><b>${r.label}</b></td>
      <td class="cell-num">${r.plan_close != null ? fmtMoney(r.plan_close, 0) : '—'}</td>
      <td class="cell-num">${r.fact_close != null ? `<b>${fmtMoney(r.fact_close, 0)}</b>` : '—'}</td>
      <td class="cell-num ${devCls}">${r.dev != null ? (r.dev>=0?'+':'')+fmtMoney(r.dev, 0) : '—'}</td>
      <td class="cell-num ${devCls}">${r.dev_pct != null ? (r.dev_pct>=0?'+':'')+r.dev_pct.toFixed(2)+'%' : '—'}</td>
      <td class="cell-num">${r.trades}</td>
      <td><span class="tag ${dispCls}">${r.discipline.label}</span></td>
    </tr>`;
  }).join('');
}

function renderSetupsTab() {
  const bySetup = {};
  for (const t of _trades) {
    const k = t.setup || '— без сетапа —';
    if (!bySetup[k]) bySetup[k] = { count:0, wins:0, pnl:0, fee:0 };
    bySetup[k].count++;
    if ((+t.pnl_usd||0)>0) bySetup[k].wins++;
    bySetup[k].pnl += +t.pnl_usd||0;
    bySetup[k].fee += +t.fee_usd||0;
  }
  const entries = Object.entries(bySetup).sort((a,b)=>(b[1].pnl - b[1].fee) - (a[1].pnl - a[1].fee));
  const grid = $('#setupGrid');
  if (!entries.length) {
    grid.innerHTML = `<div class="empty" style="grid-column:1/-1;"><div class="empty-icon">🎯</div><div class="empty-title">Нет данных по сетапам</div><div class="empty-sub">Добавь сделке тэг сетапа</div></div>`;
    return;
  }
  grid.innerHTML = entries.map(([name, s]) => {
    const net = s.pnl - s.fee;
    const cls = net>0?'cell-pos':(net<0?'cell-neg':'');
    const winrate = s.count ? s.wins/s.count*100 : 0;
    return `<div class="setup-card">
      <div class="setup-card-head"><span class="tag tag-setup">${esc(name)}</span><span class="muted">${s.count} сделок</span></div>
      <div class="setup-card-pnl ${cls}">${fmtMoney(net, 2)}</div>
      <div class="setup-card-meta">Winrate: <b style="color:var(--text-primary);">${winrate.toFixed(1)}%</b> · Avg: <b style="color:var(--text-primary);">${fmtMoney(net/s.count, 2)}</b></div>
    </div>`;
  }).join('');
}

async function renderArchive() {
  const archive = await api.get('/api/goals/archive');
  const list = $('#archiveList');
  const items = [];
  if (_data && _data.goal) items.push({ ..._data.goal, _active: true });
  for (const g of archive) items.push({ ...g, _active: false });
  if (!items.length) {
    list.innerHTML = '<div class="gh-empty">' +
      '<div class="gh-empty-icon">🏆</div>' +
      '<div class="gh-empty-title">У тебя ещё нет целей</div>' +
      '<div class="gh-empty-sub">Создай первую через ✏ в карточке цели</div></div>';
    return;
  }
  const trades = Array.isArray(_trades) ? _trades : [];
  function metricsForGoal(g) {
    const start = g.created_at ? new Date(g.created_at + 'T00:00:00') : null;
    const end = g.achieved_at ? new Date(g.achieved_at + 'T23:59:59') : new Date();
    const inRange = trades.filter(t => {
      if (!t.ts) return false;
      const ts = new Date(t.ts);
      return (!start || ts >= start) && ts <= end;
    });
    const wins = inRange.filter(t => (+t.pnl_usd||0) > 0).length;
    const losses = inRange.filter(t => (+t.pnl_usd||0) < 0).length;
    const net = inRange.reduce((a,t)=> a + (+t.pnl_usd||0) - (+t.fee_usd||0), 0);
    const decisive = wins + losses;
    const wr = decisive ? wins/decisive*100 : 0;
    let days = '—';
    if (start) {
      const ms = end.getTime() - start.getTime();
      days = Math.max(1, Math.round(ms / 86400000)) + ' дн';
    }
    return { total: inRange.length, wins, losses, net, winrate: wr, days };
  }
  list.innerHTML = '<div class="archive-list-grid">' + items.map(g => {
    const m = metricsForGoal(g);
    const badge = g._active
      ? '<span class="gh-badge active">⚡ Активная</span>'
      : '<span class="gh-badge">🏆 Достигнута ' + esc(fmtDate(g.achieved_at)) + '</span>';
    const cls = g._active ? 'active' : (g.achieved_at ? 'achieved' : '');
    const netCls = m.net > 0 ? 'pos' : (m.net < 0 ? 'neg' : '');
    return '<div class="gh-card-v2 ' + cls + '">' +
      '<div class="ghc-main">' +
        '<div class="ghc-name-row">' +
          '<span class="ghc-name">' + esc(g.name || 'Цель') + '</span>' +
          '<span class="ghc-amount">' + fmtMoney(g.amount, 0) + '</span>' +
        '</div>' +
        '<div class="ghc-meta">' +
          'Создана ' + esc(fmtDate(g.created_at)) +
          (g.achieved_at ? ' → достигнута ' + esc(fmtDate(g.achieved_at)) : ' → сейчас') +
          ' · план ' + (g.monthly_return_pct || 10) + '%/мес' +
          (g.monthly_deposit ? ' · взнос ' + fmtMoney(g.monthly_deposit, 0) + '/мес' : '') +
        '</div>' +
        '<div class="ghc-stats">' +
          '<span class="ghc-stat"><span class="ghc-stat-label">Длительность:</span> <span class="ghc-stat-value">' + m.days + '</span></span>' +
          '<span class="ghc-stat"><span class="ghc-stat-label">Сделок:</span> <span class="ghc-stat-value">' + m.total + '</span></span>' +
          '<span class="ghc-stat"><span class="ghc-stat-label">Winrate:</span> <span class="ghc-stat-value">' + m.winrate.toFixed(1) + '%</span></span>' +
          '<span class="ghc-stat"><span class="ghc-stat-label">Net:</span> <span class="ghc-stat-value ' + netCls + '">' + (m.net>=0?'+':'') + fmtMoney(m.net, 0) + '</span></span>' +
        '</div>' +
      '</div>' +
      '<div>' + badge + '</div>' +
    '</div>';
  }).join('') + '</div>';
}

async function renderSetupPills() {
  const setups = await api.get('/api/setups');
  const box = $('#setupPills');
  if (!setups.length) { box.innerHTML = `<div class="muted">Сетапов нет. Добавь первый ниже.</div>`; return; }
  box.innerHTML = setups.map(s => {
    const used = _trades.filter(t => t.setup === s).length;
    return `<span class="setup-pill">${esc(s)} <span class="muted" style="font-size:10px">(${used})</span><button data-del-setup="${esc(s)}" title="Удалить">✕</button></span>`;
  }).join('');
  box.querySelectorAll('[data-del-setup]').forEach(b => b.addEventListener('click', async () => {
    const name = b.dataset.delSetup;
    const used = _trades.filter(t => t.setup === name).length;
    const msg = used ? `Удалить "${name}"?\n${used} сделок потеряют тэг.` : `Удалить "${name}"?`;
    if (!confirm(msg)) return;
    await api.del('/api/setups/' + name);
    await loadAll();
    renderSetupPills();
    toast(t('toast.setup_removed'));
  }));
}

// ===== events =====
$$('.tab').forEach(t => t.addEventListener('click', () => {
  $$('.tab').forEach(x => x.classList.remove('tab-active'));
  $$('.tab-panel').forEach(p => p.classList.remove('tab-panel-active'));
  t.classList.add('tab-active');
  $('#tab-' + t.dataset.tab).classList.add('tab-panel-active');
  // Авто-подтяжка депозитов при первом открытии вкладки
  if (t.dataset.tab === 'deposits' && !window._depositsAutoSyncTried) {
    window._depositsAutoSyncTried = true;
    const deps = window._deposits || [];
    if (deps.length === 0) {
      maybeAutoSyncDeposits();
    }
  }
}));

async function maybeAutoSyncDeposits() {
  try {
    const creds = await fetch('/api/credentials').then(r => r.json());
    if (!creds || !creds.api_key) return;
    toast(t('toast.fetching_deposits'), 'info');
    const r = await fetch('/api/sync/full', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({})
    }).then(x => x.json());
    if (r && (r.deposits_added > 0 || r.deposits_fetched > 0)) {
      toast(`✓ Подтянуто депозитов: ${r.deposits_added}`, 'success');
    } else {
      toast(t('toast.no_deposits_api'), 'info');
    }
    if (typeof loadAll === 'function') await loadAll();
  } catch (e) { /* noop */ }
}

$$('#periodToggle button').forEach(b => b.addEventListener('click', () => {
  $$('#periodToggle button').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  _ui.period = b.dataset.p;
  // глобальный период — сбрасываем кастомные даты
  const fr = document.getElementById('globalFrom'); if (fr) fr.value = '';
  const to = document.getElementById('globalTo'); if (to) to.value = '';
  // обновляем подпись периода
  const subEl = document.getElementById('globalPeriodSub');
  if (subEl) {
    const labels = { D: t('period.last_24h'), W: t('period.last_7d'), M: t('period.last_30d'), Y: t('period.last_365d'), ALL: t('period.last_all') };
    subEl.textContent = labels[_ui.period] || '';
  }
  loadStats(_ui.period);
  // также применяем к журналу сделок (один фильтр на всё)
  window._tradesPeriod = _ui.period;
  if (typeof renderTradesTable === 'function') renderTradesTable();
}));

// statsByGoal удалён в переработке 2026-05-26

function _renderStatsBox(s) {
  setVal('#statTotal', String(s.total||0));
  setVal('#statWins', String(s.wins||0));
  setVal('#statLosses', String(s.losses||0));
  setVal('#statWinrate', (s.winrate||0).toFixed(1) + '%');
  setVal('#statAvg', fmtMoney(s.avg||0, 2));
  setVal('#statBest', fmtMoney(s.best||0, 2));
  setVal('#statWorst', fmtMoney(s.worst||0, 2));
  setVal('#statNet', fmtMoney(s.net_pnl||0, 2));
}

// === Универсальные обработчики filter-bar ===
// Применяется к любому period-toggle с data-pt="trades|deposits|..."
$$('[data-pt="deposits"] button').forEach(b => b.addEventListener('click', () => {
  $$('[data-pt="deposits"] button').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  window._depositPeriod = b.dataset.p;
  // сбрасываем date-range когда выбран chip
  if (document.getElementById('depositsFrom')) document.getElementById('depositsFrom').value = '';
  if (document.getElementById('depositsTo')) document.getElementById('depositsTo').value = '';
  renderDepositsTable();
}));
$$('[data-pt="trades"] button').forEach(b => b.addEventListener('click', () => {
  $$('[data-pt="trades"] button').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  window._tradesPeriod = b.dataset.p;
  if (document.getElementById('tradesFrom')) document.getElementById('tradesFrom').value = '';
  if (document.getElementById('tradesTo')) document.getElementById('tradesTo').value = '';
  if (typeof renderTradesTable === 'function') renderTradesTable();
}));

// Date-range inputs (Сделки + Депозиты).
// ПРАВКА 2026-05-26: при выборе диапазона — автоматически тянем сделки с биржи
// за этот период (а не только показываем что уже в БД).
let _dateFilterSyncTimer = null;
const _dateFilterSynced = new Set();  // ключи 'from-to' уже синканных диапазонов
['tradesFrom','tradesTo','depositsFrom','depositsTo'].forEach(id => {
  const el = document.getElementById(id);
  if (!el) return;
  el.addEventListener('change', () => {
    const isDep = id.startsWith('deposits');
    if (isDep) {
      window._depositPeriod = 'CUSTOM';
      renderDepositsTable();
    } else {
      window._tradesPeriod = 'CUSTOM';
      if (typeof renderTradesTable === 'function') renderTradesTable();
    }
    // Дебаунсим (юзер ещё может менять вторую дату)
    clearTimeout(_dateFilterSyncTimer);
    _dateFilterSyncTimer = setTimeout(async () => {
      const fromId = isDep ? 'depositsFrom' : 'tradesFrom';
      const toId = isDep ? 'depositsTo' : 'tradesTo';
      const from = document.getElementById(fromId)?.value;
      const to = document.getElementById(toId)?.value;
      if (!from && !to) return;
      const key = `${from || ''}|${to || ''}`;
      if (_dateFilterSynced.has(key)) return;  // не синкаем второй раз тот же диапазон
      _dateFilterSynced.add(key);
      // Проверяем что API подключён
      try {
        const creds = await fetch('/api/credentials').then(r => r.json());
        if (!creds || !creds.api_key) return;
      } catch (e) { return; }
      toast(t('toast.fetching_trades', from || '…', to || 'today'), 'info');
      try {
        const r = await fetch('/api/sync/full', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ start_date: from || '2020-01-01', end_date: to || undefined }),
        }).then(x => x.json());
        if (r.ok && (r.trades_added || 0) > 0) {
          toast(`✓ Подтянуто новых сделок: ${r.trades_added}`, 'success');
        } else if (r.ok) {
          toast(`Биржа не вернула новых сделок за этот период`, 'info');
        }
        if (typeof loadAll === 'function') await loadAll();
      } catch (e) {
        toast('✗ Ошибка автосинка: ' + e.message, 'error');
      }
    }, 800);  // 800мс дебаунс — юзер успеет выбрать вторую дату
  });
});

// Селектор цели на каждой вкладке
['depositGoalScope', 'tradesGoalScope', 'planfactGoalScope'].forEach(id => {
  const el = document.getElementById(id);
  if (!el) return;
  el.addEventListener('change', async () => {
    const v = el.value || '';
    if (id === 'depositGoalScope') {
      window._depositGoalScope = v;
      renderDepositsTable();
      // «За весь период» — авто-sync для подтяжки полной истории
      if (v === '') await autoSyncFullIfNeeded(el);
    } else if (id === 'tradesGoalScope') {
      window._tradesGoalScope = v;
      if (typeof renderTradesTable === 'function') renderTradesTable();
      if (v === '') await autoSyncFullIfNeeded(el);
    } else if (id === 'planfactGoalScope') {
      window._planfactGoalScope = v || 'active';
      if (typeof loadAll === 'function') loadAll();
    }
  });
});

// Авто-sync при выборе «За весь период»: дёргаем /api/sync/full,
// чтобы пользователь сразу увидел всю историю с биржи.
const _autoSyncFullDone = new Set();
async function autoSyncFullIfNeeded(selectEl) {
  // одноразово за сессию для каждого селекта
  const key = selectEl.id;
  if (_autoSyncFullDone.has(key)) return;
  _autoSyncFullDone.add(key);
  try {
    const creds = await fetch('/api/credentials').then(r => r.json());
    if (!creds || !creds.api_key) return;
    selectEl.disabled = true;
    toast(t('toast.fetching_full_history'), 'info');
    const r = await fetch('/api/sync/full', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({}),
    }).then(x => x.json());
    let msg = `✓ С биржи: +${r.trades_added||0} сделок`;
    if (r.deposits_added) msg += `, +${r.deposits_added} депозитов`;
    if (!r.deposits_added && r.trades_fetched === 0) {
      msg = 'Bitunix не вернула новых данных (всё уже в БД)';
    }
    toast(msg, r.ok ? 'success' : 'info');
    if (typeof loadAll === 'function') await loadAll();
  } catch (e) {
    toast(t('toast.sync_error') + ': ' + (e.message || e), 'error');
  } finally {
    selectEl.disabled = false;
  }
}

// Кнопка «↻ С биржи»
const syncDepBtn = document.querySelector('#syncDepositsBtn');
if (syncDepBtn) {
  syncDepBtn.addEventListener('click', async () => {
    syncDepBtn.disabled = true;
    syncDepBtn.textContent = '⟳ Тяну…';
    try {
      const r = await fetch('/api/sync/full', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({})
      }).then(x => x.json());
      if (r && r.deposits_added > 0) {
        toast(`✓ Подтянуто новых депозитов: ${r.deposits_added}`, 'success');
      } else if (r && r.deposits_fetched > 0) {
        toast(`Биржа вернула ${r.deposits_fetched} операций, все уже в БД`, 'info');
      } else {
        toast('Bitunix API не отдаёт депозиты. Используй «📂 Импорт CSV» или «+ Операция»', 'info');
      }
      if (typeof loadAll === 'function') await loadAll();
    } catch (e) {
      toast(t('toast.sync_error') + ': ' + e.message, 'error');
    } finally {
      syncDepBtn.disabled = false;
      syncDepBtn.textContent = '↻ С биржи';
    }
  });
}

// CSV-импорт депозитов
const csvBtn = document.querySelector('#importDepositsCsvBtn');
const csvInput = document.querySelector('#depositsCsvInput');
if (csvBtn && csvInput) {
  csvBtn.addEventListener('click', () => {
    if (!confirm('Формат CSV: date,kind,amount,note\nГде:\n  date — YYYY-MM-DD или ISO datetime\n  kind — deposit или withdraw\n  amount — сумма $\n  note — комментарий (опц.)\n\nПервая строка — заголовки. Окей?')) return;
    csvInput.click();
  });
  csvInput.addEventListener('change', async () => {
    const file = csvInput.files && csvInput.files[0];
    if (!file) return;
    const text = await file.text();
    csvInput.value = '';
    const lines = text.split(/\r?\n/).filter(l => l.trim());
    if (lines.length < 2) { toast('CSV пустой', 'error'); return; }
    const header = lines[0].toLowerCase().split(',').map(s => s.trim());
    const idx = (name) => header.indexOf(name);
    const iDate = idx('date'); const iKind = idx('kind');
    const iAmt = idx('amount'); const iNote = idx('note');
    if (iDate < 0 || iKind < 0 || iAmt < 0) {
      toast('CSV должен содержать колонки date, kind, amount', 'error'); return;
    }
    const batch = [];
    for (let i = 1; i < lines.length; i++) {
      const parts = lines[i].split(',').map(s => s.trim());
      if (parts.length < 3) continue;
      const ts = parts[iDate];
      const kind = (parts[iKind] || 'deposit').toLowerCase();
      const amt = parseFloat(parts[iAmt]);
      if (!ts || isNaN(amt)) continue;
      batch.push({
        ts: ts.length === 10 ? ts + 'T00:00:00' : ts,
        kind: kind === 'withdraw' ? 'withdraw' : 'deposit',
        amount_usd: amt,
        note: iNote >= 0 ? (parts[iNote] || '') : '',
        source: 'csv',
      });
    }
    if (!batch.length) { toast(t('toast.csv_no_rows'), 'error'); return; }
    const r = await fetch('/api/deposits', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({batch}),
    }).then(x => x.json());
    toast(`✓ Импортировано: ${r.added || 0}`, 'success');
    if (typeof loadAll === 'function') await loadAll();
  });
}

$$('.scenario-chip').forEach(c => c.addEventListener('click', async () => {
  let v;
  if (c.dataset.s === 'custom') {
    const s = prompt('Введи свой % в месяц:', _data?.settings?.scenario || 10);
    if (s == null) return;
    v = parseFloat(s);
    if (!isFinite(v) || v <= 0) { toast(t('toast.invalid_value'), 'error'); return; }
  } else v = +c.dataset.s;
  await api.post('/api/settings', { scenario: v });
  await loadAll();
}));

$('#tradeSearch').addEventListener('input', () => { _ui.tradesPage = 1; renderTradesTable(); });
$$('#tradesTable th.sortable').forEach(th => th.addEventListener('click', () => {
  const col = th.dataset.sort;
  if (_ui.sort.col === col) _ui.sort.dir = _ui.sort.dir === 'asc' ? 'desc' : 'asc';
  else { _ui.sort.col = col; _ui.sort.dir = 'desc'; }
  renderTradesTable();
}));

document.addEventListener('click', async e => {
  try {
    const dt = e.target.closest('[data-del-trade]');
    if (dt) {
      e.stopPropagation();
      // #17 Undo: soft-delete с откатом 5 сек (без confirm — он мешает UX)
      const id = dt.dataset.delTrade;
      // Сохраним строку и удалим из локального кэша + БД, при undo восстановим
      const trade = (_trades || []).find(t => String(t.id) === String(id));
      if (!trade) return;
      _trades = _trades.filter(t => String(t.id) !== String(id));
      renderTradesTable();
      try { await api.del('/api/trades/' + id); } catch (err) {
        toast('✗ Не удалось удалить: ' + (err.message || err), 'error');
        return;
      }
      showUndoSnackbar(t('toast.trade_deleted'), async () => {
        // Восстанавливаем через POST (новый external_id у manual; для bitunix-сделок sync вернёт)
        await fetch('/api/trades', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(trade) });
        await loadAll();
        toast('↶ Сделка восстановлена', 'success');
      });
      return;
    }
    const dd = e.target.closest('[data-del-dep]');
    if (dd) {
      e.stopPropagation();
      const id = dd.dataset.delDep;
      const dep = (window._deposits || []).find(x => String(x.id) === String(id));
      if (!dep) return;
      window._deposits = (window._deposits || []).filter(x => String(x.id) !== String(id));
      renderDepositsTable();
      try { await api.del('/api/deposits/' + id); } catch (err) {
        toast('✗ Не удалось удалить: ' + (err.message || err), 'error');
        return;
      }
      showUndoSnackbar(t('toast.dep_deleted'), async () => {
        await fetch('/api/deposits', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(dep) });
        await loadAll();
        toast('↶ Операция восстановлена', 'success');
      });
      return;
    }
    const cl = e.target.closest('[data-close]');
    if (cl) {
      const m = document.getElementById(cl.dataset.close);
      if (m) m.classList.remove('open');
    }
  } catch (err) {
    console.error('global click handler crashed:', err);
  }
});

const openM = id => { const el = $(id); if (el) el.classList.add('open'); };
// settingsBtn/settingsModal/saveSettingsBtn/resetDataBtn удалены из UI:
// настройки переехали в карточку цели (✏) и в danger-zone-details.

$('#editGoalBtn').addEventListener('click', () => openM('#editGoalModal'));
$('#saveGoalBtn').addEventListener('click', async () => {
  const amt = +$('#goalAmountInput').value;
  if (!amt || amt <= 0) { toast(t('toast.positive_amount'), 'error'); return; }
  const gd = $('#goalDepositInput');
  await api.patch('/api/goal', {
    name: $('#goalNameInput').value.trim(),
    amount: amt,
    monthly_return_pct: +$('#goalReturnInput').value,
    monthly_deposit: gd ? (+gd.value || 0) : undefined,
  });
  $('#editGoalModal').classList.remove('open');
  await loadAll(); toast(t('toast.goal_updated'));
});
$('#deleteGoalBtn').addEventListener('click', () => openM('#deleteGoalModal'));
$('#confirmDeleteGoalBtn').addEventListener('click', async () => {
  await api.del('/api/goal');
  $('#deleteGoalModal').classList.remove('open');
  await loadAll(); toast(t('toast.goal_deleted'));
});
$('#completeGoalBtn').addEventListener('click', async () => {
  const def = (+(_data?.goal?.amount || 1000) * 2).toString();
  const s = prompt(`🎉 Цель выполнена!\n\nКакая следующая в $?`, def);
  if (s == null) return;
  const newAmt = parseFloat(s);
  if (!isFinite(newAmt) || newAmt <= 0) { toast(t('toast.invalid_amount'), 'error'); return; }
  await api.post('/api/goal/archive', { new_amount: newAmt, new_return_pct: +(_data?.goal?.monthly_return_pct || 10) });
  await loadAll(); toast('🏆 В архив. Новая цель создана.');
});

$('#addTradeBtn').addEventListener('click', () => openTradeModal());
function openTradeModal() {
  ['tradeSymbol','tradeEntry','tradeExit','tradeQty','tradePnl','tradeFee','tradeNote'].forEach(id => $('#'+id).value = '');
  $('#tradeSetup').value = '';
  // BUG-23: локальное datetime, не UTC
  (function setLocalTs() {
    const d = new Date();
    const pad = n => String(n).padStart(2, '0');
    $('#tradeTs').value = d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate())
      + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  })();
  openM('#tradeModal');
  setTimeout(() => $('#tradeSymbol').focus(), 100);
}
$('#saveTradeBtn').addEventListener('click', async () => {
  const symbol = $('#tradeSymbol').value.trim().toUpperCase();
  if (!symbol) { toast('Укажи пару', 'error'); return; }
  const entry = +$('#tradeEntry').value || 0;
  const qty = +$('#tradeQty').value || 0;
  const pnl = +$('#tradePnl').value || 0;
  await api.post('/api/trades', {
    ts: $('#tradeTs').value || (function() {
      const d = new Date(); const pad = n => String(n).padStart(2, '0');
      return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'T'+pad(d.getHours())+':'+pad(d.getMinutes());
    })(),
    symbol, side: $('#tradeSide').value, setup: $('#tradeSetup').value || null,
    entry_price: entry, exit_price: +$('#tradeExit').value || 0,
    qty, pnl_usd: pnl,
    pnl_pct: entry && qty ? pnl/(entry*qty)*100 : 0,
    fee_usd: +$('#tradeFee').value || 0,
    note: $('#tradeNote').value.trim(), source: 'manual',
  });
  $('#tradeModal').classList.remove('open');
  await loadAll({flash:true}); toast('Сделка добавлена');
});

$('#addDepositBtn').addEventListener('click', () => {
  $('#depTs').value = new Date().toISOString().slice(0,10);
  $('#depAmount').value = ''; $('#depNote').value = '';
  openM('#depositModal');
  setTimeout(() => $('#depAmount').focus(), 100);
});
$('#saveDepBtn').addEventListener('click', async () => {
  const amount = +$('#depAmount').value || 0;
  if (!amount) { toast('Укажи сумму', 'error'); return; }
  await api.post('/api/deposits', {
    ts: $('#depTs').value || new Date().toISOString().slice(0,10),
    kind: $('#depKind').value, amount_usd: amount,
    note: $('#depNote').value.trim(), source: 'manual',
  });
  $('#depositModal').classList.remove('open');
  await loadAll({flash:true}); toast('Операция добавлена');
});

$('#manageSetupsBtn').addEventListener('click', async () => { await renderSetupPills(); openM('#setupsModal'); setTimeout(()=>$('#newSetupInput').focus(),100); });
$('#addSetupBtn').addEventListener('click', addNewSetup);
$('#newSetupInput').addEventListener('keydown', e => { if (e.key === 'Enter') addNewSetup(); });
async function addNewSetup() {
  const v = $('#newSetupInput').value.trim().toLowerCase();
  if (!v) return;
  if (v.length > 20) { toast('Слишком длинное', 'error'); return; }
  const res = await api.post('/api/setups', { name: v });
  $('#newSetupInput').value = '';
  await loadAll();
  await renderSetupPills();
  toast('Сетап добавлен');
}

$('#helpBtn').addEventListener('click', () => openM('#helpModal'));

$('#syncBtn').addEventListener('click', runSync);
async function runSync() {
  const btn = $('#syncBtn');
  if (btn.classList.contains('loading')) return;
  btn.classList.add('loading');
  const span = btn.querySelector('span'); const orig = span.textContent; span.textContent = 'Sync...';
  try {
    const r = await api.post('/api/sync', {});
    if (r.ok) {
      toast(`✓ Bitunix · +${r.trades_added} сделок, +${r.deposits_added} деп.${r.equity != null ? ', equity ' + fmtMoney(r.equity, 2) : ''}`);
    } else if (r.error) {
      toast('⚠ ' + r.error, 'error', 6000);
    } else {
      toast('⚠ ' + (r.errors || []).join('; '), 'error', 6000);
    }
    await loadAll({flash:true});
  } catch (e) {
    toast('Ошибка: ' + e, 'error');
  } finally {
    btn.classList.remove('loading'); span.textContent = orig;
  }
}

$$('.modal-overlay').forEach(m => m.addEventListener('click', e => { if (e.target===m) m.classList.remove('open'); }));

document.addEventListener('keydown', e => {
  if (e.target.matches('input, textarea, select')) {
    if (e.key === 'Escape') e.target.blur();
    return;
  }
  if (e.key === 'Escape') $$('.modal-overlay.open').forEach(m => m.classList.remove('open'));
  else if (e.key === 'n' || e.key === 'N') { e.preventDefault(); openTradeModal(); }
  else if (e.key === '/') { e.preventDefault(); document.querySelector('.tab[data-tab="trades"]').click(); $('#tradeSearch').focus(); }
  else if (e.key === 's' || e.key === 'S') { e.preventDefault(); runSync(); }
  else if (e.key === ',') { e.preventDefault(); openM('#settingsModal'); }
  else if (e.key === 'e' || e.key === 'E') { e.preventDefault(); window.location.href = '/api/trades/export.csv'; }
  else if (e.key === '?') { e.preventDefault(); openM('#helpModal'); }
});


// ===== API credentials (по клику на status pill) =====
function _maskSecret(s) {
  if (!s) return '— не задан —';
  if (s.length <= 8) return '•'.repeat(s.length);
  return '••••••••' + s.slice(-4);
}
// sec-fix 2026-05-30: backend больше НЕ отдаёт plaintext, только api_key_mask/api_connected/ek_available
let _credsConnected = false;
$('#apiStatus').addEventListener('click', async () => {
  const r = await api.get('/api/credentials');
  _credsConnected = !!r.api_connected;
  // Если encryption_key пропал (Remember-me cookie без re-login) — сразу предупреждаем
  if (r.ek_available === false) {
    if (confirm('Чтобы подключить или изменить ключи биржи, нужно войти заново с паролем (zero-knowledge защита). Перейти на /login?')) {
      window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname);
    }
    return;
  }
  $('#credExchange').value = r.exchange || 'bitunix';
  $('#credApiKey').value = '';
  $('#credApiSecret').value = '';
  const km = r.api_key_mask || '— не задан —';
  const sm = r.api_secret_mask || '— не задан —';
  const mk = $('#credApiKeyMask'); if (mk) mk.textContent = 'Сохранён ключ: ' + km;
  const ms = $('#credApiSecretMask'); if (ms) ms.textContent = 'Сохранён секрет: ' + sm;
  $('#credentialsModal').classList.add('open');
});
$('#apiStatus').style.cursor = 'pointer';
$('#apiStatus').title = 'Нажми чтобы настроить API биржи';

$('#saveCredsBtn').addEventListener('click', async () => {
  const newKey = $('#credApiKey').value.trim();
  const newSec = $('#credApiSecret').value.trim();
  if (!newKey && !newSec) {
    if (_credsConnected) {
      toast('Поля пустые — ключи не изменены', 'info');
    } else {
      toast('Введи api_key и api_secret чтобы подключить биржу', 'error');
    }
    $('#credentialsModal').classList.remove('open');
    return;
  }
  if (!newKey || !newSec) {
    toast('Нужны оба поля: api_key и api_secret', 'error');
    return;
  }
  let r;
  try {
    const resp = await fetch('/api/credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        exchange: $('#credExchange').value,
        api_key: newKey,
        api_secret: newSec,
      }),
      credentials: 'include',
    });
    r = await resp.json();
    if (resp.status === 401) {
      $('#credentialsModal').classList.remove('open');
      toast('Сессия истекла. Войди заново с паролем чтобы сохранить ключи.', 'error');
      setTimeout(() => { window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname); }, 2500);
      return;
    }
    if (!resp.ok || !r.ok) {
      toast('Ошибка сохранения: ' + (r.error || 'HTTP ' + resp.status), 'error');
      return;
    }
  } catch (e) {
    toast('Ошибка сети: ' + e.message, 'error');
    return;
  }
  $('#credentialsModal').classList.remove('open');
  await loadAll();
  toast('Ключи сохранены' + (r.auto_sync && r.auto_sync.ok ? ', синхронизация: +' + (r.auto_sync.added||0) + ' сделок' : ''), 'success');
});
$('#clearCredsBtn').addEventListener('click', async () => {
  if (!confirm('Очистить API-ключи? После этого нужно будет ввести их заново для синхронизации.')) return;
  await api.post('/api/credentials', { exchange: 'bitunix', clear: true });
  $('#credentialsModal').classList.remove('open');
  await loadAll();
  toast('Ключи очищены', 'info');
});

window.addEventListener('DOMContentLoaded', async () => {
  // #16: показываем skeleton на карточке цели до первой загрузки
  const gc = document.querySelector('.goal-card');
  if (gc) gc.classList.add('skeleton-loading');
  try {
    await loadAll();
  } catch (e) { console.error('initial loadAll failed:', e); }
  if (gc) gc.classList.remove('skeleton-loading');
  // подстраховка: если первая отрисовка прошла с race и поля пустые (например settings
  // только что мигрировали в _migrate_bad_tracking_dates), дёргаем ещё раз через 600мс
  setTimeout(() => {
    const eqText = (document.getElementById('heroEquity') || {}).textContent || '';
    const goalAmtText = (document.getElementById('goalAmount') || {}).textContent || '';
    if (eqText === '$0' || goalAmtText === '$0') {
      try { loadAll(); } catch (e) {}
    }
  }, 600);
});


// === Settings modal patch (build full form + defensive save) ===
(function patchSettingsModal() {
  const btn = document.getElementById('settingsBtn');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    const body = document.querySelector('#settingsModal .modal-body');
    if (!body) return;
    const s = await fetch('/api/settings').then(r => r.json());
    const today = new Date().toISOString().slice(0,10);
    body.innerHTML = ''
      + '<div class="form-row"><label>Стартовый капитал ($) — оставь 0 чтобы взять текущий equity при Sync</label>'
      + '<input type="number" id="setStart" step="0.01" value="' + (s.start_capital || 0) + '" /></div>'
      + '<div class="form-row"><label>Дата старта плана</label>'
      + '<input type="date" id="setStartDate" value="' + (s.start_date || '') + '" /></div>'
      + '<div class="muted" style="margin-top:6px;font-size:11.5px;">Период статистики выбирай чипами «D / W / M / Y / All» наверху дашборда. Ежемесячный взнос задаётся в форме цели.</div>'
      + '<div style="margin-top:18px;padding-top:18px;border-top:1px solid var(--border);">'
      + '<button class="btn btn-danger" id="resetDataBtn">Сбросить все сделки и депозиты</button>'
      + '<div class="muted" style="margin-top:6px;font-size:11.5px;">Удалит сделки/депозиты/архив целей. Настройки и сетапы остаются.</div>'
      + '</div>';
    document.getElementById('resetDataBtn').addEventListener('click', async () => {
      if (!confirm('Удалить все сделки, депозиты и архив целей?')) return;
      await fetch('/api/reset', {method:'POST'});
      document.getElementById('settingsModal').classList.remove('open');
      location.reload();
    });
  });
  // Defensive save handler — overrides any previous binding
  const save = document.getElementById('saveSettingsBtn');
  if (!save) return;
  const clone = save.cloneNode(true);
  save.parentNode.replaceChild(clone, save);
  clone.addEventListener('click', async () => {
    const v = id => { const el = document.getElementById(id); return el ? el.value : undefined; };
    const n = id => { const el = document.getElementById(id); return el ? +el.value : undefined; };
    const payload = {};
    const sc = n('setStart'); if (sc !== undefined && !isNaN(sc)) payload.start_capital = sc;
    const sd = v('setStartDate'); if (sd) payload.start_date = sd;
    await fetch('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    document.getElementById('settingsModal').classList.remove('open');
    location.reload();
  });
})();


// === v4 patch: tooltips in settings, theme toggle, win/loss donut ===
(function v4Patch() {
  // ---- Theme toggle ----
  const themeKey = 'crypto-planner-theme';
  function applyTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    const r = document.documentElement.style;
    if (t === 'light') {
      r.setProperty('--bg-base', '#f5f7fb');
      r.setProperty('--bg-elev', '#ffffff');
      r.setProperty('--bg-card', '#ffffff');
      r.setProperty('--bg-card-hi', '#f0f3f8');
      r.setProperty('--border', '#e2e6ee');
      r.setProperty('--border-hi', '#d2d7e1');
      r.setProperty('--text-primary', '#1a1f2e');
      r.setProperty('--text-secondary', '#5a6478');
      r.setProperty('--text-muted', '#8a93a8');
      document.documentElement.style.colorScheme = 'light';
    } else {
      r.setProperty('--bg-base', '#0a0d14');
      r.setProperty('--bg-elev', '#11151f');
      r.setProperty('--bg-card', '#161b27');
      r.setProperty('--bg-card-hi', '#1b2130');
      r.setProperty('--border', '#232a3b');
      r.setProperty('--border-hi', '#2d3548');
      r.setProperty('--text-primary', '#e6edf7');
      r.setProperty('--text-secondary', '#8a93a8');
      r.setProperty('--text-muted', '#5a6478');
      document.documentElement.style.colorScheme = 'dark';
    }
    document.querySelectorAll('#themeBtn .icon').forEach(el => el.textContent = t === 'light' ? '🌙' : '☀');
  }
  // ШАГ-1: безопасное чтение localStorage (private mode / disabled storage не падают)
  let savedTheme = 'dark';
  try { savedTheme = localStorage.getItem(themeKey) || 'dark'; } catch (e) { savedTheme = 'dark'; }
  applyTheme(savedTheme);
  // Insert theme button into nav (before helpBtn)
  const navActions = document.querySelector('.nav-actions');
  if (navActions && !document.getElementById('themeBtn')) {
    const btn = document.createElement('button');
    btn.id = 'themeBtn';
    btn.className = 'btn btn-ghost';
    btn.title = 'Переключить тему';
    btn.innerHTML = '<span class="icon">' + (savedTheme === 'light' ? '🌙' : '☀') + '</span>';
    btn.style.fontSize = '15px';
    navActions.insertBefore(btn, navActions.firstChild);
    btn.addEventListener('click', () => {
      // ШАГ-1: try/catch чтобы тема не сломалась если localStorage запрещён
      let cur = 'dark';
      try { cur = localStorage.getItem(themeKey) || 'dark'; } catch (e) {}
      const next = cur === 'dark' ? 'light' : 'dark';
      try { localStorage.setItem(themeKey, next); } catch (e) {}
      applyTheme(next);
    });
  }

  // ---- Settings modal with hints (replace existing patch) ----
  const settingsBtn = document.getElementById('settingsBtn');
  if (settingsBtn) {
    const newBtn = settingsBtn.cloneNode(true);
    settingsBtn.parentNode.replaceChild(newBtn, settingsBtn);
    newBtn.addEventListener('click', async () => {
      const body = document.querySelector('#settingsModal .modal-body');
      if (!body) return;
      const s = await fetch('/api/settings').then(r => r.json());
      const today = new Date().toISOString().slice(0,10);
      const hint = (txt) => '<div class="muted" style="font-size:11px;margin-top:4px;line-height:1.45;">💡 ' + txt + '</div>';
      body.innerHTML = ''
        + '<div class="muted" style="line-height:1.6; margin-bottom:14px;">'
        + '💡 <b>Параметры цели и стартовые условия</b> теперь задаются в <b>карточке цели</b> '
        + '(кнопка ✏ справа от названия цели) — там сумма, ежемесячный взнос, доходность, '
        + 'стартовый капитал и дата старта учёта в одной модалке.'
        + '<br><br>'
        + '<b>Период статистики</b> — чипы <b>D / W / M / Y / All</b> наверху дашборда.'
        + '</div>'
        + '<div style="margin-top:18px;padding-top:18px;border-top:1px solid var(--border);">'
        + '<button class="btn btn-danger" id="resetDataBtn">Сбросить все сделки и депозиты</button>'
        + '<div class="muted" style="margin-top:6px;font-size:11.5px;">Удалит сделки/депозиты/архив целей. Настройки и сетапы остаются.</div>'
        + '</div>'
        + '<div style="margin-top:14px;">'
        + '<button class="btn btn-ghost" id="reopenGoalOnbBtn" style="width:100%;">🎯 Открыть мастер постановки цели</button>'
        + '</div>';
      document.getElementById('resetDataBtn').addEventListener('click', async () => {
        if (!confirm('Удалить все сделки, депозиты и архив целей?')) return;
        await fetch('/api/reset', {method:'POST'});
        document.getElementById('settingsModal').classList.remove('open');
        location.reload();
      });
      const reopenBtn = document.getElementById('reopenGoalOnbBtn');
      if (reopenBtn) reopenBtn.addEventListener('click', async () => {
        document.getElementById('settingsModal').classList.remove('open');
        // Заполним поля из текущих значений
        try {
          const s = await fetch('/api/settings').then(r => r.json());
          const d = await fetch('/api/dashboard').then(r => r.json());
          const g = d.goal || {};
          const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
          set('goalOnbAmount', g.amount || 100000);
          set('goalOnbDeposit', g.monthly_deposit || 0);
          set('goalOnbReturn', g.monthly_return_pct || 10);
          set('goalOnbName', g.name || 'Моя цель');
          set('goalOnbStartCap', s.start_capital || 0);
          set('goalOnbStartDate', s.start_date || new Date().toISOString().slice(0,10));
        } catch (e) {}
        document.getElementById('goalOnboardingModal')?.classList.add('open');
      });
      document.getElementById('settingsModal').classList.add('open');
    });
  }

  // Win/Loss donut удалён (дублировал winrate в карточке цели)
})();


// ====================================================================
// v5 patch: «Загрузить всю историю с биржи» + автоподтяжка
// ====================================================================
(function patchFullSync() {
  const AUTO_FLAG = 'crypto-planner-auto-fullsync-done';

  function fmtLastSync(ts) {
    if (!ts) return 'ни разу';
    const d = new Date(parseInt(ts, 10));
    if (isNaN(d.getTime())) return 'ни разу';
    return d.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' });
  }

  async function fullSync(opts) {
    opts = opts || {};
    const btn = document.getElementById('fullSyncBtn');
    const label = document.getElementById('fullSyncLabel');
    if (btn) { btn.disabled = true; }
    if (label) { label.textContent = 'Тяну с биржи…'; }
    try {
      const res = await fetch('/api/sync/full', { method: 'POST' });
      const data = await res.json();
      if (data && data.ok) {
        const added = data.trades_added || 0;
        const fetched = data.trades_fetched || 0;
        if (typeof toast === 'function') {
          toast('✓ Bitunix: ' + added + ' новых сделок (из ' + fetched + ' пришедших)', 'success');
        }
        if (typeof loadAll === 'function') { await loadAll(); }
        updateLastSyncLabel();
        // если сделок и правда нет — поясняем
        if (fetched === 0 && !opts.silent) {
          if (typeof toast === 'function') {
            toast('На Bitunix нет ЗАКРЫТЫХ позиций — нечего тянуть. Открытые сделки в историю не попадают.', 'info');
          }
        }
      } else {
        const err = (data && (data.error || (data.errors || []).join('; '))) || 'неизвестная ошибка';
        if (typeof toast === 'function') toast('✗ Ошибка sync: ' + err, 'error');
      }
    } catch (e) {
      if (typeof toast === 'function') toast('✗ Сеть: ' + e.message, 'error');
    } finally {
      if (btn) { btn.disabled = false; }
      updateLastSyncLabel();
    }
  }

  async function updateLastSyncLabel() {
    try {
      const r = await fetch('/api/settings').then(x => x.json());
      const ts = r && r.last_sync_ts;
      const el = document.getElementById('fullSyncLabel');
      if (el) el.textContent = 'Последняя синхронизация: ' + fmtLastSync(ts);
    } catch (e) { /* noop */ }
  }

  function injectButton() {
    // Кнопка «Загрузить всю историю с биржи» убрана — авто-sync делает то же самое,
    // а фильтры (период + цели) позволяют посмотреть любой диапазон.
    // Оставляем только информер «Последняя синхронизация» в незаметной плашке.
    const panel = document.getElementById('tab-trades');
    if (!panel) return;
    if (document.getElementById('fullSyncBar')) return;
    const filterBar = panel.querySelector('.filter-bar');
    if (!filterBar) return;
    const info = document.createElement('span');
    info.id = 'fullSyncBar';
    info.className = 'muted';
    info.style.cssText = 'font-size:11px; margin-left:auto; align-self:center;';
    info.innerHTML = '<span id="fullSyncLabel">Последняя синхронизация: …</span>';
    filterBar.appendChild(info);
    updateLastSyncLabel();
  }

  async function maybeAutoSync() {
    // Один раз за вкладку: тянем сами если
    //   а) сделок 0 ИЛИ
    //   б) с последней синхронизации прошло больше 6 часов
    // ШАГ-1: безопасный sessionStorage
    try { if (sessionStorage.getItem(AUTO_FLAG)) return; } catch (e) {}
    try {
      const creds = await fetch('/api/credentials').then(r => r.json());
      if (!creds || !creds.api_key) return;  // ключи не настроены — без авто-sync

      const trades = await fetch('/api/trades').then(r => r.json());
      const tradesEmpty = Array.isArray(trades) && trades.length === 0;

      const s = await fetch('/api/settings').then(r => r.json());
      const lastTs = +(s && s.last_sync_ts || 0);
      const sixHoursMs = 6 * 60 * 60 * 1000;
      const stale = !lastTs || (Date.now() - lastTs) > sixHoursMs;

      if (tradesEmpty || stale) {
        try { sessionStorage.setItem(AUTO_FLAG, '1'); } catch (e) {}
        toast(tradesEmpty ? 'Тяну историю с биржи в первый раз…' : 'Обновляю данные с биржи…', 'info');
        await fullSync({ silent: true });
      }
    } catch (e) { /* noop */ }
  }

  // === Автоочистка #tradeSearch — анти-залипание длинных токенов/autofill ===
  function autoCleanSearchOnce() {
    const s = document.getElementById('tradeSearch');
    if (!s) return false;
    const v = (s.value || '').trim();
    // Hex-токен длиной 28+ символов из [a-f0-9] — почти наверняка autofill api-key
    if (v.length >= 28 && /^[a-fA-F0-9]+$/.test(v)) {
      s.value = '';
      if (document.activeElement === s) s.blur();
      s.dispatchEvent(new Event('input', { bubbles: true }));
      try { sessionStorage.removeItem('cp:search'); } catch (e) {}
      return true;
    }
    // Другие длинные токены без пробелов — чистим только если фокуса нет
    if (document.activeElement === s) return false;
    if (v.length >= 28 && /^[a-zA-Z0-9_\-]+$/.test(v) && !v.includes(' ')) {
      s.value = '';
      s.dispatchEvent(new Event('input', { bubbles: true }));
      try { sessionStorage.removeItem('cp:search'); } catch (e) {}
      return true;
    }
    return false;
  }
  function autoCleanSearch() {
    // BUG-12: чистим один раз на load и один раз после autofill (300ms).
    // Раньше тикало каждые 2 сек и могло стереть валидный длинный ввод.
    let toastShown = false;
    const tick = () => {
      const cleaned = autoCleanSearchOnce();
      if (cleaned && !toastShown) {
        toastShown = true;
        if (typeof toast === 'function') {
          toast('Очистил поле поиска — там был длинный токен (фильтр блокировал строки)', 'info');
        }
      }
    };
    tick();
    setTimeout(tick, 300);
    window.addEventListener('pageshow', tick);
  }

  // === Модалка выбора периода для "Загрузить всю историю" ===
  function ensurePeriodModal() {
    if (document.getElementById('fullSyncModal')) return;
    const m = document.createElement('div');
    m.className = 'modal-overlay';
    m.id = 'fullSyncModal';
    m.innerHTML =
      '<div class="modal" style="max-width: 440px;">' +
        '<div class="modal-header">' +
          '<div class="modal-title">⤓ Загрузка истории с биржи</div>' +
          '<button class="btn-icon-modal" data-close-fs>✕</button>' +
        '</div>' +
        '<div class="modal-body">' +
          '<div class="muted" style="margin-bottom: 12px;">Подтянем с Bitunix все закрытые позиции и исполнения в указанном диапазоне.</div>' +
          '<div class="form-grid" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">' +
            '<div class="form-row"><label>С даты</label><input type="date" id="fsStart"></div>' +
            '<div class="form-row"><label>По дату</label><input type="date" id="fsEnd"></div>' +
          '</div>' +
          '<div class="muted" style="margin-top:10px; font-size:11.5px;">💡 По умолчанию: с даты создания активной цели до сегодня.</div>' +
        '</div>' +
        '<div class="modal-footer">' +
          '<button class="btn btn-ghost" data-close-fs>Отмена</button>' +
          '<button class="btn btn-primary" id="fsRunBtn">Тянуть</button>' +
        '</div>' +
      '</div>';
    document.body.appendChild(m);
    m.querySelectorAll('[data-close-fs]').forEach(b => b.addEventListener('click', () => m.classList.remove('open')));
    document.getElementById('fsRunBtn').addEventListener('click', async () => {
      const start = document.getElementById('fsStart').value;
      const end = document.getElementById('fsEnd').value;
      m.classList.remove('open');
      await fullSyncWithRange(start, end);
    });
  }

  async function openPeriodModal() {
    ensurePeriodModal();
    // дефолты: дата цели → сегодня
    let defStart = '2020-01-01';
    try {
      const dash = await fetch('/api/dashboard').then(r => r.json());
      if (dash && dash.goal && dash.goal.created_at) defStart = dash.goal.created_at;
    } catch (e) {}
    const today = new Date().toISOString().slice(0, 10);
    document.getElementById('fsStart').value = defStart;
    document.getElementById('fsEnd').value = today;
    document.getElementById('fullSyncModal').classList.add('open');
  }

  async function fullSyncWithRange(start, end) {
    const btn = document.getElementById('fullSyncBtn');
    const label = document.getElementById('fullSyncLabel');
    if (btn) btn.disabled = true;
    if (label) label.textContent = 'Тяну с биржи… (' + (start || '—') + ' → ' + (end || '—') + ')';
    try {
      const res = await fetch('/api/sync/full', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ start_date: start, end_date: end }),
      });
      const data = await res.json();
      if (data && data.ok) {
        const added = data.trades_added || 0;
        const fetched = data.trades_fetched || 0;
        const rawPos = data.raw_positions_count || 0;
        const rawTr = data.raw_trades_count || 0;
        if (typeof toast === 'function') {
          toast('✓ Bitunix вернул: ' + rawPos + ' позиций, ' + rawTr + ' исполнений. Добавлено: ' + added, 'success');
        }
        if (fetched === 0) {
          if (typeof toast === 'function') {
            setTimeout(() => toast('На бирже не найдено ЗАКРЫТЫХ сделок в этом периоде. Открытые позиции не возвращаются в историю. Файл last_sync_debug.json лежит рядом с app.py — там сырой ответ.', 'info'), 800);
          }
        }
        if (typeof loadAll === 'function') await loadAll();
      } else {
        const err = (data && (data.error || (data.errors || []).join('; '))) || 'неизвестная ошибка';
        if (typeof toast === 'function') toast('✗ Ошибка sync: ' + err, 'error');
      }
    } catch (e) {
      if (typeof toast === 'function') toast('✗ Сеть: ' + e.message, 'error');
    } finally {
      if (btn) btn.disabled = false;
      try {
        const r = await fetch('/api/settings').then(x => x.json());
        const el = document.getElementById('fullSyncLabel');
        if (el) el.textContent = 'Последняя синхронизация: ' + fmtLastSync(r && r.last_sync_ts);
      } catch (e) {}
    }
  }

  // Подменяем клик старой кнопки — теперь открывает модалку периода
  function rebindButton() {
    const btn = document.getElementById('fullSyncBtn');
    if (!btn || btn.dataset.boundV5) return;
    btn.dataset.boundV5 = '1';
    // снимаем старый обработчик клонированием
    const clone = btn.cloneNode(true);
    btn.parentNode.replaceChild(clone, btn);
    clone.addEventListener('click', openPeriodModal);
  }

  // Запуск
  function bootV5() {
    injectButton();
    autoCleanSearch();
    ensurePeriodModal();
    setTimeout(rebindButton, 50);
    setTimeout(maybeAutoSync, 1200);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootV5);
  } else {
    bootV5();
  }
})();


// ====================================================================
// v6 patch: monthly_deposit в форме цели + тултип к прогнозу
// ====================================================================
(function patchGoalMonthlyDeposit() {

  function injectMonthlyDepositField() {
    // поле goalDepositInput теперь прописано в HTML напрямую,
    // и сохранение идёт через /api/goal PATCH (monthly_deposit живёт на цели).
    // Этот no-op оставлен для совместимости.
  }

  function injectForecastTooltip() {
    const fc = document.getElementById('goalForecast');
    if (!fc || fc.dataset.tipBound) return;
    fc.dataset.tipBound = '1';
    const wrap = fc.parentNode;
    if (!wrap) return;
    const tip = document.createElement('span');
    tip.textContent = ' ⓘ';
    tip.style.cssText = 'cursor:help; color: var(--text-secondary); font-size:12px; margin-left:4px;';
    tip.title =
      'Как считается прогноз:\n' +
      'cap = текущий капитал\n' +
      'каждый месяц: cap = (cap + пополнение) × (1 + r/100)\n' +
      '— пока cap < сумма цели.\n\n' +
      'Пополнение — поле "В МЕСЯЦ" в форме цели.\n' +
      'r — плановая доходность в % из формы цели.';
    wrap.appendChild(tip);
  }

  function boot() {
    injectMonthlyDepositField();
    injectForecastTooltip();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
  // также пере-инжектим после каждой перерисовки дашборда
  if (typeof window !== 'undefined') {
    const orig = window.loadAll;
    if (typeof orig === 'function') {
      window.loadAll = async function (...args) {
        const r = await orig.apply(this, args);
        setTimeout(boot, 60);
        return r;
      };
    }
  }
})();


// ====================================================================
// v7 patch: «Обгон плана» в днях + маркер плана на progress-bar
// ====================================================================
(function patchPace() {

  // Симулируем план: даёт капитал в конце месяца m
  function planAtMonth(start, dep, r, m) {
    let cap = start;
    for (let i = 0; i < m; i++) cap = (cap + dep) * (1 + r);
    return cap;
  }

  // Сколько ПОЛНЫХ месяцев плана нужно от start чтобы достичь target
  // Возвращает float (с интерполяцией внутри месяца), макс 240.
  function monthsToReachByPlan(start, dep, r, target) {
    if (target <= start) return 0;
    let cap = start;
    let m = 0;
    while (cap < target && m < 240) {
      const next = (cap + dep) * (1 + r);
      if (next >= target) {
        const frac = (target - cap) / (next - cap);
        return m + frac;
      }
      cap = next;
      m += 1;
    }
    return m;
  }

  function computePace(d) {
    if (!d || !d.goal) return null;
    const goal = d.goal;
    const settings = d.settings || {};
    const start = parseFloat(settings.start_capital || 0) || 0;
    // ПРАВКА: используем equity (общий) как индикатор прогресса
    const equity = parseFloat((d.actual && d.actual.current_equity) || 0) || 0;
    const monthsTracked = (d.actual && d.actual.months || []).length;
    // БЕЗ fallback на settings.monthly_deposit — только goal
    const dep = parseFloat(goal.monthly_deposit || 0) || 0;
    const r = (parseFloat(goal.monthly_return_pct || 0) || 0) / 100;
    const goalAmt = parseFloat(goal.amount || 0) || 0;
    // ПРАВКА: если в рамках цели нет сделок — pace не считаем
    if (d.goal_metrics && d.goal_metrics.is_empty_for_goal) {
      return { hint: 'Цель только что начата — темп измерим после первой сделки', neutral: true, plannedCap: start };
    }
    if (monthsTracked === 0) return { hint: 'Рано судить — нет полных месяцев учёта', neutral: true, plannedCap: start };

    const plannedCap = planAtMonth(start, dep, r, monthsTracked);
    const ahead = equity >= plannedCap;
    // Сколько месяцев плана соответствуют ФАКТИЧЕСКОМУ капиталу
    const monthsForActual = monthsToReachByPlan(start, dep, r, equity);
    const deltaMonths = monthsForActual - monthsTracked; // + впереди, - сзади
    const deltaDays = Math.round(deltaMonths * 30);
    const plannedPctOfGoal = goalAmt > 0 ? (plannedCap / goalAmt) * 100 : 0;

    return {
      ahead, deltaDays, deltaMonths,
      plannedCap, equity, monthsTracked,
      plannedPctOfGoal, goalAmt,
    };
  }

  function fmtDays(n) {
    n = Math.abs(n);
    if (n < 1) return '<1 дн';
    if (n === 1) return '1 день';
    if (n < 5) return n + ' дня';
    if (n < 30) return n + ' дней';
    const mo = Math.round(n / 30);
    return mo + ' мес (' + n + ' дн)';
  }

  function renderPaceChip(p) {
    let host = document.getElementById('paceChip');
    // НОВЫЙ селектор: правая часть футера новой карточки цели
    const slot = document.querySelector('.goal-card-footer .gcf-right') || document.querySelector('.goal-footer');
    if (!slot) return;
    if (!host) {
      host = document.createElement('div');
      host.id = 'paceChip';
      host.className = 'pace-chip';
      host.style.cssText = 'display:inline-flex; align-items:center; gap:6px; padding:5px 11px; border-radius:8px; font-weight:600; font-size:12.5px;';
      slot.appendChild(host);
    }
    if (!p) { host.style.display = 'none'; return; }
    host.style.display = 'inline-flex';
    if (p.neutral) {
      host.style.background = 'rgba(138,147,168,0.12)';
      host.style.color = 'var(--text-secondary)';
      host.title = p.hint || '';
      host.innerHTML = '<span>📊</span><span>' + t('goal.pace_waiting').replace(/^📊\s*/,'') + '</span>';
      return;
    }
    const days = Math.abs(p.deltaDays);
    if (days <= 2) {
      host.style.background = 'rgba(138,147,168,0.18)';
      host.style.color = 'var(--text-primary)';
      host.title = 'Плановый капитал на сегодня: $' + Math.round(p.plannedCap) + '\nФакт: $' + Math.round(p.equity) + '\nИдём ровно по плану.';
      host.innerHTML = '<span>🎯</span><span>По плану</span>';
    } else if (p.ahead) {
      host.style.background = 'rgba(16,201,138,0.14)';
      host.style.color = 'var(--green)';
      host.title = 'Плановый капитал на сегодня: $' + Math.round(p.plannedCap) + '\nФакт: $' + Math.round(p.equity) + '\nОпережаешь график на ' + days + ' дн.';
      host.innerHTML = '<span>🚀</span><span>Опережение +' + fmtDays(days) + '</span>';
    } else {
      host.style.background = 'rgba(255,90,108,0.14)';
      host.style.color = 'var(--red)';
      host.title = 'Плановый капитал на сегодня: $' + Math.round(p.plannedCap) + '\nФакт: $' + Math.round(p.equity) + '\nОтстаёшь от графика на ' + days + ' дн.';
      host.innerHTML = '<span>⏳</span><span>Отставание −' + fmtDays(days) + '</span>';
    }
  }

  function renderPlanMarker(p) {
    const track = document.querySelector('.progress-track');
    if (!track) return;
    let marker = document.getElementById('planMarker');
    if (!marker) {
      marker = document.createElement('div');
      marker.id = 'planMarker';
      marker.style.cssText = 'position:absolute; top:-4px; bottom:-4px; width:0; border-left:2px dashed #7c5cff; pointer-events:auto; z-index:3;';
      const label = document.createElement('div');
      label.id = 'planMarkerLabel';
      label.style.cssText = 'position:absolute; top:-22px; left:50%; transform:translateX(-50%); font-size:10px; color:#7c5cff; font-weight:600; white-space:nowrap; padding:1px 6px; background: rgba(124,92,255,0.12); border-radius:6px;';
      label.textContent = 'план сегодня';
      marker.appendChild(label);
      track.style.position = track.style.position || 'relative';
      track.appendChild(marker);
    }
    if (!p || p.neutral || !p.plannedPctOfGoal) { marker.style.display = 'none'; return; }
    const pct = Math.max(0, Math.min(100, p.plannedPctOfGoal));
    marker.style.display = 'block';
    marker.style.left = pct + '%';
    marker.title = 'План на сегодня: $' + Math.round(p.plannedCap) + ' (' + pct.toFixed(1) + '% от цели)';
  }

  async function refreshPace() {
    try {
      const d = await fetch('/api/dashboard').then(r => r.json());
      const p = computePace(d);
      renderPaceChip(p);
      renderPlanMarker(p);
    } catch (e) { /* noop */ }
  }

  function boot() { refreshPace(); }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
  if (typeof window !== 'undefined') {
    const orig = window.loadAll;
    if (typeof orig === 'function') {
      window.loadAll = async function (...args) {
        const r = await orig.apply(this, args);
        setTimeout(refreshPace, 80);
        return r;
      };
    }
  }
})();


// === Авто-расчёт PnL при заполнении entry/exit/qty в форме сделки ===
(function autoComputePnl() {
  function recomputePnl() {
    const entry = parseFloat(document.getElementById('tradeEntry').value);
    const exit_ = parseFloat(document.getElementById('tradeExit').value);
    const qty = parseFloat(document.getElementById('tradeQty').value);
    const side = document.getElementById('tradeSide').value;
    const pnlEl = document.getElementById('tradePnl');
    if (!pnlEl) return;
    if (!isNaN(entry) && !isNaN(exit_) && !isNaN(qty) && entry > 0 && qty > 0) {
      const sign = side === 'SHORT' ? -1 : 1;
      const pnl = (exit_ - entry) * qty * sign;
      if (!pnlEl.dataset.userEdited) {
        pnlEl.value = pnl.toFixed(2);
      }
    }
  }
  function bind() {
    ['tradeEntry','tradeExit','tradeQty','tradeSide'].forEach(id => {
      const el = document.getElementById(id); if (!el) return;
      el.addEventListener('input', recomputePnl);
      el.addEventListener('change', recomputePnl);
    });
    const pnlEl = document.getElementById('tradePnl');
    if (pnlEl) {
      pnlEl.addEventListener('input', () => { pnlEl.dataset.userEdited = '1'; });
    }
    const addBtn = document.getElementById('addTradeBtn');
    if (addBtn) addBtn.addEventListener('click', () => {
      const p = document.getElementById('tradePnl');
      if (p) delete p.dataset.userEdited;
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }
})();


// === ШАГ 2: handler для кнопки «История с нуля» в credentialsModal ===
(function fullHistoryBtnHandler() {
  function bind() {
    const btn = document.getElementById('fullHistoryBtn');
    if (!btn || btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', async () => {
      if (!confirm('Загрузить ВСЮ историю сделок с биржи с 2020 года?\n\nЭто может занять 30-60 секунд.\nДубликаты не создадутся (защита по external_id).')) return;
      btn.disabled = true;
      const orig = btn.textContent;
      btn.textContent = '⟳ Тяну…';
      try {
        const r = await fetch('/api/sync/full', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ start_date: '2020-01-01' }),
        }).then(x => x.json());
        if (r.ok) {
          let msg = '✓ Полная история: +' + (r.trades_added || 0) + ' сделок';
          if (r.deposits_added) msg += ', +' + r.deposits_added + ' депозитов';
          if (r.equity != null) msg += ', equity $' + r.equity;
          toast(msg, 'success');
        } else {
          toast('⚠ ' + ((r.errors || []).join('; ') || r.error || 'неизвестная ошибка'), 'error', 6000);
        }
        if (typeof loadAll === 'function') await loadAll({flash:true});
      } catch (e) {
        toast('✗ Ошибка: ' + e.message, 'error');
      } finally {
        btn.disabled = false;
        btn.textContent = orig;
      }
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }
})();


// === ШАГ 5: Открытые позиции + unrealized PnL (live, обновление каждые 30 сек) ===
(function openPositionsWidget() {
  const REFRESH_MS = 30000;
  let lastFetchTs = 0;
  let timer = null;
  let refreshing = false;

  function fmtTimeAgo(ms) {
    const sec = Math.floor((Date.now() - ms) / 1000);
    if (sec < 5) return 'только что';
    if (sec < 60) return t('header.time_ago_sec', sec);
    const m = Math.floor(sec / 60);
    if (m < 60) return t('header.time_ago_min', m);
    return t('header.time_ago_h', Math.floor(m / 60));
  }

  function renderPositions(data) {
    const wrap = document.getElementById('openPositionsWrap');
    if (!wrap) return;
    const positions = (data && data.positions) || [];
    // ПРАВКА: скрываем виджет если позиций 0 (экономит ~200px)
    if (!data || !data.ok || positions.length === 0) {
      wrap.style.display = 'none';
      return;  // не рисуем дальше — экономим работу
    }
    wrap.style.display = '';

    document.getElementById('opCount').textContent = positions.length;
    const totalPnl = data ? (data.total_unrealized_usd || 0) : 0;
    const totalMargin = data ? (data.total_margin_usd || 0) : 0;

    const pnlEl = document.getElementById('opTotalPnl');
    pnlEl.textContent = (totalPnl >= 0 ? '+' : '') + fmtMoney(totalPnl, 2);
    pnlEl.className = 'op-sum-val ' + (totalPnl > 0 ? 'pos' : (totalPnl < 0 ? 'neg' : ''));

    document.getElementById('opTotalMargin').textContent = fmtMoney(totalMargin, 2);

    const list = document.getElementById('opList');
    if (!positions.length) {
      list.innerHTML = '<div class="op-empty">📭 Сейчас нет открытых позиций</div>';
      return;
    }
    list.innerHTML = positions.map(p => {
      const pnl = +p.unrealized_pnl_usd || 0;
      const pct = +p.unrealized_pnl_pct || 0;
      const pnlCls = pnl > 0 ? 'pos' : (pnl < 0 ? 'neg' : '');
      const sideTag = p.side === 'SHORT'
        ? '<span class="tag tag-short">SHORT</span>'
        : (p.side === 'LONG' ? '<span class="tag tag-long">LONG</span>' : '<span class="tag tag-manual">' + esc(p.side) + '</span>');
      return `<div class="op-card">
        <div class="op-card-head">
          <div><span class="op-card-symbol">${esc(p.symbol)}</span> ${sideTag}</div>
          <span class="op-card-leverage">${(+p.leverage || 1).toFixed(0)}x</span>
        </div>
        <div class="op-card-row"><span>Entry</span><b>${(+p.entry_price).toFixed(2)}</b></div>
        <div class="op-card-row"><span>Mark</span><b>${(+p.mark_price).toFixed(2)}</b></div>
        <div class="op-card-row"><span>Qty</span><b>${(+p.qty)}</b></div>
        <div class="op-card-row"><span>Маржа</span><b>${fmtMoney(+p.margin_usd, 2)}</b></div>
        <div class="op-card-pnl">
          <span class="op-card-pnl-val ${pnlCls}">${pnl >= 0 ? '+' : ''}${fmtMoney(pnl, 2)}</span>
          <span class="op-card-pnl-pct ${pnlCls}">${pct >= 0 ? '+' : ''}${pct.toFixed(2)}%</span>
        </div>
      </div>`;
    }).join('');
  }

  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      const data = await fetch('/api/positions/open').then(r => r.json());
      lastFetchTs = Date.now();
      renderPositions(data);
      updateTimeLabel();
    } catch (e) {
      // тихо игнорируем сетевые ошибки — следующий тик попробует снова
    } finally {
      refreshing = false;
    }
  }

  function updateTimeLabel() {
    const el = document.getElementById('opRefreshInfo');
    if (el && lastFetchTs) el.textContent = 'обновлено ' + fmtTimeAgo(lastFetchTs);
  }

  function start() {
    refresh();
    if (timer) clearInterval(timer);
    timer = setInterval(() => {
      refresh();
    }, REFRESH_MS);
    // обновляем подпись «X сек назад» каждые 5 сек, даже без fetch
    setInterval(updateTimeLabel, 5000);
    const btn = document.getElementById('opRefreshBtn');
    if (btn) btn.addEventListener('click', refresh);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();


// === Onboarding: первый депозит (только если deps=0 и trades>0) ===
(function onboardingDeposit() {
  const FLAG_KEY = 'crypto-planner-onb-deposit-shown';

  async function maybeShow() {
    try {
      // не показывать если уже показывали в этой сессии
      if (sessionStorage.getItem(FLAG_KEY)) return;
    } catch (e) {}
    try {
      const [trades, deps] = await Promise.all([
        fetch('/api/trades').then(r => r.json()),
        fetch('/api/deposits').then(r => r.json()),
      ]);
      if (!Array.isArray(trades) || !Array.isArray(deps)) return;
      if (trades.length === 0) return;       // ещё нет сделок — слишком рано
      if (deps.length > 0) return;            // депозиты уже есть — не надо
      // Подставим дату самой ранней сделки
      const sorted = [...trades].sort((a,b)=>String(a.ts).localeCompare(String(b.ts)));
      const firstTs = sorted[0] && sorted[0].ts ? sorted[0].ts.slice(0, 10) : new Date().toISOString().slice(0,10);
      const input = document.getElementById('onbDepDate');
      if (input) input.value = firstTs;
      const modal = document.getElementById('onboardingDepositModal');
      if (modal) modal.classList.add('open');
      try { sessionStorage.setItem(FLAG_KEY, '1'); } catch (e) {}
    } catch (e) { /* noop */ }
  }

  function bind() {
    const skipBtn = document.getElementById('onbSkipBtn');
    if (skipBtn) skipBtn.addEventListener('click', () => {
      document.getElementById('onboardingDepositModal')?.classList.remove('open');
    });
    const saveBtn = document.getElementById('onbSaveBtn');
    if (saveBtn) saveBtn.addEventListener('click', async () => {
      const amt = parseFloat(document.getElementById('onbDepAmount').value);
      const date = document.getElementById('onbDepDate').value;
      if (!amt || amt <= 0) { toast('Укажи сумму', 'error'); return; }
      if (!date) { toast('Укажи дату', 'error'); return; }
      try {
        await fetch('/api/deposits', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({
            ts: date + 'T00:00:00',
            kind: 'deposit',
            amount_usd: amt,
            note: 'Начальный депозит (onboarding)',
            source: 'manual',
          }),
        });
        // Заодно выставим start_capital если он 0
        const s = await fetch('/api/settings').then(r => r.json());
        if (!parseFloat(s.start_capital || 0)) {
          await fetch('/api/settings', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ start_capital: String(amt) }),
          });
        }
        document.getElementById('onboardingDepositModal')?.classList.remove('open');
        toast(`✓ Начальный депозит $${amt} записан`, 'success');
        if (typeof loadAll === 'function') await loadAll({flash:true});
      } catch (e) {
        toast('✗ Ошибка: ' + e.message, 'error');
      }
    });
    // Тригер через 1.5 сек после загрузки (чтобы loadAll успел отработать)
    setTimeout(maybeShow, 1500);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }
})();


// === ГЛОБАЛЬНЫЕ ДАТЫ globalFrom/globalTo — фильтр на stats И на trades + auto-sync ===
(function globalDateFilter() {
  let timer = null;
  const synced = new Set();

  async function apply() {
    const from = document.getElementById('globalFrom')?.value;
    const to = document.getElementById('globalTo')?.value;
    if (!from && !to) {
      // сброс — вернуть выбранный период (или дефолт D)
      loadStats(_ui.period || 'D');
      window._tradesPeriod = _ui.period || 'D';
      if (typeof renderTradesTable === 'function') renderTradesTable();
      return;
    }
    // снимаем active с чипов периода
    $$('#periodToggle button').forEach(x => x.classList.remove('active'));
    window._tradesPeriod = 'CUSTOM';
    // прокидываем даты в скрытые поля для совместимости с applyFilterBar
    const tf = document.getElementById('tradesFrom');
    const tt = document.getElementById('tradesTo');
    if (tf) tf.value = from || '';
    if (tt) tt.value = to || '';

    // обновляем подпись
    const subEl = document.getElementById('globalPeriodSub');
    if (subEl) subEl.textContent = `${from || '…'} → ${to || 'сегодня'}`;

    // stats за custom-диапазон
    try {
      const s = await fetch('/api/stats?from=' + encodeURIComponent(from || '') + '&to=' + encodeURIComponent(to || '')).then(r => r.json());
      setVal('#statTotal', String(s.total||0));
      setVal('#statWins', String(s.wins||0));
      setVal('#statLosses', String(s.losses||0));
      setVal('#statWinrate', (s.winrate||0).toFixed(1) + '%');
      setVal('#statAvg', fmtMoney(s.avg||0, 2));
      setVal('#statBest', fmtMoney(s.best||0, 2));
      setVal('#statWorst', fmtMoney(s.worst||0, 2));
      setVal('#statNet', fmtMoney(s.net_pnl||0, 2));
    } catch(e) {}

    // таблица сделок
    if (typeof renderTradesTable === 'function') renderTradesTable();

    // AUTO-SYNC: подтянуть с биржи за этот диапазон (дебаунс 800мс, разово на диапазон)
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const key = `${from || ''}|${to || ''}`;
      if (synced.has(key)) return;
      synced.add(key);
      try {
        const creds = await fetch('/api/credentials').then(r => r.json());
        if (!creds || !creds.api_key) return;
      } catch (e) { return; }
      toast(`Тяну сделки с биржи за ${from || '…'} → ${to || 'сегодня'}`, 'info');
      try {
        const r = await fetch('/api/sync/full', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ start_date: from || '2020-01-01', end_date: to || undefined }),
        }).then(x => x.json());
        if (r.ok && r.trades_added) {
          toast(`✓ Подтянуто новых сделок: ${r.trades_added}`, 'success');
        } else if (r.ok) {
          toast(`Биржа не вернула новых сделок за период`, 'info');
        }
        if (typeof loadAll === 'function') await loadAll();
        await apply();
      } catch (e) {
        toast('✗ Ошибка автосинка: ' + e.message, 'error');
      }
    }, 800);
  }

  function bind() {
    ['globalFrom','globalTo'].forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.addEventListener('change', apply);
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }
})();

// === Скрытые поля tradesFrom/tradesTo (для совместимости с applyFilterBar) ===
(function ensureHiddenTradeDates() {
  function bind() {
    if (!document.getElementById('tradesFrom')) {
      const h1 = document.createElement('input');
      h1.type = 'hidden'; h1.id = 'tradesFrom';
      document.body.appendChild(h1);
    }
    if (!document.getElementById('tradesTo')) {
      const h2 = document.createElement('input');
      h2.type = 'hidden'; h2.id = 'tradesTo';
      document.body.appendChild(h2);
    }
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }
})();


// === Обновление подписи «последняя синхронизация» в #syncLastTs ===
(function syncLastTsLabel() {
  function fmtAgo(tsMs) {
    if (!tsMs) return 'ни разу';
    const sec = Math.floor((Date.now() - +tsMs) / 1000);
    if (sec < 30) return 'только что';
    if (sec < 60) return t('header.time_ago_sec', sec);
    if (sec < 3600) return t('header.time_ago_min', Math.floor(sec/60));
    if (sec < 86400) return t('header.time_ago_h', Math.floor(sec/3600));
    return t('header.time_ago_d', Math.floor(sec/86400));
  }
  async function tick() {
    const el = document.getElementById('syncLastTs');
    if (!el) return;
    try {
      const s = await fetch('/api/settings').then(r => r.json());
      const ts = +(s.last_sync_ts || 0);
      el.textContent = ts ? ('Sync: ' + fmtAgo(ts)) : 'ни разу не синкали';
      el.title = ts ? new Date(ts).toLocaleString('ru-RU') : 'API не синхронизирован';
    } catch (e) {}
  }
  function start() {
    tick();
    setInterval(tick, 30000);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();


// === GOAL ONBOARDING: пресеты $5k/$10k/$50k/$100k/своё ===
(function goalOnboarding() {
  const FLAG = 'crypto-planner-goal-onb-shown';

  function bindPresets() {
    document.querySelectorAll('.goal-preset').forEach(b => {
      b.addEventListener('click', () => {
        document.querySelectorAll('.goal-preset').forEach(x => x.classList.remove('active'));
        b.classList.add('active');
        const v = +b.dataset.amount;
        const inp = document.getElementById('goalOnbAmount');
        if (inp) inp.value = v;
      });
    });
    const inp = document.getElementById('goalOnbAmount');
    if (inp) inp.addEventListener('input', () => {
      // если ввод совпадает с пресетом — подсвечиваем
      const v = +inp.value;
      document.querySelectorAll('.goal-preset').forEach(b => {
        b.classList.toggle('active', +b.dataset.amount === v);
      });
    });
  }

  async function maybeShow() {
    // localStorage (а не session): чтобы пользователь не видел модалку при каждой новой вкладке.
    // Показываем пока он явно не нажал «Создать цель» или «Пропустить» (тогда ставим флаг).
    try { if (localStorage.getItem(FLAG)) return; } catch (e) {}
    try {
      const d = await fetch('/api/dashboard').then(r => r.json());
      const g = d.goal || {};
      // Показываем если цель — дефолт «Первая цель» $100k (пользователь её не редактировал
      // — поле amount стандартное, имя стандартное).
      // Дефолтная цель из init_db (Первая цель $100k) ИЛИ после reset (Новая цель $1k или Первая цель $100k)
      const isInitDefault = (g.name === 'Первая цель' && +g.amount === 100000);
      const isAfterReset = (g.name === 'Первая цель' && +g.amount === 100000)
                        || (g.name === 'Новая цель' && +g.amount === 1000);
      if (!g.id || isInitDefault || isAfterReset) {
        // Заполним предзначения из текущих настроек
        try {
          const s = await fetch('/api/settings').then(r => r.json());
          const scEl = document.getElementById('goalOnbStartCap');
          if (scEl) scEl.value = s.start_capital || 0;
          const sdEl = document.getElementById('goalOnbStartDate');
          if (sdEl) sdEl.value = s.start_date || new Date().toISOString().slice(0,10);
          const nameEl = document.getElementById('goalOnbName');
          if (nameEl && g.name) nameEl.value = g.name;
        } catch (e) {}
        document.getElementById('goalOnboardingModal')?.classList.add('open');
      }
    } catch (e) {}
  }

  function bindSave() {
    const skip = document.getElementById('goalOnbSkip');
    if (skip) skip.addEventListener('click', () => {
      document.getElementById('goalOnboardingModal')?.classList.remove('open');
      try { localStorage.setItem(FLAG, '1'); } catch (e) {}
    });
    const save = document.getElementById('goalOnbSave');
    if (save) save.addEventListener('click', async () => {
      const amount = +document.getElementById('goalOnbAmount').value;
      const dep = +document.getElementById('goalOnbDeposit').value || 0;
      const ret = +document.getElementById('goalOnbReturn').value || 10;
      const name = (document.getElementById('goalOnbName')?.value || '').trim();
      const startCap = +document.getElementById('goalOnbStartCap')?.value;
      const startDate = document.getElementById('goalOnbStartDate')?.value;
      if (!amount || amount <= 0) { toast('Укажи сумму цели', 'error'); return; }
      try {
        // 1) Параметры цели
        await fetch('/api/goal', {
          method: 'PATCH',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({
            name: name || 'Моя цель',
            amount: amount,
            monthly_deposit: dep,
            monthly_return_pct: ret,
          }),
        });
        // 2) Начальные условия → settings
        const settingsPayload = {};
        if (!isNaN(startCap)) settingsPayload.start_capital = String(startCap);
        if (startDate) settingsPayload.start_date = startDate;
        if (Object.keys(settingsPayload).length) {
          await fetch('/api/settings', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify(settingsPayload),
          });
        }
        document.getElementById('goalOnboardingModal')?.classList.remove('open');
        try { localStorage.setItem(FLAG, '1'); } catch (e) {}
        toast(`✓ Цель «${name || 'Моя цель'}» $${amount.toLocaleString('en-US')} создана`, 'success');
        if (typeof loadAll === 'function') await loadAll({flash:true});
      } catch (e) {
        toast('✗ Ошибка: ' + e.message, 'error');
      }
    });
  }

  function start() {
    bindPresets();
    bindSave();
    setTimeout(maybeShow, 1800);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();


// === ФАЗА 4: Аналитика — Sharpe/Sortino/R-multiple + heatmap + histogram ===
(function advancedAnalytics() {
  let loaded = false;
  async function load() {
    const host = document.getElementById('advancedContent');
    if (!host) return;
    try {
      const d = await api.get('/api/advanced');
      if (d.is_empty) {
        host.innerHTML = '<div class="adv-empty">📭 В рамках активной цели пока нет сделок. Аналитика появится после первой сделки.</div>';
        return;
      }
      // Helper для оценки качества метрик
      const sharpeCls = d.sharpe == null ? '' : (d.sharpe >= 2 ? 'good' : d.sharpe >= 1 ? 'warn' : 'bad');
      const sortinoCls = d.sortino == null ? '' : (d.sortino >= 2 ? 'good' : d.sortino >= 1 ? 'warn' : 'bad');
      const pfCls = d.profit_factor == null ? '' : (d.profit_factor >= 2 ? 'good' : d.profit_factor >= 1 ? 'warn' : 'bad');
      const rrCls = d.rr == null ? '' : (d.rr >= 2 ? 'good' : d.rr >= 1 ? 'warn' : 'bad');
      const expCls = d.expectancy > 0 ? 'good' : (d.expectancy < 0 ? 'bad' : '');
      const wrCls = d.winrate >= 50 ? 'good' : (d.winrate >= 35 ? 'warn' : 'bad');

      let html = '';

      const calmarCls = d.calmar == null ? '' : (d.calmar >= 3 ? 'good' : d.calmar >= 1 ? 'warn' : 'bad');
      // === Risk-adjusted returns + Calmar ===
      html += '<div class="adv-section">' +
        '<div class="adv-section-title">🎯 Качество стратегии <span class="adv-info">' +
          'Sharpe >2 хорошо · Sortino >2 хорошо · PF >2 хорошо · RR >2 хорошо · Calmar >3 отлично</span></div>' +
        '<div class="adv-metrics-grid">' +
          '<div class="adv-metric ' + sharpeCls + '" title="Sharpe Ratio: годовая доходность ÷ годовая волатильность. >2 = очень хорошо, 1-2 = норм, <1 = слабо"><div class="adv-metric-label">Sharpe Ratio</div>' +
            '<div class="adv-metric-value">' + (d.sharpe == null ? '—' : d.sharpe) + '</div>' +
            '<div class="adv-metric-sub">риск-adjusted</div></div>' +
          '<div class="adv-metric ' + sortinoCls + '" title="Sortino Ratio: как Sharpe, но учитывает только downside (отрицательную волатильность)"><div class="adv-metric-label">Sortino Ratio</div>' +
            '<div class="adv-metric-value">' + (d.sortino == null ? '—' : d.sortino) + '</div>' +
            '<div class="adv-metric-sub">только downside</div></div>' +
          '<div class="adv-metric ' + calmarCls + '" title="Calmar Ratio: годовая доходность ÷ максимальная просадка. >3 = отлично"><div class="adv-metric-label">Calmar Ratio</div>' +
            '<div class="adv-metric-value">' + (d.calmar == null ? '—' : d.calmar) + '</div>' +
            '<div class="adv-metric-sub">' + (d.annual_return_pct != null ? d.annual_return_pct.toFixed(1) + '%/год' : 'годовая / MDD') + '</div></div>' +
          '<div class="adv-metric ' + pfCls + '" title="Profit Factor = gross_profit / gross_loss. >2 = хорошо, 1-2 = норм, <1 = убыточно"><div class="adv-metric-label">Profit Factor</div>' +
            '<div class="adv-metric-value">' + (d.profit_factor == null ? '—' : d.profit_factor) + '</div>' +
            '<div class="adv-metric-sub">PF</div></div>' +
          '<div class="adv-metric ' + rrCls + '" title="Risk-Reward = avg_win / avg_loss. >2 значит выигрыши вдвое больше проигрышей"><div class="adv-metric-label">Risk-Reward</div>' +
            '<div class="adv-metric-value">' + (d.rr == null ? '—' : d.rr) + '</div>' +
            '<div class="adv-metric-sub">RR</div></div>' +
        '</div></div>';

      // === Распределение прибыли + median/mean ===
      const medCls = d.median_pnl > 0 ? 'good' : (d.median_pnl < 0 ? 'bad' : '');
      html += '<div class="adv-section">' +
        '<div class="adv-section-title">📊 Распределение прибыли</div>' +
        '<div class="adv-metrics-grid">' +
          '<div class="adv-metric ' + wrCls + '" title="Процент прибыльных сделок от всех решительных (без break-even)"><div class="adv-metric-label">Winrate</div>' +
            '<div class="adv-metric-value">' + d.winrate + '%</div>' +
            '<div class="adv-metric-sub">' + d.wins + ' / ' + d.losses + '</div></div>' +
          '<div class="adv-metric ' + expCls + '" title="Expectancy: winrate × avg_win − loss_rate × avg_loss. Сколько в среднем зарабатываешь с одной сделки"><div class="adv-metric-label">Expectancy</div>' +
            '<div class="adv-metric-value ' + (d.expectancy>=0?'pos':'neg') + '">' + (d.expectancy>=0?'+':'') + fmtMoney(d.expectancy, 2) + '</div>' +
            '<div class="adv-metric-sub">ожидание/сделку</div></div>' +
          '<div class="adv-metric ' + medCls + '" title="Медиана PnL: средний результат типичной сделки. Не подвержен влиянию крайних значений"><div class="adv-metric-label">Median PnL</div>' +
            '<div class="adv-metric-value ' + (d.median_pnl>=0?'pos':'neg') + '">' + (d.median_pnl>=0?'+':'') + fmtMoney(d.median_pnl, 2) + '</div>' +
            '<div class="adv-metric-sub">медиана</div></div>' +
          '<div class="adv-metric" title="Mean PnL: среднее арифметическое всех сделок"><div class="adv-metric-label">Mean PnL</div>' +
            '<div class="adv-metric-value ' + (d.mean_pnl>=0?'pos':'neg') + '">' + (d.mean_pnl>=0?'+':'') + fmtMoney(d.mean_pnl, 2) + '</div>' +
            '<div class="adv-metric-sub">среднее</div></div>' +
          '<div class="adv-metric"><div class="adv-metric-label">Avg Win</div>' +
            '<div class="adv-metric-value pos">+' + fmtMoney(d.avg_win, 2) + '</div></div>' +
          '<div class="adv-metric"><div class="adv-metric-label">Avg Loss</div>' +
            '<div class="adv-metric-value neg">−' + fmtMoney(d.avg_loss, 2) + '</div></div>' +
          '<div class="adv-metric"><div class="adv-metric-label">Gross Profit</div>' +
            '<div class="adv-metric-value pos">+' + fmtMoney(d.gross_profit, 2) + '</div></div>' +
          '<div class="adv-metric"><div class="adv-metric-label">Gross Loss</div>' +
            '<div class="adv-metric-value neg">−' + fmtMoney(d.gross_loss, 2) + '</div></div>' +
        '</div></div>';

      // === #8 #9: Когда и где торгуешь лучше ===
      const bh = d.best_hour, wh = d.worst_hour, bd = d.best_dow, wd = d.worst_dow, bs = d.best_symbol, ws = d.worst_symbol;
      html += '<div class="adv-section">' +
        '<div class="adv-section-title">⏰ Когда и где торгуешь лучше</div>' +
        '<div class="adv-metrics-grid">' +
          (bh ? '<div class="adv-metric good"><div class="adv-metric-label">Лучший час</div>' +
            '<div class="adv-metric-value pos">' + esc(bh.key) + '</div>' +
            '<div class="adv-metric-sub">+' + fmtMoney(bh.pnl, 0) + ' за ' + bh.count + ' сделок</div></div>' : '') +
          (wh ? '<div class="adv-metric bad"><div class="adv-metric-label">Худший час</div>' +
            '<div class="adv-metric-value neg">' + esc(wh.key) + '</div>' +
            '<div class="adv-metric-sub">' + fmtMoney(wh.pnl, 0) + ' за ' + wh.count + ' сделок</div></div>' : '') +
          (bd ? '<div class="adv-metric good"><div class="adv-metric-label">Лучший день</div>' +
            '<div class="adv-metric-value pos">' + esc(bd.key) + '</div>' +
            '<div class="adv-metric-sub">+' + fmtMoney(bd.pnl, 0) + ' за ' + bd.count + ' сделок</div></div>' : '') +
          (wd ? '<div class="adv-metric bad"><div class="adv-metric-label">Худший день</div>' +
            '<div class="adv-metric-value neg">' + esc(wd.key) + '</div>' +
            '<div class="adv-metric-sub">' + fmtMoney(wd.pnl, 0) + ' за ' + wd.count + ' сделок</div></div>' : '') +
          (bs ? '<div class="adv-metric good"><div class="adv-metric-label">Лучшая пара</div>' +
            '<div class="adv-metric-value pos">' + esc(bs.key) + '</div>' +
            '<div class="adv-metric-sub">+' + fmtMoney(bs.pnl, 0) + ' за ' + bs.count + ' сделок</div></div>' : '') +
          (ws ? '<div class="adv-metric bad"><div class="adv-metric-label">Худшая пара</div>' +
            '<div class="adv-metric-value neg">' + esc(ws.key) + '</div>' +
            '<div class="adv-metric-sub">' + fmtMoney(ws.pnl, 0) + ' за ' + ws.count + ' сделок</div></div>' : '') +
        '</div></div>';

      // === #7: Sharpe per setup — таблица ===
      if (d.by_setup && d.by_setup.length) {
        html += '<div class="adv-section">' +
          '<div class="adv-section-title">🎯 Метрики по сетапам <span class="adv-info">какой сетап реально работает</span></div>' +
          '<table class="adv-setup-table"><thead><tr>' +
            '<th>Сетап</th><th>Сделок</th><th>Winrate</th><th>Net P&L</th><th>Avg P&L</th><th title="Sharpe-подобная метрика на сделках: mean / std">PnL Sharpe</th>' +
          '</tr></thead><tbody>' +
          d.by_setup.map(s => {
            const netCls = s.net_pnl > 0 ? 'pos' : (s.net_pnl < 0 ? 'neg' : '');
            const psCls = s.pnl_sharpe == null ? '' : (s.pnl_sharpe >= 0.3 ? 'pos' : (s.pnl_sharpe < 0 ? 'neg' : ''));
            return '<tr>' +
              '<td><b>' + esc(s.setup) + '</b></td>' +
              '<td>' + s.count + '</td>' +
              '<td>' + s.winrate + '%</td>' +
              '<td class="' + netCls + '">' + (s.net_pnl>=0?'+':'') + fmtMoney(s.net_pnl, 2) + '</td>' +
              '<td class="' + (s.avg_pnl>0?'pos':s.avg_pnl<0?'neg':'') + '">' + (s.avg_pnl>=0?'+':'') + fmtMoney(s.avg_pnl, 2) + '</td>' +
              '<td class="' + psCls + '">' + (s.pnl_sharpe == null ? '—' : s.pnl_sharpe) + '</td>' +
            '</tr>';
          }).join('') + '</tbody></table></div>';
      }

      // === #5: Streak Distribution ===
      if (d.streak_distribution) {
        const sd = d.streak_distribution;
        const winKeys = Object.keys(sd.win || {}).map(Number).sort((a,b)=>a-b);
        const lossKeys = Object.keys(sd.loss || {}).map(Number).sort((a,b)=>a-b);
        if (winKeys.length || lossKeys.length) {
          const renderRow = (kind, dist, keys) => {
            const cls = kind === 'win' ? 'pos' : 'neg';
            const emoji = kind === 'win' ? '🔥' : '❄';
            return '<div class="streak-row"><div class="streak-row-label">' + emoji + ' ' + (kind==='win'?'Победы':'Поражения') + ':</div>' +
              keys.map(k => '<span class="streak-chip ' + cls + '">×' + k + ': ' + dist[k] + '</span>').join(' ') +
              '</div>';
          };
          html += '<div class="adv-section">' +
            '<div class="adv-section-title">📈 Распределение серий <span class="adv-info">сколько было серий длины 1, 2, 3...</span></div>' +
            (winKeys.length ? renderRow('win', sd.win, winKeys) : '') +
            (lossKeys.length ? renderRow('loss', sd.loss, lossKeys) : '') +
            '</div>';
        }
      }

      // === Histogram PnL ===
      if (d.histogram && d.histogram.length) {
        const maxCount = Math.max(...d.histogram.map(h => h.count));
        html += '<div class="adv-section">' +
          '<div class="adv-section-title">📊 Распределение PnL по бакетам <span class="adv-info">' +
            d.histogram.length + ' бакетов от ' + fmtMoney(d.histogram[0].bucket_start, 0) + ' до ' + fmtMoney(d.histogram[d.histogram.length-1].bucket_end, 0) + '</span></div>' +
          '<div class="adv-histogram" style="display:flex; align-items:flex-end; height:140px; gap:3px; padding-top:10px;">' +
          d.histogram.map(h => {
            const heightPct = maxCount ? (h.count / maxCount * 100) : 0;
            const isNeg = h.bucket_start < 0;
            const color = isNeg ? 'var(--red)' : 'var(--green)';
            return '<div style="flex:1; display:flex; flex-direction:column; align-items:center; gap:4px;" ' +
              'title="' + fmtMoney(h.bucket_start, 0) + ' → ' + fmtMoney(h.bucket_end, 0) + ': ' + h.count + ' сделок">' +
              '<div style="font-size:9px; color:var(--text-secondary);">' + (h.count || '') + '</div>' +
              '<div style="width:100%; height:' + heightPct + '%; min-height:1px; background:' + color + '; opacity:0.7; border-radius:2px 2px 0 0;"></div>' +
              '<div style="font-size:8.5px; color:var(--text-muted); writing-mode:vertical-lr; transform:rotate(180deg);">' + (isNeg?'':'+') + Math.round(h.bucket_start) + '</div>' +
            '</div>';
          }).join('') + '</div></div>';
      }

      // === Heatmap по часам × дням недели ===
      if (d.heatmap && d.heatmap.length) {
        const allVals = d.heatmap.flat();
        const maxAbs = Math.max(...allVals.map(v => Math.abs(v))) || 1;
        const days = ['Пн','Вт','Ср','Чт','Пт','Сб','Вс'];
        let hmHtml = '<table class="adv-heatmap-table"><thead><tr><th></th>';
        for (let h = 0; h < 24; h++) hmHtml += '<th>' + (h < 10 ? '0'+h : h) + '</th>';
        hmHtml += '</tr></thead><tbody>';
        for (let dIdx = 0; dIdx < 7; dIdx++) {
          hmHtml += '<tr><td>' + days[dIdx] + '</td>';
          for (let h = 0; h < 24; h++) {
            const v = d.heatmap[dIdx][h];
            const n = d.heatmap_count[dIdx][h];
            const intensity = Math.min(1, Math.abs(v) / maxAbs);
            let bg = 'transparent';
            if (v > 0) bg = 'rgba(16,201,138,' + (0.1 + intensity * 0.6) + ')';
            else if (v < 0) bg = 'rgba(255,90,108,' + (0.1 + intensity * 0.6) + ')';
            const title = days[dIdx] + ' ' + h + ':00 — ' + fmtMoney(v, 2) + ' (' + n + ' сделок)';
            hmHtml += '<td style="background:' + bg + ';" title="' + title + '">' + (n>0?n:'') + '</td>';
          }
          hmHtml += '</tr>';
        }
        hmHtml += '</tbody></table>';
        html += '<div class="adv-section">' +
          '<div class="adv-section-title">🔥 Тепловая карта: когда ты лучше торгуешь <span class="adv-info">' +
            'зелёный — прибыль, красный — убыток · в ячейке — число сделок</span></div>' +
          hmHtml + '</div>';
      }

      host.innerHTML = html;
    } catch (e) {
      host.innerHTML = '<div class="adv-empty">✗ Ошибка загрузки: ' + esc(e.message) + '</div>';
    }
  }
  // Загружаем при клике на таб
  function bind() {
    const tab = document.querySelector('[data-tab="advanced"]');
    if (tab) tab.addEventListener('click', () => {
      if (!loaded) { loaded = true; load(); }
      else { setTimeout(load, 50); }  // перерисуем
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }
})();

// === ФАЗА 5: PDF-отчёт месячный ===
(function pdfReportButton() {
  function bind() {
    const btn = document.getElementById('reportPdfBtn');
    if (!btn || btn.dataset.bound) return;
    btn.dataset.bound = '1';
    // Текущий месяц по умолчанию
    const now = new Date();
    const period = now.getFullYear() + '-' + String(now.getMonth()+1).padStart(2, '0');
    btn.href = '/api/report/pdf?period=' + period;
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }
})();

// === #17: Undo snackbar (откат удаления в течение 5 сек) ===
function showUndoSnackbar(message, onUndo) {
  const old = document.getElementById('undoSnackbar');
  if (old) old.remove();
  const bar = document.createElement('div');
  bar.id = 'undoSnackbar';
  bar.className = 'undo-snackbar';
  let secLeft = 5;
  bar.innerHTML = '<span>↶ ' + esc(message) + '</span><button id="undoBtn">Отменить</button><span class="undo-timer">' + secLeft + 's</span>';
  document.body.appendChild(bar);
  const btn = bar.querySelector('#undoBtn');
  const timerEl = bar.querySelector('.undo-timer');
  let dismissed = false;
  btn.addEventListener('click', async () => {
    if (dismissed) return;
    dismissed = true;
    bar.remove();
    try { await onUndo(); } catch (e) { toast('Ошибка отмены: ' + e.message, 'error'); }
  });
  const iv = setInterval(() => {
    secLeft -= 1;
    if (timerEl) timerEl.textContent = secLeft + 's';
    if (secLeft <= 0) {
      clearInterval(iv);
      if (!dismissed) {
        bar.classList.add('fading');
        setTimeout(() => bar.remove(), 500);
      }
    }
  }, 1000);
}

// === #2 #3: Equity curve по дням + Underwater plot ===
let _equityDailyChart = null;
async function renderEquityDaily() {
  try {
    const d = await api.get('/api/equity/daily');
    const card = document.getElementById('equityDailyCard');
    if (!card) return;
    if (d.is_empty || !d.dates || d.dates.length === 0) {
      card.style.display = 'none';
      return;
    }
    card.style.display = '';
    const canvas = document.getElementById('equityDailyChart');
    if (!canvas) return;
    if (_equityDailyChart) _equityDailyChart.destroy();
    _equityDailyChart = new Chart(canvas, {
      type: 'line',
      data: {
        labels: d.dates,
        datasets: [
          {
            label: 'Equity',
            data: d.equity,
            borderColor: '#10c98a',
            backgroundColor: c => makeGrad(c, 'rgba(16,201,138,0.30)', 'rgba(16,201,138,0)'),
            fill: true, tension: 0.2, borderWidth: 2, pointRadius: 0,
            yAxisID: 'y',
          },
          {
            label: 'Drawdown %',
            data: d.drawdown_pct.map(v => -v),  // инвертируем под линию
            borderColor: '#ff5a6c',
            backgroundColor: 'rgba(255,90,108,0.10)',
            fill: true, tension: 0.2, borderWidth: 1.5, pointRadius: 0,
            yAxisID: 'y2',
          },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#11151f', borderColor: '#2d3548', borderWidth: 1, padding: 10,
            callbacks: {
              label: c => c.dataset.label === 'Drawdown %' ? `Просадка: ${(-c.parsed.y).toFixed(2)}%` : `Equity: ${fmtMoney(c.parsed.y, 2)}`
            }
          }
        },
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { maxTicksLimit: 12 } },
          y: { position: 'left', grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { callback: v => fmtMoney(v, 0) } },
          y2: { position: 'right', grid: { display: false }, ticks: { callback: v => v + '%', color: 'rgba(255,90,108,0.7)' }, suggestedMin: -50, suggestedMax: 0 },
        }
      }
    });
  } catch (e) { console.warn('equityDaily render failed:', e); }
}
// Хук в loadAll
(function() {
  const orig = window.loadAll;
  if (typeof orig === 'function') {
    window.loadAll = async function(...args) {
      const r = await orig.apply(this, args);
      setTimeout(renderEquityDaily, 100);
      return r;
    };
  }
})();

// === #47: Sharing-кнопка ===
(function shareGoal() {
  function bind() {
    const btn = document.getElementById('shareGoalBtn');
    if (!btn || btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', async () => {
      try {
        const r = await fetch('/api/share/create', {method:'POST'}).then(x=>x.json());
        const url = window.location.origin + r.url;
        try { await navigator.clipboard.writeText(url); } catch (e) {}
        const msg = '🔗 Ссылка скопирована (действует 24ч):\n' + url + '\n\nТам видны только проценты и количество сделок, суммы замаскированы.';
        alert(msg);
      } catch (e) { toast('Ошибка: ' + e.message, 'error'); }
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind);
  else bind();
  // Перехватим loadAll чтобы биндить заново после re-render
  const orig = window.loadAll;
  if (typeof orig === 'function') {
    window.loadAll = async function(...args) {
      const r = await orig.apply(this, args);
      setTimeout(bind, 80);
      return r;
    };
  }
})();

// === #18: Конфетти при достижении цели (без либ) ===
function fireConfetti() {
  const canvas = document.getElementById('confettiCanvas');
  if (!canvas) return;
  canvas.style.display = 'block';
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  const ctx = canvas.getContext('2d');
  const colors = ['#7c5cff', '#4ea1ff', '#10c98a', '#ff5a6c', '#ffa033', '#a96cff'];
  const particles = [];
  for (let i = 0; i < 150; i++) {
    particles.push({
      x: canvas.width / 2,
      y: canvas.height / 2,
      vx: (Math.random() - 0.5) * 16,
      vy: Math.random() * -15 - 5,
      color: colors[Math.floor(Math.random() * colors.length)],
      size: Math.random() * 8 + 4,
      gravity: 0.4,
      life: 1.0,
    });
  }
  function tick() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    let alive = 0;
    particles.forEach(p => {
      if (p.life <= 0) return;
      alive++;
      p.x += p.vx;
      p.y += p.vy;
      p.vy += p.gravity;
      p.life -= 0.015;
      ctx.globalAlpha = p.life;
      ctx.fillStyle = p.color;
      ctx.fillRect(p.x, p.y, p.size, p.size);
    });
    if (alive > 0) requestAnimationFrame(tick);
    else canvas.style.display = 'none';
  }
  requestAnimationFrame(tick);
}

// Триггер конфетти когда цель достигнута
(function watchGoalAchieved() {
  let lastPct = 0;
  const orig = window.loadAll;
  if (typeof orig === 'function') {
    window.loadAll = async function(...args) {
      const r = await orig.apply(this, args);
      try {
        if (_data && _data.pct_to_goal >= 100 && lastPct < 100) {
          fireConfetti();
          if (typeof toast === 'function') toast('🎉 ЦЕЛЬ ДОСТИГНУТА!', 'success', 5000);
        }
        lastPct = _data?.pct_to_goal || 0;
      } catch (e) {}
      return r;
    };
  }
})();

// === #13: Drag-and-drop CSV ===
(function dragDropCsv() {
  let dragCounter = 0;
  let overlay = null;
  function getOverlay() {
    if (overlay) return overlay;
    overlay = document.createElement('div');
    overlay.className = 'csv-drop-overlay';
    overlay.innerHTML = '📂 Брось CSV сюда для импорта депозитов';
    document.body.appendChild(overlay);
    return overlay;
  }
  document.addEventListener('dragenter', e => {
    if (e.dataTransfer && (e.dataTransfer.types || []).indexOf('Files') >= 0) {
      dragCounter++;
      getOverlay().classList.add('active');
    }
  });
  document.addEventListener('dragleave', e => {
    dragCounter--;
    if (dragCounter <= 0) {
      dragCounter = 0;
      if (overlay) overlay.classList.remove('active');
    }
  });
  document.addEventListener('dragover', e => { e.preventDefault(); });
  document.addEventListener('drop', e => {
    e.preventDefault();
    dragCounter = 0;
    if (overlay) overlay.classList.remove('active');
    const files = Array.from(e.dataTransfer.files || []).filter(f => f.name.toLowerCase().endsWith('.csv'));
    if (!files.length) return;
    // Передаём в существующий CSV-импорт
    const input = document.getElementById('depositsCsvInput');
    if (!input) return;
    const dt = new DataTransfer();
    files.forEach(f => dt.items.add(f));
    input.files = dt.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  });
})();

// === #14: Inline-edit заметки сделки ===
(function inlineNoteEdit() {
  document.addEventListener('dblclick', async e => {
    const td = e.target.closest('.trade-note-cell');
    if (!td) return;
    const tradeId = td.dataset.tradeId;
    if (!tradeId) return;
    const oldText = td.textContent.trim();
    const inp = document.createElement('input');
    inp.type = 'text';
    inp.className = 'trade-note-input';
    inp.value = oldText;
    td.innerHTML = '';
    td.appendChild(inp);
    inp.focus();
    inp.select();
    const save = async () => {
      const newText = inp.value;
      if (newText === oldText) {
        td.textContent = oldText;
        return;
      }
      try {
        await fetch('/api/trades/' + tradeId, {
          method: 'PATCH',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ note: newText }),
        });
        td.textContent = newText;
        toast('✓ Заметка обновлена', 'success', 1500);
      } catch (err) {
        td.textContent = oldText;
        toast('✗ Не удалось обновить', 'error');
      }
    };
    inp.addEventListener('blur', save);
    inp.addEventListener('keydown', ev => {
      if (ev.key === 'Enter') inp.blur();
      if (ev.key === 'Escape') { td.textContent = oldText; }
    });
  });
})();

// === #27: Напоминание ротировать ключи (>90 дней) ===
(function rotateKeysReminder() {
  async function check() {
    try {
      const c = await fetch('/api/credentials').then(r => r.json());
      if (c.rotate_recommended) {
        const pill = document.getElementById('apiStatus');
        if (pill && !pill.querySelector('.rotate-warning')) {
          const warn = document.createElement('span');
          warn.className = 'rotate-warning';
          warn.textContent = '⏰ старше ' + c.age_days + ' дн';
          warn.title = 'Рекомендуется перевыпустить API-ключи на бирже (старше 90 дней)';
          pill.appendChild(warn);
        }
      }
    } catch (e) {}
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', check);
  else check();
})();


// ============================================================
// Фича Q-G: график монеты при клике на сделку (Lightweight Charts)
// ============================================================
(function setupTradeChart() {
  let _chart = null;
  let _series = null;
  let _currentTradeId = null;

  function openChartModal(tradeId) {
    _currentTradeId = tradeId;
    const modal = document.getElementById('tradeChartModal');
    if (!modal) return;
    modal.style.display = 'block';
    // Если у пользователя ещё дефолт 15m — на больших сделках мало контекста.
    // Default: 1h (показывает несколько суток истории — лучше для swing-trades)
    const tfEl = document.getElementById('tcm_tf');
    if (tfEl && tfEl.value === '15m') tfEl.value = '1h';
    loadAndRender(tradeId, (tfEl && tfEl.value) || '1h');
  }

  async function loadAndRender(tradeId, tf) {
    const meta = document.getElementById('tcm_meta');
    const title = document.getElementById('tcm_title');
    const subtitle = document.getElementById('tcm_subtitle');
    meta.textContent = 'Загружаю свечи…';
    try {
      const r = await fetch('/api/trades/' + tradeId + '/chart?tf=' + tf, {credentials: 'include'});
      const j = await r.json();
      if (!r.ok || !j.ok) {
        meta.textContent = 'Ошибка: ' + (j.error || 'HTTP ' + r.status);
        return;
      }
      const t = j.trade;
      const sideEmoji = t.side === 'LONG' ? '🟢' : '🔴';
      title.textContent = sideEmoji + ' ' + t.symbol + ' · ' + (t.side || '');
      const pnlSign = (t.pnl_usd >= 0 ? '+' : '');
      const pnlColor = t.pnl_usd >= 0 ? '#10c98a' : '#ff5a6c';
      subtitle.innerHTML = 'Entry: <b>' + (t.entry_price || '—') + '</b> → Exit: <b>' + (t.exit_price || '—') + '</b> · ' +
        'P&L: <b style="color:' + pnlColor + '">' + pnlSign + (t.pnl_usd || 0).toFixed(2) + '$ (' + pnlSign + (t.pnl_pct || 0).toFixed(2) + '%)</b>';
      renderChart(j.candles, t);
      // Человекочитаемый источник
      const srcMap = {
        'bitunix': 'Bitunix',
        'bybit_fallback': 'Bybit (fallback — Bitunix недоступен)',
        'unknown': '—'
      };
      const srcName = srcMap[j.source] || j.source;
      // TradingView link — perpetual futures на Bitunix
      const tvInterval = { '1m':'1','5m':'5','15m':'15','1h':'60','4h':'240','1d':'D' }[j.tf] || '60';
      const tvUrl = 'https://www.tradingview.com/chart/?symbol=BITUNIX:' + t.symbol + '.P&interval=' + tvInterval;
      meta.innerHTML = 'Источник: <b>' + srcName + '</b> · ' + j.candles.length + ' свечей · timeframe ' + j.tf +
        ' · <a href="' + tvUrl + '" target="_blank" rel="noopener" style="color:#5a9be0;text-decoration:none;">📈 Открыть в TradingView</a>';
    } catch (e) {
      meta.textContent = 'Ошибка: ' + e.message;
    }
  }

  function renderChart(candles, trade) {
    const container = document.getElementById('tcm_chart');
    if (!container) return;
    container.innerHTML = '';
    if (!window.LightweightCharts) {
      container.innerHTML = '<div style="padding:40px;text-align:center;color:#8a96a8;">LightweightCharts CDN не загрузился</div>';
      return;
    }
    _chart = window.LightweightCharts.createChart(container, {
      width: container.clientWidth,
      height: 420,
      layout: { background: { color: '#0a0e14' }, textColor: '#e5edf5' },
      grid: { vertLines: { color: '#1f2837' }, horzLines: { color: '#1f2837' } },
      timeScale: { timeVisible: true, secondsVisible: false, borderColor: '#1f2837' },
      rightPriceScale: { borderColor: '#1f2837' },
    });
    _series = _chart.addCandlestickSeries({
      upColor: '#10c98a', downColor: '#ff5a6c',
      borderUpColor: '#10c98a', borderDownColor: '#ff5a6c',
      wickUpColor: '#10c98a', wickDownColor: '#ff5a6c',
    });
    _series.setData(candles);

    const isLong = trade.side === 'LONG';
    const pnlPositive = (trade.pnl_usd || 0) >= 0;
    const entryPrice = +trade.entry_price || null;
    const exitPrice = +trade.exit_price || null;

    // --- Горизонтальные ценовые линии (как в TradingView) ---
    // Entry line — синяя пунктирная на уровне цены входа
    if (entryPrice) {
      _series.createPriceLine({
        price: entryPrice,
        color: '#5a9be0',
        lineWidth: 1,
        lineStyle: window.LightweightCharts.LineStyle.Dashed,
        axisLabelVisible: true,
        title: (isLong ? '▲ ' : '▼ ') + 'Entry ' + entryPrice,
      });
    }
    // Exit line — цвет по P&L
    if (exitPrice) {
      _series.createPriceLine({
        price: exitPrice,
        color: pnlPositive ? '#10c98a' : '#ff5a6c',
        lineWidth: 1,
        lineStyle: window.LightweightCharts.LineStyle.Dashed,
        axisLabelVisible: true,
        title: 'Exit ' + exitPrice + ' · ' + (pnlPositive ? '+' : '') + (trade.pnl_usd || 0).toFixed(2) + '$',
      });
    }

    // --- Маркеры-стрелки в баре входа/выхода ---
    // Логика: stрелка направлена в сторону ожидаемого движения для entry
    // и в сторону "куда ушла цена" для exit
    const markers = [];
    if (trade.entry_ts && entryPrice) {
      markers.push({
        time: trade.entry_ts,
        // LONG → купили, ждём рост → стрелка ВВЕРХ под баром
        // SHORT → продали, ждём падение → стрелка ВНИЗ над баром
        position: isLong ? 'belowBar' : 'aboveBar',
        color: isLong ? '#10c98a' : '#ff5a6c',
        shape: isLong ? 'arrowUp' : 'arrowDown',
        size: 2,
      });
    }
    if (trade.exit_ts && exitPrice) {
      // Exit стрелка зависит от стороны сделки + результата.
      // LONG: pnlPositive → цена выросла → стрелка ВВЕРХ зелёная
      //       pnlNegative → цена упала   → стрелка ВНИЗ красная
      // SHORT: pnlPositive → цена упала   → стрелка ВНИЗ зелёная
      //        pnlNegative → цена выросла → стрелка ВВЕРХ красная
      const priceMoved = exitPrice > entryPrice;  // вверх ли пошла цена
      markers.push({
        time: trade.exit_ts,
        position: priceMoved ? 'aboveBar' : 'belowBar',
        color: pnlPositive ? '#10c98a' : '#ff5a6c',
        shape: priceMoved ? 'arrowUp' : 'arrowDown',
        size: 2,
      });
    }
    _series.setMarkers(markers);
    _chart.timeScale().fitContent();
  }

  document.addEventListener('change', (e) => {
    if (e.target && e.target.id === 'tcm_tf' && _currentTradeId) {
      loadAndRender(_currentTradeId, e.target.value);
    }
  });

  // Делегирование кликов на <tr data-trade-row="1">, кроме delete/note/buttons/inputs
  document.addEventListener('click', (e) => {
    if (e.target.closest('[data-del-trade]')) return;
    if (e.target.closest('.trade-note-cell')) return;
    if (e.target.closest('button') || e.target.closest('a')) return;
    if (e.target.closest('input') || e.target.closest('select') || e.target.closest('textarea')) return;
    const row = e.target.closest('tr[data-trade-row="1"]');
    if (row) {
      const id = parseInt(row.getAttribute('data-trade-id'));
      if (id) openChartModal(id);
    }
  });

  window.openTradeChart = openChartModal;
})();

// ===== i18n: переключатель RU/EN =====
(function () {
  function highlight() {
    const cur = (window.i18n && window.i18n.getLang()) || 'ru';
    document.querySelectorAll('.btn-lang').forEach(function (b) {
      b.style.opacity = (b.getAttribute('data-lang') === cur) ? '1' : '0.6';
      b.style.background = (b.getAttribute('data-lang') === cur) ? 'rgba(90,155,224,0.18)' : 'transparent';
      b.style.fontWeight = (b.getAttribute('data-lang') === cur) ? '600' : '400';
    });
  }
  document.addEventListener('click', function (e) {
    const btn = e.target.closest('.btn-lang');
    if (!btn || !window.i18n) return;
    const lang = btn.getAttribute('data-lang');
    window.i18n.setLang(lang).then(highlight);
  });
  document.addEventListener('i18n:changed', function () {
    highlight();
    // Перерисовать таблицы которые рендерятся в JS (с переведённым empty-state и т.п.)
    if (typeof loadAll === 'function') { try { loadAll(); } catch (_) {} }
  });
  // подгружаем язык с сервера (если сохранён в user.lang — переписываем localStorage)
  fetch('/api/user/me', { credentials: 'include' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) {
      if (!d || !d.ok || !d.lang) return;
      const cur = localStorage.getItem('tr_lang');
      if (cur !== d.lang && window.i18n) window.i18n.setLang(d.lang).then(highlight);
      else highlight();
    })
    .catch(function () { highlight(); });
  // первичная подсветка после загрузки i18n
  document.addEventListener('DOMContentLoaded', highlight);
  setTimeout(highlight, 500);
})();
