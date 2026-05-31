// TradeRunner i18n (vanilla, no deps)
// Использование:
//   <span data-i18n="header.sync"></span>
//   <input data-i18n-placeholder="trades.note_placeholder">
//   <img data-i18n-alt="...">
//   <button title="..." data-i18n-title="...">
// В JS: t('toast.saved'), t('chart.candles', 200) для подстановки {0}.
(function () {
  const SUPPORTED = ['ru', 'en'];
  const STORAGE_KEY = 'tr_lang';
  const DEFAULT_LANG = 'ru';
  let _dict = {};
  let _lang = null;

  function detectLang() {
    // 1) localStorage
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored && SUPPORTED.includes(stored)) return stored;
    // 2) Accept-Language через navigator
    const nav = (navigator.language || navigator.userLanguage || '').toLowerCase();
    if (nav.startsWith('ru')) return 'ru';
    // 3) default
    return DEFAULT_LANG;
  }

  function get(obj, path) {
    const parts = path.split('.');
    let cur = obj;
    for (const p of parts) {
      if (cur && typeof cur === 'object' && p in cur) cur = cur[p];
      else return null;
    }
    return cur;
  }

  function format(str, args) {
    if (!str || !args || !args.length) return str;
    return str.replace(/\{(\d+)\}/g, function (_, i) {
      const v = args[+i];
      return v == null ? '' : String(v);
    });
  }

  function t(key) {
    const args = Array.prototype.slice.call(arguments, 1);
    const val = get(_dict, key);
    if (val == null) return key;  // fallback — показываем ключ
    return format(val, args);
  }

  function renderAll(root) {
    root = root || document;
    // textContent
    root.querySelectorAll('[data-i18n]').forEach(function (el) {
      const key = el.getAttribute('data-i18n');
      const txt = t(key);
      if (txt !== key) el.textContent = txt;
    });
    // placeholder
    root.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
      const key = el.getAttribute('data-i18n-placeholder');
      const txt = t(key);
      if (txt !== key) el.setAttribute('placeholder', txt);
    });
    // title
    root.querySelectorAll('[data-i18n-title]').forEach(function (el) {
      const key = el.getAttribute('data-i18n-title');
      const txt = t(key);
      if (txt !== key) el.setAttribute('title', txt);
    });
    // alt
    root.querySelectorAll('[data-i18n-alt]').forEach(function (el) {
      const key = el.getAttribute('data-i18n-alt');
      const txt = t(key);
      if (txt !== key) el.setAttribute('alt', txt);
    });
    // value (для submit-buttons и т.п.)
    root.querySelectorAll('[data-i18n-value]').forEach(function (el) {
      const key = el.getAttribute('data-i18n-value');
      const txt = t(key);
      if (txt !== key) el.setAttribute('value', txt);
    });
    // HTML lang attr
    document.documentElement.setAttribute('lang', _lang);
  }

  async function loadDict(lang) {
    try {
      const r = await fetch('/static/i18n/' + lang + '.json', { cache: 'no-cache' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return await r.json();
    } catch (e) {
      console.warn('[i18n] failed to load', lang, e);
      return {};
    }
  }

  async function setLang(lang) {
    if (!SUPPORTED.includes(lang)) lang = DEFAULT_LANG;
    _lang = lang;
    localStorage.setItem(STORAGE_KEY, lang);
    _dict = await loadDict(lang);
    renderAll();
    // Уведомляем подписчиков (например, наш chart-код)
    document.dispatchEvent(new CustomEvent('i18n:changed', { detail: { lang: lang } }));
    // Сохраняем на бэке если юзер залогинен (best-effort)
    try {
      await fetch('/api/user/lang', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ lang: lang })
      });
    } catch (e) { /* silent */ }
  }

  async function init() {
    const lang = detectLang();
    await setLang(lang);
  }

  // Глобальный API
  window.i18n = {
    t: t,
    setLang: setLang,
    getLang: function () { return _lang; },
    renderAll: renderAll,
    supported: SUPPORTED.slice(),
  };
  window.t = t;

  // Авто-инициализация после DOMContentLoaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
