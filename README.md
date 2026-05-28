# Pacemaker v4.0 — Multi-tenant SaaS-ready (2026-05-28)

**«Держи темп. Дойди до цели»** — журнал и аналитика крипто-сделок с биржи Bitunix.

Может работать локально (Flask + SQLite, как раньше) или быть задеплоен на сайт (Railway/Render + PostgreSQL) как мульти-пользовательский сервис.

**Что нового в v4.0:**
- 👥 **Multi-tenant**: каждый пользователь видит только свои данные (физическая изоляция на уровне БД)
- 🔐 **Zero-knowledge шифрование API-ключей биржи** через Argon2id + Fernet
- 🚪 Регистрация / логин / logout (Flask-Login)
- 🗄 **SQLAlchemy ORM** — готовность к PostgreSQL для прода
- 🌐 Готовность к деплою на Railway (Procfile + .env + auto Postgres URL)

---

## 🚀 Быстрый старт (локально)

### 1. Установи Python 3.10+

- **Windows:** [python.org](https://www.python.org/downloads/) → при установке поставь галочку **«Add Python to PATH»**
- **macOS:** `brew install python`
- **Linux:** `sudo apt install python3 python3-venv`

### 2. Запусти

- **Windows:** двойной клик по **`ЗАПУСТИ_МЕНЯ_Pacemaker.bat`**
- **macOS/Linux:** `./run.sh`

Браузер откроется на `http://localhost:5000/login`.

### 3. Зарегистрируйся или войди

- Если первый раз — `Зарегистрироваться` → email + пароль (8+ символов)
- Если уже мигрировал с v3.2 — войди со своими данными

### 4. Подключи биржу

- Нажми pill **«Bitunix · не настроен»** в шапке → введи API Key + Secret → Сохранить
- Жми **Sync** — подтянутся сделки

---

## 🌐 Деплой на Railway (production)

### 1. Создай проект на Railway.app
- Connect GitHub repo (или загрузи zip)
- Add PostgreSQL service (Railway сам создаст `DATABASE_URL`)

### 2. Переменные окружения
- `FLASK_SECRET_KEY` — сгенерится автоматически при первом старте, но лучше задать вручную
- `DATABASE_URL` — Railway проставит из Postgres
- `PORT` — Railway проставит автоматически (для gunicorn)

### 3. Деплой запустит `Procfile`:
```
web: gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 60
```

### 4. Подключи домен (опционально)
- Railway даёт `*.up.railway.app` бесплатно
- Свой домен — через `cryptoplanner.app` (Namecheap, Porkbun) → CNAME

**Цена:** ~$5/мес Postgres + бесплатный hobby tier для веб-приложения.

---

## 🔐 Безопасность (что важно для крипты)

### Zero-knowledge шифрование
- Пароль юзера → Argon2id (с уникальной солью) → encryption_key (32 байта)
- API-ключи биржи шифруются Fernet перед сохранением в БД
- На сервере в открытом виде ключи НЕ хранятся
- Если пароль забыт — расшифровать ключи невозможно (придётся ввести заново)

### Изоляция данных
- Все таблицы имеют колонку `user_id`
- Каждый запрос фильтруется по `user_id` залогиненного юзера
- Юзер A физически не может прочитать данные юзера B

### Защита от атак
- CSRF: проверка Origin/Referer + per-session токен
- Rate-limit на /api/sync (1 в 30 сек)
- @login_required на всех `/api/*` endpoints
- Audit log изменений в settings/goals/trades
- Логи с rotation в `logs/app.log`

---

## 📁 Структура

```
Pacemaker/
├── app.py                       # Flask + endpoints (2400+ строк)
├── models.py                    # SQLAlchemy ORM модели
├── database.py                  # Legacy sqlite функции (per-user)
├── auth.py                      # Blueprint регистрации/логина
├── crypto_keys.py               # Zero-knowledge шифрование
├── bitunix_client.py            # API клиент Bitunix
├── migrate_to_v4.py             # Миграция v3.2 → v4.0
├── templates/
│   ├── index.html               # Главный дашборд
│   ├── auth_layout.html         # Базовый шаблон auth
│   ├── auth_login.html
│   └── auth_register.html
├── static/
│   ├── app.js
│   └── style.css
├── tests/                       # pytest
├── requirements.txt
├── Procfile                     # Для Railway/Render
├── runtime.txt                  # python-3.12.4
├── .env.example                 # Шаблон env переменных
├── .gitignore
├── setup.bat/sh                 # Локальная установка venv
├── run.bat/sh                   # Локальный запуск
└── ЗАПУСТИ_МЕНЯ_Pacemaker.bat   # Полный цикл: установка + запуск
```

---

## 🛣 Roadmap

**v4.1 (в работе):**
- Подключить домен и задеплоить на Railway
- Telegram-бот для алертов (опционально)
- Logout-кнопка в UI (✅ уже есть)
- Change-password endpoint с переzашифровкой ключей

**v4.2+:**
- Multi-exchange: Binance, Bybit, OKX
- Telegram Mini App (если будет тяга от пользователей)
- Tiered subscriptions (free + paid)
- Email verification + password reset

---

## 🆘 Что-то не работает?

1. **Не запускается** — проверь Python 3.10+ установлен. На Windows запусти `ЗАПУСТИ_МЕНЯ_Pacemaker.bat`
2. **Не могу войти** — пароль чувствителен к регистру. Если забыл — увы, придётся регистрировать новый аккаунт (zero-knowledge architecture)
3. **API-ключи биржи не работают** — после логина введи их заново через UI. Они зашифруются твоим паролем.
4. **«Войди чтобы продолжить»** — кука сессии истекла. Жми Login.

---

**Автор:** собрано для Артёма
**Версия:** v4.0 · 2026-05-28
**Брендинг:** Pacemaker · «Держи темп. Дойди до цели»
