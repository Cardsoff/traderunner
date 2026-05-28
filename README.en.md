# Pacemaker

> **Keep the pace. Reach your goal.**
> An open-source crypto trading journal with zero-knowledge encryption.
> Self-host locally or deploy as a multi-user SaaS.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## Features

- 📊 **Smart goal tracking** — set a target capital, get a forecasted date based on your monthly return rate and contributions
- 📈 **30+ trader metrics** — Sharpe, Sortino, Calmar, Profit Factor, R-Reward, Expectancy, holding time, streak distribution, equity curve with underwater plot, hour-of-day and day-of-week heatmaps
- 🔌 **Bitunix Futures integration** — auto-syncs your closed trades, open positions, equity snapshots
- 🔐 **Zero-knowledge encryption** — exchange API keys are encrypted with a key derived from your password via Argon2id. Even the server admin can't read them.
- 🏠 **Multi-tenant** — every user is fully isolated at the database level. Run it as a SaaS for your community.
- 🚀 **One-click deploy** to Railway or any Postgres-capable host

## Quick start (local)

```bash
git clone https://github.com/YOUR_USERNAME/pacemaker.git
cd pacemaker
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`, register, and connect your Bitunix API key.

**Windows users:** double-click `ЗАПУСТИ_МЕНЯ_Pacemaker.bat` — it handles venv + install + launch.

## Deploy to Railway

1. Fork this repo
2. Create a new project on [railway.app](https://railway.app), connect your fork
3. Add a PostgreSQL service (Railway auto-injects `DATABASE_URL`)
4. Set `FLASK_SECRET_KEY` (any 32+ char random string) as an env var
5. Deploy. Done.

See `.env.example` for all environment variables.

## Architecture

| Layer | Tech |
|---|---|
| Backend | Flask 3 + Flask-Login + SQLAlchemy 2 |
| Database | SQLite (local) or PostgreSQL (prod) |
| Frontend | Vanilla JS + Chart.js (no build step) |
| Crypto | Argon2id + Fernet (cryptography lib) |
| Server | Gunicorn (prod) |

## Security

See [SECURITY.md](SECURITY.md) for our security model, threat model, and how to report vulnerabilities.

**Why AGPL?** If you fork Pacemaker and run it as a service, you must open-source your modifications. This protects the community from closed-source commercial forks while keeping the code free for personal use.

## Roadmap

- [ ] Telegram bot for goal/MDD/streak alerts
- [ ] Multi-exchange: Binance, Bybit, OKX, Bitget
- [ ] Read-only sharing links (with amount masking — already in v4.0)
- [ ] Mobile-first redesign
- [ ] OAuth: Google / Apple sign-in

## License

[AGPL-3.0](LICENSE) — see LICENSE for full text.

## Acknowledgments

Built for traders by a trader. If Pacemaker helps you stay disciplined and reach your goal, consider starring the repo ⭐ or [sponsoring](https://github.com/sponsors/YOUR_USERNAME).
