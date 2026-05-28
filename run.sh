#!/usr/bin/env bash
# Crypto Trading Planner — запуск (macOS / Linux)

set -e
cd "$(dirname "$0")"

echo "============================================================"
echo "  Crypto Trading Planner — запуск"
echo "============================================================"
echo

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ОШИБКА] python3 не найден. Установи Python 3.10+."
  exit 1
fi

if [ ! -d ".venv" ]; then
  echo "[setup] Создаю виртуальное окружение..."
  python3 -m venv .venv
  echo "[setup] Устанавливаю зависимости..."
  .venv/bin/python -m pip install --upgrade pip
  .venv/bin/python -m pip install -r requirements.txt
fi

# Открываем браузер через 2 секунды (macOS / Linux)
( sleep 2 && (command -v open >/dev/null && open http://localhost:5000) \
                 || (command -v xdg-open >/dev/null && xdg-open http://localhost:5000) \
                 || true ) &

.venv/bin/python app.py
