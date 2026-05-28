#!/usr/bin/env bash
# Crypto Trading Planner — первоначальная установка (macOS / Linux)

set -e
cd "$(dirname "$0")"

echo "============================================================"
echo "  Crypto Trading Planner v3.1 — первоначальная установка"
echo "============================================================"
echo

# 1. Проверка Python
echo "[1/4] Проверяю Python..."
if ! command -v python3 >/dev/null 2>&1; then
    echo
    echo "[ОШИБКА] python3 не найден."
    echo
    echo "macOS: brew install python"
    echo "Linux: sudo apt install python3 python3-venv"
    echo
    exit 1
fi
python3 --version
echo "  OK"
echo

# 2. Проверка версии 3.10+
echo "[2/4] Проверяю версию Python (нужна 3.10+)..."
if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"; then
    echo "[ОШИБКА] Нужен Python 3.10 или новее."
    exit 1
fi
echo "  OK"
echo

# 3. Виртуальное окружение
echo "[3/4] Создаю виртуальное окружение..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
echo "  OK"
echo

# 4. Зависимости
echo "[4/4] Устанавливаю зависимости (Flask, requests, pytest)..."
.venv/bin/python -m pip install --upgrade pip --quiet
.venv/bin/python -m pip install -r requirements.txt --quiet
echo "  OK"
echo

# 5. config.ini
if [ ! -f "config.ini" ] && [ -f "config.ini.example" ]; then
    cp config.ini.example config.ini
    echo "[info] Создан config.ini. После запуска зайди в 'Bitunix · не настроен'"
    echo "       в шапке и впиши свои API-ключи."
    echo
fi

echo "============================================================"
echo "  УСТАНОВКА ЗАВЕРШЕНА"
echo "============================================================"
echo
echo "Запусти приложение: ./run.sh"
echo "Приложение откроется в браузере на http://localhost:5000"
