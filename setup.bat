@echo off
chcp 65001 >nul
title Crypto Trading Planner — установка

echo ============================================================
echo   Crypto Trading Planner v3.1 — первоначальная установка
echo ============================================================
echo.

REM === 1. Проверка Python ===
echo [1/4] Проверяю Python...
where python >nul 2>nul
if errorlevel 1 (
    echo.
    echo [ОШИБКА] Python не найден.
    echo.
    echo Скачай и установи Python 3.10+ с https://www.python.org/downloads/
    echo ВАЖНО: при установке поставь галочку "Add Python to PATH"
    echo.
    echo После установки запусти этот файл (setup.bat) ещё раз.
    echo.
    pause
    start https://www.python.org/downloads/
    exit /b 1
)
python --version
echo   OK
echo.

REM === 2. Проверка версии Python (3.10+) ===
echo [2/4] Проверяю версию Python (нужна 3.10+)...
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 (
    echo.
    echo [ОШИБКА] У тебя слишком старый Python. Нужен 3.10 или новее.
    echo Обнови с https://www.python.org/downloads/
    pause
    exit /b 1
)
echo   OK
echo.

REM === 3. Создание виртуального окружения ===
echo [3/4] Создаю виртуальное окружение...
if exist ".venv\Scripts\python.exe" (
    echo   .venv уже существует, пропускаю.
) else (
    python -m venv .venv
    if errorlevel 1 (
        echo [ОШИБКА] Не получилось создать .venv
        pause
        exit /b 1
    )
    echo   OK
)
echo.

REM === 4. Установка зависимостей ===
echo [4/4] Устанавливаю зависимости (Flask, requests, pytest)...
.venv\Scripts\python.exe -m pip install --upgrade pip --quiet
.venv\Scripts\python.exe -m pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [ОШИБКА] Не удалось установить зависимости.
    echo Проверь подключение к интернету и запусти setup.bat ещё раз.
    pause
    exit /b 1
)
echo   OK
echo.

REM === 5. Создание config.ini если нет ===
if not exist "config.ini" (
    if exist "config.ini.example" (
        copy "config.ini.example" "config.ini" >nul
        echo [info] Создан config.ini ^(из примера^). После запуска приложения зайди
        echo        в "Bitunix · не настроен" в шапке и впиши свои API-ключи.
        echo.
    )
)

echo ============================================================
echo   УСТАНОВКА ЗАВЕРШЕНА
echo ============================================================
echo.
echo Запусти приложение двойным кликом по run.bat
echo Приложение откроется в браузере на http://localhost:5000
echo.
pause
