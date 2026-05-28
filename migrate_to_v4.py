"""
Pacemaker v4.0 — Миграция с v3.2 (single-user) на v4.0 (multi-tenant).

Что делает:
1. Создаёт таблицу users
2. Создаёт пользователя #1 для Артёма (email указывается при запуске)
3. Добавляет колонку user_id во все существующие таблицы
4. Привязывает все существующие данные к user_id=1
5. Переносит settings (key,value) → user_settings (user_id, key, value)
6. API-ключи биржи НЕ шифруются автоматически (юзер их перевведёт при первом логине)

Безопасно запускается несколько раз (idempotent).
"""
import sqlite3
import sys
import os
from datetime import datetime
from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get("PACEMAKER_DB", "planner.db")


def column_exists(cur, table, col):
    cur.execute(f"PRAGMA table_info({table})")
    return any(r[1] == col for r in cur.fetchall())


def table_exists(cur, table):
    cur.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
    return cur.fetchone() is not None


def migrate(admin_email: str, admin_password: str, admin_name: str = "Артём"):
    print(f"📂 БД: {DB_PATH}")
    print(f"👤 Создаём admin: {admin_email}")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = ON")

    # --- 1. Таблица users ---
    if not table_exists(cur, "users"):
        from crypto_keys import generate_salt
        salt = generate_salt()
        pwd_hash = generate_password_hash(admin_password)
        cur.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                kdf_salt TEXT NOT NULL,
                display_name TEXT,
                created_at TEXT NOT NULL,
                last_login_at TEXT,
                is_admin INTEGER NOT NULL DEFAULT 0
            )
        """)
        cur.execute("CREATE UNIQUE INDEX idx_users_email ON users(email)")
        cur.execute("""
            INSERT INTO users (id, email, password_hash, kdf_salt, display_name, created_at, is_admin)
            VALUES (1, ?, ?, ?, ?, ?, 1)
        """, (admin_email, pwd_hash, salt, admin_name, datetime.utcnow().isoformat()))
        print(f"  ✅ Создан users + Артём (id=1)")
    else:
        print(f"  ⏩ Таблица users уже существует")

    # --- 2. Добавить user_id в существующие таблицы ---
    tables_with_user = ["trades", "deposits", "equity_snapshots", "goals", "audit_log"]
    for tbl in tables_with_user:
        if not table_exists(cur, tbl):
            print(f"  ⚠ Таблица {tbl} не существует — пропускаю")
            continue
        if column_exists(cur, tbl, "user_id"):
            print(f"  ⏩ {tbl}.user_id уже существует")
            continue
        cur.execute(f"ALTER TABLE {tbl} ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1")
        cur.execute(f"CREATE INDEX IF NOT EXISTS idx_{tbl}_user ON {tbl}(user_id)")
        print(f"  ✅ Добавлен user_id в {tbl}")

    # --- 3. Перенос setups (PRIMARY KEY name → id + user_id + name) ---
    if table_exists(cur, "setups"):
        cur.execute("PRAGMA table_info(setups)")
        cols = {r[1]: r for r in cur.fetchall()}
        if "id" not in cols:
            print("  🔄 Переношу setups (PK name → id+user_id+name)")
            cur.execute("ALTER TABLE setups RENAME TO setups_old")
            cur.execute("""
                CREATE TABLE setups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL DEFAULT 1,
                    name TEXT NOT NULL,
                    UNIQUE(user_id, name)
                )
            """)
            cur.execute("CREATE INDEX idx_setups_user ON setups(user_id)")
            cur.execute("INSERT INTO setups (user_id, name) SELECT 1, name FROM setups_old")
            cur.execute("DROP TABLE setups_old")
            print(f"  ✅ Перенесено setups")
        else:
            print(f"  ⏩ setups уже multi-tenant")

    # --- 4. Перенос settings → user_settings ---
    if not table_exists(cur, "user_settings"):
        cur.execute("""
            CREATE TABLE user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                UNIQUE(user_id, key)
            )
        """)
        cur.execute("CREATE INDEX idx_user_settings_user ON user_settings(user_id)")
        # Переносим старые settings → user_settings под user_id=1
        if table_exists(cur, "settings"):
            cur.execute("SELECT key, value FROM settings")
            old_settings = cur.fetchall()
            for k, v in old_settings:
                # API-ключи биржи НЕ переносим — юзер перевведёт через UI чтобы зашифровать
                if k in ("bitunix_api_key", "bitunix_api_secret"):
                    print(f"  ⚠ Пропускаю {k} — Артём перевведёт через UI чтобы зашифровать")
                    continue
                cur.execute("INSERT OR REPLACE INTO user_settings (user_id, key, value) VALUES (1, ?, ?)", (k, v))
            print(f"  ✅ Перенесено {len(old_settings)} settings → user_settings")
            # Оставляем старую settings для глобальных параметров (flask_secret_key)
        print(f"  ✅ Создано user_settings")
    else:
        print(f"  ⏩ user_settings уже существует")

    # --- 5. Таблица share_links ---
    if not table_exists(cur, "share_links"):
        cur.execute("""
            CREATE TABLE share_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                mask_amounts INTEGER NOT NULL DEFAULT 1,
                revoked INTEGER NOT NULL DEFAULT 0
            )
        """)
        cur.execute("CREATE INDEX idx_share_user ON share_links(user_id)")
        cur.execute("CREATE INDEX idx_share_token ON share_links(token)")
        print(f"  ✅ Создано share_links")

    conn.commit()

    # --- 6. Итоговая статистика ---
    print("\n📊 Состояние после миграции:")
    for tbl in ["users", "trades", "deposits", "equity_snapshots", "goals", "setups", "user_settings", "audit_log", "share_links"]:
        if table_exists(cur, tbl):
            cur.execute(f"SELECT COUNT(*) FROM {tbl}")
            print(f"  {tbl}: {cur.fetchone()[0]}")

    conn.close()
    print("\n✅ Миграция завершена!")


if __name__ == "__main__":
    import getpass

    if len(sys.argv) < 2:
        print("Использование: python migrate_to_v4.py <email> [display_name]")
        print("Пример: python migrate_to_v4.py human.artem@icloud.com Артём")
        print("Пароль будет запрошен интерактивно (не отображается в терминале).")
        sys.exit(1)

    email = sys.argv[1]
    name = sys.argv[2] if len(sys.argv) > 2 else "Артём"

    print(f"\n🔑 Придумай пароль для входа в Pacemaker (минимум 8 символов).")
    print(f"   Из пароля выводится ключ шифрования API-ключей биржи.")
    print(f"   ⚠️  Запомни/сохрани в менеджер паролей — забудешь = API-ключи биржи придётся вводить заново!\n")

    while True:
        password = getpass.getpass("Пароль: ")
        if len(password) < 8:
            print("❌ Минимум 8 символов. Попробуй ещё раз.\n")
            continue
        password2 = getpass.getpass("Пароль ещё раз: ")
        if password != password2:
            print("❌ Пароли не совпадают. Попробуй ещё раз.\n")
            continue
        break

    print()
    migrate(email, password, name)
