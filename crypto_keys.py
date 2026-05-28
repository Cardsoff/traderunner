"""
Pacemaker — Zero-knowledge шифрование API-ключей биржи.

Архитектура:
1. При регистрации генерируется случайный kdf_salt (16 байт), сохраняется в users.kdf_salt
2. Пароль + kdf_salt → Argon2id → encryption_key (32 байта)
3. encryption_key хранится только в Flask session на время сессии
4. API-ключи биржи шифруются Fernet(encryption_key) перед записью в БД
5. При логине: вычисляем encryption_key заново из пароля
6. Если юзер потерял пароль — ключи биржи невозможно восстановить (он введёт заново)

Сервер НИКОГДА не хранит encryption_key в БД — только в активной session.
Даже админ БД не может расшифровать чужие ключи без пароля владельца.
"""
import os
import base64
from argon2.low_level import hash_secret_raw, Type
from cryptography.fernet import Fernet, InvalidToken


# Argon2id параметры (рекомендация OWASP 2024)
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 19 * 1024  # 19 MiB
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32  # 256 бит для Fernet


def generate_salt() -> str:
    """Генерирует случайную соль (16 байт), возвращает base64."""
    return base64.b64encode(os.urandom(16)).decode("ascii")


def derive_encryption_key(password: str, salt_b64: str) -> bytes:
    """
    Выводит 32-байтовый ключ шифрования из пароля юзера + соли через Argon2id.
    Возвращает Fernet-ready ключ (urlsafe base64).
    """
    salt = base64.b64decode(salt_b64)
    raw = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )
    return base64.urlsafe_b64encode(raw)


def encrypt_secret(plaintext: str, fernet_key: bytes) -> str:
    """Шифрует строку (например, API-секрет биржи) → base64 ciphertext."""
    if not plaintext:
        return ""
    f = Fernet(fernet_key)
    return f.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str, fernet_key: bytes) -> str | None:
    """Расшифровывает. Возвращает None если ключ неверный или повреждён."""
    if not ciphertext:
        return ""
    try:
        f = Fernet(fernet_key)
        return f.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


def is_encrypted_key(setting_key: str) -> bool:
    """True для ключей, которые подлежат шифрованию (API-ключи биржи)."""
    return setting_key in {
        "bitunix_api_key",
        "bitunix_api_secret",
        "binance_api_key",
        "binance_api_secret",
        "bybit_api_key",
        "bybit_api_secret",
        "okx_api_key",
        "okx_api_secret",
        "okx_passphrase",
    }


# === Helpers для интеграции с Flask session ===

def session_key_b64(session_dict) -> str | None:
    """Получает encryption_key из Flask session (base64 строка)."""
    return session_dict.get("_pace_ek")


def session_set_key(session_dict, fernet_key: bytes):
    """Сохраняет encryption_key в Flask session (base64 строка)."""
    session_dict["_pace_ek"] = fernet_key.decode("ascii")


def session_get_fernet_key(session_dict) -> bytes | None:
    """Возвращает Fernet-ready ключ из session, или None если юзер не залогинен корректно."""
    k = session_dict.get("_pace_ek")
    return k.encode("ascii") if k else None


def session_clear_key(session_dict):
    """Очищает encryption_key из session (при logout)."""
    session_dict.pop("_pace_ek", None)
