"""
Pacemaker v4.0 — SQLAlchemy модели.

Multi-tenant: каждая таблица имеет user_id, физическая изоляция данных.
Совместимо с SQLite (локально) и PostgreSQL (продакшн).
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import (
    Column, Integer, String, Float, Text, DateTime, Boolean,
    ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship

db = SQLAlchemy()


class User(db.Model, UserMixin):
    """Пользователь Pacemaker. Email + пароль = логин."""
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True)
    email         = Column(String(254), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    kdf_salt      = Column(String(64), nullable=False)  # для KDF шифрования API-ключей
    display_name  = Column(String(100))
    created_at    = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login_at = Column(DateTime)
    is_admin      = Column(Boolean, default=False, nullable=False)

    # Связи
    trades       = relationship("Trade", backref="user", cascade="all, delete-orphan")
    deposits     = relationship("Deposit", backref="user", cascade="all, delete-orphan")
    goals        = relationship("Goal", backref="user", cascade="all, delete-orphan")
    setups       = relationship("Setup", backref="user", cascade="all, delete-orphan")
    settings     = relationship("UserSetting", backref="user", cascade="all, delete-orphan")
    equity_snaps = relationship("EquitySnapshot", backref="user", cascade="all, delete-orphan")
    audit_logs   = relationship("AuditLog", backref="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User #{self.id} {self.email}>"


class UserSetting(db.Model):
    """Настройки пользователя (key-value). Включает зашифрованные API-ключи биржи."""
    __tablename__ = "user_settings"

    id      = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    key     = Column(String(100), nullable=False)
    value   = Column(Text, nullable=False)  # для encrypted_* — base64 ciphertext

    __table_args__ = (UniqueConstraint("user_id", "key", name="uix_user_setting"),)


class Trade(db.Model):
    """Сделка пользователя."""
    __tablename__ = "trades"

    id          = Column(Integer, primary_key=True)
    user_id     = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    external_id = Column(String(100))  # ID с биржи (unique per user, не глобально)
    ts          = Column(String(30), nullable=False, index=True)  # ISO datetime
    symbol      = Column(String(50), nullable=False, index=True)
    side        = Column(String(10), nullable=False, index=True)
    setup       = Column(String(100), index=True)
    entry_price = Column(Float)
    exit_price  = Column(Float)
    qty         = Column(Float)
    pnl_usd     = Column(Float, nullable=False, default=0)
    pnl_pct     = Column(Float, nullable=False, default=0)
    fee_usd     = Column(Float, nullable=False, default=0)
    funding_usd = Column(Float, nullable=False, default=0)
    note        = Column(Text, default="")
    source      = Column(String(30), nullable=False, default="manual")

    __table_args__ = (
        UniqueConstraint("user_id", "external_id", name="uix_user_external"),
    )


class Deposit(db.Model):
    """Депозит / вывод пользователя."""
    __tablename__ = "deposits"

    id          = Column(Integer, primary_key=True)
    user_id     = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    external_id = Column(String(100))
    ts          = Column(String(30), nullable=False, index=True)
    kind        = Column(String(20), nullable=False)  # deposit / withdrawal
    amount_usd  = Column(Float, nullable=False)
    note        = Column(Text, default="")
    source      = Column(String(30), nullable=False, default="manual")

    __table_args__ = (
        UniqueConstraint("user_id", "external_id", name="uix_dep_user_external"),
    )


class EquitySnapshot(db.Model):
    """Снимок equity для построения equity curve."""
    __tablename__ = "equity_snapshots"

    id         = Column(Integer, primary_key=True)
    user_id    = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    ts         = Column(String(30), nullable=False, index=True)
    equity_usd = Column(Float, nullable=False)
    source     = Column(String(30), nullable=False, default="manual")


class Goal(db.Model):
    """Финансовая цель пользователя."""
    __tablename__ = "goals"

    id                 = Column(Integer, primary_key=True)
    user_id            = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name               = Column(String(200))
    amount             = Column(Float, nullable=False)
    monthly_return_pct = Column(Float, nullable=False, default=10)
    monthly_deposit    = Column(Float, nullable=False, default=0)
    created_at         = Column(String(30), nullable=False)
    achieved_at        = Column(String(30))
    is_active          = Column(Integer, nullable=False, default=1)


class Setup(db.Model):
    """Торговый сетап пользователя (FVG, OB, breakout...)."""
    __tablename__ = "setups"

    id      = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name    = Column(String(100), nullable=False)

    __table_args__ = (UniqueConstraint("user_id", "name", name="uix_setup_user_name"),)


class AuditLog(db.Model):
    """Аудит-лог изменений (что юзер менял в settings/goals/trades)."""
    __tablename__ = "audit_log"

    id        = Column(Integer, primary_key=True)
    user_id   = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    ts        = Column(String(30), nullable=False, index=True)
    action    = Column(String(50), nullable=False)
    entity    = Column(String(50))
    entity_id = Column(String(100))
    payload   = Column(Text)


class ShareLink(db.Model):
    """Sharing-ссылки read-only с маскировкой сумм."""
    __tablename__ = "share_links"

    id         = Column(Integer, primary_key=True)
    user_id    = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token      = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    mask_amounts = Column(Boolean, default=True, nullable=False)
    revoked    = Column(Boolean, default=False, nullable=False)


# Индексы для производительности
Index("idx_trades_user_ts", Trade.user_id, Trade.ts)
Index("idx_deposits_user_ts", Deposit.user_id, Deposit.ts)
Index("idx_equity_user_ts", EquitySnapshot.user_id, EquitySnapshot.ts)
Index("idx_audit_user_ts", AuditLog.user_id, AuditLog.ts)
