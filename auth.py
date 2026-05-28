"""
Pacemaker — Auth blueprint (регистрация / логин / logout).
"""
from datetime import datetime
from flask import Blueprint, request, render_template, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError

from models import db, User
from crypto_keys import (
    generate_salt, derive_encryption_key,
    session_set_key, session_clear_key,
)

auth_bp = Blueprint("auth", __name__)


# === Регистрация ===

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        name = (request.form.get("name") or "").strip()

        # Валидация
        try:
            v = validate_email(email, check_deliverability=False)
            email = v.normalized
        except EmailNotValidError as e:
            flash(f"Невалидный email: {e}", "error")
            return render_template("auth_register.html", email=email, name=name)

        if len(password) < 8:
            flash("Пароль должен быть минимум 8 символов", "error")
            return render_template("auth_register.html", email=email, name=name)

        if password != password2:
            flash("Пароли не совпадают", "error")
            return render_template("auth_register.html", email=email, name=name)

        # Уникальность
        if User.query.filter_by(email=email).first():
            flash("Этот email уже зарегистрирован", "error")
            return render_template("auth_register.html", email=email, name=name)

        # Создаём юзера
        salt = generate_salt()
        user = User(
            email=email,
            password_hash=generate_password_hash(password),
            kdf_salt=salt,
            display_name=name or email.split("@")[0],
            created_at=datetime.utcnow(),
            last_login_at=datetime.utcnow(),
        )
        db.session.add(user)
        db.session.flush()  # получаем user.id до commit
        new_user_id = user.id
        db.session.commit()
        db.session.refresh(user)

        # Создаём дефолтные данные для нового юзера: цель + setups
        import database as legacy_db
        try:
            legacy_db.ensure_default_goal_for_user(new_user_id)
            legacy_db.ensure_default_setups_for_user(new_user_id)
        except Exception as _e:
            import traceback, sys
            print(f"[register] Ошибка при создании дефолтов для user {new_user_id}: {_e}", file=sys.stderr)
            traceback.print_exc()

        # Сразу логиним и сохраняем encryption_key в session
        ek = derive_encryption_key(password, salt)
        session_set_key(session, ek)
        login_user(user, remember=True)

        flash(f"Добро пожаловать в Pacemaker, {user.display_name}!", "success")
        return redirect(url_for("index"))

    return render_template("auth_register.html")


# === Логин ===

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        remember = bool(request.form.get("remember"))

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Неверный email или пароль", "error")
            return render_template("auth_login.html", email=email)

        # Деривируем encryption_key из пароля
        ek = derive_encryption_key(password, user.kdf_salt)
        session_set_key(session, ek)

        user.last_login_at = datetime.utcnow()
        db.session.commit()

        login_user(user, remember=remember)
        flash(f"С возвращением, {user.display_name}!", "success")

        next_url = request.args.get("next") or url_for("index")
        return redirect(next_url)

    return render_template("auth_login.html")


# === Logout ===

@auth_bp.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    session_clear_key(session)
