#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
BESS & SOLAR CALCULATOR — BACKEND API SERVER (ЕТАП 1: СЕРВЕРНА АРХІТЕКТУРА)
===============================================================================
Технологічний стек: Python 3.11 + FastAPI + SQLite3 + Node.js 8760 Calc Engine
Призначення:
1. Захист інтелектуальної власності: математичне ядро 8 760 годин (calc_engine.js)
   виконується виключно на сервері через закритий ендпоінт POST /api/calculate.
2. Реєстрація та авторизація (JWT) з обов'язковою модерацією адміністратором:
   нові заявки отримують статус 'pending' до підтвердження власником.
3. Особистий кабінет фахівця:
   - Профіль: Ім'я, По батькові, Прізвище, Пошта, Номер телефону, Спеціальність,
     Посада, Компанія, Адреса офісу, Реквізити компанії (для фірмового бланку).
   - Збережені розрахунки (CRUD + клонування проєктів у базі даних).
4. Панель керування адміністратора (Admin API):
   - Підтвердження реєстрації нових користувачів ('pending' -> 'approved')
   - Миттєве блокування / розблокування доступу ('blocked')
   - Керування підписками (тарифний план, термін дії, ліміт розрахунків)
===============================================================================
Запуск сервера:
    uvicorn bess_backend_server:app --host 0.0.0.0 --port 8000 --reload
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, EmailStr, Field

# -----------------------------------------------------------------------------
# КОНФІГУРАЦІЯ СЕРВЕРА ТА ШЛЯХІВ
# -----------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
_default_db_dir = Path("/tmp") if str(BASE_DIR).startswith("/working_dir") else BASE_DIR
DB_PATH = Path(os.environ.get("BESS_DB_PATH", str(_default_db_dir / "bess_saas_platform.db")))
CALC_ENGINE_PATH = BASE_DIR / "calc_engine.js"
FRONTEND_HTML_PATH = BASE_DIR / "bess_calculator.html"

JWT_SECRET_KEY = os.environ.get(
    "BESS_JWT_SECRET",
    "bess_solar_ukraine_enterprise_secret_key_2026_v1_change_in_prod"
)
JWT_EXPIRE_HOURS = 24 * 7  # 7 діб

DEFAULT_ADMIN_EMAIL = os.environ.get("BESS_ADMIN_EMAIL", "admin@solar-bess.com.ua")
DEFAULT_ADMIN_PASSWORD = os.environ.get("BESS_ADMIN_PASSWORD", "AdminBess2026!")

app = FastAPI(
    title="BESS & Solar Calculator SaaS API",
    description=(
        "Захищений серверний бекенд калькулятора окупності СЕС та BESS (8 760 год), "
        "Особистого кабінету інженера, системи підписок та Панелі керування адміністратора."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# КРИПТОГРАФІЯ: ХЕШУВАННЯ ПАРОЛІВ (PBKDF2-SHA256) ТА JWT-ТОКЕНИ (HMAC-SHA256)
# -----------------------------------------------------------------------------
def hash_password(password: str, salt: Optional[str] = None) -> str:
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120_000,
    )
    return f"pbkdf2_sha256$120000${salt}${dk.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    try:
        algo, iterations_str, salt, hex_digest = stored_hash.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt.encode("utf-8"),
            int(iterations_str),
        )
        return hmac.compare_digest(dk.hex(), hex_digest)
    except Exception:
        return False


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_jwt_token(user_id: int, email: str, role: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "iat": now_ts,
        "exp": now_ts + JWT_EXPIRE_HOURS * 3600,
    }
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(JWT_SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


def decode_jwt_token(token: str) -> Dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Невірний формат токена")
        h_b64, p_b64, s_b64 = parts
        signing_input = f"{h_b64}.{p_b64}".encode("ascii")
        expected_sig = hmac.new(
            JWT_SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256
        ).digest()
        actual_sig = _b64url_decode(s_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            raise ValueError("Невірний підпис токена")
        payload = json.loads(_b64url_decode(p_b64).decode("utf-8"))
        now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        if payload.get("exp", 0) < now_ts:
            raise ValueError("Термін дії сесії закінчився")
        return payload
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Помилка авторизації: {str(exc)}",
        )


# -----------------------------------------------------------------------------
# ІНІЦІАЛІЗАЦІЯ ТА СХЕМА БАЗИ ДАНИХ (SQLite3)
# -----------------------------------------------------------------------------
def get_db_connection() -> sqlite3.Connection:
    global DB_PATH
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("PRAGMA journal_mode = MEMORY;")
        conn.execute("PRAGMA foreign_keys = ON;")
    except sqlite3.OperationalError:
        DB_PATH = Path("/tmp/bess_saas_platform.db")
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db_connection()
    with conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                patronymic TEXT NOT NULL DEFAULT '',
                last_name TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL UNIQUE,
                phone TEXT NOT NULL DEFAULT '',
                specialty TEXT NOT NULL DEFAULT '',
                position TEXT NOT NULL DEFAULT '',
                company_name TEXT NOT NULL DEFAULT '',
                office_address TEXT NOT NULL DEFAULT '',
                company_requisites TEXT NOT NULL DEFAULT '',
                letterhead_logo TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',           -- 'user' | 'admin'
                status TEXT NOT NULL DEFAULT 'pending',      -- 'pending' | 'approved' | 'blocked'
                subscription_plan TEXT NOT NULL DEFAULT 'trial', -- 'none' | 'trial' | 'pro_monthly' | 'enterprise_yearly'
                subscription_expires_at TEXT NOT NULL DEFAULT '',
                monthly_calc_limit INTEGER NOT NULL DEFAULT 50,  -- -1 = безліміт
                calcs_used_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                project_title TEXT NOT NULL,
                client_company TEXT NOT NULL DEFAULT '',
                client_address TEXT NOT NULL DEFAULT '',
                client_contact TEXT NOT NULL DEFAULT '',
                client_phone TEXT NOT NULL DEFAULT '',
                project_mode TEXT NOT NULL DEFAULT 'solar_bess',
                voltage_kv INTEGER NOT NULL DEFAULT 10,
                state_json TEXT NOT NULL,
                summary_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_user_id INTEGER,
                target_user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            """
        )

        # Створення дефолтного адміністратора, якщо він ще не існує
        cur = conn.execute(
            "SELECT id FROM users WHERE lower(email) = lower(?)",
            (DEFAULT_ADMIN_EMAIL,),
        )
        if not cur.fetchone():
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            exp_iso = (
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=3650)
            ).isoformat()
            conn.execute(
                """
                INSERT INTO users (
                    first_name, patronymic, last_name, email, phone,
                    specialty, position, company_name, office_address,
                    company_requisites, password_hash, role, status,
                    subscription_plan, subscription_expires_at,
                    monthly_calc_limit, calcs_used_count, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "Олександр",
                    "Володимирович",
                    "Бондаренко",
                    DEFAULT_ADMIN_EMAIL.lower(),
                    "+380 (67) 550-88-99",
                    "Проєктування промислових СЕС та УЗЕ (BESS)",
                    "Головний інженер проєктів / Власник платформи",
                    "ТОВ «Солар Енерджі Інжиніринг»",
                    "м. Київ, вул. Ділова, 5, БЦ «Прайм», оф. 402",
                    "ЄДРПОУ 44125890 • ІПН 441258926554 • IBAN UA213223130000026007233566001",
                    hash_password(DEFAULT_ADMIN_PASSWORD),
                    "admin",
                    "approved",
                    "enterprise_yearly",
                    exp_iso,
                    -1,
                    0,
                    now_iso,
                    now_iso,
                ),
            )
    conn.close()


init_db()


# -----------------------------------------------------------------------------
# PYDANTIC МОДЕЛІ ЗАПИТІВ ТА ВІДПОВІДЕЙ
# -----------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    first_name: str = Field(..., min_length=2, description="Ім'я")
    patronymic: str = Field(..., min_length=2, description="По батькові")
    last_name: str = Field(default="", description="Прізвище (опційно)")
    email: str = Field(..., min_length=5, description="Електронна пошта")
    phone: str = Field(..., min_length=6, description="Номер телефону")
    specialty: str = Field(..., min_length=2, description="Спеціальність / напрям")
    position: str = Field(..., min_length=2, description="Посада")
    company_name: str = Field(default="", description="Назва компанії")
    office_address: str = Field(default="", description="Адреса офісу")
    company_requisites: str = Field(default="", description="Реквізити компанії")
    password: str = Field(..., min_length=6, description="Пароль для входу")


class LoginRequest(BaseModel):
    email: str
    password: str


class ProfileUpdateRequest(BaseModel):
    first_name: Optional[str] = None
    patronymic: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    specialty: Optional[str] = None
    position: Optional[str] = None
    company_name: Optional[str] = None
    office_address: Optional[str] = None
    company_requisites: Optional[str] = None
    letterhead_logo: Optional[str] = None


class ProjectSaveRequest(BaseModel):
    project_title: Optional[str] = None
    state: Dict[str, Any]


class AdminStatusUpdateRequest(BaseModel):
    status: str = Field(..., description="'approved' | 'blocked' | 'pending'")
    reason: Optional[str] = ""


class AdminSubscriptionUpdateRequest(BaseModel):
    subscription_plan: str = Field(
        ..., description="'none' | 'trial' | 'pro_monthly' | 'enterprise_yearly'"
    )
    days_valid: int = Field(default=30, ge=0, le=3650)
    monthly_calc_limit: int = Field(default=100, description="-1 для безліміту")
    reset_used_counter: bool = Field(default=False)


# -----------------------------------------------------------------------------
# ДОПОМІЖНІ ФУНКЦІЇ АВТОРИЗАЦІЇ, ПЕРЕВІРКИ ПІДПИСКИ ТА ВИКЛИКУ ЯДРА
# -----------------------------------------------------------------------------
def format_user_row(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d.pop("password_hash", None)
    full_name_parts = [d.get("last_name", ""), d.get("first_name", ""), d.get("patronymic", "")]
    d["full_name"] = " ".join(p for p in full_name_parts if p.strip()).strip()
    d["display_name_patronymic"] = f"{d.get('first_name', '')} {d.get('patronymic', '')}".strip()

    # Перевірка активності підписки
    exp_str = d.get("subscription_expires_at") or ""
    is_sub_active = False
    days_left = 0
    if exp_str:
        try:
            exp_dt = datetime.datetime.fromisoformat(exp_str)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=datetime.timezone.utc)
            now_dt = datetime.datetime.now(datetime.timezone.utc)
            delta = exp_dt - now_dt
            days_left = max(0, delta.days)
            is_sub_active = delta.total_seconds() > 0 and d.get("subscription_plan") != "none"
        except Exception:
            is_sub_active = False
    d["is_subscription_active"] = is_sub_active
    d["subscription_days_left"] = days_left
    return d


def get_current_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Необхідна авторизація (відсутній Bearer токен).",
        )
    token = authorization.split(" ", 1)[1].strip()
    payload = decode_jwt_token(token)
    user_id = payload.get("sub")

    conn = get_db_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Користувача не знайдено в системі.",
        )
    user = format_user_row(row)
    if user["status"] == "blocked":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ваш обліковий запис заблоковано адміністратором.",
        )
    if user["status"] == "pending":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ваш обліковий запис очікує підтвердження реєстрації адміністратором.",
        )
    return user


def get_admin_user(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ дозволено лише адміністратору платформи.",
        )
    return current_user


def enforce_subscription_quota(user: Dict[str, Any]) -> None:
    if user.get("role") == "admin":
        return
    if not user.get("is_subscription_active"):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Термін дії вашої підписки закінчився або тариф не активовано. Зверніться до адміністратора.",
        )
    limit = int(user.get("monthly_calc_limit", 0))
    used = int(user.get("calcs_used_count", 0))
    if limit >= 0 and used >= limit:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"Вичерпано ліміт розрахунків за вашим тарифом ({used}/{limit}). Оновіть підписку.",
        )


def run_server_8760_calculation(state_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Викликає захищене серверне математичне ядро calc_engine.js у дочірньому процесі Node.js.
    Клієнт ніколи не бачить вихідного коду формул чи бази 8 760 годин.
    """
    if not CALC_ENGINE_PATH.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Серверний модуль розрахунку calc_engine.js не знайдено.",
        )
    proc = subprocess.run(
        ["node", str(CALC_ENGINE_PATH)],
        input=json.dumps(state_payload, ensure_ascii=False),
        text=True,
        capture_output=True,
        timeout=15,
    )
    if proc.returncode != 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Помилка серверного ядра розрахунку: {proc.stderr or proc.stdout}",
        )
    return json.loads(proc.stdout)


# -----------------------------------------------------------------------------
# 1. ЕНДПОІНТИ АВТЕНТИФІКАЦІЇ ТА РЕЄСТРАЦІЇ (/api/auth/...)
# -----------------------------------------------------------------------------
@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register_user(req: RegisterRequest) -> Dict[str, Any]:
    email_clean = req.email.strip().lower()
    conn = get_db_connection()
    existing = conn.execute(
        "SELECT id FROM users WHERE lower(email) = ?", (email_clean,)
    ).fetchone()
    if existing:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Користувач із такою електронною поштою вже зареєстрований.",
        )

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # За замовчуванням надається 14-денний пробний період, але статус 'pending' (чекає підтвердження адміном)
    trial_exp = (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=14)
    ).isoformat()

    with conn:
        cur = conn.execute(
            """
            INSERT INTO users (
                first_name, patronymic, last_name, email, phone,
                specialty, position, company_name, office_address,
                company_requisites, password_hash, role, status,
                subscription_plan, subscription_expires_at,
                monthly_calc_limit, calcs_used_count, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'user', 'pending', 'trial', ?, 50, 0, ?, ?)
            """,
            (
                req.first_name.strip(),
                req.patronymic.strip(),
                req.last_name.strip(),
                email_clean,
                req.phone.strip(),
                req.specialty.strip(),
                req.position.strip(),
                req.company_name.strip(),
                req.office_address.strip(),
                req.company_requisites.strip(),
                hash_password(req.password),
                trial_exp,
                now_iso,
                now_iso,
            ),
        )
        new_user_id = cur.lastrowid
        conn.execute(
            """
            INSERT INTO audit_logs (actor_user_id, target_user_id, action, details, created_at)
            VALUES (?, ?, 'USER_REGISTERED_PENDING', ?, ?)
            """,
            (
                new_user_id,
                new_user_id,
                f"Нова заявка на реєстрацію: {req.first_name} {req.patronymic} ({email_clean}, {req.specialty}, {req.position})",
                now_iso,
            ),
        )
        row = conn.execute("SELECT * FROM users WHERE id = ?", (new_user_id,)).fetchone()
    conn.close()

    return {
        "status": "pending_approval",
        "message": (
            "Заявку на реєстрацію успішно створено! Доступ до калькулятора "
            "буде відкрито після підтвердження облікового запису адміністратором."
        ),
        "user": format_user_row(row),
    }


@app.post("/api/auth/login")
def login_user(req: LoginRequest) -> Dict[str, Any]:
    email_clean = req.email.strip().lower()
    conn = get_db_connection()
    row = conn.execute(
        "SELECT * FROM users WHERE lower(email) = ?", (email_clean,)
    ).fetchone()
    conn.close()

    if not row or not verify_password(req.password, row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Невірна електронна пошта або пароль.",
        )

    user = format_user_row(row)
    if user["status"] == "blocked":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ваш обліковий запис заблоковано адміністратором. Зверніться до служби підтримки.",
        )
    if user["status"] == "pending":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ваш обліковий запис ще не підтверджено адміністратором. Очікуйте на активацію.",
        )

    token = create_jwt_token(user["id"], user["email"], user["role"])
    return {
        "status": "ok",
        "access_token": token,
        "token_type": "bearer",
        "user": user,
    }


@app.get("/api/auth/me")
def get_me(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    return {"status": "ok", "user": current_user}


# -----------------------------------------------------------------------------
# 2. ОСОБИСТИЙ КАБІНЕТ: ПЕРСОНАЛЬНА ІНФОРМАЦІЯ КОРИСТУВАЧА (/api/profile)
# -----------------------------------------------------------------------------
@app.get("/api/profile")
def get_profile(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    return {
        "status": "ok",
        "profile": current_user,
        "executor_autofill": {
            "execPerson": current_user["full_name"] or current_user["display_name_patronymic"],
            "execPosition": current_user["position"],
            "execCompany": current_user["company_name"],
            "execPhone": current_user["phone"],
            "execEmail": current_user["email"],
            "execAddress": current_user["office_address"],
            "execRequisites": current_user["company_requisites"],
            "letterheadLogoDataUrl": current_user["letterhead_logo"],
        },
    }


@app.put("/api/profile")
def update_profile(
    req: ProfileUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    fields_to_update: Dict[str, Any] = {}
    for field_name in [
        "first_name",
        "patronymic",
        "last_name",
        "email",
        "phone",
        "specialty",
        "position",
        "company_name",
        "office_address",
        "company_requisites",
        "letterhead_logo",
    ]:
        val = getattr(req, field_name)
        if val is not None:
            fields_to_update[field_name] = val.strip() if isinstance(val, str) else val

    if not fields_to_update:
        return {"status": "ok", "profile": current_user}

    fields_to_update["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in fields_to_update.keys())
    values = list(fields_to_update.values()) + [current_user["id"]]

    conn = get_db_connection()
    with conn:
        conn.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (current_user["id"],)
        ).fetchone()
    conn.close()

    updated_user = format_user_row(row)
    return {
        "status": "ok",
        "message": "Персональні дані в особистому кабінеті успішно оновлено.",
        "profile": updated_user,
    }


# -----------------------------------------------------------------------------
# 3. ЗАХИЩЕНЕ СЕРВЕРНЕ МАТЕМАТИЧНЕ ЯДРО (/api/calculate)
# -----------------------------------------------------------------------------
@app.post("/api/calculate")
def calculate_on_server(
    state_payload: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    enforce_subscription_quota(current_user)

    # Автоматично підставляємо дані виконавця з профілю користувача, якщо вони не передані
    if not state_payload.get("execPerson"):
        state_payload["execPerson"] = (
            current_user["full_name"] or current_user["display_name_patronymic"]
        )
    if not state_payload.get("execPosition"):
        state_payload["execPosition"] = current_user["position"]
    if not state_payload.get("execCompany") and current_user.get("company_name"):
        state_payload["execCompany"] = current_user["company_name"]
    if not state_payload.get("execPhone"):
        state_payload["execPhone"] = current_user["phone"]
    if not state_payload.get("execEmail"):
        state_payload["execEmail"] = current_user["email"]

    calc_result = run_server_8760_calculation(state_payload)

    # Оновлюємо лічильник використаних розрахунків користувача
    conn = get_db_connection()
    with conn:
        conn.execute(
            "UPDATE users SET calcs_used_count = calcs_used_count + 1 WHERE id = ?",
            (current_user["id"],),
        )
    conn.close()

    return {
        "status": "ok",
        "calculated_by_user_id": current_user["id"],
        "result": calc_result,
    }


# -----------------------------------------------------------------------------
# 4. ОСОБИСТИЙ КАБІНЕТ: ЗБЕРЕЖЕННЯ ТА КЕРУВАННЯ РОЗРАХУНКАМИ (/api/projects)
# -----------------------------------------------------------------------------
@app.get("/api/projects")
def list_user_projects(
    search: Optional[str] = Query(default=None, description="Пошук за назвою або компанією"),
    mode: Optional[str] = Query(default=None, description="Фільтр за режимом: solar | bess | solar_bess"),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    conn = get_db_connection()
    sql = """
        SELECT id, user_id, project_title, client_company, client_address,
               client_contact, client_phone, project_mode, voltage_kv,
               summary_json, created_at, updated_at
        FROM projects
        WHERE user_id = ?
    """
    params: List[Any] = [current_user["id"]]
    if mode:
        sql += " AND project_mode = ?"
        params.append(mode)
    if search:
        q = f"%{search.strip()}%"
        sql += " AND (project_title LIKE ? OR client_company LIKE ? OR client_address LIKE ?)"
        params.extend([q, q, q])
    sql += " ORDER BY updated_at DESC"

    rows = conn.execute(sql, params).fetchall()
    conn.close()

    projects = []
    for r in rows:
        item = dict(r)
        try:
            item["summary"] = json.loads(item.pop("summary_json", "{}") or "{}")
        except Exception:
            item["summary"] = {}
        projects.append(item)

    return {"status": "ok", "count": len(projects), "projects": projects}


@app.post("/api/projects", status_code=status.HTTP_201_CREATED)
def save_new_project(
    req: ProjectSaveRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    enforce_subscription_quota(current_user)
    st = req.state or {}
    calc_out = run_server_8760_calculation(st)
    summary = calc_out.get("summaryMetrics", {})

    client_company = str(st.get("clientCompany") or "Новий клієнт").strip()
    project_title = (
        req.project_title.strip()
        if req.project_title and req.project_title.strip()
        else f"Розрахунок ТЕО — {client_company}"
    )
    project_mode = str(st.get("projectConfigMode") or "solar_bess")
    voltage_kv = int(st.get("connectionVoltageKv") or 10)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    conn = get_db_connection()
    with conn:
        cur = conn.execute(
            """
            INSERT INTO projects (
                user_id, project_title, client_company, client_address,
                client_contact, client_phone, project_mode, voltage_kv,
                state_json, summary_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                current_user["id"],
                project_title,
                client_company,
                str(st.get("clientAddress") or ""),
                str(st.get("clientContactPerson") or ""),
                str(st.get("clientPhone") or ""),
                project_mode,
                voltage_kv,
                json.dumps(st, ensure_ascii=False),
                json.dumps(summary, ensure_ascii=False),
                now_iso,
                now_iso,
            ),
        )
        project_id = cur.lastrowid
    conn.close()

    return {
        "status": "ok",
        "message": f"Розрахунок «{project_title}» збережено в Особистому кабінеті.",
        "project_id": project_id,
        "project_title": project_title,
        "summary": summary,
        "calculation": calc_out,
    }


@app.get("/api/projects/{project_id}")
def get_project_detail(
    project_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    conn = get_db_connection()
    row = conn.execute(
        "SELECT * FROM projects WHERE id = ? AND user_id = ?",
        (project_id, current_user["id"]),
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Розрахунок не знайдено у вашому Особистому кабінеті.",
        )
    data = dict(row)
    state_obj = json.loads(data.pop("state_json", "{}") or "{}")
    summary_obj = json.loads(data.pop("summary_json", "{}") or "{}")
    calc_out = run_server_8760_calculation(state_obj)

    return {
        "status": "ok",
        "project": {
            **data,
            "state": state_obj,
            "summary": summary_obj,
            "calculation": calc_out,
        },
    }


@app.put("/api/projects/{project_id}")
def update_saved_project(
    project_id: int,
    req: ProjectSaveRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    conn = get_db_connection()
    existing = conn.execute(
        "SELECT id, project_title FROM projects WHERE id = ? AND user_id = ?",
        (project_id, current_user["id"]),
    ).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Розрахунок не знайдено у вашому Особистому кабінеті.",
        )

    st = req.state or {}
    calc_out = run_server_8760_calculation(st)
    summary = calc_out.get("summaryMetrics", {})
    client_company = str(st.get("clientCompany") or "Клієнт").strip()
    new_title = (
        req.project_title.strip()
        if req.project_title and req.project_title.strip()
        else existing["project_title"]
    )
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    with conn:
        conn.execute(
            """
            UPDATE projects
            SET project_title = ?,
                client_company = ?,
                client_address = ?,
                client_contact = ?,
                client_phone = ?,
                project_mode = ?,
                voltage_kv = ?,
                state_json = ?,
                summary_json = ?,
                updated_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                new_title,
                client_company,
                str(st.get("clientAddress") or ""),
                str(st.get("clientContactPerson") or ""),
                str(st.get("clientPhone") or ""),
                str(st.get("projectConfigMode") or "solar_bess"),
                int(st.get("connectionVoltageKv") or 10),
                json.dumps(st, ensure_ascii=False),
                json.dumps(summary, ensure_ascii=False),
                now_iso,
                project_id,
                current_user["id"],
            ),
        )
    conn.close()

    return {
        "status": "ok",
        "message": f"Розрахунок «{new_title}» успішно оновлено.",
        "project_id": project_id,
        "summary": summary,
        "calculation": calc_out,
    }


@app.post("/api/projects/{project_id}/clone", status_code=status.HTTP_201_CREATED)
def clone_saved_project(
    project_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    conn = get_db_connection()
    row = conn.execute(
        "SELECT * FROM projects WHERE id = ? AND user_id = ?",
        (project_id, current_user["id"]),
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Вихідний розрахунок не знайдено.",
        )
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cloned_title = f"{row['project_title']} (Копія)"
    with conn:
        cur = conn.execute(
            """
            INSERT INTO projects (
                user_id, project_title, client_company, client_address,
                client_contact, client_phone, project_mode, voltage_kv,
                state_json, summary_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                current_user["id"],
                cloned_title,
                row["client_company"],
                row["client_address"],
                row["client_contact"],
                row["client_phone"],
                row["project_mode"],
                row["voltage_kv"],
                row["state_json"],
                row["summary_json"],
                now_iso,
                now_iso,
            ),
        )
        new_id = cur.lastrowid
    conn.close()
    return {
        "status": "ok",
        "message": f"Створено копію розрахунку: «{cloned_title}»",
        "project_id": new_id,
        "project_title": cloned_title,
    }


@app.delete("/api/projects/{project_id}")
def delete_saved_project(
    project_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    conn = get_db_connection()
    with conn:
        cur = conn.execute(
            "DELETE FROM projects WHERE id = ? AND user_id = ?",
            (project_id, current_user["id"]),
        )
    conn.close()
    if cur.rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Розрахунок не знайдено.",
        )
    return {"status": "ok", "message": "Розрахунок видалено з Особистого кабінету."}


# -----------------------------------------------------------------------------
# 5. ПАНЕЛЬ КЕРУВАННЯ АДМІНІСТРАТОРА (/api/admin/...)
#    - Статистика, список користувачів, підтвердження реєстрації, блокування, підписки
# -----------------------------------------------------------------------------
@app.get("/api/admin/stats")
def admin_dashboard_stats(
    admin_user: Dict[str, Any] = Depends(get_admin_user),
) -> Dict[str, Any]:
    conn = get_db_connection()
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    pending_users = conn.execute(
        "SELECT COUNT(*) FROM users WHERE status = 'pending'"
    ).fetchone()[0]
    approved_users = conn.execute(
        "SELECT COUNT(*) FROM users WHERE status = 'approved'"
    ).fetchone()[0]
    blocked_users = conn.execute(
        "SELECT COUNT(*) FROM users WHERE status = 'blocked'"
    ).fetchone()[0]
    total_projects = conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
    total_calcs = conn.execute(
        "SELECT COALESCE(SUM(calcs_used_count), 0) FROM users"
    ).fetchone()[0]
    conn.close()

    return {
        "status": "ok",
        "stats": {
            "total_users": total_users,
            "pending_registrations": pending_users,
            "approved_users": approved_users,
            "blocked_users": blocked_users,
            "total_saved_projects": total_projects,
            "total_server_calculations": total_calcs,
        },
    }


@app.get("/api/admin/users")
def admin_list_users(
    status_filter: Optional[str] = Query(
        default=None, description="Фільтр: pending | approved | blocked"
    ),
    search: Optional[str] = Query(default=None, description="Пошук за ПІБ, поштою, телефоном"),
    admin_user: Dict[str, Any] = Depends(get_admin_user),
) -> Dict[str, Any]:
    conn = get_db_connection()
    sql = """
        SELECT u.*,
               (SELECT COUNT(*) FROM projects p WHERE p.user_id = u.id) AS saved_projects_count
        FROM users u
        WHERE 1=1
    """
    params: List[Any] = []
    if status_filter:
        sql += " AND u.status = ?"
        params.append(status_filter)
    if search:
        q = f"%{search.strip()}%"
        sql += """ AND (
            u.first_name LIKE ? OR u.patronymic LIKE ? OR u.last_name LIKE ?
            OR u.email LIKE ? OR u.phone LIKE ? OR u.specialty LIKE ? OR u.position LIKE ?
        )"""
        params.extend([q, q, q, q, q, q, q])
    sql += " ORDER BY CASE u.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, u.created_at DESC"

    rows = conn.execute(sql, params).fetchall()
    conn.close()

    users_list = []
    for r in rows:
        u = format_user_row(r)
        u["saved_projects_count"] = r["saved_projects_count"]
        users_list.append(u)

    return {"status": "ok", "count": len(users_list), "users": users_list}


@app.patch("/api/admin/users/{user_id}/status")
def admin_update_user_status(
    user_id: int,
    req: AdminStatusUpdateRequest,
    admin_user: Dict[str, Any] = Depends(get_admin_user),
) -> Dict[str, Any]:
    if req.status not in ("approved", "blocked", "pending"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Недопустимий статус. Дозволені значення: 'approved', 'blocked', 'pending'.",
        )
    if user_id == admin_user["id"] and req.status != "approved":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Адміністратор не може заблокувати власний обліковий запис.",
        )

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn = get_db_connection()
    target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Користувача не знайдено."
        )

    with conn:
        conn.execute(
            "UPDATE users SET status = ?, updated_at = ? WHERE id = ?",
            (req.status, now_iso, user_id),
        )
        conn.execute(
            """
            INSERT INTO audit_logs (actor_user_id, target_user_id, action, details, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                admin_user["id"],
                user_id,
                f"USER_STATUS_{req.status.upper()}",
                f"Змінено статус користувача {target['email']} на '{req.status}'. Причина: {req.reason or '—'}",
                now_iso,
            ),
        )
        updated_row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    conn.close()

    status_labels = {
        "approved": "підтверджено (доступ відкрито)",
        "blocked": "заблоковано (доступ закрито)",
        "pending": "переведено в очікування підтвердження",
    }
    return {
        "status": "ok",
        "message": f"Обліковий запис {target['email']} {status_labels[req.status]}.",
        "user": format_user_row(updated_row),
    }


@app.patch("/api/admin/users/{user_id}/subscription")
def admin_update_user_subscription(
    user_id: int,
    req: AdminSubscriptionUpdateRequest,
    admin_user: Dict[str, Any] = Depends(get_admin_user),
) -> Dict[str, Any]:
    if req.subscription_plan not in ("none", "trial", "pro_monthly", "enterprise_yearly"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Недопустимий тарифний план підписки.",
        )
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now_dt.isoformat()
    exp_iso = (
        (now_dt + datetime.timedelta(days=req.days_valid)).isoformat()
        if req.subscription_plan != "none" and req.days_valid > 0
        else now_iso
    )

    conn = get_db_connection()
    target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Користувача не знайдено."
        )

    with conn:
        if req.reset_used_counter:
            conn.execute(
                """
                UPDATE users
                SET subscription_plan = ?,
                    subscription_expires_at = ?,
                    monthly_calc_limit = ?,
                    calcs_used_count = 0,
                    updated_at = ?
                WHERE id = ?
                """,
                (req.subscription_plan, exp_iso, req.monthly_calc_limit, now_iso, user_id),
            )
        else:
            conn.execute(
                """
                UPDATE users
                SET subscription_plan = ?,
                    subscription_expires_at = ?,
                    monthly_calc_limit = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (req.subscription_plan, exp_iso, req.monthly_calc_limit, now_iso, user_id),
            )

        conn.execute(
            """
            INSERT INTO audit_logs (actor_user_id, target_user_id, action, details, created_at)
            VALUES (?, ?, 'SUBSCRIPTION_UPDATED', ?, ?)
            """,
            (
                admin_user["id"],
                user_id,
                f"Тариф: {req.subscription_plan}, днів: {req.days_valid}, ліміт: {req.monthly_calc_limit}",
                now_iso,
            ),
        )
        updated_row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    conn.close()

    return {
        "status": "ok",
        "message": f"Підписку користувача {target['email']} оновлено ({req.subscription_plan}, {req.days_valid} дн.).",
        "user": format_user_row(updated_row),
    }


@app.get("/api/admin/audit-logs")
def admin_get_audit_logs(
    limit: int = Query(default=50, ge=1, le=500),
    admin_user: Dict[str, Any] = Depends(get_admin_user),
) -> Dict[str, Any]:
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return {"status": "ok", "logs": [dict(r) for r in rows]}


# Роздача фронтенд-інтерфейсу при відкритті кореневого маршруту "/"
@app.get("/")
def serve_frontend():
    if FRONTEND_HTML_PATH.exists():
        return FileResponse(str(FRONTEND_HTML_PATH), media_type="text/html")
    return JSONResponse(
        {"status": "ok", "service": "BESS & Solar Calculator SaaS Backend API v1.0"}
    )
