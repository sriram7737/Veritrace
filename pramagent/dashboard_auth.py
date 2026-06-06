"""
Dashboard user authentication stores.

This module is intentionally separate from the API-key registry. API keys are
machine credentials; dashboard users are human identities with generated
dashboard keys, roles, tenant scope, and reset tokens.

The production path is Postgres. SQLite is provided for local development and
tests so nobody is tempted to use CSV files for access-control state.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import bcrypt


_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{3,80}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?[0-9][0-9(). \-]{6,24}$")
_ROLES = {"viewer", "approver", "auditor", "admin"}
_KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class DashboardAuthError(ValueError):
    """Raised when dashboard user input is invalid or conflicts with state."""


@dataclass(frozen=True)
class DashboardUser:
    id: str
    username: str
    email: str
    phone: str
    tenant_id: str
    role: str
    is_active: bool = True
    verified: bool = False


@dataclass(frozen=True)
class DashboardKeyIssue:
    user: DashboardUser
    key: str


def _normalize_username(username: str) -> str:
    username = (username or "").strip()
    if not _USERNAME_RE.match(username):
        raise DashboardAuthError(
            "Username must be 3-80 characters and use letters, numbers, dots, dashes, underscores, or @"
        )
    return username


def _normalize_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not _EMAIL_RE.match(email):
        raise DashboardAuthError("Valid email is required")
    return email


def _normalize_optional_email(email: str) -> str:
    email = (email or "").strip().lower()
    if email and not _EMAIL_RE.match(email):
        raise DashboardAuthError("Valid email is required")
    return email


def _normalize_phone(phone: str) -> str:
    phone = (phone or "").strip()
    if phone and not _PHONE_RE.match(phone):
        raise DashboardAuthError("Phone must be a valid SMS-capable number")
    if not phone:
        return ""
    return re.sub(r"[().\-\s]", "", phone)


def _identity_username(email: str, phone: str) -> str:
    if email:
        return _normalize_username(email)
    if phone:
        return "phone_" + hashlib.sha256(phone.encode("utf-8")).hexdigest()[:16]
    else:
        raise DashboardAuthError("Email or phone is required")


def _phone_lookup(value: str) -> str:
    try:
        return _normalize_phone(value)
    except DashboardAuthError:
        return ""


def generate_dashboard_key(groups: int = 6, group_size: int = 6) -> str:
    """Generate a human-readable high-entropy dashboard key.

    The default 36-character base32-like key carries roughly 180 bits of
    entropy while staying easier to transcribe than raw URL-safe tokens.
    """

    groups = max(4, min(10, int(groups)))
    group_size = max(4, min(8, int(group_size)))
    chunks = [
        "".join(secrets.choice(_KEY_ALPHABET) for _ in range(group_size))
        for _ in range(groups)
    ]
    return "pga-" + "-".join(chunks)


def _normalize_secret_key(key: str) -> str:
    if len(key or "") < 24:
        raise DashboardAuthError("Dashboard key must be at least 24 characters")
    return key.strip()


def _normalize_role(role: str) -> str:
    role = (role or "viewer").strip().lower()
    if role not in _ROLES:
        raise DashboardAuthError(f"Role must be one of: {', '.join(sorted(_ROLES))}")
    return role


def _normalize_tenant(tenant_id: str) -> str:
    tenant_id = (tenant_id or "").strip()
    if not tenant_id or len(tenant_id) > 120:
        raise DashboardAuthError("Tenant id is required")
    return tenant_id


def _hash_password(password: str) -> str:
    _normalize_secret_key(password)
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def _verify_password(password: str, password_hash: str) -> bool:
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class DashboardUserStore:
    """Small interface shared by the SQLite and Postgres stores."""

    def create_user(
        self,
        *,
        username: str = "",
        email: str = "",
        password: str = "",
        phone: str = "",
        tenant_id: str = "",
        role: str = "viewer",
    ) -> DashboardUser:
        raise NotImplementedError

    def create_user_with_key(
        self,
        *,
        email: str = "",
        phone: str = "",
        tenant_id: str = "",
        role: str = "viewer",
    ) -> DashboardKeyIssue:
        key = generate_dashboard_key()
        user = self.create_user(
            username="",
            email=email,
            phone=phone,
            password=key,
            tenant_id=tenant_id,
            role=role,
        )
        return DashboardKeyIssue(user=user, key=key)

    def authenticate(self, login: str, password: str) -> Optional[DashboardUser]:
        raise NotImplementedError

    def create_reset_token(self, identity: str, *, ttl_s: int = 900) -> Optional[str]:
        raise NotImplementedError

    def reset_password(self, token: str, password: str) -> bool:
        raise NotImplementedError

    def regenerate_key(self, token: str) -> Optional[DashboardKeyIssue]:
        key = generate_dashboard_key()
        user = self._replace_key(token, key)
        if user is None:
            return None
        return DashboardKeyIssue(user=user, key=key)

    def _replace_key(self, token: str, key: str) -> Optional[DashboardUser]:
        raise NotImplementedError


class SQLiteDashboardUserStore(DashboardUserStore):
    """SQLite-backed dashboard users for local dev and tests."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _conn(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS pramagent_dashboard_users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NULL,
                    phone TEXT UNIQUE NULL,
                    password_hash TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    verified INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    last_login REAL NULL
                );
                CREATE TABLE IF NOT EXISTS pramagent_password_reset_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    used_at REAL NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES pramagent_dashboard_users(id)
                );
                CREATE INDEX IF NOT EXISTS pramagent_dashboard_users_email
                    ON pramagent_dashboard_users(email);
                CREATE INDEX IF NOT EXISTS pramagent_dashboard_users_phone
                    ON pramagent_dashboard_users(phone);
                CREATE INDEX IF NOT EXISTS pramagent_reset_tokens_user
                    ON pramagent_password_reset_tokens(user_id);
                """
            )
            cols = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(pramagent_dashboard_users)").fetchall()
            }
            if "phone" not in cols:
                conn.execute("ALTER TABLE pramagent_dashboard_users ADD COLUMN phone TEXT NULL")
                conn.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS pramagent_dashboard_users_phone_unique
                    ON pramagent_dashboard_users(phone)
                    WHERE phone IS NOT NULL AND phone != ''
                    """
                )
            if "verified" not in cols:
                conn.execute(
                    "ALTER TABLE pramagent_dashboard_users ADD COLUMN verified INTEGER NOT NULL DEFAULT 1"
                )

    @staticmethod
    def _user_from_row(row) -> DashboardUser:
        return DashboardUser(
            id=row["id"],
            username=row["username"],
            email=row["email"] or "",
            phone=row["phone"] or "",
            tenant_id=row["tenant_id"],
            role=row["role"],
            is_active=bool(row["is_active"]),
            verified=bool(row["verified"]),
        )

    def create_user(
        self,
        *,
        username: str = "",
        email: str = "",
        password: str = "",
        phone: str = "",
        tenant_id: str = "",
        role: str = "viewer",
    ) -> DashboardUser:
        email = _normalize_optional_email(email)
        phone = _normalize_phone(phone)
        username = _normalize_username(username) if username else _identity_username(email, phone)
        if not email and not phone:
            raise DashboardAuthError("Email or phone is required")
        tenant_id = _normalize_tenant(tenant_id)
        role = _normalize_role(role)
        password_hash = _hash_password(password)
        user_id = str(uuid.uuid4())
        now = time.time()
        try:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO pramagent_dashboard_users
                        (id, username, email, phone, password_hash, tenant_id, role, is_active, verified, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?)
                    """,
                    (user_id, username, email or None, phone or None, password_hash, tenant_id, role, now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise DashboardAuthError("Email or phone already exists") from exc
        return DashboardUser(user_id, username, email, phone, tenant_id, role, True, True)

    def authenticate(self, login: str, password: str) -> Optional[DashboardUser]:
        login = (login or "").strip()
        if not login or not password:
            return None
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT * FROM pramagent_dashboard_users
                WHERE (username = ? OR email = ? OR phone = ?) AND is_active = 1
                """,
                (login, login.lower(), _phone_lookup(login)),
            ).fetchone()
            if not row or not _verify_password(password, row["password_hash"]):
                return None
            conn.execute(
                "UPDATE pramagent_dashboard_users SET last_login = ?, updated_at = ? WHERE id = ?",
                (time.time(), time.time(), row["id"]),
            )
            return self._user_from_row(row)

    def create_reset_token(self, identity: str, *, ttl_s: int = 900) -> Optional[str]:
        identity = (identity or "").strip()
        if not identity:
            return None
        email = identity.lower()
        phone = _phone_lookup(identity) if not _EMAIL_RE.match(email) else ""
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT id FROM pramagent_dashboard_users
                WHERE (email = ? OR phone = ?) AND is_active = 1
                """,
                (email, phone),
            ).fetchone()
            if not row:
                return None
            token = secrets.token_urlsafe(32)
            conn.execute(
                """
                INSERT INTO pramagent_password_reset_tokens
                    (token_hash, user_id, expires_at, used_at, created_at)
                VALUES (?, ?, ?, NULL, ?)
                """,
                (_hash_token(token), row["id"], time.time() + max(60, int(ttl_s)), time.time()),
            )
            return token

    def reset_password(self, token: str, password: str) -> bool:
        return self._replace_key(token, password) is not None

    def _replace_key(self, token: str, key: str) -> Optional[DashboardUser]:
        token_hash = _hash_token(token or "")
        password_hash = _hash_password(key)
        now = time.time()
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT user_id FROM pramagent_password_reset_tokens
                WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
                """,
                (token_hash, now),
            ).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE pramagent_dashboard_users SET password_hash = ?, updated_at = ? WHERE id = ?",
                (password_hash, now, row["user_id"]),
            )
            conn.execute(
                "UPDATE pramagent_password_reset_tokens SET used_at = ? WHERE token_hash = ?",
                (now, token_hash),
            )
            user_row = conn.execute(
                "SELECT * FROM pramagent_dashboard_users WHERE id = ?",
                (row["user_id"],),
            ).fetchone()
            return self._user_from_row(user_row) if user_row else None


class PostgresDashboardUserStore(DashboardUserStore):
    """Postgres-backed dashboard users for team deployments."""

    _DDL = """
    CREATE TABLE IF NOT EXISTS pramagent_dashboard_users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NULL,
        phone TEXT UNIQUE NULL,
        password_hash TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        verified BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_login TIMESTAMPTZ NULL
    );
    CREATE TABLE IF NOT EXISTS pramagent_password_reset_tokens (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES pramagent_dashboard_users(id),
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS pramagent_dashboard_users_email
        ON pramagent_dashboard_users(email);
    CREATE INDEX IF NOT EXISTS pramagent_dashboard_users_phone
        ON pramagent_dashboard_users(phone);
    CREATE INDEX IF NOT EXISTS pramagent_reset_tokens_user
        ON pramagent_password_reset_tokens(user_id);
    """

    def __init__(self, dsn: str, *, connect=None) -> None:
        if not dsn:
            raise ValueError("Dashboard user DSN must not be empty")
        self.dsn = dsn
        self._connect = connect
        self._init_schema()

    def _connection(self):
        if self._connect is not None:
            return self._connect(self.dsn)
        try:
            import psycopg2  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "psycopg2 is required for PostgresDashboardUserStore; install pramagent[postgres]"
            ) from exc
        return psycopg2.connect(self.dsn)

    def _run(self, fn):
        conn = self._connection()
        try:
            with conn:
                with conn.cursor() as cur:
                    return fn(cur)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _init_schema(self) -> None:
        def _fn(cur):
            cur.execute(self._DDL)
            cur.execute("ALTER TABLE pramagent_dashboard_users ALTER COLUMN email DROP NOT NULL")
            cur.execute("ALTER TABLE pramagent_dashboard_users ADD COLUMN IF NOT EXISTS phone TEXT")
            cur.execute(
                "ALTER TABLE pramagent_dashboard_users ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT TRUE"
            )
            cur.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS pramagent_dashboard_users_phone_unique
                ON pramagent_dashboard_users(phone)
                WHERE phone IS NOT NULL AND phone <> ''
                """
            )

        self._run(_fn)

    @staticmethod
    def _user_from_row(row) -> DashboardUser:
        return DashboardUser(
            id=row[0],
            username=row[1],
            email=row[2] or "",
            phone=row[3] or "",
            tenant_id=row[4],
            role=row[5],
            is_active=bool(row[6]),
            verified=bool(row[7]),
        )

    def create_user(
        self,
        *,
        username: str = "",
        email: str = "",
        password: str = "",
        phone: str = "",
        tenant_id: str = "",
        role: str = "viewer",
    ) -> DashboardUser:
        email = _normalize_optional_email(email)
        phone = _normalize_phone(phone)
        username = _normalize_username(username) if username else _identity_username(email, phone)
        if not email and not phone:
            raise DashboardAuthError("Email or phone is required")
        tenant_id = _normalize_tenant(tenant_id)
        role = _normalize_role(role)
        password_hash = _hash_password(password)
        user_id = str(uuid.uuid4())

        def _fn(cur):
            try:
                cur.execute(
                    """
                    INSERT INTO pramagent_dashboard_users
                        (id, username, email, phone, password_hash, tenant_id, role, verified)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE)
                    """,
                    (user_id, username, email or None, phone or None, password_hash, tenant_id, role),
                )
            except Exception as exc:
                raise DashboardAuthError("Email or phone already exists") from exc

        self._run(_fn)
        return DashboardUser(user_id, username, email, phone, tenant_id, role, True, True)

    def authenticate(self, login: str, password: str) -> Optional[DashboardUser]:
        login = (login or "").strip()
        if not login or not password:
            return None

        def _fn(cur):
            cur.execute(
                """
                SELECT id, username, email, phone, tenant_id, role, is_active, verified, password_hash
                FROM pramagent_dashboard_users
                WHERE (username = %s OR email = %s OR phone = %s) AND is_active = TRUE
                """,
                (login, login.lower(), _phone_lookup(login)),
            )
            row = cur.fetchone()
            if not row or not _verify_password(password, row[8]):
                return None
            cur.execute(
                """
                UPDATE pramagent_dashboard_users
                SET last_login = now(), updated_at = now()
                WHERE id = %s
                """,
                (row[0],),
            )
            return self._user_from_row(row)

        return self._run(_fn)

    def create_reset_token(self, identity: str, *, ttl_s: int = 900) -> Optional[str]:
        identity = (identity or "").strip()
        if not identity:
            return None
        email = identity.lower()
        phone = _phone_lookup(identity) if not _EMAIL_RE.match(email) else ""
        token = secrets.token_urlsafe(32)

        def _fn(cur):
            cur.execute(
                """
                SELECT id FROM pramagent_dashboard_users
                WHERE (email = %s OR phone = %s) AND is_active = TRUE
                """,
                (email, phone),
            )
            row = cur.fetchone()
            if not row:
                return None
            cur.execute(
                """
                INSERT INTO pramagent_password_reset_tokens
                    (token_hash, user_id, expires_at, used_at)
                VALUES (%s, %s, now() + (%s || ' seconds')::interval, NULL)
                """,
                (_hash_token(token), row[0], str(max(60, int(ttl_s)))),
            )
            return token

        return self._run(_fn)

    def reset_password(self, token: str, password: str) -> bool:
        return self._replace_key(token, password) is not None

    def _replace_key(self, token: str, key: str) -> Optional[DashboardUser]:
        token_hash = _hash_token(token or "")
        password_hash = _hash_password(key)

        def _fn(cur):
            cur.execute(
                """
                SELECT user_id FROM pramagent_password_reset_tokens
                WHERE token_hash = %s AND used_at IS NULL AND expires_at > now()
                """,
                (token_hash,),
            )
            row = cur.fetchone()
            if not row:
                return None
            cur.execute(
                """
                UPDATE pramagent_dashboard_users
                SET password_hash = %s, updated_at = now()
                WHERE id = %s AND is_active = TRUE
                """,
                (password_hash, row[0]),
            )
            if cur.rowcount < 1:
                return None
            cur.execute(
                "UPDATE pramagent_password_reset_tokens SET used_at = now() WHERE token_hash = %s",
                (token_hash,),
            )
            cur.execute(
                """
                SELECT id, username, email, phone, tenant_id, role, is_active, verified
                FROM pramagent_dashboard_users
                WHERE id = %s
                """,
                (row[0],),
            )
            user_row = cur.fetchone()
            return self._user_from_row(user_row) if user_row else None

        return self._run(_fn)


def build_dashboard_user_store_from_env(env: dict[str, str] | None = None) -> DashboardUserStore | None:
    """Build an optional dashboard user store from environment variables.

    Supported variables:

    - ``PRAMAGENT_DASHBOARD_USER_DSN`` / ``PRAMAGENT_DASHBOARD_USERS_DSN``
      for Postgres DSNs, or ``sqlite:///path/to/users.db``.
    - ``PRAMAGENT_DASHBOARD_USERS_SQLITE`` for an explicit SQLite path.
    """

    env = env or os.environ
    dsn = (
        env.get("PRAMAGENT_DASHBOARD_USER_DSN")
        or env.get("PRAMAGENT_DASHBOARD_USERS_DSN")
        or ""
    ).strip()
    if dsn.startswith("sqlite:///"):
        return SQLiteDashboardUserStore(dsn[len("sqlite:///") :])
    if dsn:
        return PostgresDashboardUserStore(dsn)

    sqlite_path = (env.get("PRAMAGENT_DASHBOARD_USERS_SQLITE") or "").strip()
    if sqlite_path:
        return SQLiteDashboardUserStore(sqlite_path)
    return None
