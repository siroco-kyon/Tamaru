"""Server-side sessions, Argon2id passwords and durable admin/audit storage."""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import secrets
import sqlite3
import time
from pathlib import Path
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError

HASHER = PasswordHasher()
USERNAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}$")


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def validate_password(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise ValueError("パスワードは12〜256文字で指定してください。")


class Store:
    def __init__(self, state):
        self.state = Path(state)
        self.state.mkdir(parents=True, exist_ok=True)
        self.db = self.state / "app.sqlite3"
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS admins(
                    id INTEGER PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1, version INTEGER NOT NULL DEFAULT 1,
                    created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions(
                    token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL, version INTEGER NOT NULL,
                    csrf TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS audit(
                    id INTEGER PRIMARY KEY, at REAL NOT NULL, actor TEXT NOT NULL,
                    action TEXT NOT NULL, detail TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS attempts(
                    key TEXT PRIMARY KEY, failures INTEGER NOT NULL, expires REAL NOT NULL);
            """)
            db.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
            db.execute("DELETE FROM attempts WHERE expires<?", (time.time(),))
            db.commit()
        # Unknown accounts still perform password verification to reduce account enumeration.
        self.dummy_hash = HASHER.hash(secrets.token_urlsafe(32))

    @contextlib.contextmanager
    def connect(self):
        db = sqlite3.connect(self.db, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=30000")
        try:
            yield db
        finally:
            db.close()

    @staticmethod
    def log(db, actor, action, detail=""):
        db.execute(
            "INSERT INTO audit(at,actor,action,detail) VALUES(?,?,?,?)",
            (time.time(), actor, action, detail),
        )

    def audit(self, actor, action, detail=""):
        with self.connect() as db:
            self.log(db, actor, action, detail)
            db.commit()

    def get(self, key, default=None):
        with self.connect() as db:
            row = db.execute(
                "SELECT value FROM settings WHERE key=?", (key,)
            ).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, key, value):
        with self.connect() as db:
            db.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value, ensure_ascii=False)),
            )
            db.commit()

    def admins(self):
        with self.connect() as db:
            return [
                dict(r)
                for r in db.execute(
                    "SELECT id,username,display_name,enabled,created FROM admins ORDER BY id"
                )
            ]

    def create_admin(
        self, username, display_name, password, actor="server-console", first_only=False
    ):
        if not USERNAME.fullmatch(username):
            raise ValueError(
                "IDは英数字で始まる3〜64文字の英数字・_・.・-にしてください。"
            )
        if (
            not isinstance(display_name, str)
            or not 1 <= len(display_name.strip()) <= 100
        ):
            raise ValueError("表示名は1〜100文字で指定してください。")
        validate_password(password)
        hashed = HASHER.hash(password)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if first_only and db.execute("SELECT count(*) FROM admins").fetchone()[0]:
                raise ValueError(
                    "管理者は既に登録されています。追加はWebの管理者管理から行ってください。"
                )
            try:
                admin_id = db.execute(
                    "INSERT INTO admins(username,display_name,password_hash,created) VALUES(?,?,?,?)",
                    (username.lower(), display_name.strip(), hashed, time.time()),
                ).lastrowid
            except sqlite3.IntegrityError:
                raise ValueError("そのIDは既に登録されています。") from None
            self.log(db, actor, "admin_created", username.lower())
            db.commit()
        return admin_id

    def change_admin(self, admin_id, actor, *, enabled=None, password=None):
        hashed = None
        if password is not None:
            validate_password(password)
            hashed = HASHER.hash(password)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM admins WHERE id=?", (admin_id,)).fetchone()
            if not row:
                raise ValueError("管理者が見つかりません。")
            if (
                enabled is False
                and row["enabled"]
                and db.execute(
                    "SELECT count(*) FROM admins WHERE enabled=1"
                ).fetchone()[0]
                <= 1
            ):
                raise ValueError("最後の有効な管理者は無効化できません。")
            if enabled is not None:
                db.execute(
                    "UPDATE admins SET enabled=?,version=version+1 WHERE id=?",
                    (int(enabled), admin_id),
                )
            if hashed:
                db.execute(
                    "UPDATE admins SET password_hash=?,version=version+1 WHERE id=?",
                    (hashed, admin_id),
                )
            db.execute("DELETE FROM sessions WHERE admin_id=?", (admin_id,))
            self.log(
                db,
                actor,
                "admin_changed",
                json.dumps(
                    {
                        "username": row["username"],
                        "enabled": enabled,
                        "password_reset": bool(hashed),
                    }
                ),
            )
            db.commit()

    def login(self, username, password, address):
        username = username.lower()
        now = time.time()
        keys = [digest("ip:" + address), digest("user:" + username)]
        with self.connect() as db:
            limited = any(
                db.execute(
                    "SELECT 1 FROM attempts WHERE key=? AND failures>=10 AND expires>?",
                    (key, now),
                ).fetchone()
                for key in keys
            )
            if limited:
                raise ValueError(
                    "試行回数が多いため、15分ほど待ってから再試行してください。"
                )
            row = db.execute(
                "SELECT * FROM admins WHERE username=?", (username,)
            ).fetchone()
        valid = False
        try:
            valid = HASHER.verify(
                row["password_hash"] if row else self.dummy_hash, password
            )
        except (VerificationError, InvalidHashError):
            pass
        if not row or not row["enabled"] or not valid:
            with self.connect() as db:
                for key in keys:
                    db.execute(
                        """INSERT INTO attempts(key,failures,expires) VALUES(?,1,?)
                        ON CONFLICT(key) DO UPDATE SET failures=CASE WHEN attempts.expires<? THEN 1 ELSE attempts.failures+1 END,
                        expires=CASE WHEN attempts.expires<? THEN excluded.expires ELSE attempts.expires END""",
                        (key, now + 900, now, now),
                    )
                self.log(db, "anonymous", "login_failed")
                db.commit()
            raise ValueError("IDまたはパスワードが正しくありません。")
        token = secrets.token_urlsafe(48)
        csrf = secrets.token_urlsafe(32)
        with self.connect() as db:
            # Recheck after the expensive hash verification: disabling/resetting revokes in-flight logins too.
            current = db.execute(
                "SELECT enabled,version FROM admins WHERE id=?", (row["id"],)
            ).fetchone()
            if not current["enabled"] or current["version"] != row["version"]:
                raise ValueError("IDまたはパスワードが正しくありません。")
            if HASHER.check_needs_rehash(row["password_hash"]):
                db.execute(
                    "UPDATE admins SET password_hash=? WHERE id=?",
                    (HASHER.hash(password), row["id"]),
                )
            db.execute("DELETE FROM sessions WHERE expires<?", (now,))
            db.execute(
                "INSERT INTO sessions VALUES(?,?,?,?,?)",
                (digest(token), row["id"], row["version"], csrf, now + 28800),
            )
            for key in keys:
                db.execute("DELETE FROM attempts WHERE key=?", (key,))
            self.log(db, row["username"], "login")
            db.commit()
        return token

    def session(self, token):
        if not token:
            return None
        with self.connect() as db:
            row = db.execute(
                """SELECT admins.id,admins.username,admins.display_name,sessions.csrf
                FROM sessions JOIN admins ON admins.id=sessions.admin_id
                WHERE token_hash=? AND expires>? AND admins.enabled=1 AND admins.version=sessions.version""",
                (digest(token), time.time()),
            ).fetchone()
        return dict(row) if row else None

    def logout(self, token):
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (digest(token),))
            db.commit()

    def audit_list(self):
        with self.connect() as db:
            return [
                dict(r)
                for r in db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100")
            ]
