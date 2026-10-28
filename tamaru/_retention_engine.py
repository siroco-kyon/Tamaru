"""Dormant retention implementation. Only isolated tests call this engine.

Normal app construction, collection, CLI and settings never instantiate it.
Enabling deletion requires a future source change and deployment review.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time

from .inventory import BASE, DAY, ScanLock, is_link, path_key, within
from ._retention_files import _WindowsFiles, UnsafeRetentionOperation


@dataclass(frozen=True)
class RetentionPolicy:
    retention_days: int = 30
    quarantine_days: int = 7
    max_files: int = 100
    max_bytes: int = 10 * 1024**3
    freshness_seconds: int = 36 * 3600
    plan_seconds: int = 15 * 60

    def __post_init__(self):
        if (
            self.retention_days < 30
            or self.quarantine_days < 7
            or self.max_files < 1
            or self.max_bytes < 1
            or not 1 <= self.freshness_seconds <= 36 * 3600
            or not 1 <= self.plan_seconds <= 15 * 60
        ):
            raise ValueError("保持期間・退避期間・処理上限が範囲外です。")


class _RetentionEngine:
    def __init__(self, inventory, store, quarantine, *, policy=None, clock=time.time):
        self.inventory = inventory
        self.store = store
        if not Path(quarantine).is_absolute():
            raise UnsafeRetentionOperation("退避先は絶対パスで指定してください。")
        self.quarantine = Path(quarantine).absolute()
        self.policy = policy or RetentionPolicy()
        self.clock = clock
        self.files = _WindowsFiles()
        self.db_path = inventory.state / "retention.sqlite3"
        self._validate_quarantine()
        with self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS observations(
                    root_id INTEGER NOT NULL,key TEXT NOT NULL,fingerprint TEXT NOT NULL,
                    stable_since REAL NOT NULL,observed REAL NOT NULL,
                    PRIMARY KEY(root_id,key));
                CREATE TABLE IF NOT EXISTS plans(
                    id TEXT PRIMARY KEY,created REAL NOT NULL,status TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS plan_files(
                    plan TEXT NOT NULL,root_id INTEGER NOT NULL,key TEXT NOT NULL,
                    path TEXT NOT NULL,root TEXT NOT NULL,fingerprint TEXT NOT NULL,size INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS quarantine_files(
                    id TEXT PRIMARY KEY,plan TEXT NOT NULL,original_path TEXT NOT NULL,
                    path TEXT NOT NULL,fingerprint TEXT NOT NULL,size INTEGER NOT NULL,
                    moved REAL NOT NULL,status TEXT NOT NULL,error TEXT NOT NULL DEFAULT '');
            """)

    @contextlib.contextmanager
    def _db(self):
        db = sqlite3.connect(self.db_path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def _validate_quarantine(self):
        if not self.quarantine.is_absolute():
            raise UnsafeRetentionOperation("退避先は絶対パスで指定してください。")
        for root in self.inventory.config()["targets"]:
            if within(root, self.quarantine) or within(self.quarantine, root):
                raise UnsafeRetentionOperation("退避先と収集対象は重ねられません。")
        if within(self.quarantine, BASE) or within(BASE, self.quarantine):
            raise UnsafeRetentionOperation("ツール本体を退避先にできません。")
        for parent in [self.quarantine, *self.quarantine.parents]:
            if os.path.lexists(parent) and is_link(parent.lstat()):
                raise UnsafeRetentionOperation(
                    "退避先にリンク・再解析ポイントを使用できません。"
                )

    def _current(self, db, row, now):
        roots = self.inventory.selected_roots(db)
        if not any(r["id"] == row["root_id"] for r in roots):
            return None
        return db.execute(
            """SELECT f.*,r.path AS root FROM files f JOIN roots r ON r.id=f.root_id
            WHERE f.root_id=? AND f.key=? AND f.present=1 AND r.status='完了'
            AND f.seen_run=r.latest_run AND f.last_seen>=? AND f.last_seen<=?
            AND f.first_seen<=?""",
            (
                row["root_id"],
                row["key"],
                now - self.policy.freshness_seconds,
                now,
                now - self.policy.retention_days * DAY,
            ),
        ).fetchone()

    def observe(self):
        """Future opt-in baseline. No content reads; identity changes restart 30 days."""
        now = self.clock()
        with (
            ScanLock(self.inventory.state / "scan.lock"),
            contextlib.closing(self.inventory.connect()) as source,
            self._db() as db,
        ):
            roots = self.inventory.selected_roots(source)
            ids = [r["id"] for r in roots]
            placeholders = ",".join("?" for _ in ids) or "NULL"
            rows = source.execute(
                f"""SELECT f.*,r.path AS root FROM files f JOIN roots r ON r.id=f.root_id
                WHERE f.present=1 AND f.root_id IN ({placeholders}) AND r.status='完了'
                AND f.seen_run=r.latest_run AND f.last_seen>=? AND f.last_seen<=?""",
                [*ids, now - self.policy.freshness_seconds, now],
            )
            db.execute(
                "CREATE TEMP TABLE observed(root_id INTEGER,key TEXT,PRIMARY KEY(root_id,key))"
            )
            count = 0
            for row in rows:
                try:
                    fingerprint = self.files.snapshot(row["path"], row["root"])
                except (OSError, ValueError):
                    continue
                encoded = json.dumps(fingerprint, sort_keys=True)
                db.execute(
                    """INSERT INTO observations VALUES(?,?,?,?,?)
                    ON CONFLICT(root_id,key) DO UPDATE SET
                    stable_since=CASE WHEN observations.fingerprint<>excluded.fingerprint
                        OR observations.observed<? OR observations.observed>? THEN excluded.stable_since ELSE observations.stable_since END,
                    fingerprint=excluded.fingerprint,observed=excluded.observed""",
                    (
                        row["root_id"],
                        row["key"],
                        encoded,
                        now,
                        now,
                        now - self.policy.freshness_seconds,
                        now,
                    ),
                )
                db.execute(
                    "INSERT INTO observed VALUES(?,?)", (row["root_id"], row["key"])
                )
                count += 1
            db.execute(
                "DELETE FROM observations WHERE NOT EXISTS(SELECT 1 FROM observed x WHERE x.root_id=observations.root_id AND x.key=observations.key)"
            )
            return count

    def prepare(self, actor):
        now = self.clock()
        cutoff = now - self.policy.retention_days * DAY
        plan = secrets.token_hex(16)
        with (
            ScanLock(self.inventory.state / "scan.lock"),
            contextlib.closing(self.inventory.connect()) as source,
            self._db() as db,
        ):
            rows = db.execute(
                "SELECT * FROM observations WHERE stable_since<=? AND observed>=? AND observed<=?",
                (cutoff, now - self.policy.freshness_seconds, now),
            )
            selected = []
            total = 0
            for old in rows:
                current = self._current(source, old, now)
                if not current:
                    continue
                try:
                    live = self.files.snapshot(current["path"], current["root"])
                except (OSError, ValueError):
                    continue
                if json.dumps(live, sort_keys=True) != old["fingerprint"]:
                    continue
                selected.append(
                    (
                        plan,
                        old["root_id"],
                        old["key"],
                        current["path"],
                        current["root"],
                        old["fingerprint"],
                        live["size"],
                    )
                )
                total += live["size"]
                if (
                    len(selected) > self.policy.max_files
                    or total > self.policy.max_bytes
                ):
                    raise UnsafeRetentionOperation(
                        "候補が件数・容量の上限を超えています。"
                    )
            db.execute("INSERT INTO plans VALUES(?,?,'prepared')", (plan, now))
            db.executemany("INSERT INTO plan_files VALUES(?,?,?,?,?,?,?)", selected)
        self.store.audit(actor, "retention_plan_prepared", plan)
        return {"id": plan, "count": len(selected), "bytes": total}

    def quarantine_plan(self, plan, actor):
        with ScanLock(self.inventory.state / "scan.lock"):
            return self._quarantine_plan_locked(plan, actor)

    def _quarantine_plan_locked(self, plan, actor):
        now = self.clock()
        self._validate_quarantine()
        with self._db() as db:
            header = db.execute("SELECT * FROM plans WHERE id=?", (plan,)).fetchone()
            if (
                not header
                or header["status"] != "prepared"
                or not 0 <= now - header["created"] <= self.policy.plan_seconds
            ):
                raise UnsafeRetentionOperation(
                    "候補一覧が無効・期限切れ・実行済みです。"
                )
            rows = list(db.execute("SELECT * FROM plan_files WHERE plan=?", (plan,)))
            if (
                len(rows) > self.policy.max_files
                or sum(r["size"] for r in rows) > self.policy.max_bytes
            ):
                raise UnsafeRetentionOperation("処理上限を超えています。")
            db.execute("UPDATE plans SET status='started' WHERE id=?", (plan,))
        moved = skipped = 0
        for row in rows:
            item = secrets.token_hex(16)
            destination = self.quarantine / item / "payload"
            expected = json.loads(row["fingerprint"])
            try:
                with (
                    contextlib.closing(self.inventory.connect()) as source,
                    self._db() as db,
                ):
                    current = self._current(source, row, self.clock())
                    observed = db.execute(
                        "SELECT * FROM observations WHERE root_id=? AND key=?",
                        (row["root_id"], row["key"]),
                    ).fetchone()
                    if (
                        not current
                        or not observed
                        or observed["stable_since"]
                        > now - self.policy.retention_days * DAY
                        or observed["fingerprint"] != row["fingerprint"]
                    ):
                        raise UnsafeRetentionOperation("現在の記録を確認できません。")
                self.quarantine.mkdir(parents=True, exist_ok=True)
                self._validate_quarantine()
                destination.parent.mkdir()  # Unique directory; never merge/overwrite.
                self.store.audit(actor, "retention_move_started", item)
                with self._db() as db:
                    db.execute(
                        "INSERT INTO quarantine_files(id,plan,original_path,path,fingerprint,size,moved,status) VALUES(?,?,?,?,?,?,?,'moving')",
                        (
                            item,
                            plan,
                            row["path"],
                            str(destination),
                            row["fingerprint"],
                            row["size"],
                            now,
                        ),
                    )
                self.files.move(row["path"], destination, row["root"], expected)
                with self._db() as db:
                    db.execute(
                        "UPDATE quarantine_files SET status='held',moved=? WHERE id=?",
                        (self.clock(), item),
                    )
                self.store.audit(actor, "retention_moved", item)
                moved += 1
            except (OSError, ValueError) as exc:
                # Ambiguous/interrupted moves never enter the purge queue.
                with self._db() as db:
                    db.execute(
                        "UPDATE quarantine_files SET status='review',error=? WHERE id=?",
                        (str(exc), item),
                    )
                self.store.audit(
                    actor, "retention_move_skipped", item + ": " + str(exc)
                )
                skipped += 1
        with self._db() as db:
            db.execute("UPDATE plans SET status='finished' WHERE id=?", (plan,))
        return {"moved": moved, "skipped": skipped}

    def purge_due(self, actor):
        self._validate_quarantine()
        now = self.clock()
        with ScanLock(self.inventory.state / "scan.lock"), self._db() as db:
            rows = list(
                db.execute(
                    "SELECT * FROM quarantine_files WHERE status='held' AND moved<=? LIMIT ?",
                    (
                        now - self.policy.quarantine_days * DAY,
                        self.policy.max_files + 1,
                    ),
                )
            )
            if (
                len(rows) > self.policy.max_files
                or sum(r["size"] for r in rows) > self.policy.max_bytes
            ):
                raise UnsafeRetentionOperation("完全削除の処理上限を超えています。")
            purged = skipped = 0
            for row in rows:
                expected_path = self.quarantine / row["id"] / "payload"
                try:
                    if path_key(row["path"]) != path_key(expected_path):
                        raise UnsafeRetentionOperation("退避台帳のパスが一致しません。")
                    self.store.audit(actor, "retention_purge_started", row["id"])
                    db.execute(
                        "UPDATE quarantine_files SET status='purging' WHERE id=?",
                        (row["id"],),
                    )
                    db.commit()  # Crash after this point requires manual review, never automatic replay.
                    self.files.purge(
                        expected_path, self.quarantine, json.loads(row["fingerprint"])
                    )
                    db.execute(
                        "UPDATE quarantine_files SET status='purged' WHERE id=?",
                        (row["id"],),
                    )
                    db.commit()
                    self.store.audit(actor, "retention_purged", row["id"])
                    purged += 1
                except (OSError, ValueError) as exc:
                    db.execute(
                        "UPDATE quarantine_files SET status='review',error=? WHERE id=?",
                        (str(exc), row["id"]),
                    )
                    db.commit()
                    self.store.audit(
                        actor, "retention_purge_skipped", row["id"] + ": " + str(exc)
                    )
                    skipped += 1
            return {"purged": purged, "skipped": skipped}
