"""Metadata-only folder inventory. Never modifies watched files."""

from __future__ import annotations

import contextlib
import csv
import ctypes
import datetime as dt
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import threading
import time

from . import __version__

DAY = 86400
BASE = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent.parent
)


def path_key(path):
    value = os.path.normpath(os.path.abspath(os.fspath(path)))
    return os.path.normcase(value)


def within(child, parent):
    try:
        return os.path.commonpath([path_key(child), path_key(parent)]) == path_key(
            parent
        )
    except ValueError:
        return False


def stamp(value):
    return (
        dt.datetime.fromtimestamp(value, dt.timezone.utc)
        .astimezone()
        .isoformat(timespec="seconds")
        if value is not None
        else ""
    )


def is_link(info):
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x400
    )


class ScanLock:
    def __init__(self, path):
        self.path = path
        self.file = None

    def __enter__(self):
        self.file = open(self.path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt

                self.file.seek(0, 2)
                if not self.file.tell():
                    self.file.write(b"0")
                    self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            self.file = None
            raise RuntimeError("別の走査が実行中です。終了後に再実行してください。")
        return self

    def __exit__(self, *args):
        if self.file:
            self.file.close()


class Inventory:
    def __init__(self, state):
        self.state = Path(state).absolute()
        if os.name == "nt":
            anchor = self.state.anchor
            if (
                str(self.state).startswith("\\\\")
                or ctypes.windll.kernel32.GetDriveTypeW(str(anchor)) == 4
            ):
                raise ValueError(
                    "管理データは共有ドライブではなく、実行PCのローカルドライブへ保存してください。"
                )
        self.state.mkdir(parents=True, exist_ok=True)
        self.db_path = self.state / "inventory.sqlite3"
        self.config_path = self.state / "settings.json"
        self.mutex = threading.Lock()
        self.progress_lock = threading.Lock()
        self.progress = {
            "running": False,
            "files": 0,
            "current": "",
            "message": "待機中",
        }
        with contextlib.closing(self.connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS roots(
                    id INTEGER PRIMARY KEY, path TEXT NOT NULL, key TEXT NOT NULL UNIQUE,
                    latest_run INTEGER, last_complete REAL, status TEXT NOT NULL DEFAULT '未走査');
                CREATE TABLE IF NOT EXISTS runs(
                    id INTEGER PRIMARY KEY, root_id INTEGER NOT NULL, started REAL NOT NULL,
                    finished REAL, status TEXT NOT NULL, files INTEGER NOT NULL DEFAULT 0,
                    bytes INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0,
                    skipped INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS files(
                    root_id INTEGER NOT NULL, key TEXT NOT NULL, path TEXT NOT NULL,
                    relative_path TEXT NOT NULL, parent TEXT NOT NULL, name TEXT NOT NULL,
                    size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
                    first_seen REAL NOT NULL, last_seen REAL NOT NULL, seen_run INTEGER NOT NULL,
                    present INTEGER NOT NULL DEFAULT 1, missing_run INTEGER,
                    PRIMARY KEY(root_id, key));
                CREATE INDEX IF NOT EXISTS ix_files_age ON files(present,first_seen);
                CREATE INDEX IF NOT EXISTS ix_files_parent ON files(root_id,present,parent);
                CREATE TABLE IF NOT EXISTS errors(
                    id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, path TEXT NOT NULL,
                    message TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS ix_errors_run ON errors(run_id);
            """)
            # Serialize schema checks so concurrent startup cannot add a column twice.
            db.execute("BEGIN IMMEDIATE")
            if "missing_run" not in {
                r[1] for r in db.execute("PRAGMA table_info(files)")
            }:
                db.execute("ALTER TABLE files ADD COLUMN missing_run INTEGER")
            db.commit()
            try:
                with ScanLock(self.state / "scan.lock"):
                    db.execute("UPDATE roots SET status='中断' WHERE status='走査中'")
                    db.execute(
                        "UPDATE runs SET status='中断',finished=? WHERE status='走査中'",
                        (time.time(),),
                    )
                    db.commit()
            except RuntimeError:
                pass

    def connect(self):
        db = sqlite3.connect(self.db_path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=30000")
        return db

    def config(self):
        if self.config_path.exists():
            result = json.loads(self.config_path.read_text(encoding="utf-8"))
            return {"targets": result.get("targets", [])}
        return {"targets": []}

    def save_targets(self, targets):
        if (
            not isinstance(targets, list)
            or len(targets) > 100
            or any(not isinstance(p, str) for p in targets)
        ):
            raise ValueError("対象フォルダを100件以内で指定してください。")
        clean = []
        for raw in targets:
            raw = raw.strip()
            if not raw:
                continue
            if not os.path.isabs(raw):
                raise ValueError("対象は絶対パスで指定してください: " + raw)
            p = os.path.normpath(raw)
            # Never scan application/state ancestors. No watched content is modified.
            if (
                within(self.state, p)
                or within(p, self.state)
                or within(BASE, p)
                or within(p, BASE)
            ):
                raise ValueError(
                    "ツール本体・管理データと重なるフォルダは対象にできません: " + p
                )
            for previous in clean:
                if within(p, previous) or within(previous, p):
                    raise ValueError("対象フォルダが重複・包含しています: " + p)
            clean.append(p)
        with self.mutex:
            if self.progress["running"]:
                raise ValueError("走査中は設定を変更できません。")
            with ScanLock(self.state / "scan.lock"):
                tmp = self.config_path.with_suffix(".tmp")
                tmp.write_text(
                    json.dumps({"targets": clean}, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                os.replace(tmp, self.config_path)
        return self.config()

    def set_progress(self, **changes):
        with self.progress_lock:
            self.progress.update(changes)

    def start_scan(self):
        # Reserve before dispatch; a double click must not enqueue another scan.
        with self.mutex:
            if self.progress["running"]:
                raise ValueError("走査は既に実行中です。")
            if not self.config()["targets"]:
                raise ValueError("対象フォルダを設定してください。")
            self.set_progress(
                running=True, files=0, message="走査を開始しています", current=""
            )
        threading.Thread(
            target=self.scan, kwargs={"reserved": True}, daemon=True
        ).start()

    def scan(self, now=None, reserved=False):
        now = time.time() if now is None else now
        if not reserved:
            with self.mutex:
                if self.progress["running"]:
                    raise RuntimeError("走査は既に実行中です。")
                self.set_progress(running=True, files=0, current="", message="走査中")
        try:
            with ScanLock(self.state / "scan.lock"):
                targets = self.config()["targets"]
                if not targets:
                    raise ValueError("対象フォルダが未設定です。")
                total = 0
                all_complete = True
                for target in targets:
                    count, complete = self._scan_root(target, now, total)
                    total += count
                    all_complete &= complete
                self.set_progress(
                    files=total,
                    message="走査完了"
                    if all_complete
                    else "走査完了（一部未確認。エラーを確認してください）",
                )
                return all_complete
        except Exception as exc:
            self.set_progress(message="走査失敗: " + str(exc))
            if not reserved:
                raise
            return False
        finally:
            self.set_progress(running=False, current="")

    def _scan_root(self, target, now, base_count):
        db = self.connect()
        run_id = None
        try:
            db.execute(
                "INSERT INTO roots(path,key) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET path=excluded.path",
                (target, path_key(target)),
            )
            root_id = db.execute(
                "SELECT id FROM roots WHERE key=?", (path_key(target),)
            ).fetchone()[0]
            run_id = db.execute(
                "INSERT INTO runs(root_id,started,status) VALUES(?,?,'走査中')",
                (root_id, now),
            ).lastrowid
            db.execute(
                "UPDATE roots SET latest_run=?,status='走査中' WHERE id=?",
                (run_id, root_id),
            )
            db.commit()
            count = size = errors = skipped = 0
            batch = []

            def flush():
                if batch:
                    db.executemany(
                        """
                        INSERT INTO files(root_id,key,path,relative_path,parent,name,size,mtime_ns,first_seen,last_seen,seen_run,present)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,1)
                        ON CONFLICT(root_id,key) DO UPDATE SET
                          path=excluded.path, relative_path=excluded.relative_path,
                          parent=excluded.parent,name=excluded.name,size=excluded.size,
                          mtime_ns=excluded.mtime_ns,
                          first_seen=CASE WHEN files.present=0 THEN excluded.first_seen ELSE files.first_seen END,
                          last_seen=excluded.last_seen,
                          seen_run=excluded.seen_run,present=1,missing_run=NULL
                    """,
                        batch,
                    )
                    batch.clear()
                db.execute(
                    "UPDATE runs SET files=?,bytes=?,errors=?,skipped=? WHERE id=?",
                    (count, size, errors, skipped, run_id),
                )
                db.commit()
                self.set_progress(
                    files=base_count + count, current=target, message="走査中"
                )

            def failure(path, exc):
                nonlocal errors
                errors += 1
                db.execute(
                    "INSERT INTO errors(run_id,path,message) VALUES(?,?,?)",
                    (run_id, path, str(exc)),
                )

            # Check every ancestor to avoid traversing a junction embedded in the configured path.
            try:
                parts = [Path(target), *Path(target).parents]
                for part in parts:
                    if is_link(os.stat(part, follow_symlinks=False)):
                        raise OSError(
                            "対象パスにリンク／ジャンクションが含まれています。"
                        )
                if not stat.S_ISDIR(os.stat(target, follow_symlinks=False).st_mode):
                    raise OSError("対象はフォルダではありません。")
                stack = [target]
            except OSError as exc:
                failure(target, exc)
                stack = []
            while stack:
                folder = stack.pop()
                try:
                    # Recheck immediately before traversal; never intentionally follow links.
                    if is_link(os.stat(folder, follow_symlinks=False)):
                        skipped += 1
                        continue
                    with os.scandir(folder) as entries:
                        for entry in entries:
                            try:
                                info = entry.stat(follow_symlinks=False)
                                if is_link(info):
                                    skipped += 1
                                    continue
                                if stat.S_ISDIR(info.st_mode):
                                    stack.append(entry.path)
                                elif stat.S_ISREG(info.st_mode):
                                    batch.append(
                                        (
                                            root_id,
                                            path_key(entry.path),
                                            entry.path,
                                            os.path.relpath(entry.path, target),
                                            os.path.dirname(entry.path),
                                            entry.name,
                                            info.st_size,
                                            info.st_mtime_ns,
                                            now,
                                            now,
                                            run_id,
                                        )
                                    )
                                    count += 1
                                    size += info.st_size
                                    if len(batch) >= 500:
                                        flush()
                            except OSError as exc:
                                failure(entry.path, exc)
                except OSError as exc:
                    failure(folder, exc)
            flush()
            if errors == 0:
                db.execute(
                    "UPDATE files SET present=0,missing_run=? WHERE root_id=? AND seen_run<>? AND present=1",
                    (run_id, root_id, run_id),
                )
            status = "完了" if errors == 0 else "一部未確認"
            db.execute(
                "UPDATE runs SET finished=?,status=? WHERE id=?",
                (time.time(), status, run_id),
            )
            db.execute(
                "UPDATE roots SET status=?,last_complete=CASE WHEN ?=0 THEN ? ELSE last_complete END WHERE id=?",
                (status, errors, now, root_id),
            )
            db.commit()
            return count, errors == 0
        except BaseException:
            db.rollback()
            if run_id is not None:
                db.execute(
                    "UPDATE runs SET status='中断',finished=? WHERE id=?",
                    (time.time(), run_id),
                )
                db.execute(
                    "UPDATE roots SET status='中断' WHERE latest_run=?", (run_id,)
                )
                db.commit()
            raise
        finally:
            db.close()

    def selected_roots(self, db):
        keys = [path_key(p) for p in self.config()["targets"]]
        if not keys:
            return []
        return list(
            db.execute(
                "SELECT * FROM roots WHERE key IN ("
                + ",".join("?" for _ in keys)
                + ") ORDER BY path",
                keys,
            )
        )

    def where(self, db, params, now):
        missing = params.get("mode") == "missing"
        roots = [r["id"] for r in self.selected_roots(db)]
        clause = (
            f"f.present={0 if missing else 1} AND f.root_id IN ("
            + (",".join("?" for _ in roots) or "NULL")
            + ")"
        )
        values = roots[:]
        if missing:
            clause += """ AND EXISTS(SELECT 1 FROM roots mr JOIN runs m ON m.id=mr.latest_run
                WHERE mr.id=f.root_id AND mr.latest_run=f.missing_run
                AND mr.status='完了' AND m.status='完了' AND m.finished IS NOT NULL)"""
        root = params.get("root", "")
        if root:
            clause += " AND f.root_id=?"
            values.append(int(root))
        query = params.get("q", "").strip()
        if query:
            clause += " AND instr(lower(f.path),lower(?))>0"
            values.append(query)
        age = max(0, min(365000, int(params.get("age", "0") or 0)))
        if age and not missing:
            clause += " AND f.first_seen<=?"
            values.append(now - age * DAY)
        folder = params.get("folder", "")
        if folder and not missing:
            if params.get("recursive") == "1":
                clause += " AND (f.parent=? OR substr(f.path,1,length(?))=?)"
                prefix = folder.rstrip(os.sep) + os.sep
                values.extend([folder, prefix, prefix])
            else:
                clause += " AND f.parent=?"
                values.append(folder)
        return clause, values

    def summary(self):
        now = time.time()
        with contextlib.closing(self.connect()) as db:
            db.execute("BEGIN")
            roots = self.selected_roots(db)
            clause, args = self.where(db, {}, now)
            totals = dict(
                db.execute(
                    f"""SELECT count(*) AS count,coalesce(sum(f.size),0) AS bytes,
                coalesce(sum(CASE WHEN f.first_seen<=? THEN 1 ELSE 0 END),0) AS aged,
                coalesce(max(cast(max(0,(?-f.first_seen)/86400) AS INTEGER)),0) AS max_age,
                coalesce(sum(CASE WHEN f.seen_run<>r.latest_run OR r.status NOT IN ('完了','一部未確認') THEN 1 ELSE 0 END),0) AS uncertain
                FROM files f JOIN roots r ON r.id=f.root_id WHERE {clause}""",
                    [now - 30 * DAY, now, *args],
                ).fetchone()
            )
            recent = [
                dict(row)
                for row in db.execute(
                    "SELECT runs.*,roots.path FROM runs JOIN roots ON roots.id=runs.root_id ORDER BY runs.id DESC LIMIT 20"
                )
            ]
            error_rows = [
                dict(row)
                for row in db.execute(
                    "SELECT errors.* FROM errors JOIN roots ON roots.latest_run=errors.run_id ORDER BY errors.id DESC LIMIT 100"
                )
            ]
        with self.progress_lock:
            progress = self.progress.copy()
        return {
            "version": __version__,
            "totals": totals,
            "roots": [dict(r) for r in roots],
            "runs": recent,
            "errors": error_rows,
            "progress": progress,
            "state": str(self.state),
            "now": now,
        }

    def listing(self, params, now=None):
        now = time.time() if now is None else now
        page = max(1, min(10000000, int(params.get("page", "1"))))
        limit = max(10, min(200, int(params.get("limit", "100"))))
        mode = params.get("mode", "files")
        comparisons = []
        with contextlib.closing(self.connect()) as db:
            db.execute("BEGIN")
            clause, args = self.where(db, params, now)
            if mode == "missing":
                for root in self.selected_roots(db):
                    if params.get("root") and root["id"] != int(params["root"]):
                        continue
                    run = db.execute(
                        "SELECT started,status FROM runs WHERE id=?",
                        (root["latest_run"],),
                    ).fetchone()
                    comparisons.append(
                        {
                            "path": root["path"],
                            "status": root["status"],
                            "observed_at": run["started"] if run else None,
                        }
                    )
            if mode == "folders":
                count = db.execute(
                    f"SELECT count(*) FROM (SELECT f.root_id,f.parent FROM files f WHERE {clause} GROUP BY f.root_id,f.parent)",
                    args,
                ).fetchone()[0]
                order = {
                    "size": "bytes DESC,parent",
                    "count": "count DESC,parent",
                    "path": "parent",
                    "age": "first_seen,parent",
                }.get(params.get("sort"), "bytes DESC,parent")
                rows = [
                    dict(r)
                    for r in db.execute(
                        f"""SELECT f.root_id,f.parent,count(*) AS count,sum(f.size) AS bytes,
                    min(f.first_seen) AS first_seen,
                    sum(CASE WHEN f.seen_run<>r.latest_run OR r.status NOT IN ('完了','一部未確認') THEN 1 ELSE 0 END) AS uncertain
                    FROM files f JOIN roots r ON r.id=f.root_id WHERE {clause}
                    GROUP BY f.root_id,f.parent ORDER BY {order} LIMIT ? OFFSET ?""",
                        [*args, limit, (page - 1) * limit],
                    )
                ]
            else:
                count = db.execute(
                    f"SELECT count(*) FROM files f WHERE {clause}", args
                ).fetchone()[0]
                order = {
                    "age": "f.first_seen,f.path",
                    "size": "f.size DESC,f.path",
                    "path": "f.path",
                    "seen": "f.last_seen DESC,f.path",
                }.get(params.get("sort"), "f.first_seen,f.path")
                rows = [
                    dict(r)
                    for r in db.execute(
                        f"""SELECT f.*,r.path AS root_path,
                    m.started AS missing_at,
                    CASE WHEN f.present=0 THEN '今回見つからず' WHEN f.seen_run=r.latest_run AND r.status IN ('完了','一部未確認') THEN '確認済み' ELSE '未確認' END AS status
                    FROM files f JOIN roots r ON r.id=f.root_id
                    LEFT JOIN runs m ON m.id=f.missing_run WHERE {clause}
                    ORDER BY {order} LIMIT ? OFFSET ?""",
                        [*args, limit, (page - 1) * limit],
                    )
                ]
        for row in rows:
            row["age"] = max(0, int((now - row["first_seen"]) / DAY))
        return {
            "rows": rows,
            "count": count,
            "page": page,
            "limit": limit,
            "mode": mode,
            "comparisons": comparisons,
        }

    def browse(self, params, now=None):
        """List one directory level using stored metadata, with subtree totals."""
        now = time.time() if now is None else now
        page = max(1, min(10000000, int(params.get("page", "1"))))
        limit = max(10, min(200, int(params.get("limit", "100"))))
        root_id = int(params["root"]) if params.get("root") else None
        folder = params.get("folder", "")
        breadcrumbs = []
        with contextlib.closing(self.connect()) as db:
            db.execute("BEGIN")
            roots = self.selected_roots(db)
            root = next((r for r in roots if r["id"] == root_id), None)
            if root_id is not None and root is None:
                raise ValueError(
                    "対象フォルダが見つかりません。表示を更新してください。"
                )
            if folder and root is None:
                raise ValueError("対象フォルダを指定してください。")
            if root:
                folder = os.path.normpath(folder or root["path"])
                if not os.path.isabs(folder) or not within(folder, root["path"]):
                    raise ValueError("対象フォルダの範囲外です。")
                # Use the configured root's spelling for case-insensitive Windows paths.
                relative = os.path.relpath(folder, root["path"])
                folder = os.path.join(root["path"], relative)
                folder = os.path.normpath(folder)
                current = root["path"]
                breadcrumbs.append(
                    {"name": os.path.basename(current) or current, "path": current}
                )
                if relative != ".":
                    for part in relative.split(os.sep):
                        current = os.path.join(current, part)
                        breadcrumbs.append({"name": part, "path": current})
            scoped = {**params, "folder": folder, "recursive": "1"}
            clause, args = self.where(db, scoped, now)
            metrics = """count(*) AS count,sum(f.size) AS bytes,
                min(f.first_seen) AS first_seen,max(f.last_seen) AS last_seen,
                sum(CASE WHEN f.seen_run<>r.latest_run OR r.status NOT IN ('完了','一部未確認') THEN 1 ELSE 0 END) AS uncertain"""
            if root is None:
                folders = [
                    {
                        **dict(row),
                        "kind": "folder",
                        "name": os.path.basename(row["path"]) or row["path"],
                    }
                    for row in db.execute(
                        f"""SELECT f.root_id,r.path,{metrics}
                        FROM files f JOIN roots r ON r.id=f.root_id
                        WHERE {clause} GROUP BY f.root_id""",
                        args,
                    )
                ]
                direct = None
            else:
                prefix = folder.rstrip(os.sep) + os.sep
                # Native SQLite string operations avoid a Python callback per file.
                groups = list(
                    db.execute(
                        f"""SELECT CASE WHEN f.parent=? THEN '' ELSE
                        substr(substr(f.path,?),1,instr(substr(f.path,?),?)-1) END AS child,
                        {metrics}
                        FROM files f JOIN roots r ON r.id=f.root_id
                        WHERE {clause} GROUP BY child""",
                        [folder, len(prefix) + 1, len(prefix) + 1, os.sep, *args],
                    )
                )
                direct = next((row for row in groups if row["child"] == ""), None)
                folders = [
                    {
                        **dict(row),
                        "kind": "folder",
                        "root_id": root_id,
                        "path": os.path.join(folder, row["child"]),
                        "name": row["child"],
                    }
                    for row in groups
                    if row["child"]
                ]
            sort = params.get("sort", "size")
            folders.sort(
                key=lambda row: (
                    -row["bytes"]
                    if sort == "size"
                    else row["first_seen"]
                    if sort == "age"
                    else path_key(row["path"]),
                    path_key(row["path"]),
                )
            )
            direct_count = direct["count"] if direct else 0
            count = len(folders) + direct_count
            totals = {
                "count": sum(row["count"] for row in folders) + direct_count,
                "bytes": sum(row["bytes"] for row in folders)
                + (direct["bytes"] if direct else 0),
                "uncertain": sum(row["uncertain"] for row in folders)
                + (direct["uncertain"] if direct else 0),
            }
            start = (page - 1) * limit
            rows = folders[start : start + limit]
            if direct_count and len(rows) < limit:
                order = {
                    "size": "f.size DESC,f.path",
                    "age": "f.first_seen,f.path",
                }.get(sort, "f.path")
                rows.extend(
                    {**dict(row), "kind": "file", "count": 1, "bytes": row["size"]}
                    for row in db.execute(
                        f"""SELECT f.*,CASE WHEN f.seen_run=r.latest_run AND r.status IN ('完了','一部未確認') THEN 0 ELSE 1 END AS uncertain
                        FROM files f JOIN roots r ON r.id=f.root_id
                        WHERE {clause} AND f.parent=? ORDER BY {order} LIMIT ? OFFSET ?""",
                        [
                            *args,
                            folder,
                            limit - len(rows),
                            max(0, start - len(folders)),
                        ],
                    )
                )
        for row in rows:
            row["age"] = max(0, int((now - row["first_seen"]) / DAY))
        return {
            "rows": rows,
            "count": count,
            "page": page,
            "limit": limit,
            "root_id": root_id,
            "folder": folder,
            "breadcrumbs": breadcrumbs,
            "totals": totals,
        }

    def csv_chunks(self, params):
        # Stream all filtered files; never build a full inventory in memory.
        missing = params.get("mode") == "missing"
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer)

        def line(values):
            buffer.seek(0)
            buffer.truncate(0)
            writer.writerow(
                [
                    ("'" + v)
                    if isinstance(v, str)
                    and (
                        v.lstrip().startswith(("=", "+", "-", "@"))
                        or v.startswith(("\t", "\r", "\n"))
                    )
                    else v
                    for v in values
                ]
            )
            return buffer.getvalue().encode("utf-8")

        yield b"\xef\xbb\xbf"
        yield line(
            [
                "対象フォルダ",
                "ファイルの場所",
                "ファイル名",
                "前回確認時の容量(bytes)" if missing else "容量(bytes)",
                "最終確認時点の滞留日数" if missing else "滞留日数",
                "初回検出日時",
                "最終確認日時",
                "元の更新日時",
                "確認状態",
            ]
            + (["見つからないことを確認した収集の開始日時"] if missing else [])
        )
        now = time.time()
        with contextlib.closing(self.connect()) as db:
            db.execute("BEGIN")
            clause, args = self.where(db, params, now)
            cursor = db.execute(
                f"""SELECT f.*,r.path AS root_path,
                m.started AS missing_at,
                CASE WHEN f.present=0 THEN '今回見つからず（削除・移動・名前変更等）' WHEN f.seen_run=r.latest_run AND r.status IN ('完了','一部未確認') THEN '確認済み' ELSE '未確認' END AS status
                FROM files f JOIN roots r ON r.id=f.root_id
                LEFT JOIN runs m ON m.id=f.missing_run WHERE {clause} ORDER BY f.first_seen,f.path""",
                args,
            )
            for row in cursor:
                yield line(
                    [
                        row["root_path"],
                        row["path"],
                        row["name"],
                        row["size"],
                        max(
                            0,
                            int(
                                (
                                    (row["last_seen"] if missing else now)
                                    - row["first_seen"]
                                )
                                / DAY
                            ),
                        ),
                        stamp(row["first_seen"]),
                        stamp(row["last_seen"]),
                        stamp(row["mtime_ns"] / 1e9),
                        row["status"],
                    ]
                    + ([stamp(row["missing_at"])] if missing else [])
                )
