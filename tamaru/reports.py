"""Small reports over existing data. No per-file daily snapshots are stored."""

from __future__ import annotations

import contextlib
import datetime as dt
import time
from zoneinfo import ZoneInfo

from .inventory import is_link

JST = ZoneInfo("Asia/Tokyo")


def daily_trends(inventory, *, root_id=None, days=30, now=None):
    if not 1 <= days <= 366:
        raise ValueError("期間は1〜366日で指定してください。")
    now = time.time() if now is None else now
    today = dt.datetime.fromtimestamp(now, JST).date()
    first = today - dt.timedelta(days=days - 1)
    since = dt.datetime.combine(first, dt.time(), JST).timestamp()
    with contextlib.closing(inventory.connect()) as db:
        db.execute("BEGIN")
        roots = inventory.selected_roots(db)
        ids = {r["id"] for r in roots}
        if root_id is not None:
            if root_id not in ids:
                raise ValueError("対象フォルダが見つかりません。")
            ids = {root_id}
        placeholders = ",".join("?" for _ in ids) or "NULL"
        # One scan uses the same 'started' timestamp for every root. Never mix
        # totals from different scans to manufacture an all-roots observation.
        runs = list(
            db.execute(
                f"""SELECT id,root_id,started,finished,status,files,bytes FROM runs
            WHERE root_id IN ({placeholders}) AND started>=? AND started<=?
            ORDER BY started,id""",
                [*sorted(ids), since, now],
            )
        )
    batches = {}
    for run in runs:
        batches.setdefault(run["started"], {})[run["root_id"]] = run
    latest = {}
    valid = {}
    for started, batch in batches.items():
        day = dt.datetime.fromtimestamp(started, JST).date().isoformat()
        complete = set(batch) == ids and all(
            r["status"] == "完了" and r["finished"] is not None and r["finished"] <= now
            for r in batch.values()
        )
        latest[day] = "完了" if complete else "一部未確認・失敗等"
        if complete:
            valid[day] = {
                "bytes": sum(r["bytes"] for r in batch.values()),
                "count": sum(r["files"] for r in batch.values()),
                "observed_at": started,
            }
    rows = []
    previous = None
    for offset in range(days):
        day = first + dt.timedelta(days=offset)
        key = day.isoformat()
        observation = valid.get(key)
        row = {
            "date": key,
            "bytes": None,
            "count": None,
            "observed_at": None,
            "delta_bytes": None,
            "delta_count": None,
            "comparison_days": None,
            "status": latest.get(key, "未収集"),
            "warning": False,
        }
        if observation:
            row.update(observation, status="完了", warning=latest[key] != "完了")
            if previous:
                row.update(
                    delta_bytes=row["bytes"] - previous["bytes"],
                    delta_count=row["count"] - previous["count"],
                    comparison_days=(
                        day - dt.date.fromisoformat(previous["date"])
                    ).days,
                )
            previous = row
        rows.append(row)
    return {
        "rows": rows,
        "days": days,
        "timezone": "Asia/Tokyo",
        "root_id": root_id,
        "roots": [{"id": r["id"], "path": r["path"]} for r in roots],
    }


def storage_usage(inventory):
    def size(path):
        try:
            return path.stat().st_size
        except FileNotFoundError:
            return 0

    databases = [inventory.db_path, inventory.state / "app.sqlite3"]
    database_bytes = sum(size(path) for path in databases)
    journal_bytes = sum(
        size(path.with_name(path.name + suffix))
        for path in databases
        for suffix in ("-wal", "-shm", "-journal")
    )
    staging = inventory.state / "staging"
    staging_bytes = 0
    if staging.exists() and not is_link(staging.lstat()):
        staging_bytes = sum(
            size(staging / ("inventory.sqlite3" + suffix))
            for suffix in ("", "-wal", "-shm", "-journal")
        )
    with contextlib.closing(inventory.connect()) as db:
        db.execute("BEGIN")
        file_records = db.execute("SELECT count(*) FROM files").fetchone()[0]
        free_bytes = (
            db.execute("PRAGMA freelist_count").fetchone()[0]
            * db.execute("PRAGMA page_size").fetchone()[0]
        )
    return {
        "database_bytes": database_bytes,
        "journal_bytes": journal_bytes,
        "staging_bytes": staging_bytes,
        "total_bytes": database_bytes + journal_bytes + staging_bytes,
        "file_records": file_records,
        "inventory_free_bytes": free_bytes,
    }
