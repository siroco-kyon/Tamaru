import contextlib
import datetime as dt
import os
from pathlib import Path

import pytest

from tamaru.inventory import Inventory, ScanLock, path_key
from tamaru.jobs import Collector
from tamaru.reports import JST, daily_trends, storage_usage
from tamaru.security import Store


def at(day, hour=10):
    return dt.datetime(2026, 10, day, hour, tzinfo=JST).timestamp()


@pytest.fixture
def inventory(tmp_path):
    inv = Inventory(tmp_path / "state")
    roots = [tmp_path / "first", tmp_path / "second"]
    for path in roots:
        path.mkdir()
    inv.save_targets([str(path) for path in roots])
    with contextlib.closing(inv.connect()) as db:
        db.executemany(
            "INSERT INTO roots(id,path,key) VALUES(?,?,?)",
            [(i, str(path), path_key(path)) for i, path in enumerate(roots, 1)],
        )
        db.commit()
    return inv


def run(inv, root, started, *, size, count=1, status="完了", finished=True):
    with contextlib.closing(inv.connect()) as db:
        db.execute(
            "INSERT INTO runs(root_id,started,finished,status,files,bytes) VALUES(?,?,?,?,?,?)",
            (root, started, started + 10 if finished else None, status, count, size),
        )
        db.commit()


def test_trends_last_good_same_batch_and_later_partial(inventory):
    for root, size in ((1, 10), (2, 20)):
        run(inventory, root, at(26), size=size)
    for root, size in ((1, 11), (2, 22)):
        run(inventory, root, at(27), size=size)
    run(inventory, 1, at(27, 12), size=15)
    run(inventory, 2, at(27, 12), size=5, status="一部未確認")
    run(inventory, 1, at(28), size=25)
    result = daily_trends(inventory, days=3, now=at(28, 14))
    assert [row["bytes"] for row in result["rows"]] == [30, 33, None]
    assert result["rows"][1]["delta_bytes"] == 3
    assert result["rows"][1]["warning"] is True
    assert result["rows"][2]["status"] != "完了"
    individual = daily_trends(inventory, root_id=1, days=3, now=at(28, 14))
    assert [row["bytes"] for row in individual["rows"]] == [10, 15, 25]
    assert individual["rows"][1]["warning"] is False


def test_trends_gap_zero_and_japan_date(inventory):
    run(inventory, 1, at(26), size=12, count=3)
    # UTC October 27 at 15:00 is October 28 in Japan.
    midnight = dt.datetime(2026, 10, 27, 15, tzinfo=dt.timezone.utc).timestamp()
    run(inventory, 1, midnight, size=0, count=0)
    rows = daily_trends(inventory, root_id=1, days=3, now=at(28, 14))["rows"]
    assert rows[1]["bytes"] is None and rows[1]["status"] == "未収集"
    assert rows[2]["date"] == "2026-10-28"
    assert rows[2]["bytes"] == 0 and rows[2]["count"] == 0
    assert rows[2]["delta_bytes"] == -12 and rows[2]["delta_count"] == -3
    assert rows[2]["comparison_days"] == 2


def test_trends_do_not_mix_scans_or_unfinished_and_future_runs(inventory):
    run(inventory, 1, at(27), size=10)
    run(inventory, 2, at(27) + 1, size=20)
    run(inventory, 1, at(28), size=100, finished=False)
    run(inventory, 1, at(28, 18), size=500)
    rows = daily_trends(inventory, days=2, now=at(28, 14))["rows"]
    assert all(row["bytes"] is None for row in rows)
    assert (
        daily_trends(inventory, root_id=1, days=2, now=at(28, 14))["rows"][0]["bytes"]
        == 10
    )


def test_trends_validate_and_filter_current_roots(inventory):
    for days in (0, 367):
        with pytest.raises(ValueError):
            daily_trends(inventory, days=days)
    with pytest.raises(ValueError):
        daily_trends(inventory, root_id=999)
    run(inventory, 1, at(28), size=10)
    run(inventory, 2, at(28), size=20)
    inventory.save_targets([inventory.config()["targets"][0]])
    assert daily_trends(inventory, days=1, now=at(28, 14))["rows"][0]["bytes"] == 10
    inventory.save_targets([])
    assert daily_trends(inventory, days=1, now=at(28, 14))["rows"][0]["bytes"] is None


def collector_for(inv):
    return Collector(inv, Store(inv.state))


def test_collect_and_restart_discard_only_staging_database(inventory):
    path = inventory.config()["targets"][0]
    (Path(path) / "file.txt").write_bytes(b"keep watched file")
    collector = collector_for(inventory)
    assert collector.request("test")
    collector.thread.join(10)
    assert not collector.running and collector.store.get("last_job")["status"] == "完了"
    assert not (inventory.state / "staging/inventory.sqlite3").exists()
    assert inventory.listing({})["count"] == 1
    first = inventory.listing({})["rows"][0]["first_seen"]
    with contextlib.closing(inventory.connect()) as db:
        source_runs = db.execute("SELECT count(*) FROM runs").fetchone()[0]
    staging = Inventory(inventory.state / "staging")
    with (
        contextlib.closing(inventory.connect()) as source,
        contextlib.closing(staging.connect()) as dest,
    ):
        source.backup(dest)
    unrelated = staging.state / "user-note.txt"
    unrelated.write_text("preserve")
    assert storage_usage(inventory)["staging_bytes"] > 0
    collector.recover()
    assert storage_usage(inventory)["staging_bytes"] == 0
    assert unrelated.read_text() == "preserve"
    assert inventory.listing({})["rows"][0]["first_seen"] == first
    with contextlib.closing(inventory.connect()) as db:
        assert db.execute("SELECT count(*) FROM runs").fetchone()[0] == source_runs
    assert collector.request("test")
    collector.thread.join(10)
    assert inventory.listing({})["count"] == 1
    assert not (inventory.state / "staging/inventory.sqlite3").exists()


def test_staging_cleanup_defers_when_locked(inventory):
    staging = Inventory(inventory.state / "staging")
    collector = collector_for(inventory)
    with ScanLock(staging.state / "scan.lock"):
        collector.recover()
        assert staging.db_path.exists() and collector.storage_warning
    collector.recover()
    assert not staging.db_path.exists() and not collector.storage_warning


def test_failed_scan_cleans_staging_preserves_published_result(inventory, monkeypatch):
    source = Path(inventory.config()["targets"][0]) / "original.txt"
    source.write_text("published observation")
    inventory.scan()
    first = inventory.listing({})["rows"][0]["first_seen"]
    collector = collector_for(inventory)

    def failed(self, *args, **kwargs):
        raise OSError("simulated failure")

    monkeypatch.setattr(Inventory, "scan", failed)
    assert collector.request("test")
    collector.thread.join(10)
    assert collector.store.get("last_job")["status"] == "失敗"
    assert inventory.listing({})["count"] == 1
    assert inventory.listing({})["rows"][0]["first_seen"] == first
    assert source.read_text() == "published observation"
    assert not (inventory.state / "staging/inventory.sqlite3").exists()


def test_staging_junction_never_writes_or_deletes_outside(inventory, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    protected = outside / "inventory.sqlite3"
    protected.write_bytes(b"not a disposable database")
    link = inventory.state / "staging"
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(outside), str(link))
    else:
        link.symlink_to(outside, target_is_directory=True)
    try:
        collector = collector_for(inventory)
        collector.recover()
        assert collector.storage_warning
        assert collector.request("test")
        collector.thread.join(10)
        assert collector.store.get("last_job")["status"] == "失敗"
        assert protected.read_bytes() == b"not a disposable database"
    finally:
        link.rmdir() if os.name == "nt" else link.unlink()
