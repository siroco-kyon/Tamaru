import contextlib
import csv
import io
import os
import sqlite3

import pytest

from tamaru.inventory import Inventory


@pytest.fixture
def sample(tmp_path):
    target = tmp_path / "shared"
    target.mkdir()
    inv = Inventory(tmp_path / "data")
    inv.save_targets([str(target)])
    return inv, target


def missing(inv, **params):
    return inv.listing({"mode": "missing", **params})


def test_missing_latest_only_and_reappearance(sample):
    inv, target = sample
    source = target / "report.txt"
    source.write_bytes(b"original")
    assert inv.scan(now=100)
    assert missing(inv)["count"] == 0
    source.unlink()
    assert inv.scan(now=200)
    row = missing(inv)["rows"][0]
    assert (row["name"], row["size"], row["last_seen"], row["missing_at"]) == (
        "report.txt",
        8,
        100,
        200,
    )
    assert inv.listing({})["count"] == 0
    assert inv.summary()["totals"]["bytes"] == 0
    # An old absence must not keep appearing as a new disappearance.
    assert inv.scan(now=300)
    assert missing(inv)["count"] == 0
    source.write_bytes(b"back")
    assert inv.scan(now=400)
    with contextlib.closing(inv.connect()) as db:
        row = db.execute("SELECT * FROM files").fetchone()
        assert row["missing_run"] is None and row["first_seen"] == 400
    source.unlink()
    assert inv.scan(now=500)
    assert missing(inv)["rows"][0]["missing_at"] == 500
    with contextlib.closing(inv.connect()) as db:
        assert db.execute("SELECT count(*) FROM files").fetchone()[0] == 1


def test_partial_scan_does_not_infer_absence_or_repeat_old_events(sample, monkeypatch):
    inv, target = sample
    first = target / "first.txt"
    kept = target / "kept.txt"
    first.write_bytes(b"old")
    kept.write_bytes(b"keep")
    inv.scan(now=100)
    first.unlink()
    inv.scan(now=200)
    kept.unlink()
    original = os.scandir

    def denied(path):
        if os.fspath(path) == str(target):
            raise PermissionError("test access denied")
        return original(path)

    with monkeypatch.context() as patch:
        patch.setattr(os, "scandir", denied)
        assert inv.scan(now=300) is False
    result = missing(inv)
    assert result["count"] == 0
    assert result["comparisons"][0]["status"] == "一部未確認"
    assert inv.listing({})["count"] == 1
    inv.scan(now=400)
    assert [r["name"] for r in missing(inv)["rows"]] == ["kept.txt"]


def test_missing_filters_paging_rename_and_csv(sample):
    inv, target = sample
    for i in range(12):
        (target / f"item-{i:02}.txt").write_bytes(b"x" * (i + 1))
    formula = target / "=old.csv"
    formula.write_bytes(b"formula")
    inv.scan(now=100)
    formula.rename(target / "renamed.csv")
    for source in target.glob("item-*.txt"):
        source.unlink()
    inv.scan(now=200)
    # Filters used by current-file browsing must not silently hide missing rows.
    result = missing(inv, sort="size", limit="10", age="365", folder="not-a-folder")
    assert result["count"] == 13 and len(result["rows"]) == 10
    assert result["rows"][0]["size"] == 12
    assert len(missing(inv, page="2", limit="10")["rows"]) == 3
    assert missing(inv, q="item-01")["count"] == 1
    assert missing(inv, root="999")["count"] == 0
    assert missing(inv, q="' OR 1=1 --")["count"] == 0
    data = b"".join(inv.csv_chunks({"mode": "missing"})).decode("utf-8-sig")
    records = list(csv.reader(io.StringIO(data)))
    assert len(records) == 14 and len(records[0]) == 10
    assert "見つからない" in records[0][-1]
    assert any(r[2] == "'=old.csv" for r in records[1:])
    assert all(r[2] != "renamed.csv" for r in records[1:])
    assert all("削除・移動・名前変更等" in r[-2] for r in records[1:])
    assert (
        formula.exists() is False
        and (target / "renamed.csv").read_bytes() == b"formula"
    )
    inv.save_targets([])
    assert missing(inv)["count"] == 0
    assert (
        len(
            list(
                csv.reader(
                    io.StringIO(
                        b"".join(inv.csv_chunks({"mode": "missing"})).decode(
                            "utf-8-sig"
                        )
                    )
                )
            )
        )
        == 1
    )


def test_legacy_database_migration_preserves_data_without_guessing(sample):
    inv, target = sample
    source = target / "legacy.txt"
    source.write_bytes(b"legacy")
    inv.scan(now=100)
    source.unlink()
    inv.scan(now=200)
    with contextlib.closing(inv.connect()) as db:
        before = tuple(
            db.execute(
                "SELECT path,size,first_seen,last_seen,present FROM files"
            ).fetchone()
        )
        db.execute("ALTER TABLE files DROP COLUMN missing_run")
        db.commit()
    upgraded = Inventory(inv.state)
    with contextlib.closing(upgraded.connect()) as db:
        assert (
            tuple(
                db.execute(
                    "SELECT path,size,first_seen,last_seen,present FROM files"
                ).fetchone()
            )
            == before
        )
        assert db.execute("SELECT missing_run FROM files").fetchone()[0] is None
        assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    assert missing(upgraded)["count"] == 0
    Inventory(inv.state)  # Reopening a migrated DB is harmless.
