import contextlib
import csv
import datetime as dt
import io
import os

import pytest
from fastapi.testclient import TestClient

from tamaru.inventory import DAY, DAY_NS, Inventory, modification_filters
from tamaru.web import create_app

NOW = int(dt.datetime(2026, 11, 20, 12, tzinfo=dt.UTC).timestamp())
NS = 1_000_000_000


@pytest.fixture
def sample(tmp_path):
    target = tmp_path / "share"
    target.mkdir()
    inv = Inventory(tmp_path / "state")
    inv.save_targets([str(target)])
    for name, days, size in (
        ("old-a.txt", 90, 10),
        ("old-b.txt", 90, 11),
        ("recent.txt", 1, 20),
        ("boundary.txt", 30, 30),
        ("future.txt", -1, 1),
        ("epoch.txt", None, 2),
        ("child/nested.txt", 180, 40),
    ):
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)
        mtime = (NOW - days * DAY) * NS if days is not None else 0
        if name == "boundary.txt":
            mtime += 1
        os.utime(path, ns=(mtime, mtime))
    inv.scan(now=NOW)
    with contextlib.closing(inv.connect()) as db:
        # Windows filesystems round timestamps to 100 ns; exercise a 1 ns DB boundary.
        db.execute(
            "UPDATE files SET mtime_ns=? WHERE name='boundary.txt'",
            ((NOW - 30 * DAY) * NS + 1,),
        )
        db.execute("UPDATE files SET first_seen=?", (NOW - 60 * DAY,))
        db.execute(
            "UPDATE files SET first_seen=? WHERE name='old-b.txt'", (NOW - 30 * DAY,)
        )
        db.execute(
            "UPDATE files SET first_seen=? WHERE name='boundary.txt'",
            (NOW - 30 * DAY + 1,),
        )
        db.execute(
            "UPDATE files SET first_seen=? WHERE name IN ('future.txt','epoch.txt')",
            (NOW,),
        )
        db.commit()
        root_id = db.execute("SELECT id FROM roots").fetchone()[0]
    return inv, target, root_id


def names(inv, params=None, now=NOW):
    return [row["name"] for row in inv.listing(params or {}, now=now)["rows"]]


def test_unmodified_days_boundary_future_epoch_and_unconfirmed(sample):
    inv, _, root = sample
    rows = {row["name"]: row for row in inv.listing({}, now=NOW)["rows"]}
    assert rows["old-a.txt"]["unmodified_days"] == 90
    assert rows["recent.txt"]["unmodified_days"] == 1
    assert rows["boundary.txt"]["unmodified_days"] == 29
    assert rows["future.txt"]["unmodified_days"] == 0
    assert rows["epoch.txt"]["unmodified_days"] == NOW // DAY
    with contextlib.closing(inv.connect()) as db:
        db.execute(
            "UPDATE files SET seen_run=-1,last_seen=? WHERE name='old-a.txt'",
            (NOW - 10 * DAY,),
        )
        db.commit()
    rows = {row["name"]: row for row in inv.listing({}, now=NOW + DAY)["rows"]}
    assert rows["old-a.txt"]["unmodified_days"] == 80
    assert rows["old-a.txt"]["status"] == "未確認"
    assert "old-a.txt" not in names(inv, {"unmodified_days": "90"})
    browse = inv.browse({"root": str(root)}, now=NOW)
    assert browse["rows"][0]["unmodified_days"] is None
    assert (
        next(r for r in browse["rows"] if r["name"] == "old-a.txt")["unmodified_days"]
        == 80
    )


def test_unmodified_filter_sort_paging_folder_totals_and_csv(sample, monkeypatch):
    inv, target, root = sample
    params = {"unmodified_days": "30", "sort": "modified_oldest"}
    assert names(inv, params) == ["epoch.txt", "nested.txt", "old-a.txt", "old-b.txt"]
    assert names(inv, {**params, "sort": "modified_newest"}) == [
        "old-a.txt",
        "old-b.txt",
        "nested.txt",
        "epoch.txt",
    ]
    assert names(inv, {**params, "q": "old", "age": "30"}) == ["old-a.txt", "old-b.txt"]
    assert names(inv, {**params, "root": "999"}) == []
    assert names(inv, {**params, "unmodified_days": "365000"}) == []
    browse = inv.browse({**params, "root": str(root)}, now=NOW)
    assert [(r["kind"], r["name"]) for r in browse["rows"]] == [
        ("folder", "child"),
        ("file", "epoch.txt"),
        ("file", "old-a.txt"),
        ("file", "old-b.txt"),
    ]
    assert browse["totals"] == {"count": 4, "bytes": 63, "uncertain": 0}
    nested_params = {**params, "folder": str(target / "child"), "recursive": "1"}
    monkeypatch.setattr("tamaru.inventory.time.time", lambda: NOW)
    rows = list(
        csv.reader(
            io.StringIO(b"".join(inv.csv_chunks(nested_params)).decode("utf-8-sig"))
        )
    )
    assert [r[2] for r in rows[1:]] == ["nested.txt"]
    # Update sorting must happen before pagination, with path ties stable.
    with contextlib.closing(inv.connect()) as db:
        template = dict(
            db.execute("SELECT * FROM files WHERE name='old-a.txt'").fetchone()
        )
        columns = list(template)
        for i in range(15):
            item = {
                **template,
                "key": str(target / f"page{i:02}.txt"),
                "path": str(target / f"page{i:02}.txt"),
                "name": f"page{i:02}.txt",
                "mtime_ns": (NOW - (40 + i) * DAY) * NS,
            }
            db.execute(
                f"INSERT INTO files({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
                [item[c] for c in columns],
            )
        db.commit()
    ordered = names(inv, {"sort": "modified_newest"})
    paged = (
        names(inv, {"sort": "modified_newest", "limit": "10"})
        + names(inv, {"sort": "modified_newest", "limit": "10", "page": "2"})
        + names(inv, {"sort": "modified_newest", "limit": "10", "page": "3"})
    )
    assert paged == ordered and len(paged) == 22
    first = inv.browse(
        {"root": str(root), "sort": "modified_newest", "limit": "10"}, now=NOW
    )
    second = inv.browse(
        {"root": str(root), "sort": "modified_newest", "limit": "10", "page": "2"},
        now=NOW,
    )
    third = inv.browse(
        {"root": str(root), "sort": "modified_newest", "limit": "10", "page": "3"},
        now=NOW,
    )
    assert first["rows"][0]["kind"] == "folder"
    combined = first["rows"][1:] + second["rows"] + third["rows"]
    assert [r["name"] for r in combined] == [n for n in ordered if n != "nested.txt"]


def test_date_filter_includes_entire_end_day_in_viewer_zone(sample, monkeypatch):
    inv, _, root = sample
    start = int(dt.datetime(2026, 11, 9, 15, tzinfo=dt.UTC).timestamp()) * NS
    with contextlib.closing(inv.connect()) as db:
        for name, mtime in (
            ("old-a.txt", start),
            ("old-b.txt", start + DAY_NS - 1),
            ("recent.txt", start + DAY_NS),
            ("boundary.txt", start - 1),
        ):
            db.execute("UPDATE files SET mtime_ns=? WHERE name=?", (mtime, name))
        db.commit()
    params = {
        "modified_from": "2026-11-10",
        "modified_to": "2026-11-10",
        "timezone": "Asia/Tokyo",
        "q": ".txt",
    }
    assert set(names(inv, params)) == {"old-a.txt", "old-b.txt"}
    assert "boundary.txt" in names(
        inv, {"modified_to": "2026-11-09", "timezone": "Asia/Tokyo"}
    )
    assert "recent.txt" in names(
        inv, {"modified_from": "2026-11-11", "timezone": "Asia/Tokyo"}
    )
    browse = inv.browse({**params, "root": str(root)}, now=NOW)
    assert browse["totals"]["count"] == 2 and browse["totals"]["bytes"] == 21
    monkeypatch.setattr("tamaru.inventory.time.time", lambda: NOW)
    csv_rows = list(
        csv.reader(io.StringIO(b"".join(inv.csv_chunks(params)).decode("utf-8-sig")))
    )
    assert {r[2] for r in csv_rows[1:]} == {"old-a.txt", "old-b.txt"}
    assert names(inv, {"modified_from": "9998-01-01"}) == []
    assert names(inv, {"modified_to": "0002-01-01"}) == []


def test_viewer_date_bounds_follow_dst_and_reject_invalid_input():
    start, end, _ = modification_filters(
        {
            "modified_from": "2026-03-08",
            "modified_to": "2026-03-08",
            "timezone": "America/New_York",
        }
    )
    assert end - start == 23 * 3600 * NS
    start, end, _ = modification_filters(
        {
            "modified_from": "2026-11-01",
            "modified_to": "2026-11-01",
            "timezone": "America/New_York",
        }
    )
    assert end - start == 25 * 3600 * NS


def test_missing_days_and_filter_use_last_confirmation(sample):
    inv, target, _ = sample
    (target / "old-a.txt").unlink()
    inv.scan(now=NOW + 10 * DAY)
    row = inv.listing({"mode": "missing"}, now=NOW + 20 * DAY)["rows"][0]
    assert row["unmodified_days"] == 90
    assert (
        names(inv, {"mode": "missing", "unmodified_days": "91"}, now=NOW + 20 * DAY)
        == []
    )
    assert names(
        inv, {"mode": "missing", "unmodified_days": "90"}, now=NOW + 20 * DAY
    ) == ["old-a.txt"]


def test_aged_capacity_uses_first_seen_and_selected_present_files(
    sample, monkeypatch, tmp_path
):
    inv, _, _ = sample
    monkeypatch.setattr("tamaru.inventory.time.time", lambda: NOW)
    totals = inv.summary()["totals"]
    assert totals["aged"] == 4 and totals["aged_bytes"] == 81
    # Retained uncertain observations are included, just like existing counts.
    with contextlib.closing(inv.connect()) as db:
        db.execute("UPDATE files SET seen_run=-1 WHERE name='recent.txt'")
        db.execute("UPDATE files SET present=0 WHERE name='old-a.txt'")
        db.commit()
    assert inv.summary()["totals"]["aged_bytes"] == 71
    other = tmp_path / "other"
    other.mkdir()
    inv.save_targets([str(other)])
    assert inv.summary()["totals"]["aged_bytes"] == 0
    inv.save_targets([])
    assert inv.summary()["totals"]["aged_bytes"] == 0


@pytest.mark.parametrize(
    "params",
    [
        {"unmodified_days": "-1"},
        {"unmodified_days": "1.5"},
        {"unmodified_days": "365001"},
        {"modified_from": "2026-02-30"},
        {"modified_to": "20261110"},
        {"modified_from": "2026-11-11", "modified_to": "2026-11-10"},
        {"timezone": "No/Such_Zone"},
        {"modified_to": "9999-12-31"},
    ],
)
def test_invalid_filters_return_400_for_list_browse_and_streaming_export(
    sample, params
):
    inv, _, _ = sample
    app = create_app(
        inv.state,
        allowed_hosts=["testserver"],
        dev_http=True,
        scheduler=False,
        testing=True,
    )
    password = "test-filter-password-2026"
    app.state.store.create_admin("admin", "test", password)
    with TestClient(app) as client:
        token = client.get("/api/login-token").json()["token"]
        assert (
            client.post(
                "/api/login",
                json={"username": "admin", "password": password},
                headers={"X-CSRF-Token": token},
            ).status_code
            == 200
        )
        for endpoint in ("/api/list", "/api/browse", "/api/export"):
            result = client.get(endpoint, params=params)
            assert result.status_code == 400, result.text
