import datetime as dt
import os
import threading
import time

import pytest
from fastapi.testclient import TestClient

from tamaru.inventory import Inventory
from tamaru.web import create_app
from tamaru.__main__ import import_folderage, main

PASSWORD = "test-only-password-2026"


@pytest.fixture
def setup(tmp_path):
    target = tmp_path / "share"
    target.mkdir()
    state = tmp_path / "state"
    app = create_app(
        state,
        allowed_hosts=["testserver"],
        dev_http=True,
        scheduler=False,
        testing=True,
    )
    app.state.store.create_admin("admin", "管理者", PASSWORD)
    with TestClient(app) as client:
        yield app, client, target, state


def login(client, username="admin", password=PASSWORD):
    token = client.get("/api/login-token").json()["token"]
    result = client.post(
        "/api/login",
        json={"username": username, "password": password},
        headers={"X-CSRF-Token": token},
    )
    assert result.status_code == 200, result.text
    return {"X-CSRF-Token": client.get("/api/me").json()["csrf"]}


def configure(client, target, headers, **changes):
    data = {
        "targets": [str(target)],
        "enabled": False,
        "time": "02:00",
        "timezone": "Asia/Tokyo",
        **changes,
    }
    result = client.post("/api/config", json=data, headers=headers)
    assert result.status_code == 200, result.text


def scan(app, client, headers):
    response = client.post("/api/scan", json={}, headers=headers)
    assert response.status_code == 202, response.text
    app.state.collector.thread.join(10)
    assert not app.state.collector.running
    assert app.state.store.get("last_job")["status"] in ("完了", "一部未確認")


def test_all_private_apis_require_login(setup):
    app, client, target, state = setup
    assert client.get("/", follow_redirects=False).status_code == 303
    for path in (
        "/api/me",
        "/api/summary",
        "/api/list",
        "/api/browse",
        "/api/config",
        "/api/admins",
        "/api/audit",
        "/api/export",
    ):
        assert client.get(path).status_code == 401
    assert client.post("/api/scan", json={}).status_code == 401


def test_login_csrf_logout_and_cookie_flags(setup):
    app, client, target, state = setup
    assert (
        client.post(
            "/api/login", json={"username": "admin", "password": PASSWORD}
        ).status_code
        == 403
    )
    headers = login(client)
    assert client.post("/api/scan", json={}).status_code == 403
    assert client.get("/api/me").json()["display_name"] == "管理者"
    assert client.post("/api/logout", headers=headers).status_code == 200
    assert client.get("/api/me").status_code == 401


def test_multi_admin_create_last_enabled_and_session_revocation(setup):
    app, client, target, state = setup
    headers = login(client)
    assert (
        client.patch(
            "/api/admins/1", json={"enabled": False}, headers=headers
        ).status_code
        == 400
    )
    response = client.post(
        "/api/admins",
        json={"username": "second", "display_name": "追加管理者", "password": PASSWORD},
        headers=headers,
    )
    assert response.status_code == 200
    second = response.json()["id"]
    token = app.state.store.login("second", PASSWORD, "127.0.0.1")
    assert app.state.store.session(token)
    assert (
        client.patch(
            f"/api/admins/{second}", json={"enabled": False}, headers=headers
        ).status_code
        == 200
    )
    assert app.state.store.session(token) is None
    with pytest.raises(ValueError):
        app.state.store.login("second", PASSWORD, "127.0.0.1")
    assert (
        client.patch(
            f"/api/admins/{second}", json={"enabled": True}, headers=headers
        ).status_code
        == 200
    )
    assert (
        client.patch(
            f"/api/admins/{second}",
            json={"password": "new-test-password-2026"},
            headers=headers,
        ).status_code
        == 200
    )
    with pytest.raises(ValueError):
        app.state.store.login("second", PASSWORD, "127.0.0.1")
    assert app.state.store.login("second", "new-test-password-2026", "127.0.0.1")
    with app.state.store.connect() as db:
        hashes = [r[0] for r in db.execute("SELECT password_hash FROM admins")]
    assert all(h.startswith("$argon2id$") for h in hashes)
    assert PASSWORD not in str(app.state.store.audit_list())


def test_login_throttles_unknown_accounts(setup):
    app, client, target, state = setup
    for _ in range(10):
        with pytest.raises(ValueError, match="IDまたは"):
            app.state.store.login("missing", PASSWORD, "127.0.0.1")
    with pytest.raises(ValueError, match="試行回数"):
        app.state.store.login("missing", PASSWORD, "127.0.0.1")


def test_initial_cli_admin_is_only_once_and_password_validation(setup):
    app, client, target, state = setup
    with pytest.raises(ValueError, match="既に登録"):
        app.state.store.create_admin("other", "管理者", PASSWORD, first_only=True)
    with pytest.raises(ValueError, match="12"):
        app.state.store.create_admin("other", "管理者", "short")


def test_scan_counts_age_preserves_metadata_and_export(setup):
    app, client, target, state = setup
    folder = target / "営業部" / "田中"
    folder.mkdir(parents=True)
    source = folder / "=説明.csv"
    source.write_bytes(b"hello")
    os.utime(source, (1000000000, 1000000000))
    before = source.stat()
    headers = login(client)
    configure(client, target, headers)
    scan(app, client, headers)
    row = client.get("/api/list").json()["rows"][0]
    assert row["age"] == 0
    assert row["size"] == 5
    first = row["first_seen"]
    scan(app, client, headers)
    assert client.get("/api/list").json()["rows"][0]["first_seen"] == first
    data = client.get("/api/export").content.decode("utf-8-sig")
    assert "'=説明.csv" in data
    assert source.stat().st_mtime_ns == before.st_mtime_ns
    assert source.read_bytes() == b"hello"
    assert client.get("/api/summary").json()["totals"]["bytes"] == 5


def test_atomic_publish_and_duplicate_scan_rejected(setup, monkeypatch):
    app, client, target, state = setup
    (target / "old.txt").write_text("old")
    headers = login(client)
    configure(client, target, headers)
    scan(app, client, headers)
    (target / "new.txt").write_text("new")
    entered = threading.Event()
    release = threading.Event()
    original = Inventory.scan

    def held(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        entered.set()
        assert release.wait(10)
        return result

    monkeypatch.setattr(Inventory, "scan", held)
    try:
        assert client.post("/api/scan", headers=headers).status_code == 202
        assert entered.wait(5)
        assert client.get("/api/list").json()["count"] == 1
        assert client.post("/api/scan", headers=headers).status_code == 409
        assert (
            client.post(
                "/api/config",
                headers=headers,
                json={"targets": [], "enabled": False, "time": "02:00"},
            ).status_code
            == 400
        )
    finally:
        release.set()
        app.state.collector.thread.join(10)
    assert client.get("/api/list").json()["count"] == 2


def test_daily_scheduler_once_per_local_day_and_manual_addition(setup):
    app, client, target, state = setup
    (target / "file.txt").touch()
    headers = login(client)
    configure(client, target, headers, enabled=True)
    before = dt.datetime(2026, 10, 27, 16, 59, tzinfo=dt.timezone.utc)  # JST 01:59
    due = before + dt.timedelta(minutes=1)
    collector = app.state.collector
    assert collector.tick(before) is False
    assert collector.tick(due) is True
    collector.thread.join(10)
    assert collector.tick(due + dt.timedelta(hours=1)) is False
    scan(app, client, headers)
    assert collector.tick(due + dt.timedelta(days=1)) is True
    collector.thread.join(10)


def test_inaccessible_root_retains_last_observations(setup):
    app, client, target, state = setup
    (target / "file.txt").touch()
    headers = login(client)
    configure(client, target, headers)
    scan(app, client, headers)
    moved = target.with_name("offline")
    target.rename(moved)
    try:
        scan(app, client, headers)
        rows = client.get("/api/list").json()["rows"]
        assert len(rows) == 1 and rows[0]["status"] == "未確認"
    finally:
        moved.rename(target)


def test_recursive_folder_rollup_and_drilldown(setup):
    app, client, target, state = setup
    for name in ("営業/田中/a.txt", "営業/鈴木/案件/b.txt", "管理/佐藤/c.txt"):
        p = target / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"abc")
    headers = login(client)
    configure(client, target, headers)
    scan(app, client, headers)
    data = client.get("/api/list?mode=folders&depth=1&sort=size").json()
    assert data["count"] == 2
    assert data["rows"][0]["count"] == 2
    assert data["rows"][0]["bytes"] == 6
    detail = client.get(
        "/api/list", params={"folder": data["rows"][0]["parent"], "recursive": "1"}
    ).json()
    assert detail["count"] == 2


def test_source_content_is_not_opened(setup, monkeypatch):
    app, client, target, state = setup
    source = target / "file.bin"
    source.write_bytes(b"secret")
    original = open

    def guarded(path, *args, **kwargs):
        if str(path) == str(source):
            raise AssertionError("source content opened")
        return original(path, *args, **kwargs)

    headers = login(client)
    configure(client, target, headers)
    with monkeypatch.context() as scope:
        scope.setattr("builtins.open", guarded)
        scan(app, client, headers)


def test_links_are_excluded(setup):
    app, client, target, state = setup
    outside = target.parent / "outside"
    outside.mkdir()
    (outside / "not-watched.txt").touch()
    link = target / "link"
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(outside), str(link))
    else:
        link.symlink_to(outside, target_is_directory=True)
    try:
        headers = login(client)
        configure(client, target, headers)
        scan(app, client, headers)
        assert client.get("/api/list").json()["count"] == 0
    finally:
        link.rmdir() if os.name == "nt" else link.unlink()


def test_validation_state_protection_and_secure_boundary(setup, tmp_path):
    app, client, target, state = setup
    headers = login(client)
    invalid = {
        "targets": [str(state)],
        "enabled": True,
        "time": "02:00",
        "timezone": "Asia/Tokyo",
    }
    assert client.post("/api/config", json=invalid, headers=headers).status_code == 400
    assert client.get("/api/list?page=no").status_code == 400
    assert client.get("/api/list?age=-1").status_code == 400
    prod = create_app(tmp_path / "prod", allowed_hosts=["testserver"], scheduler=False)
    with TestClient(prod, client=("192.168.1.3", 50000)) as prod_client:
        assert prod_client.get("/login").status_code == 403  # HTTPS required
    with TestClient(
        prod, base_url="https://testserver", client=("8.8.8.8", 50000)
    ) as prod_client:
        assert prod_client.get("/login").status_code == 403  # LAN only
    with TestClient(
        prod, base_url="https://testserver", client=("192.168.1.3", 50000)
    ) as prod_client:
        response = prod_client.get("/api/login-token")
        assert response.status_code == 200
        assert "Secure" in response.headers["set-cookie"]
        assert "HttpOnly" in response.headers["set-cookie"]
        assert "samesite=strict" in response.headers["set-cookie"].lower()


def test_folderage_import_preserves_first_seen_and_refuses_overwrite(tmp_path):
    target = tmp_path / "share"
    target.mkdir()
    (target / "file.txt").touch()
    old = Inventory(tmp_path / "old")
    old.save_targets([str(target)])
    first = time.time() - 40 * 86400
    old.scan(now=first)
    state = tmp_path / "new"
    import_folderage(state, old.state)
    current = Inventory(state)
    row = current.listing({})["rows"][0]
    assert row["first_seen"] == first and row["age"] == 40
    with pytest.raises(ValueError):
        import_folderage(state, old.state)


def test_insecure_lan_cli_is_rejected(tmp_path):
    with pytest.raises(SystemExit) as error:
        main(
            [
                "--state",
                str(tmp_path / "state"),
                "serve",
                "--host",
                "0.0.0.0",
                "--dev-http",
            ]
        )
    assert error.value.code == 2


def test_two_servers_cannot_use_same_state(setup):
    app, client, target, state = setup
    duplicate = create_app(
        state,
        allowed_hosts=["testserver"],
        dev_http=True,
        scheduler=False,
        testing=True,
    )
    with pytest.raises(RuntimeError):
        with TestClient(duplicate):
            pass


def test_browse_roots_children_files_breadcrumbs_and_csv(setup):
    app, client, target, state = setup
    for name, size in (
        ("root.txt", 2),
        ("営業/田中/a.txt", 7),
        ("営業/b.txt", 3),
        ("管理/c.txt", 5),
    ):
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)
    (target / "empty").mkdir()
    headers = login(client)
    configure(client, target, headers)
    scan(app, client, headers)
    overview = client.get("/api/browse").json()
    assert overview["totals"] == {"count": 4, "bytes": 17, "uncertain": 0}
    assert len(overview["rows"]) == 1
    root_id = overview["rows"][0]["root_id"]
    top = client.get("/api/browse", params={"root": root_id, "sort": "size"}).json()
    assert [(r["name"], r["kind"], r["bytes"]) for r in top["rows"]] == [
        ("営業", "folder", 10),
        ("管理", "folder", 5),
        ("root.txt", "file", 2),
    ]
    sales = client.get(
        "/api/browse", params={"root": root_id, "folder": str(target / "営業")}
    ).json()
    assert [(r["name"], r["count"]) for r in sales["rows"]] == [
        ("田中", 1),
        ("b.txt", 1),
    ]
    assert [r["name"] for r in sales["breadcrumbs"]] == ["share", "営業"]
    assert sales["totals"]["bytes"] == 10
    person = client.get(
        "/api/browse", params={"root": root_id, "folder": str(target / "営業" / "田中")}
    ).json()
    assert [r["name"] for r in person["rows"]] == ["a.txt"]
    assert [r["name"] for r in person["breadcrumbs"]] == ["share", "営業", "田中"]
    csv = client.get(
        "/api/export",
        params={"root": root_id, "folder": sales["folder"], "recursive": "1"},
    ).text
    assert "a.txt" in csv and "b.txt" in csv
    assert "c.txt" not in csv and "root.txt" not in csv
    flat = client.get("/api/list", params={"sort": "size"}).json()
    assert [r["size"] for r in flat["rows"]] == [7, 5, 3, 2]


def test_browse_filters_pagination_and_uncertain_files(setup):
    app, client, target, state = setup
    for i in range(12):
        (target / f"file{i:02}.txt").write_bytes(b"x" * (i + 1))
    nested = target / "folder" / "nested"
    nested.mkdir(parents=True)
    (nested / "match.txt").write_bytes(b"found")
    headers = login(client)
    configure(client, target, headers)
    scan(app, client, headers)
    root_id = client.get("/api/browse").json()["rows"][0]["root_id"]
    first = client.get(
        "/api/browse", params={"root": root_id, "limit": 10, "sort": "size"}
    ).json()
    second = client.get(
        "/api/browse", params={"root": root_id, "limit": 10, "sort": "size", "page": 2}
    ).json()
    assert first["count"] == second["count"] == 13
    assert len(first["rows"]) == 10 and len(second["rows"]) == 3
    combined = first["rows"] + second["rows"]
    assert combined[0]["kind"] == "folder"
    assert [r["bytes"] for r in combined[1:]] == list(range(12, 0, -1))
    assert first["totals"]["count"] == 13
    filtered = client.get("/api/browse", params={"root": root_id, "q": "match"}).json()
    assert filtered["rows"][0]["name"] == "folder" and filtered["totals"]["count"] == 1
    assert client.get("/api/browse?age=30").json()["rows"] == []
    moved = target.with_name("offline")
    target.rename(moved)
    try:
        scan(app, client, headers)
        uncertain = client.get("/api/browse", params={"root": root_id}).json()
        assert uncertain["totals"]["uncertain"] == 13
        assert all(r["uncertain"] >= 1 for r in uncertain["rows"])
    finally:
        moved.rename(target)


def test_browse_multiple_roots_and_scope_validation(setup, tmp_path):
    app, client, target, state = setup
    other = tmp_path / "other"
    other.mkdir()
    (target / "a.txt").touch()
    (other / "b.txt").touch()
    headers = login(client)
    configure(client, target, headers, targets=[str(target), str(other)])
    scan(app, client, headers)
    roots = client.get("/api/browse").json()["rows"]
    assert {r["path"] for r in roots} == {str(target), str(other)}
    root_id = next(r["root_id"] for r in roots if r["path"] == str(target))
    for params in (
        {"root": 99999},
        {"folder": str(target)},
        {"root": root_id, "folder": str(other)},
        {"root": root_id, "folder": str(target / ".." / "other")},
    ):
        assert client.get("/api/browse", params=params).status_code == 400
    configure(client, target, headers)
    assert len(client.get("/api/browse").json()["rows"]) == 1


def test_listing_keeps_one_snapshot_during_publication(tmp_path, monkeypatch):
    import contextlib
    import sqlite3

    target = tmp_path / "share"
    target.mkdir()
    (target / "a.txt").touch()
    inventory = Inventory(tmp_path / "state")
    inventory.save_targets([str(target)])
    inventory.scan()
    connect = inventory.connect
    changed = []

    class PublishingConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            cursor = super().execute(sql, parameters)
            if sql.startswith("SELECT count(*) FROM files") and not changed:
                with contextlib.closing(connect()) as writer:
                    writer.execute("""INSERT INTO files SELECT root_id,key || '-new',path || '-new',
                        relative_path || '-new',parent,name || '-new',size,mtime_ns,first_seen,last_seen,seen_run,present FROM files""")
                    writer.commit()
                changed.append(True)
            return cursor

    def publishing_connect():
        db = sqlite3.connect(inventory.db_path, factory=PublishingConnection)
        db.row_factory = sqlite3.Row
        return db

    monkeypatch.setattr(inventory, "connect", publishing_connect)
    result = inventory.listing({})
    assert changed and result["count"] == len(result["rows"]) == 1
    assert inventory.listing({})["count"] == 2
