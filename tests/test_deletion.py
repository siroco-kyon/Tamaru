import os
from pathlib import Path
import time

import pytest
from fastapi.testclient import TestClient

from tamaru.deletion import DeletionDisabled, DeletionService
from tamaru.inventory import DAY, Inventory, ScanLock
from tamaru.security import Store
from tamaru.web import create_app
from tamaru._retention_engine import _RetentionEngine, RetentionPolicy
from tamaru._retention_files import UnsafeRetentionOperation


@pytest.fixture
def engine(tmp_path):
    if os.name != "nt":
        pytest.skip("実ファイルを退避・削除する内部バックエンドはWindows専用")
    root = tmp_path / "share"
    root.mkdir()
    file = root / "部署" / "利用者" / "資料.txt"
    file.parent.mkdir(parents=True)
    file.write_bytes(b"test fixture only")
    inventory = Inventory(tmp_path / "state")
    inventory.save_targets([str(root)])
    store = Store(inventory.state)
    clock = [time.time()]
    internal = _RetentionEngine(
        inventory, store, tmp_path / "quarantine", clock=lambda: clock[0]
    )
    inventory.scan(now=clock[0])
    assert internal.observe() == 1
    return internal, clock, file


def age(engine, days=30):
    internal, clock, file = engine
    for _ in range(days):
        clock[0] += DAY
        internal.inventory.scan(now=clock[0])
        internal.observe()
    return internal.prepare("test-admin")


def test_public_facade_unconditionally_blocks_environment_and_options(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("TAMARU_ENABLE_DELETION", "true")
    monkeypatch.setenv("TAMARU_DELETION_ENABLED", "1")
    service = DeletionService()
    for action in (service.prepare, service.quarantine, service.purge):
        with pytest.raises(DeletionDisabled):
            action(enabled=True, force=True, actor="admin", path=str(tmp_path))
    assert service.status()["enabled"] is False
    assert not list(tmp_path.iterdir())


def test_no_mutating_routes_or_controls_and_configuration_cannot_enable(tmp_path):
    app = create_app(
        tmp_path / "state",
        allowed_hosts=["testserver"],
        dev_http=True,
        scheduler=False,
        testing=True,
    )
    app.state.store.create_admin("admin", "管理者", "test-only-password-2026")
    with TestClient(app) as client:
        assert client.get("/api/deletion/status").status_code == 401
        token = client.get("/api/login-token").json()["token"]
        assert (
            client.post(
                "/api/login",
                json={"username": "admin", "password": "test-only-password-2026"},
                headers={"X-CSRF-Token": token},
            ).status_code
            == 200
        )
        headers = {"X-CSRF-Token": client.get("/api/me").json()["csrf"]}
        assert client.get("/api/deletion/status").json()["enabled"] is False
        for path in (
            "/api/delete",
            "/api/deletion/execute",
            "/api/deletion/quarantine",
            "/api/deletion/purge",
        ):
            assert (
                client.post(path, json={"enabled": True}, headers=headers).status_code
                == 404
            )
        assert (
            client.post(
                "/api/config",
                json={
                    "targets": [],
                    "enabled": False,
                    "time": "02:00",
                    "deletion_enabled": True,
                },
                headers=headers,
            ).status_code
            == 422
        )
        html = client.get("/").text
        assert "削除する</button>" not in html
        assert "退避する</button>" not in html
        assert "完全削除</button>" not in html
        assert not (tmp_path / "state/retention.sqlite3").exists()


def test_observation_does_not_read_contents_or_mutate_files(engine, monkeypatch):
    internal, clock, file = engine
    original = file.stat()

    original_open = Path.open

    def denied(path, *args, **kwargs):
        if path == file:
            raise AssertionError("file content must not be opened")
        return original_open(path, *args, **kwargs)

    with monkeypatch.context() as scope:
        scope.setattr(Path, "open", denied)
        assert internal.observe() == 1
        assert internal.prepare("test-admin")["count"] == 0
    assert file.read_bytes() == b"test fixture only"
    assert file.stat().st_mtime_ns == original.st_mtime_ns


def test_internal_quarantine_then_purge_after_seven_days(engine):
    internal, clock, file = engine
    plan = age(engine)
    assert plan["count"] == 1
    original = internal.files.snapshot(file, internal.inventory.config()["targets"][0])
    assert internal.quarantine_plan(plan["id"], "test-admin") == {
        "moved": 1,
        "skipped": 0,
    }
    assert not file.exists()
    with internal._db() as db:
        row = db.execute("SELECT * FROM quarantine_files").fetchone()
    payload = Path(row["path"])
    assert payload.read_bytes() == b"test fixture only"
    assert internal.files.snapshot(payload, internal.quarantine) == original
    assert internal.purge_due("test-admin") == {"purged": 0, "skipped": 0}
    clock[0] += 7 * DAY
    assert internal.purge_due("test-admin") == {"purged": 1, "skipped": 0}
    assert not payload.exists()
    assert any(r["action"] == "retention_purged" for r in internal.store.audit_list())


def test_replacement_after_plan_is_not_moved(engine):
    internal, clock, file = engine
    plan = age(engine)
    replacement = file.with_name("replacement.txt")
    replacement.write_bytes(b"new data")
    os.replace(replacement, file)
    assert internal.quarantine_plan(plan["id"], "test-admin") == {
        "moved": 0,
        "skipped": 1,
    }
    assert file.read_bytes() == b"new data"


def test_replacement_observation_restarts_retention(engine):
    internal, clock, file = engine
    assert age(engine)["count"] == 1
    replacement = file.with_name("replacement.txt")
    replacement.write_bytes(b"replacement")
    os.replace(replacement, file)
    internal.inventory.scan(now=clock[0])
    internal.observe()
    assert internal.prepare("test-admin")["count"] == 0


def test_expired_and_repeated_plan_are_refused(engine):
    internal, clock, file = engine
    plan = age(engine)
    clock[0] += 901
    with pytest.raises(UnsafeRetentionOperation):
        internal.quarantine_plan(plan["id"], "test-admin")
    assert file.exists()
    plan = internal.prepare("test-admin")
    internal.quarantine_plan(plan["id"], "test-admin")
    with pytest.raises(UnsafeRetentionOperation):
        internal.quarantine_plan(plan["id"], "test-admin")


def test_stale_or_failed_observation_has_no_candidates(engine):
    internal, clock, file = engine
    assert age(engine)["count"] == 1
    clock[0] += 37 * 3600
    assert internal.prepare("test-admin")["count"] == 0
    internal.observe()
    internal.inventory.scan(now=clock[0])
    internal.observe()
    assert internal.prepare("test-admin")["count"] == 0


def test_quarantine_overlap_and_scan_exclusion(engine):
    internal, clock, file = engine
    with pytest.raises(UnsafeRetentionOperation):
        _RetentionEngine(internal.inventory, internal.store, file.parent / "quarantine")
    plan = age(engine)
    internal.inventory.save_targets([])
    assert internal.quarantine_plan(plan["id"], "test-admin")["moved"] == 0
    assert file.exists()


def test_changed_quarantine_payload_is_never_purged(engine):
    internal, clock, file = engine
    plan = age(engine)
    internal.quarantine_plan(plan["id"], "test-admin")
    with internal._db() as db:
        payload = Path(db.execute("SELECT path FROM quarantine_files").fetchone()[0])
    payload.write_bytes(b"modified quarantined file")
    clock[0] += 7 * DAY
    assert internal.purge_due("test-admin") == {"purged": 0, "skipped": 1}
    assert payload.exists()


def test_tampered_quarantine_path_and_partial_move_never_purged(engine):
    internal, clock, file = engine
    plan = age(engine)
    internal.quarantine_plan(plan["id"], "test-admin")
    with internal._db() as db:
        row = db.execute("SELECT * FROM quarantine_files").fetchone()
        db.execute("UPDATE quarantine_files SET path=?", (str(file),))
    clock[0] += 7 * DAY
    assert internal.purge_due("test-admin") == {"purged": 0, "skipped": 1}
    assert Path(row["path"]).exists()
    with internal._db() as db:
        db.execute("UPDATE quarantine_files SET status='moving',path=?", (row["path"],))
    assert internal.purge_due("test-admin")["purged"] == 0


def test_limits_and_shared_job_lock(engine):
    internal, clock, file = engine
    age(engine)
    internal.policy = RetentionPolicy(max_bytes=1)
    with pytest.raises(UnsafeRetentionOperation):
        internal.prepare("test-admin")
    internal.policy = RetentionPolicy()
    plan = internal.prepare("test-admin")
    with ScanLock(internal.inventory.state / "scan.lock"):
        with pytest.raises(RuntimeError):
            internal.quarantine_plan(plan["id"], "test-admin")
    assert file.exists()


def test_junctions_and_hard_links_refused(engine, tmp_path):
    internal, clock, file = engine
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "outside.txt"
    target.write_bytes(b"outside")
    import _winapi

    link = file.parent / "junction"
    _winapi.CreateJunction(str(outside), str(link))
    try:
        with pytest.raises(UnsafeRetentionOperation):
            internal.files.snapshot(link / "outside.txt", file.parent)
    finally:
        link.rmdir()
    hard = file.with_name("hard.txt")
    os.link(file, hard)
    with pytest.raises(UnsafeRetentionOperation):
        internal.files.snapshot(file, file.parent)


def test_cli_has_no_deletion_command(tmp_path):
    from tamaru.__main__ import main

    with pytest.raises(SystemExit) as exc:
        main(["--state", str(tmp_path / "state"), "delete"])
    assert exc.value.code == 2
    assert not (tmp_path / "state").exists()


def test_busy_file_is_not_moved(engine):
    internal, clock, file = engine
    plan = age(engine)
    with file.open("rb"):
        assert internal.quarantine_plan(plan["id"], "test-admin") == {
            "moved": 0,
            "skipped": 1,
        }
    assert file.read_bytes() == b"test fixture only"


def test_parent_replaced_by_junction_after_plan_is_not_followed(engine):
    internal, clock, file = engine
    plan = age(engine)
    parent = file.parent
    moved = parent.with_name(parent.name + "-moved")
    parent.rename(moved)
    import _winapi

    _winapi.CreateJunction(str(moved), str(parent))
    try:
        assert internal.quarantine_plan(plan["id"], "test-admin") == {
            "moved": 0,
            "skipped": 1,
        }
        assert (moved / file.name).read_bytes() == b"test fixture only"
    finally:
        parent.rmdir()


def test_file_count_limit(engine):
    internal, clock, file = engine
    file.with_name("second.txt").write_bytes(b"second test fixture")
    internal.inventory.scan(now=clock[0])
    internal.observe()
    assert age(engine)["count"] == 2
    internal.policy = RetentionPolicy(max_files=1)
    with pytest.raises(UnsafeRetentionOperation):
        internal.prepare("test-admin")
    assert file.exists() and file.with_name("second.txt").exists()
