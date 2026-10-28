import contextlib
import time

from fastapi.testclient import TestClient

from tamaru.web import create_app
from tamaru._retention_engine import _RetentionEngine


def test_normal_manual_and_daily_collection_never_construct_deletion_engine(
    tmp_path, monkeypatch
):
    def forbidden(*args, **kwargs):
        raise AssertionError("Dormant deletion engine must not start")

    monkeypatch.setattr(_RetentionEngine, "__init__", forbidden)
    monkeypatch.setenv("TAMARU_DELETION_ENABLED", "true")
    root = tmp_path / "share"
    root.mkdir()
    file = root / "old.txt"
    file.write_bytes(b"must remain untouched")
    app = create_app(
        tmp_path / "state",
        allowed_hosts=["testserver"],
        dev_http=True,
        scheduler=False,
        testing=True,
    )
    store = app.state.store
    store.create_admin("admin", "管理者", "test-only-password-2026")
    inv = app.state.inventory
    inv.save_targets([str(root)])
    inv.scan(now=time.time() - 90 * 86400)
    store.put("schedule", {"enabled": True, "time": "00:00", "timezone": "Asia/Tokyo"})
    with TestClient(app) as client:
        token = client.get("/api/login-token").json()["token"]
        client.post(
            "/api/login",
            json={"username": "admin", "password": "test-only-password-2026"},
            headers={"X-CSRF-Token": token},
        )
        headers = {"X-CSRF-Token": client.get("/api/me").json()["csrf"]}
        assert client.post("/api/scan", headers=headers).status_code == 202
        app.state.collector.thread.join(10)
        assert app.state.collector.tick() is True
        app.state.collector.thread.join(10)
        assert client.get("/api/deletion/status").json()["enabled"] is False
    assert file.read_bytes() == b"must remain untouched"
    assert not (tmp_path / "state/retention.sqlite3").exists()
    assert not any("retention_" in r["action"] for r in store.audit_list())
    with contextlib.closing(inv.connect()) as db:
        assert db.execute("SELECT present FROM files").fetchone()[0] == 1
