import os
from pathlib import Path
import subprocess
import sys

import pytest

from tamaru.__main__ import main
from tamaru.inventory import Inventory, ScanLock
from tamaru.jobs import Collector
from tamaru.security import Store


@pytest.fixture
def configured(tmp_path):
    target = tmp_path / "share"
    target.mkdir()
    source = target / "sample.txt"
    source.write_bytes(b"original")
    inv = Inventory(tmp_path / "state")
    inv.save_targets([str(target)])
    return inv, source


def test_collect_once_saves_and_exits_without_web_or_prompt(
    configured, monkeypatch, capsys
):
    inv, source = configured
    before = source.stat().st_mtime_ns
    for name in ("builtins.input", "getpass.getpass", "webbrowser.open", "uvicorn.run"):
        monkeypatch.setattr(
            name, lambda *a, **kw: pytest.fail("interactive or web startup")
        )
    monkeypatch.setattr(Collector, "start", lambda *a: pytest.fail("scheduler started"))
    store = Store(inv.state)
    schedule = {"enabled": True, "time": "15:00", "timezone": "Asia/Tokyo"}
    store.put("schedule", schedule)
    # A viewer can keep its server lock while a task collects into the same DB.
    with ScanLock(inv.state / "server.lock"):
        assert main(["--state", str(inv.state), "collect"]) == 0
    assert "完了" in capsys.readouterr().out
    assert inv.summary()["totals"]["bytes"] == 8
    job = store.get("last_job")
    assert (job["status"], job["actor"], job["reason"]) == (
        "完了",
        "task-scheduler",
        "task",
    )
    assert store.get("schedule") == schedule
    assert store.get("daily_key") is None
    assert not (inv.state / "staging" / "inventory.sqlite3").exists()
    assert source.read_bytes() == b"original" and source.stat().st_mtime_ns == before
    source.unlink()
    assert main(["--state", str(inv.state), "collect"]) == 0
    assert inv.listing({"mode": "missing"})["count"] == 1


def test_collect_partial_returns_two_and_preserves_unconfirmed(configured, monkeypatch):
    inv, source = configured
    assert main(["--state", str(inv.state), "collect"]) == 0
    original = os.scandir

    def denied(path):
        if os.fspath(path) == str(source.parent):
            raise PermissionError("test permission denied")
        return original(path)

    monkeypatch.setattr(os, "scandir", denied)
    assert main(["--state", str(inv.state), "collect"]) == 2
    assert Store(inv.state).get("last_job")["status"] == "一部未確認"
    assert inv.listing({"mode": "missing"})["count"] == 0
    assert inv.summary()["totals"]["count"] == 1


def test_collect_failure_keeps_previous_published_result(configured, monkeypatch):
    inv, source = configured
    assert main(["--state", str(inv.state), "collect"]) == 0
    before = inv.listing({})["rows"]

    def fail(*args, **kwargs):
        raise RuntimeError("test scan failure")

    monkeypatch.setattr(Inventory, "scan", fail)
    assert main(["--state", str(inv.state), "collect"]) == 1
    assert inv.listing({})["rows"] == before
    assert Store(inv.state).get("last_job")["status"] == "失敗"
    assert not (inv.state / "staging" / "inventory.sqlite3").exists()


def test_collect_conflict_does_not_replace_active_job(configured):
    inv, source = configured
    store = Store(inv.state)
    active = {
        "status": "実行中",
        "actor": "web-admin",
        "reason": "manual",
        "started": 123,
    }
    store.put("last_job", active)
    with ScanLock(inv.state / "scan.lock"):
        with pytest.raises(RuntimeError, match="別の走査"):
            main(["--state", str(inv.state), "collect"])
    assert store.get("last_job") == active


def test_viewer_startup_does_not_mark_running_task_interrupted(configured):
    inv, source = configured
    store = Store(inv.state)
    active = {
        "status": "実行中",
        "actor": "task-scheduler",
        "reason": "task",
        "started": 123,
    }
    store.put("last_job", active)
    collector = Collector(inv, store)
    with ScanLock(inv.state / "scan.lock"):
        collector.recover()
    assert store.get("last_job") == active
    collector.recover()
    assert store.get("last_job")["status"] == "中断"


def test_collect_module_process_returns_without_prompt_or_server(configured):
    inv, source = configured
    result = subprocess.run(
        [
            sys.executable,
            "-X",
            "utf8",
            "-B",
            "-m",
            "tamaru",
            "--state",
            str(inv.state),
            "collect",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert result.returncode == 0, result.stderr
    assert "完了" in result.stdout
    assert not Store(inv.state).admins()


def test_collect_unconfigured_process_returns_error_without_prompt(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-X",
            "utf8",
            "-B",
            "-m",
            "tamaru",
            "--state",
            str(tmp_path / "empty"),
            "collect",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert result.returncode == 1
    assert "対象フォルダ" in result.stderr
