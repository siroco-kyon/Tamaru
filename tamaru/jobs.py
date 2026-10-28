"""A single background collector with durable daily scheduling and atomic publication."""

from __future__ import annotations

import contextlib
import datetime as dt
import threading
import time
from zoneinfo import ZoneInfo
from .inventory import Inventory, ScanLock


DEFAULT_SCHEDULE = {"enabled": True, "time": "02:00", "timezone": "Asia/Tokyo"}


class Collector:
    def __init__(self, inventory, store):
        self.inventory = inventory
        self.store = store
        self.lock = threading.RLock()
        self.running = False
        self.thread = None
        self.current = None
        self.stop = threading.Event()
        self.error = ""
        self.scheduler = None

    def recover(self):
        previous = self.store.get("last_job")
        if previous and previous.get("status") == "実行中":
            previous.update(status="中断", finished=time.time())
            self.store.put("last_job", previous)
            if previous.get("reason") == "daily":
                self.store.put("daily_key", None)

    def status(self):
        with self.lock:
            progress = (
                self.current.progress.copy()
                if self.current
                else {"files": 0, "current": ""}
            )
            return {
                "running": self.running,
                "files": progress.get("files", 0),
                "current": progress.get("current", ""),
                "message": progress.get("message")
                if self.running
                else (self.error or "待機中"),
                "last_job": self.store.get("last_job"),
                "schedule": self.store.get("schedule", DEFAULT_SCHEDULE),
            }

    def request(self, actor, reason="manual", daily_key=None):
        with self.lock:
            if self.running:
                return False
            if not self.inventory.config()["targets"]:
                raise ValueError("対象フォルダを設定してください。")
            if daily_key and self.store.get("daily_key") == daily_key:
                return False
            job = {
                "actor": actor,
                "reason": reason,
                "started": time.time(),
                "status": "実行中",
            }
            self.store.put("last_job", job)
            if daily_key:
                self.store.put("daily_key", daily_key)
            self.store.audit(actor, "scan_requested", reason)
            self.running = True
            self.error = ""
            self.thread = threading.Thread(
                target=self._run, args=(job,), name="tamaru-collector", daemon=False
            )
            self.thread.start()
            return True

    def _run(self, job):
        try:
            with ScanLock(self.inventory.state / "scan.lock"):
                staging = Inventory(self.inventory.state / "staging")
                with (
                    contextlib.closing(self.inventory.connect()) as source,
                    contextlib.closing(staging.connect()) as dest,
                ):
                    source.backup(dest)
                staging.save_targets(self.inventory.config()["targets"])
                with self.lock:
                    self.current = staging
                complete = staging.scan()
                # SQLite backup publishes one transaction. Existing readers keep their prior snapshot.
                with (
                    contextlib.closing(staging.connect()) as source,
                    contextlib.closing(self.inventory.connect()) as dest,
                ):
                    source.backup(dest)
                job.update(
                    status="完了" if complete else "一部未確認", finished=time.time()
                )
                self.store.audit(job["actor"], "scan_finished", job["status"])
        except Exception as exc:
            job.update(status="失敗", finished=time.time(), error=str(exc))
            self.store.audit(job["actor"], "scan_failed", str(exc))
        finally:
            try:
                self.store.put("last_job", job)
            finally:
                with self.lock:
                    self.error = job.get("error", job["status"])
                    self.running = False
                    self.current = None

    def tick(self, now=None):
        schedule = self.store.get("schedule", DEFAULT_SCHEDULE)
        if not schedule["enabled"] or not self.inventory.config()["targets"]:
            return False
        local = (now or dt.datetime.now(dt.timezone.utc)).astimezone(
            ZoneInfo(schedule["timezone"])
        )
        hour, minute = map(int, schedule["time"].split(":"))
        if (local.hour, local.minute) < (hour, minute):
            return False
        return self.request("scheduler", "daily", local.date().isoformat())

    def start(self):
        def loop():
            while not self.stop.is_set():
                try:
                    self.tick()
                except Exception as exc:
                    self.error = "定期収集の受付失敗: " + str(exc)
                self.stop.wait(30)

        self.scheduler = threading.Thread(
            target=loop, name="tamaru-scheduler", daemon=True
        )
        self.scheduler.start()

    def close(self):
        self.stop.set()
        if self.scheduler:
            self.scheduler.join(timeout=2)
        if self.thread:
            self.thread.join()
