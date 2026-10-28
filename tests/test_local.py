import threading

import pytest
import uvicorn

from tamaru.__main__ import main, run_with_browser
from tamaru.security import Store


PASSWORD = "local-test-password-only"


def test_local_first_run_and_restart(tmp_path, monkeypatch):
    state = tmp_path / "state"
    monkeypatch.setattr("builtins.input", lambda prompt: "")
    monkeypatch.setattr("getpass.getpass", lambda prompt: PASSWORD)
    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **options: calls.append(options))
    assert main(["--state", str(state), "local", "--no-browser", "--port", "9876"]) == 0
    assert Store(state).admins()[0]["username"] == "admin"
    assert calls[0]["host"] == "127.0.0.1" and calls[0]["port"] == 9876
    assert calls[0]["proxy_headers"] is False
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("setup repeated"))
    assert main(["--state", str(state), "local", "--no-browser"]) == 0
    assert len(Store(state).admins()) == 1


def test_no_command_starts_local_and_opens_browser(tmp_path, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "owner")
    monkeypatch.setattr("getpass.getpass", lambda prompt: PASSWORD)
    calls = []
    monkeypatch.setattr(
        "tamaru.__main__.run_with_browser",
        lambda server, url: calls.append((server, url)),
    )
    assert main(["--state", str(tmp_path / "state")]) == 0
    server, url = calls[0]
    assert server.config.host == "127.0.0.1"
    assert url == "http://127.0.0.1:8765/"


def test_local_does_not_expose_lan_or_accept_invalid_port(tmp_path):
    for options in (["--host", "0.0.0.0"], ["--port", "0"], ["--port", "65536"]):
        with pytest.raises(SystemExit) as error:
            main(["--state", str(tmp_path / "state"), "local", *options])
        assert error.value.code == 2
    assert not (tmp_path / "state").exists()


def test_browser_opens_after_server_is_ready(monkeypatch):
    opened = threading.Event()
    monkeypatch.setattr("webbrowser.open", lambda url: opened.set())

    class Server:
        started = False

        def run(self):
            assert not opened.is_set()
            self.started = True
            assert opened.wait(2)

    run_with_browser(Server(), "http://127.0.0.1:8765/")


def test_browser_does_not_open_when_server_fails(monkeypatch):
    monkeypatch.setattr(
        "webbrowser.open", lambda url: pytest.fail("browser opened on failure")
    )

    class Server:
        started = False

        def run(self):
            raise RuntimeError("port already used")

    with pytest.raises(RuntimeError, match="port already used"):
        run_with_browser(Server(), "http://127.0.0.1:8765/")
    assert not any(thread.name == "tamaru-browser" for thread in threading.enumerate())
