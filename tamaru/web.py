from __future__ import annotations

import contextlib
import ipaddress
import os
from pathlib import Path
import secrets
import time
from contextlib import asynccontextmanager
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .inventory import Inventory, ScanLock
from .jobs import Collector, DEFAULT_SCHEDULE
from .deletion import DeletionService
from .security import Store
from .reports import daily_trends, storage_usage

STATIC = Path(__file__).with_name("static")
NETWORKS = [
    ipaddress.ip_network(x)
    for x in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]
COOKIE = "tamaru_session"


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class AdminCreate(Login):
    display_name: str = Field(min_length=1, max_length=100)


class AdminChange(BaseModel):
    enabled: bool | None = None
    password: str | None = Field(default=None, max_length=256)


class Configuration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    targets: list[str] = Field(max_length=100)
    enabled: bool = True
    time: str = Field(pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")
    timezone: str = Field(default="Asia/Tokyo", max_length=64)


def create_app(
    state, *, allowed_hosts=None, dev_http=False, scheduler=True, testing=False
):
    inventory = Inventory(state)
    store = Store(state)
    collector = Collector(inventory, store)

    @asynccontextmanager
    async def lifespan(app):
        with ScanLock(inventory.state / "server.lock"):
            collector.recover()
            if scheduler:
                collector.start()
            try:
                yield
            finally:
                collector.close()

    app = FastAPI(
        title="Tamaru",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.inventory = inventory
    app.state.store = store
    app.state.collector = collector
    app.state.deletion = DeletionService()
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=allowed_hosts or ["localhost", "127.0.0.1"]
    )

    @app.middleware("http")
    async def boundary(request, call_next):
        remote = request.client.host if request.client else ""
        if not testing:
            try:
                address = ipaddress.ip_address(remote)
                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                    address = address.ipv4_mapped
            except ValueError:
                return JSONResponse(
                    {"error": "接続元を確認できません。"}, status_code=403
                )
            if not any(address in network for network in NETWORKS):
                return JSONResponse(
                    {"error": "社内LANから接続してください。"}, status_code=403
                )
            if request.url.scheme != "https" and not (dev_http and address.is_loopback):
                return JSONResponse(
                    {"error": "HTTPSで接続してください。"}, status_code=403
                )
        length = request.headers.get("content-length", "0")
        if not length.isdigit() or int(length) > 100000:
            return JSONResponse(
                {"error": "リクエストが大きすぎます。"}, status_code=413
            )
        if request.method in ("POST", "PATCH", "PUT"):
            chunks = []
            total = 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > 100000:
                    return JSONResponse(
                        {"error": "リクエストが大きすぎます。"}, status_code=413
                    )
                chunks.append(chunk)
            request._body = b"".join(chunks)
        result = await call_next(request)
        result.headers["Cache-Control"] = "no-store"
        result.headers["X-Content-Type-Options"] = "nosniff"
        result.headers["X-Frame-Options"] = "DENY"
        result.headers["Referrer-Policy"] = "same-origin"
        result.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        return result

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        return JSONResponse({"error": str(exc)}, status_code=400)

    @app.exception_handler(HTTPException)
    async def denied(request, exc):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    def admin(request: Request):
        user = store.session(request.cookies.get(COOKIE))
        if not user:
            raise HTTPException(401, "ログインしてください。")
        return user

    def mutation(request: Request, user=Depends(admin)):
        if not secrets.compare_digest(
            request.headers.get("X-CSRF-Token", ""), user["csrf"]
        ):
            raise HTTPException(403, "画面を再読み込みして、もう一度操作してください。")
        return user

    def safe_params(request):
        # Bound SQL inputs before they reach the inventory query builder.
        params = dict(request.query_params)
        for name, low, high in (
            ("page", 1, 10000000),
            ("limit", 10, 200),
            ("age", 0, 365000),
        ):
            if name in params:
                try:
                    value = int(params[name])
                except ValueError:
                    raise ValueError("数値の検索条件が正しくありません。") from None
                if not low <= value <= high:
                    raise ValueError("検索条件が範囲外です。")
        if len(params.get("q", "")) > 1000 or len(params.get("folder", "")) > 32767:
            raise ValueError("検索条件が長すぎます。")
        if params.get("root"):
            int(params["root"])
        return params

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    def home(request: Request):
        if not store.session(request.cookies.get(COOKIE)):
            return RedirectResponse("/login", status_code=303)
        return FileResponse(STATIC / "dashboard.html")

    @app.get("/login")
    def login_page():
        return FileResponse(STATIC / "login.html")

    @app.get("/api/login-token")
    def login_token(response: Response):
        token = secrets.token_urlsafe(32)
        response.set_cookie(
            "tamaru_login_csrf",
            token,
            max_age=900,
            httponly=True,
            secure=not dev_http,
            samesite="strict",
        )
        return {"token": token, "setup_needed": not store.admins()}

    @app.post("/api/login")
    def sign_in(body: Login, request: Request, response: Response):
        cookie = request.cookies.get("tamaru_login_csrf", "")
        if not cookie or not secrets.compare_digest(
            cookie, request.headers.get("X-CSRF-Token", "")
        ):
            raise HTTPException(403, "ログイン画面を開き直してください。")
        token = store.login(
            body.username,
            body.password,
            request.client.host if request.client else "unknown",
        )
        response.set_cookie(
            COOKIE,
            token,
            max_age=28800,
            httponly=True,
            secure=not dev_http,
            samesite="strict",
        )
        response.delete_cookie("tamaru_login_csrf")
        return {"ok": True}

    @app.get("/api/me")
    def me(user=Depends(admin)):
        return user

    @app.get("/api/deletion/status")
    def deletion_status(user=Depends(admin)):
        return DeletionService.status()

    @app.post("/api/logout")
    def logout(request: Request, response: Response, user=Depends(mutation)):
        store.logout(request.cookies[COOKIE])
        store.audit(user["username"], "logout")
        response.delete_cookie(COOKIE)
        return {"ok": True}

    @app.get("/api/summary")
    def summary(user=Depends(admin)):
        result = inventory.summary()
        result.update(version=__version__, progress=collector.status())
        return result

    @app.get("/api/list")
    def listing(request: Request, user=Depends(admin)):
        params = safe_params(request)
        depth = params.get("depth", "0")
        if params.get("mode") == "folders" and depth in ("1", "2", "3"):
            now = time.time()
            page = int(params.get("page", "1"))
            limit = int(params.get("limit", "100"))
            with contextlib.closing(inventory.connect()) as db:
                db.execute("BEGIN")

                def grouping(path, root):
                    parent = os.path.dirname(path)
                    relative = os.path.relpath(parent, root)
                    return (
                        root
                        if relative == "."
                        else os.path.join(root, *relative.split(os.sep)[: int(depth)])
                    )

                db.create_function("group_folder", 2, grouping, deterministic=True)
                clause, args = inventory.where(db, params, now)
                query = f"""SELECT f.root_id,group_folder(f.path,r.path) AS parent,count(*) AS count,sum(f.size) AS bytes,
                    min(f.first_seen) AS first_seen,
                    sum(CASE WHEN f.seen_run<>r.latest_run OR r.status NOT IN ('完了','一部未確認') THEN 1 ELSE 0 END) AS uncertain
                    FROM files f JOIN roots r ON r.id=f.root_id WHERE {clause}
                    GROUP BY f.root_id,group_folder(f.path,r.path)"""
                count = db.execute(
                    "SELECT count(*) FROM (" + query + ")", args
                ).fetchone()[0]
                order = {
                    "age": "first_seen,parent",
                    "path": "parent",
                    "size": "bytes DESC,parent",
                }.get(params.get("sort"), "bytes DESC,parent")
                rows = [
                    dict(r)
                    for r in db.execute(
                        "SELECT * FROM ("
                        + query
                        + ") ORDER BY "
                        + order
                        + " LIMIT ? OFFSET ?",
                        [*args, limit, (page - 1) * limit],
                    )
                ]
            for row in rows:
                row["age"] = max(0, int((now - row["first_seen"]) / 86400))
            return {
                "rows": rows,
                "count": count,
                "page": page,
                "limit": limit,
                "mode": "folders",
                "recursive": True,
            }
        return inventory.listing(params)

    @app.get("/api/browse")
    def browse(request: Request, user=Depends(admin)):
        return inventory.browse(safe_params(request))

    @app.get("/api/trends")
    def trends(days: int = 30, root: int | None = None, user=Depends(admin)):
        return daily_trends(inventory, root_id=root, days=days)

    @app.get("/api/storage")
    def storage(user=Depends(admin)):
        return {**storage_usage(inventory), "warning": collector.storage_warning}

    @app.get("/api/export")
    def export(request: Request, user=Depends(admin)):
        params = safe_params(request)
        store.audit(user["username"], "csv_export")
        return StreamingResponse(
            inventory.csv_chunks(params),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="Tamaru-files.csv"'},
        )

    @app.get("/api/config")
    def configuration(user=Depends(admin)):
        return {**inventory.config(), **store.get("schedule", DEFAULT_SCHEDULE)}

    @app.post("/api/config")
    def configure(body: Configuration, user=Depends(mutation)):
        try:
            ZoneInfo(body.timezone)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("タイムゾーンが正しくありません。") from None
        with collector.lock:
            if collector.running:
                raise ValueError("収集中は設定を変更できません。")
            inventory.save_targets(body.targets)
            store.put(
                "schedule",
                {"enabled": body.enabled, "time": body.time, "timezone": body.timezone},
            )
            store.audit(user["username"], "config_changed")
        return {"ok": True}

    @app.post("/api/scan")
    def scan(user=Depends(mutation)):
        if not collector.request(user["username"]):
            raise HTTPException(409, "既に収集しています。完了をお待ちください。")
        return JSONResponse({"ok": True}, status_code=202)

    @app.get("/api/admins")
    def administrators(user=Depends(admin)):
        return store.admins()

    @app.post("/api/admins")
    def add_administrator(body: AdminCreate, user=Depends(mutation)):
        return {
            "id": store.create_admin(
                body.username, body.display_name, body.password, user["username"]
            )
        }

    @app.patch("/api/admins/{admin_id}")
    def change_administrator(admin_id: int, body: AdminChange, user=Depends(mutation)):
        if body.enabled is None and body.password is None:
            raise ValueError("変更する項目を指定してください。")
        store.change_admin(
            admin_id, user["username"], enabled=body.enabled, password=body.password
        )
        return {"ok": True}

    @app.get("/api/audit")
    def audit(user=Depends(admin)):
        return store.audit_list()

    return app
