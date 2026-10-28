from __future__ import annotations
import argparse
import contextlib
import getpass
import json
from pathlib import Path
import sqlite3
import sys

from .inventory import Inventory, ScanLock, within
from .security import Store


def default_state():
    base = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path.cwd()
    return base / "data"


def import_folderage(state, source):
    inventory = Inventory(state)
    source = Path(source).absolute()
    if (
        source == inventory.state
        or within(inventory.state, source)
        or within(source, inventory.state)
    ):
        raise ValueError(
            "コピー元と管理データ保存先は、互いに別のフォルダを指定してください。"
        )
    if not (source / "inventory.sqlite3").is_file():
        raise ValueError("FolderAgeのinventory.sqlite3が見つかりません。")
    settings = json.loads((source / "settings.json").read_text(encoding="utf-8"))
    with ScanLock(inventory.state / "server.lock"), ScanLock(source / "scan.lock"):
        with contextlib.closing(inventory.connect()) as dest:
            if (
                dest.execute("SELECT count(*) FROM files").fetchone()[0]
                or dest.execute("SELECT count(*) FROM roots").fetchone()[0]
            ):
                raise ValueError(
                    "取り込み先に既に記録があります。空の保存先を使用してください。"
                )
            inventory.save_targets(settings["targets"])
            with contextlib.closing(
                sqlite3.connect(
                    (source / "inventory.sqlite3").as_uri() + "?mode=ro", uri=True
                )
            ) as old:
                # Validate the inventory shape before replacing the empty destination.
                old.execute(
                    "SELECT root_id,key,path,first_seen,last_seen FROM files LIMIT 1"
                )
                old.backup(dest)
        Store(state).audit("server-console", "folderage_import")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Tamaru — 社内LAN向けファイル滞留状況ダッシュボード"
    )
    parser.add_argument(
        "--state",
        type=Path,
        default=default_state(),
        help="管理データの保存先（ローカル）",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("create-admin", help="初期管理者を対話形式で登録")
    init.add_argument("username")
    init.add_argument("--display-name", default="管理者")
    reset = sub.add_parser(
        "reset-password", help="サーバー上で管理者のパスワードを回復"
    )
    reset.add_argument("username")
    old = sub.add_parser(
        "import-folderage", help="既存FolderAgeの記録を空の保存先へ取り込む"
    )
    old.add_argument("source", type=Path)
    serve = sub.add_parser("serve", help="Webアプリと日次収集を起動")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--allowed-host", action="append")
    serve.add_argument("--cert-file")
    serve.add_argument("--key-file")
    serve.add_argument(
        "--trusted-proxy",
        action="append",
        help="TLS終端プロキシのIP（明示した場合だけ転送ヘッダーを信頼）",
    )
    serve.add_argument(
        "--dev-http",
        action="store_true",
        help="ローカル試運転専用。LAN向けHTTP接続は許可しない",
    )
    args = parser.parse_args(argv)
    if args.command in ("create-admin", "reset-password"):
        Inventory(args.state)  # Validate local state storage even for account commands.
        store = Store(args.state)
        password = getpass.getpass("新しいパスワード（12文字以上）: ")
        if getpass.getpass("もう一度入力: ") != password:
            raise ValueError("パスワードが一致しません。")
        if args.command == "create-admin":
            store.create_admin(
                args.username, args.display_name, password, first_only=True
            )
        else:
            found = next(
                (
                    a
                    for a in store.admins()
                    if a["username"].lower() == args.username.lower()
                ),
                None,
            )
            if not found:
                raise ValueError("管理者が見つかりません。")
            store.change_admin(
                found["id"], "server-console", enabled=True, password=password
            )
        print("管理者情報を保存しました。")
        return 0
    if args.command == "import-folderage":
        import_folderage(args.state, args.source)
        print("初回検出日時を引き継いで取り込みました。")
        return 0
    if args.dev_http and args.host not in ("127.0.0.1", "localhost", "::1"):
        parser.error("--dev-httpはループバックでの試運転専用です。")
    if bool(args.cert_file) != bool(args.key_file):
        parser.error("証明書と秘密鍵を両方指定してください。")
    if not args.dev_http and not args.cert_file and not args.trusted_proxy:
        parser.error(
            "HTTPS証明書を指定するか、TLS終端用の信頼するプロキシを指定してください。"
        )
    if args.trusted_proxy and args.host not in ("127.0.0.1", "localhost", "::1"):
        parser.error(
            "プロキシ経由ではバックエンドをループバックだけで待ち受けてください。"
        )
    from .web import create_app
    import uvicorn

    app = create_app(
        args.state, allowed_hosts=args.allowed_host, dev_http=args.dev_http
    )
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        workers=1,
        loop="asyncio",
        http="h11",
        ws="none",
        lifespan="on",
        proxy_headers=bool(args.trusted_proxy),
        forwarded_allow_ips=",".join(args.trusted_proxy or []),
        ssl_certfile=args.cert_file,
        ssl_keyfile=args.key_file,
        server_header=False,
        access_log=False,
        limit_concurrency=64,
        h11_max_incomplete_event_size=65536,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, sqlite3.Error, RuntimeError) as exc:
        print("Tamaru: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
