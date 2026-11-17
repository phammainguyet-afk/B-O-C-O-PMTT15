
#!/usr/bin/env python3
"""PMTT15 shared-store demo. Use only with approved, protected hosting."""
import argparse
import base64
import hmac
import json
import os
import sqlite3
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
lock = threading.RLock()
conn = None

USERNAME = os.environ.get("PMTT_USER", "")
PASSWORD = os.environ.get("PMTT_PASSWORD", "")
MAX_BODY = 35 * 1024 * 1024
START = "070000004288"
ADMIN_PIN = os.environ.get("PMTT_ADMIN_PIN", "")


class PgConnection:
    def __init__(self, dsn):
        import psycopg
        self.raw = psycopg.connect(dsn, autocommit=True, prepare_threshold=None, connect_timeout=12, sslmode='require')

    def execute(self, query, params=()):
        q = query.strip()
        if q == 'BEGIN IMMEDIATE':
            self.raw.execute('BEGIN')
            self.raw.execute('SELECT pg_advisory_xact_lock(701215)')
            return None
        if 'INSERT OR IGNORE INTO citizens' in q:
            q = q.replace('INSERT OR IGNORE INTO citizens', 'INSERT INTO citizens') + ' ON CONFLICT DO NOTHING'
        q = q.replace("json_extract(payload,'$.fields[3]')", "(payload::jsonb -> 'fields' ->> 3)")
        return self.raw.execute(q.replace('?', '%s'), params)

def connect(dbpath):
    global conn
    conn = sqlite3.connect(
        dbpath,
        check_same_thread=False,
        timeout=30,
        isolation_level=None
    )
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS records (
            mode TEXT NOT NULL,
            store TEXT NOT NULL,
            id TEXT NOT NULL,
            payload TEXT NOT NULL,
            version INTEGER NOT NULL,
            PRIMARY KEY(mode, store, id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            rev INTEGER PRIMARY KEY AUTOINCREMENT,
            mode TEXT NOT NULL,
            store TEXT NOT NULL,
            id TEXT NOT NULL,
            changed_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS citizens (
            mode TEXT NOT NULL,
            number TEXT NOT NULL,
            case_id TEXT NOT NULL,
            PRIMARY KEY(mode, number)
        )
    """)
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS citizens_case
        ON citizens(mode, case_id)
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS citizen_settings (
            mode TEXT PRIMARY KEY, next_number TEXT NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS citizen_settings_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mode TEXT NOT NULL, old_number TEXT NOT NULL,
            new_number TEXT NOT NULL,
            changed_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)


def valid_citizen_number(s):
    return isinstance(s, str) and len(s) == 12 and s.isascii() and s.isdigit() and s != "000000000000"


def next_free_number(m):
    row = conn.execute("SELECT next_number FROM citizen_settings WHERE mode=?", (m,)).fetchone()
    n = int(row[0] if row else START)
    while n <= 999999999999:
        candidate = str(n).zfill(12)
        already = conn.execute("SELECT 1 FROM citizens WHERE mode=? AND number=?", (m, candidate)).fetchone()
        imported = conn.execute(
            "SELECT 1 FROM records WHERE mode=? AND store='cases' AND json_extract(payload,'$.fields[3]')=? LIMIT 1",
            (m, candidate)
        ).fetchone()
        if not already and not imported:
            return candidate
        n += 1
    raise ValueError("Đã hết dãy số 12 chữ số")


def save_next_number(m, n):
    conn.execute(
        "INSERT INTO citizen_settings(mode,next_number,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) "
        "ON CONFLICT(mode) DO UPDATE SET next_number=excluded.next_number, updated_at=CURRENT_TIMESTAMP",
        (m, n)
    )


def mode(value):
    if value not in ("trial", "official"):
        raise ValueError("Chế độ không hợp lệ")
    return value


class Handler(BaseHTTPRequestHandler):
    server_version = "PMTT15-Shared/1.0"

    def send(self, obj, status=200):
        body = json.dumps(
            obj, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        self.send_response(status)
        self.send_header(
            "Content-Type", "application/json; charset=utf-8"
        )
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def require_auth(self):
        if not USERNAME or not PASSWORD:
            self.send(
                {"error": "Chưa cấu hình tài khoản máy chủ"}, 503
            )
            return False

        header = self.headers.get("Authorization", "")
        try:
            raw = (
                base64.b64decode(
                    header.removeprefix("Basic "),
                    validate=True
                ).decode("utf-8")
                if header.startswith("Basic ")
                else ""
            )
        except Exception:
            raw = ""

        user, _, password = raw.partition(":")
        valid = (
            hmac.compare_digest(user, USERNAME)
            and hmac.compare_digest(password, PASSWORD)
        )

        if not valid:
            self.send_response(401)
            self.send_header(
                "WWW-Authenticate",
                'Basic realm="PMTT15 authorised staff"'
            )
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return False
        return True

    def parse_mode(self):
        query = parse_qs(urlparse(self.path).query)
        return mode(query.get("mode", ["official"])[0])

    def do_GET(self):
        if not self.require_auth():
            return

        url = urlparse(self.path)
        route = url.path

        if route in ("/", "/index.html"):
            try:
                content = (ROOT / "index.html").read_bytes()
            except FileNotFoundError:
                return self.send(
                    {"error": "Thiếu index.html"}, 404
                )

            self.send_response(200)
            self.send_header(
                "Content-Type", "text/html; charset=utf-8"
            )
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        if route == "/api/health":
            return self.send({"ok": True, "shared": True})

        try:
            current_mode = self.parse_mode()

            if route == "/api/citizen-config":
                with lock:
                    next_number = next_free_number(current_mode)
                return self.send({"next": next_number, "mode": current_mode, "automatic": True})

            if route == "/api/snapshot":
                with lock:
                    records = conn.execute(
                        "SELECT store,id,payload,version "
                        "FROM records WHERE mode=?",
                        (current_mode,)
                    ).fetchall()

                    revision = conn.execute(
                        "SELECT COALESCE(MAX(rev),0) "
                        "FROM events WHERE mode=?",
                        (current_mode,)
                    ).fetchone()[0]

                data = {
                    "cases": [],
                    "batches": [],
                    "prefs": []
                }
                versions = {}

                for store, record_id, payload, version in records:
                    data.setdefault(store, []).append(
                        json.loads(payload)
                    )
                    versions[store + ":" + record_id] = version

                return self.send({
                    "data": data,
                    "versions": versions,
                    "revision": revision
                })

            if route == "/api/changes":
                since = max(
                    0,
                    int(parse_qs(url.query).get("since", ["0"])[0])
                )

                with lock:
                    revision = conn.execute(
                        "SELECT COALESCE(MAX(rev),0) "
                        "FROM events WHERE mode=?",
                        (current_mode,)
                    ).fetchone()[0]

                    entries = conn.execute(
                        "SELECT DISTINCT store,id FROM events "
                        "WHERE mode=? AND rev>?",
                        (current_mode, since)
                    ).fetchall()

                    changes = []

                    for store, record_id in entries:
                        record = conn.execute(
                            "SELECT payload,version FROM records "
                            "WHERE mode=? AND store=? AND id=?",
                            (current_mode, store, record_id)
                        ).fetchone()

                        changes.append({
                            "store": store,
                            "id": record_id,
                            "value": (
                                json.loads(record[0])
                                if record else None
                            ),
                            "version": (
                                record[1] if record else 0
                            )
                        })

                return self.send({
                    "revision": revision,
                    "changes": changes
                })

            return self.send(
                {"error": "Không tìm thấy API"}, 404
            )

        except Exception as error:
            return self.send({"error": str(error)}, 400)

    def do_POST(self):
        if not self.require_auth():
            return

        url = urlparse(self.path)

        try:
            current_mode = self.parse_mode()
            length = int(
                self.headers.get("Content-Length", "0")
            )

            if length <= 0 or length > MAX_BODY:
                return self.send(
                    {"error": "Gói dữ liệu quá lớn"}, 413
                )

            data = json.loads(self.rfile.read(length))

            if url.path == "/api/citizen-config":
                if not ADMIN_PIN:
                    return self.send({"error": "Chưa cấu hình PMTT_ADMIN_PIN trên Render"}, 503)
                if not hmac.compare_digest(self.headers.get("X-PMTT-Admin-Pin", ""), ADMIN_PIN):
                    return self.send({"error": "Mã quản trị không đúng"}, 403)
                candidate = data.get("next")
                expected = data.get("expected")
                if not valid_citizen_number(candidate):
                    raise ValueError("Số mới phải gồm 12 chữ số và không được toàn số 0")
                with lock:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        current = next_free_number(current_mode)
                        if expected != current:
                            raise RuntimeError("Số tiếp theo đã thay đổi trên máy khác. Vui lòng tải lại.")
                        used = conn.execute("SELECT 1 FROM citizens WHERE mode=? AND number=?", (current_mode,candidate)).fetchone()
                        in_cases = conn.execute(
                            "SELECT 1 FROM records WHERE mode=? AND store='cases' AND json_extract(payload,'$.fields[3]')=? LIMIT 1",
                            (current_mode, candidate)
                        ).fetchone()
                        if used or in_cases:
                            raise RuntimeError("Số này đã được sử dụng; vui lòng chọn số khác")
                        save_next_number(current_mode,candidate)
                        conn.execute(
                            "INSERT INTO citizen_settings_audit(mode,old_number,new_number) VALUES(?,?,?)",
                            (current_mode,current,candidate)
                        )
                        conn.execute("COMMIT")
                    except Exception:
                        conn.execute("ROLLBACK")
                        raise
                return self.send({"ok": True, "next": candidate, "mode": current_mode})

            if url.path in ("/api/put", "/api/transaction"):
                operations = (
                    data.get("operations")
                    if url.path == "/api/transaction"
                    else [data]
                )

                if (
                    not isinstance(operations, list)
                    or len(operations) > 3
                ):
                    raise ValueError("Gói lưu không hợp lệ")

                with lock:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        current = {}

                        for operation in operations:
                            store = operation.get("store")
                            items = operation.get("items")
                            versions = (
                                operation.get("versions") or {}
                            )

                            if (
                                store not in
                                ("cases", "batches", "prefs")
                                or not isinstance(items, list)
                                or len(items) > 15000
                            ):
                                raise ValueError(
                                    "Gói lưu không hợp lệ"
                                )

                            current[store] = {}

                            for item in items:
                                if (
                                    not isinstance(item, dict)
                                    or not isinstance(
                                        item.get("id"), str
                                    )
                                    or len(item["id"]) > 300
                                ):
                                    raise ValueError(
                                        "ID không hợp lệ"
                                    )

                                record_id = item["id"]

                                old = conn.execute(
                                    "SELECT version FROM records "
                                    "WHERE mode=? AND store=? AND id=?",
                                    (
                                        current_mode,
                                        store,
                                        record_id
                                    )
                                ).fetchone()

                                old_version = old[0] if old else 0

                                if (
                                    int(versions.get(record_id, 0))
                                    != old_version
                                ):
                                    raise RuntimeError(
                                        "CONFLICT: Ca đã được sửa "
                                        "trên máy khác. Hãy tải lại "
                                        "dữ liệu rồi kiểm tra."
                                    )

                                if (
                                    store == "cases"
                                    and item.get("autoCitizen")
                                ):
                                    fields = (
                                        item.get("fields")
                                        or [None] * 4
                                    )
                                    number = str(
                                        fields[3] or ""
                                    )

                                    if (
                                        len(number) != 12
                                        or not number.isdigit()
                                    ):
                                        raise ValueError(
                                            "CCCD tự cấp không hợp lệ"
                                        )

                                    recorded = conn.execute(
                                        "SELECT case_id FROM citizens "
                                        "WHERE mode=? AND number=?",
                                        (current_mode, number)
                                    ).fetchone()

                                    if (
                                        recorded
                                        and recorded[0] != record_id
                                    ):
                                        raise RuntimeError(
                                            "CCCD đã cấp cho ca khác"
                                        )

                                    previous = conn.execute(
                                        "SELECT number FROM citizens "
                                        "WHERE mode=? AND case_id=?",
                                        (current_mode, record_id)
                                    ).fetchone()

                                    if (
                                        previous
                                        and previous[0] != number
                                    ):
                                        raise RuntimeError(
                                            "Không được đổi CCCD "
                                            "đã cấp cho ca này"
                                        )

                                    conn.execute(
                                        "INSERT OR IGNORE INTO citizens"
                                        "(mode,number,case_id) "
                                        "VALUES (?,?,?)",
                                        (
                                            current_mode,
                                            number,
                                            record_id
                                        )
                                    )

                                payload = json.dumps(
                                    item,
                                    ensure_ascii=False,
                                    separators=(",", ":")
                                )
                                new_version = old_version + 1

                                conn.execute(
                                    "INSERT INTO records"
                                    "(mode,store,id,payload,version) "
                                    "VALUES(?,?,?,?,?) "
                                    "ON CONFLICT(mode,store,id) "
                                    "DO UPDATE SET "
                                    "payload=excluded.payload,"
                                    "version=excluded.version",
                                    (
                                        current_mode,
                                        store,
                                        record_id,
                                        payload,
                                        new_version
                                    )
                                )

                                conn.execute(
                                    "INSERT INTO events(mode,store,id) "
                                    "VALUES(?,?,?)",
                                    (
                                        current_mode,
                                        store,
                                        record_id
                                    )
                                )

                                current[store][record_id] = (
                                    new_version
                                )

                        revision = conn.execute(
                            "SELECT COALESCE(MAX(rev),0) "
                            "FROM events WHERE mode=?",
                            (current_mode,)
                        ).fetchone()[0]

                        conn.execute("COMMIT")

                    except Exception:
                        conn.execute("ROLLBACK")
                        raise

                result_versions = (
                    current
                    if url.path == "/api/transaction"
                    else current.get(data.get("store"), {})
                )

                return self.send({
                    "versions": result_versions,
                    "revision": revision,
                    "ok": True
                })

            if url.path == "/api/citizen":
                record_id = data.get("id")

                if (
                    not isinstance(record_id, str)
                    or not record_id
                ):
                    raise ValueError(
                        "Thiếu mã định danh ca"
                    )

                with lock:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        existing = conn.execute(
                            "SELECT number FROM citizens "
                            "WHERE mode=? AND case_id=?",
                            (current_mode, record_id)
                        ).fetchone()

                        if existing:
                            number = existing[0]
                        else:
                            next_number = int(next_free_number(current_mode))
                            number = str(next_number).zfill(12)
                            save_next_number(current_mode, str(next_number + 1).zfill(12))

                            conn.execute(
                                "INSERT INTO citizens"
                                "(mode,number,case_id) "
                                "VALUES(?,?,?)",
                                (
                                    current_mode,
                                    number,
                                    record_id
                                )
                            )

                        conn.execute("COMMIT")

                    except Exception:
                        conn.execute("ROLLBACK")
                        raise

                return self.send({"number": number})

            return self.send(
                {"error": "Không tìm thấy API"}, 404
            )

        except RuntimeError as error:
            return self.send({"error": str(error)}, 409)
        except Exception as error:
            return self.send({"error": str(error)}, 400)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--host", default="127.0.0.1"
    )
    parser.add_argument(
        "--port", type=int, default=8765
    )
    parser.add_argument(
        "--db",
        default=str(ROOT / "pmtt15-shared.sqlite3")
    )
    args = parser.parse_args()

    if not USERNAME or not PASSWORD:
        raise SystemExit(
            "Cần đặt PMTT_USER và PMTT_PASSWORD "
            "trước khi chạy máy chủ"
        )

    connect(args.db)

    print(
        "PMTT15 server: "
        "http://%s:%d" % (args.host, args.port),
        flush=True
    )

    ThreadingHTTPServer(
        (args.host, args.port), Handler
    ).serve_forever()


if __name__ == "__main__":
    main()

