#!/usr/bin/env python3
"""Zero-dependency HTTP server for the private infinite gallery."""

from __future__ import annotations

import base64
import binascii
import getpass
import hashlib
import hmac
import json
import mimetypes
import secrets
import sqlite3
import struct
import sys
import time
from collections import defaultdict, deque
from email.utils import formatdate
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

import config


CHALLENGES: dict[str, tuple[float, str]] = {}
SESSION_CACHE: dict[str, tuple[int, str, str]] = {}
ACCESS_CODE_SET_CACHE: tuple[float, tuple[str, int, list[dict]]] | None = None
FAILED_ATTEMPTS: defaultdict[str, deque[float]] = defaultdict(deque)
ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp", "image/gif"}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("invalid base64url value") from error


def derive_access_key(code: str, salt: str | None = None, iterations: int | None = None) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        code.encode("utf-8"),
        (salt or config.PBKDF2_SALT).encode("utf-8"),
        iterations or config.PBKDF2_ITERATIONS,
        dklen=32,
    )


def derive_proof_for_key(key: bytes, nonce: str) -> str:
    return b64url(hmac.new(key, nonce.encode("ascii"), hashlib.sha256).digest())


def derive_proof(code: str, nonce: str) -> str:
    return derive_proof_for_key(derive_access_key(code), nonce)


def configured_access_key() -> bytes:
    if config.ACCESS_KEY:
        try:
            key = b64url_decode(config.ACCESS_KEY)
        except ValueError as error:
            raise RuntimeError("ACCESS_KEY must be valid base64url") from error
        if len(key) != 32:
            raise RuntimeError("ACCESS_KEY must decode to exactly 32 bytes")
        return key
    return derive_access_key(config.ACCESS_CODE)


def new_access_store() -> dict:
    return {
        "version": 1,
        "salt": b64url(secrets.token_bytes(16)),
        "iterations": config.PBKDF2_ITERATIONS,
        "codes": [],
    }


def validate_access_store(payload: object) -> dict:
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise RuntimeError("Access code JSON must use version 1")
    salt = payload.get("salt")
    iterations = payload.get("iterations")
    codes = payload.get("codes")
    if not isinstance(salt, str) or not (8 <= len(salt) <= 128):
        raise RuntimeError("Access code JSON has an invalid salt")
    if not isinstance(iterations, int) or not (100_000 <= iterations <= 2_000_000):
        raise RuntimeError("Access code JSON has invalid PBKDF2 iterations")
    if not isinstance(codes, list):
        raise RuntimeError("Access code JSON must contain a codes array")

    normalized = {"version": 1, "salt": salt, "iterations": iterations, "codes": []}
    seen_ids: set[str] = set()
    for item in codes:
        if not isinstance(item, dict):
            raise RuntimeError("Each access code entry must be an object")
        code_id = item.get("id")
        label = item.get("label")
        encoded_key = item.get("access_key")
        if not isinstance(code_id, str) or not code_id or len(code_id) > 64 or code_id in seen_ids:
            raise RuntimeError("Access code JSON contains an invalid or duplicate id")
        if not isinstance(label, str) or not label.strip() or len(label) > 80:
            raise RuntimeError("Access code JSON contains an invalid label")
        if not isinstance(encoded_key, str):
            raise RuntimeError("Access code JSON contains an invalid access_key")
        try:
            key = b64url_decode(encoded_key)
        except ValueError as error:
            raise RuntimeError("Access code JSON contains an invalid access_key") from error
        if len(key) != 32:
            raise RuntimeError("Every access_key must decode to exactly 32 bytes")
        seen_ids.add(code_id)
        normalized["codes"].append(
            {
                "id": code_id,
                "label": label.strip(),
                "access_key": encoded_key,
                "created_at": int(item.get("created_at", 0)),
            }
        )
    return normalized


def load_access_store(path: Path | None = None) -> dict | None:
    store_path = path or config.ACCESS_CODES_PATH
    if not store_path.exists():
        return None
    try:
        payload = json.loads(store_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot read access code JSON: {store_path}") from error
    return validate_access_store(payload)


def write_access_store(payload: dict, path: Path | None = None) -> None:
    global ACCESS_CODE_SET_CACHE
    store_path = path or config.ACCESS_CODES_PATH
    normalized = validate_access_store(payload)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = store_path.with_name(store_path.name + ".tmp")
    temporary.write_text(json.dumps(normalized, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(store_path)
    store_path.chmod(0o600)
    if store_path == config.ACCESS_CODES_PATH:
        ACCESS_CODE_SET_CACHE = None


def access_code_set(path: Path | None = None) -> tuple[str, int, list[dict]]:
    global ACCESS_CODE_SET_CACHE
    if path is None and ACCESS_CODE_SET_CACHE and ACCESS_CODE_SET_CACHE[0] > time.monotonic():
        return ACCESS_CODE_SET_CACHE[1]
    store = load_access_store(path)
    if store is None:
        result = (
            config.PBKDF2_SALT,
            config.PBKDF2_ITERATIONS,
            [{"id": "legacy", "label": "Environment", "key": configured_access_key()}],
        )
    else:
        codes = [
            {"id": item["id"], "label": item["label"], "key": b64url_decode(item["access_key"])}
            for item in store["codes"]
        ]
        result = (store["salt"], store["iterations"], codes)
    if path is None:
        ACCESS_CODE_SET_CACHE = (time.monotonic() + 2, result)
    return result


def active_access_code_ids() -> set[str]:
    return {item["id"] for item in access_code_set()[2]}


def detect_image_type(data: bytes) -> str | None:
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def image_dimensions(data: bytes, mime: str) -> tuple[int, int] | None:
    """Read dimensions from common image headers without external packages."""
    try:
        if mime == "image/png" and len(data) >= 24:
            return struct.unpack(">II", data[16:24])
        if mime == "image/gif" and len(data) >= 10:
            return struct.unpack("<HH", data[6:10])
        if mime == "image/webp" and len(data) >= 25:
            kind = data[12:16]
            if kind == b"VP8X" and len(data) >= 30:
                w = 1 + int.from_bytes(data[24:27], "little")
                h = 1 + int.from_bytes(data[27:30], "little")
                return w, h
            if kind == b"VP8 " and len(data) >= 30 and data[23:26] == b"\x9d\x01\x2a":
                w = int.from_bytes(data[26:28], "little") & 0x3FFF
                h = int.from_bytes(data[28:30], "little") & 0x3FFF
                return w, h
            if kind == b"VP8L" and data[20] == 0x2F:
                bits = int.from_bytes(data[21:25], "little")
                w = (bits & 0x3FFF) + 1
                h = ((bits >> 14) & 0x3FFF) + 1
                return w, h
        if mime == "image/jpeg":
            i = 2
            while i + 9 < len(data):
                if data[i] != 0xFF:
                    i += 1
                    continue
                marker = data[i + 1]
                if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
                    h, w = struct.unpack(">HH", data[i + 5 : i + 9])
                    return w, h
                if marker in {0xD8, 0xD9}:
                    i += 2
                    continue
                segment_length = struct.unpack(">H", data[i + 2 : i + 4])[0]
                i += 2 + segment_length
    except (IndexError, struct.error, ValueError):
        return None
    return None


def safe_original_name(raw: str) -> str:
    name = Path(unquote(raw)).name.strip() or "image"
    return "".join(ch for ch in name if ch.isalnum() or ch in "._- ")[:120] or "image"


def db_connect() -> sqlite3.Connection:
    connection = sqlite3.connect(config.DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def delete_image_record(image_id: int) -> dict | None:
    """Hide static images or permanently remove uploaded image files."""
    with db_connect() as db:
        row = db.execute(
            """SELECT id, filename, source, thumbnail_filename
               FROM images WHERE id = ? AND deleted_at IS NULL""",
            (image_id,),
        ).fetchone()
        if not row:
            return None
        image = dict(row)
        if image["source"] == "upload":
            db.execute("DELETE FROM images WHERE id = ?", (image_id,))
        else:
            db.execute("UPDATE images SET deleted_at = ? WHERE id = ?", (int(time.time()), image_id))

    if image["source"] == "upload":
        (config.UPLOAD_DIR / image["filename"]).unlink(missing_ok=True)
        if image["thumbnail_filename"]:
            (config.THUMBNAIL_DIR / image["thumbnail_filename"]).unlink(missing_ok=True)
    return image


def sync_public_images(db: sqlite3.Connection | None = None) -> int:
    """Index supported files copied into public/images without duplicating rows."""
    own_connection = db is None
    connection = db or db_connect()
    added = 0
    try:
        image_dir = config.PUBLIC_DIR / "images"
        for path in sorted(image_dir.iterdir() if image_dir.exists() else []):
            if not path.is_file():
                continue
            data = path.read_bytes()
            mime = detect_image_type(data)
            if mime not in ALLOWED_MIME:
                continue
            dims = image_dimensions(data, mime)
            if not dims or min(dims) < 1 or max(dims) > 30_000:
                continue
            cursor = connection.execute(
                """INSERT OR IGNORE INTO images
                   (filename, original_name, mime, width, height, source, created_at)
                   VALUES (?, ?, ?, ?, ?, 'public', ?)""",
                (path.name, path.name, mime, dims[0], dims[1], int(path.stat().st_mtime)),
            )
            added += cursor.rowcount
        if own_connection:
            connection.commit()
    finally:
        if own_connection:
            connection.close()
    return added


def init_storage() -> None:
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    config.THUMBNAIL_DIR.mkdir(parents=True, exist_ok=True)
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    with db_connect() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL UNIQUE,
                original_name TEXT NOT NULL,
                mime TEXT NOT NULL,
                width INTEGER NOT NULL,
                height INTEGER NOT NULL,
                source TEXT NOT NULL DEFAULT 'upload',
                created_at INTEGER NOT NULL
            )
            """
        )
        image_columns = {row[1] for row in db.execute("PRAGMA table_info(images)").fetchall()}
        if "thumbnail_filename" not in image_columns:
            db.execute("ALTER TABLE images ADD COLUMN thumbnail_filename TEXT")
        if "deleted_at" not in image_columns:
            db.execute("ALTER TABLE images ADD COLUMN deleted_at INTEGER")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                csrf_token TEXT NOT NULL,
                access_code_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        db.execute("CREATE INDEX IF NOT EXISTS sessions_expires_at ON sessions(expires_at)")
        sync_public_images(db)


def prune_state() -> None:
    now = time.time()
    for nonce, (expires, _) in list(CHALLENGES.items()):
        if expires < now:
            CHALLENGES.pop(nonce, None)
    with db_connect() as db:
        db.execute("DELETE FROM sessions WHERE expires_at < ?", (int(now),))
    for token_hash, record in list(SESSION_CACHE.items()):
        if record[0] < now:
            SESSION_CACHE.pop(token_hash, None)


def session_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def session_cookie(token: str, max_age: int | None = None) -> str:
    lifetime = config.SESSION_TTL_SECONDS if max_age is None else max_age
    secure = "; Secure" if config.COOKIE_SECURE else ""
    expires = formatdate(time.time() + max(0, lifetime), usegmt=True)
    return (
        f"gallery_session={token}; Path=/; HttpOnly; SameSite=Strict; "
        f"Max-Age={lifetime}; Expires={expires}; Priority=High{secure}"
    )


class GalleryHandler(BaseHTTPRequestHandler):
    server_version = "PrivateGallery/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {self.client_address[0]} {fmt % args}")

    def send_json(self, payload: object, status: int = 200, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self, limit: int = 16_384) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > limit:
            return None
        try:
            payload = json.loads(self.rfile.read(length))
            return payload if isinstance(payload, dict) else None
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def current_session(self) -> tuple[str, str, str] | None:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("gallery_session")
        if not morsel:
            return None
        token_hash = session_token_hash(morsel.value)
        cached = SESSION_CACHE.get(token_hash)
        if cached:
            expires_at, csrf_token, access_code_id = cached
        else:
            with db_connect() as db:
                record = db.execute(
                    "SELECT csrf_token, access_code_id, expires_at FROM sessions WHERE token_hash = ?",
                    (token_hash,),
                ).fetchone()
            if not record:
                return None
            expires_at = record["expires_at"]
            csrf_token = record["csrf_token"]
            access_code_id = record["access_code_id"]
            SESSION_CACHE[token_hash] = (expires_at, csrf_token, access_code_id)
        if expires_at < time.time():
            SESSION_CACHE.pop(token_hash, None)
            return None
        if access_code_id not in active_access_code_ids():
            with db_connect() as db:
                db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            SESSION_CACHE.pop(token_hash, None)
            return None
        return morsel.value, csrf_token, access_code_id

    def require_auth(self, csrf: bool = False) -> tuple[str, str, str] | None:
        session = self.current_session()
        if not session:
            self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return None
        if csrf and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), session[1]):
            self.send_json({"error": "invalid_csrf"}, HTTPStatus.FORBIDDEN)
            return None
        return session

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/auth/challenge":
            return self.auth_challenge()
        if path == "/api/auth/session":
            session = self.current_session()
            headers = None
            if session:
                expires_at = int(time.time()) + config.SESSION_TTL_SECONDS
                with db_connect() as db:
                    db.execute(
                        "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
                        (expires_at, session_token_hash(session[0])),
                    )
                SESSION_CACHE[session_token_hash(session[0])] = (expires_at, session[1], session[2])
                headers = {"Set-Cookie": session_cookie(session[0])}
            return self.send_json(
                {"authenticated": bool(session), "csrf": session[1] if session else None},
                headers=headers,
            )
        if path == "/api/images":
            if not self.require_auth():
                return
            return self.list_images()
        if path.startswith("/images/"):
            if not self.require_auth():
                return
            return self.serve_gallery_image(path.removeprefix("/images/"))
        if path.startswith("/uploads/"):
            if not self.require_auth():
                return
            if path.startswith("/uploads/thumbnails/"):
                return self.serve_thumbnail(path.removeprefix("/uploads/thumbnails/"))
            return self.serve_upload(path.removeprefix("/uploads/"))
        return self.serve_public(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/auth/verify":
            return self.auth_verify()
        if path == "/api/auth/logout":
            return self.logout()
        if path == "/api/images":
            if not self.require_auth(csrf=True):
                return
            return self.upload_image()
        if path.startswith("/api/images/") and path.endswith("/thumbnail"):
            if not self.require_auth(csrf=True):
                return
            raw_id = path.removeprefix("/api/images/").removesuffix("/thumbnail").strip("/")
            if not raw_id.isdigit():
                return self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
            return self.upload_thumbnail(int(raw_id))
        self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if not path.startswith("/api/images/"):
            return self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        if not self.require_auth(csrf=True):
            return
        raw_id = path.removeprefix("/api/images/").strip("/")
        if not raw_id.isdigit():
            return self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        return self.delete_image(int(raw_id))

    def auth_challenge(self) -> None:
        prune_state()
        salt, iterations, _ = access_code_set()
        nonce = b64url(secrets.token_bytes(24))
        CHALLENGES[nonce] = (time.time() + config.CHALLENGE_TTL_SECONDS, self.client_address[0])
        self.send_json(
            {
                "nonce": nonce,
                "salt": salt,
                "iterations": iterations,
                "algorithm": "PBKDF2-HMAC-SHA256",
            }
        )

    def auth_verify(self) -> None:
        ip = self.client_address[0]
        now = time.time()
        failures = FAILED_ATTEMPTS[ip]
        while failures and failures[0] < now - 60:
            failures.popleft()
        if len(failures) >= 5:
            self.send_json({"error": "rate_limited"}, HTTPStatus.TOO_MANY_REQUESTS)
            return

        body = self.read_json()
        if not body:
            self.send_json({"error": "invalid_request"}, HTTPStatus.BAD_REQUEST)
            return
        nonce = str(body.get("nonce", ""))
        proof = str(body.get("proof", ""))
        challenge = CHALLENGES.pop(nonce, None)
        valid_challenge = challenge and challenge[0] >= now and challenge[1] == ip
        matched_access_code_id = None
        if valid_challenge:
            for access_code in access_code_set()[2]:
                expected = derive_proof_for_key(access_code["key"], nonce)
                if hmac.compare_digest(proof, expected) and matched_access_code_id is None:
                    matched_access_code_id = access_code["id"]
        if not valid_challenge or matched_access_code_id is None:
            failures.append(now)
            self.send_json({"error": "wrong_code"}, HTTPStatus.UNAUTHORIZED)
            return

        FAILED_ATTEMPTS.pop(ip, None)
        token = b64url(secrets.token_bytes(32))
        csrf_token = b64url(secrets.token_bytes(24))
        expires_at = int(now) + config.SESSION_TTL_SECONDS
        token_hash = session_token_hash(token)
        with db_connect() as db:
            db.execute(
                """INSERT INTO sessions
                   (token_hash, csrf_token, access_code_id, expires_at, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (token_hash, csrf_token, matched_access_code_id, expires_at, int(now)),
            )
        SESSION_CACHE[token_hash] = (expires_at, csrf_token, matched_access_code_id)
        self.send_json({"ok": True, "csrf": csrf_token}, headers={"Set-Cookie": session_cookie(token)})

    def logout(self) -> None:
        session = self.current_session()
        if session:
            token_hash = session_token_hash(session[0])
            with db_connect() as db:
                db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            SESSION_CACHE.pop(token_hash, None)
        self.send_json(
            {"ok": True},
            headers={"Set-Cookie": session_cookie("", 0)},
        )

    def list_images(self) -> None:
        sync_public_images()
        with db_connect() as db:
            rows = db.execute(
                """SELECT id, filename, original_name, mime, width, height, source,
                          thumbnail_filename, created_at
                   FROM images WHERE deleted_at IS NULL ORDER BY id DESC"""
            ).fetchall()
        images = []
        for row in rows:
            prefix = "/images/" if row["source"] in {"demo", "public"} else "/uploads/"
            image_url = f"{prefix}{row['filename']}?v={row['created_at']}"
            thumbnail_url = (
                "/uploads/thumbnails/" + row["thumbnail_filename"]
                if row["thumbnail_filename"]
                else image_url
            )
            images.append(
                {
                    "id": row["id"],
                    "url": image_url,
                    "thumbnailUrl": thumbnail_url,
                    "needsThumbnail": row["source"] == "upload" and not row["thumbnail_filename"],
                    "name": row["original_name"],
                    "width": row["width"],
                    "height": row["height"],
                    "createdAt": row["created_at"],
                }
            )
        self.send_json({"images": images})

    def upload_image(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > config.MAX_UPLOAD_BYTES:
            self.send_json({"error": "file_too_large"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return

        claimed_mime = self.headers.get("Content-Type", "").split(";", 1)[0].lower()
        data = self.rfile.read(length)
        actual_mime = detect_image_type(data)
        if actual_mime not in ALLOWED_MIME or claimed_mime not in ALLOWED_MIME:
            self.send_json({"error": "invalid_image"}, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            return
        dims = image_dimensions(data, actual_mime)
        if not dims or min(dims) < 1 or max(dims) > 30_000:
            self.send_json({"error": "invalid_dimensions"}, HTTPStatus.UNPROCESSABLE_ENTITY)
            return

        extensions = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "image/gif": ".gif"}
        filename = f"{int(time.time())}-{secrets.token_hex(10)}{extensions[actual_mime]}"
        destination = config.UPLOAD_DIR / filename
        destination.write_bytes(data)
        original_name = safe_original_name(self.headers.get("X-Filename", "image"))
        created = int(time.time())
        with db_connect() as db:
            cursor = db.execute(
                """INSERT INTO images (filename, original_name, mime, width, height, source, created_at)
                   VALUES (?, ?, ?, ?, ?, 'upload', ?)""",
                (filename, original_name, actual_mime, dims[0], dims[1], created),
            )
            image_id = cursor.lastrowid
        self.send_json(
            {
                "image": {
                    "id": image_id,
                    "url": "/uploads/" + filename,
                    "thumbnailUrl": "/uploads/" + filename,
                    "needsThumbnail": True,
                    "name": original_name,
                    "width": dims[0],
                    "height": dims[1],
                    "createdAt": created,
                }
            },
            HTTPStatus.CREATED,
        )

    def upload_thumbnail(self, image_id: int) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 3 * 1024 * 1024:
            self.send_json({"error": "thumbnail_too_large"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return

        data = self.rfile.read(length)
        actual_mime = detect_image_type(data)
        if actual_mime not in {"image/jpeg", "image/png", "image/webp"}:
            self.send_json({"error": "invalid_thumbnail"}, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            return
        dims = image_dimensions(data, actual_mime)
        if not dims or min(dims) < 1 or max(dims) > 2048:
            self.send_json({"error": "invalid_thumbnail_dimensions"}, HTTPStatus.UNPROCESSABLE_ENTITY)
            return

        with db_connect() as db:
            image = db.execute(
                "SELECT id, thumbnail_filename FROM images WHERE id = ? AND source = 'upload'",
                (image_id,),
            ).fetchone()
            if not image:
                self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
                return
            extensions = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}
            thumbnail_name = f"{image_id}-{secrets.token_hex(8)}{extensions[actual_mime]}"
            destination = config.THUMBNAIL_DIR / thumbnail_name
            destination.write_bytes(data)
            db.execute(
                "UPDATE images SET thumbnail_filename = ? WHERE id = ?",
                (thumbnail_name, image_id),
            )

        old_thumbnail = image["thumbnail_filename"]
        if old_thumbnail:
            (config.THUMBNAIL_DIR / old_thumbnail).unlink(missing_ok=True)
        self.send_json(
            {"thumbnailUrl": "/uploads/thumbnails/" + thumbnail_name},
            HTTPStatus.CREATED,
        )

    def delete_image(self, image_id: int) -> None:
        image = delete_image_record(image_id)
        if not image:
            self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
            return
        self.send_json({"ok": True, "id": image_id})

    def serve_upload(self, raw_name: str) -> None:
        name = Path(unquote(raw_name)).name
        if not name or name != unquote(raw_name):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.serve_file(config.UPLOAD_DIR / name, cache="private, max-age=31536000, immutable")

    def serve_thumbnail(self, raw_name: str) -> None:
        name = Path(unquote(raw_name)).name
        if not name or name != unquote(raw_name):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.serve_file(config.THUMBNAIL_DIR / name, cache="private, max-age=31536000, immutable")

    def serve_gallery_image(self, raw_name: str) -> None:
        name = Path(unquote(raw_name)).name
        if not name or name != unquote(raw_name):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        with db_connect() as db:
            image = db.execute(
                """SELECT id FROM images
                   WHERE filename = ? AND source IN ('demo', 'public') AND deleted_at IS NULL""",
                (name,),
            ).fetchone()
        if not image:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.serve_file(config.PUBLIC_DIR / "images" / name, cache="private, max-age=31536000, immutable")

    def serve_public(self, raw_path: str) -> None:
        path = unquote(raw_path)
        if path == "/":
            path = "/index.html"
        relative = Path(path.lstrip("/"))
        if any(part == ".." for part in relative.parts):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        cache = (
            "private, max-age=31536000, immutable"
            if relative.parts and relative.parts[0] == "images"
            else "no-cache"
        )
        self.serve_file(config.PUBLIC_DIR / relative, cache=cache)

    def serve_file(self, path: Path, cache: str) -> None:
        if not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content = path.read_bytes()
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.end_headers()
        self.wfile.write(content)


def create_server(host: str = config.HOST, port: int = config.PORT) -> ThreadingHTTPServer:
    access_code_set()
    init_storage()
    return ThreadingHTTPServer((host, port), GalleryHandler)


def generate_access_key_cli() -> int:
    code = getpass.getpass("10-digit access code: ").strip()
    confirmation = getpass.getpass("Repeat access code: ").strip()
    if code != confirmation:
        print("Codes do not match", file=sys.stderr)
        return 1
    if len(code) != 10 or not code.isdigit():
        print("Code must contain exactly 10 digits", file=sys.stderr)
        return 1
    salt = b64url(secrets.token_bytes(16))
    print(f"PBKDF2_SALT={salt}")
    print(f"ACCESS_KEY={b64url(derive_access_key(code, salt))}")
    return 0


def prompt_new_access_code() -> str | None:
    code = getpass.getpass("10-digit access code: ").strip()
    confirmation = getpass.getpass("Repeat access code: ").strip()
    if code != confirmation:
        print("Codes do not match", file=sys.stderr)
        return None
    if len(code) != 10 or not code.isdigit():
        print("Code must contain exactly 10 digits", file=sys.stderr)
        return None
    return code


def add_access_code_cli(label: str, path: Path | None = None) -> int:
    store_path = path or config.ACCESS_CODES_PATH
    store = load_access_store(store_path) or new_access_store()
    code = prompt_new_access_code()
    if code is None:
        return 1
    access_key = b64url(derive_access_key(code, store["salt"], store["iterations"]))
    if any(hmac.compare_digest(item["access_key"], access_key) for item in store["codes"]):
        print("This access code already exists", file=sys.stderr)
        return 1
    code_id = secrets.token_hex(4)
    store["codes"].append(
        {
            "id": code_id,
            "label": label.strip(),
            "access_key": access_key,
            "created_at": int(time.time()),
        }
    )
    write_access_store(store, store_path)
    print(f"Added {label.strip()} ({code_id}) to {store_path}")
    return 0


def list_access_codes_cli(path: Path | None = None) -> int:
    store_path = path or config.ACCESS_CODES_PATH
    store = load_access_store(store_path)
    if store is None or not store["codes"]:
        print(f"No access codes in {store_path}")
        return 0
    for item in store["codes"]:
        created = time.strftime("%Y-%m-%d", time.localtime(item["created_at"])) if item["created_at"] else "unknown"
        print(f"{item['id']}  {item['label']}  created {created}")
    return 0


def remove_access_code_cli(code_id: str, path: Path | None = None) -> int:
    global ACCESS_CODE_SET_CACHE
    store_path = path or config.ACCESS_CODES_PATH
    store = load_access_store(store_path)
    if store is None:
        print(f"Access code file does not exist: {store_path}", file=sys.stderr)
        return 1
    remaining = [item for item in store["codes"] if item["id"] != code_id]
    if len(remaining) == len(store["codes"]):
        print(f"Unknown access code id: {code_id}", file=sys.stderr)
        return 1
    store["codes"] = remaining
    write_access_store(store, store_path)
    ACCESS_CODE_SET_CACHE = None
    for token_hash, record in list(SESSION_CACHE.items()):
        if record[2] == code_id:
            SESSION_CACHE.pop(token_hash, None)
    if config.DATABASE_PATH.exists():
        try:
            with db_connect() as db:
                db.execute("DELETE FROM sessions WHERE access_code_id = ?", (code_id,))
        except sqlite3.OperationalError:
            pass
    print(f"Removed {code_id} from {store_path}; its sessions were revoked")
    return 0


def print_usage() -> None:
    print(
        "Usage:\n"
        "  python3 server.py\n"
        "  python3 server.py access-code add <label>\n"
        "  python3 server.py access-code list\n"
        "  python3 server.py access-code remove <id>\n"
        "  python3 server.py generate-access-key",
        file=sys.stderr,
    )


if __name__ == "__main__":
    if sys.argv[1:] == ["generate-access-key"]:
        raise SystemExit(generate_access_key_cli())
    if sys.argv[1:3] == ["access-code", "add"] and len(sys.argv) == 4 and sys.argv[3].strip():
        raise SystemExit(add_access_code_cli(sys.argv[3]))
    if sys.argv[1:] == ["access-code", "list"]:
        raise SystemExit(list_access_codes_cli())
    if sys.argv[1:3] == ["access-code", "remove"] and len(sys.argv) == 4:
        raise SystemExit(remove_access_code_cli(sys.argv[3]))
    if sys.argv[1:]:
        print_usage()
        raise SystemExit(2)
    server = create_server()
    print(f"Private Gallery running at http://{config.HOST}:{config.PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping…")
    finally:
        server.server_close()
