#!/usr/bin/env python3
"""Zero-dependency HTTP server for the private infinite gallery."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import sqlite3
import struct
import time
from collections import defaultdict, deque
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

import config


CHALLENGES: dict[str, tuple[float, str]] = {}
SESSIONS: dict[str, tuple[float, str]] = {}
FAILED_ATTEMPTS: defaultdict[str, deque[float]] = defaultdict(deque)
ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp", "image/gif"}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def derive_proof(code: str, nonce: str) -> str:
    key = hashlib.pbkdf2_hmac(
        "sha256",
        code.encode("utf-8"),
        config.PBKDF2_SALT.encode("utf-8"),
        config.PBKDF2_ITERATIONS,
        dklen=32,
    )
    return b64url(hmac.new(key, nonce.encode("ascii"), hashlib.sha256).digest())


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
        if mime == "image/webp" and len(data) >= 30:
            kind = data[12:16]
            if kind == b"VP8X":
                w = 1 + int.from_bytes(data[24:27], "little")
                h = 1 + int.from_bytes(data[27:30], "little")
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


def init_storage() -> None:
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
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
        count = db.execute("SELECT COUNT(*) FROM images").fetchone()[0]
        if count == 0:
            for path in sorted((config.PUBLIC_DIR / "images").glob("demo-*.jpg")):
                data = path.read_bytes()
                dims = image_dimensions(data, "image/jpeg") or (900, 1200)
                db.execute(
                    """INSERT OR IGNORE INTO images
                       (filename, original_name, mime, width, height, source, created_at)
                       VALUES (?, ?, ?, ?, ?, 'demo', ?)""",
                    (path.name, path.name, "image/jpeg", dims[0], dims[1], int(path.stat().st_mtime)),
                )


def prune_state() -> None:
    now = time.time()
    for nonce, (expires, _) in list(CHALLENGES.items()):
        if expires < now:
            CHALLENGES.pop(nonce, None)
    for token, (expires, _) in list(SESSIONS.items()):
        if expires < now:
            SESSIONS.pop(token, None)


class GalleryHandler(BaseHTTPRequestHandler):
    server_version = "CapiGallery/1.0"

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

    def current_session(self) -> tuple[str, str] | None:
        prune_state()
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("gallery_session")
        if not morsel:
            return None
        record = SESSIONS.get(morsel.value)
        if not record or record[0] < time.time():
            return None
        return morsel.value, record[1]

    def require_auth(self, csrf: bool = False) -> tuple[str, str] | None:
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
            return self.send_json({"authenticated": bool(session), "csrf": session[1] if session else None})
        if path == "/api/images":
            if not self.require_auth():
                return
            return self.list_images()
        if path.startswith("/uploads/"):
            if not self.require_auth():
                return
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
        self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)

    def auth_challenge(self) -> None:
        prune_state()
        nonce = b64url(secrets.token_bytes(24))
        CHALLENGES[nonce] = (time.time() + config.CHALLENGE_TTL_SECONDS, self.client_address[0])
        self.send_json(
            {
                "nonce": nonce,
                "salt": config.PBKDF2_SALT,
                "iterations": config.PBKDF2_ITERATIONS,
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
        expected = derive_proof(config.ACCESS_CODE, nonce) if valid_challenge else "invalid"
        if not valid_challenge or not hmac.compare_digest(proof, expected):
            failures.append(now)
            self.send_json({"error": "wrong_code"}, HTTPStatus.UNAUTHORIZED)
            return

        FAILED_ATTEMPTS.pop(ip, None)
        token = b64url(secrets.token_bytes(32))
        csrf_token = b64url(secrets.token_bytes(24))
        SESSIONS[token] = (now + config.SESSION_TTL_SECONDS, csrf_token)
        secure = "; Secure" if config.COOKIE_SECURE else ""
        cookie = f"gallery_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={config.SESSION_TTL_SECONDS}{secure}"
        self.send_json({"ok": True, "csrf": csrf_token}, headers={"Set-Cookie": cookie})

    def logout(self) -> None:
        session = self.current_session()
        if session:
            SESSIONS.pop(session[0], None)
        self.send_json(
            {"ok": True},
            headers={"Set-Cookie": "gallery_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"},
        )

    def list_images(self) -> None:
        with db_connect() as db:
            rows = db.execute(
                "SELECT id, filename, original_name, mime, width, height, source, created_at FROM images ORDER BY id DESC"
            ).fetchall()
        images = []
        for row in rows:
            prefix = "/images/" if row["source"] == "demo" else "/uploads/"
            images.append(
                {
                    "id": row["id"],
                    "url": prefix + row["filename"],
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
                    "name": original_name,
                    "width": dims[0],
                    "height": dims[1],
                    "createdAt": created,
                }
            },
            HTTPStatus.CREATED,
        )

    def serve_upload(self, raw_name: str) -> None:
        name = Path(unquote(raw_name)).name
        if not name or name != unquote(raw_name):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.serve_file(config.UPLOAD_DIR / name, cache="private, max-age=86400")

    def serve_public(self, raw_path: str) -> None:
        path = unquote(raw_path)
        if path == "/":
            path = "/index.html"
        relative = Path(path.lstrip("/"))
        if any(part == ".." for part in relative.parts):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.serve_file(config.PUBLIC_DIR / relative, cache="public, max-age=3600")

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
    init_storage()
    return ThreadingHTTPServer((host, port), GalleryHandler)


if __name__ == "__main__":
    server = create_server()
    print(f"CAPI Gallery running at http://{config.HOST}:{config.PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping…")
    finally:
        server.server_close()
