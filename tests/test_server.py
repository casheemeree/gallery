from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import config
import server


class AuthTests(unittest.TestCase):
    def test_proof_matches_protocol(self) -> None:
        nonce = "test-nonce"
        key = hashlib.pbkdf2_hmac(
            "sha256",
            config.ACCESS_CODE.encode(),
            config.PBKDF2_SALT.encode(),
            config.PBKDF2_ITERATIONS,
            dklen=32,
        )
        expected = base64.urlsafe_b64encode(hmac.new(key, nonce.encode(), hashlib.sha256).digest()).decode().rstrip("=")
        self.assertEqual(server.derive_proof(config.ACCESS_CODE, nonce), expected)

    def test_wrong_code_creates_different_proof(self) -> None:
        self.assertNotEqual(server.derive_proof(config.ACCESS_CODE, "nonce"), server.derive_proof("0000000000", "nonce"))

    def test_proof_can_be_verified_from_stored_key(self) -> None:
        key = server.derive_access_key(config.ACCESS_CODE)
        self.assertEqual(server.derive_proof(config.ACCESS_CODE, "nonce"), server.derive_proof_for_key(key, "nonce"))

    def test_access_key_round_trip(self) -> None:
        key = server.derive_access_key(config.ACCESS_CODE)
        self.assertEqual(server.b64url_decode(server.b64url(key)), key)

    def test_persistent_cookie_uses_long_lifetime_and_security_flags(self) -> None:
        cookie = server.session_cookie("token")
        self.assertIn(f"Max-Age={config.SESSION_TTL_SECONDS}", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)


class AccessCodeStoreTests(unittest.TestCase):
    def test_json_stores_multiple_derived_keys_without_plain_codes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "access-codes.json"
            store = {
                "version": 1,
                "salt": "test-gallery-salt",
                "iterations": 180_000,
                "codes": [
                    {
                        "id": "owner",
                        "label": "Owner",
                        "access_key": server.b64url(server.derive_access_key("1234567890", "test-gallery-salt", 180_000)),
                        "created_at": 1,
                    },
                    {
                        "id": "guest",
                        "label": "Guest",
                        "access_key": server.b64url(server.derive_access_key("0987654321", "test-gallery-salt", 180_000)),
                        "created_at": 2,
                    },
                ],
            }
            server.write_access_store(store, path)
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("1234567890", raw)
            self.assertNotIn("0987654321", raw)
            self.assertEqual(len(server.access_code_set(path)[2]), 2)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    @mock.patch.object(server, "prompt_new_access_code", return_value="1234567890")
    def test_cli_adds_code_to_new_json(self, _prompt: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "access-codes.json"
            self.assertEqual(server.add_access_code_cli("Local", path), 0)
            store = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(store["codes"][0]["label"], "Local")
            self.assertNotIn("1234567890", path.read_text(encoding="utf-8"))
            code_id = store["codes"][0]["id"]
            with mock.patch.object(config, "DATABASE_PATH", Path(temporary_directory) / "missing.sqlite3"):
                self.assertEqual(server.remove_access_code_cli(code_id, path), 0)
            self.assertEqual(server.load_access_store(path)["codes"], [])

    def test_session_token_is_persisted_only_as_a_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "gallery.sqlite3"
            with mock.patch.object(config, "DATABASE_PATH", database_path):
                server.init_storage()
                token = "browser-cookie-token"
                with server.db_connect() as db:
                    db.execute(
                        """INSERT INTO sessions
                           (token_hash, csrf_token, access_code_id, expires_at, created_at)
                           VALUES (?, ?, ?, ?, ?)""",
                        (server.session_token_hash(token), "csrf", "owner", int(time.time()) + 60, int(time.time())),
                    )
                    row = db.execute("SELECT token_hash FROM sessions").fetchone()
                self.assertNotEqual(row["token_hash"], token)
                self.assertEqual(row["token_hash"], hashlib.sha256(token.encode("ascii")).hexdigest())


class ImageTests(unittest.TestCase):
    def storage_patches(self, root: Path):
        public_dir = root / "public"
        upload_dir = root / "uploads"
        thumbnail_dir = upload_dir / "thumbnails"
        public_dir.mkdir()
        (public_dir / "images").mkdir()
        upload_dir.mkdir()
        thumbnail_dir.mkdir()
        return mock.patch.multiple(
            config,
            DATABASE_PATH=root / "data" / "gallery.sqlite3",
            DATA_DIR=root / "data",
            PUBLIC_DIR=public_dir,
            UPLOAD_DIR=upload_dir,
            THUMBNAIL_DIR=thumbnail_dir,
        )

    def test_detects_supported_signatures(self) -> None:
        self.assertEqual(server.detect_image_type(b"\xff\xd8\xff\x00"), "image/jpeg")
        self.assertEqual(server.detect_image_type(b"\x89PNG\r\n\x1a\nrest"), "image/png")
        self.assertEqual(server.detect_image_type(b"GIF89a" + b"\0" * 10), "image/gif")
        self.assertEqual(server.detect_image_type(b"RIFF\x00\x00\x00\x00WEBP"), "image/webp")
        self.assertIsNone(server.detect_image_type(b"not-an-image"))

    def test_reads_png_dimensions(self) -> None:
        data = b"\x89PNG\r\n\x1a\n" + b"\0" * 8 + (640).to_bytes(4, "big") + (480).to_bytes(4, "big")
        self.assertEqual(server.image_dimensions(data, "image/png"), (640, 480))

    def test_reads_extended_webp_dimensions(self) -> None:
        data = b"RIFF" + b"\0" * 4 + b"WEBPVP8X" + b"\0" * 8
        data += (511).to_bytes(3, "little") + (682).to_bytes(3, "little")
        self.assertEqual(server.image_dimensions(data, "image/webp"), (512, 683))

    def test_reads_lossy_webp_dimensions(self) -> None:
        data = b"RIFF" + b"\0" * 4 + b"WEBPVP8 " + b"\0" * 7 + b"\x9d\x01\x2a"
        data += (640).to_bytes(2, "little") + (480).to_bytes(2, "little")
        self.assertEqual(server.image_dimensions(data, "image/webp"), (640, 480))

    def test_reads_lossless_webp_dimensions(self) -> None:
        width, height = 321, 654
        bits = (width - 1) | ((height - 1) << 14)
        data = b"RIFF" + b"\0" * 4 + b"WEBPVP8L" + b"\0" * 4 + b"\x2f" + bits.to_bytes(4, "little")
        self.assertEqual(server.image_dimensions(data, "image/webp"), (width, height))

    def test_sanitizes_original_filename(self) -> None:
        self.assertEqual(server.safe_original_name("../../my%20photo!.jpg"), "my photo.jpg")

    def test_delete_uploaded_image_removes_database_row_and_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with self.storage_patches(root):
                server.init_storage()
                original = config.UPLOAD_DIR / "upload.webp"
                thumbnail = config.THUMBNAIL_DIR / "thumb.webp"
                original.write_bytes(b"original")
                thumbnail.write_bytes(b"thumbnail")
                with server.db_connect() as db:
                    cursor = db.execute(
                        """INSERT INTO images
                           (filename, original_name, mime, width, height, source,
                            thumbnail_filename, created_at)
                           VALUES (?, ?, ?, ?, ?, 'upload', ?, ?)""",
                        ("upload.webp", "upload.webp", "image/webp", 20, 30, "thumb.webp", 1),
                    )
                    image_id = cursor.lastrowid

                self.assertIsNotNone(server.delete_image_record(image_id))
                self.assertFalse(original.exists())
                self.assertFalse(thumbnail.exists())
                with server.db_connect() as db:
                    self.assertIsNone(db.execute("SELECT id FROM images WHERE id = ?", (image_id,)).fetchone())

    def test_delete_public_image_keeps_file_and_creates_tombstone(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with self.storage_patches(root):
                server.init_storage()
                original = config.PUBLIC_DIR / "images" / "public.png"
                original.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 8 + (20).to_bytes(4, "big") + (30).to_bytes(4, "big"))
                with server.db_connect() as db:
                    cursor = db.execute(
                        """INSERT INTO images
                           (filename, original_name, mime, width, height, source, created_at)
                           VALUES (?, ?, ?, ?, ?, 'public', ?)""",
                        ("public.png", "public.png", "image/png", 20, 30, 1),
                    )
                    image_id = cursor.lastrowid

                self.assertIsNotNone(server.delete_image_record(image_id))
                self.assertTrue(original.exists())
                self.assertEqual(server.sync_public_images(), 0)
                with server.db_connect() as db:
                    row = db.execute("SELECT deleted_at FROM images WHERE id = ?", (image_id,)).fetchone()
                    count = db.execute("SELECT COUNT(*) FROM images WHERE filename = 'public.png'").fetchone()[0]
                self.assertIsNotNone(row["deleted_at"])
                self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
