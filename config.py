"""Server-side configuration for the private gallery.

Never expose this module through the static file handler. Production values should
be supplied with environment variables; the defaults are for local development.
"""

from __future__ import annotations

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"
UPLOAD_DIR = BASE_DIR / "uploads"
THUMBNAIL_DIR = UPLOAD_DIR / "thumbnails"
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "gallery.sqlite3"
ACCESS_CODES_PATH = Path(os.getenv("ACCESS_CODES_PATH", str(DATA_DIR / "access-codes.json")))

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8080"))

# ACCESS_CODE is a local-development fallback. Production should store only the
# generated ACCESS_KEY verifier and leave ACCESS_CODE unset.
ACCESS_CODE = os.getenv("ACCESS_CODE", "").strip()
ACCESS_KEY = os.getenv("ACCESS_KEY", "").strip()
if not ACCESS_CODE and not ACCESS_KEY:
    ACCESS_CODE = "1234567890"
PBKDF2_SALT = os.getenv("PBKDF2_SALT", "capi-gallery-v1")
PBKDF2_ITERATIONS = int(os.getenv("PBKDF2_ITERATIONS", "180000"))
# Current Chromium-based browsers cap persistent cookies at roughly 400 days.
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "34560000"))
CHALLENGE_TTL_SECONDS = int(os.getenv("CHALLENGE_TTL_SECONDS", "120"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(15 * 1024 * 1024)))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"


def is_valid_access_code(value: str) -> bool:
    return len(value) == 10 and value.isascii() and value.isalnum()


if ACCESS_CODE and ACCESS_KEY:
    raise RuntimeError("Set ACCESS_KEY or ACCESS_CODE, not both")
if ACCESS_CODE and not is_valid_access_code(ACCESS_CODE):
    raise RuntimeError("ACCESS_CODE must contain exactly 10 ASCII letters or digits")
