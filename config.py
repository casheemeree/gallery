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
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "gallery.sqlite3"

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8080"))

# Local-only default. Set a unique 10-digit value in production.
ACCESS_CODE = os.getenv("ACCESS_CODE", "1234567890")
PBKDF2_SALT = os.getenv("PBKDF2_SALT", "capi-gallery-v1")
PBKDF2_ITERATIONS = int(os.getenv("PBKDF2_ITERATIONS", "180000"))
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "86400"))
CHALLENGE_TTL_SECONDS = int(os.getenv("CHALLENGE_TTL_SECONDS", "120"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(15 * 1024 * 1024)))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"

if len(ACCESS_CODE) != 10 or not ACCESS_CODE.isdigit():
    raise RuntimeError("ACCESS_CODE must contain exactly 10 digits")
