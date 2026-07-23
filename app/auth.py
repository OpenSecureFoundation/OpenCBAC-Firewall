from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path


HASH_NAME = "sha256"
ITERATIONS = 390_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(HASH_NAME, password.encode("utf-8"), salt, ITERATIONS)
    return (
        f"pbkdf2_{HASH_NAME}${ITERATIONS}$"
        f"{base64.b64encode(salt).decode()}$"
        f"{base64.b64encode(digest).decode()}"
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = stored_hash.split("$", 3)
        if algorithm != f"pbkdf2_{HASH_NAME}":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac(
            HASH_NAME, password.encode("utf-8"), salt, int(iterations)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def load_admin(admin_file: Path) -> dict:
    with admin_file.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def authenticate(admin_file: Path, username: str, password: str) -> bool:
    admin = load_admin(admin_file)
    return username == admin.get("username") and verify_password(
        password, admin.get("password_hash", "")
    )
