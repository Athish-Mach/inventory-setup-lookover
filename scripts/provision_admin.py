"""Provision a real administrator with an interactively entered password."""

from __future__ import annotations

import getpass
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402
from pwdlib import PasswordHash  # noqa: E402
from supabase_client import create_resilient_client  # noqa: E402


USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


def main() -> None:
    load_dotenv(ROOT / ".env")
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        raise SystemExit("Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY first.")

    username = input("New admin username: ").strip().casefold()
    if not USERNAME_RE.fullmatch(username):
        raise SystemExit("Use 3–64 letters, numbers, dots, underscores, or hyphens.")
    password = getpass.getpass("New admin password (minimum 14 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 14 or password != confirmation:
        raise SystemExit("Passwords must match and be at least 14 characters long.")

    client = create_resilient_client(url, key)
    existing = (
        client.table("app_users")
        .select("username")
        .eq("username", username)
        .limit(1)
        .execute()
    )
    if getattr(existing, "data", None):
        raise SystemExit("That account already exists; refusing to overwrite it.")

    client.table("app_users").insert(
        {
            "username": username,
            "password_hash": PasswordHash.recommended().hash(password),
            "role": "admin",
            "is_active": True,
        }
    ).execute()
    print(f"Created administrator account {username!r}.")


if __name__ == "__main__":
    main()
