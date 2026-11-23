"""Create the explicitly local-only admin/admin123 demo account."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402
from pwdlib import PasswordHash  # noqa: E402
from supabase_client import create_resilient_client  # noqa: E402


def main() -> None:
    load_dotenv(ROOT / ".env")
    if os.getenv("DEMO_MODE", "").casefold() != "true":
        raise SystemExit("Set DEMO_MODE=true to seed the local demo account.")
    if os.getenv("VERCEL") or os.getenv("VERCEL_ENV") or os.getenv("APP_ENV", "").casefold() in {"prod", "production"}:
        raise SystemExit("Demo credentials are disabled in deployed or production environments.")

    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        raise SystemExit("Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY first.")
    if (urlparse(url).hostname or "").casefold() not in {"localhost", "127.0.0.1", "::1"}:
        raise SystemExit("The demo password is allowed only with a local Supabase instance. Use provision_admin.py for a deployed project.")

    client = create_resilient_client(url, key)
    existing = (
        client.table("app_users")
        .select("username")
        .eq("username", "admin")
        .limit(1)
        .execute()
    )
    if getattr(existing, "data", None):
        raise SystemExit("The admin account already exists; refusing to reset its password.")

    password_hash = PasswordHash.recommended().hash("admin123")
    client.table("app_users").insert(
        {
            "username": "admin",
            "password_hash": password_hash,
            "role": "admin",
            "is_active": True,
        }
    ).execute()
    print("Created the local demo account: admin / admin123")


if __name__ == "__main__":
    main()
