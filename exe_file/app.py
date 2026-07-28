from __future__ import annotations

import logging
import tkinter.messagebox as messagebox

from config import ConfigError, load_config, setup_logging
from database import SupabaseDatabase
from product_store import LocalProductStore
from ui import CiscoAdvisoryApp


def main() -> int:
    setup_logging()
    logger = logging.getLogger(__name__)

    try:
        settings = load_config()
        database = SupabaseDatabase(
            supabase_url=settings["SUPABASE_URL"],
            supabase_key=settings["SUPABASE_KEY"],
            advisory_tables=settings["SUPABASE_TABLES"],
        )
        database.connect()
    except ConfigError as exc:
        logger.error("Configuration error: %s", exc)
        messagebox.showerror("Configuration Error", str(exc))
        return 1
    except Exception as exc:
        logger.error("Startup failed: %s", exc, exc_info=True)
        messagebox.showerror(
            "Supabase Connection Error",
            "Could not connect to Supabase. Check your internet connection, "
            "environment variables, and advisory table name.\n\n"
            f"Details: {exc}",
        )
        return 1

    app = CiscoAdvisoryApp(database, LocalProductStore())
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
