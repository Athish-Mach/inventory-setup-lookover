from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime, timedelta

from dotenv import load_dotenv
import os


APP_NAME = "Cisco Security Advisory Monitor"
ADVISORY_TABLE = "cisco_security_advisories"
POLL_INTERVAL_SECONDS = 15
LOG_RETENTION_DAYS = 7  # Keep logs for this many days

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "application.log"
DATA_DIR = BASE_DIR / "data"
PRODUCTS_FILE = DATA_DIR / "monitored_products.json"


class ConfigError(RuntimeError):
    """Raised when required application configuration is missing."""


def setup_logging() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    cleanup_old_files()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=1_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.handlers.clear()
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)


def load_config() -> dict[str, str]:
    load_dotenv()

    supabase_url = os.getenv("SUPABASE_URL", "").strip()
    supabase_key = os.getenv("SUPABASE_KEY", "").strip()
    supabase_tables = [
        table.strip()
        for table in os.getenv("SUPABASE_TABLES", "").split(",")
        if table.strip()
    ]
    if not supabase_tables:
        legacy_table = os.getenv("SUPABASE_TABLE", ADVISORY_TABLE).strip()
        supabase_tables = [legacy_table or ADVISORY_TABLE]

    missing = [
        name
        for name, value in {
            "SUPABASE_URL": supabase_url,
            "SUPABASE_KEY": supabase_key,
        }.items()
        if not value
    ]
    if missing:
        raise ConfigError(
            "Missing required environment variable(s): " + ", ".join(missing)
        )

    return {
        "SUPABASE_URL": supabase_url,
        "SUPABASE_KEY": supabase_key,
        "SUPABASE_TABLES": supabase_tables,
    }


def cleanup_old_files() -> None:
    """Delete old log files and cached data older than LOG_RETENTION_DAYS."""
    try:
        if not LOG_DIR.exists():
            return
        
        cutoff_time = datetime.now() - timedelta(days=LOG_RETENTION_DAYS)
        
        # Clean up old log files
        for log_file in LOG_DIR.glob("*.log*"):
            try:
                file_mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                if file_mtime < cutoff_time:
                    log_file.unlink()
                    print(f"Deleted old log file: {log_file.name}")
            except (OSError, ValueError):
                pass
    except Exception as exc:
        print(f"Error during cleanup: {exc}")
