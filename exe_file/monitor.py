from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Callable

from config import POLL_INTERVAL_SECONDS, cleanup_old_files
from database import SupabaseDatabase
from utils import (
    advisory_fingerprint,
    advisory_key,
    format_timestamp,
    parse_affected_products,
    products_matching_advisory,
    send_windows_notification,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MonitorStatus:
    message: str
    last_checked: str
    monitored_count: int
    connected: bool


@dataclass(frozen=True)
class AdvisoryMatch:
    row: dict[str, Any]
    matched_products: list[str]
    is_new: bool


@dataclass(frozen=True)
class AdvisorySnapshot:
    rows: list[dict[str, Any]]
    new_or_updated_keys: set[str]


class AdvisoryMonitor:
    def __init__(
        self,
        database: SupabaseDatabase,
        get_monitored_products: Callable[[], list[str]],
        on_status: Callable[[MonitorStatus], None],
        on_advisories: Callable[[AdvisorySnapshot], None],
        poll_interval: int = POLL_INTERVAL_SECONDS,
    ) -> None:
        self.database = database
        self.get_monitored_products = get_monitored_products
        self.on_status = on_status
        self.on_advisories = on_advisories
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen_fingerprints: dict[str, str] = {}
        self._notified: set[tuple[str, str, str]] = set()
        self._cleanup_counter = 0  # Counter for periodic cleanup

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="AdvisoryMonitor",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def trigger_check(self) -> None:
        threading.Thread(
            target=self.check_once,
            name="AdvisoryMonitorManualCheck",
            daemon=True,
        ).start()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self.check_once()
            self._stop_event.wait(self.poll_interval)

    def check_once(self) -> None:
        # Perform cleanup every 10th check (approximately every 150 seconds with 15s interval)
        self._cleanup_counter += 1
        if self._cleanup_counter >= 10:
            try:
                cleanup_old_files()
            except Exception as exc:
                logger.warning("Cleanup failed: %s", exc)
            self._cleanup_counter = 0

        status = MonitorStatus(
            message="Checking for updates...",
            last_checked=format_timestamp(),
            monitored_count=0,
            connected=True,
        )
        self.on_status(status)

        try:
            monitored_products = self.get_monitored_products()
            rows = self.database.get_advisories()
            logger.info("Database updates detected during polling check")

            new_or_updated_keys: set[str] = set()
            for row in rows:
                key = advisory_key(row)
                fingerprint = advisory_fingerprint(row)
                previous_fingerprint = self._seen_fingerprints.get(key)
                is_new = previous_fingerprint != fingerprint
                if is_new:
                    new_or_updated_keys.add(key)
                self._seen_fingerprints[key] = fingerprint

                affected_products = parse_affected_products(row.get("affected_products"))
                matched_products = products_matching_advisory(
                    monitored_products,
                    affected_products,
                )
                if not matched_products:
                    continue

                if is_new:
                    logger.info(
                        "Matching advisories found: advisory=%s products=%s",
                        row.get("id"),
                        ", ".join(matched_products),
                    )
                    self._notify_once(key, fingerprint, matched_products)

            self.on_advisories(
                AdvisorySnapshot(
                    rows=rows,
                    new_or_updated_keys=new_or_updated_keys,
                )
            )

            self.on_status(
                MonitorStatus(
                    message="Waiting for updates...",
                    last_checked=format_timestamp(),
                    monitored_count=len(monitored_products),
                    connected=True,
                )
            )
        except Exception as exc:
            logger.error("Monitor check failed: %s", exc, exc_info=True)
            self.on_status(
                MonitorStatus(
                    message=f"Error: {exc}",
                    last_checked=format_timestamp(),
                    monitored_count=0,
                    connected=False,
                )
            )

    def _notify_once(
        self,
        advisory_key_value: str,
        fingerprint: str,
        matched_products: list[str],
    ) -> None:
        for product in matched_products:
            notification_key = (advisory_key_value, fingerprint, product.casefold())
            if notification_key in self._notified:
                continue
            self._notified.add(notification_key)
            send_windows_notification(
                "Cisco Security Advisory",
                f"New advisory found for {product}",
            )
