from __future__ import annotations

import logging
from typing import Any

from supabase import Client, create_client

logger = logging.getLogger(__name__)


class SupabaseDatabase:
    def __init__(self, supabase_url: str, supabase_key: str, advisory_tables: list[str]) -> None:
        self.supabase_url = supabase_url
        self.supabase_key = supabase_key
        self.advisory_tables = list(dict.fromkeys(advisory_tables))
        self.client: Client | None = None

    def connect(self) -> None:
        self.client = create_client(self.supabase_url, self.supabase_key)
        self.health_check()
        logger.info("Connection established")

    def _client(self) -> Client:
        if self.client is None:
            raise RuntimeError("Supabase client is not connected.")
        return self.client

    def health_check(self) -> None:
        try:
            for table in self.advisory_tables:
                self._client().table(table).select("id").limit(1).execute()
        except Exception as exc:
            if "PGRST205" in str(exc):
                raise RuntimeError(
                    f"A configured Supabase advisory table was not found: {exc}. "
                    "Check SUPABASE_TABLES in .env."
                ) from exc
            raise

    def get_advisories(self) -> list[dict[str, Any]]:
        # Supabase REST responses are commonly capped at 1,000 rows.
        # Page through the table so the UI receives every current row.
        page_size = 1_000
        rows: list[Any] = []
        try:
            for table in self.advisory_tables:
                offset = 0
                while True:
                    response = (
                        self._client()
                        .table(table)
                        .select("*")
                        .range(offset, offset + page_size - 1)
                        .execute()
                    )
                    page = response.data or []
                    for row in page:
                        if isinstance(row, dict):
                            row = dict(row)
                            row["_source_table"] = table
                        rows.append(row)
                    if len(page) < page_size:
                        break
                    offset += page_size
        except Exception as exc:
            logger.error("Failed fetching Supabase advisory tables: %s", exc, exc_info=True)
            raise RuntimeError(f"Could not read Supabase advisory tables: {exc}") from exc

        valid_rows: list[dict[str, Any]] = []
        seen_ids: set[Any] = set()
        seen_hashes: set[str] = set()

        for row in rows:
            if not isinstance(row, dict):
                logger.warning("Invalid advisory row skipped: %r", row)
                continue

            row_id = row.get("id")
            if row_id is not None:
                if row_id in seen_ids:
                    continue
                seen_ids.add(row_id)
            else:
                try:
                    items = tuple(sorted(row.items()))
                    h = repr(items)
                except Exception:
                    h = repr(row)
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)

            if row_id is None:
                logger.warning("Advisory row missing id: %r", row)
            valid_rows.append(row)

        return valid_rows

    def insert_advisory(self, advisory: dict[str, Any]) -> None:
        if not self.advisory_tables:
            raise RuntimeError("No advisory tables configured.")
        target_table = self.advisory_tables[0]
        self._client().table(target_table).insert(advisory).execute()

    def next_advisory_id(self) -> int:
        if not self.advisory_tables:
            return 1
        target_table = self.advisory_tables[0]
        try:
            response = (
                self._client()
                .table(target_table)
                .select("id")
                .order("id", desc=True)
                .limit(1)
                .execute()
            )
            if response.data and len(response.data) > 0:
                current_max = response.data[0].get("id")
                if isinstance(current_max, int):
                    return current_max + 1
        except Exception as exc:
            logger.warning("Could not fetch max advisory id: %s", exc)
        return 1

