from __future__ import annotations

import json
import logging
import threading

from config import PRODUCTS_FILE
from utils import normalize_for_match, validate_product_name

logger = logging.getLogger(__name__)


class LocalProductStore:
    def __init__(self) -> None:
        self.path = PRODUCTS_FILE
        self._lock = threading.Lock()

    def get_products(self) -> list[str]:
        with self._lock:
            return self._read_products()

    def add_product(self, product_name: str) -> tuple[bool, str]:
        cleaned = validate_product_name(product_name)
        with self._lock:
            products = self._read_products()
            normalized_existing = {normalize_for_match(product) for product in products}
            if normalize_for_match(cleaned) in normalized_existing:
                return False, f"{cleaned} is already being monitored."

            products.append(cleaned)
            products.sort(key=str.casefold)
            self._write_products(products)

        logger.info("Product added: %s", cleaned)
        return True, f"Monitoring started for {cleaned}."

    def _read_products(self) -> list[str]:
        if not self.path.exists():
            return []

        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.error("Could not parse local monitored products file: %s", exc)
            return []
        except OSError as exc:
            logger.error("Could not read local monitored products file: %s", exc)
            return []

        if not isinstance(payload, list):
            logger.error("Local monitored products file must contain a JSON list")
            return []

        products: list[str] = []
        seen: set[str] = set()
        for item in payload:
            if not isinstance(item, str):
                logger.warning("Invalid local monitored product skipped: %r", item)
                continue
            try:
                cleaned = validate_product_name(item)
            except ValueError:
                logger.warning("Invalid local monitored product skipped: %r", item)
                continue
            normalized = normalize_for_match(cleaned)
            if normalized not in seen:
                products.append(cleaned)
                seen.add(normalized)

        products.sort(key=str.casefold)
        return products

    def _write_products(self, products: list[str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(products, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
