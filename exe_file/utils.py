from __future__ import annotations

import hashlib
import json
import logging
import re
import sys
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


PRODUCT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+\-/()]{1,119}$")
PRODUCT_EXCLUSION_PHRASES = (
    "for information",
    "fixed software",
    "software releases are vulnerable",
    "section of this advisory",
)


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())


def normalize_for_match(value: str) -> str:
    return normalize_text(value).casefold()


def validate_product_name(product_name: str) -> str:
    cleaned = normalize_text(product_name)
    if not cleaned:
        raise ValueError("Enter a product name.")
    if len(cleaned) < 2:
        raise ValueError("Product name must contain at least 2 characters.")
    if len(cleaned) > 120:
        raise ValueError("Product name must be 120 characters or fewer.")
    if not PRODUCT_PATTERN.fullmatch(cleaned):
        raise ValueError(
            "Use letters, numbers, spaces, and common product punctuation only."
        )
    return cleaned


def flatten_json_values(value: Any) -> list[str]:
    flattened: list[str] = []

    def visit(node: Any) -> None:
        if node is None:
            return
        if isinstance(node, str):
            text = normalize_text(node)
            if text:
                flattened.append(text)
            return
        if isinstance(node, (int, float, bool)):
            flattened.append(str(node))
            return
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        if isinstance(node, dict):
            for key, item in node.items():
                visit(key)
                visit(item)
            return
        logger.warning("Unsupported JSON value in affected_products: %r", type(node))

    visit(value)
    return flattened


def parse_affected_products(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            logger.warning("Could not parse affected_products JSON string")
            return [normalize_text(value)] if normalize_text(value) else []
        return flatten_json_values(parsed)
    return flatten_json_values(value)


def display_affected_products(value: Any) -> list[str]:
    products: list[str] = []
    seen: set[str] = set()
    for product in parse_affected_products(value):
        normalized = normalize_for_match(product)
        if not normalized or normalized in seen:
            continue
        if not is_likely_product_name(product):
            continue
        products.append(product)
        seen.add(normalized)
    return products


def display_fixed_releases(value: Any) -> list[str]:
    releases: list[str] = []
    seen: set[str] = set()
    for release in parse_affected_products(value):
        normalized = normalize_for_match(release)
        if not normalized or normalized in seen:
            continue
        releases.append(release)
        seen.add(normalized)
    return releases


def advisory_fixed_releases(row: dict[str, Any]) -> list[str]:
    for key in ("fixed_releases", "fixed_release", "fixed_software", "fixed_versions"):
        releases = display_fixed_releases(row.get(key))
        if releases:
            return releases
    return []


def is_likely_product_name(value: str) -> bool:
    text = normalize_text(value)
    if not text:
        return False
    lowered = text.casefold()
    if len(text) > 100:
        return False
    return not any(phrase in lowered for phrase in PRODUCT_EXCLUSION_PHRASES)


def products_matching_advisory(
    monitored_products: list[str],
    affected_products: list[str],
) -> list[str]:
    affected_blob = " | ".join(affected_products).casefold()
    matches = []
    for product in monitored_products:
        normalized_product = normalize_for_match(product)
        if normalized_product and normalized_product in affected_blob:
            matches.append(product)
    return matches


def advisory_fingerprint(row: dict[str, Any]) -> str:
    payload = {
        "id": row.get("id"),
        "name": row.get("name"),
        "summary": row.get("summary"),
        "cve_id": row.get("cve_id"),
        "cvss_score": row.get("cvss_score"),
        "severity": row.get("severity"),
        "workarounds": row.get("workarounds"),
        "affected_products": row.get("affected_products"),
        "fixed_releases": row.get("fixed_releases"),
        "updated_at": row.get("updated_at"),
        "last_updated": row.get("last_updated"),
    }
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def advisory_key(row: dict[str, Any]) -> str:
    source = str(row.get("_source_table", "")).strip()
    row_id = row.get("id")
    if row_id is not None:
        return f"{source}:{row_id}" if source else str(row_id)
    return advisory_fingerprint(row)


def advisory_last_updated(row: dict[str, Any]) -> str:
    for key in ("last_updated", "updated_at", "created_at"):
        value = row.get(key)
        if value:
            return str(value)
    return "Unknown"


def safe_advisory_text(row: dict[str, Any], key: str, fallback: str = "Not provided") -> str:
    value = row.get(key)
    if value is None:
        return fallback
    text = normalize_text(str(value))
    return text if text else fallback


def format_timestamp(value: datetime | None = None) -> str:
    current = value or datetime.now()
    return current.strftime("%Y-%m-%d %H:%M:%S")


def send_windows_notification(title: str, message: str) -> None:
    if sys.platform != "win32":
        logger.debug("Windows notification skipped on non-Windows platform")
        return
    try:
        from winotify import Notification

        toast = Notification(
            app_id="Cisco Security Advisory Monitor",
            title=title,
            msg=message,
            duration="short",
        )
        toast.show()
    except Exception as exc:
        logger.error("Windows notification failed: %s", exc)
