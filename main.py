"""Continuously scrape the first four Cisco advisories into Supabase."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, NavigableString, Tag
from dotenv import load_dotenv
from playwright.async_api import BrowserContext, Error as PlaywrightError
from playwright.async_api import Page, TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright
from postgrest.exceptions import APIError
from supabase import Client
from supabase_client import create_resilient_client

LISTING_URL = (
    "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"
)
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
MAX_RETRIES = 3
NAVIGATION_TIMEOUT_MS = 45_000
SCRAPE_INTERVAL_SECONDS = 3600
SECTION_HEADINGS = {"summary", "workarounds", "affected products", "fixed software"}
VERSION_PATTERN = re.compile(
    r"(?<![\w.-])\d+(?:\.\d+){1,4}(?:[A-Za-z]+)?"
    r"(?:[-._][A-Za-z0-9][A-Za-z0-9._-]*)?(?![\w.-])"
)


class SupabaseSetupError(RuntimeError):
    """A persistent Supabase configuration problem that needs user action."""


@dataclass(frozen=True)
class Advisory:
    """The deliberately small, required representation of an advisory."""

    name: str
    summary: str
    workarounds: str
    affected_products: list[str]
    fixed_software: str
    fixed_releases: list[str]

    def as_json(self) -> dict[str, str | list[str]]:
        """Return precisely the output contract expected by downstream users."""
        return {
            "name": self.name,
            "summary": self.summary,
            "workarounds": self.workarounds,
            "affected_products": self.affected_products,
            "fixed_software": self.fixed_software,
            "fixed_releases": self.fixed_releases,
        }


class SupabaseAdvisoryStore:
    """Replace the advisory table with the latest Cisco listing snapshot."""

    def __init__(self, client: Client, table_name: str) -> None:
        self.client = client
        self.table_name = table_name

    @classmethod
    def from_environment(cls) -> "SupabaseAdvisoryStore":
        """Create a store from the project's Supabase environment variables."""
        load_dotenv()
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")
        table_name = os.getenv("SUPABASE_TABLE", "cisco_security_advisories")
        if not url or not key:
            raise RuntimeError(
                "Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env"
            )
        return cls(create_resilient_client(url, key), table_name)

    def replace_all(self, advisories: list[Advisory]) -> None:
        """Delete stale rows and insert only the newly scraped advisory data."""
        if not advisories:
            raise ValueError("Refusing to replace the advisory snapshot with no rows")
        table = self.client.table(self.table_name)
        try:
            table.delete().gte("id", 0).execute()
            table.insert([advisory.as_json() for advisory in advisories]).execute()
        except APIError as error:
            if error.code == "PGRST205":
                raise SupabaseSetupError(
                    f"Supabase table public.{self.table_name} was not found. "
                    "Run the SQL in supabase_schema.sql in the Supabase SQL "
                    "Editor, then confirm SUPABASE_URL points to that project "
                    "and SUPABASE_TABLE matches the table name."
                ) from error
            raise


def clean_text(value: str) -> str:
    """Collapse browser whitespace while retaining all textual content."""
    return " ".join(value.split())


def is_heading(tag: Tag) -> bool:
    """Identify semantic headings and Cisco's occasional heading-like elements."""
    if tag.name in {"h1", "h2", "h3", "h4", "h5", "h6"}:
        return True
    return clean_text(tag.get_text(" ", strip=True)).casefold() in SECTION_HEADINGS


def heading_level(tag: Tag) -> int | None:
    """Return a semantic heading's numeric level, when it has one."""
    if tag.name and re.fullmatch(r"h[1-6]", tag.name):
        return int(tag.name[1])
    return None


def find_heading(soup: BeautifulSoup, heading: str) -> Tag | None:
    """Find a section heading despite harmless punctuation or whitespace changes."""
    target = heading.casefold()
    tags = ["h1", "h2", "h3", "h4", "h5", "h6", "div", "p", "strong"]
    for tag in soup.find_all(tags):
        text = clean_text(tag.get_text(" ", strip=True)).rstrip(":").casefold()
        if text == target:
            return tag
    return None


def section_nodes(soup: BeautifulSoup, heading: str) -> list[Tag]:
    """Return sibling nodes belonging to a named section, excluding the next one."""
    start = find_heading(soup, heading)
    if start is None:
        return []

    nodes: list[Tag] = []
    start_level = heading_level(start)
    for sibling in start.next_siblings:
        if isinstance(sibling, NavigableString):
            continue
        if not isinstance(sibling, Tag):
            continue
        sibling_level = heading_level(sibling)
        if sibling_level is not None and (
            start_level is None or sibling_level <= start_level
        ):
            break
        if sibling_level is None and is_heading(sibling):
            break
        nodes.append(sibling)
    return nodes


def text_from_nodes(nodes: Iterable[Tag]) -> str:
    """Convert section markup to clean text without emitting HTML."""
    return clean_text(" ".join(node.get_text(" ", strip=True) for node in nodes))


def extract_section(soup: BeautifulSoup, heading: str) -> str:
    """Extract plain text from one named advisory section."""
    return text_from_nodes(section_nodes(soup, heading))


def products_from_text(text: str) -> list[str]:
    """Extract Cisco product names from Cisco's vulnerable-product prose."""
    products: list[str] = []
    product_pattern = re.compile(
        r"Cisco\s+.+?(?=,\s*(?:and\s+)?Cisco\b|\s+and\s+Cisco\b|"
        r",?\s+(?:regardless|when|where|with|that|which|running|using|if|as)\b|[.;]|$)",
        re.IGNORECASE,
    )
    for sentence in re.split(r"(?<=[.])\s+", clean_text(text)):
        if "affect" in sentence.casefold():
            products.extend(
                clean_text(match.group())
                for match in product_pattern.finditer(sentence)
            )
    return products


def extract_products(soup: BeautifulSoup) -> list[str]:
    """Extract products from Cisco's vulnerable-product container only."""
    vulnerable_section = soup.select_one("#vulnerableproducts")
    nodes = [vulnerable_section] if vulnerable_section else section_nodes(
        soup,
        "Affected Products",
    )
    products: list[str] = []
    for node in nodes:
        if node is None:
            continue
        for item in node.find_all("li"):
            candidate = clean_text(item.get_text(" ", strip=True))
            if candidate.startswith("Cisco ") and len(candidate) <= 160:
                products.append(candidate)
        for row in node.find_all("tr"):
            cells = row.find_all(["td", "th"])
            if cells:
                candidate = clean_text(cells[0].get_text(" ", strip=True))
                if candidate.startswith("Cisco "):
                    products.append(candidate)
        products.extend(products_from_text(node.get_text(" ", strip=True)))

    return list(dict.fromkeys(product for product in products if product))


def extract_fixed_releases(fixed_software: str) -> list[str]:
    """Extract distinct release/version strings in their published order."""
    releases = (
        match.rstrip(".,;:") for match in VERSION_PATTERN.findall(fixed_software)
    )
    return list(dict.fromkeys(release for release in releases if release))


class CiscoAdvisoryScraper:
    """Browser-backed scraper for Cisco's dynamically rendered advisory pages."""

    def __init__(self, context: BrowserContext) -> None:
        self.context = context

    async def _new_page(self) -> Page:
        page = await self.context.new_page()
        page.set_default_navigation_timeout(NAVIGATION_TIMEOUT_MS)
        return page

    async def _goto_with_retries(self, page: Page, url: str) -> None:
        """Navigate with exponential backoff for transient Cisco/network failures."""
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response = await page.goto(url, wait_until="domcontentloaded")
                if response is not None and response.status >= 500:
                    raise RuntimeError(f"Cisco returned HTTP {response.status}")
                return
            except (PlaywrightTimeoutError, RuntimeError) as error:
                if attempt == MAX_RETRIES:
                    raise RuntimeError(f"Could not load {url}") from error
                delay = 2 ** attempt
                logging.warning(
                    "Attempt %s failed for %s; retrying in %ss",
                    attempt,
                    url,
                    delay,
                )
                await asyncio.sleep(delay)

    @staticmethod
    def _is_advisory_url(url: str) -> bool:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").casefold()
        return (
            parsed.scheme == "https"
            and (hostname == "cisco.com" or hostname.endswith(".cisco.com"))
            and "/security/center/" in parsed.path
            and "publicationListing" not in parsed.path
            and ("content/" in parsed.path or "advisory" in parsed.path.casefold())
        )

    async def get_advisory_links(self) -> list[str]:
        """Return the first four advisory URLs shown in Cisco's listing order."""
        page = await self._new_page()
        try:
            await self._goto_with_retries(page, LISTING_URL)
            await page.wait_for_function(
                """() => [...document.querySelectorAll(
                    '#advisory-tab a[href], a[href]')]
                    .some(link => link.href.includes('/security/center/content/'))""",
                timeout=NAVIGATION_TIMEOUT_MS,
            )
            hrefs = await page.locator("#advisory-tab a[href], a[href]").evaluate_all(
                "links => links.map(link => link.href)"
            )
            unique = list(dict.fromkeys(
                urljoin(LISTING_URL, href)
                for href in hrefs
                if self._is_advisory_url(href)
            ))
            if len(unique) < 4:
                raise RuntimeError(f"Cisco displayed only {len(unique)} advisory links")
            return unique[:4]
        finally:
            await page.close()

    async def scrape_advisory(self, url: str) -> Advisory:
        """Visit one advisory and return only the requested fields."""
        page = await self._new_page()
        try:
            await self._goto_with_retries(page, url)
            await page.wait_for_selector("h1", timeout=NAVIGATION_TIMEOUT_MS)
            soup = BeautifulSoup(await page.content(), "html.parser")
            name_tag = soup.find("h1")
            fixed_software = extract_section(soup, "Fixed Software")
            return Advisory(
                name=clean_text(name_tag.get_text(" ", strip=True)) if name_tag else "",
                summary=extract_section(soup, "Summary"),
                workarounds=extract_section(soup, "Workarounds"),
                affected_products=extract_products(soup),
                fixed_software=fixed_software,
                fixed_releases=extract_fixed_releases(fixed_software),
            )
        finally:
            await page.close()


def prepare_playwright_environment() -> None:
    """Avoid Cursor sandbox browser paths that leave Chromium incomplete."""
    sandbox_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "")
    if "cursor-sandbox-cache" in sandbox_path:
        os.environ.pop("PLAYWRIGHT_BROWSERS_PATH", None)


async def launch_browser(playwright: Any):
    """Launch Chromium, downloading it once when Playwright has none locally."""
    prepare_playwright_environment()
    try:
        return await playwright.chromium.launch(  # type: ignore[attr-defined]
            headless=True
        )
    except PlaywrightError as error:
        if "Executable doesn't exist" not in str(error):
            raise
        logging.info("Installing the Playwright Chromium browser")
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            check=True,
            env={
                key: value
                for key, value in os.environ.items()
                if key != "PLAYWRIGHT_BROWSERS_PATH"
                or "cursor-sandbox-cache" not in value
            },
        )
        return await playwright.chromium.launch(  # type: ignore[attr-defined]
            headless=True
        )


async def scrape_once(scraper: CiscoAdvisoryScraper) -> list[Advisory]:
    """Scrape the current set of four listed advisories."""
    advisories: list[Advisory] = []
    for url in await scraper.get_advisory_links():
        advisory = await scraper.scrape_advisory(url)
        advisories.append(advisory)
    return advisories


def scheduled_run_is_due(store: SupabaseAdvisoryStore) -> bool:
    """Check the dashboard's enabled cadence against the last worker start."""
    active_result = (
        store.client.table("scraper_runs")
        .select("id,status,created_at")
        .in_("status", ["queued", "running"])
        .limit(20)
        .execute()
    )
    now = datetime.now(timezone.utc)
    active_rows = getattr(active_result, "data", None) or []
    for run in active_rows:
        created_at = run.get("created_at")
        if not created_at:
            logging.info("An existing scraper run is active; skipping this check")
            return False
        started = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        if now - started > timedelta(minutes=45):
            store.client.table("scraper_runs").update(
                {
                    "status": "failed",
                    "finished_at": now.isoformat(),
                    "message": "The worker did not finish within the expected time.",
                }
            ).eq("id", run["id"]).in_("status", ["queued", "running"]).execute()
        else:
            logging.info("An existing scraper run is active; skipping this check")
            return False

    result = (
        store.client.table("scraper_settings")
        .select("enabled,interval_minutes,last_run_at")
        .eq("id", 1)
        .limit(1)
        .execute()
    )
    rows = getattr(result, "data", None) or []
    if not rows:
        raise RuntimeError("Missing scraper_settings row; run supabase_schema.sql")
    settings = rows[0]
    if not settings["enabled"]:
        logging.info("Scheduled scraping is disabled in the dashboard")
        return False
    last_run_at = settings.get("last_run_at")
    if not last_run_at:
        return True
    last_run = datetime.fromisoformat(last_run_at.replace("Z", "+00:00"))
    interval_seconds = int(settings["interval_minutes"]) * 60
    due = (now - last_run).total_seconds() >= interval_seconds
    if not due:
        logging.info("Scraper cadence has not elapsed; skipping this hourly check")
    return due


async def run_scrape_job(
    source: str,
    store: SupabaseAdvisoryStore | None = None,
    run_id: int | None = None,
) -> int:
    """Run one scrape, replacing the snapshot and writing an operations record."""
    if source not in {"manual", "scheduled"}:
        raise ValueError("Unsupported scraper run source")
    store = store or SupabaseAdvisoryStore.from_environment()
    started_at = datetime.now(timezone.utc)
    if run_id is None:
        start_result = (
            store.client.table("scraper_runs")
            .insert(
                {
                    "run_source": source,
                    "status": "running",
                    "started_at": started_at.isoformat(),
                    "message": "Scrape is in progress.",
                }
            )
            .select("id")
            .execute()
        )
        start_rows = getattr(start_result, "data", None) or []
        if not start_rows:
            raise RuntimeError("Could not create a scraper run record")
        run_id = start_rows[0]["id"]
    else:
        queued_update = (
            store.client.table("scraper_runs")
            .update(
                {
                    "status": "running",
                    "started_at": started_at.isoformat(),
                    "message": "Scrape is in progress.",
                }
            )
            .eq("id", run_id)
            .eq("status", "queued")
            .select("id")
            .execute()
        )
        if not (getattr(queued_update, "data", None) or []):
            raise RuntimeError("Could not find the queued dashboard run record")
    store.client.table("scraper_settings").update(
        {"last_run_at": started_at.isoformat()}
    ).eq("id", 1).execute()

    try:
        async with async_playwright() as playwright:
            browser = await launch_browser(playwright)
            context = None
            try:
                context = await browser.new_context(user_agent=USER_AGENT)
                scraper = CiscoAdvisoryScraper(context)
                advisories = await scrape_once(scraper)
                store.replace_all(advisories)
            finally:
                if context is not None:
                    await context.close()
                await browser.close()
        finished_at = datetime.now(timezone.utc)
        store.client.table("scraper_runs").update(
            {
                "status": "succeeded",
                "finished_at": finished_at.isoformat(),
                "advisory_count": len(advisories),
                "message": "Scrape completed successfully.",
            }
        ).eq("id", run_id).execute()
        logging.info("Stored %s advisories in Supabase", len(advisories))
        return len(advisories)
    except Exception:
        store.client.table("scraper_runs").update(
            {
                "status": "failed",
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "message": "Scrape failed. Review the worker log for details.",
            }
        ).eq("id", run_id).execute()
        raise


async def run() -> None:
    """Continuously replace Supabase rows with the latest advisory snapshot."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    store = SupabaseAdvisoryStore.from_environment()
    async with async_playwright() as playwright:
        browser = await launch_browser(playwright)
        context = await browser.new_context(user_agent=USER_AGENT)
        try:
            scraper = CiscoAdvisoryScraper(context)
            while True:
                try:
                    advisories = await scrape_once(scraper)
                    store.replace_all(advisories)
                    logging.info("Stored %s advisories in Supabase", len(advisories))
                except SupabaseSetupError:
                    logging.exception("Supabase setup must be corrected before scraping can continue")
                    raise
                except Exception:
                    logging.exception("Snapshot failed; the next cycle will retry")
                logging.info(
                    "Waiting %s seconds for the next scrape",
                    SCRAPE_INTERVAL_SECONDS,
                )
                await asyncio.sleep(SCRAPE_INTERVAL_SECONDS)
        finally:
            await context.close()
            await browser.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scrape Cisco security advisories")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Run one manual scrape")
    parser.add_argument("--run-id", type=int, help="Existing queued manual run record")
    mode.add_argument(
        "--if-due",
        action="store_true",
        help="Run one scheduled scrape only when dashboard settings are due",
    )
    args = parser.parse_args()
    if args.once:
        asyncio.run(run_scrape_job("manual", run_id=args.run_id))
    elif args.if_due:
        store = SupabaseAdvisoryStore.from_environment()
        if scheduled_run_is_due(store):
            asyncio.run(run_scrape_job("scheduled", store))
    else:
        asyncio.run(run())
