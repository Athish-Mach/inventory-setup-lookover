"""Continuously scrape the first four Cisco advisories into Supabase."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urldefrag, urlparse

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
SCRAPE_TIMEOUT_SECONDS = 8 * 60
SCRAPE_INTERVAL_SECONDS = 3600
SECTION_HEADINGS = {"summary", "workarounds", "affected products", "fixed software"}
VERSION_PATTERN = re.compile(
    r"(?<![\w.-])\d+(?:\.\d+){1,4}(?:\([\d.A-Za-z]+\))?"
    r"(?:[A-Za-z][A-Za-z0-9]*)?"
    r"(?:[-._][A-Za-z0-9][A-Za-z0-9._-]*)?(?![\w.-])"
)
FIXED_COLUMN_PATTERN = re.compile(
    r"(?:first )?fixed (?:(?:software|firmware) )?(?:release|version)s?",
    re.IGNORECASE,
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
    source_url: str | None = None

    def as_json(self) -> dict[str, str | list[str] | None]:
        """Serialize the fields stored in the advisory snapshot."""
        return {
            "name": self.name,
            "summary": self.summary,
            "workarounds": self.workarounds,
            "affected_products": self.affected_products,
            "fixed_software": self.fixed_software,
            "fixed_releases": self.fixed_releases,
            "source_url": self.source_url,
        }


class SupabaseAdvisoryStore:
    """Replace the advisory table with the latest Cisco listing snapshot."""

    def __init__(self, client: Client) -> None:
        self.client = client

    @classmethod
    def from_environment(cls) -> "SupabaseAdvisoryStore":
        """Create a store from the project's Supabase environment variables."""
        load_dotenv()
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")
        if not url or not key:
            raise RuntimeError(
                "Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env"
            )
        if os.getenv("SUPABASE_TABLE", "cisco_security_advisories") != "cisco_security_advisories":
            raise SupabaseSetupError("The dashboard requires the cisco_security_advisories table.")
        return cls(create_resilient_client(url, key))

    def rpc(self, name: str, params: dict[str, Any]) -> Any:
        try:
            return self.client.rpc(name, params).execute().data
        except APIError as error:
            if error.code in {"PGRST202", "PGRST205"}:
                raise SupabaseSetupError(
                    "Apply supabase_schema.sql to the configured Supabase project."
                ) from error
            raise

    def publish(self, run_id: int, advisories: list[Advisory]) -> int:
        """Commit the snapshot and the successful run status together."""
        return self.rpc(
            "publish_advisory_snapshot",
            {"p_run_id": run_id, "p_items": [advisory.as_json() for advisory in advisories]},
        )


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


def extract_fixed_releases(fixed_nodes: Iterable[Tag]) -> list[str]:
    """Read version identifiers only from columns explicitly labeled as fixes."""
    releases: list[str] = []
    for node in fixed_nodes:
        tables = [node] if node.name == "table" else node.find_all("table")
        for table in tables:
            fixed_columns: list[int] = []
            for row in table.find_all("tr"):
                cells = [
                    clean_text(cell.get_text(" ", strip=True))
                    for cell in row.find_all(["th", "td"], recursive=False)
                ]
                labeled_columns = [
                    index for index, cell in enumerate(cells)
                    if FIXED_COLUMN_PATTERN.fullmatch(cell)
                ]
                if labeled_columns:
                    fixed_columns = labeled_columns
                    continue
                for index in fixed_columns:
                    if index < len(cells) and VERSION_PATTERN.match(cells[index]):
                        releases.extend(VERSION_PATTERN.findall(cells[index]))
    return list(dict.fromkeys(releases))


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
                if response is not None and response.status >= 400:
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
                """() => new Set([...document.querySelectorAll('a[href]')]
                    .filter(link => link instanceof HTMLAnchorElement &&
                        link.protocol === 'https:' &&
                        (link.hostname === 'cisco.com' || link.hostname.endsWith('.cisco.com')) &&
                        link.pathname.includes('/security/center/') &&
                        !link.pathname.includes('publicationListing') &&
                        (link.pathname.includes('content/') || /advisory/i.test(link.pathname)))
                    .map(link => link.href.split('#')[0])).size >= 4""",
                timeout=NAVIGATION_TIMEOUT_MS,
            )
            hrefs = await page.locator("a[href]").evaluate_all(
                """links => [
                    ...links.filter(link => link.closest('#advisory-tab')),
                    ...links,
                ].filter(link => link instanceof HTMLAnchorElement).map(link => link.href)"""
            )
            unique = list(dict.fromkeys(
                urldefrag(href).url for href in hrefs if self._is_advisory_url(href)
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
            name_tag = soup.select_one("h1.headline") or soup.find("h1")
            name = clean_text(name_tag.get_text(" ", strip=True)) if name_tag else ""
            summary = extract_section(soup, "Summary")
            if (
                not name or name.casefold() == "cisco security advisory"
                or not summary or not self._is_advisory_url(page.url)
            ):
                raise RuntimeError(f"Cisco advisory was incomplete or redirected: {url}")
            fixed_nodes = section_nodes(soup, "Fixed Software")
            return Advisory(
                name=name,
                summary=summary,
                workarounds=extract_section(soup, "Workarounds"),
                affected_products=extract_products(soup),
                fixed_software=text_from_nodes(fixed_nodes),
                fixed_releases=extract_fixed_releases(fixed_nodes),
                source_url=url,
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
            timeout=120,
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


async def run_scrape_job(
    source: str,
    store: SupabaseAdvisoryStore | None = None,
    run_id: int | None = None,
) -> int:
    """Claim a run before opening Chromium and publish only complete snapshots."""
    store = store or SupabaseAdvisoryStore.from_environment()
    claimed_id = store.rpc("claim_scraper_run", {"p_source": source, "p_run_id": run_id})
    if claimed_id is None:
        if source == "manual":
            raise RuntimeError("The scraper is busy or the requested run is no longer queued.")
        logging.info("Scheduled scrape is paused, already active, or not due.")
        return 0

    try:
        async with async_playwright() as playwright:
            browser = await launch_browser(playwright)
            try:
                context = await browser.new_context(user_agent=USER_AGENT)
                try:
                    advisories = await asyncio.wait_for(
                        scrape_once(CiscoAdvisoryScraper(context)),
                        timeout=SCRAPE_TIMEOUT_SECONDS,
                    )
                finally:
                    await context.close()
            finally:
                await browser.close()
        count = store.publish(claimed_id, advisories)
    except Exception:
        try:
            store.client.table("scraper_runs").update(
                {
                    "status": "failed",
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                    "message": "Scrape failed. Review the worker log for details.",
                }
            ).eq("id", claimed_id).eq("status", "running").execute()
        except Exception:
            logging.exception("Could not record failure for scraper run %s", claimed_id)
        raise

    logging.info("Scraper run %s published %s advisories", claimed_id, count)
    return count


async def run() -> None:
    """Check the saved schedule repeatedly for standalone installations."""
    store = SupabaseAdvisoryStore.from_environment()
    while True:
        try:
            await run_scrape_job("scheduled", store)
        except SupabaseSetupError:
            raise
        except Exception:
            logging.exception("Snapshot failed; the next cycle will retry")
        logging.info("Checking the scrape schedule again in %s seconds", SCRAPE_INTERVAL_SECONDS)
        await asyncio.sleep(SCRAPE_INTERVAL_SECONDS)


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
    if args.run_id is not None and not args.once:
        parser.error("--run-id requires --once")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if args.once:
        asyncio.run(run_scrape_job("manual", run_id=args.run_id))
    elif args.if_due:
        asyncio.run(run_scrape_job("scheduled"))
    else:
        asyncio.run(run())
