import unittest
from unittest.mock import AsyncMock, Mock

from main import CiscoAdvisoryScraper


class ScraperTests(unittest.IsolatedAsyncioTestCase):
    url = "https://www.cisco.com/security/center/content/example"

    def scraper_for(self, html, url=None):
        page = AsyncMock()
        page.url = url or self.url
        page.set_default_navigation_timeout = Mock()
        page.content.return_value = html
        page.goto.return_value = Mock(status=200)
        context = Mock(new_page=AsyncMock(return_value=page))
        return CiscoAdvisoryScraper(context), page

    async def test_advisory_preserves_source_and_patch_guidance(self):
        scraper, page = self.scraper_for("""
            <h1>Cisco Security Advisory</h1><h1 class="headline">Cisco example advisory</h1>
            <h2>Summary</h2><p>Example summary.</p>
            <h2>Affected Products</h2>
            <div id="vulnerableproducts"><ul><li>Cisco Example Product</li></ul></div>
            <h2>Workarounds</h2><p>Example workaround.</p>
            <h2>Fixed Software</h2><p>Review the notes for release 16.9.</p>
            <table>
                <tr><th>Cisco Software Release</th><th>First Fixed Release</th></tr>
                <tr><td>Earlier than 12.3</td><td>Migrate to a fixed release.</td></tr>
                <tr><td>12.3</td><td>12.3.4</td></tr>
                <tr><td>15.1</td><td>15.1(1)SY10</td></tr>
                <tr><td>6.0</td><td>6.0(2.260143) <sup>1</sup></td></tr>
            </table>
        """)
        advisory = await scraper.scrape_advisory(self.url)
        self.assertEqual(advisory.name, "Cisco example advisory")
        self.assertEqual(advisory.as_json()["source_url"], self.url)
        self.assertEqual(advisory.affected_products, ["Cisco Example Product"])
        self.assertEqual(advisory.fixed_releases, ["12.3.4", "15.1(1)SY10", "6.0(2.260143)"])
        self.assertEqual(advisory.workarounds, "Example workaround.")
        page.close.assert_awaited_once()

    async def test_redirect_or_missing_summary_rejects_the_page(self):
        for url, html in (
            (self.url, "<h1>Access denied</h1>"),
            ("https://example.test/", "<h1>Example</h1><h2>Summary</h2><p>Example.</p>"),
        ):
            with self.subTest(url=url):
                scraper, page = self.scraper_for(html, url)
                with self.assertRaisesRegex(RuntimeError, "incomplete or redirected"):
                    await scraper.scrape_advisory(self.url)
                page.close.assert_awaited_once()
