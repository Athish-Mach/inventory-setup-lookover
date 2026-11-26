import os
import unittest
from unittest.mock import Mock, patch

import httpx
from fastapi.testclient import TestClient

with patch("dotenv.load_dotenv"):
    import app


class AdvisoryApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app.app)
        self.addCleanup(self.client.close)
        self.addCleanup(app.app.dependency_overrides.clear)

    def test_routes_require_authentication(self):
        for path in ("/api/advisories", "/api/admin/products", "/api/admin/scraper/settings"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.headers["cache-control"], "no-store")

    def test_analyst_reads_feed_but_cannot_queue_a_scrape(self):
        app.app.dependency_overrides[app.current_user] = lambda: {"role": "analyst"}
        feed = {
            "items": [{"affected_products": ["Cisco example"], "fixed_releases": ["12.3.4"]}],
            "total": 1,
            "fetched_at": "2026-01-01T12:00:00Z",
            "stale": False,
        }
        with patch.object(app, "read_advisory_feed", return_value=feed):
            response = self.client.get("/api/advisories")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {**feed, "products": 1, "fixed_releases": 1})
        self.assertEqual(self.client.post("/api/admin/scraper/run").status_code, 403)

    def test_admin_queues_local_worker_once(self):
        app.app.dependency_overrides[app.current_user] = lambda: {"role": "admin", "username": "test-admin"}
        database = Mock()
        database.rpc.return_value.execute.return_value.data = 7
        with (
            patch.object(app, "database", return_value=database),
            patch.object(app, "github_scraper_config", return_value=None),
            patch.object(app, "local_scraper_allowed", return_value=True),
            patch.object(app, "run_local_scraper") as worker,
        ):
            response = self.client.post("/api/admin/scraper/run")
            self.assertEqual(response.status_code, 202)
            self.assertEqual(response.json()["run_id"], 7)
            worker.assert_called_once_with(7)
            database.rpc.assert_called_once_with(
                "claim_scraper_run", {"p_source": "manual", "p_requested_by": "test-admin"}
            )
            database.rpc.return_value.execute.return_value.data = None
            self.assertEqual(self.client.post("/api/admin/scraper/run").status_code, 409)
            worker.assert_called_once_with(7)

    def test_readiness_tracks_database_availability(self):
        with (
            patch.dict(os.environ, {"JWT_SECRET": "s" * 32}),
            patch.object(app, "read_advisory_feed", side_effect=[{}, httpx.ConnectError("offline")]),
        ):
            self.assertEqual(self.client.get("/api/ready").status_code, 200)
            self.assertEqual(self.client.get("/api/ready").status_code, 503)
        self.assertEqual(self.client.get("/api/health").status_code, 200)
