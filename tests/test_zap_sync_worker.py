import unittest
from unittest.mock import patch

from scanner import zap_sync_worker as worker


class ZapSyncWorkerTests(unittest.TestCase):
    def test_sync_imports_existing_alerts(self):
        endpoint = "http://127.0.0.1:8090"
        alerts = [{"name": "Mock alert", "risk": "Medium"}]

        with (
            patch.object(worker, "load_endpoint", return_value=endpoint),
            patch.object(worker, "ensure_zap_running") as startup_mock,
            patch.object(
                worker,
                "fetch_alerts",
                return_value={"count": 1, "alerts": alerts},
            ) as fetch_mock,
            patch.object(
                worker, "import_zap_alerts_to_drafts", return_value=1
            ) as import_mock,
        ):
            result = worker.sync_once()

        self.assertEqual(
            result, {"status": "ok", "fetched": 1, "created": 1}
        )
        startup_mock.assert_called_once_with(endpoint)
        fetch_mock.assert_called_once_with(endpoint=endpoint, limit=100)
        import_mock.assert_called_once_with(alerts)

    def test_unavailable_zap_returns_safe_status(self):
        endpoint = "http://127.0.0.1:8090"

        with (
            patch.object(worker, "load_endpoint", return_value=endpoint),
            patch.object(worker, "ensure_zap_running"),
            patch.object(
                worker,
                "fetch_alerts",
                side_effect=worker.ZapProxyError("unavailable"),
            ) as fetch_mock,
            patch.object(worker, "import_zap_alerts_to_drafts") as import_mock,
        ):
            result = worker.sync_once()

        self.assertEqual(
            result, {"status": "unavailable", "fetched": 0, "created": 0}
        )
        fetch_mock.assert_called_once_with(endpoint=endpoint, limit=100)
        import_mock.assert_not_called()

    def test_startup_failure_returns_safe_status(self):
        with (
            patch.object(
                worker, "load_endpoint",
                return_value="http://127.0.0.1:8090"
            ),
            patch.object(
                worker,
                "ensure_zap_running",
                side_effect=worker.ZapProxyError("startup failed"),
            ) as startup_mock,
            patch.object(worker, "fetch_alerts") as fetch_mock,
        ):
            result = worker.sync_once()

        self.assertEqual(
            result, {"status": "unavailable", "fetched": 0, "created": 0}
        )
        startup_mock.assert_called_once()
        fetch_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
