import csv
import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import app as app_module



class UnifiedWebSecurityZapRouteTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def test_zap_proxy_page_renders_managed_interface_without_manual_settings(self):
        with patch("app.ensure_zap_running") as startup_mock:
            response = self.client.get("/zap-proxy")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ZAP Proxy", response.data)
        self.assertIn(b"Automatic Alert Synchronization", response.data)
        self.assertIn(b"OWASP ZAP Installation", response.data)
        self.assertIn(b"Start / Check ZAP", response.data)
        self.assertNotIn(b"ZAP API Settings", response.data)
        self.assertNotIn(b'name="api_key"', response.data)
        self.assertNotIn(b'name="endpoint"', response.data)
        self.assertNotIn(b"Save Settings", response.data)
        startup_mock.assert_not_called()

    def test_web_security_page_contains_native_assessment_information(self):
        response = self.client.get("/web-security")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Web Application Security Assessment", response.data)
        self.assertIn(b"Open Unified Scan", response.data)
        self.assertIn(b"Security headers", response.data)
        self.assertNotIn(b"OWASP ZAP Integration", response.data)
        self.assertNotIn(b"Fetch Existing Alerts", response.data)
        self.assertNotIn(b"Import Alerts to Draft Findings", response.data)

    def test_web_security_get_does_not_call_zap_management(self):
        with patch("app.fetch_alerts") as fetch_mock, \
             patch("app.ensure_zap_running") as startup_mock:
            response = self.client.get("/web-security")

        self.assertEqual(response.status_code, 200)
        fetch_mock.assert_not_called()
        startup_mock.assert_not_called()

    def test_web_security_post_redirects_to_unified_scan(self):
        with patch("app.fetch_alerts") as fetch_mock, \
             patch("app.ensure_zap_running") as startup_mock:
            response = self.client.post(
                "/web-security",
                data={
                    "action": "fetch_alerts",
                    "endpoint": "http://127.0.0.1:8090",
                    "api_key": "test-only-key",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response.headers["Location"].endswith("/unified-scan"),
            response.headers["Location"],
        )
        fetch_mock.assert_not_called()
        startup_mock.assert_not_called()

    def test_standalone_web_security_batch_redirects_to_unified_scan(self):
        response = self.client.post(
            "/web-security/batch",
            data={"targets": "http://127.0.0.1"},
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response.headers["Location"].endswith("/unified-scan"),
            response.headers["Location"],
        )

    def test_unified_scan_page_renders_zap_module_without_api_settings(self):
        response = self.client.get("/unified-scan")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'name="modules" value="zap"', response.data)
        self.assertIn(b"OWASP ZAP", response.data)
        self.assertNotIn(b"ZAP API Settings", response.data)
        self.assertNotIn(b'name="api_key"', response.data)

    def test_start_action_uses_managed_zap_startup(self):
        with patch(
            "app.ensure_zap_running",
            return_value={"connected": True, "version": "2.17.0"},
        ) as startup_mock:
            response = self.client.post(
                "/zap-proxy",
                data={"action": "start"},
            )

        self.assertEqual(response.status_code, 200)
        startup_mock.assert_called_once_with("http://127.0.0.1:8090")
        self.assertIn(b"OWASP ZAP is ready", response.data)

    def test_manual_save_action_is_not_supported(self):
        with patch("app.ensure_zap_running") as startup_mock:
            response = self.client.post(
                "/zap-proxy",
                data={
                    "action": "save",
                    "endpoint": "http://127.0.0.1:8090",
                    "api_key": "synthetic-manual-key",
                },
            )

        self.assertEqual(response.status_code, 200)
        startup_mock.assert_not_called()
        self.assertNotIn(b"synthetic-manual-key", response.data)


class ZapExportRouteTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    @contextmanager
    def temporary_zap_scan(self, result):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test-zap.sqlite3"

            with sqlite3.connect(database_path) as db:
                db.execute("""
                    CREATE TABLE zap_scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target TEXT NOT NULL,
                        status TEXT NOT NULL,
                        started_at TEXT NOT NULL,
                        finished_at TEXT,
                        duration_seconds REAL,
                        result_json TEXT,
                        error TEXT
                    )
                """)
                db.execute("""
                    INSERT INTO zap_scans (
                        target, status, started_at, finished_at,
                        duration_seconds, result_json, error
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    "http://127.0.0.1:5000",
                    "completed",
                    "2026-11-17T10:00:00",
                    "2026-11-17T10:00:10",
                    10.0,
                    json.dumps(result),
                    None,
                ))

            with patch.object(
                app_module, "DATABASE_PATH", str(database_path)
            ):
                yield

    def test_zap_pdf_export_returns_pdf_attachment(self):
        result = {
            "alerts": [{
                "name": "Synthetic XSS Alert",
                "risk": "High",
                "confidence": "Medium",
                "url": "http://127.0.0.1:5000/test",
                "method": "GET",
                "param": "q",
                "attack": "synthetic-test",
                "evidence": "synthetic evidence",
                "description": "Synthetic test description",
                "solution": "Synthetic test remediation",
                "reference": "https://example.com",
                "pluginId": "12345",
                "cweid": "79",
                "wascid": "8",
            }],
            "spider_scan_id": "1",
            "active_scan_id": "2",
        }

        with self.temporary_zap_scan(result):
            response = self.client.get("/zap/results/1/export.pdf")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.content_type.startswith("application/pdf"))
        self.assertTrue(response.data.startswith(b"%PDF"))
        self.assertIn("attachment;", response.headers.get("Content-Disposition", ""))
        self.assertEqual(
            response.headers.get("X-Content-Type-Options"), "nosniff"
        )

    def test_zap_csv_export_includes_alert_details(self):
        result = {
            "alerts": [{
                "name": "Synthetic XSS Alert",
                "risk": "High",
                "confidence": "Medium",
                "url": "http://127.0.0.1:5000/test",
                "method": "GET",
                "param": "q",
                "attack": "synthetic-test",
                "evidence": "synthetic evidence",
                "description": "Synthetic test description",
                "solution": "Synthetic test remediation",
                "reference": "https://example.com",
                "pluginId": "12345",
                "cweid": "79",
                "wascid": "8",
            }]
        }

        with self.temporary_zap_scan(result):
            response = self.client.get("/zap/results/1/export.csv")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.content_type.startswith("text/csv"))
        self.assertIn("attachment;", response.headers.get("Content-Disposition", ""))
        self.assertEqual(
            response.headers.get("X-Content-Type-Options"), "nosniff"
        )

        rows = list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["alert_name"], "Synthetic XSS Alert")
        self.assertEqual(rows[0]["risk"], "High")
        self.assertEqual(rows[0]["parameter"], "q")
        self.assertEqual(rows[0]["plugin_id"], "12345")
        self.assertEqual(rows[0]["cwe_id"], "79")

    def test_zap_csv_export_handles_scan_without_alerts(self):
        with self.temporary_zap_scan({"alerts": []}):
            response = self.client.get("/zap/results/1/export.csv")

        self.assertEqual(response.status_code, 200)
        rows = list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scan_id"], "1")
        self.assertEqual(rows[0]["target"], "http://127.0.0.1:5000")
        self.assertEqual(rows[0]["alert_name"], "")

    def test_zap_exports_return_404_for_missing_scan(self):
        with self.temporary_zap_scan({"alerts": []}):
            pdf_response = self.client.get("/zap/results/999/export.pdf")
            csv_response = self.client.get("/zap/results/999/export.csv")

        self.assertEqual(pdf_response.status_code, 404)
        self.assertEqual(csv_response.status_code, 404)

if __name__ == "__main__":
    unittest.main()
