import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from grc import automatic_risks as risks


class ZapImportTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test.db")

        with sqlite3.connect(self.db_path) as db:
            db.execute("""
                CREATE TABLE draft_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    source_record_id INTEGER,
                    fingerprint TEXT NOT NULL UNIQUE,
                    target TEXT NOT NULL DEFAULT '',
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    evidence TEXT NOT NULL DEFAULT '',
                    suggested_severity TEXT NOT NULL DEFAULT 'Review',
                    confidence TEXT NOT NULL DEFAULT 'Low',
                    recommendation TEXT NOT NULL DEFAULT '',
                    iso_controls TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'Draft',
                    risk_id INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

        self.connection_patch = patch.object(
            risks, "connect_db", side_effect=self.connect_test_db
        )
        self.connection_patch.start()
        self.addCleanup(self.connection_patch.stop)
        self.addCleanup(self.temp_dir.cleanup)

    def connect_test_db(self):
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        return db

    def test_web_security_findings_link_to_each_scan(self):
        result = {
            "target": "https://example.test/",
            "status_code": 200,
            "headers": [{
                "header": "content-security-policy",
                "name": "Content-Security-Policy",
                "present": False,
                "issue": True,
            }],
            "cookies": [],
        }

        self.assertEqual(
            risks.generate_web_security_drafts(result, source_record_id=101),
            1,
        )
        self.assertEqual(
            risks.generate_web_security_drafts(result, source_record_id=101),
            0,
        )
        self.assertEqual(
            risks.generate_web_security_drafts(result, source_record_id=102),
            1,
        )

        with self.connect_test_db() as db:
            rows = db.execute(
                """
                SELECT source, source_record_id, status
                FROM draft_findings
                ORDER BY source_record_id
                """
            ).fetchall()

        self.assertEqual(len(rows), 2)
        self.assertEqual(
            [(row["source"], row["source_record_id"], row["status"])
             for row in rows],
            [
                ("web_security", 101, "Draft"),
                ("web_security", 102, "Draft"),
            ],
        )

    def test_partial_web_security_result_generates_available_header_draft(self):
        result = {
            "target": "https://example.test/",
            "status_code": 200,
            "headers": [{
                "header": "content-security-policy",
                "name": "Content-Security-Policy",
                "present": False,
                "issue": True,
            }],
            "cookies": [],
            "discovery": {
                "errors": ["Mock discovery failure"],
                "blocked_urls": [],
                "deferred_urls": ["/account"],
                "truncated": True,
            },
        }

        self.assertEqual(
            risks.generate_web_security_drafts(result, source_record_id=105),
            1,
        )

        with self.connect_test_db() as db:
            row = db.execute(
                """
                SELECT source, source_record_id, title,
                       suggested_severity, confidence, status
                FROM draft_findings
                """
            ).fetchone()

        self.assertEqual(row["source"], "web_security")
        self.assertEqual(row["source_record_id"], 105)
        self.assertIn("Content-Security-Policy", row["title"])
        self.assertEqual(row["suggested_severity"], "Review")
        self.assertEqual(row["confidence"], "Low")
        self.assertEqual(row["status"], "Draft")

    def test_web_discovery_creates_scan_linked_review_draft(self):
        result = {
            "target": "https://example.test/",
            "status_code": 200,
            "headers": [],
            "cookies": [],
            "discovery": {
                "api_endpoints": [
                    "https://example.test/api/v1/users",
                ],
                "forms": [{
                    "page": "https://example.test/login",
                    "method": "POST",
                    "action": "https://example.test/auth/login",
                    "enctype": "application/x-www-form-urlencoded",
                    "fields": [{
                        "name": "username",
                        "element": "input",
                        "type": "text",
                        "required": True,
                    }],
                }],
            },
        }

        self.assertEqual(
            risks.generate_web_security_drafts(result, source_record_id=103),
            1,
        )
        self.assertEqual(
            risks.generate_web_security_drafts(result, source_record_id=103),
            0,
        )

        with self.connect_test_db() as db:
            row = db.execute(
                """
                SELECT source, source_record_id, title, evidence,
                       suggested_severity, confidence, status
                FROM draft_findings
                """
            ).fetchone()

        self.assertEqual(row["source"], "web_security")
        self.assertEqual(row["source_record_id"], 103)
        self.assertIn("attack surface", row["title"].lower())
        self.assertIn("/api/v1/users", row["evidence"])
        self.assertIn("/auth/login", row["evidence"])
        self.assertIn("username", row["evidence"])
        self.assertEqual(row["suggested_severity"], "Review")
        self.assertEqual(row["confidence"], "Low")
        self.assertEqual(row["status"], "Draft")

    def test_web_discovery_ignores_malformed_metadata(self):
        result = {
            "target": "https://example.test/",
            "status_code": 200,
            "headers": [],
            "cookies": [],
            "discovery": {
                "api_endpoints": [None, 123, "", {"path": "/api/private"}],
                "forms": [None, "invalid", 123],
            },
        }

        self.assertEqual(
            risks.generate_web_security_drafts(result, source_record_id=104),
            0,
        )

        with self.connect_test_db() as db:
            count = db.execute(
                "SELECT COUNT(*) FROM draft_findings"
            ).fetchone()[0]

        self.assertEqual(count, 0)

    def test_imports_alert_as_draft(self):
        alerts = [{
            "name": "Example alert",
            "risk": "Medium",
            "url": "https://example.test/page",
            "description": "Mock description",
            "solution": "Mock remediation",
            "alert": "Example evidence",
            "confidence": "High",
            "pluginId": "10001",
        }]

        self.assertEqual(risks.import_zap_alerts_to_drafts(alerts), 1)

        with self.connect_test_db() as db:
            row = db.execute(
                "SELECT source, status, target FROM draft_findings"
            ).fetchone()

        self.assertEqual(row["source"], "zap")
        self.assertEqual(row["status"], "Draft")
        self.assertEqual(row["target"], "https://example.test/page")

    def test_duplicate_alert_is_skipped(self):
        alert = [{
            "name": "Example alert",
            "risk": "Medium",
            "url": "https://example.test/page",
            "pluginId": "10001",
        }]

        self.assertEqual(risks.import_zap_alerts_to_drafts(alert), 1)
        self.assertEqual(risks.import_zap_alerts_to_drafts(alert), 0)

        with self.connect_test_db() as db:
            count = db.execute(
                "SELECT COUNT(*) FROM draft_findings"
            ).fetchone()[0]

        self.assertEqual(count, 1)

    def test_invalid_target_is_rejected(self):
        alerts = [{
            "name": "Invalid target",
            "url": "javascript:alert(1)",
        }]

        self.assertEqual(risks.import_zap_alerts_to_drafts(alerts), 0)


if __name__ == "__main__":
    unittest.main()
