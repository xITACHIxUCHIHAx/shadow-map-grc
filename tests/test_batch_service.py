import sqlite3
import unittest

from scanner.batch_service import execute_batch
from tests.test_batch_storage import SCHEMA
from grc.scan_registry import create_registry_tables


class BatchServiceTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        create_registry_tables(self.db)

    def tearDown(self):
        self.db.close()

    def db_factory(self):
        return self.db

    def test_successful_targets_are_saved_individually(self):
        calls = []

        def validator(target):
            return target.strip().lower()

        def scanner(target):
            calls.append(target)
            return {"target": target, "status_code": 200}

        batch_id, summary = execute_batch(
            self.db_factory,
            "web_security",
            "",
            ["https://a.test", "https://b.test"],
            validator,
            scanner,
        )

        self.assertEqual(calls, ["https://a.test", "https://b.test"])
        self.assertEqual(summary["status"], "Completed")
        self.assertEqual(summary["completed_targets"], 2)

        rows = self.db.execute(
            "SELECT target, status FROM web_security_scans ORDER BY id"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["target"], "https://a.test")
        self.assertEqual(rows[1]["target"], "https://b.test")

        items = self.db.execute(
            "SELECT status, result_record_id FROM scan_batch_items "
            "WHERE batch_id=? ORDER BY position",
            (batch_id,),
        ).fetchall()
        self.assertTrue(all(row["status"] == "Completed" for row in items))
        self.assertTrue(all(row["result_record_id"] for row in items))

    def test_validation_failure_does_not_stop_later_target(self):
        calls = []

        def validator(target):
            if target == "bad-target":
                raise ValueError("Target rejected by validator.")
            return target

        def scanner(target):
            calls.append(target)
            return {"ip": target, "found": False}

        batch_id, summary = execute_batch(
            self.db_factory,
            "threat_intel",
            "",
            ["bad-target", "8.8.8.8"],
            validator,
            scanner,
        )

        self.assertEqual(calls, ["8.8.8.8"])
        self.assertEqual(summary["status"], "Partial")
        self.assertEqual(summary["failed_targets"], 1)
        self.assertEqual(summary["completed_targets"], 1)

        items = self.db.execute(
            "SELECT target, status, error FROM scan_batch_items "
            "WHERE batch_id=? ORDER BY position",
            (batch_id,),
        ).fetchall()
        self.assertEqual(items[0]["status"], "Failed")
        self.assertIn("Target rejected", items[0]["error"])
        self.assertEqual(items[1]["status"], "Completed")

    def test_scanner_exception_does_not_stop_later_target(self):
        calls = []

        def scanner(target):
            calls.append(target)
            if target == "first.test":
                raise TimeoutError("Scanner timed out.")
            return {"target": target, "status_code": 200}

        batch_id, summary = execute_batch(
            self.db_factory,
            "web_security",
            "",
            ["first.test", "second.test"],
            lambda target: target,
            scanner,
        )

        self.assertEqual(calls, ["first.test", "second.test"])
        self.assertEqual(summary["failed_targets"], 1)
        self.assertEqual(summary["completed_targets"], 1)

        items = self.db.execute(
            "SELECT status, error FROM scan_batch_items "
            "WHERE batch_id=? ORDER BY position",
            (batch_id,),
        ).fetchall()
        self.assertEqual(items[0]["status"], "Failed")
        self.assertIn("timed out", items[0]["error"].lower())
        self.assertEqual(items[1]["status"], "Completed")

    def test_scanner_reported_failure_is_not_marked_completed(self):
        batch_id, summary = execute_batch(
            self.db_factory,
            "web_security",
            "",
            ["failed.test"],
            lambda target: target,
            lambda target: {
                "target": target,
                "status": "Failed",
                "error": "Scanner reported failure.",
            },
        )

        self.assertEqual(summary["failed_targets"], 1)
        item = self.db.execute(
            "SELECT status, error FROM scan_batch_items "
            "WHERE batch_id=?",
            (batch_id,),
        ).fetchone()
        self.assertEqual(item["status"], "Failed")
        self.assertIn("Scanner reported failure", item["error"])


if __name__ == "__main__":
    unittest.main()
