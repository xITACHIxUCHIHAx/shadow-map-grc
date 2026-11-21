import json
import sqlite3
import unittest

from grc.scan_registry import create_registry_tables
from scanner.batch_storage import (
    create_batch,
    finish_batch,
    finish_batch_item,
    save_module_result,
    save_nmap_result,
    start_batch_item,
)


SCHEMA = """
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE nmap_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    host_state TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_seconds REAL,
    command_display TEXT,
    xml_output TEXT,
    error TEXT,
    mac_address TEXT,
    mac_vendor TEXT,
    os_match TEXT,
    os_accuracy TEXT,
    os_matches_json TEXT,
    os_detection_status TEXT
);
CREATE TABLE nmap_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    product TEXT,
    version TEXT,
    extra_info TEXT,
    reason TEXT,
    service_method TEXT,
    service_confidence TEXT,
    service_tunnel TEXT,
    service_cpe TEXT
);
CREATE TABLE scan_batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module TEXT NOT NULL,
    profile TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Running',
    total_targets INTEGER NOT NULL DEFAULT 0,
    completed_targets INTEGER NOT NULL DEFAULT 0,
    partial_targets INTEGER NOT NULL DEFAULT 0,
    failed_targets INTEGER NOT NULL DEFAULT 0,
    skipped_targets INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE scan_batch_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending',
    started_at TEXT,
    finished_at TEXT,
    duration_seconds REAL,
    result_type TEXT NOT NULL DEFAULT '',
    result_record_id INTEGER,
    request_id INTEGER,
    error TEXT,
    UNIQUE(batch_id, position)
);
CREATE TABLE web_security_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_seconds REAL,
    result_json TEXT,
    error TEXT
);
CREATE TABLE zap_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_seconds REAL,
    result_json TEXT,
    error TEXT
);
CREATE TABLE threat_intel_lookups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_seconds REAL,
    result_json TEXT,
    error TEXT
);
CREATE TABLE firewall_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_seconds REAL,
    result_json TEXT,
    error TEXT
);
CREATE TABLE asset_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_key TEXT NOT NULL,
    asset_type TEXT NOT NULL DEFAULT 'Unknown',
    target TEXT NOT NULL,
    source TEXT NOT NULL,
    source_record_id TEXT NOT NULL DEFAULT '',
    vendor TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    service TEXT NOT NULL DEFAULT '',
    port INTEGER,
    protocol TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'Unassessed',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    fingerprint TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
"""


class BatchStorageTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        create_registry_tables(self.db)


    def tearDown(self):
        self.db.close()

    def test_create_batch_and_individual_items(self):
        batch_id = create_batch(
            self.db, "web_security", "", ["https://a.test", "https://b.test"]
        )
        items = self.db.execute(
            "SELECT * FROM scan_batch_items WHERE batch_id=? ORDER BY position",
            (batch_id,),
        ).fetchall()

        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["target"], "https://a.test")
        self.assertEqual(items[1]["target"], "https://b.test")
        self.assertEqual(items[0]["status"], "Pending")

    def test_web_security_result_is_saved_as_json(self):
        result = {"target": "https://a.test", "status_code": 200}
        result_type, result_id = save_module_result(
            self.db, "web_security", result["target"], "Completed",
            "2026-01-01T00:00:00+00:00", 1.2, result,
        )
        row = self.db.execute(
            "SELECT * FROM web_security_scans WHERE id=?", (result_id,)
        ).fetchone()

        self.assertEqual(result_type, "web_security")
        self.assertEqual(json.loads(row["result_json"]), result)

    def test_zap_result_is_saved_as_json(self):
        result = {
            "status": "finished",
            "spider_scan_id": "1",
            "ascan_scan_id": "2",
            "alerts": [
                {
                    "name": "Example alert",
                    "risk": "Medium",
                    "url": "http://127.0.0.1/example",
                }
            ],
        }
        result_type, result_id = save_module_result(
            self.db, "zap", "http://127.0.0.1", "Completed",
            "2026-01-01T00:00:00+00:00", 12.5, result,
        )
        row = self.db.execute(
            "SELECT * FROM zap_scans WHERE id=?", (result_id,)
        ).fetchone()

        self.assertEqual(result_type, "zap")
        self.assertEqual(row["target"], "http://127.0.0.1")
        self.assertEqual(row["status"], "Completed")
        self.assertEqual(json.loads(row["result_json"]), result)

    def test_threat_intel_result_is_saved_separately(self):
        result = {"ip": "8.8.8.8", "found": False, "ports": []}
        result_type, result_id = save_module_result(
            self.db, "threat_intel", "8.8.8.8", "Completed",
            "2026-01-01T00:00:00+00:00", 0.4, result,
        )
        self.assertEqual(result_type, "threat_intel")
        self.assertIsNotNone(
            self.db.execute(
                "SELECT id FROM threat_intel_lookups WHERE id=?",
                (result_id,),
            ).fetchone()
        )
        self.assertEqual(
            self.db.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 0
        )

    def test_nmap_result_uses_existing_tables(self):
        result = {
            "host_state": "up",
            "ports": [{
                "port": 443, "protocol": "tcp", "state": "open",
                "service": "https", "product": "Example Server",
                "version": "2.4", "extra_info": "", "reason": "syn-ack",
                "service_method": "probed",
                "service_confidence": "10",
                "service_tunnel": "ssl",
                "service_cpe": ["cpe:/a:example:server:2.4"],
            }],
            "command_display": "nmap test",
            "xml_output": "<nmaprun/>",
            "mac_address": "00:11:22:33:44:55",
            "mac_vendor": "Example Vendor",
            "os_match": "Example Linux",
            "os_accuracy": 98,
            "os_matches": [
                {"name": "Example Linux", "accuracy": "98"}
            ],
            "os_detection_status": "enabled",
        }
        result_type, scan_id, request_id = save_nmap_result(
            self.db, "192.0.2.10", "standard", "Completed",
            "2026-01-01T00:00:00+00:00", 2.0, result,
        )
        self.assertEqual(result_type, "nmap")
        saved_metadata = self.db.execute(
            "SELECT mac_address, mac_vendor, os_match, os_accuracy, "
            "os_matches_json, os_detection_status FROM nmap_scans WHERE id=?",
            (scan_id,),
        ).fetchone()
        self.assertEqual(saved_metadata["mac_address"], "00:11:22:33:44:55")
        self.assertEqual(saved_metadata["mac_vendor"], "Example Vendor")
        self.assertEqual(saved_metadata["os_match"], "Example Linux")
        self.assertEqual(saved_metadata["os_accuracy"], "98")
        self.assertEqual(
            json.loads(saved_metadata["os_matches_json"]),
            [{"name": "Example Linux", "accuracy": "98"}],
        )
        self.assertEqual(saved_metadata["os_detection_status"], "enabled")
        saved_port = self.db.execute(
            "SELECT service, product, version, service_method, "
            "service_confidence, service_tunnel, service_cpe "
            "FROM nmap_ports WHERE scan_id=?",
            (scan_id,),
        ).fetchone()

        self.assertEqual(saved_port["service"], "https")
        self.assertEqual(saved_port["product"], "Example Server")
        self.assertEqual(saved_port["version"], "2.4")
        self.assertEqual(saved_port["service_method"], "probed")
        self.assertEqual(saved_port["service_confidence"], "10")
        self.assertEqual(saved_port["service_tunnel"], "ssl")
        self.assertEqual(
            json.loads(saved_port["service_cpe"]),
            ["cpe:/a:example:server:2.4"],
        )

        self.assertEqual(
            self.db.execute(
                "SELECT COUNT(*) FROM nmap_ports WHERE scan_id=?", (scan_id,)
            ).fetchone()[0],
            1,
        )
        self.assertIsNotNone(
            self.db.execute(
                "SELECT id FROM scans WHERE id=?", (request_id,)
            ).fetchone()
        )

    def test_global_scan_and_target_ids_across_all_modules(self):
        target = "https://example.test/login"
        started_at = "2026-01-01T00:00:00+00:00"

        for module in ("web_security", "zap", "threat_intel", "firewall"):
            save_module_result(
                self.db, module, target, "Failed",
                started_at, 0.1, error="Test failure",
            )

        save_nmap_result(
            self.db, target, "standard", "Failed",
            started_at, 0.1, error="Test failure",
        )

        rows = self.db.execute(
            "SELECT scan_id, target_id, scan_type, source_record_id "
            "FROM scan_registry ORDER BY id"
        ).fetchall()

        self.assertEqual(len(rows), 5)
        self.assertEqual(
            [row["scan_id"] for row in rows],
            [f"SCN-{number:05d}" for number in range(1, 6)],
        )
        self.assertEqual(
            len({row["target_id"] for row in rows}),
            1,
        )
        self.assertEqual(
            {row["scan_type"] for row in rows},
            {"Web Security", "OWASP ZAP", "Threat Intelligence",
             "Firewall", "Nmap"},
        )
        self.assertEqual(
            [row["source_record_id"] for row in rows],
            [1, 1, 1, 1, 1],
        )
        self.assertEqual(rows[0]["target_id"], "TGT-00001")


    def test_skipped_items_are_counted_without_failing_batch(self):
        batch_id = create_batch(
            self.db, "threat_intel", "public_ipv4", ["192.168.1.10"]
        )
        item = self.db.execute(
            "SELECT id FROM scan_batch_items WHERE batch_id=?",
            (batch_id,),
        ).fetchone()

        finish_batch_item(
            self.db, item["id"], "Skipped", 0.0,
            error="Threat Intelligence supports public IP addresses only.",
        )

        summary = finish_batch(self.db, batch_id)

        self.assertEqual(summary["status"], "Completed")
        self.assertEqual(summary["total_targets"], 1)
        self.assertEqual(summary["completed_targets"], 0)
        self.assertEqual(summary["failed_targets"], 0)
        self.assertEqual(summary["skipped_targets"], 1)

        saved = self.db.execute(
            "SELECT status, error FROM scan_batch_items WHERE id=?",
            (item["id"],),
        ).fetchone()
        self.assertEqual(saved["status"], "Skipped")
        self.assertIn("public IP addresses only", saved["error"])

    def test_batch_summary_and_item_linkage(self):
        batch_id = create_batch(self.db, "nmap", "standard", ["a", "b"])
        items = self.db.execute(
            "SELECT id FROM scan_batch_items WHERE batch_id=? ORDER BY position",
            (batch_id,),
        ).fetchall()

        start_batch_item(self.db, items[0]["id"])
        finish_batch_item(
            self.db, items[0]["id"], "Completed", 1.0,
            "nmap", 10, 20,
        )
        finish_batch_item(
            self.db, items[1]["id"], "Failed", 0.1,
            error="Timed out",
        )

        summary = finish_batch(self.db, batch_id)
        self.assertEqual(summary["status"], "Partial")
        self.assertEqual(summary["completed_targets"], 1)
        self.assertEqual(summary["failed_targets"], 1)

        saved = self.db.execute(
            "SELECT result_record_id, request_id FROM scan_batch_items "
            "WHERE id=?", (items[0]["id"],)
        ).fetchone()
        self.assertEqual(saved["result_record_id"], 10)
        self.assertEqual(saved["request_id"], 20)


if __name__ == "__main__":
    unittest.main()
