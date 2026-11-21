import json
import sqlite3

import app as app_module


def setup_test_app(monkeypatch, tmp_path):
    database = tmp_path / "firewall-pdf-test.db"
    monkeypatch.setattr(app_module, "DATABASE_PATH", database)
    app_module.app.config.update(TESTING=True)
    app_module.init_db()
    return app_module.app.test_client(), database


def test_firewall_pdf_export_returns_saved_assessment(
    monkeypatch, tmp_path
):
    client, database = setup_test_app(monkeypatch, tmp_path)

    result = {
        "target": "192.0.2.10",
        "host": "192.0.2.10",
        "resolved_addresses": ["192.0.2.10"],
        "duration_seconds": 0.1,
        "tcp": {
            "ports": [],
            "counts": {
                "open": 0,
                "closed": 0,
                "no_response": 0,
                "indeterminate": 0,
            },
        },
        "services": {"items": []},
        "https": {
            "checked": False,
            "url": "https://192.0.2.10/",
            "scheme": "https",
            "port": 443,
            "headers": {},
        },
        "tls": {"available": False},
        "waf": {
            "detected": False,
            "vendor_identification": [],
            "confidence": "unknown",
        },
        "limitations": ["Mock-only route test."],
    }

    with sqlite3.connect(database) as db:
        cursor = db.execute(
            """
            INSERT INTO firewall_scans (
                target, status, started_at, finished_at,
                duration_seconds, result_json, error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "192.0.2.10",
                "completed",
                "2026-11-04 10:00:00",
                "2026-11-04 10:00:01",
                0.1,
                json.dumps(result),
                None,
            ),
        )
        scan_id = cursor.lastrowid

    response = client.get(
        f"/firewall/results/{scan_id}/export.pdf"
    )

    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.data.startswith(b"%PDF-")
    assert f"shadow-map-firewall-{scan_id}.pdf" in (
        response.headers.get("Content-Disposition", "")
    )
    assert response.headers.get("X-Content-Type-Options") == "nosniff"


def test_firewall_pdf_export_returns_404_for_missing_scan(
    monkeypatch, tmp_path
):
    client, _ = setup_test_app(monkeypatch, tmp_path)

    response = client.get("/firewall/results/999999/export.pdf")

    assert response.status_code == 404


def test_firewall_results_page_renders_saved_service_items(
    monkeypatch, tmp_path
):
    client, database = setup_test_app(monkeypatch, tmp_path)

    result = {
        "target": "192.0.2.10",
        "host": "192.0.2.10",
        "resolved_addresses": ["192.0.2.10"],
        "duration_seconds": 0.1,
        "tcp": {
            "ports": [],
            "counts": {
                "open": 0,
                "closed": 0,
                "no_response": 0,
                "indeterminate": 0,
            },
            "interpretation": "Mock TCP interpretation.",
        },
        "services": {
            "items": [
                {
                    "address": "192.0.2.10",
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                    "application": {
                        "product": "Mock Web Server",
                        "version": "1.0",
                        "confidence": "high",
                        "evidence": ["Mock response fingerprint."],
                    },
                }
            ]
        },
        "https": {
            "checked": False,
            "url": "https://192.0.2.10/",
            "scheme": "https",
            "port": 443,
            "headers": {},
        },
        "tls": {"available": False},
        "waf": {
            "detected": False,
            "vendor_identification": [],
            "confidence": "unknown",
            "limitation": "Mock WAF limitation.",
        },
        "limitations": ["Mock-only route test."],
    }

    with sqlite3.connect(database) as db:
        cursor = db.execute(
            """
            INSERT INTO firewall_scans (
                target, status, started_at, finished_at,
                duration_seconds, result_json, error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "192.0.2.10",
                "Completed",
                "2026-11-04 10:00:00",
                "2026-11-04 10:00:01",
                0.1,
                json.dumps(result),
                None,
            ),
        )
        scan_id = cursor.lastrowid

    response = client.get(f"/firewall/results/{scan_id}")

    assert response.status_code == 200
    assert b"Service &amp; Application Identification" in response.data
    assert b"Mock Web Server" in response.data
    assert b"Mock response fingerprint." in response.data
