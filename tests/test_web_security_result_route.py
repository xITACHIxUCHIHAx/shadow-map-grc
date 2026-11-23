import json
import sqlite3

import app as app_module


def setup_test_app(monkeypatch, tmp_path):
    database = tmp_path / "web-security-result-test.db"
    monkeypatch.setattr(app_module, "DATABASE_PATH", database)
    app_module.app.config.update(TESTING=True)
    app_module.init_db()
    return app_module.app.test_client(), database


def save_web_security_result(database, result):
    with sqlite3.connect(database) as db:
        cursor = db.execute(
            """
            INSERT INTO web_security_scans (
                target, status, started_at, finished_at,
                duration_seconds, result_json, error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "https://example.test",
                "Completed",
                "2026-01-01T10:00:00+00:00",
                "2026-01-01T10:00:02+00:00",
                2.0,
                json.dumps(result),
                None,
            ),
        )
        return cursor.lastrowid


def base_result():
    return {
        "target": "https://example.test",
        "status_code": 200,
        "headers": [],
        "cookies": [],
        "missing_headers": 0,
        "notes": [],
        "discovery": {
            "pages": [],
            "discovered_urls": [],
            "forms": [],
            "api_endpoints": [],
            "notes": [],
            "errors": [],
        },
    }


def test_result_route_displays_wapiti_findings_and_export_links(
    monkeypatch, tmp_path
):
    client, database = setup_test_app(monkeypatch, tmp_path)
    result = base_result()
    result.update({
        "classifications": {
            "SQL Injection": {
                "desc": "Database query injection indicator.",
                "sol": "Use parameterized queries.",
                "ref": ["https://owasp.org/"],
            }
        },
        "vulnerabilities": {
            "SQL Injection": [{
                "level": 3,
                "module": "sql",
                "method": "GET",
                "path": "/search",
                "parameter": "q",
                "info": "Potential SQL injection indicator.",
                "http_request": "MUST_NOT_BE_EXPORTED",
                "curl_command": "MUST_NOT_BE_EXPORTED",
            }]
        },
    })
    scan_id = save_web_security_result(database, result)

    response = client.get(f"/web-security/results/{scan_id}")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Wapiti Vulnerability Findings" in html
    assert "SQL Injection" in html
    assert "High" in html
    assert "Potential SQL injection indicator." in html
    assert "Download PDF" in html
    assert "Download CSV" in html
    assert "Vulnerability Assessment Coverage" not in html
    assert "MUST_NOT_BE_EXPORTED" not in html

    csv_response = client.get(
        f"/web-security/results/{scan_id}/export.csv"
    )
    assert csv_response.status_code == 200
    assert "text/csv" in csv_response.content_type
    csv_text = csv_response.get_data(as_text=True)
    assert "finding_category" in csv_text
    assert "SQL Injection" in csv_text
    assert "Potential SQL injection indicator." in csv_text
    assert "MUST_NOT_BE_EXPORTED" not in csv_text


def test_result_route_handles_older_results_without_assessment_fields(
    monkeypatch, tmp_path
):
    client, database = setup_test_app(monkeypatch, tmp_path)

    result = base_result()
    scan_id = save_web_security_result(database, result)

    response = client.get(f"/web-security/results/{scan_id}")

    assert response.status_code == 200
    html = response.get_data(as_text=True)

    assert "https://example.test" in html
    assert "HTTPS response" in html
    assert "Vulnerability Assessment Coverage" not in html
