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


def test_result_route_displays_active_and_planned_assessments(
    monkeypatch, tmp_path
):
    client, database = setup_test_app(monkeypatch, tmp_path)

    result = base_result()
    result.update({
        "reflected_input_assessment": {
            "status": "completed",
            "checks": [
                {
                    "parameter": "search",
                    "status": "suspected",
                    "confidence": "low",
                    "verified": False,
                }
            ],
        },
        "sql_injection_assessment": {
            "status": "not_run",
            "checks": [],
        },
        "assessment_plan": {
            "sql_boolean_based_checks": [
                {
                    "parameter": "id",
                    "status": "not_tested",
                    "verified": False,
                }
            ],
        },
    })

    scan_id = save_web_security_result(database, result)

    response = client.get(f"/web-security/results/{scan_id}")

    assert response.status_code == 200
    html = response.get_data(as_text=True)

    assert "Vulnerability Assessment Coverage" in html
    assert "Reflected-input check" in html
    assert "search" in html
    assert "Suspected" in html
    assert "Not verified" in html
    assert "Boolean-based SQL injection" in html
    assert "Planned — Not Tested" in html
    assert "id" in html
    assert "no Boolean test requests were sent" in html


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


def test_result_route_displays_empty_assessment_plan(
    monkeypatch, tmp_path
):
    client, database = setup_test_app(monkeypatch, tmp_path)

    result = base_result()
    result["assessment_plan"] = {
        "sql_boolean_based_checks": [],
    }
    scan_id = save_web_security_result(database, result)

    response = client.get(f"/web-security/results/{scan_id}")

    assert response.status_code == 200
    html = response.get_data(as_text=True)

    assert "Vulnerability Assessment Coverage" in html
    assert "No assessment checks recorded." in html
