import sqlite3

import app as app_module
from grc import automatic_risks


def setup_combined_findings_app(monkeypatch, tmp_path):
    database = tmp_path / "combined-findings-test.db"
    monkeypatch.setattr(app_module, "DATABASE_PATH", database)

    app_module.app.config.update(TESTING=True)
    app_module.init_db()
    monkeypatch.setattr(automatic_risks, "DATABASE_PATH", database)
    automatic_risks.initialize_automatic_risks()

    return app_module.app.test_client(), database


def test_combined_findings_displays_linked_web_scan_statuses(
    monkeypatch, tmp_path
):
    client, database = setup_combined_findings_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        db.execute(
            """
            INSERT INTO web_security_scans (
                id, target, status, started_at, finished_at,
                duration_seconds, result_json, error
            ) VALUES
                (101, 'https://partial.example.test/', 'Partial',
                 '2026-11-07T10:00:00', '2026-11-07T10:00:05',
                 5.0, '{}', NULL),
                (102, 'https://complete.example.test/', 'Completed',
                 '2026-11-07T10:01:00', '2026-11-07T10:01:05',
                 5.0, '{}', NULL)
            """
        )
        db.execute(
            """
            INSERT INTO draft_findings (
                source, source_record_id, fingerprint, target, title,
                description, evidence, suggested_severity, confidence,
                recommendation, iso_controls, status, created_at, updated_at
            ) VALUES (
                'web_security', 101, 'partial-web-finding',
                'https://partial.example.test/',
                'Missing Content-Security-Policy',
                'The response did not include a Content-Security-Policy header.',
                'Content-Security-Policy absent',
                'Review', 'Low', 'Review the available header evidence.',
                'A.8.26', 'Draft', '2026-11-07', '2026-11-07'
            )
            """
        )
        db.execute(
            "INSERT INTO draft_findings (source, source_record_id, fingerprint, "
            "target, title, description, evidence, suggested_severity, confidence, "
            "recommendation, iso_controls, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "web_security", 102, "completed-web-finding",
                "https://complete.example.test/", "Completed scan finding",
                "Finding from the completed scan.", "Completed scan evidence",
                "Review", "Low", "Review the available evidence.",
                "A.8.26", "Draft", "2026-11-07", "2026-11-07",
            ),
        )
        db.commit()

    response = client.get("/combined-findings")

    assert response.status_code == 200
    assert b"Partial" in response.data
    assert b"Completed" in response.data
    assert b"Missing Content-Security-Policy" in response.data
    assert b"web_security:101" in response.data
    assert b"web_security:102" in response.data

    filtered_response = client.get(
        "/combined-findings?scan_id=web_security:101"
    )

    assert filtered_response.status_code == 200
    assert b"Missing Content-Security-Policy" in filtered_response.data
    assert b"Completed scan finding" not in filtered_response.data
    assert b"web_security:102" in filtered_response.data
