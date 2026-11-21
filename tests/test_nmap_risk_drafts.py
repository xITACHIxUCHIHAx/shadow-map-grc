import sqlite3

import pytest

import app as app_module
from grc import automatic_risks


def setup_nmap_risk_test_db(monkeypatch, tmp_path):
    database = tmp_path / "nmap-risk-test.db"

    monkeypatch.setattr(app_module, "DATABASE_PATH", database)
    monkeypatch.setattr(automatic_risks, "DATABASE_PATH", database)

    app_module.app.config.update(TESTING=True)
    app_module.init_db()
    automatic_risks.initialize_automatic_risks()

    return database


@pytest.mark.parametrize(
    ("port", "service", "expected"),
    [
        (21, "ftp", "SFTP or FTPS"),
        (22, "ssh", "key-based authentication"),
        (23, "telnet", "does not encrypt sessions"),
        (445, "microsoft-ds", "SMB/NetBIOS"),
        (3389, "ms-wbt-server", "Remote Desktop"),
        (3306, "mysql", "database"),
        (5432, "postgresql", "PostgreSQL"),
        (6379, "redis", "Redis"),
        (27017, "mongodb", "MongoDB"),
    ],
)
def test_service_recommendation_covers_common_services(
    port, service, expected
):
    recommendation = automatic_risks.service_recommendation(port, service)

    assert expected.lower() in recommendation.lower()


def test_unknown_service_receives_generic_review_guidance():
    recommendation = automatic_risks.service_recommendation(
        9999, "unknown-service"
    )

    assert "Identify and verify the purpose" in recommendation
    assert "9999" in recommendation


def test_nmap_drafts_include_open_ports_and_exclude_closed_ports(
    monkeypatch, tmp_path
):
    database = setup_nmap_risk_test_db(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        cursor = db.execute(
            """
            INSERT INTO scans (target, scan_type, status, created_at)
            VALUES (?, 'nmap', 'Completed', ?)
            """,
            ("192.0.2.10", "2026-11-14T10:00:00"),
        )
        request_id = cursor.lastrowid

        cursor = db.execute(
            """
            INSERT INTO nmap_scans (
                request_id, target, status, started_at
            ) VALUES (?, ?, 'Completed', ?)
            """,
            (request_id, "192.0.2.10", "2026-11-14T10:00:00"),
        )
        scan_id = cursor.lastrowid

        db.executemany(
            """
            INSERT INTO nmap_ports (
                scan_id, port, protocol, state, service,
                product, version, extra_info, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_id, 23, "tcp", "open", "telnet",
                    "", "", "", "syn-ack",
                ),
                (
                    scan_id, 445, "tcp", "open", "microsoft-ds",
                    "Samba", "4.18", "", "syn-ack",
                ),
                (
                    scan_id, 21, "tcp", "closed", "ftp",
                    "", "", "", "conn-refused",
                ),
            ],
        )
        db.commit()

    created = automatic_risks.generate_nmap_drafts(scan_id)

    assert created == 2

    with sqlite3.connect(database) as db:
        db.row_factory = sqlite3.Row
        findings = db.execute(
            """
            SELECT * FROM draft_findings
            WHERE source = 'nmap' AND source_record_id = ?
            ORDER BY title
            """,
            (scan_id,),
        ).fetchall()

    assert len(findings) == 2

    titles = [finding["title"] for finding in findings]
    assert any("port 23" in title for title in titles)
    assert any("port 445" in title for title in titles)
    assert not any("port 21" in title for title in titles)

    for finding in findings:
        assert finding["status"] == "Draft"
        assert finding["suggested_severity"] == "Review"
        assert finding["confidence"] == "Low"
        assert finding["target"] == "192.0.2.10"
        assert f"Nmap scan #{scan_id}" in finding["evidence"]
        assert "A.8.20, A.8.21" == finding["iso_controls"]


def test_nmap_draft_generation_does_not_duplicate_findings(
    monkeypatch, tmp_path
):
    database = setup_nmap_risk_test_db(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        cursor = db.execute(
            """
            INSERT INTO scans (target, scan_type, status, created_at)
            VALUES (?, 'nmap', 'Completed', ?)
            """,
            ("192.0.2.20", "2026-11-14T10:00:00"),
        )
        request_id = cursor.lastrowid

        cursor = db.execute(
            """
            INSERT INTO nmap_scans (
                request_id, target, status, started_at
            ) VALUES (?, ?, 'Completed', ?)
            """,
            (request_id, "192.0.2.20", "2026-11-14T10:00:00"),
        )
        scan_id = cursor.lastrowid

        db.execute(
            """
            INSERT INTO nmap_ports (
                scan_id, port, protocol, state, service,
                product, version, extra_info, reason
            ) VALUES (?, 22, 'tcp', 'open', 'ssh', '', '', '', 'syn-ack')
            """,
            (scan_id,),
        )
        db.commit()

    assert automatic_risks.generate_nmap_drafts(scan_id) == 1
    assert automatic_risks.generate_nmap_drafts(scan_id) == 0

    with sqlite3.connect(database) as db:
        count = db.execute(
            """
            SELECT COUNT(*) FROM draft_findings
            WHERE source = 'nmap' AND source_record_id = ?
            """,
            (scan_id,),
        ).fetchone()[0]

    assert count == 1


def test_nmap_draft_generation_skips_non_completed_scans(
    monkeypatch, tmp_path
):
    database = setup_nmap_risk_test_db(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        cursor = db.execute(
            """
            INSERT INTO scans (target, scan_type, status, created_at)
            VALUES (?, 'nmap', 'Partial', ?)
            """,
            ("192.0.2.30", "2026-11-14T10:00:00"),
        )
        request_id = cursor.lastrowid

        cursor = db.execute(
            """
            INSERT INTO nmap_scans (
                request_id, target, status, started_at
            ) VALUES (?, ?, 'Partial', ?)
            """,
            (request_id, "192.0.2.30", "2026-11-14T10:00:00"),
        )
        scan_id = cursor.lastrowid
        db.commit()

    assert automatic_risks.generate_nmap_drafts(scan_id) == 0
