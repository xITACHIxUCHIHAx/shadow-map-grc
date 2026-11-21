import csv
import io
import sqlite3

import app as app_module
from grc import automatic_risks as risks


def setup_host_test_app(monkeypatch, tmp_path):
    database = tmp_path / "host-report-test.db"

    # Both modules must use the same isolated test database.
    monkeypatch.setattr(app_module, "DATABASE_PATH", database)
    monkeypatch.setattr(risks, "DATABASE_PATH", database)

    app_module.app.config.update(TESTING=True)
    app_module.init_db()
    risks.initialize_automatic_risks()

    with sqlite3.connect(database) as db:
        db.execute("""
            INSERT INTO draft_findings (
                id, source, fingerprint, target, title, description,
                evidence, suggested_severity, confidence, recommendation,
                iso_controls, status, created_at, updated_at
            ) VALUES
                (1, 'nmap', 'host-one', '192.0.2.10',
                 'SSH service exposed', 'SSH service detected',
                 'TCP port 22 open', 'High', 'High', 'Restrict SSH access',
                 'A.8.20', 'Draft', '2026-11-01', '2026-11-01'),
                (2, 'web', 'host-two', '192.0.2.10',
                 'Missing security header', 'CSP header missing',
                 'Content-Security-Policy absent', 'Medium', 'Medium',
                 'Configure CSP', 'A.8.26', 'Draft',
                 '2026-11-01', '2026-11-01'),
                (3, 'nmap', 'other-host', '192.0.2.20',
                 'Other host finding', 'Different host',
                 'Unrelated evidence', 'Critical', 'High',
                 'Review other host', 'A.8.20', 'Draft',
                 '2026-11-01', '2026-11-01')
        """)
        db.commit()

    return app_module.app.test_client(), database


def test_host_report_shows_only_findings_for_selected_host(
    monkeypatch, tmp_path
):
    client, _ = setup_host_test_app(monkeypatch, tmp_path)

    response = client.get("/finding-intelligence/host/192.0.2.10")

    assert response.status_code == 200
    assert b"SSH service exposed" in response.data
    assert b"Missing security header" in response.data
    assert b"Other host finding" not in response.data


def test_host_report_combines_search_and_severity_filters(
    monkeypatch, tmp_path
):
    client, _ = setup_host_test_app(monkeypatch, tmp_path)

    response = client.get(
        "/finding-intelligence/host/192.0.2.10"
        "?q=SSH&severity=High"
    )

    assert response.status_code == 200
    assert b"SSH service exposed" in response.data
    assert b"Missing security header" not in response.data
    assert b"Other host finding" not in response.data


def test_filtered_host_csv_contains_only_matching_host_findings(
    monkeypatch, tmp_path
):
    client, _ = setup_host_test_app(monkeypatch, tmp_path)

    response = client.get(
        "/finding-intelligence/host/192.0.2.10/export-filtered.csv"
        "?severity=High"
    )

    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert b"SSH service exposed" in response.data
    assert b"Missing security header" not in response.data
    assert b"Other host finding" not in response.data


def test_analyst_review_returns_to_same_host_and_preserves_automated_values(
    monkeypatch, tmp_path
):
    client, database = setup_host_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        db.execute("""
            INSERT INTO finding_intelligence (
                finding_id, auto_cve_ids, auto_mitre_technique,
                auto_security_category, validation_status, updated_at
            ) VALUES (
                1, 'CVE-2024-12345', 'T1110',
                'Security Misconfiguration', 'Unreviewed', '2026-11-01'
            )
        """)
        db.commit()

    response = client.post(
        "/finding-intelligence",
        data={
            "finding_id": "1",
            "return_host": "192.0.2.10",
            "cve_ids": "CVE-2024-12345",
            "owasp_category": "A05:2021 – Security Misconfiguration",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110",
            "mapping_confidence": "High",
            "validation_status": "Evidence-supported",
            "mapping_rationale": "Repeated failed login attempts confirmed.",
            "source_reference": "https://attack.mitre.org/techniques/T1110/",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "/finding-intelligence/host/192.0.2.10" in response.headers["Location"]
    assert "finding=1" in response.headers["Location"]

    with sqlite3.connect(database) as db:
        row = db.execute("""
            SELECT cve_ids, mitre_technique, auto_cve_ids,
                   auto_mitre_technique, auto_security_category,
                   validation_status
            FROM finding_intelligence
            WHERE finding_id = 1
        """).fetchone()

    assert row == (
        "CVE-2024-12345",
        "T1110",
        "CVE-2024-12345",
        "T1110",
        "Security Misconfiguration",
        "Evidence-supported",
    )


def test_host_register_groups_pages_under_one_website_origin(
    monkeypatch, tmp_path
):
    client, database = setup_host_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        db.execute("""
            INSERT INTO draft_findings (
                id, source, fingerprint, target, title, description,
                evidence, suggested_severity, confidence, recommendation,
                iso_controls, status, created_at, updated_at
            ) VALUES
                (4, 'web', 'page-one',
                 'https://example.test/login',
                 'Login page finding', 'Login page issue',
                 'Login evidence', 'High', 'High', 'Review login',
                 'A.8.26', 'Draft', '2026-11-01', '2026-11-01'),
                (5, 'web', 'page-two',
                 'https://example.test/account/profile',
                 'Profile page finding', 'Profile page issue',
                 'Profile evidence', 'Low', 'Medium', 'Review profile',
                 'A.8.26', 'Draft', '2026-11-01', '2026-11-01')
        """)
        db.commit()

    response = client.get("/finding-intelligence")

    assert response.status_code == 200
    assert b"https://example.test" in response.data
    assert b"2 stored target aliases" in response.data
    assert b"Login page finding" not in response.data
    assert b"Profile page finding" not in response.data


def test_host_register_search_matches_original_page_url_alias(
    monkeypatch, tmp_path
):
    client, database = setup_host_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        db.execute("""
            INSERT INTO draft_findings (
                id, source, fingerprint, target, title, description,
                evidence, suggested_severity, confidence, recommendation,
                iso_controls, status, created_at, updated_at
            ) VALUES
                (4, 'web', 'page-one',
                 'https://example.test/login',
                 'Login page finding', 'Login page issue',
                 'Login evidence', 'High', 'High', 'Review login',
                 'A.8.26', 'Draft', '2026-11-01', '2026-11-01'),
                (5, 'web', 'page-two',
                 'https://example.test/account/profile',
                 'Profile page finding', 'Profile page issue',
                 'Profile evidence', 'Low', 'Medium', 'Review profile',
                 'A.8.26', 'Draft', '2026-11-01', '2026-11-01')
        """)
        db.commit()

    response = client.get(
        "/finding-intelligence?q=example.test%2Faccount%2Fprofile"
    )

    assert response.status_code == 200
    assert b"https://example.test" in response.data
    assert b"192.0.2.10" not in response.data
    assert b"192.0.2.20" not in response.data


def test_opening_host_register_does_not_create_intelligence_rows(
    monkeypatch, tmp_path
):
    client, database = setup_host_test_app(monkeypatch, tmp_path)

    response = client.get("/finding-intelligence")

    assert response.status_code == 200

    with sqlite3.connect(database) as db:
        count = db.execute(
            "SELECT COUNT(*) FROM finding_intelligence"
        ).fetchone()[0]

    assert count == 0


def test_filtered_host_pdf_receives_only_matching_findings(
    monkeypatch, tmp_path
):
    client, _ = setup_host_test_app(monkeypatch, tmp_path)
    captured = {}

    def fake_host_report_pdf(host, rows, title):
        captured["host"] = host
        captured["rows"] = rows
        captured["title"] = title
        return b"%PDF-test"

    monkeypatch.setattr(risks, "_host_report_pdf", fake_host_report_pdf)

    response = client.get(
        "/finding-intelligence/host/192.0.2.10/export-filtered.pdf"
        "?severity=High"
    )

    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.data == b"%PDF-test"
    assert captured["host"] == "192.0.2.10"
    assert [row["title"] for row in captured["rows"]] == [
        "SSH service exposed"
    ]


def test_unknown_host_report_returns_404(monkeypatch, tmp_path):
    client, _ = setup_host_test_app(monkeypatch, tmp_path)

    response = client.get(
        "/finding-intelligence/host/192.0.2.99"
    )

    assert response.status_code == 404


def test_full_host_csv_exports_iso_and_automated_intelligence(
    monkeypatch, tmp_path
):
    client, database = setup_host_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        db.execute("""
            INSERT INTO finding_intelligence (
                finding_id, auto_security_category, auto_mitre_tactic,
                auto_mitre_technique, auto_mitre_rationale,
                auto_mitre_confidence, validation_status, updated_at
            ) VALUES (
                1, 'Exposed Network Service', 'Credential Access',
                'T1110', 'Repeated brute-force evidence',
                'High', 'Evidence-supported', '2026-11-01'
            )
        """)
        db.commit()

    original_query = risks._intelligence_query
    captured = {}

    def tracked_query(args, limit=1000):
        captured["limit"] = limit
        return original_query(args, limit=limit)

    monkeypatch.setattr(risks, "_intelligence_query", tracked_query)

    response = client.get(
        "/finding-intelligence/host/192.0.2.10/export.csv"
    )

    assert response.status_code == 200
    assert captured["limit"] is None

    rows = list(csv.reader(io.StringIO(
        response.data.decode("utf-8-sig")
    )))
    headers = rows[0]
    exported = next(
        dict(zip(headers, row))
        for row in rows[1:]
        if row[0] == "1"
    )

    assert exported["iso_controls"] == "A.8.20"
    assert exported["auto_security_category"] == "Exposed Network Service"
    assert exported["auto_mitre_tactic"] == "Credential Access"
    assert exported["auto_mitre_technique"] == "T1110"
    assert exported["auto_mitre_rationale"] == "Repeated brute-force evidence"
    assert exported["auto_mitre_confidence"] == "High"


def test_full_host_pdf_exports_iso_and_separates_automated_mapping(
    monkeypatch, tmp_path
):
    client, database = setup_host_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        db.execute("""
            INSERT INTO finding_intelligence (
                finding_id, auto_security_category, auto_mitre_tactic,
                auto_mitre_technique, auto_mitre_rationale,
                auto_mitre_confidence, mitre_tactic, mitre_technique,
                mapping_rationale, validation_status, updated_at
            ) VALUES (
                1, 'Exposed Network Service', 'Credential Access',
                'T1110', 'Automated brute-force evidence',
                'High', 'Initial Access', 'T1190',
                'Analyst-confirmed exploitation evidence',
                'Evidence-supported', '2026-11-01'
            )
        """)
        db.commit()

    original_query = risks._intelligence_query
    captured = {}

    def tracked_query(args, limit=1000):
        captured["limit"] = limit
        return original_query(args, limit=limit)

    def fake_build_grc_pdf(**kwargs):
        captured["findings"] = kwargs["findings"]
        return b"%PDF-test"

    monkeypatch.setattr(risks, "_intelligence_query", tracked_query)
    monkeypatch.setattr(risks, "build_grc_pdf", fake_build_grc_pdf)

    response = client.get(
        "/finding-intelligence/host/192.0.2.10/export.pdf"
    )

    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.data == b"%PDF-test"
    assert captured["limit"] is None

    finding = next(
        row for row in captured["findings"]
        if row["title"] == "SSH service exposed"
    )
    assert finding["iso_controls"] == "A.8.20"
    assert "Automated MITRE suggestion: Credential Access T1110" in finding["evidence"]
    assert "Analyst MITRE mapping: Initial Access T1190" in finding["evidence"]
    assert "Automated security category: Exposed Network Service" in finding["evidence"]
    assert "Automated brute-force evidence" in finding["evidence"]
    assert "Analyst-confirmed exploitation evidence" in finding["evidence"]


def _post_analyst_technique(
    client, technique, tactic="Credential Access"
):
    return client.post(
        "/finding-intelligence",
        data={
            "finding_id": "1",
            "mitre_technique": technique,
            "mitre_tactic": tactic,
            "mapping_confidence": "High",
            "validation_status": "Evidence-supported",
            "mapping_rationale": "Analyst-reviewed evidence.",
        },
        follow_redirects=False,
    )


def test_analyst_mapping_accepts_active_catalogue_technique(
    monkeypatch, tmp_path
):
    client, database = setup_host_test_app(monkeypatch, tmp_path)

    monkeypatch.setattr(
        risks, "get_latest_attack_version", lambda: "test-version"
    )
    monkeypatch.setattr(
        risks,
        "get_attack_technique",
        lambda *args, **kwargs: {
            "technique_id": "T1110",
            "name": "Brute Force",
            "deprecated": 0,
            "revoked": 0,
        },
    )

    response = _post_analyst_technique(client, "T1110")

    assert response.status_code == 302

    with sqlite3.connect(database) as db:
        row = db.execute(
            "SELECT mitre_technique FROM finding_intelligence "
            "WHERE finding_id = 1"
        ).fetchone()

    assert row == ("T1110",)


def test_analyst_mapping_rejects_unknown_catalogue_technique(
    monkeypatch, tmp_path
):
    client, database = setup_host_test_app(monkeypatch, tmp_path)

    monkeypatch.setattr(
        risks, "get_latest_attack_version", lambda: "test-version"
    )
    monkeypatch.setattr(
        risks, "get_attack_technique", lambda *args, **kwargs: None
    )

    response = _post_analyst_technique(client, "T9999")

    assert response.status_code == 302

    with sqlite3.connect(database) as db:
        row = db.execute(
            "SELECT mitre_technique FROM finding_intelligence "
            "WHERE finding_id = 1"
        ).fetchone()

    assert row is None


def test_analyst_mapping_rejects_revoked_catalogue_technique(
    monkeypatch, tmp_path
):
    client, database = setup_host_test_app(monkeypatch, tmp_path)

    monkeypatch.setattr(
        risks, "get_latest_attack_version", lambda: "test-version"
    )
    monkeypatch.setattr(
        risks,
        "get_attack_technique",
        lambda *args, **kwargs: {
            "technique_id": "T1110",
            "name": "Brute Force",
            "deprecated": 0,
            "revoked": 1,
        },
    )

    response = _post_analyst_technique(client, "T1110")

    assert response.status_code == 302

    with sqlite3.connect(database) as db:
        row = db.execute(
            "SELECT mitre_technique FROM finding_intelligence "
            "WHERE finding_id = 1"
        ).fetchone()

    assert row is None


def test_analyst_mapping_retains_deprecated_catalogue_technique(
    monkeypatch, tmp_path
):
    client, database = setup_host_test_app(monkeypatch, tmp_path)

    monkeypatch.setattr(
        risks, "get_latest_attack_version", lambda: "test-version"
    )
    monkeypatch.setattr(
        risks,
        "get_attack_technique",
        lambda *args, **kwargs: {
            "technique_id": "T1110",
            "name": "Brute Force",
            "deprecated": 1,
            "revoked": 0,
        },
    )

    with client.session_transaction() as session:
        session["_flashes"] = []

    response = _post_analyst_technique(client, "T1110")

    assert response.status_code == 302

    with client.session_transaction() as session:
        flashes = session.get("_flashes", [])

    assert any(
        category == "warning" and "deprecated" in message.lower()
        for category, message in flashes
    )

    with sqlite3.connect(database) as db:
        row = db.execute(
            "SELECT mitre_technique FROM finding_intelligence "
            "WHERE finding_id = 1"
        ).fetchone()

    assert row == ("T1110",)


def test_analyst_mapping_is_not_saved_when_catalogue_database_fails(
    monkeypatch, tmp_path
):
    client, database = setup_host_test_app(monkeypatch, tmp_path)

    def fail_catalogue_lookup():
        raise sqlite3.OperationalError("simulated catalogue database failure")

    monkeypatch.setattr(
        risks, "get_latest_attack_version", fail_catalogue_lookup
    )

    response = _post_analyst_technique(client, "T1110")

    assert response.status_code == 302

    with sqlite3.connect(database) as db:
        row = db.execute(
            "SELECT mitre_technique FROM finding_intelligence "
            "WHERE finding_id = 1"
        ).fetchone()

    assert row is None

    with client.session_transaction() as session:
        flashes = session.get("_flashes", [])

    assert any(
        category == "error" and "catalogue validation failed" in message.lower()
        for category, message in flashes
    )


def test_analyst_route_uses_imported_attack_catalogue_without_changing_automated_mapping(
    monkeypatch, tmp_path
):
    from grc import attack_catalogue

    # Keep both the application and catalogue on the isolated test database.
    database = tmp_path / "host-report-test.db"
    monkeypatch.setattr(
        attack_catalogue, "DATABASE_PATH", database
    )

    client, database = setup_host_test_app(monkeypatch, tmp_path)

    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--integration-0001",
                "name": "Execution",
                "x_mitre_shortname": "execution",
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": "TA0002",
                    "url": "https://attack.mitre.org/tactics/TA0002/",
                }],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--integration-0001",
                "name": "Command and Scripting Interpreter",
                "description": "Execute commands and scripts.",
                "x_mitre_domains": ["enterprise-attack"],
                "x_mitre_is_subtechnique": False,
                "kill_chain_phases": [{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "execution",
                }],
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": "T1059",
                    "url": "https://attack.mitre.org/techniques/T1059/",
                }],
            },
        ],
    }

    imported = attack_catalogue.import_attack_stix(
        bundle,
        "integration-v1",
        database_path=database,
        source_reference="synthetic integration-test fixture",
    )

    assert imported["status"] == "success"
    assert imported["techniques_imported"] == 1

    # Seed automated intelligence and verify the analyst route preserves it.
    with sqlite3.connect(database) as db:
        db.execute(
            """
            INSERT INTO finding_intelligence (
                finding_id,
                auto_mitre_tactic,
                auto_mitre_technique,
                auto_mitre_rationale,
                auto_mitre_confidence,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                1,
                "Credential Access",
                "T1110",
                "Automated brute-force evidence",
                "High",
                "2026-11-12",
            ),
        )
        db.commit()

        seeded = db.execute(
            """
            SELECT
                auto_mitre_tactic,
                auto_mitre_technique,
                auto_mitre_rationale,
                auto_mitre_confidence
            FROM finding_intelligence
            WHERE finding_id = 1
            """
        ).fetchone()

        assert seeded == (
            "Credential Access",
            "T1110",
            "Automated brute-force evidence",
            "High",
        ), f"Automated mapping was not seeded correctly: {seeded!r}"

    response = _post_analyst_technique(
        client, "T1059", tactic="Execution"
    )

    assert response.status_code == 302

    with sqlite3.connect(database) as db:
        row = db.execute(
            """
            SELECT
                mitre_tactic,
                mitre_technique,
                auto_mitre_tactic,
                auto_mitre_technique,
                auto_mitre_rationale,
                auto_mitre_confidence
            FROM finding_intelligence
            WHERE finding_id = 1
            """
        ).fetchone()

    assert row == (
        "Execution",
        "T1059",
        "Credential Access",
        "T1110",
        "Automated brute-force evidence",
        "High",
    )
