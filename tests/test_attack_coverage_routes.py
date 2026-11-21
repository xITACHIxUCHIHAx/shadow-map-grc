import sqlite3

import app as app_module
from grc import automatic_risks as risks
from grc.attack_catalogue import initialize_attack_catalogue


def setup_attack_test_app(monkeypatch, tmp_path, with_catalogue=False):
    database = tmp_path / "attack-coverage-route-test.db"

    monkeypatch.setattr(app_module, "DATABASE_PATH", database)
    monkeypatch.setattr(risks, "DATABASE_PATH", database)

    app_module.app.config.update(TESTING=True)
    app_module.init_db()
    risks.initialize_automatic_risks()
    initialize_attack_catalogue(database)

    with sqlite3.connect(database) as db:
        db.execute("""
            INSERT INTO draft_findings (
                id, source, fingerprint, target, title, description,
                evidence, suggested_severity, confidence, recommendation,
                iso_controls, status, created_at, updated_at
            ) VALUES
                (1, 'nmap', 'attack-one', '192.0.2.10',
                 'SSH service exposed', 'SSH service detected',
                 'TCP port 22 open', 'High', 'High',
                 'Restrict SSH access', 'A.8.20', 'Draft',
                 '2026-11-15', '2026-11-15'),
                (2, 'web', 'attack-two', '192.0.2.20',
                 'Missing security header', 'CSP header missing',
                 'Content-Security-Policy absent', 'Medium', 'Medium',
                 'Configure CSP', 'A.8.26', 'Draft',
                 '2026-11-15', '2026-11-15')
        """)

        db.execute("""
            INSERT INTO finding_intelligence (
                finding_id, mitre_tactic, mitre_technique,
                mapping_rationale, mapping_confidence,
                validation_status, source_reference, updated_at
            ) VALUES (
                1, 'Initial Access', 'T1190',
                'Analyst-confirmed evidence supports exploitation of a public-facing application.',
                'High', 'Evidence-supported',
                'https://attack.mitre.org/techniques/T1190/',
                '2026-11-15'
            )
        """)

        if with_catalogue:
            db.execute("""
                INSERT INTO attack_frameworks (
                    framework_id, version, framework_name,
                    domain, imported_at
                ) VALUES (
                    'mitre-attack', 'v1.0',
                    'MITRE ATT&CK Enterprise', 'enterprise-attack',
                    '2026-11-15'
                )
            """)

            db.execute("""
                INSERT INTO attack_tactics (
                    framework_id, version, tactic_id,
                    name, short_name, description, url
                ) VALUES (
                    'mitre-attack', 'v1.0', 'TA0001',
                    'Initial Access', 'initial-access', '',
                    'https://attack.mitre.org/tactics/TA0001/'
                )
            """)

            db.execute("""
                INSERT INTO attack_techniques (
                    framework_id, version, technique_id,
                    name, description, url
                ) VALUES (
                    'mitre-attack', 'v1.0', 'T1190',
                    'Exploit Public-Facing Application', '',
                    'https://attack.mitre.org/techniques/T1190/'
                )
            """)

            db.execute("""
                INSERT INTO attack_technique_tactics (
                    framework_id, version, technique_id, tactic_id
                ) VALUES (
                    'mitre-attack', 'v1.0', 'T1190', 'TA0001'
                )
            """)

        db.commit()

    return app_module.app.test_client(), database


def test_attack_coverage_dashboard_loads_without_catalogue(
    monkeypatch, tmp_path
):
    client, _ = setup_attack_test_app(monkeypatch, tmp_path)

    response = client.get("/attack-coverage")

    assert response.status_code == 200
    assert b"MITRE ATT&CK" in response.data
    assert b"catalogue" in response.data.lower()
    assert b"Confirmed technique coverage" in response.data
    assert b"Uncovered findings" not in response.data
    assert b"SSH service exposed" not in response.data
    assert b"Missing security header" not in response.data


def test_attack_coverage_dashboard_loads_with_catalogue(
    monkeypatch, tmp_path
):
    client, _ = setup_attack_test_app(
        monkeypatch, tmp_path, with_catalogue=True
    )

    response = client.get("/attack-coverage")

    assert response.status_code == 200
    assert b"Exploit Public-Facing Application" in response.data
    assert b"Initial Access" in response.data
    assert b"SSH service exposed" in response.data
    assert b"Missing security header" not in response.data
    assert b"Uncovered findings" not in response.data


def test_navigator_export_contains_only_confirmed_techniques(
    monkeypatch, tmp_path
):
    client, _ = setup_attack_test_app(
        monkeypatch, tmp_path, with_catalogue=True
    )

    response = client.get("/attack-coverage/export.navigator.json")

    assert response.status_code == 200
    assert response.mimetype == "application/json"

    layer = response.get_json()

    assert layer["domain"] == "enterprise-attack"
    assert [item["techniqueID"] for item in layer["techniques"]] == [
        "T1190"
    ]


def test_navigator_export_returns_404_without_catalogue(
    monkeypatch, tmp_path
):
    client, _ = setup_attack_test_app(monkeypatch, tmp_path)

    response = client.get("/attack-coverage/export.navigator.json")

    assert response.status_code == 404

def test_attack_coverage_dashboard_shows_sync_and_manual_import(
    monkeypatch, tmp_path
):
    client, _ = setup_attack_test_app(monkeypatch, tmp_path)

    response = client.get("/attack-coverage")

    assert response.status_code == 200
    assert b"MITRE ATT&amp;CK catalogue synchronization" in response.data or (
        b"MITRE ATT&CK catalogue synchronization" in response.data
    )
    assert b"Check for updates" in response.data
    assert b"Manual STIX JSON import" in response.data
    assert b"stix_file" in response.data


def test_attack_coverage_sync_queues_update_with_valid_csrf(
    monkeypatch, tmp_path
):
    client, _ = setup_attack_test_app(monkeypatch, tmp_path)
    called = []
    monkeypatch.setattr(
        risks, "request_attack_update", lambda: called.append(True) or True
    )

    client.get("/attack-coverage")

    with client.session_transaction() as session:
        token = session["attack_import_csrf_token"]

    response = client.post(
        "/attack-coverage/sync",
        data={"csrf_token": token},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/attack-coverage")
    assert called == [True]

    response = client.get("/attack-coverage")
    assert b"An immediate MITRE ATT&amp;CK update check has been queued." in (
        response.data
    ) or b"An immediate MITRE ATT&CK update check has been queued." in (
        response.data
    )


def test_attack_coverage_sync_rejects_invalid_csrf(
    monkeypatch, tmp_path
):
    client, _ = setup_attack_test_app(monkeypatch, tmp_path)
    called = []
    monkeypatch.setattr(
        risks, "request_attack_update", lambda: called.append(True) or True
    )

    response = client.post(
        "/attack-coverage/sync",
        data={"csrf_token": "invalid-token"},
    )

    assert response.status_code == 400
    assert called == []


def test_attack_coverage_sync_reports_stopped_updater(
    monkeypatch, tmp_path
):
    client, _ = setup_attack_test_app(monkeypatch, tmp_path)
    monkeypatch.setattr(risks, "request_attack_update", lambda: False)

    client.get("/attack-coverage")

    with client.session_transaction() as session:
        token = session["attack_import_csrf_token"]

    response = client.post(
        "/attack-coverage/sync",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert (
        b"The automatic ATT&amp;CK updater is not running." in response.data
        or b"The automatic ATT&CK updater is not running." in response.data
    )



def test_attack_coverage_shows_recent_global_scan_ids(
    monkeypatch, tmp_path
):
    from grc.scan_registry import register_scan

    client, database = setup_attack_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        scan_id = register_scan(
            db,
            "Nmap",
            "nmap_scans",
            1,
            "192.168.1.10",
            "Completed",
            "2026-11-05T10:00:00+00:00",
            "2026-11-05T10:01:00+00:00",
            60,
        )
        db.commit()

    response = client.get("/attack-coverage")

    assert response.status_code == 200
    assert scan_id == "SCN-00001"
    assert b"SCN-00001" in response.data
    assert b"TGT-00001" in response.data
    assert b"192.168.1.10" in response.data
    assert b"/attack-coverage/report/SCN-00001" in response.data
    assert b"View All Scans" in response.data


def test_attack_target_report_shows_only_mapped_findings_for_exact_target(
    monkeypatch, tmp_path
):
    from grc.scan_registry import register_scan

    client, database = setup_attack_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        scan_id = register_scan(
            db,
            "Nmap",
            "nmap_scans",
            1,
            "192.0.2.10",
            "Completed",
            "2026-11-15T10:00:00+00:00",
            "2026-11-15T10:01:00+00:00",
            60,
        )
        db.commit()

    response = client.get(f"/attack-coverage/report/{scan_id}")

    assert response.status_code == 200
    assert b"SCN-00001" in response.data
    assert b"192.0.2.10" in response.data
    assert b"SSH service exposed" in response.data
    assert b"T1190" in response.data
    assert b"Initial Access" in response.data
    assert b"Evidence-supported" in response.data
    assert b"Missing security header" not in response.data
    assert b"192.0.2.20" not in response.data


def test_attack_target_report_returns_404_for_unknown_scan(
    monkeypatch, tmp_path
):
    client, _ = setup_attack_test_app(monkeypatch, tmp_path)

    response = client.get("/attack-coverage/report/SCN-99999")

    assert response.status_code == 404


def test_attack_target_report_separates_automated_and_analyst_mappings(
    monkeypatch, tmp_path
):
    from grc.scan_registry import register_scan

    client, database = setup_attack_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        db.execute("""
            UPDATE draft_findings
            SET target = '192.0.2.10'
            WHERE id = 2
        """)

        db.execute("""
            INSERT INTO finding_intelligence (
                finding_id, auto_mitre_tactic, auto_mitre_technique,
                auto_mitre_rationale, auto_mitre_confidence, updated_at
            ) VALUES (
                2, 'Discovery', 'T1046',
                'Automated service discovery suggestion.',
                'Medium', '2026-11-15'
            )
        """)

        scan_id = register_scan(
            db,
            "Nmap",
            "nmap_scans",
            1,
            "192.0.2.10",
            "Completed",
            "2026-11-15T10:00:00+00:00",
            "2026-11-15T10:01:00+00:00",
            60,
        )
        db.commit()

    response = client.get(f"/attack-coverage/report/{scan_id}")

    assert response.status_code == 200
    assert b"SSH service exposed" in response.data
    assert b"Initial Access" in response.data
    assert b"T1190" in response.data
    assert b"Missing security header" in response.data
    assert b"Discovery" in response.data
    assert b"T1046" in response.data
    assert b"Automated service discovery suggestion." in response.data
