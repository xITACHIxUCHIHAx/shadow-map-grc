import json
import sqlite3

from grc import automatic_risks
from grc.vulnerability_intelligence import (
    initialize_vulnerability_intelligence,
)


ASSET_KEY = "host:192.168.1.10"
TARGET = "192.168.1.10"
CVE_ID = "CVE-2026-12345"


def _create_database(tmp_path, monkeypatch):
    database = tmp_path / "cve-finding-sync.db"

    initialize_vulnerability_intelligence(database)

    monkeypatch.setattr(automatic_risks, "DATABASE_PATH", database)
    automatic_risks.initialize_automatic_risks()

    return database


def _add_exposure(database, status="Version Match", is_kev=0):
    now = "2026-11-14T10:00:00+00:00"

    evidence = {
        "target": TARGET,
        "product": "OpenSSH",
        "detected_version": "9.2",
        "service": "ssh",
        "port": 22,
        "protocol": "tcp",
        "source": "nmap",
        "limitations": ["Version correlation is not exploit confirmation."],
    }

    with sqlite3.connect(database) as db:
        db.execute("""
            INSERT INTO vulnerability_records (
                cve_id, source, description, severity,
                cvss_version, cvss_score, references_json,
                is_kev, kev_date_added, kev_due_date,
                kev_required_action, first_seen_at,
                last_seen_at, updated_at
            ) VALUES (?, 'NVD', 'Test vulnerability', 'High',
                      '3.1', 8.1, ?, ?, '2026-11-01', '',
                      '', ?, ?, ?)
        """, (
            CVE_ID,
            json.dumps(["https://example.com/advisory"]),
            is_kev,
            now,
            now,
            now,
        ))

        cursor = db.execute("""
            INSERT INTO asset_observations (
                asset_key, asset_type, target, source,
                product, version, service, port, protocol,
                observed_at, confidence, fingerprint, created_at
            ) VALUES (?, 'Host', ?, 'nmap', 'OpenSSH', '9.2',
                      'ssh', 22, 'tcp', ?, 'High', ?, ?)
        """, (
            ASSET_KEY,
            TARGET,
            now,
            f"test-{CVE_ID}-{status}",
            now,
        ))

        observation_id = cursor.lastrowid

        db.execute("""
            INSERT INTO vulnerability_exposures (
                cve_id, asset_key, observation_id,
                match_status, confidence, evidence_json,
                assessment_source, first_detected_at, last_checked_at
            ) VALUES (?, ?, ?, ?, 'High', ?, 'local-test', ?, ?)
        """, (
            CVE_ID,
            ASSET_KEY,
            observation_id,
            status,
            json.dumps(evidence),
            now,
            now,
        ))


def _findings(database):
    with sqlite3.connect(database) as db:
        return db.execute("""
            SELECT id, source, fingerprint, title, status,
                   suggested_severity, evidence
            FROM draft_findings
            WHERE source = 'local_cve_intelligence'
        """).fetchall()


def test_version_match_creates_potential_finding(tmp_path, monkeypatch):
    database = _create_database(tmp_path, monkeypatch)
    _add_exposure(database)

    counts = automatic_risks.sync_cve_exposures_to_findings(database)

    findings = _findings(database)

    assert counts["exposures_processed"] == 1
    assert counts["findings_created"] == 1
    assert counts["findings_synchronized"] == 1
    assert len(findings) == 1
    assert "Potential version match" in findings[0][3]
    assert findings[0][4] == "Draft"

    evidence = json.loads(findings[0][6])
    assert evidence["confirmation"] is False
    assert evidence["match_status"] == "Version Match"


def test_repeated_sync_updates_same_finding(tmp_path, monkeypatch):
    database = _create_database(tmp_path, monkeypatch)
    _add_exposure(database)

    first = automatic_risks.sync_cve_exposures_to_findings(database)
    second = automatic_risks.sync_cve_exposures_to_findings(database)

    findings = _findings(database)

    assert first["findings_created"] == 1
    assert second["findings_created"] == 0
    assert second["findings_updated"] == 1
    assert len(findings) == 1


def test_sync_preserves_finding_status_and_manual_intelligence(
    tmp_path, monkeypatch
):
    database = _create_database(tmp_path, monkeypatch)
    _add_exposure(database)

    automatic_risks.sync_cve_exposures_to_findings(database)

    with sqlite3.connect(database) as db:
        finding_id = db.execute("""
            SELECT id FROM draft_findings
            WHERE source = 'local_cve_intelligence'
        """).fetchone()[0]

        db.execute("""
            UPDATE draft_findings
            SET status = 'Approved'
            WHERE id = ?
        """, (finding_id,))

        db.execute("""
            UPDATE finding_intelligence
            SET cve_ids = 'CVE-MANUAL-123',
                owasp_category = 'Manual OWASP mapping',
                mitre_technique = 'T1190',
                mapping_rationale = 'Manually assessed',
                validation_status = 'Evidence-supported'
            WHERE finding_id = ?
        """, (finding_id,))

    automatic_risks.sync_cve_exposures_to_findings(database)

    with sqlite3.connect(database) as db:
        finding = db.execute("""
            SELECT status FROM draft_findings WHERE id = ?
        """, (finding_id,)).fetchone()

        intelligence = db.execute("""
            SELECT cve_ids, owasp_category, mitre_technique,
                   mapping_rationale, validation_status,
                   local_cve_ids, local_cve_match_status
            FROM finding_intelligence
            WHERE finding_id = ?
        """, (finding_id,)).fetchone()

    assert finding[0] == "Approved"
    assert intelligence[:5] == (
        "CVE-MANUAL-123",
        "Manual OWASP mapping",
        "T1190",
        "Manually assessed",
        "Evidence-supported",
    )
    assert intelligence[5] == CVE_ID  # local_cve_ids
    assert intelligence[6] == "Version Match"  # local_cve_match_status


def test_not_matched_does_not_create_new_finding(tmp_path, monkeypatch):
    database = _create_database(tmp_path, monkeypatch)
    _add_exposure(database, status="Not Matched")

    counts = automatic_risks.sync_cve_exposures_to_findings(database)

    assert counts["findings_created"] == 0
    assert counts["findings_synchronized"] == 0
    assert _findings(database) == []


def test_not_matched_updates_existing_historical_finding(
    tmp_path, monkeypatch
):
    database = _create_database(tmp_path, monkeypatch)
    _add_exposure(database)

    automatic_risks.sync_cve_exposures_to_findings(database)

    with sqlite3.connect(database) as db:
        finding_id = db.execute("""
            SELECT id FROM draft_findings
            WHERE source = 'local_cve_intelligence'
        """).fetchone()[0]

        db.execute("""
            UPDATE draft_findings
            SET status = 'Dismissed'
            WHERE id = ?
        """, (finding_id,))

        db.execute("""
            UPDATE vulnerability_exposures
            SET match_status = 'Not Matched'
            WHERE cve_id = ? AND asset_key = ?
        """, (CVE_ID, ASSET_KEY))

    counts = automatic_risks.sync_cve_exposures_to_findings(database)

    findings = _findings(database)

    assert counts["findings_created"] == 0
    assert counts["findings_updated"] == 1
    assert len(findings) == 1
    assert findings[0][0] == finding_id
    assert findings[0][4] == "Dismissed"
    assert "No current version match" in findings[0][3]

    with sqlite3.connect(database) as db:
        status = db.execute("""
            SELECT local_cve_match_status
            FROM finding_intelligence
            WHERE finding_id = ?
        """, (finding_id,)).fetchone()[0]

    assert status == "Not Matched"


def test_unassessed_exposure_creates_review_finding(
    tmp_path, monkeypatch
):
    database = _create_database(tmp_path, monkeypatch)
    _add_exposure(database, status="Unassessed")

    automatic_risks.sync_cve_exposures_to_findings(database)

    findings = _findings(database)

    assert len(findings) == 1
    assert findings[0][5] == "Review"
    assert "Unassessed software observation" in findings[0][3]


def test_kev_is_recorded_without_claiming_confirmation(
    tmp_path, monkeypatch
):
    database = _create_database(tmp_path, monkeypatch)
    _add_exposure(database, is_kev=1)

    automatic_risks.sync_cve_exposures_to_findings(database)

    findings = _findings(database)
    evidence = json.loads(findings[0][6])

    assert evidence["is_kev"] is True
    assert evidence["confirmation"] is False
    assert "KEV" in findings[0][3] or "KEV" in (
        automatic_risks.sync_cve_exposures_to_findings(database)
        and evidence.get("cve_description", "")
    ) or "Known Exploited Vulnerabilities" in _recommendation(
        database, findings[0][0]
    )


def _recommendation(database, finding_id):
    with sqlite3.connect(database) as db:
        return db.execute("""
            SELECT recommendation FROM draft_findings WHERE id = ?
        """, (finding_id,)).fetchone()[0]




def test_correlation_writer_does_not_clobber_auto_cve_ids(
    tmp_path, monkeypatch
):
    """Regression: sync_cve_exposures_to_findings must not overwrite auto_*.

    Before the Step 2 schema split, this writer wrote auto_cve_ids and
    auto_cve_match_status, so any prior NVD enrichment on the same row
    was silently overwritten. After the split, it writes local_* and
    leaves auto_* intact.
    """
    from grc import automatic_risks as risks

    database = _create_database(tmp_path, monkeypatch)
    _add_exposure(database)
    risks.sync_cve_exposures_to_findings(database)

    with sqlite3.connect(database) as db:
        finding_id = db.execute(
            "SELECT id FROM draft_findings "
            "WHERE source = 'local_cve_intelligence'"
        ).fetchone()[0]

        # Pre-seed auto_* as if a prior NVD enrichment had populated it.
        db.execute("""
            UPDATE finding_intelligence
            SET auto_cve_ids = 'CVE-2024-99999',
                auto_cve_match_status = 'Version Match'
            WHERE finding_id = ?
        """, (finding_id,))
        db.commit()

    # Re-run the correlation writer.
    risks.sync_cve_exposures_to_findings(database)

    with sqlite3.connect(database) as db:
        row = db.execute("""
            SELECT auto_cve_ids, auto_cve_match_status,
                   local_cve_ids, local_cve_match_status
            FROM finding_intelligence
            WHERE finding_id = ?
        """, (finding_id,)).fetchone()

    assert row is not None
    auto_cves, auto_status, local_cves, local_status = row

    # Local side was refreshed by this run.
    assert local_cves == CVE_ID
    assert local_status == "Version Match"

    # Auto side (NVD enrichment) is preserved untouched.
    assert auto_cves == "CVE-2024-99999"
    assert auto_status == "Version Match"
