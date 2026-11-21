import sqlite3

import pytest

from grc.attack_catalogue import (
    initialize_attack_catalogue,
    import_attack_stix,
    import_attack_stix_file,
    load_attack_stix_file,
    parse_attack_stix,
)


def _connect(path):
    db = sqlite3.connect(path)
    db.execute("PRAGMA foreign_keys = ON")
    return db


def test_catalogue_initialization_is_idempotent(tmp_path):
    database = tmp_path / "attack.db"

    assert initialize_attack_catalogue(database) is True
    assert initialize_attack_catalogue(database) is True

    with _connect(database) as db:
        tables = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }

    assert {
        "attack_frameworks",
        "attack_tactics",
        "attack_techniques",
        "attack_technique_tactics",
    }.issubset(tables)


def test_framework_versions_are_stored_separately(tmp_path):
    database = tmp_path / "attack.db"
    initialize_attack_catalogue(database)

    with _connect(database) as db:
        db.executemany(
            """
            INSERT INTO attack_frameworks (
                framework_id, version, framework_name, domain, imported_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            [
                ("mitre-attack", "v1", "MITRE ATT&CK", "enterprise", "now"),
                ("mitre-attack", "v2", "MITRE ATT&CK", "enterprise", "now"),
            ],
        )

        versions = db.execute(
            """
            SELECT version FROM attack_frameworks
            WHERE framework_id = ?
            ORDER BY version
            """,
            ("mitre-attack",),
        ).fetchall()

    assert [row[0] for row in versions] == ["v1", "v2"]


def test_subtechnique_and_tactic_relationships(tmp_path):
    database = tmp_path / "attack.db"
    initialize_attack_catalogue(database)

    with _connect(database) as db:
        db.execute(
            """
            INSERT INTO attack_frameworks (
                framework_id, version, framework_name, domain, imported_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            ("mitre-attack", "v1", "MITRE ATT&CK", "enterprise", "now"),
        )

        db.execute(
            """
            INSERT INTO attack_tactics (
                framework_id, version, tactic_id, name, short_name
            ) VALUES (?, ?, ?, ?, ?)
            """,
            ("mitre-attack", "v1", "TA0001", "Initial Access", "initial-access"),
        )

        db.execute(
            """
            INSERT INTO attack_techniques (
                framework_id, version, technique_id, name
            ) VALUES (?, ?, ?, ?)
            """,
            ("mitre-attack", "v1", "T1059", "Command and Scripting Interpreter"),
        )

        db.execute(
            """
            INSERT INTO attack_techniques (
                framework_id, version, technique_id, name,
                is_subtechnique, parent_technique_id
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "mitre-attack", "v1", "T1059.001",
                "PowerShell", 1, "T1059",
            ),
        )

        db.execute(
            """
            INSERT INTO attack_technique_tactics (
                framework_id, version, technique_id, tactic_id
            ) VALUES (?, ?, ?, ?)
            """,
            ("mitre-attack", "v1", "T1059.001", "TA0001"),
        )

        child = db.execute(
            """
            SELECT is_subtechnique, parent_technique_id
            FROM attack_techniques
            WHERE technique_id = ?
            """,
            ("T1059.001",),
        ).fetchone()

        relation = db.execute(
            """
            SELECT tactic_id FROM attack_technique_tactics
            WHERE technique_id = ?
            """,
            ("T1059.001",),
        ).fetchone()

    assert child == (1, "T1059")
    assert relation == ("TA0001",)


def test_catalogue_rejects_orphan_relationships(tmp_path):
    database = tmp_path / "attack.db"
    initialize_attack_catalogue(database)

    with _connect(database) as db:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                """
                INSERT INTO attack_technique_tactics (
                    framework_id, version, technique_id, tactic_id
                ) VALUES (?, ?, ?, ?)
                """,
                ("missing-framework", "v1", "T1190", "TA0001"),
            )


def test_framework_delete_cascades_catalogue_records(tmp_path):
    database = tmp_path / "attack.db"
    initialize_attack_catalogue(database)

    with _connect(database) as db:
        db.execute(
            """
            INSERT INTO attack_frameworks (
                framework_id, version, framework_name, domain, imported_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            ("mitre-attack", "v1", "MITRE ATT&CK", "enterprise", "now"),
        )

        db.execute(
            """
            INSERT INTO attack_tactics (
                framework_id, version, tactic_id, name, short_name
            ) VALUES (?, ?, ?, ?, ?)
            """,
            ("mitre-attack", "v1", "TA0001", "Initial Access", "initial-access"),
        )

        db.execute(
            """
            INSERT INTO attack_techniques (
                framework_id, version, technique_id, name
            ) VALUES (?, ?, ?, ?)
            """,
            ("mitre-attack", "v1", "T1190", "Exploit Public-Facing Application"),
        )

        db.execute(
            """
            INSERT INTO attack_technique_tactics (
                framework_id, version, technique_id, tactic_id
            ) VALUES (?, ?, ?, ?)
            """,
            ("mitre-attack", "v1", "T1190", "TA0001"),
        )

        db.execute(
            "DELETE FROM attack_frameworks WHERE framework_id=? AND version=?",
            ("mitre-attack", "v1"),
        )

        remaining = db.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM attack_tactics),
                (SELECT COUNT(*) FROM attack_techniques),
                (SELECT COUNT(*) FROM attack_technique_tactics)
            """
        ).fetchone()

    assert remaining == (0, 0, 0)


def test_framework_delete_cascades_parent_and_subtechnique(tmp_path):
    database = tmp_path / "attack.db"
    initialize_attack_catalogue(database)

    with _connect(database) as db:
        db.execute(
            """
            INSERT INTO attack_frameworks (
                framework_id, version, framework_name, domain, imported_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            ("mitre-attack", "v1", "MITRE ATT&CK", "enterprise", "now"),
        )

        db.executemany(
            """
            INSERT INTO attack_techniques (
                framework_id, version, technique_id, name,
                is_subtechnique, parent_technique_id
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "mitre-attack", "v1", "T1059",
                    "Command and Scripting Interpreter", 0, None,
                ),
                (
                    "mitre-attack", "v1", "T1059.001",
                    "PowerShell", 1, "T1059",
                ),
            ],
        )

        db.execute(
            """
            DELETE FROM attack_frameworks
            WHERE framework_id = ? AND version = ?
            """,
            ("mitre-attack", "v1"),
        )

        remaining = db.execute(
            "SELECT COUNT(*) FROM attack_techniques"
        ).fetchone()[0]

    assert remaining == 0


def _stix_test_object(
    object_type,
    object_id,
    name,
    external_id,
    **extra,
):
    return {
        "type": object_type,
        "id": object_id,
        "name": name,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": external_id,
                "url": f"https://attack.mitre.org/{external_id}/",
            }
        ],
        **extra,
    }


def test_parse_attack_stix_extracts_enterprise_catalogue():
    tactic = _stix_test_object(
        "x-mitre-tactic",
        "x-mitre-tactic--0001",
        "Execution",
        "TA0002",
        x_mitre_shortname="execution",
        description="Execution tactic.",
    )

    parent = _stix_test_object(
        "attack-pattern",
        "attack-pattern--0001",
        "Command and Scripting Interpreter",
        "T1059",
        x_mitre_domains=["enterprise-attack"],
        x_mitre_is_subtechnique=False,
        kill_chain_phases=[
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "execution",
            }
        ],
    )

    child = _stix_test_object(
        "attack-pattern",
        "attack-pattern--0002",
        "PowerShell",
        "T1059.001",
        x_mitre_domains=["enterprise-attack"],
        x_mitre_is_subtechnique=True,
        x_mitre_deprecated=True,
        revoked=True,
        kill_chain_phases=[
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "execution",
            }
        ],
    )

    result = parse_attack_stix(
        {"type": "bundle", "objects": [tactic, parent, child]}
    )

    assert len(result["tactics"]) == 1
    assert result["tactics"][0]["tactic_id"] == "TA0002"

    techniques = {
        item["technique_id"]: item
        for item in result["techniques"]
    }

    assert techniques["T1059"]["is_subtechnique"] == 0
    assert techniques["T1059"]["parent_technique_id"] is None

    assert techniques["T1059.001"]["is_subtechnique"] == 1
    assert techniques["T1059.001"]["parent_technique_id"] == "T1059"
    assert techniques["T1059.001"]["deprecated"] == 1
    assert techniques["T1059.001"]["revoked"] == 1

    assert result["relationships"] == [
        ("T1059", "TA0002"),
        ("T1059.001", "TA0002"),
    ]


def test_parse_attack_stix_rejects_missing_parent():
    child = _stix_test_object(
        "attack-pattern",
        "attack-pattern--0002",
        "PowerShell",
        "T1059.001",
        x_mitre_domains=["enterprise-attack"],
        x_mitre_is_subtechnique=True,
    )

    with pytest.raises(ValueError, match="Missing parent technique"):
        parse_attack_stix({"type": "bundle", "objects": [child]})


def test_parse_attack_stix_rejects_non_bundle():
    with pytest.raises(ValueError, match="must be a bundle"):
        parse_attack_stix({"type": "indicator", "objects": []})


def test_parse_attack_stix_excludes_non_enterprise_techniques():
    mobile = _stix_test_object(
        "attack-pattern",
        "attack-pattern--0003",
        "Mobile Technique",
        "T1234",
        x_mitre_domains=["mobile-attack"],
    )

    result = parse_attack_stix(
        {"type": "bundle", "objects": [mobile]}
    )

    assert result["techniques"] == []
    assert result["relationships"] == []


def test_parse_attack_stix_rejects_duplicate_technique_ids():
    first = _stix_test_object(
        "attack-pattern",
        "attack-pattern--0001",
        "Technique One",
        "T1059",
        x_mitre_domains=["enterprise-attack"],
    )
    second = _stix_test_object(
        "attack-pattern",
        "attack-pattern--0002",
        "Technique Two",
        "T1059",
        x_mitre_domains=["enterprise-attack"],
    )

    with pytest.raises(ValueError, match="Duplicate technique ID"):
        parse_attack_stix(
            {"type": "bundle", "objects": [first, second]}
        )


def _import_test_bundle():
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--00000000-0000-4000-8000-000000000001",
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
                "id": "attack-pattern--00000000-0000-4000-8000-000000000001",
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
            {
                "type": "attack-pattern",
                "id": "attack-pattern--00000000-0000-4000-8000-000000000002",
                "name": "PowerShell",
                "description": "Use PowerShell.",
                "x_mitre_domains": ["enterprise-attack"],
                "x_mitre_is_subtechnique": True,
                "x_mitre_deprecated": True,
                "x_mitre_revoked": False,
                "kill_chain_phases": [{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "execution",
                }],
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": "T1059.001",
                    "url": "https://attack.mitre.org/techniques/T1059/001/",
                }],
            },
        ],
    }


def test_import_attack_stix_persists_catalogue(tmp_path):
    database = tmp_path / "attack.db"

    result = import_attack_stix(
        _import_test_bundle(),
        "test-v1",
        database_path=database,
        release_date="2026-11-12",
        source_reference="local test fixture",
    )

    assert result == {
        "framework_id": "mitre-attack",
        "version": "test-v1",
        "domain": "enterprise-attack",
        "tactics_imported": 1,
        "techniques_imported": 2,
        "relationships_imported": 2,
        "status": "success",
    }

    with _connect(database) as db:
        framework = db.execute(
            """
            SELECT framework_name, domain, release_date, source_reference
            FROM attack_frameworks
            WHERE framework_id = ? AND version = ?
            """,
            ("mitre-attack", "test-v1"),
        ).fetchone()

        child = db.execute(
            """
            SELECT is_subtechnique, parent_technique_id, deprecated, revoked
            FROM attack_techniques
            WHERE framework_id = ? AND version = ? AND technique_id = ?
            """,
            ("mitre-attack", "test-v1", "T1059.001"),
        ).fetchone()

        relationships = db.execute(
            """
            SELECT COUNT(*) FROM attack_technique_tactics
            WHERE framework_id = ? AND version = ?
            """,
            ("mitre-attack", "test-v1"),
        ).fetchone()[0]

    assert framework == (
        "MITRE ATT&CK",
        "enterprise-attack",
        "2026-11-12",
        "local test fixture",
    )
    assert child == (1, "T1059", 1, 0)
    assert relationships == 2


def test_import_attack_stix_rejects_duplicate_version(tmp_path):
    database = tmp_path / "attack.db"
    bundle = _import_test_bundle()

    import_attack_stix(
        bundle, "test-v1", database_path=database
    )

    with pytest.raises(ValueError, match="already imported"):
        import_attack_stix(
            bundle, "test-v1", database_path=database
        )

    with _connect(database) as db:
        count = db.execute(
            """
            SELECT COUNT(*) FROM attack_frameworks
            WHERE framework_id = ? AND version = ?
            """,
            ("mitre-attack", "test-v1"),
        ).fetchone()[0]

    assert count == 1


def test_import_attack_stix_rolls_back_failed_import(tmp_path):
    database = tmp_path / "attack.db"
    initialize_attack_catalogue(database)

    # Force a SQLite failure after framework and tactic insertion.
    with _connect(database) as db:
        db.execute("""
            CREATE TRIGGER reject_attack_technique
            BEFORE INSERT ON attack_techniques
            BEGIN
                SELECT RAISE(ABORT, 'simulated import failure');
            END
        """)

    with pytest.raises(sqlite3.IntegrityError, match="simulated import failure"):
        import_attack_stix(
            _import_test_bundle(),
            "test-failure",
            database_path=database,
        )

    with _connect(database) as db:
        counts = db.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM attack_frameworks),
                (SELECT COUNT(*) FROM attack_tactics),
                (SELECT COUNT(*) FROM attack_techniques),
                (SELECT COUNT(*) FROM attack_technique_tactics)
            """
        ).fetchone()

    assert counts == (0, 0, 0, 0)


def test_import_attack_stix_requires_explicit_version(tmp_path):
    with pytest.raises(ValueError, match="version is required"):
        import_attack_stix(
            _import_test_bundle(),
            "",
            database_path=tmp_path / "attack.db",
        )


def test_load_attack_stix_file_validates_local_json(tmp_path):
    import json

    stix_file = tmp_path / "enterprise-attack.json"
    bundle = _import_test_bundle()
    stix_file.write_text(json.dumps(bundle), encoding="utf-8")

    loaded = load_attack_stix_file(stix_file)

    assert loaded["type"] == "bundle"
    assert len(loaded["objects"]) == 3


def test_load_attack_stix_file_rejects_malformed_json(tmp_path):
    stix_file = tmp_path / "malformed.json"
    stix_file.write_text('{"type": "bundle",', encoding="utf-8")

    with pytest.raises(ValueError, match="Unable to read valid STIX JSON"):
        load_attack_stix_file(stix_file)


def test_load_attack_stix_file_rejects_missing_file(tmp_path):
    with pytest.raises(ValueError, match="Unable to read valid STIX JSON"):
        load_attack_stix_file(tmp_path / "missing.json")


def test_load_attack_stix_file_rejects_oversized_file(
    tmp_path, monkeypatch
):
    import grc.attack_catalogue as catalogue

    stix_file = tmp_path / "large.json"
    stix_file.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(catalogue, "MAX_STIX_FILE_BYTES", 1)

    with pytest.raises(ValueError, match="100 MB size limit"):
        load_attack_stix_file(stix_file)


def test_import_attack_stix_file_imports_local_release(tmp_path):
    import json

    stix_file = tmp_path / "enterprise-attack.json"
    database = tmp_path / "attack.db"

    stix_file.write_text(
        json.dumps(_import_test_bundle()),
        encoding="utf-8",
    )

    result = import_attack_stix_file(
        stix_file,
        "local-v1",
        database_path=database,
        source_reference="local test fixture",
    )

    assert result["status"] == "success"
    assert result["version"] == "local-v1"



def test_parse_attack_stix_rejects_malformed_mitre_external_id():
    technique = _stix_test_object(
        "attack-pattern",
        "attack-pattern--invalid-id",
        "Malformed Technique",
        "T1059.0001",
        x_mitre_domains=["enterprise-attack"],
    )

    with pytest.raises(ValueError, match="invalid MITRE ATT&CK external ID"):
        parse_attack_stix({"type": "bundle", "objects": [technique]})


def test_parse_attack_stix_rejects_invalid_domain_metadata():
    technique = _stix_test_object(
        "attack-pattern",
        "attack-pattern--invalid-domain",
        "Malformed Domain",
        "T1059",
        x_mitre_domains="enterprise-attack",
    )

    with pytest.raises(ValueError, match="x_mitre_domains"):
        parse_attack_stix({"type": "bundle", "objects": [technique]})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("x_mitre_is_subtechnique", "false"),
        ("x_mitre_deprecated", "false"),
        ("revoked", "false"),
    ],
)
def test_parse_attack_stix_rejects_non_boolean_flags(field, value):
    technique = _stix_test_object(
        "attack-pattern",
        f"attack-pattern--invalid-{field}",
        "Invalid Boolean Flag",
        "T1059",
        x_mitre_domains=["enterprise-attack"],
        x_mitre_is_subtechnique=False,
    )
    technique[field] = value

    with pytest.raises(ValueError, match="must be a boolean"):
        parse_attack_stix({"type": "bundle", "objects": [technique]})


def test_parse_attack_stix_rejects_duplicate_tactic_short_names():
    first = _stix_test_object(
        "x-mitre-tactic",
        "x-mitre-tactic--0001",
        "Execution",
        "TA0002",
        x_mitre_shortname="execution",
    )
    second = _stix_test_object(
        "x-mitre-tactic",
        "x-mitre-tactic--0002",
        "Other Execution",
        "TA0003",
        x_mitre_shortname="execution",
    )

    with pytest.raises(ValueError, match="Duplicate tactic short name"):
        parse_attack_stix({"type": "bundle", "objects": [first, second]})


def test_parse_attack_stix_rejects_unknown_kill_chain_tactic():
    technique = _stix_test_object(
        "attack-pattern",
        "attack-pattern--unknown-tactic",
        "Technique With Unknown Tactic",
        "T1059",
        x_mitre_domains=["enterprise-attack"],
        kill_chain_phases=[
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": "not-a-known-tactic",
            }
        ],
    )

    with pytest.raises(ValueError, match="unknown ATT&CK tactic"):
        parse_attack_stix({"type": "bundle", "objects": [technique]})
