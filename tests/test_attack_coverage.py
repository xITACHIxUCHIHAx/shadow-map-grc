import json

import pytest

from grc.attack_coverage import (
    build_attack_coverage,
    build_navigator_layer,
)


def _technique(
    technique_id,
    name,
    *,
    subtechnique=False,
    parent=None,
    deprecated=0,
    revoked=0,
):
    return {
        "technique_id": technique_id,
        "name": name,
        "is_subtechnique": subtechnique,
        "parent_technique_id": parent,
        "url": f"https://attack.mitre.org/techniques/{technique_id}/",
        "deprecated": deprecated,
        "revoked": revoked,
    }


def _finding(
    finding_id,
    technique_id,
    *,
    status="Evidence-supported",
):
    return {
        "id": finding_id,
        "target": "192.168.1.10",
        "title": f"Finding {finding_id}",
        "suggested_severity": "High",
        "mitre_technique": technique_id,
        "validation_status": status,
        "mapping_confidence": "High",
        "mapping_rationale": "Supported by collected evidence.",
        "source_reference": "Evidence record 1",
    }


@pytest.fixture
def catalogue():
    techniques = [
        _technique("T1190", "Exploit Public-Facing Application"),
        _technique(
            "T1059.001",
            "PowerShell",
            subtechnique=True,
            parent="T1059",
        ),
        _technique("T1001", "Deprecated Technique", deprecated=1),
        _technique("T1002", "Revoked Technique", revoked=1),
    ]

    tactics = [
        {
            "tactic_id": "TA0001",
            "name": "Initial Access",
            "short_name": "initial-access",
        },
        {
            "tactic_id": "TA0002",
            "name": "Execution",
            "short_name": "execution",
        },
    ]

    relationships = [
        {"technique_id": "T1190", "tactic_id": "TA0001"},
        {"technique_id": "T1059.001", "tactic_id": "TA0002"},
    ]

    return techniques, tactics, relationships


def test_only_evidence_supported_analyst_mappings_count(catalogue):
    techniques, tactics, relationships = catalogue

    findings = [
        _finding(1, "T1190"),
        _finding(2, "T1059.001"),
        _finding(3, "T1190", status="Needs-validation"),
        _finding(4, "T1190", status="Unreviewed"),
        _finding(5, "T1190", status="Rejected"),
        _finding(6, ""),
    ]

    result = build_attack_coverage(
        findings,
        techniques,
        tactics,
        relationships,
        version="v1.0",
    )

    assert result["total_findings"] == 6
    assert result["supported_mappings"] == 2
    assert result["unique_techniques"] == 2
    assert result["uncovered_findings"] == 4
    assert result["invalid_supported_mappings"] == 0
    assert {
        row["id"] for row in result["uncovered_finding_rows"]
    } == {3, 4, 5, 6}


def test_automatic_suggestion_does_not_count_as_analyst_mapping(catalogue):
    techniques, tactics, relationships = catalogue
    finding = _finding(7, "")
    finding["auto_mitre_technique"] = "T1190"

    result = build_attack_coverage(
        [finding], techniques, tactics, relationships, version="v1.0"
    )

    assert result["supported_mappings"] == 0
    assert result["unique_techniques"] == 0
    assert result["uncovered_findings"] == 1
    assert result["invalid_supported_mappings"] == 0


def test_deprecated_revoked_missing_and_malformed_mappings_are_excluded(
    catalogue,
):
    techniques, tactics, relationships = catalogue

    findings = [
        _finding(1, "T1001"),
        _finding(2, "T1002"),
        _finding(3, "T9999"),
        _finding(4, "not-a-technique"),
        _finding(5, "T1190"),
    ]

    result = build_attack_coverage(
        findings,
        techniques,
        tactics,
        relationships,
        version="v1.0",
    )

    assert result["supported_mappings"] == 1
    assert result["invalid_supported_mappings"] == 4
    assert result["uncovered_findings"] == 4
    assert [row["technique_id"] for row in result["technique_rows"]] == [
        "T1190"
    ]


def test_subtechnique_and_tactic_relationship_are_preserved(catalogue):
    techniques, tactics, relationships = catalogue

    result = build_attack_coverage(
        [_finding(1, "T1059.001")],
        techniques,
        tactics,
        relationships,
        version="v1.0",
    )

    row = result["technique_rows"][0]

    assert row["technique_id"] == "T1059.001"
    assert row["is_subtechnique"] is True
    assert row["parent_technique_id"] == "T1059"
    assert [item["tactic_id"] for item in row["tactics"]] == ["TA0002"]

    execution = next(
        item for item in result["tactic_rows"]
        if item["tactic_id"] == "TA0002"
    )
    assert execution["technique_count"] == 1
    assert execution["finding_count"] == 1


def test_multiple_findings_are_grouped_under_one_technique(catalogue):
    techniques, tactics, relationships = catalogue

    result = build_attack_coverage(
        [
            _finding(1, "T1190"),
            _finding(2, "T1190"),
        ],
        techniques,
        tactics,
        relationships,
        version="v1.0",
    )

    assert result["supported_mappings"] == 2
    assert result["unique_techniques"] == 1
    assert result["technique_rows"][0]["finding_count"] == 2


def test_navigator_export_contains_only_confirmed_techniques(catalogue):
    techniques, tactics, relationships = catalogue

    coverage = build_attack_coverage(
        [
            _finding(1, "T1190"),
            _finding(2, "T1001"),
            _finding(3, "T1059.001", status="Needs-validation"),
        ],
        techniques,
        tactics,
        relationships,
        version="v1.0",
    )

    layer = build_navigator_layer(coverage)

    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["attack"] == "v1.0"
    assert len(layer["techniques"]) == 1
    assert sorted(t["techniqueID"] for t in layer["techniques"]) == [
        "T1190"
    ]
    assert layer["techniques"][0]["score"] == 100
    assert "not a severity or risk score" in layer["description"]

    # Confirm that the result is JSON-serializable.
    serialized = json.loads(json.dumps(layer))
    technique_ids = sorted(
        t["techniqueID"] for t in serialized["techniques"]
    )
    assert technique_ids == ["T1190"]


def test_navigator_export_requires_an_imported_catalogue():
    coverage = {
        "catalogue_available": False,
        "version": None,
        "technique_rows": [],
    }

    with pytest.raises(ValueError, match="Import an Enterprise ATT&CK"):
        build_navigator_layer(coverage)
