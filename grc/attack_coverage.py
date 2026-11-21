"""Evidence-based MITRE ATT&CK coverage calculations and Navigator export."""

import re


TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _finding_value(finding, key, default=None):
    """Read a finding field safely from dicts and sqlite3.Row objects."""
    try:
        return finding[key]
    except (KeyError, IndexError, TypeError):
        return default


def _valid_catalogue_technique(technique_id, catalogue):
    """Return a valid, active catalogue technique or None."""
    if not TECHNIQUE_ID_PATTERN.fullmatch(technique_id):
        return None

    technique = catalogue.get(technique_id)

    if (
        technique is None
        or technique["deprecated"]
        or technique["revoked"]
    ):
        return None

    return technique


def _finding_details(finding, confidence, rationale):
    """Build consistent finding details for coverage rows."""
    return {
        "id": finding["id"],
        "target": finding["target"],
        "title": finding["title"],
        "severity": finding["suggested_severity"],
        "confidence": confidence,
        "rationale": rationale,
        "source_reference": finding["source_reference"],
        "suggested_severity": finding["suggested_severity"],
        "mapping_confidence": confidence,
        "mapping_rationale": rationale,
    }


def build_attack_coverage(
    findings,
    catalogue_techniques,
    catalogue_tactics,
    technique_tactics,
    version=None,
):
    """Calculate confirmed and automated-suggestion ATT&CK coverage."""
    total_findings = len(findings)

    technique_catalogue = {
        row["technique_id"]: dict(row)
        for row in catalogue_techniques
    }

    tactic_catalogue = {
        row["tactic_id"]: dict(row)
        for row in catalogue_tactics
    }

    relationships = {}
    for relation in technique_tactics:
        relationships.setdefault(
            relation["technique_id"], []
        ).append(relation["tactic_id"])

    # Analyst-confirmed mappings. This logic remains independent
    # from automated suggestions.
    mapped = {}
    invalid_supported_mappings = 0

    # Automated suggestions. These are never treated as confirmed.
    suggested = {}
    invalid_suggested_mappings = 0

    for finding in findings:
        # Confirmed coverage requires an evidence-supported analyst mapping.
        if finding["validation_status"] == "Evidence-supported":
            technique_id = (
                str(finding["mitre_technique"] or "").strip().upper()
            )

            if technique_id:
                technique = _valid_catalogue_technique(
                    technique_id, technique_catalogue
                )

                if technique is None:
                    invalid_supported_mappings += 1
                else:
                    mapped.setdefault(technique_id, []).append(
                        _finding_details(
                            finding,
                            finding["mapping_confidence"],
                            finding["mapping_rationale"],
                        )
                    )

        # Automated suggestions are counted separately, regardless
        # of validation_status. They are not analyst-confirmed mappings.
        suggested_id = (
            str(
                _finding_value(finding, "auto_mitre_technique", "") or ""
            ).strip().upper()
        )

        if suggested_id:
            technique = _valid_catalogue_technique(
                suggested_id, technique_catalogue
            )

            if technique is None:
                invalid_suggested_mappings += 1
            else:
                suggested.setdefault(suggested_id, []).append(
                    _finding_details(
                        finding,
                        _finding_value(
                            finding, "auto_mitre_confidence"
                        ),
                        _finding_value(
                            finding, "auto_mitre_rationale"
                        ),
                    )
                )

    def build_technique_rows(mapping):
        rows = []

        for technique_id, mapped_findings in sorted(mapping.items()):
            technique = technique_catalogue[technique_id]
            tactic_ids = relationships.get(technique_id, [])

            rows.append({
                "technique_id": technique_id,
                "name": technique["name"],
                "description": technique.get("description", "") or "",
                "is_subtechnique": bool(technique["is_subtechnique"]),
                "parent_technique_id": technique["parent_technique_id"],
                "url": technique["url"],
                "finding_count": len(mapped_findings),
                "tactics": [
                    tactic_catalogue[tactic_id]
                    for tactic_id in tactic_ids
                    if tactic_id in tactic_catalogue
                ],
                "findings": mapped_findings,
            })

        return rows

    # These rows remain confirmed-only for existing consumers and exports.
    technique_rows = build_technique_rows(mapped)

    # Automated candidates have their own independent rows.
    suggested_technique_rows = build_technique_rows(suggested)

    tactic_rows = []

    for tactic_id, tactic in sorted(
        tactic_catalogue.items(),
        key=lambda item: item[1]["name"].casefold(),
    ):
        confirmed_related = [
            row for row in technique_rows
            if any(
                mapped_tactic["tactic_id"] == tactic_id
                for mapped_tactic in row["tactics"]
            )
        ]

        suggested_related = [
            row for row in suggested_technique_rows
            if any(
                mapped_tactic["tactic_id"] == tactic_id
                for mapped_tactic in row["tactics"]
            )
        ]

        tactic_rows.append({
            **tactic,
            # Confirmed analyst coverage.
            "technique_count": len(confirmed_related),
            "finding_count": sum(
                row["finding_count"] for row in confirmed_related
            ),
            # Automated, unconfirmed suggestion coverage.
            "suggested_technique_count": len(suggested_related),
            "suggested_finding_count": sum(
                row["finding_count"] for row in suggested_related
            ),
        })

    supported_mappings = sum(
        row["finding_count"] for row in technique_rows
    )

    suggested_mappings = sum(
        row["finding_count"] for row in suggested_technique_rows
    )

    covered_finding_ids = {
        finding["id"]
        for findings_for_technique in mapped.values()
        for finding in findings_for_technique
    }

    uncovered_finding_rows = [
        {
            "id": finding["id"],
            "target": finding["target"],
            "title": finding["title"],
            "severity": finding["suggested_severity"],
            "validation_status": finding["validation_status"],
            "mitre_technique": finding["mitre_technique"],
        }
        for finding in findings
        if finding["id"] not in covered_finding_ids
    ]

    return {
        "version": version,
        "catalogue_available": bool(version),
        "total_findings": total_findings,

        # Confirmed coverage: analyst mappings only.
        "supported_mappings": supported_mappings,
        "unique_techniques": len(technique_rows),
        "invalid_supported_mappings": invalid_supported_mappings,
        "technique_rows": technique_rows,

        # Automated suggestions: separate and explicitly unconfirmed.
        "suggested_mappings": suggested_mappings,
        "suggested_unique_techniques": len(suggested_technique_rows),
        "invalid_suggested_mappings": invalid_suggested_mappings,
        "suggested_technique_rows": suggested_technique_rows,

        "uncovered_findings": max(
            0, total_findings - len(covered_finding_ids)
        ),
        "uncovered_finding_rows": uncovered_finding_rows,
        "tactic_rows": tactic_rows,
    }


def build_navigator_layer(coverage):
    """Build an ATT&CK Navigator layer from confirmed coverage only."""
    if not coverage["catalogue_available"]:
        raise ValueError(
            "Import an Enterprise ATT&CK catalogue before exporting."
        )

    techniques = []

    # Deliberately use confirmed technique_rows only.
    # Automated suggestions must never enter the Navigator export.
    for row in coverage["technique_rows"]:
        finding_ids = [
            str(finding["id"]) for finding in row["findings"]
        ]

        techniques.append({
            "techniqueID": row["technique_id"],
            "score": 100,
            "enabled": True,
            "showSubtechniques": True,
            "metadata": [],
            "comment": (
                "Evidence-supported analyst mappings. "
                f"Finding count: {row['finding_count']}. "
                f"Finding IDs: {', '.join(finding_ids)}."
            ),
        })

    return {
        "name": "Shadow Map GRC - Evidence-supported coverage",
        "versions": {
            "attack": coverage["version"],
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            "Only analyst mappings marked Evidence-supported and "
            "validated against the selected imported Enterprise ATT&CK "
            "catalogue are included. Automated suggestions are excluded. "
            "A score of 100 indicates that at least one qualifying finding "
            "maps to the technique; it is not a severity or risk score."
        ),
        "filters": {
            "platforms": [],
            "stages": [],
            "tactics": [],
            "assets": [],
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": False,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
            "expandedSubtechniques": "none",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }
