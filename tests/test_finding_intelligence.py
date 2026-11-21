from unittest.mock import Mock, patch

from grc.automatic_risks import _nvd_candidates, _suggest_owasp


def test_owasp_suggestion_is_limited_to_recognized_evidence_terms():
    assert _suggest_owasp(
        "Review missing Content-Security-Policy header", "", ""
    ) == "A05:2021 – Security Misconfiguration"
    assert _suggest_owasp("Open TCP port 443", "Service exposure", "") == ""


def test_nvd_keyword_results_are_candidates_with_valid_cve_ids_only():
    response = Mock()
    response.json.return_value = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2024-12345"}},
            {"cve": {"id": "NOT-A-CVE"}},
        ]
    }
    response.raise_for_status.return_value = None
    with patch("grc.automatic_risks.requests.get", return_value=response) as get:
        result = _nvd_candidates("Example Server", "2.4.1")
    assert result == ["CVE-2024-12345"]
    assert get.call_args.kwargs["params"]["keywordSearch"] == "Example Server 2.4.1"
    assert get.call_args.kwargs["timeout"] == (4, 12)


def test_nvd_lookup_skips_missing_product_or_version():
    with patch("grc.automatic_risks.requests.get") as get:
        assert _nvd_candidates("Example Server", "") == []
        get.assert_not_called()


def test_host_filter_uses_grouped_targets_and_full_text_search_includes_target():
    from grc.automatic_risks import _intelligence_query
    with patch("grc.automatic_risks.connect_db") as connect:
        db = Mock()
        db.execute.return_value.fetchall.return_value = []
        connect.return_value.__enter__.return_value = db
        _intelligence_query({"host": "192.0.2.10", "q": "192.0.2"})
    sql, params = db.execute.call_args.args
    assert "LOWER(TRIM(f.target)) IN (?)" in sql
    assert "f.target LIKE ?" in sql
    assert "192.0.2.10" in params


def test_mitre_technique_id_validation_accepts_enterprise_and_subtechnique_ids():
    import re
    pattern = r"T\d{4}(?:\.\d{3})?"
    assert re.fullmatch(pattern, "T1190")
    assert re.fullmatch(pattern, "T1059.001")
    assert not re.fullmatch(pattern, "T119")


def test_mitre_suggestion_requires_explicit_behavior_evidence():
    from grc.automatic_risks import _suggest_mitre

    brute_force = _suggest_mitre(
        "Repeated failed login attempts", "", ""
    )
    assert brute_force["technique"] == "T1110"
    assert brute_force["tactic"] == "Credential Access"

    shell = _suggest_mitre(
        "Confirmed shell command execution", "", ""
    )
    assert shell["technique"] == "T1059.004"

    exploitation = _suggest_mitre(
        "Successful exploitation observed", "", ""
    )
    assert exploitation["technique"] == "T1190"


def test_mitre_maps_open_ports_and_missing_headers_automatically():
    from grc.automatic_risks import _suggest_mitre, _suggest_general_category

    # Now expects auto-mapping based on indicators
    open_port = _suggest_mitre("Open TCP port 443", "HTTPS service detected", "port 443 open")
    assert open_port["technique"] == "T1046"

    missing_headers = _suggest_mitre(
        "Missing Content-Security-Policy header", "", ""
    )
    assert missing_headers["technique"] == "T1189"

    assert _suggest_general_category(
        "Open TCP port 443", "Service exposure", ""
    ) == "Exposed Network Service"


def test_potential_injection_is_mapped_to_t1190():
    from grc.automatic_risks import _suggest_mitre, _suggest_general_category

    mitre = _suggest_mitre(
        "Potential SQL injection vulnerability", "Input may be injectable", ""
    )
    # Now auto-maps SQLi to Exploit Public-Facing Application
    assert mitre["technique"] == "T1190"

    assert _suggest_general_category(
        "Potential SQL injection vulnerability", "Input may be injectable", ""
    ) == "Potential Injection Vulnerability"


def test_ordinary_nmap_service_discovery_is_mapped_automatically():
    from grc.automatic_risks import _suggest_mitre

    result = _suggest_mitre(
        "Nmap service discovery",
        "Detected OpenSSH service and version",
        "port=22 service=ssh product=OpenSSH",
        "nmap",
    )
    # Maps to Remote Services (T1021) because of "ssh"
    assert result["technique"] == "T1021"
    assert result["confidence"] == "Low"


def test_host_register_groups_url_paths_and_aggregates_findings():
    import sqlite3
    from unittest.mock import patch
    from grc import automatic_risks as risks

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row

    db.executescript("""
        CREATE TABLE draft_findings (
            id INTEGER PRIMARY KEY,
            source TEXT NOT NULL,
            source_record_id INTEGER,
            fingerprint TEXT NOT NULL UNIQUE,
            target TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '',
            suggested_severity TEXT NOT NULL DEFAULT 'Review',
            confidence TEXT NOT NULL DEFAULT 'Low',
            recommendation TEXT NOT NULL DEFAULT '',
            iso_controls TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Draft',
            risk_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE finding_intelligence (
            finding_id INTEGER PRIMARY KEY,
            cve_ids TEXT DEFAULT '',
            owasp_category TEXT DEFAULT '',
            mitre_tactic TEXT DEFAULT '',
            mitre_technique TEXT DEFAULT '',
            validation_status TEXT DEFAULT 'Unreviewed',
            auto_cve_ids TEXT DEFAULT '',
            local_cve_ids TEXT DEFAULT '',
            auto_owasp_category TEXT DEFAULT '',
            auto_mitre_tactic TEXT DEFAULT '',
            auto_mitre_technique TEXT DEFAULT '',
            auto_security_category TEXT DEFAULT ''
        );
    """)

    findings = [
        (1, "nmap", "https://example.com", "Open port", "High"),
        (2, "web", "https://example.com/login", "Missing header", "Medium"),
        (3, "web", "https://example.com/admin", "Potential SQL injection", "Review"),
        (4, "nmap", "192.0.2.10", "SSH service", "Low"),
    ]

    for finding_id, source, target, title, severity in findings:
        db.execute("""
            INSERT INTO draft_findings (
                id, source, fingerprint, target, title, description,
                suggested_severity, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'now', 'now')
        """, (
            finding_id, source, f"fingerprint-{finding_id}",
            target, title, title, severity
        ))

    db.execute("""
        INSERT INTO finding_intelligence (
            finding_id, validation_status, auto_cve_ids,
            auto_mitre_technique, auto_security_category
        ) VALUES (1, 'Evidence-supported', 'CVE-2024-12345',
                  'T1190', 'Vulnerable Component')
    """)
    db.execute("""
        INSERT INTO finding_intelligence (
            finding_id, validation_status, auto_security_category
        ) VALUES (2, 'Needs-validation', 'Security Misconfiguration')
    """)
    db.commit()

    with patch.object(risks, "connect_db") as connect:
        connect.return_value.__enter__.return_value = db
        rows = risks._host_register_rows()

    example = next(row for row in rows if row["host"] == "https://example.com")

    assert example["total_findings"] == 3
    assert example["severity_counts"]["High"] == 1
    assert example["severity_counts"]["Medium"] == 1
    assert example["severity_counts"]["Review"] == 1
    assert example["validation_counts"]["Evidence-supported"] == 1
    assert example["validation_counts"]["Needs-validation"] == 1
    assert example["cve_candidates"] == 1
    assert example["mitre_suggestions"] == 1
    assert "https://example.com/login" in example["aliases"]
    assert "https://example.com/admin" in example["aliases"]


def test_host_register_search_matches_host_aliases():
    import sqlite3
    from unittest.mock import patch
    from grc import automatic_risks as risks

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE draft_findings (
            id INTEGER PRIMARY KEY,
            source TEXT NOT NULL,
            fingerprint TEXT NOT NULL UNIQUE,
            target TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '',
            suggested_severity TEXT NOT NULL DEFAULT 'Review',
            confidence TEXT NOT NULL DEFAULT 'Low',
            recommendation TEXT NOT NULL DEFAULT '',
            iso_controls TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Draft',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE finding_intelligence (
            finding_id INTEGER PRIMARY KEY,
            cve_ids TEXT DEFAULT '',
            mitre_technique TEXT DEFAULT '',
            validation_status TEXT DEFAULT 'Unreviewed',
            auto_cve_ids TEXT DEFAULT '',
            local_cve_ids TEXT DEFAULT '',
            auto_mitre_technique TEXT DEFAULT '',
            auto_security_category TEXT DEFAULT ''
        );
    """)
    db.execute("""
        INSERT INTO draft_findings (
            id, source, fingerprint, target, title, description,
            created_at, updated_at
        ) VALUES (1, 'web', 'one', 'https://example.com/account',
                  'Account page', 'Test finding', 'now', 'now')
    """)
    db.commit()

    with patch.object(risks, "connect_db") as connect:
        connect.return_value.__enter__.return_value = db
        rows = risks._host_register_rows(search="account")

    assert len(rows) == 1
    assert rows[0]["host"] == "https://example.com"


def test_host_register_does_not_create_intelligence_rows_while_reading():
    import sqlite3
    from unittest.mock import patch
    from grc import automatic_risks as risks

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE draft_findings (
            id INTEGER PRIMARY KEY,
            source TEXT NOT NULL,
            fingerprint TEXT NOT NULL UNIQUE,
            target TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '',
            suggested_severity TEXT NOT NULL DEFAULT 'Review',
            confidence TEXT NOT NULL DEFAULT 'Low',
            recommendation TEXT NOT NULL DEFAULT '',
            iso_controls TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Draft',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE finding_intelligence (
            finding_id INTEGER PRIMARY KEY,
            cve_ids TEXT DEFAULT '',
            mitre_technique TEXT DEFAULT '',
            validation_status TEXT DEFAULT 'Unreviewed',
            auto_cve_ids TEXT DEFAULT '',
            local_cve_ids TEXT DEFAULT '',
            auto_mitre_technique TEXT DEFAULT '',
            auto_security_category TEXT DEFAULT ''
        );
    """)
    db.execute("""
        INSERT INTO draft_findings (
            id, source, fingerprint, target, title, description,
            created_at, updated_at
        ) VALUES (1, 'nmap', 'one', '192.0.2.10',
                  'SSH service', 'Detected SSH', 'now', 'now')
    """)
    db.commit()

    with patch.object(risks, "connect_db") as connect:
        connect.return_value.__enter__.return_value = db
        risks._host_register_rows()

    assert db.execute(
        "SELECT COUNT(*) FROM finding_intelligence"
    ).fetchone()[0] == 0


def test_intelligence_query_can_return_all_findings_without_limit():
    from grc.automatic_risks import _intelligence_query

    with patch("grc.automatic_risks.connect_db") as connect:
        db = Mock()
        db.execute.return_value.fetchall.return_value = []
        connect.return_value.__enter__.return_value = db

        _intelligence_query({"host": "192.0.2.10"}, limit=None)

    sql, params = db.execute.call_args.args
    assert "LIMIT" not in sql.upper()
    assert "192.0.2.10" in params


def test_intelligence_mitre_filter_includes_automated_and_analyst_mappings():
    from grc.automatic_risks import _intelligence_query

    with patch("grc.automatic_risks.connect_db") as connect:
        db = Mock()
        db.execute.return_value.fetchall.return_value = []
        connect.return_value.__enter__.return_value = db

        _intelligence_query({"mitre": "T1190"})

    sql, params = db.execute.call_args.args
    assert "i.mitre_technique" in sql
    assert "i.auto_mitre_technique" in sql
    assert "%T1190%" in params


def test_cve_version_match_exact_version():
    from grc.automatic_risks import _match_cve_version_range

    assert _match_cve_version_range(
        "2.4.1", version="2.4.1"
    ) == "Version Match"


def test_cve_version_match_inclusive_and_exclusive_bounds():
    from grc.automatic_risks import _match_cve_version_range

    assert _match_cve_version_range(
        "2.4.1",
        version_start_including="2.4.1",
        version_end_excluding="2.5.0",
    ) == "Version Match"

    assert _match_cve_version_range(
        "2.4.1",
        version_start_excluding="2.4.1",
        version_end_including="2.5.0",
    ) == "Not Matched"


def test_cve_version_match_numeric_ordering():
    from grc.automatic_risks import _match_cve_version_range

    assert _match_cve_version_range(
        "2.10.0", version_end_including="2.9.9"
    ) == "Not Matched"


def test_cve_version_match_unbounded_range():
    from grc.automatic_risks import _match_cve_version_range

    assert _match_cve_version_range(
        "1.2.0", version_start_including="1.0.0"
    ) == "Version Match"


def test_cve_version_match_invalid_versions_are_unassessed():
    from grc.automatic_risks import _match_cve_version_range

    assert _match_cve_version_range(
        "unknown", version_end_including="2.0"
    ) == "Unassessed"


def test_cve_version_match_rejects_conflicting_boundaries():
    from grc.automatic_risks import _match_cve_version_range

    assert _match_cve_version_range(
        "2.4.1",
        version_start_including="2.0",
        version_start_excluding="2.1",
    ) == "Unassessed"


def test_cve_version_match_rejects_exact_version_with_range():
    from grc.automatic_risks import _match_cve_version_range

    assert _match_cve_version_range(
        "2.4.1",
        version="2.4.1",
        version_end_including="2.5.0",
    ) == "Unassessed"


def test_cve_version_match_rejects_non_numeric_range():
    from grc.automatic_risks import _match_cve_version_range

    assert _match_cve_version_range(
        "2.4.1",
        version_start_including="2.x",
    ) == "Unassessed"


def test_cve_version_match_does_not_assume_missing_range():
    from grc.automatic_risks import _match_cve_version_range

    assert _match_cve_version_range("2.4.1") == "Unassessed"


def test_cve_version_match_rejects_inverted_range():
    from grc.automatic_risks import _match_cve_version_range

    assert _match_cve_version_range(
        "2.4.1",
        version_start_including="3.0",
        version_end_including="2.0",
    ) == "Unassessed"


def test_nvd_cpe_exact_version_match():
    from grc.automatic_risks import _match_nvd_cpe

    result = _match_nvd_cpe(
        "OpenSSH",
        "9.2",
        "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*",
    )

    assert result == "Version Match"


def test_nvd_cpe_version_range_match():
    from grc.automatic_risks import _match_nvd_cpe

    result = _match_nvd_cpe(
        "OpenSSH",
        "9.2",
        "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
        version_start_including="9.0",
        version_end_excluding="9.5",
    )

    assert result == "Version Match"


def test_nvd_cpe_rejects_unrelated_product():
    from grc.automatic_risks import _match_nvd_cpe

    result = _match_nvd_cpe(
        "OpenSSH",
        "9.2",
        "cpe:2.3:a:apache:http_server:9.2:*:*:*:*:*:*:*",
    )

    assert result == "Not Matched"


def test_nvd_cpe_wildcard_version_without_range_is_unassessed():
    from grc.automatic_risks import _match_nvd_cpe

    result = _match_nvd_cpe(
        "OpenSSH",
        "9.2",
        "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
    )

    assert result == "Unassessed"


def test_nvd_cpe_rejects_malformed_criteria():
    from grc.automatic_risks import _match_nvd_cpe

    assert _match_nvd_cpe(
        "OpenSSH", "9.2", "cpe:2.3:a:openbsd:openssh"
    ) == "Unassessed"


def test_nvd_cpe_rejects_ambiguous_escaped_product():
    from grc.automatic_risks import _match_nvd_cpe

    assert _match_nvd_cpe(
        "OpenSSH",
        "9.2",
        r"cpe:2.3:a:openbsd:open\:ssh:9.2:*:*:*:*:*:*:*",
    ) == "Unassessed"


def test_nvd_cpe_rejects_empty_product():
    from grc.automatic_risks import _match_nvd_cpe

    assert _match_nvd_cpe(
        "OpenSSH",
        "9.2",
        "cpe:2.3:a:openbsd:*:9.2:*:*:*:*:*:*:*",
    ) == "Unassessed"


def test_nvd_configuration_matches_simple_or_cpe():
    from grc.automatic_risks import _match_nvd_configuration

    configuration = [{
        "nodes": [{
            "operator": "OR",
            "cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*",
            }],
        }],
    }]

    assert _match_nvd_configuration(
        "OpenSSH", "9.2", configuration
    ) == "Version Match"


def test_nvd_configuration_rejects_and_logic_as_unassessed():
    from grc.automatic_risks import _match_nvd_configuration

    configuration = [{
        "nodes": [{
            "operator": "AND",
            "cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*",
            }],
        }],
    }]

    assert _match_nvd_configuration(
        "OpenSSH", "9.2", configuration
    ) == "Unassessed"


def test_nvd_configuration_rejects_negated_logic():
    from grc.automatic_risks import _match_nvd_configuration

    configuration = [{
        "nodes": [{
            "operator": "OR",
            "negate": True,
            "cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*",
            }],
        }],
    }]

    assert _match_nvd_configuration(
        "OpenSSH", "9.2", configuration
    ) == "Unassessed"


def test_nvd_configuration_ignores_non_vulnerable_cpe_entries():
    from grc.automatic_risks import _match_nvd_configuration

    configuration = [{
        "nodes": [{
            "operator": "OR",
            "cpeMatch": [{
                "vulnerable": False,
                "criteria": "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*",
            }],
        }],
    }]

    assert _match_nvd_configuration(
        "OpenSSH", "9.2", configuration
    ) == "Unassessed"



def test_nvd_configuration_rejects_malformed_vulnerable_product_identity():
    from grc.automatic_risks import _match_nvd_configuration

    configuration = [{
        "nodes": [{
            "operator": "OR",
            "cpeMatch": [{
                "vulnerable": True,
                "criteria": "malformed-cpe-criteria",
            }],
        }],
    }]

    assert _match_nvd_configuration(
        "OpenSSH", "9.2", configuration
    ) == "Not Matched"


def test_nvd_configuration_rejects_escaped_unidentifiable_vulnerable_product():
    from grc.automatic_risks import _match_nvd_configuration

    configuration = [{
        "nodes": [{
            "operator": "OR",
            "cpeMatch": [{
                "vulnerable": True,
                "criteria": (
                    r"cpe:2.3:a:openbsd:open\\:ssh:9.2:*:*:*:*:*:*:*"
                ),
            }],
        }],
    }]

    assert _match_nvd_configuration(
        "OpenSSH", "9.2", configuration
    ) == "Not Matched"


def test_nvd_configuration_rejects_unrelated_and_malformed_vulnerable_products():
    from grc.automatic_risks import _match_nvd_configuration

    configuration = [{
        "nodes": [{
            "operator": "OR",
            "cpeMatch": [
                {
                    "vulnerable": True,
                    "criteria": (
                        "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*"
                    ),
                },
                {
                    "vulnerable": True,
                    "criteria": "malformed-cpe-criteria",
                },
            ],
        }],
    }]

    assert _match_nvd_configuration(
        "OpenSSH", "9.2", configuration
    ) == "Not Matched"


def test_nvd_configuration_matches_vulnerable_entry_with_environmental_entry():
    from grc.automatic_risks import _match_nvd_configuration

    configuration = [{
        "nodes": [{
            "operator": "OR",
            "cpeMatch": [
                {
                    "vulnerable": False,
                    "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                },
                {
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*",
                },
            ],
        }],
    }]

    assert _match_nvd_configuration(
        "OpenSSH", "9.2", configuration
    ) == "Version Match"


def test_nvd_lookup_successful_empty_response():
    from unittest.mock import Mock, patch
    from grc.automatic_risks import _nvd_lookup

    response = Mock()
    response.json.return_value = {"vulnerabilities": []}

    with patch("grc.automatic_risks.requests.get", return_value=response):
        result = _nvd_lookup("OpenSSH", "9.2")

    assert result["lookup_status"] == "Succeeded"
    assert result["candidates"] == []
    assert result["match_status"] == "Unassessed"


def test_nvd_lookup_api_failure():
    from unittest.mock import patch
    import requests
    from grc.automatic_risks import _nvd_lookup

    with patch(
        "grc.automatic_risks.requests.get",
        side_effect=requests.RequestException("connection failed"),
    ):
        result = _nvd_lookup("OpenSSH", "9.2")

    assert result["lookup_status"] == "Failed"
    assert result["candidates"] == []
    assert result["match_status"] == "Unassessed"


def test_nvd_lookup_detects_version_match():
    from unittest.mock import Mock, patch
    from grc.automatic_risks import _nvd_lookup

    response = Mock()
    response.json.return_value = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-12345",
                "configurations": [{
                    "nodes": [{
                        "operator": "OR",
                        "cpeMatch": [{
                            "vulnerable": True,
                            "criteria": (
                                "cpe:2.3:a:openbsd:openssh:9.2:"
                                "*:*:*:*:*:*:*"
                            ),
                        }],
                    }],
                }],
            },
        }],
    }

    with patch("grc.automatic_risks.requests.get", return_value=response):
        result = _nvd_lookup("OpenSSH", "9.2")

    assert result["lookup_status"] == "Succeeded"
    assert result["candidates"] == ["CVE-2024-12345"]
    assert result["match_status"] == "Version Match"
    assert "CVE-2024-12345: Version Match" in result["match_details"]
    assert "vendor identity was not independently verified" in result["match_details"]
    assert "product/version evidence" in result["match_details"]


def test_nvd_lookup_detects_version_mismatch():
    from unittest.mock import Mock, patch
    from grc.automatic_risks import _nvd_lookup

    response = Mock()
    response.json.return_value = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-12345",
                "configurations": [{
                    "nodes": [{
                        "operator": "OR",
                        "cpeMatch": [{
                            "vulnerable": True,
                            "criteria": (
                                "cpe:2.3:a:nginx:nginx:1.24:"
                                "*:*:*:*:*:*:*"
                            ),
                        }],
                    }],
                }],
            },
        }],
    }

    with patch("grc.automatic_risks.requests.get", return_value=response):
        result = _nvd_lookup("OpenSSH", "9.2")

    assert result["lookup_status"] == "Succeeded"
    assert result["candidates"] == ["CVE-2024-12345"]
    assert result["match_status"] == "Not Matched"


def test_nvd_lookup_unsupported_configuration_is_unassessed():
    from unittest.mock import Mock, patch
    from grc.automatic_risks import _nvd_lookup

    response = Mock()
    response.json.return_value = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-12345",
                "configurations": [{
                    "nodes": [{
                        "operator": "AND",
                        "cpeMatch": [{
                            "vulnerable": True,
                            "criteria": (
                                "cpe:2.3:a:openbsd:openssh:9.2:"
                                "*:*:*:*:*:*:*"
                            ),
                        }],
                    }],
                }],
            },
        }],
    }

    with patch("grc.automatic_risks.requests.get", return_value=response):
        result = _nvd_lookup("OpenSSH", "9.2")

    assert result["lookup_status"] == "Succeeded"
    assert result["match_status"] == "Unassessed"


def _create_enrichment_test_db():
    import sqlite3

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE draft_findings (
            id INTEGER PRIMARY KEY,
            source TEXT NOT NULL,
            source_record_id INTEGER,
            target TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            evidence TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE finding_intelligence (
            finding_id INTEGER PRIMARY KEY,
            cve_ids TEXT DEFAULT '',
            validation_status TEXT DEFAULT 'Unreviewed',
            auto_cve_ids TEXT DEFAULT '',
            local_cve_ids TEXT DEFAULT '',
            auto_cve_match_status TEXT DEFAULT 'Unassessed',
            auto_cve_match_details TEXT DEFAULT '',
            auto_cve_checked_at TEXT DEFAULT '',
            auto_owasp_category TEXT DEFAULT '',
            auto_security_category TEXT DEFAULT '',
            auto_mitre_tactic TEXT DEFAULT '',
            auto_mitre_technique TEXT DEFAULT '',
            auto_mitre_rationale TEXT DEFAULT '',
            auto_mitre_confidence TEXT DEFAULT '',
            auto_source_summary TEXT DEFAULT '',
            last_enriched_at TEXT DEFAULT '',
            updated_at TEXT DEFAULT ''
        );

        CREATE TABLE nmap_ports (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER,
            state TEXT,
            product TEXT,
            version TEXT,
            port INTEGER
        );
    """)
    return db


def _insert_enrichment_test_finding(db, *, auto_cves="", analyst_cves="",
                                    validation="Unreviewed"):
    db.execute("""
        INSERT INTO draft_findings (
            id, source, source_record_id, target, title, description, evidence
        ) VALUES (
            1, 'nmap', 10, '192.0.2.10', 'OpenSSH service',
            'Detected OpenSSH service', 'port=22 service=ssh'
        )
    """)
    db.execute("""
        INSERT INTO finding_intelligence (
            finding_id, cve_ids, validation_status, auto_cve_ids,
            auto_cve_match_status, auto_cve_match_details, auto_cve_checked_at
        ) VALUES (1, ?, ?, ?, 'Unassessed', '', 'previous-check')
    """, (analyst_cves, validation, auto_cves))
    db.execute("""
        INSERT INTO nmap_ports (
            scan_id, state, product, version, port
        ) VALUES (10, 'open', 'OpenSSH', '9.2', 22)
    """)
    db.commit()


def test_enrichment_preserves_analyst_cves_and_validation_status():
    from unittest.mock import patch
    from grc import automatic_risks as risks

    db = _create_enrichment_test_db()
    _insert_enrichment_test_finding(
        db,
        auto_cves="CVE-2023-11111",
        analyst_cves="CVE-2022-22222",
        validation="Evidence-supported",
    )

    lookup = {
        "lookup_status": "Succeeded",
        "candidates": ["CVE-2024-12345"],
        "match_status": "Version Match",
        "match_details": "CVE-2024-12345: Version Match",
    }

    with patch.object(risks, "connect_db") as connect, \
         patch.object(risks, "_nvd_lookup", return_value=lookup), \
         patch.object(risks.time, "sleep"):
        connect.return_value.__enter__.return_value = db
        risks._enrich_existing_findings()

    row = db.execute("""
        SELECT cve_ids, validation_status, auto_cve_ids,
               auto_cve_match_status, auto_cve_match_details
        FROM finding_intelligence WHERE finding_id=1
    """).fetchone()

    assert row["cve_ids"] == "CVE-2022-22222"
    assert row["validation_status"] == "Evidence-supported"
    assert row["auto_cve_ids"] == "CVE-2024-12345"
    assert row["auto_cve_match_status"] == "Version Match"
    assert row["auto_cve_match_details"] == "CVE-2024-12345: Version Match"


def test_enrichment_persists_nvd_applicability_evidence_and_timestamp():
    from unittest.mock import patch
    from grc import automatic_risks as risks

    db = _create_enrichment_test_db()
    _insert_enrichment_test_finding(db)

    lookup = {
        "lookup_status": "Succeeded",
        "candidates": ["CVE-2024-12345"],
        "match_status": "Version Match",
        "match_details": "CVE-2024-12345: Version Match",
    }

    with patch.object(risks, "connect_db") as connect, \
         patch.object(risks, "_nvd_lookup", return_value=lookup), \
         patch.object(risks.time, "sleep"):
        connect.return_value.__enter__.return_value = db
        counts = risks._enrich_existing_findings()

    row = db.execute("""
        SELECT auto_cve_ids, auto_cve_match_status,
               auto_cve_match_details, auto_cve_checked_at
        FROM finding_intelligence WHERE finding_id=1
    """).fetchone()

    assert counts["processed"] == 1
    assert counts["nvd_candidates"] == 1
    assert row["auto_cve_ids"] == "CVE-2024-12345"
    assert row["auto_cve_match_status"] == "Version Match"
    assert "CVE-2024-12345" in row["auto_cve_match_details"]
    assert row["auto_cve_checked_at"]
    assert row["auto_cve_checked_at"] != "previous-check"


def test_enrichment_lookup_failure_preserves_existing_auto_cves():
    from unittest.mock import patch
    from grc import automatic_risks as risks

    db = _create_enrichment_test_db()
    _insert_enrichment_test_finding(db, auto_cves="CVE-2023-11111")

    lookup = {
        "lookup_status": "Failed",
        "candidates": [],
        "match_status": "Unassessed",
        "match_details": "NVD lookup failed; applicability remains unassessed.",
    }

    with patch.object(risks, "connect_db") as connect, \
         patch.object(risks, "_nvd_lookup", return_value=lookup):
        connect.return_value.__enter__.return_value = db
        risks._enrich_existing_findings()

    row = db.execute("""
        SELECT auto_cve_ids, auto_cve_match_status,
               auto_cve_match_details
        FROM finding_intelligence WHERE finding_id=1
    """).fetchone()

    assert row["auto_cve_ids"] == "CVE-2023-11111"
    assert row["auto_cve_match_status"] == "Unassessed"
    assert "lookup failed" in row["auto_cve_match_details"]


def test_enrichment_successful_empty_lookup_clears_stale_auto_cves():
    from unittest.mock import patch
    from grc import automatic_risks as risks

    db = _create_enrichment_test_db()
    _insert_enrichment_test_finding(db, auto_cves="CVE-2023-11111")

    lookup = {
        "lookup_status": "Succeeded",
        "candidates": [],
        "match_status": "Unassessed",
        "match_details": "NVD lookup succeeded; no CVE candidates returned.",
    }

    with patch.object(risks, "connect_db") as connect, \
         patch.object(risks, "_nvd_lookup", return_value=lookup):
        connect.return_value.__enter__.return_value = db
        risks._enrich_existing_findings()

    row = db.execute("""
        SELECT auto_cve_ids, auto_cve_match_status,
               auto_cve_match_details
        FROM finding_intelligence WHERE finding_id=1
    """).fetchone()

    assert row["auto_cve_ids"] == ""
    assert row["auto_cve_match_status"] == "Unassessed"
    assert "no CVE candidates" in row["auto_cve_match_details"]


def test_enrichment_without_product_version_preserves_cves_and_timestamp():
    from unittest.mock import patch
    from grc import automatic_risks as risks

    db = _create_enrichment_test_db()
    _insert_enrichment_test_finding(db, auto_cves="CVE-2023-11111")

    db.execute("DELETE FROM nmap_ports")
    db.commit()

    with patch.object(risks, "connect_db") as connect, \
         patch.object(risks, "_nvd_lookup") as lookup:
        connect.return_value.__enter__.return_value = db
        risks._enrich_existing_findings()

    lookup.assert_not_called()

    row = db.execute("""
        SELECT auto_cve_ids, auto_cve_match_status, auto_cve_checked_at
        FROM finding_intelligence WHERE finding_id=1
    """).fetchone()

    assert row["auto_cve_ids"] == "CVE-2023-11111"
    assert row["auto_cve_match_status"] == "Unassessed"
    assert row["auto_cve_checked_at"] == "previous-check"


def test_mitre_rejects_missing_deprecated_and_revoked_techniques():
    from grc.automatic_risks import _suggest_mitre

    invalid_techniques = [
        None,
        {
            "technique_id": "T1110",
            "name": "Brute Force",
            "deprecated": 1,
            "revoked": 0,
        },
        {
            "technique_id": "T1110",
            "name": "Brute Force",
            "deprecated": 0,
            "revoked": 1,
        },
    ]

    for technique in invalid_techniques:
        with patch(
            "grc.automatic_risks.get_latest_attack_version",
            return_value="20.1",
        ), patch(
            "grc.automatic_risks.get_attack_technique",
            return_value=technique,
        ):
            result = _suggest_mitre(
                "Repeated failed login attempts", "", ""
            )

        assert result["technique"] == ""
        assert result["tactic"] == ""
        assert result["confidence"] == "Unassessed"


def test_mitre_returns_unassessed_when_catalogue_is_unavailable():
    from grc.automatic_risks import _suggest_mitre

    with patch(
        "grc.automatic_risks.get_latest_attack_version",
        return_value=None,
    ), patch(
        "grc.automatic_risks.get_attack_technique",
    ) as technique_lookup:
        result = _suggest_mitre(
            "Repeated failed login attempts", "", ""
        )

    assert result["technique"] == ""
    assert result["tactic"] == ""
    assert result["confidence"] == "Unassessed"
    technique_lookup.assert_not_called()


def test_mitre_rejects_missing_tactic_relationship():
    from grc.automatic_risks import _suggest_mitre

    with patch(
        "grc.automatic_risks.get_latest_attack_version",
        return_value="20.1",
    ), patch(
        "grc.automatic_risks.get_attack_technique",
        return_value={
            "technique_id": "T1110",
            "name": "Brute Force",
            "deprecated": 0,
            "revoked": 0,
        },
    ), patch(
        "grc.automatic_risks.sqlite3.connect"
    ) as connect:
        connect.return_value.execute.return_value.fetchall.return_value = []

        result = _suggest_mitre(
            "Repeated failed login attempts", "", ""
        )

    assert result["technique"] == ""
    assert result["tactic"] == ""
    assert result["confidence"] == "Unassessed"


def test_mitre_handles_ambiguous_tactic_relationship():
    from grc.automatic_risks import _suggest_mitre

    with patch(
        "grc.automatic_risks.get_latest_attack_version",
        return_value="20.1",
    ), patch(
        "grc.automatic_risks.get_attack_technique",
        return_value={
            "technique_id": "T1110",
            "name": "Brute Force",
            "deprecated": 0,
            "revoked": 0,
        },
    ), patch(
        "grc.automatic_risks.sqlite3.connect"
    ) as connect:
        connect.return_value.execute.return_value.fetchall.return_value = [
            ("Credential Access",),
            ("Initial Access",),
        ]

        result = _suggest_mitre(
            "Repeated failed login attempts", "", ""
        )

    # Auto-mapping picks the first tactic alphabetically to avoid crashing
    assert result["technique"] == "T1110"
    assert result["tactic"] == "Credential Access"


def test_host_register_counts_local_correlation_cves():
    """R1 regression: local_cve_ids must count toward cve_candidates.

    Before Step 3a, a finding whose CVE lived only in local_cve_ids was
    invisible to the host register counter, so cve_candidates was
    under-reported for every finding produced by
    sync_cve_exposures_to_findings.
    """
    import sqlite3
    from unittest.mock import patch
    from grc import automatic_risks as risks

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE draft_findings (
            id INTEGER PRIMARY KEY,
            source TEXT NOT NULL,
            fingerprint TEXT NOT NULL UNIQUE,
            target TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '',
            suggested_severity TEXT NOT NULL DEFAULT 'Review',
            confidence TEXT NOT NULL DEFAULT 'Low',
            recommendation TEXT NOT NULL DEFAULT '',
            iso_controls TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Draft',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE finding_intelligence (
            finding_id INTEGER PRIMARY KEY,
            cve_ids TEXT DEFAULT '',
            mitre_technique TEXT DEFAULT '',
            validation_status TEXT DEFAULT 'Unreviewed',
            auto_cve_ids TEXT DEFAULT '',
            local_cve_ids TEXT DEFAULT '',
            auto_mitre_technique TEXT DEFAULT '',
            auto_security_category TEXT DEFAULT ''
        );
    """)

    db.execute("""
        INSERT INTO draft_findings (
            id, source, fingerprint, target, title, description,
            created_at, updated_at
        ) VALUES (1, 'local_cve_intelligence', 'one', '192.0.2.10',
                  'CVE finding', 'From local correlation', 'now', 'now')
    """)
    db.execute("""
        INSERT INTO finding_intelligence (
            finding_id, auto_cve_ids, local_cve_ids
        ) VALUES (1, '', 'CVE-2026-12345')
    """)
    db.commit()

    with patch.object(risks, "connect_db") as connect:
        connect.return_value.__enter__.return_value = db
        rows = risks._host_register_rows()

    assert len(rows) == 1
    assert rows[0]["cve_candidates"] == 1


def test_intelligence_query_exposes_local_correlation_cves():
    from grc.vulnerability_intelligence import initialize_vulnerability_intelligence
    """R2 regression: local_cve_ids must be selectable and filterable.

    Before Step 3a, a finding whose CVE lived only in local_cve_ids was
    not returned by _intelligence_query at all, so it never reached the
    host report, CSV export or PDF export.
    """
    import sqlite3
    from grc import automatic_risks as risks

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row

    # Build the tables via the real initializer so this test sees the
    # same schema the application ships, not a hand-written imitation.
    original_connect = risks.connect_db
    risks.connect_db = lambda: db
    try:
        risks.initialize_automatic_risks()
        # Create the hexbrain table manually for this in-memory test
        db.execute("CREATE TABLE hexbrain_enrichment (cve_id TEXT PRIMARY KEY, summary TEXT, testing_context_json TEXT, references_json TEXT)")
    finally:
        risks.connect_db = original_connect

    db.execute("""
        INSERT INTO draft_findings (
            source, fingerprint, target, title, description,
            evidence, suggested_severity, confidence, recommendation,
            iso_controls, status, created_at, updated_at
        ) VALUES (
            'local_cve_intelligence', 'one', '192.0.2.10',
            'CVE finding', 'From local correlation', 'evidence text',
            'Review', 'High', 'Patch it', '', 'Draft', 'now', 'now'
        )
    """)
    db.execute("""
        INSERT INTO finding_intelligence (
            finding_id, local_cve_ids, local_cve_match_status,
            local_owasp_category, local_security_category,
            local_source_summary, updated_at
        ) VALUES (
            1, 'CVE-2026-12345', 'Version Match',
            'A06:2021 – Vulnerable and Outdated Components',
            'Vulnerability Intelligence',
            'Local CVE database; Potential version match; KEV=No',
            'now'
        )
    """)
    db.commit()

    original_connect = risks.connect_db
    risks.connect_db = lambda: db
    try:
        # 1. The column must be selected and populated.
        rows = risks._intelligence_query({}, limit=None)
        assert len(rows) == 1
        assert rows[0]["local_cve_ids"] == "CVE-2026-12345"
        assert rows[0]["local_cve_match_status"] == "Version Match"

        # 2. The cve filter must match on local_cve_ids.
        filtered = risks._intelligence_query({"cve": "CVE-2026-12345"})
        assert len(filtered) == 1

        # 3. The q search must match on local_cve_ids.
        searched = risks._intelligence_query({"q": "CVE-2026-12345"})
        assert len(searched) == 1
    finally:
        risks.connect_db = original_connect
