import json
import sqlite3

from grc.asset_observations import (
    ingest_firewall_observations,
    ingest_nmap_observations,
)
from grc.vulnerability_intelligence import (
    initialize_vulnerability_intelligence,
)


def create_test_db(tmp_path):
    database = tmp_path / "asset-observations.db"
    initialize_vulnerability_intelligence(database)

    db = sqlite3.connect(database)
    db.row_factory = sqlite3.Row
    return db


def test_nmap_ingests_only_valid_open_ports(tmp_path):
    db = create_test_db(tmp_path)

    try:
        ids = ingest_nmap_observations(
            db,
            "192.168.1.10",
            {
                "ports": [
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "https",
                        "product": "Example Server",
                        "version": "2.4.1",
                        "extra_info": "Test build",
                        "reason": "syn-ack",
                        "service_method": "probed",
                        "service_confidence": "10",
                        "service_tunnel": "ssl",
                        "service_cpe": [
                            "cpe:/a:example:server:2.4"
                        ],
                    },
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "state": "closed",
                        "service": "ssh",
                        "product": "OpenSSH",
                        "version": "9.0",
                    },
                    {
                        "port": 70000,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "invalid",
                    },
                    {
                        "port": 53,
                        "protocol": "invalid",
                        "state": "open",
                        "service": "dns",
                    },
                ],
            },
            source_record_id="scan-101",
        )

        rows = db.execute("""
            SELECT asset_key, target, source, product, version,
                   service, port, protocol, confidence, evidence_json
            FROM asset_observations
        """).fetchall()

        assert len(ids) == 1
        assert len(rows) == 1
        assert rows[0]["asset_key"] == "host:192.168.1.10"
        assert rows[0]["product"] == "Example Server"
        assert rows[0]["version"] == "2.4.1"
        assert rows[0]["port"] == 443
        assert rows[0]["confidence"] == "High"

        evidence = json.loads(rows[0]["evidence_json"])
        assert evidence["state"] == "open"
        assert evidence["service_method"] == "probed"
        assert evidence["service_confidence"] == "10"
        assert evidence["service_tunnel"] == "ssl"
        assert evidence["service_cpe"] == [
            "cpe:/a:example:server:2.4"
        ]
    finally:
        db.close()


def test_nmap_observation_refresh_is_idempotent(tmp_path):
    db = create_test_db(tmp_path)

    result = {
        "ports": [{
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "9.0",
            "extra_info": "",
            "reason": "syn-ack",
        }]
    }

    try:
        first_ids = ingest_nmap_observations(
            db, "192.168.1.20", result,
            source_record_id="scan-201",
        )
        second_ids = ingest_nmap_observations(
            db, "192.168.1.20", result,
            source_record_id="scan-202",
        )

        count = db.execute(
            "SELECT COUNT(*) FROM asset_observations"
        ).fetchone()[0]

        row = db.execute("""
            SELECT source_record_id
            FROM asset_observations
            WHERE id = ?
        """, (first_ids[0],)).fetchone()

        assert first_ids == second_ids
        assert count == 1
        assert row["source_record_id"] == "scan-202"
    finally:
        db.close()


def test_firewall_ingests_application_once_and_keeps_protocols_distinct(
    tmp_path,
):
    db = create_test_db(tmp_path)

    application = {
        "address": "192.168.1.30",
        "port": 443,
        "protocol": "https",
        "service": "https",
        "vendor": "Example Vendor",
        "product": "Example Web Server",
        "version": "5.2.1",
        "confidence": "high",
        "evidence": ["server-header"],
    }

    result = {
        "host": "https://Example.internal:443/app",
        "services": {
            "items": [
                {
                    "port": 443,
                    "protocol": "https",
                    "service": "https",
                    "application": application,
                },
                {
                    "address": "192.168.1.30",
                    "port": 445,
                    "protocol": "tcp",
                    "service": "smb",
                    "product": "SMB",
                    "version": "3.1.1",
                    "confidence": "medium",
                },
                {
                    "address": "192.168.1.30",
                    "port": 3389,
                    "protocol": "tcp",
                    "service": "rdp",
                    "product": "Remote Desktop",
                    "version": "CredSSP",
                    "confidence": "medium",
                },
                {
                    "address": "192.168.1.30",
                    "port": 53,
                    "protocol": "udp",
                    "service": "dns",
                    "product": "",
                    "version": "DNS",
                    "confidence": "medium",
                },
            ]
        },
        "https": {"application": application},
    }

    try:
        ids = ingest_firewall_observations(
            db,
            "192.168.1.30",
            result,
            source_record_id="firewall-301",
        )

        rows = db.execute("""
            SELECT asset_key, product, version, service, port
            FROM asset_observations
            ORDER BY port
        """).fetchall()

        assert len(ids) == 4
        assert len(rows) == 4
        assert all(row["asset_key"] == "host:example.internal" for row in rows)

        by_service = {row["service"]: row for row in rows}

        assert by_service["https"]["product"] == "Example Web Server"
        assert by_service["https"]["version"] == "5.2.1"
        assert by_service["smb"]["version"] == ""
        assert by_service["rdp"]["version"] == ""
        assert by_service["dns"]["version"] == ""
    finally:
        db.close()


def test_firewall_stores_waf_as_non_cve_matchable_evidence(tmp_path):
    db = create_test_db(tmp_path)

    try:
        ingest_firewall_observations(
            db,
            "192.168.1.40",
            {
                "host": "192.168.1.40",
                "services": {"items": []},
                "waf": {
                    "vendor_identification": [{
                        "vendor": "Example CDN",
                        "product": "Example WAF",
                        "confidence": "medium",
                        "evidence": ["response-header"],
                    }]
                },
            },
            source_record_id="firewall-401",
        )

        row = db.execute("""
            SELECT source, vendor, product, version, service,
                   evidence_json
            FROM asset_observations
        """).fetchone()

        evidence = json.loads(row["evidence_json"])

        assert row["source"] == "firewall_waf"
        assert row["vendor"] == "Example CDN"
        assert row["product"] == ""
        assert row["version"] == ""
        assert row["service"] == "waf"
        assert evidence["cve_matchable"] is False
        assert evidence["product_hint"] == "Example WAF"
    finally:
        db.close()
