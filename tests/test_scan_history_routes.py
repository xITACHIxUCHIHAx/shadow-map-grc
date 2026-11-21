import sqlite3

import app as app_module
from grc import automatic_risks as risks
from grc.scan_registry import register_scan


def setup_history_test_app(monkeypatch, tmp_path):
    database = tmp_path / "scan-history-test.db"

    monkeypatch.setattr(app_module, "DATABASE_PATH", database)
    monkeypatch.setattr(risks, "DATABASE_PATH", database)

    app_module.app.config.update(TESTING=True)
    app_module.init_db()
    risks.initialize_automatic_risks()

    return app_module.app.test_client(), database


def test_global_scan_history_displays_scan_and_target_ids(
    monkeypatch, tmp_path
):
    client, database = setup_history_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        register_scan(
            db,
            "Nmap",
            "nmap_scans",
            1,
            "192.168.1.10",
            "Completed",
            "2026-11-19T10:00:00+00:00",
        )
        db.commit()

    response = client.get("/history")

    assert response.status_code == 200
    assert b"Global Scan History" in response.data
    assert b"SCN-00001" in response.data
    assert b"TGT-00001" in response.data
    assert b"Nmap" in response.data
    assert b"192.168.1.10" in response.data
    assert b"/nmap/results/1" in response.data


def test_global_history_filters_cascade_dropdown_options(
    monkeypatch, tmp_path
):
    client, database = setup_history_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        register_scan(
            db, "Nmap", "nmap_scans", 1,
            "192.168.1.10", "Completed",
            "2026-11-19T10:00:00+00:00",
        )
        register_scan(
            db, "Web Security", "web_security_scans", 1,
            "192.168.1.20", "Failed",
            "2026-11-19T11:00:00+00:00",
        )
        db.commit()

    response = client.get(
        "/history?global_scan_id=SCN-00001"
    )

    assert response.status_code == 200
    assert b"SCN-00001" in response.data
    assert b'value="192.168.1.10"' in response.data
    assert b'value="192.168.1.20"' not in response.data
    assert b'name="target"' in response.data
    assert b'name="target_id"' not in response.data
    assert b'value="Nmap"' in response.data
    assert b'value="Web Security"' not in response.data
    assert b'value="Completed"' in response.data
    assert b'value="Failed"' not in response.data


def test_global_history_status_filter(
    monkeypatch, tmp_path
):
    client, database = setup_history_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        register_scan(
            db, "Nmap", "nmap_scans", 1,
            "192.168.1.10", "Completed",
            "2026-11-18T10:00:00+00:00",
        )
        register_scan(
            db, "Web Security", "web_security_scans", 1,
            "192.168.1.20", "Failed",
            "2026-11-19T11:00:00+00:00",
        )
        db.commit()

    response = client.get(
        "/history?status=Failed"
    )

    assert response.status_code == 200
    assert b"SCN-00002" in response.data
    assert b"SCN-00001" not in response.data
    assert b"192.168.1.20" in response.data
    assert b"192.168.1.10" not in response.data



def test_global_history_ignores_removed_date_filters(
    monkeypatch, tmp_path
):
    client, database = setup_history_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        register_scan(
            db, "Nmap", "nmap_scans", 1,
            "192.168.1.10", "Completed",
            "2026-11-18T10:00:00+00:00",
        )
        register_scan(
            db, "Web Security", "web_security_scans", 1,
            "192.168.1.20", "Failed",
            "2026-11-19T11:00:00+00:00",
        )
        db.commit()

    response = client.get(
        "/history?date_from=invalid-date&date_to=2026-99-99"
    )

    assert response.status_code == 200
    assert b"SCN-00001" in response.data
    assert b"SCN-00002" in response.data


def test_target_details_displays_identity_and_scan_history(
    monkeypatch, tmp_path
):
    client, database = setup_history_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        register_scan(
            db,
            "Nmap",
            "nmap_scans",
            1,
            "192.168.1.10",
            "Completed",
            "2026-11-19T10:00:00+00:00",
        )
        db.commit()

    response = client.get("/history/target/TGT-00001")

    assert response.status_code == 200
    assert b"TGT-00001" in response.data
    assert b"192.168.1.10" in response.data
    assert b"SCN-00001" in response.data
    assert b"/nmap/results/1" in response.data


def test_target_details_returns_404_for_unknown_target(
    monkeypatch, tmp_path
):
    client, _ = setup_history_test_app(monkeypatch, tmp_path)

    response = client.get("/history/target/TGT-99999")

    assert response.status_code == 404


def create_unified_run(db, batches, created_at):
    import json

    module_details = {
        "nmap": ("Nmap", "nmap_scans"),
        "web_security": ("Web Security", "web_security_scans"),
    }

    run_cursor = db.execute(
        """
        INSERT INTO unified_scan_runs (
            targets_json, modules_json, batch_ids_json,
            status, created_at, finished_at
        )
        VALUES (?, ?, '{}', 'Completed', ?, ?)
        """,
        (
            json.dumps(sorted({
                target
                for items in batches.values()
                for target, _status in items
            })),
            json.dumps(list(batches)),
            created_at,
            created_at,
        ),
    )
    run_id = run_cursor.lastrowid
    batch_ids = {}

    for module, items in batches.items():
        if module not in module_details:
            raise ValueError(f"Unsupported test module: {module}")

        module_name, source_table = module_details[module]
        completed = sum(status == "Completed" for _target, status in items)
        failed = sum(status == "Failed" for _target, status in items)
        skipped = sum(status == "Skipped" for _target, status in items)

        batch_cursor = db.execute(
            """
            INSERT INTO scan_batches (
                module, profile, status, total_targets,
                completed_targets, failed_targets, skipped_targets,
                created_at, finished_at
            )
            VALUES (?, 'test', 'Completed', ?, ?, ?, ?, ?, ?)
            """,
            (
                module,
                len(items),
                completed,
                failed,
                skipped,
                created_at,
                created_at,
            ),
        )
        batch_id = batch_cursor.lastrowid
        batch_ids[module] = batch_id

        for position, (target, status) in enumerate(items, start=1):
            result_type = ""
            result_record_id = None
            finished_at = created_at if status != "Pending" else None

            if status == "Completed":
                if module == "nmap":
                    result_cursor = db.execute(
                        """
                        INSERT INTO nmap_scans (
                            target, status, started_at, finished_at,
                            duration_seconds
                        )
                        VALUES (?, ?, ?, ?, 0.1)
                        """,
                        (target, status, created_at, created_at),
                    )
                else:
                    result_cursor = db.execute(
                        """
                        INSERT INTO web_security_scans (
                            target, status, started_at, finished_at,
                            duration_seconds
                        )
                        VALUES (?, ?, ?, ?, 0.1)
                        """,
                        (target, status, created_at, created_at),
                    )

                result_record_id = result_cursor.lastrowid
                result_type = module

                register_scan(
                    db,
                    module_name,
                    source_table,
                    result_record_id,
                    target,
                    status,
                    created_at,
                    created_at,
                    0.1,
                )

            db.execute(
                """
                INSERT INTO scan_batch_items (
                    batch_id, position, target, status,
                    started_at, finished_at, duration_seconds,
                    result_type, result_record_id, request_id, error
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
                """,
                (
                    batch_id,
                    position,
                    target,
                    status,
                    created_at,
                    finished_at,
                    0.1 if status == "Completed" else None,
                    result_type,
                    result_record_id,
                    None if status == "Completed" else f"Test {status.lower()} item",
                ),
            )

    db.execute(
        """
        UPDATE unified_scan_runs
        SET batch_ids_json = ?
        WHERE id = ?
        """,
        (json.dumps(batch_ids), run_id),
    )

    return run_id


def test_global_history_expands_unified_scan_into_module_target_rows(
    monkeypatch, tmp_path
):
    client, database = setup_history_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        create_unified_run(
            db,
            {
                "nmap": [
                    ("192.168.1.10", "Completed"),
                    ("192.168.1.20", "Failed"),
                ],
                "web_security": [
                    ("192.168.1.10", "Completed"),
                ],
            },
            "2026-11-20T10:00:00+00:00",
        )
        db.commit()

    response = client.get("/history")

    assert response.status_code == 200
    assert b"Global Scan History" in response.data
    assert b"SCN-00001" in response.data
    assert b"SCN-00002" in response.data
    assert b"Nmap" in response.data
    assert b"Web Security" in response.data
    assert b"192.168.1.10" in response.data
    assert b"192.168.1.20" in response.data
    assert b"Failed" in response.data
    assert b"/nmap/results/1" in response.data
    assert b"/web-security/results/1" in response.data
    assert b"<td>Unified Scan</td>" not in response.data


def test_global_history_unified_scan_type_filter(
    monkeypatch, tmp_path
):
    client, database = setup_history_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        register_scan(
            db, "Nmap", "nmap_scans", 99,
            "192.168.1.30", "Completed",
            "2026-11-20T09:00:00+00:00",
        )

        create_unified_run(
            db,
            {
                "nmap": [
                    ("192.168.1.10", "Completed"),
                ],
                "web_security": [
                    ("192.168.1.20", "Completed"),
                ],
            },
            "2026-11-20T10:00:00+00:00",
        )
        db.commit()

    response = client.get("/history?scan_type=Unified+Scan")

    assert response.status_code == 200
    assert b"192.168.1.10" in response.data
    assert b"192.168.1.20" in response.data
    assert b"192.168.1.30" not in response.data
    assert b"Nmap" in response.data
    assert b"Web Security" in response.data


def test_global_history_unified_scan_target_and_status_filters(
    monkeypatch, tmp_path
):
    client, database = setup_history_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        create_unified_run(
            db,
            {
                "nmap": [
                    ("192.168.1.10", "Completed"),
                    ("192.168.1.20", "Failed"),
                ],
                "web_security": [
                    ("192.168.1.20", "Completed"),
                ],
            },
            "2026-11-20T10:00:00+00:00",
        )
        db.commit()

    response = client.get(
        "/history?scan_type=Unified+Scan"
        "&target=192.168.1.20&status=Completed"
    )

    assert response.status_code == 200

    history_rows = (
        response.data.split(b"<th>Scan ID</th>", 1)[1]
        .split(b"</tbody>", 1)[0]
    )

    assert b"192.168.1.20" in history_rows
    assert b"Web Security" in history_rows
    assert b"192.168.1.10" not in history_rows
    assert b"Failed" not in history_rows


def test_global_history_module_filter_includes_standalone_and_unified_rows(
    monkeypatch, tmp_path
):
    client, database = setup_history_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        register_scan(
            db, "Nmap", "nmap_scans", 99,
            "192.168.1.30", "Completed",
            "2026-11-20T09:00:00+00:00",
        )

        create_unified_run(
            db,
            {
                "nmap": [
                    ("192.168.1.10", "Completed"),
                ],
                "web_security": [
                    ("192.168.1.20", "Completed"),
                ],
            },
            "2026-11-20T10:00:00+00:00",
        )
        db.commit()

    response = client.get("/history?scan_type=Nmap")

    assert response.status_code == 200

    history_rows = (
        response.data.split(b"<th>Scan ID</th>", 1)[1]
        .split(b"</tbody>", 1)[0]
    )

    assert b"192.168.1.10" in history_rows
    assert b"192.168.1.30" in history_rows
    assert b"192.168.1.20" not in history_rows


def test_global_history_csv_export_includes_selected_scan_and_findings(
    monkeypatch, tmp_path
):
    client, database = setup_history_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        cursor = db.execute(
            """
            INSERT INTO nmap_scans
                (target, status, started_at, finished_at, duration_seconds)
            VALUES (?, 'Completed', ?, ?, 0.1)
            """,
            ("192.168.1.10", "2026-11-20T10:00:00+00:00",
             "2026-11-20T10:00:01+00:00"),
        )
        record_id = cursor.lastrowid
        register_scan(
            db, "Nmap", "nmap_scans", record_id,
            "192.168.1.10", "Completed",
            "2026-11-20T10:00:00+00:00",
        )
        db.execute(
            """
            INSERT INTO draft_findings (
                source, source_record_id, fingerprint, target, title,
                description, evidence, suggested_severity, confidence,
                recommendation, iso_controls, status, created_at, updated_at
            )
            VALUES (
                'nmap', ?, 'test-export-finding', ?, 'Open test port',
                'Test description', 'TCP/22 open', 'Medium', 'High',
                'Restrict access', 'A.8.20', 'Draft', ?, ?
            )
            """,
            (
                record_id, "192.168.1.10",
                "2026-11-20T10:00:00+00:00",
                "2026-11-20T10:00:00+00:00",
            ),
        )
        db.commit()

    response = client.post(
        "/history/export",
        data={"selected_scans": "scan:SCN-00001", "export_format": "csv"},
    )

    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert b"Open test port" in response.data
    assert b"TCP/22 open" in response.data
    assert b"192.168.1.10" in response.data


def test_global_history_pdf_export_returns_pdf(
    monkeypatch, tmp_path
):
    client, database = setup_history_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        cursor = db.execute(
            """
            INSERT INTO nmap_scans
                (target, status, started_at, finished_at, duration_seconds)
            VALUES (?, 'Completed', ?, ?, 0.1)
            """,
            ("192.168.1.10", "2026-11-20T10:00:00+00:00",
             "2026-11-20T10:00:01+00:00"),
        )
        record_id = cursor.lastrowid
        register_scan(
            db, "Nmap", "nmap_scans", record_id,
            "192.168.1.10", "Completed",
            "2026-11-20T10:00:00+00:00",
        )
        db.commit()

    response = client.post(
        "/history/export",
        data={"selected_scans": "scan:SCN-00001", "export_format": "pdf"},
    )

    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.data.startswith(b"%PDF")


def test_global_history_export_rejects_invalid_selection(
    monkeypatch, tmp_path
):
    client, _ = setup_history_test_app(monkeypatch, tmp_path)

    response = client.post(
        "/history/export",
        data={"selected_scans": "scan:SCN-99999", "export_format": "csv"},
    )

    assert response.status_code == 400


def test_global_history_csv_export_includes_failed_and_skipped_batch_items(
    monkeypatch, tmp_path
):
    client, database = setup_history_test_app(monkeypatch, tmp_path)

    with sqlite3.connect(database) as db:
        create_unified_run(
            db,
            {
                "nmap": [
                    ("192.168.1.20", "Failed"),
                    ("192.168.1.30", "Skipped"),
                ]
            },
            "2026-11-20T10:00:00+00:00",
        )
        db.commit()
        items = db.execute(
            """
            SELECT batch_id, id
            FROM scan_batch_items
            ORDER BY id
            """
        ).fetchall()

    selected = [
        f"batch:{batch_id}:{item_id}"
        for batch_id, item_id in items
    ]
    response = client.post(
        "/history/export",
        data={
            "selected_scans": selected,
            "export_format": "csv",
        },
    )

    assert response.status_code == 200
    assert b"192.168.1.20" in response.data
    assert b"192.168.1.30" in response.data
    assert b"Failed" in response.data
    assert b"Skipped" in response.data
