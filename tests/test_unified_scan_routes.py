import json
import sqlite3

import app as app_module
import grc.automatic_risks as automatic_risks_module
import scanner.zap_proxy as zap_proxy_module


def setup_test_app(monkeypatch, tmp_path):
    database = tmp_path / "unified-test.db"
    monkeypatch.setattr(app_module, "DATABASE_PATH", database)
    monkeypatch.setattr(
        automatic_risks_module,
        "DATABASE_PATH",
        database,
    )
    app_module.app.config.update(TESTING=True)
    app_module.init_db()
    return app_module.app.test_client(), database


def test_unified_scan_runs_selected_modules_with_independent_validation(
    monkeypatch, tmp_path
):
    client, database = setup_test_app(monkeypatch, tmp_path)

    calls = {"nmap": [], "web": [], "threat": [], "zap": [], "zap_alerts": []}

    def nmap_validator(target):
        return target

    def web_validator(target):
        if target == "example.com":
            return "https://example.com/"
        if target == "8.8.8.8":
            return "https://8.8.8.8/"
        raise ValueError("Not a valid web target")

    def threat_validator(target):
        if target != "8.8.8.8":
            raise ValueError("Only public IPv4 addresses are supported.")
        return target

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "example.com":
            return [
                (2, 1, 6, "", ("8.8.8.8", 0))
            ]
        raise OSError("Mock DNS: unknown host")

    def fake_nmap(target, scan_profile="standard", progress_callback=None, detect_os=False, custom_ports=None):
        calls["nmap"].append(target)
        return {
            "status": "Completed",
            "duration_seconds": 0.1,
            "host_state": "up",
            "ports": [],
            "command_display": "mocked nmap",
            "xml_output": "<nmaprun/>",
        }

    def fake_web(target, approved_scopes=None, profile="standard", run_guard=None, progress_callback=None):
        calls["web"].append(target)
        return {
            "target": target,
            "status_code": 200,
            "headers": [],
            "cookies": [],
            "missing_headers": 0,
            "notes": [],
            "discovery": {
                "errors": (
                    ["Mock discovery failure"]
                    if "8.8.8.8" in target
                    else []
                ),
                "blocked_urls": [],
                "deferred_urls": [],
                "truncated": False,
            },
        }

    def fake_threat(target, progress_callback=None):
        calls["threat"].append(target)
        return {
            "ip": target,
            "found": False,
            "ports": [],
            "hostnames": [],
            "tags": [],
            "vulns": [],
        }

    def fake_zap_scan(target, timeout=300, progress_callback=None):
        calls["zap"].append(target)
        return {
            "status": "finished",
            "spider_scan_id": "1",
            "ascan_scan_id": "2",
        }

    def fake_fetch_alerts(endpoint=None, base_url=None, limit=100):
        calls["zap_alerts"].append((base_url, limit))
        return {"alerts": []}

    class ImmediateThread:
        def __init__(self, target, args=(), kwargs=None, **options):
            self.target = target
            self.args = args
            self.kwargs = kwargs or {}

        def start(self):
            self.target(*self.args, **self.kwargs)

    # Keep this route test deterministic while exercising the real worker.
    monkeypatch.setattr(app_module.threading, "Thread", ImmediateThread)

    monkeypatch.setattr(
        app_module.socket, "getaddrinfo", fake_getaddrinfo
    )
    monkeypatch.setattr(app_module, "validate_target", nmap_validator)
    monkeypatch.setattr(app_module, "_validate_authorized_web_url", web_validator)
    monkeypatch.setattr(app_module, "validate_public_ipv4", threat_validator)
    monkeypatch.setattr(app_module, "run_nmap", fake_nmap)
    monkeypatch.setattr(app_module, "scan_web_security", fake_web)
    monkeypatch.setattr(app_module, "lookup_ip", fake_threat)
    monkeypatch.setattr(zap_proxy_module, "ensure_zap_running", lambda: None)
    monkeypatch.setattr(
        zap_proxy_module, "trigger_zap_active_scan", fake_zap_scan
    )
    monkeypatch.setattr(zap_proxy_module, "fetch_alerts", fake_fetch_alerts)
    monkeypatch.setattr(
        app_module, "generate_web_security_drafts", lambda result, source_record_id=None: 0
    )

    response = client.post(
        "/unified-scan",
        data={
            "authorized": "yes",
            "targets": "example.com\n8.8.8.8",
            "modules": ["nmap", "web_security", "threat_intel", "zap"],
            "nmap_profile": "standard",
        },
    )

    assert response.status_code == 302
    assert "/unified-scan/" in response.headers["Location"]

    assert calls["nmap"] == ["example.com", "8.8.8.8"]
    assert calls["web"] == [
        "https://example.com/",
        "https://8.8.8.8/",
    ]
    assert calls["threat"] == ["8.8.8.8", "8.8.8.8"]
    assert calls["zap"] == [
        "https://example.com/",
        "https://8.8.8.8/",
    ]
    assert calls["zap_alerts"] == [
        ("https://example.com/", 200),
        ("https://8.8.8.8/", 200),
    ]

    with sqlite3.connect(database) as db:
        db.row_factory = sqlite3.Row

        run = db.execute(
            "SELECT * FROM unified_scan_runs"
        ).fetchone()

        assert run["status"] == "Partial"

        batch_ids = json.loads(run["batch_ids_json"])
        assert set(batch_ids) == {"nmap", "web_security", "threat_intel", "zap"}

        expected = {
            "nmap": ["Completed", "Completed"],
            "web_security": ["Completed", "Partial"],
            "threat_intel": ["Completed", "Completed"],
            "zap": ["Completed", "Completed"],
        }

        for module, statuses in expected.items():
            rows = db.execute(
                """
                SELECT status FROM scan_batch_items
                WHERE batch_id = ?
                ORDER BY position
                """,
                (batch_ids[module],),
            ).fetchall()

            assert [row["status"] for row in rows] == statuses


def test_unified_scan_rejects_submission_without_authorization(
    monkeypatch, tmp_path
):
    client, database = setup_test_app(monkeypatch, tmp_path)

    response = client.post(
        "/unified-scan",
        data={
            "targets": "example.com",
            "modules": ["nmap"],
        },
    )

    assert response.status_code == 302

    with sqlite3.connect(database) as db:
        count = db.execute(
            "SELECT COUNT(*) FROM unified_scan_runs"
        ).fetchone()[0]

    assert count == 0


def test_unified_scan_rejects_submission_without_selected_modules(
    monkeypatch, tmp_path
):
    client, database = setup_test_app(monkeypatch, tmp_path)

    response = client.post(
        "/unified-scan",
        data={
            "authorized": "yes",
            "targets": "example.com",
            "modules": [],
        },
    )

    assert response.status_code == 302

    with sqlite3.connect(database) as db:
        count = db.execute(
            "SELECT COUNT(*) FROM unified_scan_runs"
        ).fetchone()[0]

    assert count == 0



def test_unified_target_normalization_allows_internal_nmap_hostname():
    result = app_module.normalize_unified_target(
        "internal.example", "nmap"
    )

    assert result == "internal.example"


def test_private_target_skips_threat_intel_but_runs_other_modules(
    monkeypatch, tmp_path
):
    client, database = setup_test_app(monkeypatch, tmp_path)

    calls = {
        "nmap": [],
        "web": [],
        "firewall": [],
        "threat": [],
    }

    def fake_nmap_validator(target):
        return target

    def fake_web_validator(target):
        return "http://192.168.1.10/"

    def fake_nmap(target, **kwargs):
        calls["nmap"].append(target)
        return {
            "status": "Completed",
            "duration_seconds": 0.01,
            "host_state": "up",
            "ports": [],
            "command_display": "mocked nmap",
            "xml_output": "<nmaprun/>",
        }

    def fake_web(target, approved_scopes=None, profile="standard", run_guard=None, progress_callback=None):
        calls["web"].append(target)
        return {
            "target": target,
            "status_code": 200,
            "headers": [],
            "cookies": [],
            "missing_headers": 0,
            "notes": [],
            "discovery": {
                "errors": [],
                "blocked_urls": [],
                "deferred_urls": [],
                "truncated": False,
            },
        }

    def fake_firewall(target, tcp_ports=None, progress_callback=None):
        calls["firewall"].append((target, tcp_ports))
        return {
            "target": target,
            "duration_seconds": 0.01,
            "tcp_results": [],
            "service_results": [],
            "tls": {"available": False},
            "web": {"checked": False},
            "findings": [],
        }

    def forbidden_threat_lookup(target):
        calls["threat"].append(target)
        raise AssertionError(
            "Threat Intelligence must not receive a private target."
        )

    class ImmediateThread:
        def __init__(self, target, args=(), kwargs=None, **options):
            self.target = target
            self.args = args
            self.kwargs = kwargs or {}

        def start(self):
            self.target(*self.args, **self.kwargs)

    monkeypatch.setattr(app_module.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(app_module, "validate_target", fake_nmap_validator)
    monkeypatch.setattr(
        app_module, "_validate_authorized_web_url", fake_web_validator
    )
    monkeypatch.setattr(app_module, "run_nmap", fake_nmap)
    monkeypatch.setattr(app_module, "scan_web_security", fake_web)
    monkeypatch.setattr(app_module, "scan_firewall", fake_firewall)
    monkeypatch.setattr(
        app_module, "lookup_ip", forbidden_threat_lookup
    )
    monkeypatch.setattr(
        app_module,
        "generate_web_security_drafts",
        lambda result, source_record_id=None: 0,
    )
    monkeypatch.setattr(
        app_module,
        "generate_firewall_drafts",
        lambda result, source_record_id=None: 0,
    )

    response = client.post(
        "/unified-scan",
        data={
            "authorized": "yes",
            "targets": "192.168.1.10",
            "modules": [
                "nmap",
                "web_security",
                "threat_intel",
                "firewall",
            ],
            "nmap_profile": "standard",
        },
    )

    assert response.status_code == 302

    run_id = int(response.headers["Location"].rstrip("/").split("/")[-1])

    assert calls["nmap"] == ["192.168.1.10"]
    assert calls["web"] == ["http://192.168.1.10/"]
    assert calls["firewall"] == [("192.168.1.10", None)]
    assert calls["threat"] == []

    with sqlite3.connect(database) as db:
        db.row_factory = sqlite3.Row

        run = db.execute(
            "SELECT * FROM unified_scan_runs WHERE id = ?",
            (run_id,),
        ).fetchone()

        assert run["status"] == "Completed"

        batch_ids = json.loads(run["batch_ids_json"])
        assert set(batch_ids) == {
            "nmap",
            "web_security",
            "threat_intel",
            "firewall",
        }

        expected = {
            "nmap": "Completed",
            "web_security": "Completed",
            "threat_intel": "Skipped",
            "firewall": "Completed",
        }

        for module, expected_status in expected.items():
            item = db.execute(
                """
                SELECT status, error
                FROM scan_batch_items
                WHERE batch_id = ?
                """,
                (batch_ids[module],),
            ).fetchone()

            assert item["status"] == expected_status

            if module == "threat_intel":
                assert "public IP addresses only" in item["error"]
                assert "private or non-public address" in item["error"]

        threat_batch = db.execute(
            """
            SELECT status, total_targets, completed_targets,
                   partial_targets, failed_targets, skipped_targets
            FROM scan_batches
            WHERE id = ?
            """,
            (batch_ids["threat_intel"],),
        ).fetchone()

        assert threat_batch["status"] == "Completed"
        assert threat_batch["total_targets"] == 1
        assert threat_batch["completed_targets"] == 0
        assert threat_batch["partial_targets"] == 0
        assert threat_batch["failed_targets"] == 0
        assert threat_batch["skipped_targets"] == 1

    progress_response = client.get(
        f"/unified-scan/{run_id}/progress"
    )
    assert progress_response.status_code == 200

    progress_data = progress_response.get_json()
    threat_progress_batch = next(
        batch for batch in progress_data["batches"]
        if batch["module"] == "threat_intel"
    )
    assert threat_progress_batch["skipped_targets"] == 1


def test_unified_web_security_shares_aggregate_guard_across_targets(
    monkeypatch, tmp_path
):
    from scanner.run_limits import UnifiedWebRunGuard

    client, database = setup_test_app(monkeypatch, tmp_path)

    calls = {
        "nmap": [],
        "web": [],
        "guards": [],
    }

    real_guard = UnifiedWebRunGuard(
        maximum_requests=2,
        timeout_seconds=60,
    )

    def fake_guard_factory():
        return real_guard

    def fake_nmap(target, **kwargs):
        calls["nmap"].append(target)
        return {
            "status": "Completed",
            "duration_seconds": 0.01,
            "host_state": "up",
            "ports": [],
            "command_display": "mocked nmap",
            "xml_output": "<nmaprun/>",
        }

    def fake_web(
        target,
        approved_scopes=None,
        profile="standard",
        run_guard=None,
        progress_callback=None,
    ):
        calls["web"].append(target)
        calls["guards"].append(run_guard)

        assert run_guard is not None
        run_guard.consume()

        return {
            "target": target,
            "status_code": 200,
            "headers": [],
            "cookies": [],
            "missing_headers": 0,
            "notes": [],
            "discovery": {
                "errors": [],
                "blocked_urls": [],
                "deferred_urls": [],
                "truncated": False,
            },
        }

    class ImmediateThread:
        def __init__(self, target, args=(), kwargs=None, **options):
            self.target = target
            self.args = args
            self.kwargs = kwargs or {}

        def start(self):
            self.target(*self.args, **self.kwargs)

    monkeypatch.setattr(
        app_module.threading, "Thread", ImmediateThread
    )
    monkeypatch.setattr(
        app_module, "UnifiedWebRunGuard", fake_guard_factory
    )
    monkeypatch.setattr(
        app_module, "validate_target", lambda target: target
    )
    monkeypatch.setattr(
        app_module,
        "_validate_authorized_web_url",
        lambda target: f"http://{target}/",
    )
    monkeypatch.setattr(app_module, "run_nmap", fake_nmap)
    monkeypatch.setattr(app_module, "scan_web_security", fake_web)
    monkeypatch.setattr(
        app_module,
        "generate_web_security_drafts",
        lambda result, source_record_id=None: 0,
    )

    targets = [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
    ]

    response = client.post(
        "/unified-scan",
        data={
            "authorized": "yes",
            "targets": "\n".join(targets),
            "modules": ["nmap", "web_security"],
            "nmap_profile": "standard",
        },
    )

    assert response.status_code == 302

    run_id = int(response.headers["Location"].rstrip("/").split("/")[-1])

    # Network assessment remains independent of the Web Security budget.
    assert calls["nmap"] == targets

    # Only the first two Web Security targets are dispatched.
    assert calls["web"] == [
        "http://192.168.1.10/",
        "http://192.168.1.11/",
    ]

    # Both dispatched targets received the exact same guard instance.
    assert len(calls["guards"]) == 2
    assert calls["guards"][0] is real_guard
    assert calls["guards"][1] is real_guard
    assert calls["guards"][0] is calls["guards"][1]
    assert real_guard.used_requests == 2

    with sqlite3.connect(database) as db:
        db.row_factory = sqlite3.Row

        run = db.execute(
            "SELECT * FROM unified_scan_runs WHERE id = ?",
            (run_id,),
        ).fetchone()

        assert run["status"] == "Partial"

        batch_ids = json.loads(run["batch_ids_json"])

        expected = {
            "nmap": ["Completed", "Completed", "Completed"],
            "web_security": ["Completed", "Completed", "Skipped"],
        }

        for module, expected_statuses in expected.items():
            rows = db.execute(
                """
                SELECT status, error
                FROM scan_batch_items
                WHERE batch_id = ?
                ORDER BY position
                """,
                (batch_ids[module],),
            ).fetchall()

            assert [row["status"] for row in rows] == expected_statuses

            if module == "web_security":
                assert "request limit exhausted" in rows[2]["error"].lower()

def test_zap_target_normalization_uses_authorized_web_validator(monkeypatch):
    calls = []

    def fake_authorized_web_validator(target):
        calls.append(target)
        return "normalized:" + target

    monkeypatch.setattr(
        app_module,
        "_validate_authorized_web_url",
        fake_authorized_web_validator,
    )

    targets = [
        "http://127.0.0.1:5000",
        "https://192.168.1.10",
        "http://example.com",
    ]

    for target in targets:
        assert app_module.normalize_unified_target(target, "zap") == (
            "normalized:" + target
        )

    assert calls == targets

def test_dashboard_shows_zap_batch_view_action(monkeypatch, tmp_path):
    client, database = setup_test_app(monkeypatch, tmp_path)

    app_module.initialize_automatic_risks()
    app_module.init_risk_db()

    with sqlite3.connect(database) as db:
        cursor = db.execute(
            """
            INSERT INTO scan_batches (
                module, profile, status, total_targets,
                completed_targets, created_at, finished_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "zap", "standard", "Completed", 1,
                1, "2026-11-18T12:00:00", "2026-11-18T12:01:00",
            ),
        )
        batch_id = cursor.lastrowid

        db.execute(
            """
            INSERT INTO scan_batch_items (
                batch_id, position, target, status, result_type
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                batch_id, 1, "http://127.0.0.1:5000",
                "Completed", "zap",
            ),
        )

    response = client.get("/")

    assert response.status_code == 200
    assert b"OWASP ZAP" in response.data
    assert (
        f'href="/zap/batches/{batch_id}"'.encode()
        in response.data
    )
