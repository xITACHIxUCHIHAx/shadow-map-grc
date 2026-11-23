import json
import sqlite3

import app as app_module
import pytest

from grc import network_discovery as network_routes
from scanner.network_discovery import NetworkDiscoveryError


SAMPLE_INTERFACES = [
    {
        "name": "eth0",
        "address": "192.168.1.10",
        "prefix_length": 24,
        "network": "192.168.1.0/24",
        "gateway": "192.168.1.1",
    }
]

SAMPLE_DEVICES = [
    {
        "ip_address": "192.168.1.1",
        "mac_address": "AA:BB:CC:DD:EE:01",
        "vendor": "Example Vendor",
        "hostnames": ["router.local"],
        "status": "up",
        "device_type": "router",
        "classification_confidence": "medium",
        "classification_evidence": ["Hostname suggests a router."],
        "open_ports": [
            {
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "9.2",
                "extrainfo": "",
            },
            {
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "product": "nginx",
                "version": "1.24",
                "extrainfo": "",
            },
        ],
    }
]


def setup_network_discovery_app(monkeypatch, tmp_path):
    database = tmp_path / "network-discovery-test.db"

    monkeypatch.setattr(app_module, "DATABASE_PATH", database)
    monkeypatch.setattr(network_routes, "DATABASE_PATH", database)

    app_module.app.config.update(TESTING=True)
    app_module.init_db()

    return app_module.app.test_client(), database


def test_network_monitor_initialization_is_repeatable(tmp_path):
    database = tmp_path / "network-monitor-init.db"

    network_routes.initialize_network_discovery(database)
    network_routes.initialize_network_discovery(database)

    with sqlite3.connect(database) as db:
        tables = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }

        columns = {
            row[1]
            for row in db.execute(
                "PRAGMA table_info(discovered_devices)"
            ).fetchall()
        }

    assert "network_discovery_runs" in tables
    assert "discovered_devices" in tables
    assert "network_discovery_run_devices" in tables
    assert "network_observations" not in tables
    assert "open_ports_json" in columns
    assert "mac_source" in columns
    assert "mac_neighbour_state" in columns


def test_existing_observation_table_and_records_are_preserved(tmp_path):
    database = tmp_path / "network-monitor-legacy.db"

    with sqlite3.connect(database) as db:
        db.executescript("""
            CREATE TABLE network_discovery_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                interface_name TEXT NOT NULL,
                subnet TEXT NOT NULL,
                status TEXT NOT NULL,
                devices_found INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                error TEXT
            );

            CREATE TABLE discovered_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                interface_name TEXT NOT NULL,
                subnet TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                vendor TEXT,
                hostnames_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'up',
                device_type TEXT NOT NULL DEFAULT 'unknown',
                classification_confidence TEXT NOT NULL DEFAULT 'low',
                classification_evidence_json TEXT NOT NULL DEFAULT '[]',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_discovery_run_id INTEGER,
                UNIQUE(interface_name, ip_address)
            );

            CREATE TABLE network_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                observation_type TEXT
            );

            INSERT INTO network_discovery_runs (
                interface_name, subnet, status, devices_found,
                started_at, finished_at
            ) VALUES (
                'eth0', '192.168.1.0/24', 'completed', 1,
                '2026-11-15T10:00:00+00:00',
                '2026-11-15T10:00:00+00:00'
            );

            INSERT INTO discovered_devices (
                interface_name, subnet, ip_address, mac_address,
                vendor, hostnames_json, status, device_type,
                classification_confidence,
                classification_evidence_json,
                first_seen, last_seen, last_discovery_run_id
            ) VALUES (
                'eth0', '192.168.1.0/24', '192.168.1.5',
                'AA:BB:CC:DD:EE:05', 'Legacy Vendor',
                '["legacy.local"]', 'up', 'unknown', 'low',
                '[]', '2026-11-15T10:00:00+00:00',
                '2026-11-15T10:00:00+00:00', 1
            );

            INSERT INTO network_observations (observation_type)
            VALUES ('legacy-record');
        """)

    network_routes.initialize_network_discovery(database)

    with sqlite3.connect(database) as db:
        columns = {
            row[1]
            for row in db.execute(
                "PRAGMA table_info(discovered_devices)"
            ).fetchall()
        }

        observation_count = db.execute(
            "SELECT COUNT(*) FROM network_observations"
        ).fetchone()[0]

        run_count = db.execute(
            "SELECT COUNT(*) FROM network_discovery_runs"
        ).fetchone()[0]

    assert "open_ports_json" in columns
    assert observation_count == 1
    assert run_count == 1

    devices = network_routes.get_discovered_devices(database)
    assert len(devices) == 1
    assert devices[0]["ip_address"] == "192.168.1.5"
    assert devices[0]["mac_address"] == "AA:BB:CC:DD:EE:05"
    assert devices[0]["status"] == "online"
    assert devices[0]["open_ports"] == []


def test_successful_discovery_persists_run_device_and_open_ports(tmp_path):
    database = tmp_path / "network-discovery-save.db"
    network_routes.initialize_network_discovery(database)

    run_id = network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        SAMPLE_DEVICES,
        database_path=database,
    )

    devices = network_routes.get_discovered_devices(database)

    assert len(devices) == 1

    device = devices[0]
    assert device["ip_address"] == "192.168.1.1"
    assert device["mac_address"] == "AA:BB:CC:DD:EE:01"
    assert device["vendor"] == "Example Vendor"
    assert device["hostnames"] == ["router.local"]
    assert device["classification_evidence"] == [
        "Hostname suggests a router."
    ]
    assert device["status"] == "online"
    assert device["open_ports"] == SAMPLE_DEVICES[0]["open_ports"]

    runs = network_routes.get_recent_discovery_runs(
        database_path=database
    )

    assert len(runs) == 1
    assert runs[0]["id"] == run_id
    assert runs[0]["status"] == "completed"
    assert runs[0]["devices_found"] == 1


def test_rediscovery_updates_device_without_losing_mac_or_vendor(
    monkeypatch, tmp_path
):
    database = tmp_path / "network-discovery-upsert.db"
    network_routes.initialize_network_discovery(database)

    timestamps = iter([
        "2026-11-16T10:00:00+00:00",
        "2026-11-16T11:00:00+00:00",
    ])
    monkeypatch.setattr(
        network_routes,
        "now_utc",
        lambda: next(timestamps),
    )

    network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        SAMPLE_DEVICES,
        database_path=database,
    )

    second_observation = [
        {
            "ip_address": "192.168.1.1",
            "mac_address": None,
            "vendor": None,
            "hostnames": ["gateway.local"],
            "status": "up",
            "device_type": "unknown",
            "classification_confidence": "low",
            "classification_evidence": ["Host responded to discovery."],
            "open_ports": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "nginx",
                    "version": "",
                    "extrainfo": "",
                }
            ],
        }
    ]

    network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        second_observation,
        database_path=database,
    )

    devices = network_routes.get_discovered_devices(database)
    assert len(devices) == 1

    device = devices[0]
    assert device["mac_address"] is None
    assert device["vendor"] is None
    assert device["mac_source"] == "unavailable"
    assert device["mac_neighbour_state"] is None
    assert device["hostnames"] == ["gateway.local"]
    assert device["open_ports"] == second_observation[0]["open_ports"]
    assert device["status"] == "online"
    assert device["first_seen"] == "2026-11-16T10:00:00+00:00"
    assert device["last_seen"] == "2026-11-16T11:00:00+00:00"

    with sqlite3.connect(database) as db:
        run_count = db.execute(
            "SELECT COUNT(*) FROM network_discovery_runs"
        ).fetchone()[0]

        device_count = db.execute(
            "SELECT COUNT(*) FROM discovered_devices"
        ).fetchone()[0]

    assert run_count == 2
    assert device_count == 1

    first_run = network_routes.get_discovery_run_details(
        1, database_path=database
    )
    assert first_run["devices"][0]["mac_address"] == "AA:BB:CC:DD:EE:01"


def test_successful_scan_marks_missing_devices_not_recently_seen(tmp_path):
    database = tmp_path / "network-monitor-missing.db"
    network_routes.initialize_network_discovery(database)

    network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        SAMPLE_DEVICES,
        database_path=database,
    )

    network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        [],
        database_path=database,
    )

    devices = network_routes.get_discovered_devices(database)

    assert devices == []


def test_missing_device_status_is_scoped_to_interface_and_subnet(tmp_path):
    database = tmp_path / "network-monitor-scope.db"
    network_routes.initialize_network_discovery(database)

    network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        SAMPLE_DEVICES,
        database_path=database,
    )

    network_routes.save_discovery_run(
        "wlan0",
        "192.168.1.0/24",
        SAMPLE_DEVICES,
        database_path=database,
    )

    network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        [],
        database_path=database,
    )

    devices = network_routes.get_discovered_devices(database)

    # The latest successful scan was empty, so current inventory is empty.
    assert devices == []


def test_failed_scan_does_not_change_existing_device_status(tmp_path):
    database = tmp_path / "network-monitor-failed-status.db"
    network_routes.initialize_network_discovery(database)

    network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        SAMPLE_DEVICES,
        database_path=database,
    )

    network_routes.save_failed_discovery_run(
        "eth0",
        "192.168.1.0/24",
        "Nmap discovery timed out.",
        database_path=database,
    )

    devices = network_routes.get_discovered_devices(database)

    assert len(devices) == 1
    assert devices[0]["status"] == "online"


def test_failed_discovery_is_recorded_without_creating_devices(tmp_path):
    database = tmp_path / "network-discovery-failure.db"
    network_routes.initialize_network_discovery(database)

    run_id = network_routes.save_failed_discovery_run(
        "eth0",
        "192.168.1.0/24",
        "Nmap discovery timed out.",
        database_path=database,
    )

    runs = network_routes.get_recent_discovery_runs(
        database_path=database
    )

    assert len(runs) == 1
    assert runs[0]["id"] == run_id
    assert runs[0]["status"] == "failed"
    assert runs[0]["devices_found"] == 0
    assert runs[0]["error"] == "Nmap discovery timed out."

    assert network_routes.get_discovered_devices(database) == []


def test_recent_runs_reject_invalid_limits(tmp_path):
    database = tmp_path / "network-monitor-limits.db"
    network_routes.initialize_network_discovery(database)

    for invalid_limit in (0, -1, True, "10"):
        with pytest.raises(ValueError):
            network_routes.get_recent_discovery_runs(
                limit=invalid_limit,
                database_path=database,
            )


def test_network_monitor_page_renders(
    monkeypatch, tmp_path
):
    client, _ = setup_network_discovery_app(monkeypatch, tmp_path)

    monkeypatch.setattr(
        network_routes,
        "get_network_interfaces",
        lambda: SAMPLE_INTERFACES,
    )

    response = client.get("/network-discovery/")

    assert response.status_code == 200
    assert b"eth0" in response.data


def test_post_without_authorization_does_not_start_discovery(
    monkeypatch, tmp_path
):
    client, database = setup_network_discovery_app(monkeypatch, tmp_path)

    monkeypatch.setattr(
        network_routes,
        "get_network_interfaces",
        lambda: SAMPLE_INTERFACES,
    )

    def unexpected_discovery(*args, **kwargs):
        pytest.fail("Discovery must not run without authorization.")

    monkeypatch.setattr(
        network_routes,
        "discover_hosts",
        unexpected_discovery,
    )

    response = client.post(
        "/network-discovery/",
        data={
            "interface": "eth0",
            "subnet": "192.168.1.0/24",
        },
    )

    assert response.status_code == 200

    with sqlite3.connect(database) as db:
        run_count = db.execute(
            "SELECT COUNT(*) FROM network_discovery_runs"
        ).fetchone()[0]

    assert run_count == 0


def test_post_success_runs_discovery_and_persists_results(
    monkeypatch, tmp_path
):
    client, database = setup_network_discovery_app(monkeypatch, tmp_path)

    monkeypatch.setattr(
        network_routes,
        "get_network_interfaces",
        lambda: SAMPLE_INTERFACES,
    )

    calls = []

    def fake_discover_hosts(subnet, interface, authorized=False):
        calls.append((subnet, interface, authorized))
        return {
            "subnet": subnet,
            "interface": interface,
            "devices": SAMPLE_DEVICES,
            "devices_found": len(SAMPLE_DEVICES),
        }

    monkeypatch.setattr(
        network_routes,
        "discover_hosts",
        fake_discover_hosts,
    )

    response = client.post(
        "/network-discovery/",
        data={
            "authorized": "yes",
            "interface": "eth0",
            "subnet": "192.168.1.0/24",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/network-discovery/")
    assert calls == [("192.168.1.0/24", "eth0", True)]

    devices = network_routes.get_discovered_devices(database)
    assert len(devices) == 1
    assert devices[0]["ip_address"] == "192.168.1.1"
    assert devices[0]["status"] == "online"
    assert devices[0]["open_ports"] == SAMPLE_DEVICES[0]["open_ports"]

    runs = network_routes.get_recent_discovery_runs(
        database_path=database
    )
    assert len(runs) == 1
    assert runs[0]["status"] == "completed"


def test_post_records_scanner_failure(
    monkeypatch, tmp_path
):
    client, database = setup_network_discovery_app(monkeypatch, tmp_path)

    monkeypatch.setattr(
        network_routes,
        "get_network_interfaces",
        lambda: SAMPLE_INTERFACES,
    )

    def failed_discovery(*args, **kwargs):
        raise NetworkDiscoveryError("Mocked discovery failure.")

    monkeypatch.setattr(
        network_routes,
        "discover_hosts",
        failed_discovery,
    )

    response = client.post(
        "/network-discovery/",
        data={
            "authorized": "yes",
            "interface": "eth0",
            "subnet": "192.168.1.0/24",
        },
    )

    assert response.status_code == 200

    runs = network_routes.get_recent_discovery_runs(
        database_path=database
    )

    assert len(runs) == 1
    assert runs[0]["status"] == "failed"
    assert runs[0]["error"] == "Mocked discovery failure."

    assert network_routes.get_discovered_devices(database) == []


def test_historical_snapshot_remains_unchanged_after_rediscovery(tmp_path):
    database = tmp_path / "network-monitor-history.db"
    network_routes.initialize_network_discovery(database)

    first_run_id = network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        SAMPLE_DEVICES,
        database_path=database,
    )

    changed_devices = [
        {
            "ip_address": "192.168.1.1",
            "mac_address": None,
            "vendor": None,
            "hostnames": ["gateway.local"],
            "status": "up",
            "device_type": "unknown",
            "classification_confidence": "low",
            "classification_evidence": ["Host responded to discovery."],
            "open_ports": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "nginx",
                    "version": "1.26",
                    "extrainfo": "",
                }
            ],
        }
    ]

    second_run_id = network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        changed_devices,
        database_path=database,
    )

    first_details = network_routes.get_discovery_run_details(
        first_run_id,
        database_path=database,
    )
    second_details = network_routes.get_discovery_run_details(
        second_run_id,
        database_path=database,
    )

    assert first_details["run"]["status"] == "completed"
    assert first_details["devices"] == SAMPLE_DEVICES

    assert second_details["run"]["status"] == "completed"
    assert second_details["devices"] == changed_devices

    network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        [],
        database_path=database,
    )

    first_details_after_empty_scan = (
        network_routes.get_discovery_run_details(
            first_run_id,
            database_path=database,
        )
    )

    assert first_details_after_empty_scan["devices"] == SAMPLE_DEVICES



def test_current_inventory_shows_latest_scan_only_and_preserves_history(tmp_path):
    database = tmp_path / "network-monitor-current-inventory.db"
    network_routes.initialize_network_discovery(database)

    first_run_id = network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        SAMPLE_DEVICES,
        database_path=database,
    )

    current_devices = [SAMPLE_DEVICES[0]]

    second_run_id = network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        current_devices,
        database_path=database,
    )

    inventory = network_routes.get_discovered_devices(
        database_path=database,
    )

    assert [device["ip_address"] for device in inventory] == [
        "192.168.1.1"
    ]

    first_history = network_routes.get_discovery_run_details(
        first_run_id,
        database_path=database,
    )
    second_history = network_routes.get_discovery_run_details(
        second_run_id,
        database_path=database,
    )

    assert first_history["devices"] == SAMPLE_DEVICES
    assert second_history["devices"] == current_devices


def test_successful_empty_scan_has_empty_historical_snapshot(tmp_path):
    database = tmp_path / "network-monitor-empty-history.db"
    network_routes.initialize_network_discovery(database)

    run_id = network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        [],
        database_path=database,
    )

    details = network_routes.get_discovery_run_details(
        run_id,
        database_path=database,
    )

    assert details is not None
    assert details["run"]["status"] == "completed"
    assert details["devices"] == []


def test_failed_scan_has_error_but_no_device_snapshot(tmp_path):
    database = tmp_path / "network-monitor-failed-history.db"
    network_routes.initialize_network_discovery(database)

    run_id = network_routes.save_failed_discovery_run(
        "eth0",
        "192.168.1.0/24",
        "Nmap discovery timed out.",
        database_path=database,
    )

    details = network_routes.get_discovery_run_details(
        run_id,
        database_path=database,
    )

    assert details is not None
    assert details["run"]["status"] == "failed"
    assert details["run"]["error"] == "Nmap discovery timed out."
    assert details["devices"] == []


def test_missing_historical_run_returns_none(tmp_path):
    database = tmp_path / "network-monitor-missing-history.db"
    network_routes.initialize_network_discovery(database)

    assert network_routes.get_discovery_run_details(
        999,
        database_path=database,
    ) is None



def test_completed_run_details_page_displays_historical_devices(
    monkeypatch, tmp_path
):
    client, database = setup_network_discovery_app(monkeypatch, tmp_path)

    run_id = network_routes.save_discovery_run(
        "eth0",
        "192.168.1.0/24",
        SAMPLE_DEVICES,
        database_path=database,
    )

    response = client.get(f"/network-discovery/runs/{run_id}")

    assert response.status_code == 200
    assert b"192.168.1.1" in response.data
    assert b"router.local" in response.data
    assert b"Example Vendor" in response.data
    assert b"OpenSSH" in response.data
    assert b"nginx" in response.data


def test_failed_run_details_page_displays_error(
    monkeypatch, tmp_path
):
    client, database = setup_network_discovery_app(monkeypatch, tmp_path)

    error_message = "Nmap discovery timed out."

    run_id = network_routes.save_failed_discovery_run(
        "eth0",
        "192.168.1.0/24",
        error_message,
        database_path=database,
    )

    response = client.get(f"/network-discovery/runs/{run_id}")

    assert response.status_code == 200
    assert b"Nmap discovery timed out." in response.data


def test_missing_run_details_page_returns_404(
    monkeypatch, tmp_path
):
    client, _ = setup_network_discovery_app(monkeypatch, tmp_path)

    response = client.get("/network-discovery/runs/99999")

    assert response.status_code == 404


def test_host_agent_interfaces_are_used_by_network_monitor(
    monkeypatch, tmp_path
):
    client, _ = setup_network_discovery_app(monkeypatch, tmp_path)

    monkeypatch.setenv(
        "SHADOW_MAP_HOST_AGENT_URL", "http://172.18.0.1:5001"
    )
    monkeypatch.setenv("SHADOW_MAP_HOST_AGENT_TOKEN", "test-agent-token")

    calls = []

    class FakeResponse:
        ok = True
        status_code = 200

        def json(self):
            return {"interfaces": SAMPLE_INTERFACES}

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return FakeResponse()

    monkeypatch.setattr(network_routes.requests, "request", fake_request)

    response = client.get("/network-discovery/")

    assert response.status_code == 200
    assert b"eth0" in response.data
    assert len(calls) == 1
    assert calls[0][0] == "GET"
    assert calls[0][1].endswith("/interfaces")
    assert calls[0][2]["headers"]["Authorization"] == (
        "Bearer test-agent-token"
    )


def test_host_agent_scan_is_forwarded_and_persisted(
    monkeypatch, tmp_path
):
    client, database = setup_network_discovery_app(monkeypatch, tmp_path)

    monkeypatch.setenv(
        "SHADOW_MAP_HOST_AGENT_URL", "http://172.18.0.1:5001"
    )
    monkeypatch.setenv("SHADOW_MAP_HOST_AGENT_TOKEN", "test-agent-token")

    calls = []

    class FakeResponse:
        ok = True
        status_code = 200

        def __init__(self, payload):
            self.payload = payload

        def json(self):
            return self.payload

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))

        if url.endswith("/interfaces"):
            return FakeResponse({"interfaces": SAMPLE_INTERFACES})

        return FakeResponse({
            "subnet": "192.168.1.0/24",
            "interface": "eth0",
            "devices": SAMPLE_DEVICES,
            "devices_found": len(SAMPLE_DEVICES),
        })

    monkeypatch.setattr(network_routes.requests, "request", fake_request)

    response = client.post(
        "/network-discovery/",
        data={
            "authorized": "yes",
            "interface": "eth0",
            "subnet": "192.168.1.0/24",
        },
    )

    assert response.status_code == 302
    assert [call[0] for call in calls] == ["GET", "POST"]
    assert calls[1][1].endswith("/scan")
    assert calls[1][2]["headers"]["Authorization"] == (
        "Bearer test-agent-token"
    )
    assert calls[1][2]["json"] == {
        "interface": "eth0",
        "subnet": "192.168.1.0/24",
        "authorized": True,
    }

    devices = network_routes.get_discovered_devices(database)
    assert len(devices) == 1
    assert devices[0]["ip_address"] == "192.168.1.1"

    runs = network_routes.get_recent_discovery_runs(
        database_path=database
    )
    assert len(runs) == 1
    assert runs[0]["status"] == "completed"


def test_host_agent_connection_failure_is_recorded_safely(
    monkeypatch, tmp_path
):
    client, database = setup_network_discovery_app(monkeypatch, tmp_path)

    monkeypatch.setenv(
        "SHADOW_MAP_HOST_AGENT_URL", "http://172.18.0.1:5001"
    )
    monkeypatch.setenv("SHADOW_MAP_HOST_AGENT_TOKEN", "test-agent-token")

    class FakeResponse:
        ok = True
        status_code = 200

        def json(self):
            return {"interfaces": SAMPLE_INTERFACES}

    def fake_request(method, url, **kwargs):
        if url.endswith("/interfaces"):
            return FakeResponse()
        raise network_routes.requests.ConnectionError(
            "Mocked host-agent connection failure."
        )

    monkeypatch.setattr(network_routes.requests, "request", fake_request)

    response = client.post(
        "/network-discovery/",
        data={
            "authorized": "yes",
            "interface": "eth0",
            "subnet": "192.168.1.0/24",
        },
    )

    assert response.status_code == 200

    runs = network_routes.get_recent_discovery_runs(
        database_path=database
    )
    assert len(runs) == 1
    assert runs[0]["status"] == "failed"
    assert "Could not contact the host discovery agent" in runs[0]["error"]

    assert network_routes.get_discovered_devices(database) == []
