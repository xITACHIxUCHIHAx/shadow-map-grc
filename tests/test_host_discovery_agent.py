import pytest

from scanner import host_discovery_agent as agent


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(agent, "TOKEN", "test-agent-token")
    return agent.app.test_client()


@pytest.fixture
def auth_headers():
    return {"Authorization": "Bearer test-agent-token"}


def test_health_requires_authentication(client):
    response = client.get("/health")

    assert response.status_code == 401
    assert response.get_json()["error"] == "Unauthorized"


def test_health_returns_ok(client, auth_headers):
    response = client.get("/health", headers=auth_headers)

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_interfaces_returns_host_interfaces(
    client, auth_headers, monkeypatch
):
    expected = [
        {
            "name": "eth0",
            "ip_address": "192.168.1.10",
            "subnet": "192.168.1.0/24",
        }
    ]
    monkeypatch.setattr(
        agent, "get_network_interfaces", lambda: expected
    )

    response = client.get("/interfaces", headers=auth_headers)

    assert response.status_code == 200
    assert response.get_json() == {"interfaces": expected}


def test_interfaces_reports_discovery_error(
    client, auth_headers, monkeypatch
):
    def fail():
        raise agent.NetworkDiscoveryError("Interface lookup failed.")

    monkeypatch.setattr(agent, "get_network_interfaces", fail)

    response = client.get("/interfaces", headers=auth_headers)

    assert response.status_code == 400
    assert response.get_json()["error"] == "Interface lookup failed."


def test_scan_rejects_missing_json(client, auth_headers):
    response = client.post(
        "/scan",
        data="not-json",
        content_type="text/plain",
        headers=auth_headers,
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "A JSON request is required."


def test_scan_requires_explicit_authorization(client, auth_headers):
    response = client.post(
        "/scan",
        json={
            "interface": "eth0",
            "subnet": "192.168.1.0/24",
            "authorized": False,
        },
        headers=auth_headers,
    )

    assert response.status_code == 403
    assert "authorization" in response.get_json()["error"].lower()


def test_scan_rejects_invalid_interface_or_subnet(client, auth_headers):
    response = client.post(
        "/scan",
        json={
            "interface": 123,
            "subnet": "192.168.1.0/24",
            "authorized": True,
        },
        headers=auth_headers,
    )

    assert response.status_code == 400
    assert "interface and subnet" in response.get_json()["error"].lower()


def test_scan_forwards_authorized_request(
    client, auth_headers, monkeypatch
):
    expected = {
        "subnet": "192.168.1.0/24",
        "interface": "eth0",
        "devices": [],
        "devices_found": 0,
    }
    calls = []

    def fake_discover_hosts(subnet, interface, authorized=False):
        calls.append((subnet, interface, authorized))
        return expected

    monkeypatch.setattr(agent, "discover_hosts", fake_discover_hosts)

    response = client.post(
        "/scan",
        json={
            "interface": "eth0",
            "subnet": "192.168.1.0/24",
            "authorized": True,
        },
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.get_json() == expected
    assert calls == [("192.168.1.0/24", "eth0", True)]


def test_scan_reports_discovery_error(
    client, auth_headers, monkeypatch
):
    def fail(*args, **kwargs):
        raise agent.NetworkDiscoveryError("Discovery failed.")

    monkeypatch.setattr(agent, "discover_hosts", fail)

    response = client.post(
        "/scan",
        json={
            "interface": "eth0",
            "subnet": "192.168.1.0/24",
            "authorized": True,
        },
        headers=auth_headers,
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Discovery failed."



def test_agent_port_validation():
    assert agent._validated_port("5001") == 5001
    for value in ("0", "65536", "invalid"):
        with pytest.raises(RuntimeError):
            agent._validated_port(value)
