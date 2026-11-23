import app as app_module


def test_server_mac_uses_interface_matching_current_server_ip(monkeypatch):
    monkeypatch.setattr(
        app_module.psutil, "net_if_addrs",
        lambda: {"lo": [], "eth0": [], "wlan0": []},
    )

    addresses = {
        "lo": "127.0.0.1",
        "eth0": "192.168.29.88",
        "wlan0": "192.168.50.10",
    }
    macs = {
        "lo": "00:00:00:00:00:00",
        "eth0": "02:11:22:33:44:55",
        "wlan0": "02:aa:bb:cc:dd:ee",
    }

    monkeypatch.setattr(
        app_module, "_get_interface_ipv4",
        lambda interface: addresses.get(interface),
    )
    monkeypatch.setattr(
        app_module, "_read_interface_mac",
        lambda interface: macs.get(interface),
    )

    assert app_module.get_interface_mac_for_ip("192.168.29.88") == (
        "02:11:22:33:44:55"
    )


def test_server_mac_changes_when_active_interface_changes(monkeypatch):
    monkeypatch.setattr(
        app_module.psutil, "net_if_addrs",
        lambda: {"eth0": [], "wlan0": []},
    )

    addresses = {
        "eth0": "192.168.29.88",
        "wlan0": "192.168.50.10",
    }
    macs = {
        "eth0": "02:11:22:33:44:55",
        "wlan0": "02:aa:bb:cc:dd:ee",
    }

    monkeypatch.setattr(
        app_module, "_get_interface_ipv4",
        lambda interface: addresses.get(interface),
    )
    monkeypatch.setattr(
        app_module, "_read_interface_mac",
        lambda interface: macs.get(interface),
    )

    assert app_module.get_interface_mac_for_ip("192.168.50.10") == (
        "02:aa:bb:cc:dd:ee"
    )


def test_server_mac_is_unavailable_when_no_interface_matches(monkeypatch):
    monkeypatch.setattr(
        app_module.psutil, "net_if_addrs",
        lambda: {"lo": []},
    )
    monkeypatch.setattr(
        app_module, "_get_interface_ipv4",
        lambda interface: "127.0.0.1",
    )

    assert app_module.get_interface_mac_for_ip("192.168.29.88") == (
        "Unavailable"
    )


def test_neighbor_mac_is_parsed_from_exact_ip_entry(monkeypatch):
    class Result:
        returncode = 0
        stdout = (
            "192.168.29.120 dev eth0 lladdr 02:12:34:56:78:9a "
            "REACHABLE\n"
        )
        stderr = ""

    monkeypatch.setattr(
        app_module.subprocess, "run",
        lambda *args, **kwargs: Result(),
    )

    assert app_module.get_neighbor_mac("192.168.29.120") == (
        "02:12:34:56:78:9a"
    )


def test_neighbor_mac_is_unavailable_when_entry_is_missing(monkeypatch):
    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(
        app_module.subprocess, "run",
        lambda *args, **kwargs: Result(),
    )

    assert app_module.get_neighbor_mac("192.168.29.120") == (
        "Unavailable"
    )


def test_neighbor_lookup_rejects_invalid_ip():
    assert app_module.get_neighbor_mac("not-an-ip") == "Unavailable"


def test_connection_details_use_host_agent_interface(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "get_host_network_interfaces",
        lambda: [
            {
                "name": "docker0",
                "address": "172.18.0.2",
                "mac_address": "ce:dc:2f:2e:c3:a5",
                "gateway": None,
            },
            {
                "name": "eth0",
                "address": "192.168.29.88",
                "mac_address": "00:0c:29:4b:b3:0b",
                "gateway": "192.168.29.1",
            },
        ],
    )
    monkeypatch.setattr(
        app_module,
        "get_neighbor_mac",
        lambda address: "Unavailable",
    )

    with app_module.app.test_request_context("/"):
        details = app_module.get_connection_details()

    assert details["server_lan_ip"] == "192.168.29.88"
    assert details["server_mac_address"] == "00:0c:29:4b:b3:0b"
    assert details["client_mac_address"] == "Unavailable"


def test_server_mac_uses_interface_matching_current_server_ipv6(monkeypatch):
    monkeypatch.setattr(
        app_module.socket, "if_nameindex",
        lambda: [(1, "lo"), (2, "eth0")],
    )
    monkeypatch.setattr(
        app_module, "_get_interface_ipv6",
        lambda interface: {
            "lo": "::1",
            "eth0": "2001:db8::88",
        }.get(interface),
        raising=False,
    )
    monkeypatch.setattr(
        app_module, "_read_interface_mac",
        lambda interface: "02:11:22:33:44:55" if interface == "eth0"
        else "Unavailable",
    )

    assert app_module.get_interface_mac_for_ip("2001:db8::88") == (
        "02:11:22:33:44:55"
    )


def test_windows_style_interface_mac_is_normalized(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(
        app_module.socket,
        "if_nameindex",
        lambda: [(1, "Ethernet")],
    )
    monkeypatch.setattr(
        app_module.psutil,
        "net_if_addrs",
        lambda: {
            "Ethernet": [
                SimpleNamespace(
                    family=app_module.socket.AF_INET,
                    address="192.168.29.194",
                ),
                SimpleNamespace(
                    family=app_module.psutil.AF_LINK,
                    address="A0-B1-C2-D3-E4-F5",
                ),
            ]
        },
    )

    assert app_module.get_interface_mac_for_ip("192.168.29.194") == (
        "a0:b1:c2:d3:e4:f5"
    )


def test_server_mac_matches_correct_adapter_on_windows(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(
        app_module.socket,
        "if_nameindex",
        lambda: [(1, "Ethernet"), (2, "Wi-Fi")],
    )
    monkeypatch.setattr(
        app_module.psutil,
        "net_if_addrs",
        lambda: {
            "Ethernet": [
                SimpleNamespace(
                    family=app_module.socket.AF_INET,
                    address="192.168.29.194",
                ),
                SimpleNamespace(
                    family=app_module.psutil.AF_LINK,
                    address="A0-B1-C2-D3-E4-F5",
                ),
            ],
            "Wi-Fi": [
                SimpleNamespace(
                    family=app_module.socket.AF_INET,
                    address="192.168.50.10",
                ),
                SimpleNamespace(
                    family=app_module.psutil.AF_LINK,
                    address="10-20-30-40-50-60",
                ),
            ],
        },
    )

    assert app_module.get_interface_mac_for_ip("192.168.29.194") == (
        "a0:b1:c2:d3:e4:f5"
    )
    assert app_module.get_interface_mac_for_ip("192.168.50.10") == (
        "10:20:30:40:50:60"
    )
