from types import SimpleNamespace
from unittest.mock import patch

import pytest

from scanner import live_ping


@pytest.mark.parametrize(
    ("platform", "expected"),
    [
        (
            "win32",
            ["ping.exe", "-n", "1", "-w", "2000", "192.168.1.10"],
        ),
        (
            "linux",
            ["ping", "-n", "-c", "1", "-W", "2", "-3", "192.168.1.10"],
        ),
        (
            "darwin",
            ["ping", "-n", "-c", "1", "-W", "2000", "192.168.1.10"],
        ),
    ],
)
def test_build_ping_command(platform, expected):
    binary = "ping.exe" if platform == "win32" else "ping"

    assert live_ping._build_ping_command(
        binary, "192.168.1.10", 2, platform
    ) == expected


@pytest.mark.parametrize(
    ("platform", "stdout", "expected_latency"),
    [
        ("win32", "Reply from 192.168.1.10: bytes=32 time<1ms TTL=128", 1.0),
        ("win32", "Reply from 192.168.1.10: bytes=32 time=12ms TTL=128", 12.0),
        ("linux", "64 bytes from 192.168.1.10: icmp_seq=1 ttl=64 time=0.03 ms", 0.03),
        ("darwin", "64 bytes from 192.168.1.10: icmp_seq=0 ttl=64 time=0.08 ms", 0.08),
    ],
)
def test_ping_once_parses_platform_latency(
    platform, stdout, expected_latency
):
    result = SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    with (
        patch("scanner.live_ping.shutil.which", return_value="ping"),
        patch("scanner.live_ping.sys.platform", platform, create=True),
        patch("scanner.live_ping.subprocess.run", return_value=result) as run,
    ):
        # ping_once imports sys locally; patch the actual sys module attribute.
        response = live_ping.ping_once("192.168.1.10", timeout_seconds=2)

    assert response["reachable"] is True
    assert response["latency_ms"] == expected_latency
    assert run.call_args.args[0][-1] == "192.168.1.10"


def test_ping_once_returns_timeout():
    with (
        patch("scanner.live_ping.shutil.which", return_value="ping"),
        patch("scanner.live_ping.subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("ping", 2)),
    ):
        response = live_ping.ping_once("192.168.1.10")

    assert response["reachable"] is False
    assert response["latency_ms"] is None
    assert response["message"] == "Request timed out."


def test_ping_once_handles_windows_host_resolution_error():
    result = SimpleNamespace(
        returncode=1,
        stdout="Ping request could not find host invalid-host.",
        stderr="",
    )

    with (
        patch("scanner.live_ping.shutil.which", return_value="ping"),
        patch("scanner.live_ping.subprocess.run", return_value=result),
    ):
        response = live_ping.ping_once("invalid-host")

    assert response["reachable"] is False
    assert response["message"] == "Hostname could not be resolved."
