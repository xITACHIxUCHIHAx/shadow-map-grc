import importlib.util
from pathlib import Path
import os
import sys

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "grc_launcher.py"
SPEC = importlib.util.spec_from_file_location("grc_launcher", MODULE_PATH)
launcher = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = launcher
SPEC.loader.exec_module(launcher)


def test_env_reader_handles_comments_quotes_and_equals(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\nSHADOW_MAP_SECRET_KEY='abc=def'\nEMPTY=\nINVALID LINE\n"
    )
    assert launcher.read_env_file(env_file) == {
        "SHADOW_MAP_SECRET_KEY": "abc=def",
        "EMPTY": "",
    }


def test_ensure_runtime_env_generates_and_persists_token(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("SHADOW_MAP_SECRET_KEY=secret-key\n")
    monkeypatch.setattr(launcher, "ENV_FILE", env_file)
    values = launcher.ensure_runtime_env()
    assert len(values["SHADOW_MAP_HOST_AGENT_TOKEN"]) >= 40
    assert "SHADOW_MAP_HOST_AGENT_TOKEN=" in env_file.read_text()
    if os.name != "nt":
        assert env_file.stat().st_mode & 0o777 == 0o600


def test_ensure_runtime_env_requires_app_secret(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("# no secret\n")
    monkeypatch.setattr(launcher, "ENV_FILE", env_file)
    try:
        launcher.ensure_runtime_env()
    except RuntimeError as exc:
        assert "SHADOW_MAP_SECRET_KEY" in str(exc)
    else:
        raise AssertionError("missing app secret should be rejected")


def test_ensure_runtime_env_preserves_existing_agent_token(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "SHADOW_MAP_SECRET_KEY=secret\nSHADOW_MAP_HOST_AGENT_TOKEN=existing-token\n"
    )
    monkeypatch.setattr(launcher, "ENV_FILE", env_file)
    assert launcher.ensure_runtime_env()["SHADOW_MAP_HOST_AGENT_TOKEN"] == "existing-token"


def test_gateway_discovery_uses_compose_network_label(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if "network" in command and "ls" in command:
            return type("Result", (), {"stdout": "network-id\n"})()
        return type("Result", (), {
            "stdout": '[{"IPAM":{"Config":[{"Gateway":"172.30.0.1"}]}}]'
        })()

    monkeypatch.setattr(launcher, "_run", fake_run)
    assert launcher._network_gateway(["docker"], "shadow-map-grc-release") == "172.30.0.1"
    assert "label=com.docker.compose.project=shadow-map-grc-release" in calls[0]
    assert "label=com.docker.compose.network=default" in calls[0]


def test_pid_reader_rejects_missing_or_legacy_pid_file(tmp_path, monkeypatch):
    monkeypatch.setattr(launcher, "PID_FILE", tmp_path / "agent.pid")
    assert launcher._read_pid() is None
    launcher.PID_FILE.write_text("999999999")
    assert launcher._read_pid() is None


def test_stop_does_not_kill_unmanaged_agent(tmp_path, monkeypatch):
    pid_file = tmp_path / "agent.pid"
    monkeypatch.setattr(launcher, "PID_FILE", pid_file)
    monkeypatch.setattr(launcher, "_agent_process_from_pid_file", lambda: None)
    pid_file.write_text("legacy-pid")
    result = launcher.stop_owned_agent()
    assert "external agents are left untouched" in result
    assert not pid_file.exists()


def test_stop_uses_verified_process_handle(tmp_path, monkeypatch):
    pid_file = tmp_path / "agent.pid"
    monkeypatch.setattr(launcher, "PID_FILE", pid_file)

    class FakeProcess:
        pid = 1234
        def __init__(self):
            self.terminated = False
        def terminate(self):
            self.terminated = True
        def wait(self, timeout):
            return 0

    fake = FakeProcess()
    monkeypatch.setattr(launcher, "_agent_process_from_pid_file", lambda: fake)
    pid_file.write_text("{}")
    result = launcher.stop_owned_agent()
    assert fake.terminated
    assert "1234" in result
    assert not pid_file.exists()


def test_agent_port_validation():
    assert launcher._validated_agent_port("5001") == 5001
    for value in ("0", "65536", "not-a-port"):
        try:
            launcher._validated_agent_port(value)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"invalid port accepted: {value}")


def test_start_agent_reuses_authenticated_external_agent(tmp_path, monkeypatch):
    monkeypatch.setattr(launcher, "DATA_DIR", tmp_path)
    monkeypatch.setattr(launcher, "PID_FILE", tmp_path / "agent.pid")
    monkeypatch.setattr(launcher, "_read_pid", lambda: None)
    monkeypatch.setattr(launcher, "_agent_health", lambda url, token: True)

    class BusySocket:
        def bind(self, address):
            raise OSError("address already in use")
        def close(self):
            pass

    monkeypatch.setattr(launcher.socket, "socket", lambda *args: BusySocket())
    env = {"SHADOW_MAP_HOST_AGENT_TOKEN": "test-token"}
    result = launcher.start_agent(env, "127.0.0.1")
    assert "already running" in result
    assert not launcher.PID_FILE.exists()


def test_sudo_commands_preserve_compose_runtime_variables(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return type("Result", (), {})()

    monkeypatch.setattr(launcher.subprocess, "run", fake_run)
    launcher._run(
        ["sudo", "docker", "compose", "up", "-d"],
        env={"SHADOW_MAP_SECRET_KEY": "secret"},
    )
    assert captured["command"][1].startswith("--preserve-env=")
    assert "SHADOW_MAP_HOST_AGENT_URL" in captured["command"][1]



def test_publish_image_builds_then_pushes_configured_service(monkeypatch):
    calls = []

    def fake_run(command, *, env, **kwargs):
        calls.append(command)
        return type("Result", (), {"stdout": ""})()

    monkeypatch.setattr(launcher, "_run", fake_run)
    base = ["docker", "compose", "-f", "docker-compose.yml"]
    launcher.publish_image(base, {"SHADOW_MAP_SECRET_KEY": "secret"})

    assert calls == [
        base + ["config", "--quiet"],
        base + ["build", "grc"],
        base + ["push", "grc"],
    ]
