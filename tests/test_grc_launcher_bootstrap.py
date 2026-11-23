import hashlib
import subprocess
from pathlib import Path

import pytest

from scripts import grc_launcher as launcher


def prepare_project(tmp_path, monkeypatch):
    requirements = tmp_path / "requirements-host-agent.txt"
    requirements.write_text(
        "Flask==3.1.3\\nrequests==2.34.2\\npsutil==7.2.2\\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(launcher, "PROJECT_DIR", tmp_path)
    monkeypatch.setattr(launcher.sys, "executable", "/usr/bin/python3")
    return requirements, tmp_path / ".host-agent-venv"


def fake_runtime(monkeypatch, venv_dir, *, dependency_result=0):
    calls = []
    exec_calls = []

    def fake_run(command, **kwargs):
        calls.append(list(command))

        if len(command) >= 3 and command[1:3] == ["-m", "venv"]:
            venv_dir.mkdir(parents=True, exist_ok=True)
            python = venv_dir / "bin" / "python"
            python.parent.mkdir(parents=True, exist_ok=True)
            python.touch()
            return subprocess.CompletedProcess(command, 0)

        if len(command) >= 3 and command[1:3] == ["-c", "import flask, requests, psutil"]:
            return subprocess.CompletedProcess(command, dependency_result)

        if len(command) >= 3 and command[1:3] == ["-m", "pip"]:
            return subprocess.CompletedProcess(command, 0)

        raise AssertionError(f"Unexpected subprocess command: {command}")

    monkeypatch.setattr(launcher.subprocess, "run", fake_run)
    monkeypatch.setattr(
        launcher.os,
        "execv",
        lambda executable, args: exec_calls.append((executable, args)),
    )
    return calls, exec_calls


def test_creates_environment_and_installs_dependencies(tmp_path, monkeypatch):
    requirements, venv_dir = prepare_project(tmp_path, monkeypatch)
    calls, exec_calls = fake_runtime(monkeypatch, venv_dir)

    launcher.prepare_host_agent_runtime()

    python = venv_dir / "bin" / "python"
    assert python.is_file()
    assert any(command[1:3] == ["-m", "venv"] for command in calls)
    assert any(command[1:3] == ["-m", "pip"] for command in calls)
    assert (venv_dir / ".requirements.sha256").read_text().strip() == (
        hashlib.sha256(requirements.read_bytes()).hexdigest()
    )
    assert len(exec_calls) == 1
    assert exec_calls[0][0] == str(python)


def test_reuses_environment_when_requirements_are_unchanged(tmp_path, monkeypatch):
    requirements, venv_dir = prepare_project(tmp_path, monkeypatch)
    python = venv_dir / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.touch()
    stamp = venv_dir / ".requirements.sha256"
    stamp.write_text(hashlib.sha256(requirements.read_bytes()).hexdigest())

    calls, exec_calls = fake_runtime(monkeypatch, venv_dir)

    launcher.prepare_host_agent_runtime()

    assert not any(command[1:3] == ["-m", "venv"] for command in calls)
    assert not any(command[1:3] == ["-m", "pip"] for command in calls)
    assert len(exec_calls) == 1


def test_reinstalls_when_requirements_change(tmp_path, monkeypatch):
    requirements, venv_dir = prepare_project(tmp_path, monkeypatch)
    python = venv_dir / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.touch()
    (venv_dir / ".requirements.sha256").write_text("old-requirements-hash")

    calls, _ = fake_runtime(monkeypatch, venv_dir)

    launcher.prepare_host_agent_runtime()

    assert any(command[1:3] == ["-m", "pip"] for command in calls)
    assert (venv_dir / ".requirements.sha256").read_text().strip() == (
        hashlib.sha256(requirements.read_bytes()).hexdigest()
    )


def test_reinstalls_when_dependency_import_check_fails(tmp_path, monkeypatch):
    requirements, venv_dir = prepare_project(tmp_path, monkeypatch)
    python = venv_dir / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.touch()
    (venv_dir / ".requirements.sha256").write_text(
        hashlib.sha256(requirements.read_bytes()).hexdigest()
    )

    calls, _ = fake_runtime(monkeypatch, venv_dir, dependency_result=1)

    launcher.prepare_host_agent_runtime()

    assert any(command[1:3] == ["-m", "pip"] for command in calls)


def test_uses_windows_interpreter_path(tmp_path):
    venv_dir = tmp_path / ".host-agent-venv"

    assert launcher.host_agent_python_path(venv_dir, "nt") == (
        venv_dir / "Scripts" / "python.exe"
    )


@pytest.mark.parametrize("system_name", ["posix", "darwin"])
def test_uses_posix_interpreter_path(tmp_path, system_name):
    venv_dir = tmp_path / ".host-agent-venv"

    assert launcher.host_agent_python_path(venv_dir, system_name) == (
        venv_dir / "bin" / "python"
    )
