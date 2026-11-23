#!/usr/bin/env python3
"""Cross-platform Shadow Map GRC launcher and host-agent lifecycle manager."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

PROJECT_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_DIR / ".env"
DATA_DIR = PROJECT_DIR / "data"
PID_FILE = DATA_DIR / "host-agent.pid"
LOG_FILE = DATA_DIR / "host-agent.log"


def read_env_file(path: Path | None = None) -> dict[str, str]:
    """Read simple KEY=VALUE dotenv entries without executing shell code."""
    path = path or ENV_FILE
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value and value[0:1] in ("'", '"') and value[-1:] == value[0:1]:
            value = value[1:-1]
        if key and key.replace("_", "").isalnum() and not key[0].isdigit():
            values[key] = value
    return values


def secure_env_permissions(path: Path) -> None:
    """Restrict the environment file to the current account where possible."""
    if os.name == "nt":
        username = os.environ.get("USERNAME")
        icacls = shutil.which("icacls")
        if username and icacls:
            subprocess.run(
                [icacls, str(path), "/inheritance:r", "/grant:r", f"{username}:(R,W)"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
            )
    else:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def ensure_runtime_env(path: Path | None = None) -> dict[str, str]:
    """Load .env and create a strong host-agent token when one is absent."""
    path = path or ENV_FILE
    values = read_env_file(path)
    values.update({k: v for k, v in os.environ.items() if k.startswith("SHADOW_MAP_")})
    if not values.get("SHADOW_MAP_SECRET_KEY"):
        raise RuntimeError("SHADOW_MAP_SECRET_KEY must be configured in .env.")
    token = values.get("SHADOW_MAP_HOST_AGENT_TOKEN", "").strip()
    if not token:
        token = secrets.token_urlsafe(48)
        values["SHADOW_MAP_HOST_AGENT_TOKEN"] = token
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        lines = [line for line in lines if not line.strip().startswith("SHADOW_MAP_HOST_AGENT_TOKEN=")]
        lines.append(f"SHADOW_MAP_HOST_AGENT_TOKEN={token}")
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            os.chmod(temp, 0o600)
        except OSError:
            pass
        temp.replace(path)
    secure_env_permissions(path)
    return values


def _run(command: list[str], *, env: dict[str, str], check: bool = True,
         capture: bool = False) -> subprocess.CompletedProcess:
    # sudo commonly filters environment variables. Compose needs the generated
    # URL and token to interpolate the container configuration correctly.
    if command and Path(command[0]).name == "sudo":
        preserve = (
            "SHADOW_MAP_SECRET_KEY,SHADOW_MAP_HOST_AGENT_TOKEN,"
            "SHADOW_MAP_HOST_AGENT_URL,SHADOW_MAP_HOST_AGENT_PORT,"
            "COMPOSE_PROJECT_NAME"
        )
        command = [command[0], f"--preserve-env={preserve}", *command[1:]]
    return subprocess.run(
        command, cwd=PROJECT_DIR, env=env, check=check,
        text=True, capture_output=capture,
    )


def _docker_prefix() -> list[str]:
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("Docker is not installed or not available in PATH.")
    if os.name == "nt" or subprocess.run(
        [docker, "info"], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, check=False,
    ).returncode == 0:
        return [docker]
    sudo = shutil.which("sudo")
    if sudo and subprocess.run(
        [sudo, docker, "info"], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, check=False,
    ).returncode == 0:
        return [sudo, docker]
    raise RuntimeError("Docker is unavailable or permission was denied.")


def _compose_command(prefix: list[str]) -> list[str]:
    if subprocess.run(prefix + ["compose", "version"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                      check=False).returncode == 0:
        return prefix + ["compose"]
    legacy = shutil.which("docker-compose")
    if legacy:
        if prefix[0] == "sudo":
            return [prefix[0], legacy]
        return [legacy]
    raise RuntimeError("Docker Compose is not installed.")


def _network_gateway(prefix: list[str], project: str) -> str:
    result = _run(
        prefix + ["network", "ls", "--filter",
                  f"label=com.docker.compose.project={project}",
                  "--filter", "label=com.docker.compose.network=default", "-q"],
        env=os.environ.copy(), capture=True,
    )
    ids = result.stdout.split()
    if not ids:
        raise RuntimeError("Could not find the Shadow Map Compose network.")
    for network_id in ids:
        inspected = _run(
            prefix + ["network", "inspect", network_id],
            env=os.environ.copy(), capture=True,
        )
        data = json.loads(inspected.stdout)
        for config in data[0].get("IPAM", {}).get("Config", []):
            gateway = config.get("Gateway")
            if gateway:
                return gateway
    raise RuntimeError("The Shadow Map Docker network has no IPv4 gateway.")


def _agent_process_from_pid_file():
    """Return the exact launcher-owned process, rejecting stale/reused PIDs."""
    try:
        metadata = json.loads(PID_FILE.read_text(encoding="utf-8"))
        pid = int(metadata["pid"])
        expected_create_time = float(metadata["create_time"])
        expected_executable = str(metadata["executable"])
        if pid <= 0:
            return None

        import psutil

        process = psutil.Process(pid)
        command = process.cmdline()
        executable = process.exe()
        if (
            "-m" not in command
            or "scanner.host_discovery_agent" not in command
            or Path(executable).resolve() != Path(expected_executable).resolve()
            or abs(process.create_time() - expected_create_time) > 0.01
        ):
            return None
        return process
    except Exception:
        # Legacy PID-only files are intentionally not trusted for termination.
        return None


def _pid_is_running(pid: int) -> bool:
    """Return true only when the recorded PID still matches our process identity."""
    process = _agent_process_from_pid_file()
    return process is not None and process.pid == pid


def _read_pid() -> int | None:
    process = _agent_process_from_pid_file()
    return process.pid if process is not None else None


def _validated_agent_port(value: str | int) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("SHADOW_MAP_HOST_AGENT_PORT must be an integer from 1 to 65535.") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("SHADOW_MAP_HOST_AGENT_PORT must be between 1 and 65535.")
    return port


def _agent_health(url: str, token: str) -> bool:
    try:
        request = Request(url.rstrip("/") + "/health",
                          headers={"Authorization": f"Bearer {token}"})
        with urlopen(request, timeout=1) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return response.status == 200 and payload.get("status") == "ok"
    except (OSError, ValueError, URLError):
        return False


def start_agent(env: dict[str, str], bind: str) -> str:
    """Start an owned agent, or safely reuse an authenticated existing one."""
    token = env["SHADOW_MAP_HOST_AGENT_TOKEN"]
    port = _validated_agent_port(env.get("SHADOW_MAP_HOST_AGENT_PORT", "5001"))
    url = f"http://{bind if bind != '0.0.0.0' else '127.0.0.1'}:{port}"
    owned_pid = _read_pid()
    if owned_pid and _agent_health(url, token):
        return f"Host agent already running (launcher PID {owned_pid})."
    if owned_pid:
        stop_owned_agent()

    # A manually started agent is never adopted into our PID file or stopped.
    probe = socket.socket()
    try:
        probe.bind((bind, port))
    except OSError:
        if _agent_health(url, token):
            return "An authenticated host agent is already running; leaving it unmanaged."
        raise RuntimeError(
            f"Port {port} is already occupied by another process; refusing to start a duplicate."
        )
    finally:
        probe.close()

    import importlib.util

    missing = [
        package for package in ("flask", "requests", "psutil")
        if importlib.util.find_spec(package) is None
    ]
    if missing:
        raise RuntimeError(
            "Host-agent Python dependencies are missing: "
            + ", ".join(missing)
            + ". Install them with: python -m pip install -r requirements-host-agent.txt"
        )
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    child_env = env.copy()
    child_env.update({
        "SHADOW_MAP_HOST_AGENT_TOKEN": token,
        "SHADOW_MAP_HOST_AGENT_BIND": bind,
        "SHADOW_MAP_HOST_AGENT_PORT": str(port),
    })
    log_handle = LOG_FILE.open("ab")
    kwargs = {
        "cwd": str(PROJECT_DIR), "env": child_env,
        "stdin": subprocess.DEVNULL, "stdout": log_handle,
        "stderr": subprocess.STDOUT,
    }
    if os.name == "nt":
        kwargs["creationflags"] = (
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        )
    else:
        kwargs["start_new_session"] = True
    process = subprocess.Popen(
        [sys.executable, "-m", "scanner.host_discovery_agent"], **kwargs
    )
    log_handle.close()
    try:
        import psutil
        process_identity = psutil.Process(process.pid)
        metadata = {
            "pid": process.pid,
            "create_time": process_identity.create_time(),
            "executable": process_identity.exe(),
        }
    except Exception as exc:
        process.terminate()
        raise RuntimeError("Could not verify the started host-agent process identity.") from exc

    PID_FILE.write_text(json.dumps(metadata), encoding="utf-8")
    try:
        os.chmod(PID_FILE, 0o600)
    except OSError:
        pass
    for _ in range(30):
        if _agent_health(url, token):
            return f"Host agent started (PID {process.pid}, bind {bind}:{port})."
        if process.poll() is not None:
            break
        time.sleep(0.2)
    stop_owned_agent()
    raise RuntimeError(f"Host agent failed to become healthy; inspect {LOG_FILE}.")


def stop_owned_agent() -> str:
    """Stop only the process whose PID and creation identity are recorded."""
    process = _agent_process_from_pid_file()
    if process is None:
        PID_FILE.unlink(missing_ok=True)
        return "No verified launcher-managed host agent to stop; external agents are left untouched."

    try:
        # psutil operates on the verified process handle rather than issuing a
        # fresh PID-only taskkill/kill command that could hit a reused PID.
        process.terminate()
        try:
            process.wait(timeout=2.5)
        except Exception:
            if process.is_running():
                process.kill()
                process.wait(timeout=2.5)
    finally:
        PID_FILE.unlink(missing_ok=True)
    return f"Stopped launcher-managed host agent (PID {process.pid})."


def build_image(base: list[str], env: dict[str, str]) -> None:
    """Build the current source tree and validate Compose configuration."""
    _run(base + ["config", "--quiet"], env=env)
    _run(base + ["build", "grc"], env=env)


def push_image(base: list[str], env: dict[str, str]) -> None:
    """Push the configured image after local deployment has been verified."""
    _run(base + ["push", "grc"], env=env)


def publish_image(base: list[str], env: dict[str, str]) -> None:
    """Compatibility helper: build and push without deploying."""
    build_image(base, env)
    push_image(base, env)


def wait_for_application(url: str = "http://127.0.0.1:5000/health") -> None:
    """Wait briefly for the deployed application health endpoint."""
    deadline = time.monotonic() + 45
    last_error = "application health check did not succeed"
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=2) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if response.status == 200 and payload.get("status") == "ok":
                return
            last_error = "application returned an unexpected health response"
        except (OSError, ValueError, URLError) as exc:
            last_error = str(exc)
        time.sleep(1)
    raise RuntimeError(f"Deployment health check failed: {last_error}")


def start_stack(
    base: list[str],
    env: dict[str, str],
    prefix: list[str],
    project: str,
    *,
    pull_image: bool,
) -> None:
    """Prepare the host agent and start the Compose application."""
    if pull_image:
        _run(base + ["pull", "grc"], env=env)

    # Create the user-defined network before binding the host agent to its gateway.
    agent_port = _validated_agent_port(env.get("SHADOW_MAP_HOST_AGENT_PORT", "5001"))
    env["SHADOW_MAP_HOST_AGENT_URL"] = f"http://host.docker.internal:{agent_port}"
    _run(base + ["create"], env=env)
    if sys.platform.startswith("linux"):
        gateway = _network_gateway(prefix, project)
        bind = gateway
        env["SHADOW_MAP_HOST_AGENT_URL"] = f"http://{gateway}:{agent_port}"
    else:
        bind = env.get("SHADOW_MAP_HOST_AGENT_BIND", "0.0.0.0")
        env["SHADOW_MAP_HOST_AGENT_URL"] = f"http://host.docker.internal:{agent_port}"

    previously_owned_pid = _read_pid()
    print(start_agent(env, bind))
    newly_started_pid = _read_pid()
    try:
        _run(base + ["up", "-d"], env=env)
    except Exception:
        if newly_started_pid is not None and newly_started_pid != previously_owned_pid:
            stop_owned_agent()
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Shadow Map GRC launcher")
    parser.add_argument(
        "action",
        choices=("start", "stop", "restart", "status", "logs", "publish"),
    )
    args = parser.parse_args()
    try:
        env = os.environ.copy()
        env.update(ensure_runtime_env())
        # Compose interpolates required agent settings even for stop/status/logs.
        env.setdefault(
            "SHADOW_MAP_HOST_AGENT_URL",
            f"http://host.docker.internal:{env.get('SHADOW_MAP_HOST_AGENT_PORT', '5001')}",
        )
        # Compose project defaults to the directory name unless overridden.
        project = env.get("COMPOSE_PROJECT_NAME", PROJECT_DIR.name)
        compose_file = str(PROJECT_DIR / "docker-compose.yml")
        prefix = _docker_prefix()
        compose = _compose_command(prefix)
        base = compose + ["--project-directory", str(PROJECT_DIR), "-f", compose_file]
        if args.action in ("start", "restart"):
            if args.action == "restart":
                _run(base + ["down"], env=env)
                stop_owned_agent()
            start_stack(base, env, prefix, project, pull_image=True)
        elif args.action == "publish":
            # Validate/build first, deploy the exact local image, verify health,
            # and only then publish it to the configured registry.
            build_image(base, env)
            start_stack(base, env, prefix, project, pull_image=False)
            wait_for_application()
            push_image(base, env)
        elif args.action == "stop":
            _run(base + ["down"], env=env)
            print(stop_owned_agent())
        elif args.action == "status":
            _run(base + ["ps"], env=env)
            pid = _read_pid()
            print(
                "Host agent: running (launcher-managed)"
                if pid else
                "Host agent: not launcher-managed (external agents are left untouched)"
            )
        elif args.action == "logs":
            _run(base + ["logs", "-f"], env=env, check=False)
        return 0
    except (RuntimeError, subprocess.CalledProcessError, OSError, ValueError) as exc:
        print(f"Shadow Map GRC: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
