"""Safe, optional connection helpers for a local OWASP ZAP instance."""

import ipaddress
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests

from config import DATA_DIR
from scanner.zap_install import detect_zap, install_zap, managed_zap_root

DEFAULT_ENDPOINT = "http://127.0.0.1:8090"
AUTO_KEY_FILE = DATA_DIR / ".zap_auto_key"
PROCESS_RECORD_FILE = DATA_DIR / ".zap_managed_process.json"


class ZapProxyError(Exception):
    """Raised for ZAP configuration or connection errors."""


def validate_endpoint(value):
    """Accept only the fixed, managed local ZAP endpoint."""
    value = (value or "").strip().rstrip("/")
    if value != DEFAULT_ENDPOINT:
        raise ZapProxyError(
            "Shadow Map uses its managed local ZAP endpoint "
            f"({DEFAULT_ENDPOINT}). Manual endpoint configuration is disabled."
        )
    return DEFAULT_ENDPOINT


def load_endpoint():
    """Return the fixed managed local ZAP endpoint."""
    return DEFAULT_ENDPOINT


def get_api_key():
    """Read only Shadow Map's internally generated local API key."""
    try:
        key = AUTO_KEY_FILE.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ZapProxyError(
            "Could not read Shadow Map's managed ZAP API key."
        ) from exc

    return key or None


def fetch_alerts(endpoint=None, base_url=None, limit=100):
    """Read existing ZAP alerts only; never start or modify a scan."""
    endpoint = validate_endpoint(endpoint or load_endpoint())
    api_key = get_api_key()

    if not api_key:
        raise ZapProxyError(
            "Shadow Map has no managed ZAP API key. Use Start / Check ZAP to initialize it."
        )

    try:
        limit = int(limit)
    except (TypeError, ValueError) as exc:
        raise ZapProxyError("Alert limit must be an integer.") from exc

    if not 1 <= limit <= 500:
        raise ZapProxyError("Alert limit must be between 1 and 500.")

    params = {"apikey": api_key, "start": 0, "count": limit}
    if base_url:
        base_url = base_url.strip()
        if len(base_url) > 2048 or not base_url.startswith(("http://", "https://")):
            raise ZapProxyError("Enter a valid HTTP(S) target URL filter.")
        params["baseurl"] = base_url

    session = requests.Session()
    session.trust_env = False

    try:
        response = session.get(
            endpoint + "/JSON/core/view/alerts/",
            params=params,
            timeout=(3, 10),
            allow_redirects=False,
        )
        if response.is_redirect:
            raise ZapProxyError("ZAP returned a redirect; connection refused.")
        response.raise_for_status()

        try:
            payload = response.json()
        except ValueError as exc:
            raise ZapProxyError("ZAP returned an unexpected alert response.") from exc

        alerts = payload.get("alerts") if isinstance(payload, dict) else None
        if not isinstance(alerts, list):
            raise ZapProxyError(
                "ZAP's response did not contain a valid alerts list."
            )

        # Return only fields used by the preview. Treat alert content as untrusted.
        cleaned = []
        for item in alerts[:limit]:
            if not isinstance(item, dict):
                continue
            def safe_text(value, maximum=4000):
                if not isinstance(value, (str, int, float)):
                    return ""
                return str(value)[:maximum]

            cleaned.append({
                "name": safe_text(item.get("name"), 500) or "Unnamed alert",
                "risk": safe_text(item.get("risk"), 50) or "Unknown",
                "url": safe_text(item.get("url"), 2048),
                "description": safe_text(item.get("description")),
                "solution": safe_text(item.get("solution")),
                "alert": safe_text(item.get("alert"), 1000),
                "confidence": safe_text(item.get("confidence"), 100),
                "pluginId": safe_text(item.get("pluginId"), 50),
            })

        return {"count": len(cleaned), "alerts": cleaned}
    except ZapProxyError:
        raise
    except requests.RequestException as exc:
        raise ZapProxyError(
            "Could not retrieve alerts from local ZAP. Check that it is running "
            "and that Shadow Map can authenticate with its managed API key."
        ) from exc
    finally:
        session.close()


def test_connection(endpoint=None):
    """Check ZAP's version endpoint without starting any scan."""
    endpoint = validate_endpoint(endpoint or load_endpoint())
    api_key = get_api_key()

    if not api_key:
        raise ZapProxyError(
            "Shadow Map has no managed ZAP API key. Use Start / Check ZAP to initialize it."
        )

    session = requests.Session()
    session.trust_env = False

    try:
        response = session.get(
            endpoint + "/JSON/core/view/version/",
            params={"apikey": api_key},
            timeout=(3, 5),
            allow_redirects=False,
        )
        if response.is_redirect:
            raise ZapProxyError("ZAP returned a redirect; connection refused.")
        response.raise_for_status()

        try:
            payload = response.json()
        except ValueError as exc:
            raise ZapProxyError(
                "ZAP returned an unexpected response."
            ) from exc

        version = payload.get("version") if isinstance(payload, dict) else None
        if not version:
            raise ZapProxyError(
                "The endpoint responded but did not identify itself as ZAP."
            )

        return {"connected": True, "version": str(version)}
    except ZapProxyError:
        raise
    except requests.RequestException as exc:
        raise ZapProxyError(
            "Could not connect to ZAP. Check that it is running, "
            "Shadow Map can authenticate with its managed API key."
        ) from exc
    finally:
        session.close()


# ---------------------------------------------------------------------------
# HexBrain API Key management (mirrors ZAP's keyring pattern)
# ---------------------------------------------------------------------------

HEXBRAIN_KEYRING_SERVICE = "shadow-map-grc"
HEXBRAIN_KEYRING_USERNAME = "hexbrain_api_key"


def get_hexbrain_api_key():
    """Retrieve the HexBrain API key from the OS keyring."""
    try:
        import keyring
        return keyring.get_password(HEXBRAIN_KEYRING_SERVICE, HEXBRAIN_KEYRING_USERNAME)
    except Exception:
        return None


def save_hexbrain_api_key(api_key):
    """Save the HexBrain API key to the OS keyring."""
    try:
        import keyring
        if api_key:
            keyring.set_password(HEXBRAIN_KEYRING_SERVICE, HEXBRAIN_KEYRING_USERNAME, api_key)
        else:
            try:
                keyring.delete_password(HEXBRAIN_KEYRING_SERVICE, HEXBRAIN_KEYRING_USERNAME)
            except Exception:
                pass
        return True
    except Exception:
        return False


def trigger_zap_active_scan(
    target_url, endpoint=None, timeout=300,
    progress_callback=None,
):
    """Spider the target, wait for the scan tree to populate, then active-scan.

    ZAP refuses ``ascan/action/scan`` until the URL is present in the scan
    tree, which the standard spider populates. ZAP 2.17.0 also reports
    active-scan progress via ``ascan/view/scans/`` (there is no
    ``ascan/view/status/`` endpoint). This helper drives both phases in the
    correct order and returns the scan IDs for cancellation and progress
    lookups by the caller.
    """
    def emit(task, percent=None):
        if progress_callback is None:
            return
        try:
            progress_callback({"task": task, "percent": percent})
        except Exception:
            pass

    emit("Validating OWASP ZAP configuration")
    endpoint = validate_endpoint(endpoint or load_endpoint())
    api_key = get_api_key()

    if not api_key:
        raise ZapProxyError("No ZAP API key configured.")

    session = requests.Session()
    session.trust_env = False
    spider_scan_id = None
    ascan_scan_id = None

    try:
        # Phase 1: standard spider (populates scan tree — required before ascan)
        emit("OWASP ZAP spider: starting")
        spider_resp = session.get(
            endpoint + "/JSON/spider/action/scan/",
            params={"apikey": api_key, "url": target_url, "recurse": "true"},
            timeout=(3, 10),
        )
        spider_resp.raise_for_status()
        spider_scan_id = str(spider_resp.json().get("scan", ""))
        if not spider_scan_id:
            raise ZapProxyError("ZAP did not return a spider scan ID.")

        # Phase 2: wait for spider to finish before ascan
        spider_timeout = max(30, int(timeout) // 3)
        spider_start = time.time()
        spider_finished = False

        while time.time() - spider_start < spider_timeout:
            try:
                status = session.get(
                    endpoint + "/JSON/spider/view/status/",
                    params={"apikey": api_key, "scanId": spider_scan_id},
                    timeout=(3, 5),
                ).json().get("status")
                try:
                    spider_percent = max(0.0, min(100.0, float(status)))
                except (TypeError, ValueError):
                    spider_percent = None
                emit("OWASP ZAP spider: reported phase progress", spider_percent)
                if str(status) == "100":
                    spider_finished = True
                    break
            except Exception:
                pass
            time.sleep(2)

        if not spider_finished:
            emit("OWASP ZAP spider timed out")
            return {
                "status": "spider_timeout",
                "spider_scan_id": spider_scan_id,
                "ascan_scan_id": None,
            }

        # Phase 2.5: constrain resource usage before active scan
        try:
            session.get(
                endpoint + "/JSON/ascan/action/setOptionThreadPerHost/",
                params={"apikey": api_key, "Integer": "2"},
                timeout=(3, 5),
            )
            session.get(
                endpoint + "/JSON/ascan/action/setOptionMaxScanDurationInMins/",
                params={"apikey": api_key, "Integer": "10"},
                timeout=(3, 5),
            )
        except Exception:
            pass

        # Phase 3: active scan — tree is now populated
        emit("OWASP ZAP active scan: starting")
        ascan_resp = session.get(
            endpoint + "/JSON/ascan/action/scan/",
            params={"apikey": api_key, "url": target_url, "recurse": "true"},
            timeout=(3, 10),
        )
        ascan_resp.raise_for_status()
        ascan_scan_id = str(ascan_resp.json().get("scan", ""))

        # Phase 4: poll ascan until finished / stopped / timeout
        ascan_start = time.time()
        final_state = "timeout"
        while time.time() - ascan_start < max(int(timeout), 660):
            try:
                scans = session.get(
                    endpoint + "/JSON/ascan/view/scans/",
                    params={"apikey": api_key},
                    timeout=(3, 5),
                ).json().get("scans", [])

                if not scans:
                    final_state = "unknown"
                    break

                ours = next(
                    (s for s in scans if str(s.get("id")) == ascan_scan_id),
                    None,
                )
                if ours is None:
                    final_state = "unknown"
                    break

                state = str(ours.get("state", "")).upper()
                progress = int(str(ours.get("progress", "0")) or "0")
                progress = max(0, min(100, progress))
                emit("OWASP ZAP active scan: reported phase progress", progress)

                if state == "FINISHED" or progress >= 100:
                    final_state = "finished"
                    break
                if state == "STOPPED":
                    final_state = "stopped"
                    break
            except Exception:
                pass
            time.sleep(2)

        if final_state == "finished":
            emit("OWASP ZAP assessment complete", 100)
        else:
            emit(f"OWASP ZAP active scan {final_state}")
        return {
            "status": final_state,
            "spider_scan_id": spider_scan_id,
            "ascan_scan_id": ascan_scan_id,
        }
    except Exception as exc:
        raise ZapProxyError(f"Failed to trigger ZAP scan: {exc}")
    finally:
        session.close()


def stop_zap_scans(endpoint=None):
    """Request ZAP to abort any in-flight spider and active scans."""
    endpoint = validate_endpoint(endpoint or load_endpoint())
    api_key = get_api_key()
    if not api_key:
        raise ZapProxyError("No ZAP API key configured.")

    session = requests.Session()
    session.trust_env = False
    results = {"ascan": "unknown", "spider": "unknown"}
    try:
        for name, path in (
            ("ascan", "/JSON/ascan/action/stopAllScans/"),
            ("spider", "/JSON/spider/action/stopAllScans/"),
        ):
            try:
                resp = session.get(
                    endpoint + path,
                    params={"apikey": api_key},
                    timeout=(3, 10),
                )
                results[name] = "stopped" if resp.status_code == 200 else f"http {resp.status_code}"
            except Exception as exc:
                results[name] = f"error: {exc}"
        return results
    finally:
        session.close()


def get_zap_scan_progress(endpoint=None):
    """Return the current ZAP spider/ascan progress for the unified-scan bar."""
    endpoint = validate_endpoint(endpoint or load_endpoint())
    api_key = get_api_key()
    if not api_key:
        return {"running": False, "ascan": 0, "spider": 0, "error": "no API key"}

    session = requests.Session()
    session.trust_env = False
    ascan_pct = 0
    spider_pct = 0
    running = False
    try:
        try:
            scans = session.get(
                endpoint + "/JSON/ascan/view/scans/",
                params={"apikey": api_key},
                timeout=(2, 5),
            ).json().get("scans", [])
            for scan in scans:
                if str(scan.get("state", "")).upper() == "RUNNING":
                    running = True
                    pct = int(str(scan.get("progress", "0")) or "0")
                    if pct > ascan_pct:
                        ascan_pct = pct
        except Exception:
            pass

        try:
            spider_status = session.get(
                endpoint + "/JSON/spider/view/status/",
                params={"apikey": api_key},
                timeout=(2, 5),
            ).json().get("status", "0")
            spider_pct = int(spider_status) if str(spider_status).isdigit() else 0
            if 0 < spider_pct < 100:
                running = True
        except Exception:
            pass

        return {"running": running, "ascan": ascan_pct, "spider": spider_pct}
    finally:
        session.close()


def _ensure_zap_api_key():
    """Return or generate Shadow Map's private local ZAP API key."""
    api_key = get_api_key()
    if api_key:
        return api_key

    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        api_key = secrets.token_hex(32)
        temporary_file = AUTO_KEY_FILE.with_suffix(".tmp")

        temporary_file.write_text(api_key + "\n", encoding="utf-8")
        temporary_file.chmod(0o600)
        temporary_file.replace(AUTO_KEY_FILE)
        AUTO_KEY_FILE.chmod(0o600)

    except OSError as exc:
        raise ZapProxyError(
            "Could not securely create Shadow Map's managed ZAP API key."
        ) from exc

    return api_key


def _find_java_executable():
    """Find Java using JAVA_HOME, PATH, and standard Windows locations."""
    java_name = "java.exe" if os.name == "nt" else "java"

    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / java_name
        if candidate.is_file():
            return str(candidate)

    # Search installed macOS JVM bundles before PATH, which may resolve
    # to Apple's Java installation stub rather than an installed runtime.
    if platform.system() == "Darwin":
        mac_java_root = Path(
            "/Library/Java/JavaVirtualMachines"
        )
        for candidate in sorted(
            mac_java_root.glob("*/Contents/Home/bin/java"),
            reverse=True,
        ):
            if candidate.is_file():
                return str(candidate)

    path_java = shutil.which("java")
    if path_java:
        return path_java

    if os.name == "nt":
        roots = [
            Path(os.environ.get("ProgramFiles", r"C:\\Program Files")),
            Path(os.environ.get("ProgramFiles(x86)", r"C:\\Program Files (x86)")),
        ]

        patterns = (
            "Java/*/bin/java.exe",
            "Eclipse Adoptium/*/bin/java.exe",
            "Microsoft/*/bin/java.exe",
            "Amazon Corretto/*/bin/java.exe",
        )

        for root in roots:
            for pattern in patterns:
                for candidate in sorted(root.glob(pattern), reverse=True):
                    if candidate.is_file():
                        return str(candidate)

    return None


def _require_java_17():
    """Ensure a Java 17+ runtime is available for ZAP."""
    java_path = _find_java_executable()

    if not java_path:
        raise ZapProxyError(
            "Java 17 or newer is required to start OWASP ZAP. "
            "Install a Java runtime and restart Shadow Map."
        )

    try:
        result = subprocess.run(
            [java_path, "-version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ZapProxyError(
            "Java 17 or newer is required to start OWASP ZAP. "
            "Could not execute the detected Java runtime."
        ) from exc

    version_text = (result.stdout or "") + "\n" + (result.stderr or "")
    match = re.search(
        r'(?:version\s+"|openjdk\s+)(?:1\.)?(\d+)',
        version_text,
        re.IGNORECASE,
    )

    if result.returncode != 0 or not match or int(match.group(1)) < 17:
        raise ZapProxyError(
            "Java 17 or newer is required to start OWASP ZAP. "
            "Check that the detected Java runtime reports version 17 or later."
        )

    return java_path


SESSION_NAME = "shadow-map-grc.session"
SESSION_MANIFEST_NAME = ".shadow-map-session.json"
SESSION_MANIFEST_VERSION = 1


def _session_manifest_path(zap_home):
    return Path(zap_home) / SESSION_MANIFEST_NAME


def _write_managed_session_manifest(zap_home, status):
    """Atomically write the managed ZAP session recovery manifest."""
    manifest_path = _session_manifest_path(zap_home)
    temporary_path = manifest_path.with_suffix(".tmp")

    record = {
        "schema_version": SESSION_MANIFEST_VERSION,
        "session_name": SESSION_NAME,
        "session_path": str(
            (Path(zap_home) / "session" / SESSION_NAME).resolve()
        ),
        "status": status,
    }

    try:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path.write_text(
            json.dumps(record, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary_path.chmod(0o600)
        temporary_path.replace(manifest_path)
        manifest_path.chmod(0o600)
    except OSError as exc:
        raise ZapProxyError(
            "Could not securely write the managed ZAP session manifest."
        ) from exc


def _read_managed_session_manifest(zap_home):
    """Read and validate the managed session manifest."""
    manifest_path = _session_manifest_path(zap_home)

    try:
        record = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError) as exc:
        raise ZapProxyError(
            "The managed ZAP session manifest is unreadable or corrupted. "
            "It was not replaced."
        ) from exc

    expected_path = str(
        (Path(zap_home) / "session" / SESSION_NAME).resolve()
    )

    if (
        not isinstance(record, dict)
        or record.get("schema_version") != SESSION_MANIFEST_VERSION
        or record.get("session_name") != SESSION_NAME
        or record.get("session_path") != expected_path
        or record.get("status") not in {"initializing", "ready"}
    ):
        raise ZapProxyError(
            "The managed ZAP session manifest is inconsistent. "
            "The existing session was not modified."
        )

    return record


def _managed_session_artifacts_exist(zap_home):
    """Check for the persisted HSQLDB session files."""
    session_dir = Path(zap_home) / "session"
    session_base = session_dir / SESSION_NAME

    return (
        session_base.with_name(session_base.name + ".data").is_file()
        and session_base.with_name(
            session_base.name + ".properties"
        ).is_file()
    )


def _prepare_managed_zap_session(zap_home):
    """Choose first-session creation or reopening; never overwrite a session."""
    zap_home = Path(zap_home)
    session_dir = zap_home / "session"

    record = _read_managed_session_manifest(zap_home)

    if record is not None:
        if record["status"] != "ready":
            raise ZapProxyError(
                "The managed ZAP session has incomplete initialization. "
                "It was not recreated or overwritten. Inspect the ZAP logs "
                "and session files before recovery."
            )

        if not _managed_session_artifacts_exist(zap_home):
            raise ZapProxyError(
                "The managed ZAP session files are missing or incomplete. "
                "The existing session was not recreated or overwritten."
            )

        return ["-session", SESSION_NAME]

    # An untracked session directory may contain data from an interrupted
    # initialization or a manually created session. Never adopt or overwrite it.
    if session_dir.exists():
        try:
            if any(session_dir.iterdir()):
                raise ZapProxyError(
                    "The managed ZAP profile contains session files but has "
                    "no Shadow Map session manifest. Refusing to overwrite "
                    "or adopt those files."
                )
        except OSError as exc:
            raise ZapProxyError(
                "Could not safely inspect the managed ZAP session directory."
            ) from exc

    try:
        session_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ZapProxyError(
            "Could not create the managed ZAP session directory."
        ) from exc

    _write_managed_session_manifest(zap_home, "initializing")
    return ["-newsession", SESSION_NAME]


def _mark_managed_zap_session_ready(zap_home):
    """Mark initialization complete only after persisted DB files exist."""
    if not _managed_session_artifacts_exist(zap_home):
        raise ZapProxyError(
            "ZAP became API-ready, but its managed session database files "
            "were not found. The session remains marked as initializing "
            "and will not be silently recreated."
        )

    _write_managed_session_manifest(zap_home, "ready")


def _zap_launch_command(
    zap_info, host, port, api_key, zap_home, session_args=None,
    validated_java_path=None,
):
    """Build a platform-neutral daemon command for a system install or JAR."""
    zap_path = Path(zap_info["path"])

    # macOS application bundles need the managed cross-platform JAR.
    if zap_path.is_dir() or zap_path.suffix.lower() == ".app":
        try:
            zap_info = install_zap()
        except Exception as exc:
            raise ZapProxyError(
                f"Could not prepare the managed ZAP installation: {exc}"
            ) from exc
        zap_path = Path(zap_info["path"])

    arguments = [
        "-daemon",
        "-host", host,
        "-port", str(port),
        "-config", f"api.key={api_key}",
        "-dir", str(zap_home),
    ]

    if session_args:
        command_session_args = list(session_args)
        if len(command_session_args) != 2 or command_session_args[0] not in {
            "-session", "-newsession"
        }:
            raise ZapProxyError("Invalid managed ZAP session startup arguments.")
        arguments.extend(command_session_args)

    if zap_path.suffix.lower() == ".jar":
        java_path = validated_java_path or _require_java_17()
        return [
            java_path, "-Xms256m", "-Xmx1024m",
            "-jar", str(zap_path), *arguments,
        ]

    if not zap_path.exists():
        raise ZapProxyError(
            f"The detected ZAP executable does not exist: {zap_path}"
        )

    return [str(zap_path), *arguments]


def _write_managed_process_record(process, endpoint, zap_home):
    """Atomically record the PID and profile of the process we launched."""
    try:
        pid = int(process.pid)
        if pid <= 0:
            raise ValueError("Invalid process ID.")

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        record = {
            "pid": pid,
            "endpoint": endpoint,
            "zap_home": str(Path(zap_home).resolve()),
        }

        temporary_file = PROCESS_RECORD_FILE.with_suffix(".tmp")
        temporary_file.write_text(
            json.dumps(record, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary_file.chmod(0o600)
        temporary_file.replace(PROCESS_RECORD_FILE)
        PROCESS_RECORD_FILE.chmod(0o600)

    except (OSError, TypeError, ValueError, AttributeError) as exc:
        raise ZapProxyError(
            "Could not securely record the managed ZAP process."
        ) from exc


def _read_managed_process_record():
    """Read Shadow Map's process record; malformed records fail closed."""
    try:
        record = json.loads(
            PROCESS_RECORD_FILE.read_text(encoding="utf-8")
        )
    except (OSError, ValueError, TypeError):
        return None

    if not isinstance(record, dict):
        return None

    try:
        pid = int(record.get("pid"))
        endpoint = record.get("endpoint")
        zap_home = record.get("zap_home")
    except (TypeError, ValueError):
        return None

    if pid <= 0 or not isinstance(endpoint, str) or not isinstance(zap_home, str):
        return None

    return {
        "pid": pid,
        "endpoint": endpoint,
        "zap_home": zap_home,
    }


def _get_process_command_line(pid):
    """Read a process command line using the host operating system."""
    system = platform.system().lower()

    try:
        if system == "linux":
            command_file = Path("/proc") / str(pid) / "cmdline"
            raw = command_file.read_bytes()
            if not raw:
                return None
            return [
                item.decode("utf-8", errors="replace")
                for item in raw.split(b"\0")
                if item
            ]

        if system == "darwin":
            result = subprocess.run(
                ["ps", "-ww", "-p", str(pid), "-o", "command="],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None
            return shlex.split(result.stdout.strip())

        if system == "windows":
            script = (
                f"$p = Get-CimInstance Win32_Process "
                f"-Filter 'ProcessId = {pid}'; "
                "if ($p) { $p.CommandLine }"
            )
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    script,
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None
            return shlex.split(result.stdout.strip(), posix=False)

    except (OSError, subprocess.SubprocessError, ValueError):
        return None

    return None


def _process_matches_managed_zap(pid, endpoint, zap_home):
    """Verify the recorded process is using Shadow Map's endpoint and profile."""
    command = _get_process_command_line(pid)
    if not command:
        return False

    tokens = [str(item).strip('"') for item in command]
    parsed = urlsplit(endpoint)
    expected_host = parsed.hostname or ""
    expected_port = str(parsed.port or 80)
    expected_home = str(Path(zap_home).resolve())

    try:
        dir_index = tokens.index("-dir")
        host_index = tokens.index("-host")
        port_index = tokens.index("-port")

        actual_home = str(Path(tokens[dir_index + 1]).resolve())
        actual_host = tokens[host_index + 1]
        actual_port = tokens[port_index + 1]
    except (ValueError, IndexError, OSError):
        return False

    return (
        "-daemon" in tokens
        and actual_home == expected_home
        and actual_host == expected_host
        and actual_port == expected_port
    )


def _is_managed_zap_process(endpoint, zap_home):
    """Require a matching recorded PID and verified process command line."""
    record = _read_managed_process_record()
    if not record:
        return False

    if record["endpoint"] != endpoint:
        return False

    if record["zap_home"] != str(Path(zap_home).resolve()):
        return False

    return _process_matches_managed_zap(
        record["pid"],
        endpoint,
        zap_home,
    )


def shutdown_managed_zap(grace_seconds=5):
    """Stop only the isolated ZAP process group verified as Shadow Map-owned."""
    if os.name != "posix":
        return False

    record = _read_managed_process_record()
    if not record:
        return False

    endpoint = record["endpoint"]
    zap_home = Path(record["zap_home"])
    pid = record["pid"]

    try:
        if validate_endpoint(endpoint) != endpoint:
            return False

        expected_home = managed_zap_root().parent / "zap-home"
        if zap_home.resolve() != expected_home.resolve():
            return False

        if not _process_matches_managed_zap(pid, endpoint, zap_home):
            return False

        # ZAP is launched with start_new_session=True. Verify its PID
        # is the leader of its own isolated process group before acting.
        if os.getpgid(pid) != pid:
            return False

        def group_exists():
            try:
                os.killpg(pid, 0)
                return True
            except ProcessLookupError:
                return False

        os.killpg(pid, signal.SIGTERM)

        deadline = time.monotonic() + max(0, grace_seconds)
        while group_exists() and time.monotonic() < deadline:
            time.sleep(0.2)

        # Escalate only against the same isolated process group.
        if group_exists():
            os.killpg(pid, signal.SIGKILL)

        # Allow the operating system time to finish group termination.
        deadline = time.monotonic() + 3
        while group_exists() and time.monotonic() < deadline:
            time.sleep(0.1)

        if group_exists():
            return False

        # Remove only the record we originally verified.
        if _read_managed_process_record() == record:
            try:
                PROCESS_RECORD_FILE.unlink()
            except FileNotFoundError:
                pass

        return True

    except (OSError, ZapProxyError, ValueError):
        return False


def _validate_existing_managed_zap_session(zap_home):
    """Require an intact, ready session when reusing an existing daemon."""
    record = _read_managed_session_manifest(zap_home)

    if record is None:
        raise ZapProxyError(
            "The running managed ZAP process has no session manifest. "
            "Its session was not modified."
        )

    if record["status"] != "ready":
        raise ZapProxyError(
            "The running managed ZAP process has a session that is not "
            "marked ready. Its session was not modified."
        )

    if not _managed_session_artifacts_exist(zap_home):
        raise ZapProxyError(
            "The running managed ZAP process has missing or incomplete "
            "session database files. Its session was not modified."
        )

    return True


def ensure_zap_running(endpoint=None):
    """Start local ZAP if needed and return only after its API identifies itself."""
    endpoint = validate_endpoint(endpoint or load_endpoint())
    parsed = urlsplit(endpoint)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    api_key = _ensure_zap_api_key()

    # The API key alone does not prove that this is Shadow Map's process.
    zap_home = managed_zap_root().parent / "zap-home"

    try:
        connection = test_connection(endpoint)
    except ZapProxyError:
        connection = None

    if connection is not None:
        if not _is_managed_zap_process(endpoint, zap_home):
            raise ZapProxyError(
                "A ZAP API is responding, but Shadow Map cannot verify that "
                "the process uses its managed profile. The existing process "
                "was not stopped or modified. Close it manually only after "
                "confirming it is safe to do so, then retry."
            )

        _validate_existing_managed_zap_session(zap_home)
        return connection

    if parsed.scheme != "http":
        raise ZapProxyError(
            "Automatic startup requires a local HTTP ZAP endpoint. "
            "An existing HTTPS endpoint can be used only if its API check succeeds."
        )

    java_path = _require_java_17()

    try:
        zap_info = detect_zap()
        if not zap_info.get("installed"):
            zap_info = install_zap()
    except Exception as exc:
        raise ZapProxyError(
            f"Could not detect or install OWASP ZAP: {exc}"
        ) from exc

    # Keep ZAP configuration, add-ons, and sessions inside
    # Shadow Map's application-managed data directory.
    try:
        zap_home.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ZapProxyError(
            "Could not create the separate ZAP working directory."
        ) from exc

    session_args = _prepare_managed_zap_session(zap_home)

    command = _zap_launch_command(
        zap_info, host, port, api_key, zap_home,
        session_args=session_args,
        validated_java_path=java_path,
    )

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    log_file_path = Path(zap_home) / "shadow-map-zap.log"
    env = os.environ.copy()
    env["_JAVA_OPTIONS"] = "-Xms256m -Xmx1024m"

    try:
        popen_options = {
            "stdout": None,
            "stderr": subprocess.STDOUT,
            "env": env,
            "cwd": (
                str(Path(zap_info["path"]).parent)
                if Path(zap_info["path"]).suffix.lower() == ".jar"
                else None
            ),
        }

        if platform.system().lower() == "windows":
            popen_options["creationflags"] = (
                getattr(subprocess, "DETACHED_PROCESS", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            )
        else:
            popen_options["start_new_session"] = True

        with log_file_path.open("a", encoding="utf-8") as log_file:
            popen_options["stdout"] = log_file
            process = subprocess.Popen(command, **popen_options)

        _write_managed_process_record(process, endpoint, zap_home)

    except (OSError, subprocess.SubprocessError) as exc:
        raise ZapProxyError(f"Failed to start OWASP ZAP: {exc}") from exc

    # ZAP may need extra time on first launch to initialize its add-ons.
    deadline = time.monotonic() + 90
    last_error = None

    while time.monotonic() < deadline:
        try:
            connection = test_connection(endpoint)
            if not _is_managed_zap_process(endpoint, zap_home):
                raise ZapProxyError(
                    "ZAP responded, but its process identity or managed "
                    "profile could not be verified."
                )

            if session_args[0] == "-newsession":
                _mark_managed_zap_session_ready(zap_home)

            return connection
        except ZapProxyError as exc:
            last_error = exc

        if process.poll() is not None:
            break

        time.sleep(1)

    try:
        log_tail = log_file_path.read_text(
            encoding="utf-8", errors="replace"
        )[-4000:]
    except OSError:
        log_tail = ""

    detail = f" Last API error: {last_error}" if last_error else ""
    if log_tail:
        detail += f" ZAP log tail: {log_tail}"

    raise ZapProxyError(
        "ZAP did not become API-ready. Check the managed ZAP log."
        + detail
    )
