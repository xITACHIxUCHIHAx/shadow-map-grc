"""Automatic MITRE ATT&CK Enterprise catalogue synchronization."""

import json
import logging
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from config import DATABASE_PATH
from grc.attack_catalogue import (
    MAX_STIX_FILE_BYTES,
    get_latest_attack_version,
    import_attack_stix_file,
)

logger = logging.getLogger(__name__)

INDEX_URL = (
    "https://raw.githubusercontent.com/"
    "mitre-attack/attack-stix-data/master/index.json"
)

SOURCE_PREFIX = (
    "https://raw.githubusercontent.com/"
    "mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-"
)

SOURCE_SUFFIX = ".json"

CHECK_INTERVAL_SECONDS = 86400
RETRY_INTERVAL_SECONDS = 900
REQUEST_TIMEOUT = (10, 60)
MAX_INDEX_BYTES = 2 * 1024 * 1024

_VERSION_PATTERN = re.compile(r"^\d+\.\d+$")

_STOP_EVENT = threading.Event()
_WAKE_EVENT = threading.Event()
_WORKER_THREAD = None
_STATUS_LOCK = threading.Lock()
_SYNC_LOCK = threading.Lock()

_SYNC_STATUS = {
    "status": "not_started",
    "last_checked": None,
    "latest_available_version": None,
    "imported_version": None,
    "result": None,
    "error": None,
}


def get_sync_status():
    """Return a thread-safe snapshot of ATT&CK synchronization status."""
    with _STATUS_LOCK:
        return dict(_SYNC_STATUS)


def _record_status(result):
    with _STATUS_LOCK:
        _SYNC_STATUS.update(result)
        _SYNC_STATUS["last_checked"] = datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds")


def _version_key(version):
    if not isinstance(version, str) or not _VERSION_PATTERN.fullmatch(version):
        raise ValueError("Invalid Enterprise ATT&CK release version.")

    return tuple(int(part) for part in version.split("."))


def _get_latest_release(session=None):
    """Discover the newest versioned Enterprise release from MITRE's index."""
    client = session or requests

    response = client.get(
        INDEX_URL,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": "ShadowMapGRC-ATTACK-Updater/1.0"},
    )
    response.raise_for_status()

    content = response.content
    if not content or len(content) > MAX_INDEX_BYTES:
        raise ValueError("MITRE ATT&CK collection index is empty or too large.")

    try:
        index = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("MITRE ATT&CK collection index is invalid JSON.") from exc

    collections = index.get("collections")
    if not isinstance(collections, list):
        raise ValueError("MITRE ATT&CK index has no valid collections list.")

    enterprise = next(
        (
            item for item in collections
            if isinstance(item, dict)
            and item.get("name") == "Enterprise ATT&CK"
        ),
        None,
    )

    if enterprise is None:
        raise ValueError("Enterprise ATT&CK collection was not found.")

    versions = enterprise.get("versions")
    if not isinstance(versions, list) or not versions:
        raise ValueError("Enterprise ATT&CK release list is empty.")

    valid_releases = []

    for release in versions:
        if not isinstance(release, dict):
            continue

        version = release.get("version")
        url = release.get("url")
        modified = release.get("modified", "")

        if not isinstance(version, str) or not _VERSION_PATTERN.fullmatch(version):
            continue

        expected_url = f"{SOURCE_PREFIX}{version}{SOURCE_SUFFIX}"

        # Only accept the official, version-specific Enterprise JSON URL.
        if url != expected_url:
            continue

        if not isinstance(modified, str):
            modified = ""

        valid_releases.append({
            "version": version,
            "url": expected_url,
            "modified": modified,
        })

    if not valid_releases:
        raise ValueError("No valid versioned Enterprise ATT&CK releases found.")

    return max(
        valid_releases,
        key=lambda item: _version_key(item["version"]),
    )


def _download_and_import(release, session=None):
    """Download, validate and atomically import one official release."""
    client = session or requests
    temporary_path = None
    total_bytes = 0
    response = None

    try:
        response = client.get(
            release["url"],
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "ShadowMapGRC-ATTACK-Updater/1.0"},
            stream=True,
        )
        response.raise_for_status()

        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > MAX_STIX_FILE_BYTES:
            raise ValueError("ATT&CK STIX download exceeds the 100 MB limit.")

        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix="shadow-map-attack-sync-",
            suffix=".json",
            delete=False,
        ) as temporary_file:
            temporary_path = temporary_file.name

            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue

                total_bytes += len(chunk)

                if total_bytes > MAX_STIX_FILE_BYTES:
                    raise ValueError(
                        "ATT&CK STIX download exceeds the 100 MB limit."
                    )

                temporary_file.write(chunk)

        if total_bytes == 0:
            raise ValueError("MITRE returned an empty ATT&CK STIX file.")

        release_date = release.get("modified", "")[:10]

        return import_attack_stix_file(
            temporary_path,
            release["version"],
            database_path=DATABASE_PATH,
            release_date=release_date,
            source_reference=release["url"],
        )

    finally:
        if response is not None:
            response.close()

        if temporary_path:
            Path(temporary_path).unlink(missing_ok=True)


def sync_once():
    """Check MITRE and import a newer Enterprise release when available."""
    if not _SYNC_LOCK.acquire(blocking=False):
        return {
            "status": "already_running",
            "latest_available_version": None,
            "imported_version": None,
            "result": None,
            "error": "An ATT&CK synchronization is already running.",
        }

    result = {
        "status": "error",
        "latest_available_version": None,
        "imported_version": None,
        "result": None,
        "error": None,
    }

    try:
        release = _get_latest_release()
        remote_version = release["version"]
        result["latest_available_version"] = remote_version

        local_version = get_latest_attack_version(DATABASE_PATH)

        if (
            local_version
            and _version_key(local_version) >= _version_key(remote_version)
        ):
            result["status"] = "up_to_date"
            result["imported_version"] = local_version
            return result

        imported = _download_and_import(release)
        result["status"] = "updated"
        result["imported_version"] = imported["version"]
        result["result"] = imported

        logger.info(
            "Imported MITRE Enterprise ATT&CK version %s.",
            imported["version"],
        )

    except Exception as exc:
        logger.exception("MITRE ATT&CK synchronization failed.")
        result["error"] = str(exc)

    finally:
        _record_status(result)
        _SYNC_LOCK.release()

    return result


def request_update():
    """Queue an immediate check for the background worker."""
    if not (_WORKER_THREAD and _WORKER_THREAD.is_alive()):
        return False

    _WAKE_EVENT.set()
    return True


def _worker_loop():
    """Check immediately, then every 24 hours or retry after failure."""
    while not _STOP_EVENT.is_set():
        result = sync_once()

        if result["status"] in {"updated", "up_to_date"}:
            delay = CHECK_INTERVAL_SECONDS
        else:
            delay = RETRY_INTERVAL_SECONDS

        if _STOP_EVENT.is_set():
            break

        _WAKE_EVENT.wait(delay)
        _WAKE_EVENT.clear()


def start_worker():
    """Start one dedicated daemon worker; repeated calls are safe."""
    global _WORKER_THREAD

    if _WORKER_THREAD and _WORKER_THREAD.is_alive():
        return False

    _STOP_EVENT.clear()
    _WAKE_EVENT.clear()

    _WORKER_THREAD = threading.Thread(
        target=_worker_loop,
        name="shadow-map-attack-catalogue",
        daemon=True,
    )
    _WORKER_THREAD.start()
    return True


def stop_worker(timeout=2):
    """Request worker shutdown; useful for tests and controlled shutdown."""
    _STOP_EVENT.set()
    _WAKE_EVENT.set()

    if _WORKER_THREAD and _WORKER_THREAD.is_alive():
        _WORKER_THREAD.join(timeout=timeout)
