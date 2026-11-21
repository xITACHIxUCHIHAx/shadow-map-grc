import json
from unittest.mock import Mock, patch

import pytest

from scanner import attack_catalogue_worker as worker


def _release(version="20.1"):
    return {
        "version": version,
        "url": f"{worker.SOURCE_PREFIX}{version}.json",
        "modified": "2026-11-05T00:00:00Z",
    }


def test_version_key_uses_numeric_ordering():
    assert worker._version_key("19.10") > worker._version_key("19.2")
    assert worker._version_key("20.1") > worker._version_key("19.10")


@pytest.mark.parametrize("version", ["", "v20.1", "20", "20.1.2", "../20.1"])
def test_version_key_rejects_invalid_versions(version):
    with pytest.raises(ValueError):
        worker._version_key(version)


def test_release_discovery_selects_newest_enterprise_version():
    releases = [
        _release("19.10"),
        _release("20.1"),
        _release("19.2"),
    ]
    response = Mock()
    response.content = json.dumps({
        "collections": [{
            "name": "Enterprise ATT&CK",
            "versions": releases,
        }]
    }).encode()
    response.json.return_value = {
        "collections": [{
            "name": "Enterprise ATT&CK",
            "versions": releases,
        }]
    }
    response.raise_for_status.return_value = None

    client = Mock()
    client.get.return_value = response

    result = worker._get_latest_release(session=client)

    assert result["version"] == "20.1"
    assert result["url"] == f"{worker.SOURCE_PREFIX}20.1.json"
    client.get.assert_called_once()


def test_release_discovery_rejects_untrusted_release_url():
    release = _release("20.1")
    release["url"] = "https://example.com/attack.json"

    response = Mock()
    response.content = b'{"collections": []}'
    response.json.return_value = {
        "collections": [{
            "name": "Enterprise ATT&CK",
            "versions": [release],
        }]
    }
    response.raise_for_status.return_value = None

    client = Mock()
    client.get.return_value = response

    with pytest.raises(ValueError, match="No valid versioned"):
        worker._get_latest_release(session=client)


def test_release_discovery_rejects_oversized_index():
    response = Mock()
    response.content = b"x" * (worker.MAX_INDEX_BYTES + 1)
    response.raise_for_status.return_value = None

    client = Mock()
    client.get.return_value = response

    with pytest.raises(ValueError, match="too large"):
        worker._get_latest_release(session=client)


def test_sync_once_skips_import_when_catalogue_is_current():
    release = _release("20.1")

    with (
        patch.object(worker, "_get_latest_release", return_value=release),
        patch.object(worker, "get_latest_attack_version", return_value="20.1"),
        patch.object(worker, "_download_and_import") as download,
        patch.object(worker, "_record_status"),
    ):
        result = worker.sync_once()

    assert result["status"] == "up_to_date"
    assert result["imported_version"] == "20.1"
    download.assert_not_called()


def test_sync_once_imports_newer_release():
    release = _release("20.1")
    imported = {
        "version": "20.1",
        "status": "success",
        "techniques_imported": 800,
    }

    with (
        patch.object(worker, "_get_latest_release", return_value=release),
        patch.object(worker, "get_latest_attack_version", return_value="19.2"),
        patch.object(worker, "_download_and_import", return_value=imported),
        patch.object(worker, "_record_status"),
    ):
        result = worker.sync_once()

    assert result["status"] == "updated"
    assert result["imported_version"] == "20.1"
    assert result["result"] == imported


def test_sync_once_preserves_error_status_when_discovery_fails():
    with (
        patch.object(
            worker,
            "_get_latest_release",
            side_effect=RuntimeError("network unavailable"),
        ),
        patch.object(worker, "_record_status"),
    ):
        result = worker.sync_once()

    assert result["status"] == "error"
    assert result["error"] == "network unavailable"
    assert result["imported_version"] is None


def test_request_update_requires_running_worker():
    with patch.object(worker, "_WORKER_THREAD", None):
        assert worker.request_update() is False


def test_request_update_wakes_running_worker():
    running_thread = Mock()
    running_thread.is_alive.return_value = True

    with (
        patch.object(worker, "_WORKER_THREAD", running_thread),
        patch.object(worker, "_WAKE_EVENT") as wake_event,
    ):
        assert worker.request_update() is True

    wake_event.set.assert_called_once()


def test_download_import_closes_response_and_removes_temp_file(
    monkeypatch,
):
    response = Mock()
    response.headers = {"Content-Length": "3"}
    response.iter_content.return_value = [b"abc"]
    response.raise_for_status.return_value = None

    client = Mock()
    client.get.return_value = response

    created_paths = []
    real_named_temporary_file = worker.tempfile.NamedTemporaryFile

    def tracked_temp_file(*args, **kwargs):
        handle = real_named_temporary_file(*args, **kwargs)
        created_paths.append(handle.name)
        return handle

    imported = {"version": "20.1", "status": "success"}

    monkeypatch.setattr(
        worker.tempfile, "NamedTemporaryFile", tracked_temp_file
    )

    def fake_import(path, version, **kwargs):
        from pathlib import Path
        assert Path(path).read_bytes() == b"abc"
        assert version == "20.1"
        return imported

    monkeypatch.setattr(worker, "import_attack_stix_file", fake_import)

    result = worker._download_and_import(_release(), session=client)

    assert result == imported
    response.close.assert_called_once()
    assert len(created_paths) == 1

    from pathlib import Path
    assert not Path(created_paths[0]).exists()


def test_download_http_error_still_closes_response():
    response = Mock()
    response.raise_for_status.side_effect = RuntimeError("HTTP 503")

    client = Mock()
    client.get.return_value = response

    with pytest.raises(RuntimeError, match="HTTP 503"):
        worker._download_and_import(_release(), session=client)

    response.close.assert_called_once()


def test_download_rejects_oversized_stream_and_cleans_temp_file(
    monkeypatch,
):
    response = Mock()
    response.headers = {}
    response.iter_content.return_value = [b"1234"]
    response.raise_for_status.return_value = None

    client = Mock()
    client.get.return_value = response

    created_paths = []
    real_named_temporary_file = worker.tempfile.NamedTemporaryFile

    def tracked_temp_file(*args, **kwargs):
        handle = real_named_temporary_file(*args, **kwargs)
        created_paths.append(handle.name)
        return handle

    monkeypatch.setattr(
        worker.tempfile, "NamedTemporaryFile", tracked_temp_file
    )
    monkeypatch.setattr(worker, "MAX_STIX_FILE_BYTES", 3)

    with pytest.raises(ValueError, match="exceeds the 100 MB limit"):
        worker._download_and_import(_release(), session=client)

    response.close.assert_called_once()

    from pathlib import Path
    assert len(created_paths) == 1
    assert not Path(created_paths[0]).exists()


def test_sync_once_rejects_concurrent_run(monkeypatch):
    assert worker._SYNC_LOCK.acquire(blocking=False)

    try:
        monkeypatch.setattr(
            worker,
            "_get_latest_release",
            Mock(side_effect=AssertionError("Must not start another sync")),
        )

        result = worker.sync_once()

        assert result["status"] == "already_running"
        assert result["error"] == (
            "An ATT&CK synchronization is already running."
        )
    finally:
        worker._SYNC_LOCK.release()
