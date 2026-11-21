import threading
from unittest.mock import Mock

from scanner import live_ping_manager as manager


def _session(thread):
    return {
        "status": "Running",
        "message": "Monitoring started.",
        "stop_event": threading.Event(),
        "thread": thread,
        "lock": threading.RLock(),
    }


def test_shutdown_ping_returns_true_when_no_session(monkeypatch):
    monkeypatch.setattr(manager, "ACTIVE_SESSION", None)

    assert manager.shutdown_ping() is True


def test_shutdown_ping_signals_and_joins_active_worker(monkeypatch):
    worker = Mock()
    worker.is_alive.return_value = False
    session = _session(worker)

    monkeypatch.setattr(manager, "ACTIVE_SESSION", session)

    assert manager.shutdown_ping(timeout=3) is True

    assert session["stop_event"].is_set()
    assert session["status"] == "Stopping"
    assert session["message"] == "Application shutting down..."
    worker.join.assert_called_once_with(3.0)


def test_shutdown_ping_reports_worker_that_did_not_stop(monkeypatch):
    worker = Mock()
    worker.is_alive.return_value = True
    session = _session(worker)

    monkeypatch.setattr(manager, "ACTIVE_SESSION", session)

    assert manager.shutdown_ping(timeout=0.1) is False

    assert session["stop_event"].is_set()
    worker.join.assert_called_once_with(0.1)


def test_shutdown_ping_does_not_join_current_thread(monkeypatch):
    current_thread = threading.current_thread()
    session = _session(current_thread)

    monkeypatch.setattr(manager, "ACTIVE_SESSION", session)

    assert manager.shutdown_ping() is False
    assert session["stop_event"].is_set()
