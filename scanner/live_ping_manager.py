import statistics
import threading
import time
from datetime import datetime, timezone

from config import DATABASE_PATH
from scanner.live_ping import (
    LivePingError,
    normalize_ping_target,
    resolve_ping_target,
    ping_once,
)


SESSION_LOCK = threading.RLock()
ACTIVE_SESSION = None

MIN_INTERVAL = 1
MAX_INTERVAL = 10
MIN_COUNT = 1
MAX_COUNT = 300
MAX_LOG_ENTRIES = 50


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _database():
    import sqlite3

    db = sqlite3.connect(DATABASE_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    return db


def _public_status(session):
    """Return a safe snapshot without exposing thread objects or locks."""
    with session["lock"]:
        latencies = list(session["latencies"])
        sent = session["packets_sent"]
        received = session["packets_received"]

        average = (
            round(statistics.fmean(latencies), 3)
            if latencies else None
        )

        return {
            "session_id": session["session_id"],
            "target": session["target"],
            "resolved_ips": list(session["resolved_ips"]),
            "status": session["status"],
            "interval_seconds": session["interval_seconds"],
            "max_packets": session["max_packets"],
            "packets_sent": sent,
            "packets_received": received,
            "packets_lost": sent - received,
            "packet_loss_percent": (
                round(((sent - received) / sent) * 100, 2)
                if sent else 0
            ),
            "min_latency_ms": round(min(latencies), 3) if latencies else None,
            "max_latency_ms": round(max(latencies), 3) if latencies else None,
            "avg_latency_ms": average,
            "last_latency_ms": (
                round(latencies[-1], 3) if latencies else None
            ),
            "started_at": session["started_at"],
            "finished_at": session["finished_at"],
            "duration_seconds": round(
                max(0, time.monotonic() - session["started_monotonic"]),
                2,
            ),
            "message": session["message"],
            "log": list(session["log"]),
        }


def _save_history(session):
    """Persist one completed or stopped monitoring session."""
    with session["lock"]:
        latencies = list(session["latencies"])
        sent = session["packets_sent"]
        received = session["packets_received"]
        finished_at = session["finished_at"] or _now()

        values = (
            session["target"],
            session["status"],
            sent,
            received,
            sent - received,
            min(latencies) if latencies else None,
            max(latencies) if latencies else None,
            statistics.fmean(latencies) if latencies else None,
            session["started_at"],
            finished_at,
            max(0, time.monotonic() - session["started_monotonic"]),
        )

    with _database() as db:
        db.execute(
            """
            INSERT INTO live_ping_history (
                target, status, packets_sent, packets_received,
                packets_lost, min_latency_ms, max_latency_ms,
                avg_latency_ms, started_at, finished_at,
                duration_seconds
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )


def _worker(session):
    global ACTIVE_SESSION

    try:
        while not session["stop_event"].is_set():
            result = ping_once(session["target"])

            with session["lock"]:
                if session["stop_event"].is_set():
                    break

                session["packets_sent"] += 1
                timestamp = _now()

                if result["reachable"]:
                    session["packets_received"] += 1
                    session["latencies"].append(result["latency_ms"])

                session["message"] = result["message"]
                session["log"].append({
                    "timestamp": timestamp,
                    "reachable": result["reachable"],
                    "latency_ms": result["latency_ms"],
                    "message": result["message"],
                })
                session["log"] = session["log"][-MAX_LOG_ENTRIES:]

                if session["packets_sent"] >= session["max_packets"]:
                    session["status"] = "Completed"
                    break

            session["stop_event"].wait(session["interval_seconds"])

        with session["lock"]:
            if session["status"] in {"Running", "Stopping"}:
                session["status"] = "Stopped"

    except Exception as exc:
        with session["lock"]:
            session["status"] = "Error"
            session["message"] = str(exc)

    finally:
        with session["lock"]:
            session["finished_at"] = _now()
            if session["status"] == "Running":
                session["status"] = "Stopped"

        try:
            _save_history(session)
        except Exception as exc:
            with session["lock"]:
                session["message"] = (
                    f"{session['message']} | History save failed: {exc}"
                ).strip(" |")

        with SESSION_LOCK:
            if ACTIVE_SESSION is session:
                ACTIVE_SESSION = None


def start_ping(target, interval_seconds=2, packet_count=10):
    """Validate settings and start one background monitoring session."""
    global ACTIVE_SESSION

    normalized_target = normalize_ping_target(target)
    resolved_ips = resolve_ping_target(normalized_target)

    try:
        interval_seconds = int(interval_seconds)
        packet_count = int(packet_count)
    except (TypeError, ValueError) as exc:
        raise LivePingError("Interval and packet count must be whole numbers.") from exc

    if not MIN_INTERVAL <= interval_seconds <= MAX_INTERVAL:
        raise LivePingError(
            f"Interval must be between {MIN_INTERVAL} and {MAX_INTERVAL} seconds."
        )

    if not MIN_COUNT <= packet_count <= MAX_COUNT:
        raise LivePingError(
            f"Packet count must be between {MIN_COUNT} and {MAX_COUNT}."
        )

    with SESSION_LOCK:
        if ACTIVE_SESSION is not None:
            if ACTIVE_SESSION["thread"].is_alive():
                raise LivePingError("A Live Ping session is already running.")
            ACTIVE_SESSION = None

        session = {
            "session_id": None,
            "target": normalized_target,
            "resolved_ips": resolved_ips,
            "status": "Running",
            "interval_seconds": interval_seconds,
            "max_packets": packet_count,
            "packets_sent": 0,
            "packets_received": 0,
            "latencies": [],
            "started_at": _now(),
            "finished_at": None,
            "started_monotonic": time.monotonic(),
            "message": "Monitoring started.",
            "log": [],
            "lock": threading.RLock(),
            "stop_event": threading.Event(),
            "thread": None,
        }

        worker = threading.Thread(
            target=_worker,
            args=(session,),
            daemon=True,
            name="shadow-map-live-ping",
        )

        session["thread"] = worker
        ACTIVE_SESSION = session

        try:
            worker.start()
        except Exception:
            ACTIVE_SESSION = None
            raise

        return _public_status(session)


def stop_ping():
    """Request a graceful stop after the current probe."""
    with SESSION_LOCK:
        session = ACTIVE_SESSION

        if session is None:
            raise LivePingError("There is no active Live Ping session.")

        with session["lock"]:
            if session["status"] != "Running":
                return _public_status(session)

            session["status"] = "Stopping"
            session["message"] = "Stopping monitoring..."
            session["stop_event"].set()

        return _public_status(session)


def get_ping_status():
    with SESSION_LOCK:
        session = ACTIVE_SESSION

        if session is None:
            return {
                "active": False,
                "status": "Idle",
            }

        result = _public_status(session)
        result["active"] = session["thread"].is_alive()
        return result


def get_recent_ping_history(limit=5):
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 5

    limit = max(1, min(limit, 5))

    with _database() as db:
        rows = db.execute(
            """
            SELECT id, target, status, packets_sent, packets_received,
                   packets_lost, min_latency_ms, max_latency_ms,
                   avg_latency_ms, started_at, finished_at,
                   duration_seconds
            FROM live_ping_history
            ORDER BY finished_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def shutdown_ping(timeout=5):
    """Request Live Ping shutdown and wait a bounded time for its worker."""
    with SESSION_LOCK:
        session = ACTIVE_SESSION

        if session is None:
            return True

        with session["lock"]:
            if session["status"] == "Running":
                session["status"] = "Stopping"
                session["message"] = "Application shutting down..."
            session["stop_event"].set()

        thread = session["thread"]

    if thread is threading.current_thread():
        return False

    thread.join(max(0, float(timeout)))
    return not thread.is_alive()
