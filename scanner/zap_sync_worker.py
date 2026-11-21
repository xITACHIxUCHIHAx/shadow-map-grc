"""Background synchronization of existing local ZAP alerts into GRC drafts."""

import logging
import os
import threading
from datetime import datetime, timezone

from grc.automatic_risks import import_zap_alerts_to_drafts
from scanner.zap_proxy import (
    ZapProxyError,
    ensure_zap_running,
    fetch_alerts,
    load_endpoint,
)

logger = logging.getLogger(__name__)

_STOP_EVENT = threading.Event()
_WORKER_THREAD = None
_STATUS_LOCK = threading.Lock()
_SYNC_STATUS = {
    "status": "not_started",
    "last_checked": None,
    "fetched": 0,
    "created": 0,
}


def get_sync_status():
    """Return a safe snapshot of the latest synchronization status."""
    with _STATUS_LOCK:
        return dict(_SYNC_STATUS)


def _record_status(result):
    with _STATUS_LOCK:
        _SYNC_STATUS.update(result)
        _SYNC_STATUS["last_checked"] = datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        )


def sync_once():
    """Start local ZAP if needed and import its existing alerts as GRC drafts."""
    endpoint = load_endpoint()

    try:
        ensure_zap_running(endpoint)
        result = fetch_alerts(
            endpoint=endpoint,
            limit=100,
        )
        alerts = result.get("alerts", [])
        created = import_zap_alerts_to_drafts(alerts)

        return {
            "status": "ok",
            "fetched": len(alerts),
            "created": created,
        }

    except ZapProxyError:
        logger.info(
            "ZAP sync skipped because the local ZAP API is unavailable."
        )
        return {
            "status": "unavailable",
            "fetched": 0,
            "created": 0,
        }

    except Exception:
        logger.exception("Unexpected error during ZAP alert synchronization.")
        return {
            "status": "error",
            "fetched": 0,
            "created": 0,
        }


def _worker_loop(interval):
    while not _STOP_EVENT.is_set():
        result = sync_once()
        _record_status(result)

        if result["status"] == "ok" and result["fetched"]:
            logger.info(
                "ZAP sync checked %d existing alert(s); created %d new draft(s).",
                result["fetched"],
                result["created"],
            )

        _STOP_EVENT.wait(interval)


def start_worker():
    """Start one daemon worker; safe to call repeatedly."""
    global _WORKER_THREAD

    if _WORKER_THREAD and _WORKER_THREAD.is_alive():
        return False

    try:
        interval = int(os.environ.get("SHADOW_MAP_ZAP_SYNC_INTERVAL", "60"))
    except ValueError:
        interval = 60

    interval = max(30, min(interval, 3600))
    _STOP_EVENT.clear()

    _WORKER_THREAD = threading.Thread(
        target=_worker_loop,
        args=(interval,),
        name="shadow-map-zap-sync",
        daemon=True,
    )
    _WORKER_THREAD.start()
    return True


def stop_worker(timeout=2):
    """Ask the worker to stop; useful for controlled shutdown and tests."""
    _STOP_EVENT.set()

    if _WORKER_THREAD and _WORKER_THREAD.is_alive():
        _WORKER_THREAD.join(timeout=timeout)
