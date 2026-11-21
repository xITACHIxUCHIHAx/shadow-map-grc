"""SQLite persistence helpers for independent batch scan results."""

import json
from datetime import datetime, timezone

from grc.asset_observations import (
    ingest_firewall_observations,
    ingest_nmap_observations,
)
from grc.scan_registry import register_scan


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _register_module_scan(
    db, module, record_id, target, status,
    started_at, finished_at, duration_seconds,
):
    sources = {
        "web_security": ("Web Security", "web_security_scans"),
        "zap": ("OWASP ZAP", "zap_scans"),
        "threat_intel": ("Threat Intelligence", "threat_intel_lookups"),
        "firewall": ("Firewall", "firewall_scans"),
    }
    scan_type, source_table = sources[module]
    return register_scan(
        db,
        scan_type,
        source_table,
        record_id,
        target,
        status,
        started_at,
        finished_at,
        duration_seconds,
    )


def create_batch(db, module, profile, targets):
    created_at = now_utc()
    cursor = db.execute(
        """
        INSERT INTO scan_batches
            (module, profile, status, total_targets, created_at)
        VALUES (?, ?, 'Running', ?, ?)
        """,
        (module, profile or "", len(targets), created_at),
    )
    batch_id = cursor.lastrowid

    db.executemany(
        """
        INSERT INTO scan_batch_items
            (batch_id, position, target, status)
        VALUES (?, ?, ?, 'Pending')
        """,
        [
            (batch_id, position, target)
            for position, target in enumerate(targets, start=1)
        ],
    )
    return batch_id


def start_batch_item(db, item_id):
    db.execute(
        """
        UPDATE scan_batch_items
        SET status = 'Running', started_at = ?
        WHERE id = ? AND status = 'Pending'
        """,
        (now_utc(), item_id),
    )


def save_module_result(db, module, target, status, started_at,
                       duration_seconds, result=None, error=None):
    """Save one independent module result and return (result_type, id)."""
    finished_at = now_utc()
    result_json = (
        json.dumps(result, ensure_ascii=False)
        if result is not None else None
    )

    if module == "web_security":
        cursor = db.execute(
            """
            INSERT INTO web_security_scans
                (target, status, started_at, finished_at,
                 duration_seconds, result_json, error)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (target, status, started_at, finished_at,
             duration_seconds, result_json, error),
        )
        _register_module_scan(
            db, "web_security", cursor.lastrowid, target, status,
            started_at, finished_at, duration_seconds,
        )
        return "web_security", cursor.lastrowid

    if module == "zap":
        cursor = db.execute(
            """
            INSERT INTO zap_scans
                (target, status, started_at, finished_at,
                 duration_seconds, result_json, error)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (target, status, started_at, finished_at,
             duration_seconds, result_json, error),
        )
        _register_module_scan(
            db, "zap", cursor.lastrowid, target, status,
            started_at, finished_at, duration_seconds,
        )
        return "zap", cursor.lastrowid

    if module == "threat_intel":
        cursor = db.execute(
            """
            INSERT INTO threat_intel_lookups
                (target, status, started_at, finished_at,
                 duration_seconds, result_json, error)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (target, status, started_at, finished_at,
             duration_seconds, result_json, error),
        )
        _register_module_scan(
            db, "threat_intel", cursor.lastrowid, target, status,
            started_at, finished_at, duration_seconds,
        )
        return "threat_intel", cursor.lastrowid

    if module == "firewall":
        cursor = db.execute(
            """
            INSERT INTO firewall_scans
                (target, status, started_at, finished_at,
                 duration_seconds, result_json, error)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (target, status, started_at, finished_at,
             duration_seconds, result_json, error),
        )

        if status in {"Completed", "Partial"} and isinstance(result, dict):
            ingest_firewall_observations(
                db,
                target,
                result,
                observed_at=finished_at,
                source_record_id=str(cursor.lastrowid),
            )

        _register_module_scan(
            db, "firewall", cursor.lastrowid, target, status,
            started_at, finished_at, duration_seconds,
        )
        return "firewall", cursor.lastrowid

    raise ValueError(f"Unsupported result module: {module}")


def save_nmap_result(db, target, profile, status, started_at,
                     duration_seconds, result=None, error=None):
    """Save Nmap using its existing request, scan and port tables."""
    cursor = db.execute(
        """
        INSERT INTO scans (target, scan_type, status, created_at)
        VALUES (?, 'nmap', ?, ?)
        """,
        (target, status, started_at),
    )
    request_id = cursor.lastrowid

    cursor = db.execute(
        """
        INSERT INTO nmap_scans
            (request_id, target, status, started_at)
        VALUES (?, ?, ?, ?)
        """,
        (request_id, target, status, started_at),
    )
    scan_id = cursor.lastrowid

    if result:
        ports = result.get("ports", [])
        db.executemany(
            """
            INSERT INTO nmap_ports
                (scan_id, port, protocol, state, service, product,
                 version, extra_info, reason, service_method,
                 service_confidence, service_tunnel, service_cpe)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_id,
                    port["port"],
                    port["protocol"],
                    port["state"],
                    port["service"],
                    port["product"],
                    port["version"],
                    port["extra_info"],
                    port["reason"],
                    port.get("service_method", ""),
                    port.get("service_confidence", ""),
                    port.get("service_tunnel", ""),
                    json.dumps(
                        port.get("service_cpe", [])
                        if isinstance(port.get("service_cpe", []), list)
                        else []
                    ),
                )
                for port in ports
            ],
        )

    finished_at = now_utc()
    db.execute(
        """
        UPDATE nmap_scans
        SET status = ?, host_state = ?, finished_at = ?,
            duration_seconds = ?, command_display = ?,
            xml_output = ?, error = ?,
            mac_address = ?, mac_vendor = ?, os_match = ?,
            os_accuracy = ?, os_matches_json = ?,
            os_detection_status = ?
        WHERE id = ?
        """,
        (
            status,
            result.get("host_state") if result else None,
            finished_at,
            duration_seconds,
            result.get("command_display") if result else None,
            result.get("xml_output") if result else None,
            error,
            result.get("mac_address") if result else None,
            result.get("mac_vendor") if result else None,
            result.get("os_match") if result else None,
            str(result.get("os_accuracy"))
                if result and result.get("os_accuracy") is not None else None,
            json.dumps(result.get("os_matches", [])) if result else None,
            result.get("os_detection_status") if result else None,
            scan_id,
        ),
    )

    if status in {"Completed", "Partial"} and isinstance(result, dict):
        ingest_nmap_observations(
            db,
            target,
            result,
            observed_at=finished_at,
            source_record_id=str(scan_id),
        )

    register_scan(
        db,
        "Nmap",
        "nmap_scans",
        scan_id,
        target,
        status,
        started_at,
        finished_at,
        duration_seconds,
    )
    return "nmap", scan_id, request_id


def finish_batch_item(db, item_id, status, duration_seconds,
                      result_type="", result_record_id=None,
                      request_id=None, error=None):
    db.execute(
        """
        UPDATE scan_batch_items
        SET status = ?, finished_at = ?, duration_seconds = ?,
            result_type = ?, result_record_id = ?, request_id = ?,
            error = ?
        WHERE id = ?
        """,
        (
            status, now_utc(), duration_seconds, result_type,
            result_record_id, request_id, error, item_id,
        ),
    )


def finish_batch(db, batch_id):
    counts = db.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed,
            SUM(CASE WHEN status = 'Partial' THEN 1 ELSE 0 END) AS partial,
            SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed,
            SUM(CASE WHEN status = 'Skipped' THEN 1 ELSE 0 END) AS skipped
        FROM scan_batch_items
        WHERE batch_id = ?
        """,
        (batch_id,),
    ).fetchone()

    total = counts["total"] or 0
    completed = counts["completed"] or 0
    partial = counts["partial"] or 0
    failed = counts["failed"] or 0
    skipped = counts["skipped"] or 0

    if failed == total and total:
        status = "Failed"
    elif failed or partial:
        status = "Partial"
    else:
        status = "Completed"

    db.execute(
        """
        UPDATE scan_batches
        SET status = ?, completed_targets = ?, partial_targets = ?,
            failed_targets = ?, skipped_targets = ?, finished_at = ?
        WHERE id = ?
        """,
        (status, completed, partial, failed, skipped, now_utc(), batch_id),
    )

    return {
        "status": status,
        "total_targets": total,
        "completed_targets": completed,
        "partial_targets": partial,
        "failed_targets": failed,
        "skipped_targets": skipped,
    }
