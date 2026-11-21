"""Global scan, target, and Unified Scan ID registry."""

import json
import sqlite3
from datetime import datetime, timezone

from target_identity import target_group_key, target_group_label


SCAN_SOURCES = {
    "Nmap": "nmap_scans",
    "Web Security": "web_security_scans",
    "Threat Intelligence": "threat_intel_lookups",
    "Firewall": "firewall_scans",
    "OWASP ZAP": "zap_scans",
}


def _now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def create_registry_tables(db):
    """Create additive registry tables without changing source records."""
    db.execute("""
        CREATE TABLE IF NOT EXISTS target_registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id TEXT UNIQUE,
            target_key TEXT NOT NULL UNIQUE,
            target_label TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS scan_registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE,
            scan_type TEXT NOT NULL,
            source_table TEXT NOT NULL,
            source_record_id INTEGER NOT NULL,
            target_id TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            duration_seconds REAL,
            created_at TEXT NOT NULL,
            UNIQUE (scan_type, source_record_id)
        )
    """)

    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_scan_registry_target
        ON scan_registry(target_id, started_at DESC)
    """)

    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_scan_registry_type_started
        ON scan_registry(scan_type, started_at DESC)
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS run_registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT UNIQUE,
            source_run_id INTEGER NOT NULL UNIQUE,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            finished_at TEXT
        )
    """)


def _get_or_create_target(db, target, seen_at):
    value = str(target or "").strip()
    key = json.dumps(
        target_group_key(value),
        ensure_ascii=True,
        separators=(",", ":"),
    )
    label = target_group_label(value)

    row = db.execute(
        "SELECT target_id FROM target_registry WHERE target_key = ?",
        (key,),
    ).fetchone()

    if row:
        db.execute(
            """
            UPDATE target_registry
            SET last_seen_at = CASE
                WHEN last_seen_at < ? THEN ?
                ELSE last_seen_at
            END
            WHERE target_key = ?
            """,
            (seen_at, seen_at, key),
        )
        return row[0]

    cursor = db.execute(
        """
        INSERT INTO target_registry
            (target_key, target_label, first_seen_at, last_seen_at)
        VALUES (?, ?, ?, ?)
        """,
        (key, label, seen_at, seen_at),
    )

    target_id = f"TGT-{cursor.lastrowid:05d}"

    db.execute(
        "UPDATE target_registry SET target_id = ? WHERE id = ?",
        (target_id, cursor.lastrowid),
    )

    return target_id


def register_scan(
    db,
    scan_type,
    source_table,
    source_record_id,
    target,
    status,
    started_at,
    finished_at=None,
    duration_seconds=None,
):
    """Register a persisted module scan and return its global SCN identifier."""
    if (
        scan_type not in SCAN_SOURCES
        or SCAN_SOURCES[scan_type] != source_table
    ):
        raise ValueError(
            f"Unsupported scan source: {scan_type} / {source_table}"
        )

    existing = db.execute(
        """
        SELECT scan_id
        FROM scan_registry
        WHERE scan_type = ? AND source_record_id = ?
        """,
        (scan_type, source_record_id),
    ).fetchone()

    if existing:
        db.execute(
            """
            UPDATE scan_registry
            SET status = ?, finished_at = ?, duration_seconds = ?
            WHERE scan_type = ? AND source_record_id = ?
            """,
            (
                status,
                finished_at,
                duration_seconds,
                scan_type,
                source_record_id,
            ),
        )
        return existing[0]

    timestamp = started_at or _now_utc()
    target_id = _get_or_create_target(db, target, timestamp)

    cursor = db.execute(
        """
        INSERT INTO scan_registry (
            scan_type, source_table, source_record_id,
            target_id, target, status, started_at,
            finished_at, duration_seconds, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_type,
            source_table,
            source_record_id,
            target_id,
            str(target or ""),
            status,
            timestamp,
            finished_at,
            duration_seconds,
            _now_utc(),
        ),
    )

    scan_id = f"SCN-{cursor.lastrowid:05d}"

    db.execute(
        "UPDATE scan_registry SET scan_id = ? WHERE id = ?",
        (scan_id, cursor.lastrowid),
    )

    return scan_id


def update_scan_status(
    db,
    scan_type,
    source_record_id,
    status,
    finished_at=None,
    duration_seconds=None,
):
    db.execute(
        """
        UPDATE scan_registry
        SET status = ?,
            finished_at = ?,
            duration_seconds = COALESCE(?, duration_seconds)
        WHERE scan_type = ? AND source_record_id = ?
        """,
        (
            status,
            finished_at,
            duration_seconds,
            scan_type,
            source_record_id,
        ),
    )


def register_run(db, source_run_id, status, created_at, finished_at=None):
    """Register a Unified Scan parent run and return its RUN identifier."""
    existing = db.execute(
        "SELECT run_id FROM run_registry WHERE source_run_id = ?",
        (source_run_id,),
    ).fetchone()

    if existing:
        db.execute(
            """
            UPDATE run_registry
            SET status = ?, finished_at = ?
            WHERE source_run_id = ?
            """,
            (status, finished_at, source_run_id),
        )
        return existing[0]

    cursor = db.execute(
        """
        INSERT INTO run_registry
            (source_run_id, status, created_at, finished_at)
        VALUES (?, ?, ?, ?)
        """,
        (source_run_id, status, created_at or _now_utc(), finished_at),
    )

    run_id = f"RUN-{cursor.lastrowid:05d}"

    db.execute(
        "UPDATE run_registry SET run_id = ? WHERE id = ?",
        (run_id, cursor.lastrowid),
    )

    return run_id


def update_run_status(db, source_run_id, status, finished_at=None):
    db.execute(
        """
        UPDATE run_registry
        SET status = ?, finished_at = ?
        WHERE source_run_id = ?
        """,
        (status, finished_at, source_run_id),
    )


def backfill_scan_registry(db):
    """Idempotently register existing module scans in chronological order."""
    records = []

    for scan_type, table in SCAN_SOURCES.items():
        rows = db.execute(
            f"""
            SELECT id, target, status, started_at,
                   finished_at, duration_seconds
            FROM {table}
            """
        ).fetchall()

        for row in rows:
            records.append((row[3] or "", scan_type, table, row))

    records.sort(
        key=lambda item: (item[0], item[1], item[3][0])
    )

    for _, scan_type, table, row in records:
        register_scan(
            db,
            scan_type,
            table,
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            row[5],
        )

    runs = db.execute(
        """
        SELECT id, status, created_at, finished_at
        FROM unified_scan_runs
        ORDER BY created_at, id
        """
    ).fetchall()

    for row in runs:
        register_run(db, row[0], row[1], row[2], row[3])


def initialize_scan_registry(database_path):
    """Create registry schema and perform an atomic historical backfill."""
    db = sqlite3.connect(database_path, timeout=15)

    try:
        create_registry_tables(db)
        backfill_scan_registry(db)
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
