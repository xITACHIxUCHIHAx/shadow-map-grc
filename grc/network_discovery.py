"""GRC storage and Flask routes for the authorized LAN Network Monitor."""

import json
import sqlite3
from datetime import datetime, timezone

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from config import DATABASE_PATH
from scanner.network_discovery import (
    NetworkDiscoveryError,
    discover_hosts,
    get_network_interfaces,
)


network_discovery_bp = Blueprint(
    "network_discovery",
    __name__,
    url_prefix="/network-discovery",
)


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect_db(database_path=None):
    """Open the Network Monitor SQLite database."""
    db = sqlite3.connect(
        database_path or DATABASE_PATH,
        timeout=15,
    )
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize_network_discovery(database_path=None):
    """Create or safely migrate Network Monitor tables."""
    with connect_db(database_path) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS network_discovery_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                interface_name TEXT NOT NULL,
                subnet TEXT NOT NULL,
                status TEXT NOT NULL,
                devices_found INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                error TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS network_discovery_run_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                device_data_json TEXT NOT NULL,
                FOREIGN KEY (run_id)
                    REFERENCES network_discovery_runs(id)
                    ON DELETE CASCADE,
                UNIQUE(run_id, ip_address)
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_run_devices_run_id
            ON network_discovery_run_devices(run_id)
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS discovered_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                interface_name TEXT NOT NULL,
                subnet TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                vendor TEXT,
                hostnames_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'not_recently_seen',
                device_type TEXT NOT NULL DEFAULT 'unknown',
                classification_confidence TEXT NOT NULL DEFAULT 'low',
                classification_evidence_json TEXT NOT NULL DEFAULT '[]',
                open_ports_json TEXT NOT NULL DEFAULT '[]',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_discovery_run_id INTEGER,
                UNIQUE(interface_name, ip_address),
                FOREIGN KEY (last_discovery_run_id)
                    REFERENCES network_discovery_runs(id)
            )
        """)

        # Migrate existing databases without removing any existing records.
        columns = {
            row["name"]
            for row in db.execute(
                "PRAGMA table_info(discovered_devices)"
            ).fetchall()
        }

        if "open_ports_json" not in columns:
            db.execute("""
                ALTER TABLE discovered_devices
                ADD COLUMN open_ports_json TEXT NOT NULL DEFAULT '[]'
            """)

        # Convert the previous scanner status into the new UI terminology.
        db.execute("""
            UPDATE discovered_devices
            SET status = 'online'
            WHERE status = 'up'
        """)

        # Backfill snapshots for legacy devices linked to completed runs.
        # Existing snapshots are never overwritten.
        legacy_rows = db.execute("""
            SELECT d.*
            FROM discovered_devices AS d
            INNER JOIN network_discovery_runs AS run
                ON run.id = d.last_discovery_run_id
            WHERE run.status = 'completed'
              AND run.interface_name = d.interface_name
              AND run.subnet = d.subnet
        """).fetchall()

        for row in legacy_rows:
            legacy_device = dict(row)

            for column, output_key in (
                ("hostnames_json", "hostnames"),
                ("classification_evidence_json", "classification_evidence"),
                ("open_ports_json", "open_ports"),
            ):
                try:
                    legacy_device[output_key] = json.loads(
                        legacy_device.pop(column, "[]")
                    )
                except (TypeError, json.JSONDecodeError):
                    legacy_device[output_key] = []

            snapshot_device = {
                key: legacy_device.get(key)
                for key in (
                    "ip_address",
                    "mac_address",
                    "vendor",
                    "hostnames",
                    "status",
                    "device_type",
                    "classification_confidence",
                    "classification_evidence",
                    "open_ports",
                )
            }

            db.execute("""
                INSERT OR IGNORE INTO network_discovery_run_devices (
                    run_id, ip_address, device_data_json
                )
                VALUES (?, ?, ?)
            """, (
                row["last_discovery_run_id"],
                row["ip_address"],
                json.dumps(snapshot_device),
            ))

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_discovered_devices_last_seen
            ON discovered_devices(last_seen DESC)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_network_discovery_runs_started
            ON network_discovery_runs(started_at DESC)
        """)


def _json_list(value):
    """Serialize a list-like scanner result safely for SQLite."""
    if value is None:
        value = []
    if not isinstance(value, list):
        raise ValueError("Expected a list of scanner results.")
    return json.dumps(value)


def save_discovery_run(interface_name, subnet, devices, database_path=None):
    """Persist a successful scan and update the current device inventory."""
    if not isinstance(devices, list):
        raise ValueError("Devices must be provided as a list.")

    timestamp = now_utc()

    with connect_db(database_path) as db:
        cursor = db.execute("""
            INSERT INTO network_discovery_runs (
                interface_name, subnet, status, devices_found,
                started_at, finished_at
            )
            VALUES (?, ?, 'completed', ?, ?, ?)
        """, (
            interface_name,
            subnet,
            len(devices),
            timestamp,
            timestamp,
        ))
        run_id = cursor.lastrowid

        # A successful scan is evidence that devices not seen in this scan
        # have not responded recently. It is not proof that they are offline.
        db.execute("""
            UPDATE discovered_devices
            SET status = 'not_recently_seen'
            WHERE interface_name = ?
              AND subnet = ?
        """, (interface_name, subnet))

        for device in devices:
            if not isinstance(device, dict) or not device.get("ip_address"):
                raise ValueError("Every discovered device must have an IP address.")

            hostnames_json = _json_list(device.get("hostnames", []))
            evidence_json = _json_list(
                device.get("classification_evidence", [])
            )
            open_ports_json = _json_list(device.get("open_ports", []))

            # Preserve this device exactly as observed during this scan.
            device_snapshot_json = json.dumps(device)

            db.execute("""
                INSERT INTO network_discovery_run_devices (
                    run_id, ip_address, device_data_json
                )
                VALUES (?, ?, ?)
            """, (
                run_id,
                device["ip_address"],
                device_snapshot_json,
            ))

            db.execute("""
                INSERT INTO discovered_devices (
                    interface_name, subnet, ip_address,
                    mac_address, vendor, hostnames_json,
                    status, device_type, classification_confidence,
                    classification_evidence_json, open_ports_json,
                    first_seen, last_seen, last_discovery_run_id
                )
                VALUES (?, ?, ?, ?, ?, ?, 'online', ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(interface_name, ip_address)
                DO UPDATE SET
                    subnet = excluded.subnet,
                    mac_address = COALESCE(
                        excluded.mac_address,
                        discovered_devices.mac_address
                    ),
                    vendor = COALESCE(
                        excluded.vendor,
                        discovered_devices.vendor
                    ),
                    hostnames_json = excluded.hostnames_json,
                    status = 'online',
                    device_type = excluded.device_type,
                    classification_confidence =
                        excluded.classification_confidence,
                    classification_evidence_json =
                        excluded.classification_evidence_json,
                    open_ports_json = excluded.open_ports_json,
                    last_seen = excluded.last_seen,
                    last_discovery_run_id =
                        excluded.last_discovery_run_id
            """, (
                interface_name,
                subnet,
                device["ip_address"],
                device.get("mac_address"),
                device.get("vendor"),
                hostnames_json,
                device.get("device_type", "unknown"),
                device.get("classification_confidence", "low"),
                evidence_json,
                open_ports_json,
                timestamp,
                timestamp,
                run_id,
            ))

    return run_id


def save_failed_discovery_run(
    interface_name,
    subnet,
    error,
    database_path=None,
):
    """Record a failed attempt without changing the device inventory."""
    timestamp = now_utc()

    with connect_db(database_path) as db:
        cursor = db.execute("""
            INSERT INTO network_discovery_runs (
                interface_name, subnet, status, devices_found,
                started_at, finished_at, error
            )
            VALUES (?, ?, 'failed', 0, ?, ?, ?)
        """, (
            interface_name or "unknown",
            subnet or "unknown",
            timestamp,
            timestamp,
            str(error)[:2000],
        ))
        return cursor.lastrowid


def get_discovered_devices(database_path=None):
    """Return devices detected in the latest successful scan overall."""
    with connect_db(database_path) as db:
        rows = db.execute("""
            SELECT d.*
            FROM network_discovery_runs AS run
            INNER JOIN network_discovery_run_devices AS snapshot
                ON snapshot.run_id = run.id
            INNER JOIN discovered_devices AS d
                ON d.interface_name = run.interface_name
               AND d.subnet = run.subnet
               AND d.ip_address = snapshot.ip_address
            WHERE run.id = (
                SELECT MAX(latest.id)
                FROM network_discovery_runs AS latest
                WHERE latest.status = 'completed'
            )
              AND run.status = 'completed'
            ORDER BY d.last_seen DESC, d.ip_address
        """).fetchall()

    devices = []

    for row in rows:
        device = dict(row)

        for column, output_key in (
            ("hostnames_json", "hostnames"),
            ("classification_evidence_json", "classification_evidence"),
            ("open_ports_json", "open_ports"),
        ):
            try:
                device[output_key] = json.loads(device.pop(column, "[]"))
            except (TypeError, json.JSONDecodeError):
                device[output_key] = []

        devices.append(device)

    return devices


def get_discovery_run_details(run_id, database_path=None):
    """Return one scan and its immutable historical device snapshots."""
    if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id < 1:
        raise ValueError("Run ID must be a positive integer.")

    with connect_db(database_path) as db:
        run = db.execute("""
            SELECT *
            FROM network_discovery_runs
            WHERE id = ?
        """, (run_id,)).fetchone()

        if run is None:
            return None

        rows = db.execute("""
            SELECT ip_address, device_data_json
            FROM network_discovery_run_devices
            WHERE run_id = ?
            ORDER BY ip_address
        """, (run_id,)).fetchall()

    devices = []

    for row in rows:
        try:
            device = json.loads(row["device_data_json"])
        except (TypeError, json.JSONDecodeError):
            device = {}

        if not isinstance(device, dict):
            device = {}

        device.setdefault("ip_address", row["ip_address"])
        devices.append(device)

    return {
        "run": dict(run),
        "devices": devices,
    }


def get_recent_discovery_runs(limit=10, database_path=None):
    """Return recent scan attempts."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("Limit must be a positive integer.")

    with connect_db(database_path) as db:
        rows = db.execute("""
            SELECT *
            FROM network_discovery_runs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


@network_discovery_bp.route("/runs/<int:run_id>")
def run_details(run_id):
    """Display an immutable historical scan result."""
    details = get_discovery_run_details(run_id)

    if details is None:
        abort(404)

    return render_template(
        "network_discovery_run.html",
        run=details["run"],
        devices=details["devices"],
        active_page=request.endpoint,
    )


@network_discovery_bp.route("/", methods=["GET", "POST"])
def index():
    interfaces = []
    interface_error = None
    selected_interface = request.form.get("interface", "").strip()
    selected_subnet = request.form.get("subnet", "").strip()

    try:
        interfaces = get_network_interfaces()

        # Select the first active interface on the initial page load.
        if request.method == "GET" and not selected_interface and interfaces:
            selected_interface = interfaces[0]["name"]

        # Populate the detected subnet when no manual value was supplied.
        selected_interface_details = next(
            (
                item for item in interfaces
                if item["name"] == selected_interface
            ),
            None,
        )

        if not selected_subnet and selected_interface_details:
            selected_subnet = selected_interface_details["network"]

    except NetworkDiscoveryError as exc:
        interface_error = str(exc)

    if request.method == "POST":
        authorized = request.form.get("authorized") == "yes"

        if not authorized:
            flash(
                "Confirm that you are authorized to discover devices "
                "on this network.",
                "error",
            )
        elif not selected_interface or not selected_subnet:
            flash("Select a network interface and enter a subnet.", "error")
        else:
            try:
                result = discover_hosts(
                    selected_subnet,
                    selected_interface,
                    authorized=True,
                )

                save_discovery_run(
                    selected_interface,
                    result["subnet"],
                    result["devices"],
                )

                flash(
                    f"Network scan completed. "
                    f"{result['devices_found']} device(s) found.",
                    "success",
                )
                return redirect(url_for("network_discovery.index"))

            except NetworkDiscoveryError as exc:
                save_failed_discovery_run(
                    selected_interface,
                    selected_subnet,
                    exc,
                )
                flash(str(exc), "error")

            except (sqlite3.Error, ValueError, KeyError, TypeError) as exc:
                flash(
                    "The scan could not be saved or its results were "
                    f"invalid: {exc}",
                    "error",
                )

    return render_template(
        "network_discovery.html",
        interfaces=interfaces,
        interface_error=interface_error,
        selected_interface=selected_interface,
        selected_subnet=selected_subnet,
        devices=get_discovered_devices(),
        recent_runs=get_recent_discovery_runs(),
        active_page=request.endpoint,
    )
