import atexit
import csv
import ipaddress
import socket
import psutil
import subprocess
import io
import json
import sqlite3
import threading
import time
import re
import signal
from urllib.parse import urlsplit
from datetime import datetime, timezone
from grc.datetime_utils import format_datetime, format_date, format_time

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, abort, Response, jsonify
)

from config import DATABASE_PATH, SECRET_KEY, HOST, PORT, TRUSTED_PROXY_CIDRS
from grc.vulnerability_intelligence import initialize_vulnerability_intelligence
from grc.scan_registry import (
    initialize_scan_registry,
    register_run,
    register_scan,
    update_run_status,
    update_scan_status,
)
from grc.network_discovery import (
    network_discovery_bp,
    initialize_network_discovery,
)
from grc.vulnerability_correlation import correlate_asset_observations
from grc.asset_observations import _asset_identity
from reporting.pdf_generator import build_grc_pdf, build_nmap_pdf, build_web_security_pdf, build_threat_intel_pdf, build_unified_scan_pdf, build_firewall_pdf, build_zap_pdf, build_global_scan_history_pdf
from target_identity import group_targets
from scanner.nmap_scanner import run_nmap, NmapError, validate_target, parse_custom_ports, shutdown_active_nmap_processes
from scanner.live_ping import LivePingError
from scanner.live_ping_manager import (
    start_ping,
    stop_ping,
    get_ping_status,
    get_recent_ping_history,
    shutdown_ping,
)
from grc.automatic_risks import automatic_risks_bp, initialize_automatic_risks, generate_nmap_drafts, generate_web_security_drafts, generate_firewall_drafts, import_zap_alerts_to_drafts, sync_cve_exposures_to_findings, sync_cve_exposures_to_findings
from scanner.web_security_scanner import scan_web_security, WebSecurityError, _validate_public_https_url, _validate_authorized_web_url
from scanner.web_crawler import crawl_public_site
from scanner.run_limits import UnifiedWebRunGuard
from scanner.threat_intel import lookup_ip, ThreatIntelError, validate_public_ipv4
from scanner.firewall_scanner import scan_firewall, _parse_target as parse_firewall_target, FirewallScanError
from scanner.batch_runner import parse_batch_targets
from scanner.batch_storage import (
    now_utc,
    create_batch,
    start_batch_item,
    save_nmap_result,
    save_module_result,
    finish_batch_item,
    finish_batch,
)
from scanner.zap_install import detect_zap
from scanner.zap_sync_worker import get_sync_status, start_worker, stop_worker as stop_zap_sync_worker
from scanner.vulnerability_monitor_worker import start_worker as start_vulnerability_monitor_worker, stop_worker as stop_vulnerability_monitor_worker
from scanner.attack_catalogue_worker import start_worker as start_attack_catalogue_worker, stop_worker as stop_attack_catalogue_worker
from scanner.zap_proxy import (
    DEFAULT_ENDPOINT, ZapProxyError, load_endpoint,
    ensure_zap_running, fetch_alerts, validate_endpoint, shutdown_managed_zap,
)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.add_template_filter(format_datetime, 'datetime')
app.add_template_filter(format_date, 'date')
app.add_template_filter(format_time, 'time')
app.register_blueprint(automatic_risks_bp)
app.register_blueprint(network_discovery_bp)


def get_server_lan_ip():
    """Detect the server's active LAN IP using the operating system's route."""
    for family, destination in (
        (socket.AF_INET, ("1.1.1.1", 80)),
        (socket.AF_INET6, ("2606:4700:4700::1111", 80, 0, 0)),
    ):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as probe:
                probe.settimeout(2)
                probe.connect(destination)
                address = ipaddress.ip_address(probe.getsockname()[0])
                if not address.is_loopback and not address.is_unspecified:
                    return str(address)
        except (OSError, ValueError):
            continue

    return "Unavailable"



def _get_interface_ipv4(interface):
    """Read an IPv4 address assigned to an interface on any supported OS."""
    try:
        for address in psutil.net_if_addrs().get(interface, []):
            if address.family == socket.AF_INET:
                return str(ipaddress.ip_address(address.address))
    except (OSError, TypeError, ValueError):
        pass

    return None


def _get_interface_ipv6(interface):
    """Read a usable IPv6 address assigned to an interface."""
    try:
        for address in psutil.net_if_addrs().get(interface, []):
            if address.family == socket.AF_INET6:
                value = address.address.split("%", 1)[0]
                parsed = ipaddress.ip_address(value)
                if (
                    not parsed.is_loopback
                    and not parsed.is_unspecified
                    and not parsed.is_link_local
                ):
                    return str(parsed)
    except (OSError, TypeError, ValueError):
        pass

    return None


def _read_interface_mac(interface):
    """Read an interface hardware address on Windows, Linux or macOS."""
    try:
        link_family = getattr(psutil, "AF_LINK", None)
        if link_family is None:
            link_family = getattr(socket, "AF_PACKET", None)

        for address in psutil.net_if_addrs().get(interface, []):
            if address.family == link_family:
                value = address.address.strip().lower().replace("-", ":")
                if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value):
                    if value != "00:00:00:00:00:00":
                        return value
    except (OSError, TypeError, ValueError):
        pass

    return "Unavailable"


def get_interface_mac_for_ip(address):
    """Find the MAC address of the interface assigned the supplied IP."""
    try:
        parsed = ipaddress.ip_address(address)
        expected = str(parsed)
    except (OSError, TypeError, ValueError):
        return "Unavailable"

    address_reader = (
        _get_interface_ipv4 if parsed.version == 4 else _get_interface_ipv6
    )

    # Use psutil interface names directly for Windows, Linux and macOS.
    # socket.if_nameindex() may return different aliases on Windows.
    for interface in psutil.net_if_addrs():
        if address_reader(interface) == expected:
            mac = _read_interface_mac(interface)
            if mac != "Unavailable":
                return mac

    return "Unavailable"


def get_neighbor_mac(address):
    """Read a matching IPv4 or IPv6 neighbour entry without probing it."""
    try:
        expected = str(ipaddress.ip_address(address))
    except (TypeError, ValueError):
        return "Unavailable"

    parsed = ipaddress.ip_address(expected)
    if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
        return "Unavailable"

    try:
        result = subprocess.run(
            ["ip", "neigh", "show", "to", expected],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if result.returncode != 0:
            return "Unavailable"

        for line in result.stdout.splitlines():
            fields = line.split()
            if not fields or fields[0].split("%", 1)[0] != expected:
                continue

            for index, field in enumerate(fields[:-1]):
                if field == "lladdr":
                    mac = fields[index + 1].lower()
                    if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                        return mac
    except (OSError, subprocess.SubprocessError):
        pass

    return "Unavailable"


def get_connection_details():
    """Return request connection details without trusting arbitrary forwarded headers."""
    peer_value = request.remote_addr or ""
    try:
        peer = ipaddress.ip_address(peer_value)
    except ValueError:
        peer = None

    trusted_networks = []
    for value in TRUSTED_PROXY_CIDRS:
        try:
            trusted_networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue

    peer_is_trusted = bool(
        peer and any(peer in network for network in trusted_networks)
    )

    client_ip = str(peer) if peer else "Unknown"
    proxy_ip = str(peer) if peer_is_trusted else "Not detected"
    scheme = request.scheme.upper() if request.scheme in ("http", "https") else "Unknown"

    if peer_is_trusted:
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        forwarded_addresses = []

        for value in forwarded_for.split(","):
            try:
                forwarded_addresses.append(str(ipaddress.ip_address(value.strip())))
            except ValueError:
                continue

        # Walk from the immediate proxy toward the original client.
        # Trusted proxy hops are skipped; the first untrusted address is the client.
        chain = forwarded_addresses + [str(peer)]
        resolved_client = None

        for address in reversed(chain):
            current = ipaddress.ip_address(address)
            if any(current in network for network in trusted_networks):
                continue
            resolved_client = str(current)
            break

        client_ip = resolved_client or "Unknown"

        forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
        if forwarded_proto:
            candidate = forwarded_proto.split(",")[0].strip().lower()
            if candidate in ("http", "https"):
                scheme = candidate.upper()

    server_lan_ip = get_server_lan_ip()

    if client_ip == "Unknown":
        client_mac = "Unavailable"
    else:
        try:
            client_address = ipaddress.ip_address(client_ip)
            client_mac = (
                "Localhost"
                if client_address.is_loopback
                else get_neighbor_mac(client_ip)
            )
        except ValueError:
            client_mac = "Unavailable"

    return {
        "client_ip": client_ip,
        "client_mac_address": client_mac,
        "server_lan_ip": server_lan_ip,
        "server_mac_address": get_interface_mac_for_ip(server_lan_ip),
        "proxy_ip": proxy_ip,
        "proxy_detected": peer_is_trusted,
        "connection_scheme": scheme,
    }


@app.context_processor
def inject_connection_details():
    return {"connection_details": get_connection_details()}

NAV_ITEMS = [
    {"endpoint": "dashboard", "label": "Dashboard", "icon": "⌂"},
    {"endpoint": "nmap_page", "label": "Nmap", "icon": "⌘"},
    {"endpoint": "threat_intel_page", "label": "Threat Intelligence", "icon": "◈"},
    {"endpoint": "custom_rules_page", "label": "Custom Rules", "icon": "⚙"},
    {"endpoint": "combined_findings_page", "label": "Combined Findings", "icon": "▤"},
    {"endpoint": "traceability_page", "label": "Traceability", "icon": "↔"},
    {"endpoint": "automatic_risks.findings_page", "label": "Findings Review", "icon": "✓"},
    {"endpoint": "reports_page", "label": "Reports & GRC", "icon": "▧"},
    {"endpoint": "history_page", "label": "Scan History", "icon": "◷"},
    {"endpoint": "risk_register_page", "label": "Risk Register", "icon": "⚑"},
    {"endpoint": "records_management_page", "label": "Records Management", "icon": "▣"},
]


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db():
    db = sqlite3.connect(DATABASE_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with get_db() as db:
        # Preserve the existing scan-request table.
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS nmap_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                host_state TEXT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                duration_seconds REAL,
                command_display TEXT,
                xml_output TEXT,
                error TEXT,
                mac_address TEXT,
                mac_vendor TEXT,
                os_match TEXT,
                os_accuracy TEXT,
                os_matches_json TEXT,
                FOREIGN KEY (request_id) REFERENCES scans(id)
            )
        """)

        # Store the latest genuine Nmap task progress separately.
        db.execute("""
            CREATE TABLE IF NOT EXISTS nmap_scan_progress (
                scan_id INTEGER PRIMARY KEY,
                task TEXT NOT NULL DEFAULT 'Starting',
                percent REAL NOT NULL DEFAULT 0,
                remaining_seconds INTEGER,
                estimated_completion TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES nmap_scans(id)
                    ON DELETE CASCADE
            )
        """)

        # Add Nmap metadata columns to existing databases safely.
        existing_columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(nmap_scans)").fetchall()
        }

        metadata_columns = {
            "mac_address": "TEXT",
            "mac_vendor": "TEXT",
            "os_match": "TEXT",
            "os_accuracy": "TEXT",
            "os_matches_json": "TEXT",
            "os_detection_status": "TEXT",
        }

        for column, definition in metadata_columns.items():
            if column not in existing_columns:
                db.execute(
                    f"ALTER TABLE nmap_scans ADD COLUMN {column} {definition}"
                )

        db.execute("""
            CREATE TABLE IF NOT EXISTS nmap_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                service TEXT,
                product TEXT,
                version TEXT,
                extra_info TEXT,
                reason TEXT,
                FOREIGN KEY (scan_id) REFERENCES nmap_scans(id)
                    ON DELETE CASCADE
            )
        """)

        existing_port_columns = {
            row["name"]
            for row in db.execute(
                "PRAGMA table_info(nmap_ports)"
            ).fetchall()
        }

        port_metadata_columns = {
            "service_method": "TEXT",
            "service_confidence": "TEXT",
            "service_tunnel": "TEXT",
            "service_cpe": "TEXT",
        }

        for column, definition in port_metadata_columns.items():
            if column not in existing_port_columns:
                db.execute(
                    f"ALTER TABLE nmap_ports ADD COLUMN "
                    f"{column} {definition}"
                )

        # Batch scan tracking. Each target remains an independent item.
        db.execute("""
            CREATE TABLE IF NOT EXISTS scan_batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module TEXT NOT NULL,
                profile TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'Running',
                total_targets INTEGER NOT NULL DEFAULT 0,
                completed_targets INTEGER NOT NULL DEFAULT 0,
                partial_targets INTEGER NOT NULL DEFAULT 0,
                failed_targets INTEGER NOT NULL DEFAULT 0,
                skipped_targets INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                finished_at TEXT
            )
        """)

        existing_batch_columns = {
            row["name"]
            for row in db.execute(
                "PRAGMA table_info(scan_batches)"
            ).fetchall()
        }
        if "skipped_targets" not in existing_batch_columns:
            db.execute(
                "ALTER TABLE scan_batches ADD COLUMN "
                "skipped_targets INTEGER NOT NULL DEFAULT 0"
            )

        db.execute("""
            CREATE TABLE IF NOT EXISTS scan_batch_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id INTEGER NOT NULL,
                position INTEGER NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                started_at TEXT,
                finished_at TEXT,
                duration_seconds REAL,
                result_type TEXT NOT NULL DEFAULT '',
                result_record_id INTEGER,
                request_id INTEGER,
                error TEXT,
                FOREIGN KEY (batch_id) REFERENCES scan_batches(id)
                    ON DELETE CASCADE,
                UNIQUE (batch_id, position)
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_batch_items_batch
            ON scan_batch_items(batch_id, position)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_batch_items_result
            ON scan_batch_items(result_type, result_record_id)
        """)


        # Link the independent module batches created by one unified submission.
        db.execute("""
            CREATE TABLE IF NOT EXISTS unified_scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                targets_json TEXT NOT NULL,
                modules_json TEXT NOT NULL,
                batch_ids_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'Running',
                created_at TEXT NOT NULL,
                finished_at TEXT
            )
        """)

        # Persist each Web Security assessment independently.
        # Live progress for background Unified Scan executions.
        db.execute("""
            CREATE TABLE IF NOT EXISTS unified_scan_progress (
                run_id INTEGER NOT NULL,
                module TEXT NOT NULL,
                target TEXT NOT NULL,
                task TEXT NOT NULL DEFAULT 'Queued',
                percent REAL,
                remaining_seconds INTEGER,
                estimated_completion TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (run_id, module, target),
                FOREIGN KEY (run_id) REFERENCES unified_scan_runs(id)
                    ON DELETE CASCADE
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS web_security_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                duration_seconds REAL,
                result_json TEXT,
                error TEXT
            )
        """)

        # Persist independent OWASP ZAP assessment results.
        db.execute("""
            CREATE TABLE IF NOT EXISTS zap_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                duration_seconds REAL,
                result_json TEXT,
                error TEXT
            )
        """)

        # Persist each Threat Intelligence lookup independently.
        db.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel_lookups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                duration_seconds REAL,
                result_json TEXT,
                error TEXT
            )
        """)

        # Persist independent Firewall Detection assessment results.
        db.execute("""
            CREATE TABLE IF NOT EXISTS firewall_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                duration_seconds REAL,
                result_json TEXT,
                error TEXT
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_firewall_scans_target
            ON firewall_scans(target, id)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_web_security_scans_target
            ON web_security_scans(target, id)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_intel_lookups_target
            ON threat_intel_lookups(target, id)
        """)

        # Persist explicit authorization scopes independently of scan history.
        db.execute("""
            CREATE TABLE IF NOT EXISTS authorized_scopes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope_name TEXT NOT NULL,
                target TEXT NOT NULL,
                ports_json TEXT NOT NULL DEFAULT '[]',
                paths_json TEXT NOT NULL DEFAULT '[]',
                excluded_paths_json TEXT NOT NULL DEFAULT '[]',
                profiles_json TEXT NOT NULL DEFAULT '["standard"]',
                techniques_json TEXT NOT NULL DEFAULT '[]',
                sql_contexts_json TEXT NOT NULL DEFAULT '[]',
                test_accounts_json TEXT NOT NULL DEFAULT '[]',
                rate_limit_rps REAL NOT NULL DEFAULT 1.0,
                max_requests INTEGER NOT NULL DEFAULT 50,
                status TEXT NOT NULL DEFAULT 'Pending'
                    CHECK (status IN ('Pending', 'Approved', 'Revoked', 'Expired')),
                authorization_note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                approved_at TEXT,
                expires_at TEXT NOT NULL,
                approver_attestation TEXT,
                revoked_at TEXT,
                revocation_reason TEXT
            )
        """)

        # Migrate existing authorization databases without changing scope history.
        authorized_scope_columns = {
            row["name"]
            for row in db.execute(
                "PRAGMA table_info(authorized_scopes)"
            ).fetchall()
        }
        if "sql_contexts_json" not in authorized_scope_columns:
            db.execute("""
                ALTER TABLE authorized_scopes
                ADD COLUMN sql_contexts_json TEXT NOT NULL DEFAULT '[]'
            """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_authorized_scopes_target_status
            ON authorized_scopes(target, status, expires_at)
        """)

        # Record scope lifecycle events; application code must append, not rewrite.
        db.execute("""
            CREATE TABLE IF NOT EXISTS scope_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                actor_attestation TEXT NOT NULL DEFAULT '',
                event_details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_scope_audit_log_scope
            ON scope_audit_log(scope_id, id)
        """)

        # Persist completed Live Ping monitoring sessions.
        db.execute("""
            CREATE TABLE IF NOT EXISTS live_ping_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                packets_sent INTEGER NOT NULL DEFAULT 0,
                packets_received INTEGER NOT NULL DEFAULT 0,
                packets_lost INTEGER NOT NULL DEFAULT 0,
                min_latency_ms REAL,
                max_latency_ms REAL,
                avg_latency_ms REAL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                duration_seconds REAL NOT NULL DEFAULT 0
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_live_ping_history_recent
            ON live_ping_history(finished_at DESC, id DESC)
        """)


    initialize_vulnerability_intelligence(DATABASE_PATH)
    initialize_automatic_risks()
    initialize_network_discovery(DATABASE_PATH)
    initialize_scan_registry(DATABASE_PATH)


init_db()


def get_recent_scans(limit=10):
    with get_db() as db:
        return db.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()


def render_section(title, subtitle, description, notice):
    return render_template(
        "section.html",
        nav_items=NAV_ITEMS,
        active_page=request.endpoint,
        title=title,
        subtitle=subtitle,
        description=description,
        notice=notice,
        scans=get_recent_scans(100),
    )




def record_unified_progress(run_id, module, target, event):
    """Persist genuine scanner progress without interrupting the scanner."""
    try:
        with get_db() as db:
            db.execute(
                """
                INSERT INTO unified_scan_progress
                    (run_id, module, target, task, percent,
                     remaining_seconds, estimated_completion, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, module, target) DO UPDATE SET
                    task = excluded.task,
                    percent = CASE
                        WHEN ? THEN excluded.percent
                        ELSE COALESCE(excluded.percent, unified_scan_progress.percent)
                    END,
                    remaining_seconds = COALESCE(
                        excluded.remaining_seconds,
                        unified_scan_progress.remaining_seconds
                    ),
                    estimated_completion = COALESCE(
                        excluded.estimated_completion,
                        unified_scan_progress.estimated_completion
                    ),
                    updated_at = excluded.updated_at
                """,
                (
                    run_id, module, target,
                    event.get("task", "Assessment"),
                    event.get("percent"),
                    event.get("remaining_seconds"),
                    event.get("estimated_completion"),
                    now_utc(),
                    "percent" in event,
                ),
            )
    except Exception:
        app.logger.exception(
            "Could not persist Unified Scan progress for %s", target
        )


def update_unified_progress_state(run_id, module, target, task):
    """Update a target's state without inventing or resetting scan percentages."""
    try:
        with get_db() as db:
            db.execute(
                """
                UPDATE unified_scan_progress
                SET task = ?,
                    percent = CASE
                        WHEN ? IN ('Completed', 'Partial') THEN 100
                        WHEN ? IN ('Failed', 'Skipped') THEN NULL
                        ELSE percent
                    END,
                    updated_at = ?
                WHERE run_id = ? AND module = ? AND target = ?
                """,
                (task, task, task, now_utc(), run_id, module, target),
            )
    except Exception:
        app.logger.exception(
            "Could not update Unified Scan state for %s", target
        )


class ThreatIntelNotApplicable(Exception):
    """Raised when a target is outside public Threat Intelligence coverage."""


def _threat_intel_non_public_reason(raw_target):
    """Classify valid HTTPS targets that resolve to non-public addresses."""
    value = (raw_target or "").strip()
    if not value or len(value) > 2048:
        return None

    candidate = value if "://" in value else "https://" + value

    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        return None

    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or port not in (None, 443)
    ):
        return None

    host = parsed.hostname.rstrip(".")
    if not host or any(char.isspace() for char in host):
        return None

    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            records = socket.getaddrinfo(
                host, None, family=socket.AF_INET,
                type=socket.SOCK_STREAM,
            )
            addresses = [
                ipaddress.ip_address(record[4][0])
                for record in records
            ]
        except (OSError, ValueError):
            return None

    if addresses and any(not address.is_global for address in addresses):
        return (
            "Skipped: Threat Intelligence lookup supports public IP addresses "
            "only. This target resolves to a private or non-public address; "
            "the other selected assessment modules can still scan it."
        )

    return None


def normalize_unified_target(raw_target, module):
    """Normalize one submitted hostname, HTTPS URL, or public IPv4 for a module."""
    raw_target = (raw_target or "").strip()
    if not raw_target:
        raise ValueError("Enter a hostname, HTTPS URL, or public IPv4 address.")

    if module == "nmap":
        # Nmap supports authorized private, loopback, and public targets.
        # Do not apply Web Security's public-address restriction here.
        return validate_target(raw_target)

    if module == "web_security":
        return _validate_authorized_web_url(raw_target)

    if module == "zap":
        # ZAP supports authorized public and private HTTP/HTTPS targets.
        return _validate_authorized_web_url(raw_target)

    if module == "firewall":
        try:
            parse_firewall_target(raw_target)
            return raw_target
        except FirewallScanError as exc:
            raise ValueError(str(exc)) from exc

    # Threat Intelligence is public-IP-only. Classify non-public targets
    # separately so Unified Scan can mark this module Not Applicable.
    if module == "threat_intel":
        reason = _threat_intel_non_public_reason(raw_target)
        if reason:
            raise ThreatIntelNotApplicable(reason)

    safe_url = _validate_public_https_url(raw_target)
    host = urlsplit(safe_url).hostname
    if not host:
        raise ValueError("The target hostname is invalid.")

    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        try:
            records = socket.getaddrinfo(
                host, None, family=socket.AF_INET,
                type=socket.SOCK_STREAM,
            )
            addresses = [
                ipaddress.ip_address(record[4][0])
                for record in records
            ]
        except (OSError, ValueError) as exc:
            raise ValueError(
                "The hostname could not be resolved to an IPv4 address."
            ) from exc

    if not addresses:
        raise ValueError("The hostname has no usable IPv4 address.")

    if any(
        not isinstance(address, ipaddress.IPv4Address)
        or not address.is_global
        for address in addresses
    ):
        raise ValueError(
            "The target resolves to a private or non-public address and was blocked."
        )

    public_ip = str(addresses[0])

    if module == "nmap":
        return validate_target(public_ip)
    if module == "threat_intel":
        return validate_public_ipv4(public_ip)

    raise ValueError("Unsupported Unified Scan module.")


def _run_unified_scan_background(run_id, targets, modules, profile, detect_os=False, custom_ports=None):
    """Execute a Unified Scan outside the HTTP request."""
    batch_ids = {}
    overall_error = False

    try:
        batch_ids = {}
        overall_error = False

        try:
            # One aggregate HTTP budget/deadline shared by every Web
            # Security target in this Unified Scan run.
            web_run_guard = (
                UnifiedWebRunGuard()
                if "web_security" in modules
                else None
            )

            for module in modules:
                module_profile = {
                    "nmap": (
                        f"custom_tcp:{','.join(map(str, custom_ports))}"
                        if custom_ports else profile
                    ),
                    "web_security": "wapiti_web_assessment",
                    "threat_intel": "shodan_internetdb",
                    "firewall": "native_firewall_detection",
                    "zap": "zap_active_scan",
                }[module]

                with get_db() as db:
                    batch_id = create_batch(
                        db, module, module_profile, targets
                    )
                    batch_ids[module] = batch_id
                    db.execute(
                        """
                        UPDATE unified_scan_runs
                        SET batch_ids_json = ?
                        WHERE id = ?
                        """,
                        (json.dumps(batch_ids), run_id),
                    )
                    items = db.execute(
                        """
                        SELECT id, position, target
                        FROM scan_batch_items
                        WHERE batch_id = ?
                        ORDER BY position
                        """,
                        (batch_id,),
                    ).fetchall()

                for item in items:
                    item_id = item["id"]
                    raw_target = item["target"]
                    started_at = now_utc()
                    item_started = time.monotonic()

                    with get_db() as db:
                        start_batch_item(db, item_id)

                    if module == "web_security" and web_run_guard is not None:
                        try:
                            web_run_guard.check()
                        except Exception as exc:
                            error = str(exc) or exc.__class__.__name__
                            duration = time.monotonic() - item_started
                            overall_error = True

                            with get_db() as db:
                                finish_batch_item(
                                    db,
                                    item_id,
                                    "Skipped",
                                    duration,
                                    error=error,
                                )

                            update_unified_progress_state(
                                run_id, module, raw_target, "Skipped"
                            )
                            continue

                    validated_target = None
                    result = None
                    error = None
                    status = "Failed"
                    result_type = ""
                    result_id = None
                    request_id = None

                    # Validate independently for each selected module.
                    update_unified_progress_state(
                        run_id, module, raw_target, "Validating"
                    )
                    try:
                        validated_target = normalize_unified_target(
                            raw_target, module
                        )
                    except ThreatIntelNotApplicable as exc:
                        error = str(exc)
                        duration = time.monotonic() - item_started
                        with get_db() as db:
                            finish_batch_item(
                                db, item_id, "Skipped", duration, error=error
                            )
                        update_unified_progress_state(
                            run_id, module, raw_target, "Skipped"
                        )
                        continue
                    except Exception as exc:
                        error = str(exc) or exc.__class__.__name__
                        duration = time.monotonic() - item_started
                        with get_db() as db:
                            finish_batch_item(
                                db, item_id, "Failed", duration, error=error
                            )
                        update_unified_progress_state(
                            run_id, module, raw_target, "Failed"
                        )
                        continue

                    scan_started = time.monotonic()

                    # Execute only the selected module's scanner.
                    update_unified_progress_state(
                        run_id, module, raw_target,
                        "Running Nmap" if module == "nmap"
                        else "Running Web Security" if module == "web_security"
                        else "Running Threat Intelligence" if module == "threat_intel"
                        else "Running Firewall Detection" if module == "firewall"
                        else "Running OWASP ZAP" if module == "zap"
                        else "Running Unknown Module"
                    )
                    try:
                        if module == "nmap":
                            result = run_nmap(
                                validated_target,
                                scan_profile=profile,
                                detect_os=detect_os,
                                custom_ports=custom_ports,
                                progress_callback=lambda event: record_unified_progress(
                                    run_id, module, raw_target, event
                                ),
                            )
                            status = result.get("status", "Completed")
                            if status not in {"Completed", "Partial"}:
                                status = "Failed"
                            error = result.get("error")

                        elif module == "web_security":
                            result = scan_web_security(
                                validated_target,
                                run_guard=web_run_guard,
                                progress_callback=lambda event: record_unified_progress(
                                    run_id, module, raw_target, event
                                ),
                            )
                            discovery = (
                                result.get("discovery")
                                if isinstance(result, dict)
                                else None
                            )
                            discovery_incomplete = (
                                not isinstance(discovery, dict)
                                or bool(result.get("discovery_error"))
                                or bool(discovery.get("errors"))
                                or bool(discovery.get("blocked_urls"))
                                or bool(discovery.get("deferred_urls"))
                                or bool(discovery.get("truncated"))
                                or bool(result.get("blocked_redirect"))
                                or bool(discovery.get("blocked_redirect"))
                            )
                            status = (
                                "Partial"
                                if discovery_incomplete
                                else "Completed"
                            )

                        elif module == "threat_intel":
                            result = lookup_ip(
                                validated_target,
                                progress_callback=lambda event: record_unified_progress(
                                    run_id, module, raw_target, event
                                ),
                            )
                            status = "Completed"

                        elif module == "firewall":
                            result = scan_firewall(
                                validated_target,
                                tcp_ports=custom_ports,
                                progress_callback=lambda event: record_unified_progress(
                                    run_id, module, raw_target, event
                                ),
                            )
                            status = "Completed"

                        elif module == "zap":
                            from scanner.zap_proxy import (
                                ensure_zap_running,
                                trigger_zap_active_scan,
                                fetch_alerts,
                            )
                            # ZAP requires an http:// or https:// scheme.
                            # If the validated target lost its scheme,
                            # restore it before passing to ZAP.
                            zap_url = validated_target
                            if not str(zap_url).lower().startswith(
                                ("http://", "https://")
                            ):
                                zap_url = "http://" + str(zap_url).lstrip("/")

                            app.logger.info(
                                "ZAP module: ensure_zap_running() ..."
                            )
                            ensure_zap_running()
                            app.logger.info(
                                "ZAP module: trigger_zap_active_scan(%s) ...",
                                zap_url,
                            )
                            zap_result = trigger_zap_active_scan(
                                zap_url,
                                timeout=300,
                                progress_callback=lambda event: record_unified_progress(
                                    run_id, module, raw_target, event
                                ),
                            )
                            result = zap_result
                            zap_state = zap_result.get("status", "")
                            status = (
                                "Completed"
                                if zap_state == "finished"
                                else "Partial"
                            )
                            app.logger.info(
                                "ZAP module: scan %s (spider=%s ascan=%s)",
                                zap_state,
                                zap_result.get("spider_scan_id"),
                                zap_result.get("ascan_scan_id"),
                            )

                            # Store the alert evidence with this scan record.
                            # Alert retrieval failure must not discard a valid scan.
                            result = dict(zap_result)
                            try:
                                alerts_result = fetch_alerts(base_url=zap_url, limit=200)
                                alerts = alerts_result.get("alerts", [])
                                if not isinstance(alerts, list):
                                    alerts = []
                                result["alerts"] = alerts
                                result["alerts_count"] = len(alerts)
                            except Exception as alerts_exc:
                                result["alerts"] = []
                                result["alerts_count"] = 0
                                result["alerts_error"] = (
                                    str(alerts_exc)[:1000]
                                    or alerts_exc.__class__.__name__
                                )
                                app.logger.warning(
                                    "ZAP scan completed but alert retrieval "
                                    "failed for %s: %s",
                                    validated_target,
                                    alerts_exc,
                                )

                        else:
                            raise ValueError(
                                f"Unsupported Unified Scan module: {module}"
                            )

                    except Exception as exc:
                        error = str(exc) or exc.__class__.__name__
                        aggregate_limit_reached = (
                            module == "web_security"
                            and "unified web security" in error.lower()
                        )
                        status = (
                            "Partial" if aggregate_limit_reached else "Failed"
                        )
                        result = None
                        app.logger.warning(
                            "%s unified scan item %s failed: %s",
                            module, item["position"], error,
                        )

                    duration = (
                        float(result.get("duration_seconds") or
                              (time.monotonic() - scan_started))
                        if module in {"nmap", "firewall"}
                        and isinstance(result, dict)
                        else time.monotonic() - scan_started
                    )

                    # Persist each result once; never retry a result insert.
                    try:
                        with get_db() as db:
                            if module == "nmap":
                                result_type, result_id, request_id = save_nmap_result(
                                    db,
                                    validated_target,
                                    profile,
                                    status,
                                    started_at,
                                    duration,
                                    result=result,
                                    error=error,
                                )
                            else:
                                result_type, result_id = save_module_result(
                                    db,
                                    module,
                                    validated_target,
                                    status,
                                    started_at,
                                    duration,
                                    result=result,
                                    error=error,
                                )

                            finish_batch_item(
                                db,
                                item_id,
                                status,
                                duration,
                                result_type,
                                result_id,
                                request_id,
                                error,
                            )

                    except Exception:
                        overall_error = True
                        app.logger.exception(
                            "%s unified scan item %s could not be persisted",
                            module, item["position"],
                        )
                        try:
                            with get_db() as db:
                                finish_batch_item(
                                    db,
                                    item_id,
                                    "Failed",
                                    duration,
                                    error=f"Could not persist {module} result.",
                                )
                        except Exception:
                            app.logger.exception(
                                "Could not mark unified batch item %s failed",
                                item_id,
                            )
                        continue

                    if (
                        module in {"nmap", "firewall"}
                        and status in {"Completed", "Partial"}
                    ):
                        try:
                            asset_key, _ = _asset_identity(validated_target)
                            correlation_counts = correlate_asset_observations(
                                database_path=DATABASE_PATH,
                                asset_key=asset_key,
                            )
                            app.logger.info(
                                "Local CVE correlation for %s: %s",
                                validated_target,
                                correlation_counts,
                            )
                            finding_sync_counts = sync_cve_exposures_to_findings(
                                database_path=DATABASE_PATH,
                            )
                            app.logger.info(
                                "Local CVE finding synchronization for %s: %s",
                                validated_target,
                                finding_sync_counts,
                            )
                        except Exception:
                            app.logger.exception(
                                "Local CVE correlation failed for %s; "
                                "scan result remains persisted.",
                                validated_target,
                            )

                    if status in {"Failed", "Partial"}:
                        overall_error = True

                    if module == "web_security" and status in {"Completed", "Partial"} and result:
                        try:
                            generate_web_security_drafts(result, result_id)
                        except Exception:
                            app.logger.exception(
                                "Could not generate Web Security draft findings for %s",
                                validated_target,
                            )

                    if module == "firewall" and status == "Completed" and result:
                        try:
                            generate_firewall_drafts(result, result_id)
                        except Exception:
                            app.logger.exception(
                                "Could not generate Firewall Detection draft findings for %s",
                                validated_target,
                            )

                    if module == "zap" and status in {"Completed", "Partial"}:
                        try:
                            alerts = (
                                result.get("alerts", [])
                                if isinstance(result, dict)
                                else []
                            )
                            created = import_zap_alerts_to_drafts(alerts)
                            app.logger.info(
                                "ZAP active scan imported %s draft findings for %s",
                                created,
                                validated_target,
                            )
                        except Exception:
                            app.logger.exception(
                                "Could not import saved ZAP alerts for %s",
                                validated_target,
                            )

                    # Mark the target terminal only after result persistence
                    # and module-specific draft/finding synchronization.
                    update_unified_progress_state(
                        run_id, module, raw_target, status
                    )

                with get_db() as db:
                    summary = finish_batch(db, batch_id)
                    if summary["status"] in {"Failed", "Partial"}:
                        overall_error = True

            with get_db() as db:
                final_status = "Partial" if overall_error else "Completed"
                finished_at = now_utc()
                db.execute(
                    """
                    UPDATE unified_scan_runs
                    SET status = ?, finished_at = ?
                    WHERE id = ?
                    """,
                    (final_status, finished_at, run_id),
                )
                update_run_status(db, run_id, final_status, finished_at)

        except Exception:
            app.logger.exception("Unified assessment run %s failed unexpectedly", run_id)
            with get_db() as db:
                finished_at = now_utc()
                db.execute(
                    """
                    UPDATE unified_scan_runs
                    SET status = 'Failed', batch_ids_json = ?, finished_at = ?
                    WHERE id = ?
                    """,
                    (json.dumps(batch_ids), finished_at, run_id),
                )
                update_run_status(db, run_id, "Failed", finished_at)


    except Exception:
        app.logger.exception(
            "Unified assessment run %s failed unexpectedly", run_id
        )
        with get_db() as db:
            finished_at = now_utc()
            db.execute(
                """
                UPDATE unified_scan_runs
                SET status = 'Failed', batch_ids_json = ?, finished_at = ?
                WHERE id = ?
                """,
                (json.dumps(batch_ids), finished_at, run_id),
            )
            update_run_status(db, run_id, "Failed", finished_at)


@app.route("/unified-scan", methods=["GET"])
def unified_scan_page():
    """Display the Unified Scan workspace."""
    return render_template(
        "unified_scan.html",
        nav_items=NAV_ITEMS,
        active_page="unified_scan_page",
    )


@app.route("/unified-scan", methods=["POST"])
def unified_scan():
    if request.form.get("authorized") != "yes":
        flash("Confirm that you are authorized to assess these targets.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    try:
        targets = parse_batch_targets(request.form.get("targets", ""))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(request.referrer or url_for("dashboard"))

    allowed_modules = {"nmap", "web_security", "threat_intel", "firewall", "zap"}
    requested_modules = request.form.getlist("modules")
    modules = list(dict.fromkeys(
        module for module in requested_modules if module in allowed_modules
    ))

    if not modules:
        flash("Select at least one assessment module.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    profile = (request.form.get("nmap_profile") or "standard").strip()
    detect_os = (
        request.form.get("os_detection") == "yes"
        and "nmap" in modules
    )
    if profile not in {"quick", "standard", "full_tcp"}:
        flash("Choose a valid Nmap scan profile.", "error")
        return redirect(request.referrer or url_for("dashboard"))

    try:
        custom_ports = (
            parse_custom_ports(request.form.get("custom_ports", ""))
            if {"nmap", "firewall"}.intersection(modules) else None
        )
        if "firewall" in modules and custom_ports and len(custom_ports) > 16:
            raise NmapError(
                "Firewall Detection supports a maximum of 16 selected TCP ports."
            )
    except NmapError as exc:
        flash(str(exc), "error")
        return redirect(request.referrer or url_for("dashboard"))

    with get_db() as db:
        cursor = db.execute(
            """
            INSERT INTO unified_scan_runs
                (targets_json, modules_json, batch_ids_json, status, created_at)
            VALUES (?, ?, '{}', 'Running', ?)
            """,
            (json.dumps(targets), json.dumps(modules), now_utc()),
        )
        run_id = cursor.lastrowid
        register_run(
            db, run_id, "Running", now_utc()
        )

        for module in modules:
            for target in targets:
                db.execute(
                    """
                    INSERT INTO unified_scan_progress
                        (run_id, module, target, task, percent, updated_at)
                    VALUES (?, ?, ?, 'Queued', NULL, ?)
                    """,
                    (run_id, module, target, now_utc()),
                )

    _start_tracked_worker(
        _run_unified_scan_background,
        args=(run_id, targets, modules, profile, detect_os, custom_ports),
        name=f"unified-scan-{run_id}",
    )

    return redirect(url_for("unified_scan_results", run_id=run_id))


@app.route("/unified-scan/<int:run_id>/progress")
def unified_scan_live_progress(run_id):
    """Return read-only live status for a Unified Scan run."""
    with get_db() as db:
        run = db.execute(
            """
            SELECT id, status, batch_ids_json
            FROM unified_scan_runs
            WHERE id = ?
            """,
            (run_id,),
        ).fetchone()

        if run is None:
            abort(404)

        progress_rows = db.execute(
            """
            SELECT module, target, task, percent, remaining_seconds,
                   estimated_completion, updated_at
            FROM unified_scan_progress
            WHERE run_id = ?
            ORDER BY module, target
            """,
            (run_id,),
        ).fetchall()

        try:
            batch_ids = json.loads(run["batch_ids_json"] or "{}")
        except (TypeError, ValueError):
            batch_ids = {}

        batches = []
        for module, batch_id in batch_ids.items():
            batch = db.execute(
                """
                SELECT id, module, status, total_targets,
                       completed_targets, partial_targets, failed_targets,
                       skipped_targets
                FROM scan_batches
                WHERE id = ? AND module = ?
                """,
                (batch_id, module),
            ).fetchone()

            if batch:
                batches.append(dict(batch))

    return jsonify({
        "run_id": run_id,
        "status": run["status"],
        "progress": [dict(row) for row in progress_rows],
        "batches": batches,
    })


@app.route("/unified-scan/<int:run_id>")
def unified_scan_results(run_id):
    with get_db() as db:
        run = db.execute(
            "SELECT * FROM unified_scan_runs WHERE id = ?",
            (run_id,),
        ).fetchone()

        if run is None:
            abort(404)

        targets = json.loads(run["targets_json"])
        modules = json.loads(run["modules_json"])
        batch_ids = json.loads(run["batch_ids_json"] or "{}")

        batches = []
        batch_items = []

        for module in modules:
            batch_id = batch_ids.get(module)
            if not batch_id:
                continue

            batch = db.execute(
                """
                SELECT * FROM scan_batches
                WHERE id = ? AND module = ?
                """,
                (batch_id, module),
            ).fetchone()

            if batch:
                batches.append(batch)

                rows = db.execute(
                    """
                    SELECT * FROM scan_batch_items
                    WHERE batch_id = ?
                    ORDER BY position, id
                    """,
                    (batch_id,),
                ).fetchall()

                for row in rows:
                    item = dict(row)
                    item["module"] = module
                    batch_items.append(item)

    return render_template(
        "unified_scan_results.html",
        nav_items=NAV_ITEMS,
        active_page="dashboard",
        run=run,
        targets=targets,
        modules=modules,
        batches=batches,
        batch_items=batch_items,
    )


@app.route("/unified-scan/<int:run_id>/export.pdf")
def export_unified_scan_pdf(run_id):
    with get_db() as db:
        run = db.execute(
            "SELECT * FROM unified_scan_runs WHERE id = ?",
            (run_id,),
        ).fetchone()

        if run is None:
            abort(404)

        try:
            targets = json.loads(run["targets_json"] or "[]")
            modules = json.loads(run["modules_json"] or "[]")
            batch_ids = json.loads(run["batch_ids_json"] or "{}")
        except (TypeError, ValueError):
            abort(500)

        batches = []
        items = []

        for module in modules:
            batch_id = batch_ids.get(module)
            if not isinstance(batch_id, int):
                continue

            batch = db.execute(
                """
                SELECT * FROM scan_batches
                WHERE id = ? AND module = ?
                """,
                (batch_id, module),
            ).fetchone()

            if batch is None:
                continue

            batches.append(dict(batch))

            rows = db.execute(
                """
                SELECT * FROM scan_batch_items
                WHERE batch_id = ?
                ORDER BY position, id
                """,
                (batch_id,),
            ).fetchall()

            for row in rows:
                item = dict(row)
                item["module"] = module
                item["technical_result"] = None

                # Load only the saved technical result for supported modules.
                # ZAP is deliberately excluded from this report enrichment.
                record_id = item.get("result_record_id")
                result_type = item.get("result_type")

                if type(record_id) is int:
                    if module == "nmap" and result_type == "nmap":
                        scan = db.execute(
                            """
                            SELECT id, target, status, host_state,
                                   duration_seconds, mac_address, mac_vendor,
                                   os_match, os_accuracy, os_detection_status
                            FROM nmap_scans
                            WHERE id = ?
                            """,
                            (record_id,),
                        ).fetchone()

                        if scan is not None:
                            ports = db.execute(
                                """
                                SELECT port, protocol, state, service,
                                       product, version, reason
                                FROM nmap_ports
                                WHERE scan_id = ?
                                ORDER BY port, protocol
                                """,
                                (record_id,),
                            ).fetchall()
                            item["technical_result"] = {
                                "scan": dict(scan),
                                "ports": [dict(port) for port in ports],
                            }

                    elif module in {
                        "web_security", "threat_intel", "firewall"
                    } and result_type == module:
                        result_tables = {
                            "web_security": "web_security_scans",
                            "threat_intel": "threat_intel_lookups",
                            "firewall": "firewall_scans",
                        }
                        table = result_tables[module]
                        saved = db.execute(
                            f"SELECT result_json FROM {table} WHERE id = ?",
                            (record_id,),
                        ).fetchone()

                        if saved is not None and saved["result_json"]:
                            try:
                                parsed_result = json.loads(
                                    saved["result_json"]
                                )
                            except (TypeError, ValueError):
                                parsed_result = None

                            if isinstance(parsed_result, dict):
                                item["technical_result"] = parsed_result

                items.append(item)

    pdf_bytes = build_unified_scan_pdf(
        run=run,
        targets=targets,
        modules=modules,
        batches=batches,
        items=items,
    )

    response = Response(pdf_bytes, mimetype="application/pdf")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="shadow-map-unified-run-{run_id}.pdf"'
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/")
def dashboard():
    # Read-only dashboard metrics: no records are changed.
    with get_db() as db:
        stats = {
            "requests_total": db.execute(
                "SELECT COUNT(*) FROM scans"
            ).fetchone()[0],
            "nmap_total": db.execute(
                "SELECT COUNT(*) FROM nmap_scans"
            ).fetchone()[0],
            "nmap_completed": db.execute(
                "SELECT COUNT(*) FROM nmap_scans "
                "WHERE lower(status) = 'completed'"
            ).fetchone()[0],
            "firewall_total": db.execute(
                "SELECT COUNT(*) FROM firewall_scans"
            ).fetchone()[0],
            "firewall_completed": db.execute(
                "SELECT COUNT(*) FROM firewall_scans "
                "WHERE lower(status) = 'completed'"
            ).fetchone()[0],
            "findings_total": db.execute(
                "SELECT COUNT(*) FROM draft_findings"
            ).fetchone()[0],
            "findings_approved": db.execute(
                "SELECT COUNT(*) FROM draft_findings "
                "WHERE lower(status) = 'approved'"
            ).fetchone()[0],
            "findings_pending": db.execute(
                "SELECT COUNT(*) FROM draft_findings "
                "WHERE lower(status) NOT IN ('approved', 'dismissed')"
            ).fetchone()[0],
            "risks_total": db.execute(
                "SELECT COUNT(*) FROM risk_assessments"
            ).fetchone()[0],
            "risks_open": db.execute(
                "SELECT COUNT(*) FROM risk_assessments "
                "WHERE lower(status) = 'open'"
            ).fetchone()[0],
            "risks_missing_due_date": db.execute(
                "SELECT COUNT(*) FROM risk_assessments "
                "WHERE due_date IS NULL OR TRIM(due_date) = ''"
            ).fetchone()[0],
            "risks_overdue": db.execute(
                "SELECT COUNT(*) FROM risk_assessments "
                "WHERE due_date IS NOT NULL AND TRIM(due_date) != '' "
                "AND due_date < ? AND lower(status) != 'remediated'",
                (datetime.now().date().isoformat(),),
            ).fetchone()[0],
            "risks_in_progress": db.execute(
                "SELECT COUNT(*) FROM risk_assessments "
                "WHERE lower(status) = 'in progress'"
            ).fetchone()[0],
            "risks_remediated": db.execute(
                "SELECT COUNT(*) FROM risk_assessments "
                "WHERE lower(status) = 'remediated'"
            ).fetchone()[0],
        }

        activity = db.execute("""
            SELECT b.*,
                (SELECT GROUP_CONCAT(target, ', ')
                 FROM (
                    SELECT target FROM scan_batch_items
                    WHERE batch_id = b.id ORDER BY position, id
                 )) AS targets
            FROM scan_batches b
            ORDER BY b.created_at DESC, b.id DESC
            LIMIT 5
        """).fetchall()

    return render_template(
        "index.html",
        nav_items=NAV_ITEMS,
        active_page="dashboard",
        scans=get_recent_scans(10),
        activity=activity,
        stats=stats,
    )


@app.route("/scan", methods=["POST"])
def create_scan():
    target = request.form.get("target", "").strip()
    selected = request.form.getlist("scanners")

    if not target:
        flash("Enter a target before continuing.", "error")
        return redirect(url_for("dashboard"))

    allowed_modules = {"nmap", "web", "threat_intel", "custom_rules"}
    selected = [item for item in selected if item in allowed_modules]

    if not selected:
        flash("Select at least one valid scan module.", "error")
        return redirect(url_for("dashboard"))

    with get_db() as db:
        db.execute(
            """
            INSERT INTO scans (target, scan_type, status, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (target, ", ".join(selected), "Queued", now_utc()),
        )

    flash(
        "Scan request saved. To execute Nmap, open the Nmap page "
        "and submit an authorized target there.",
        "success",
    )
    return redirect(url_for("dashboard"))



@app.route("/scan-requests/<int:request_id>/delete", methods=["POST"])
def delete_scan_request(request_id):
    with get_db() as db:
        saved = db.execute(
            "SELECT id FROM scans WHERE id = ?", (request_id,)
        ).fetchone()

        if saved is None:
            flash("Scan request not found.", "error")
            return redirect(url_for("dashboard"))

        linked = db.execute(
            "SELECT 1 FROM nmap_scans WHERE request_id = ? LIMIT 1",
            (request_id,),
        ).fetchone()

        if linked:
            flash(
                "This request has linked Nmap history and was kept. "
                "Delete the Nmap scan from Scan History if appropriate.",
                "error",
            )
        else:
            db.execute("DELETE FROM scans WHERE id = ?", (request_id,))
            flash(f"Scan request #{request_id} deleted.", "success")

    return redirect(url_for("dashboard"))


@app.route("/scan-requests/clear", methods=["POST"])
def clear_scan_requests():
    with get_db() as db:
        result = db.execute("""
            DELETE FROM scans
            WHERE NOT EXISTS (
                SELECT 1 FROM nmap_scans
                WHERE nmap_scans.request_id = scans.id
            )
        """)
        deleted = result.rowcount

        linked = db.execute("""
            SELECT COUNT(*) FROM scans
            WHERE EXISTS (
                SELECT 1 FROM nmap_scans
                WHERE nmap_scans.request_id = scans.id
            )
        """).fetchone()[0]

    message = f"Cleared {deleted} unlinked scan request(s)."
    if linked:
        message += f" Kept {linked} request(s) linked to Nmap history."
    flash(message, "success")
    return redirect(url_for("dashboard"))

@app.route("/nmap")
def nmap_page():
    with get_db() as db:
        recent = db.execute("""
            SELECT id, target, status, host_state, started_at,
                   finished_at, duration_seconds, error
            FROM nmap_scans
            ORDER BY id DESC
            LIMIT 20
        """).fetchall()

    return render_template(
        "nmap.html",
        nav_items=NAV_ITEMS,
        active_page="nmap_page",
        recent_scans=recent,
        result=None,
        ports=[],
        counts=None,
    )


def _run_nmap_background(target, scan_id, request_id, scan_profile, detect_os=False):
    """Execute one Nmap scan and persist genuine progress and results."""

    def record_progress(event):
        with get_db() as db:
            db.execute(
                """
                INSERT INTO nmap_scan_progress
                    (scan_id, task, percent, remaining_seconds,
                     estimated_completion, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    task = excluded.task,
                    percent = excluded.percent,
                    remaining_seconds = excluded.remaining_seconds,
                    estimated_completion = excluded.estimated_completion,
                    updated_at = excluded.updated_at
                """,
                (
                    scan_id,
                    event.get("task") or "Scanning",
                    float(event.get("percent") or 0),
                    event.get("remaining_seconds"),
                    event.get("estimated_completion"),
                    now_utc(),
                ),
            )

    try:
        scan_result = run_nmap(
            target,
            scan_profile=scan_profile,
            progress_callback=record_progress,
            detect_os=detect_os,
        )

        scan_status = scan_result.get("status", "Completed")
        scan_error = scan_result.get("error")

        with get_db() as db:
            db.executemany(
                """
                INSERT INTO nmap_ports
                    (scan_id, port, protocol, state, service, product,
                     version, extra_info, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    )
                    for port in scan_result["ports"]
                ],
            )

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
                    scan_status,
                    scan_result["host_state"],
                    now_utc(),
                    scan_result["duration_seconds"],
                    scan_result["command_display"],
                    scan_result["xml_output"],
                    scan_error,
                    scan_result.get("mac_address"),
                    scan_result.get("mac_vendor"),
                    scan_result.get("os_match"),
                    (
                        str(scan_result["os_accuracy"])
                        if scan_result.get("os_accuracy") is not None
                        else None
                    ),
                    json.dumps(scan_result.get("os_matches", [])),
                    scan_result.get("os_detection_status"),
                    scan_id,
                ),
            )

            db.execute(
                "UPDATE scans SET status = ? WHERE id = ?",
                (scan_status, request_id),
            )
            update_scan_status(
                db, "Nmap", scan_id, scan_status,
                now_utc(), scan_result["duration_seconds"]
            )

            if scan_status == "Completed":
                db.execute(
                    """
                    INSERT INTO nmap_scan_progress
                        (scan_id, task, percent, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(scan_id) DO UPDATE SET
                        task = excluded.task,
                        percent = excluded.percent,
                        remaining_seconds = NULL,
                        estimated_completion = NULL,
                        updated_at = excluded.updated_at
                    """,
                    (scan_id, "Completed", 100, now_utc()),
                )
            else:
                db.execute(
                    """
                    UPDATE nmap_scan_progress
                    SET task = ?, remaining_seconds = NULL,
                        estimated_completion = NULL, updated_at = ?
                    WHERE scan_id = ?
                    """,
                    (scan_status, now_utc(), scan_id),
                )

    except NmapError as exc:
        with get_db() as db:
            db.execute(
                """
                UPDATE nmap_scans
                SET status = ?, finished_at = ?, error = ?
                WHERE id = ?
                """,
                ("Failed", now_utc(), str(exc), scan_id),
            )
            db.execute(
                "UPDATE scans SET status = ? WHERE id = ?",
                ("Failed", request_id),
            )
            update_scan_status(
                db, "Nmap", scan_id, "Failed", now_utc(), None
            )
            db.execute(
                """
                INSERT INTO nmap_scan_progress
                    (scan_id, task, percent, updated_at)
                VALUES (?, ?, 0, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    task = excluded.task,
                    remaining_seconds = NULL,
                    estimated_completion = NULL,
                    updated_at = excluded.updated_at
                """,
                (scan_id, "Failed", now_utc()),
            )

    except Exception:
        app.logger.exception("Unexpected error in background Nmap scan %s", scan_id)
        with get_db() as db:
            db.execute(
                """
                UPDATE nmap_scans
                SET status = ?, finished_at = ?,
                    error = ?
                WHERE id = ?
                """,
                (
                    "Failed",
                    now_utc(),
                    "Unexpected error while saving scan results. Check the application log.",
                    scan_id,
                ),
            )
            db.execute(
                "UPDATE scans SET status = ? WHERE id = ?",
                ("Failed", request_id),
            )
            update_scan_status(
                db, "Nmap", scan_id, "Failed", now_utc(), None
            )
            db.execute(
                """
                INSERT INTO nmap_scan_progress
                    (scan_id, task, percent, updated_at)
                VALUES (?, ?, 0, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    task = excluded.task,
                    remaining_seconds = NULL,
                    estimated_completion = NULL,
                    updated_at = excluded.updated_at
                """,
                (scan_id, "Failed", now_utc()),
            )


@app.route("/nmap/scan", methods=["POST"])
def start_nmap_scan():
    target = request.form.get("target", "").strip()
    authorization = request.form.get("authorized")

    if authorization != "yes":
        flash(
            "Confirm that you are authorized to scan this target.",
            "error",
        )
        return redirect(url_for("nmap_page"))

    try:
        target = validate_target(target)
    except NmapError as exc:
        flash(str(exc), "error")
        return redirect(url_for("nmap_page"))

    scan_profile = (request.form.get("scan_profile") or "standard").strip()
    if scan_profile not in {"quick", "standard", "full_tcp"}:
        flash("Choose a valid Nmap scan profile.", "error")
        return redirect(url_for("nmap_page"))

    detect_os = request.form.get("os_detection") == "yes"
    started_at = now_utc()

    with get_db() as db:
        cursor = db.execute(
            """
            INSERT INTO scans (target, scan_type, status, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (target, "nmap", "Running", started_at),
        )
        request_id = cursor.lastrowid

        cursor = db.execute(
            """
            INSERT INTO nmap_scans
                (request_id, target, status, started_at)
            VALUES (?, ?, ?, ?)
            """,
            (request_id, target, "Running", started_at),
        )
        scan_id = cursor.lastrowid
        register_scan(
            db,
            "Nmap",
            "nmap_scans",
            scan_id,
            target,
            "Running",
            started_at,
            None,
            None,
        )

        db.execute(
            """
            INSERT INTO nmap_scan_progress
                (scan_id, task, percent, updated_at)
            VALUES (?, ?, 0, ?)
            """,
            (scan_id, "Starting Nmap", started_at),
        )

    _start_tracked_worker(
        _run_nmap_background,
        args=(target, scan_id, request_id, scan_profile, detect_os),
        name=f"shadow-map-nmap-{scan_id}",
    )

    return redirect(url_for("nmap_results", scan_id=scan_id))


@app.route("/nmap/batch", methods=["POST"])
def start_nmap_batch():
    if request.form.get("authorized") != "yes":
        flash("Confirm that you are authorized to scan these targets.", "error")
        return redirect(url_for("nmap_page"))

    try:
        targets = parse_batch_targets(request.form.get("targets", ""))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("nmap_page"))

    profile = (request.form.get("scan_profile") or "standard").strip()
    if profile not in {"quick", "standard", "full_tcp"}:
        flash("Choose a valid Nmap scan profile.", "error")
        return redirect(url_for("nmap_page"))

    with get_db() as db:
        batch_id = create_batch(db, "nmap", profile, targets)
        items = db.execute(
            """
            SELECT id, position, target
            FROM scan_batch_items
            WHERE batch_id = ?
            ORDER BY position
            """,
            (batch_id,),
        ).fetchall()

    for item in items:
        item_id = item["id"]
        target = item["target"]
        started_at = now_utc()
        item_started = time.monotonic()

        with get_db() as db:
            start_batch_item(db, item_id)

        # Phase 1: validate this target exactly once.
        try:
            validated_target = validate_target(target)
        except Exception as exc:
            error = str(exc) or exc.__class__.__name__
            duration = time.monotonic() - item_started

            with get_db() as db:
                finish_batch_item(
                    db, item_id, "Failed", duration, error=error
                )

            app.logger.warning(
                "Nmap batch item %s validation failed for %s: %s",
                item["position"], target, error,
            )
            continue

        # Phase 2: execute the scanner independently of persistence.
        scan_started = time.monotonic()
        try:
            scan_result = run_nmap(
                validated_target,
                scan_profile=profile,
            )
            duration = float(
                scan_result.get("duration_seconds")
                or (time.monotonic() - scan_started)
            )

            status = scan_result.get("status", "Completed")
            if status not in {"Completed", "Partial"}:
                status = "Failed"

            error = scan_result.get("error")

        except Exception as exc:
            error = str(exc) or exc.__class__.__name__
            duration = time.monotonic() - scan_started
            scan_result = None
            status = "Failed"

        # Phase 3: persist once. A persistence failure is never retried
        # by creating another scan-history record.
        try:
            with get_db() as db:
                result_type, scan_id, request_id = save_nmap_result(
                    db,
                    validated_target,
                    profile,
                    status,
                    started_at,
                    duration,
                    result=scan_result,
                    error=error,
                )
                finish_batch_item(
                    db,
                    item_id,
                    status,
                    duration,
                    result_type,
                    scan_id,
                    request_id,
                    error,
                )

        except Exception as exc:
            persistence_error = (
                f"Could not persist Nmap result: "
                f"{str(exc) or exc.__class__.__name__}"
            )
            app.logger.exception(
                "Nmap batch item %s persistence failed for %s",
                item["position"], target,
            )

            # Make one separate attempt to mark the batch item failed.
            # Do not retry save_nmap_result().
            try:
                with get_db() as db:
                    finish_batch_item(
                        db,
                        item_id,
                        "Failed",
                        duration,
                        error=persistence_error,
                    )
            except Exception:
                app.logger.exception(
                    "Could not update failed batch item %s",
                    item_id,
                )

            continue

        if status == "Failed":
            app.logger.warning(
                "Nmap batch item %s scanner failed for %s: %s",
                item["position"], target, error,
            )

    with get_db() as db:
        summary = finish_batch(db, batch_id)

    flash(
        (
            f"Nmap batch {batch_id}: {summary['completed_targets']} completed, "
            f"{summary['partial_targets']} partial, "
            f"{summary['failed_targets']} failed."
        ),
        "success" if summary["status"] == "Completed" else "warning",
    )
    return redirect(url_for("nmap_batch_results", batch_id=batch_id))


@app.route("/nmap/batches/<int:batch_id>")
def nmap_batch_results(batch_id):
    with get_db() as db:
        batch = db.execute(
            "SELECT * FROM scan_batches WHERE id = ? AND module = 'nmap'",
            (batch_id,),
        ).fetchone()

        if batch is None:
            abort(404)

        items = db.execute(
            """
            SELECT i.*,
                   n.status AS scan_status,
                   n.host_state,
                   n.duration_seconds AS scan_duration
            FROM scan_batch_items AS i
            LEFT JOIN nmap_scans AS n
              ON i.result_type = 'nmap'
             AND i.result_record_id = n.id
            WHERE i.batch_id = ?
            ORDER BY i.position
            """,
            (batch_id,),
        ).fetchall()

    return render_template(
        "batch_results.html",
        nav_items=NAV_ITEMS,
        active_page="nmap_page",
        batch=batch,
        items=items,
    )

@app.route("/nmap/progress/<int:scan_id>")
def nmap_scan_progress(scan_id):
    with get_db() as db:
        scan = db.execute(
            "SELECT status FROM nmap_scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

        if scan is None:
            abort(404)

        progress = db.execute(
            """
            SELECT task, percent, remaining_seconds,
                   estimated_completion, updated_at
            FROM nmap_scan_progress
            WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchone()

    return jsonify({
        "status": scan["status"],
        "task": progress["task"] if progress else "Waiting for Nmap progress",
        "percent": progress["percent"] if progress else None,
        "remaining_seconds": (
            progress["remaining_seconds"] if progress else None
        ),
        "estimated_completion": (
            progress["estimated_completion"] if progress else None
        ),
        "updated_at": progress["updated_at"] if progress else None,
    })


@app.route("/nmap/results/<int:scan_id>")
def nmap_results(scan_id):
    with get_db() as db:
        result = db.execute(
            "SELECT * FROM nmap_scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

        if result is None:
            abort(404)

        ports = db.execute(
            """
            SELECT * FROM nmap_ports
            WHERE scan_id = ?
            ORDER BY port, protocol
            """,
            (scan_id,),
        ).fetchall()

        recent = db.execute("""
            SELECT id, target, status, host_state, started_at,
                   finished_at, duration_seconds, error
            FROM nmap_scans
            ORDER BY id DESC
            LIMIT 20
        """).fetchall()

    # Generate draft observations only after the scan has finished.
    if result["status"] in ("Completed", "Partial"):
        generate_nmap_drafts(scan_id)

    counts = {
        "open": sum(port["state"] == "open" for port in ports),
        "closed": sum(port["state"] == "closed" for port in ports),
        "filtered": sum(port["state"] == "filtered" for port in ports),
        "other": sum(
            port["state"] not in {"open", "closed", "filtered"}
            for port in ports
        ),
    }

    return render_template(
        "nmap.html",
        nav_items=NAV_ITEMS,
        active_page="nmap_page",
        recent_scans=recent,
        result=result,
        ports=ports,
        counts=counts,
    )


@app.route("/nmap/results/<int:scan_id>/export.pdf")
def export_nmap_pdf(scan_id):
    with get_db() as db:
        scan = db.execute(
            "SELECT * FROM nmap_scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

        if scan is None:
            abort(404)

        ports = db.execute("""
            SELECT port, protocol, state, service, product,
                   version, extra_info, reason
            FROM nmap_ports
            WHERE scan_id = ?
            ORDER BY port, protocol
        """, (scan_id,)).fetchall()

        findings = db.execute("""
            SELECT title, suggested_severity, status, description,
                   evidence, recommendation, iso_controls
            FROM draft_findings
            WHERE source = 'nmap'
              AND CAST(source_record_id AS INTEGER) = ?
            ORDER BY id
        """, (scan_id,)).fetchall()

    counts = {
        "open": sum(row["state"] == "open" for row in ports),
        "closed": sum(row["state"] == "closed" for row in ports),
        "filtered": sum(row["state"] == "filtered" for row in ports),
        "other": sum(
            row["state"] not in {"open", "closed", "filtered"}
            for row in ports
        ),
    }

    pdf_bytes = build_nmap_pdf(
        scan=scan,
        ports=ports,
        findings=findings,
        counts=counts,
    )

    response = Response(pdf_bytes, mimetype="application/pdf")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="shadow-map-nmap-{scan_id}.pdf"'
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/hexbrain-api", methods=["GET", "POST"])
def hexbrain_api_page():
    from scanner.zap_proxy import get_hexbrain_api_key, save_hexbrain_api_key
    from grc.vulnerability_feeds import sync_hexbrain
    from grc.vulnerability_intelligence import connect_vulnerability_db

    error = None
    key_configured = bool(get_hexbrain_api_key())

    # Fetch sync status from the database
    sync_status = {"status": "not_started", "last_checked": "Never"}
    try:
        with connect_vulnerability_db() as db:
            row = db.execute(
                "SELECT status, last_attempt_at FROM vulnerability_feed_state WHERE feed_key = 'hexbrain'"
            ).fetchone()
            if row:
                sync_status = {"status": row["status"], "last_checked": row["last_attempt_at"]}
    except Exception:
        pass

    if request.method == "POST":
        action = request.form.get("action")
        submitted_key = (request.form.get("api_key") or "").strip()

        if action == "save":
            if save_hexbrain_api_key(submitted_key):
                flash("HexBrain API key saved securely to the OS keyring.", "success")
                key_configured = bool(submitted_key)
            else:
                flash("Failed to save key to OS keyring. Ensure `keyring` is installed and a backend is available.", "error")

        elif action == "test":
            test_key = submitted_key or get_hexbrain_api_key()
            if not test_key:
                flash("No API key configured to test.", "error")
            else:
                try:
                    # Test with a single known CVE, limit 1 batch
                    sync_hexbrain(api_key=test_key, batch_size=1, max_batches=1)
                    flash("Connection to HexBrain successful. A background sync has been queued.", "success")
                except Exception as exc:
                    flash(f"HexBrain connection failed: {exc}", "error")

    return render_template(
        "hexbrain_api.html",
        nav_items=NAV_ITEMS,
        active_page="hexbrain_api_page",
        key_configured=key_configured,
        sync_status=sync_status,
        error=error,
    )


@app.route("/zap-proxy", methods=["GET", "POST"])
def zap_proxy_page():
    endpoint = load_endpoint() or DEFAULT_ENDPOINT
    alerts = []
    alert_count = 0
    error = None
    connection_status = None

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()

        try:
            if action in ("start", "test"):
                connection_result = ensure_zap_running(endpoint)
                connection_status = "connected"
                flash(
                    "OWASP ZAP is ready. Version "
                    + connection_result["version"]
                    + ". No scan was started.",
                    "success",
                )

            elif action in ("fetch_alerts", "import_alerts"):
                connection_result = ensure_zap_running(endpoint)
                connection_status = "connected"

                zap_result = fetch_alerts(
                    endpoint=endpoint,
                    limit=100,
                )
                alerts = zap_result["alerts"]
                alert_count = zap_result["count"]

                if action == "import_alerts":
                    created = import_zap_alerts_to_drafts(alerts)
                    flash(
                        f"Imported {created} new draft finding(s) from "
                        f"{alert_count} existing ZAP alert(s). "
                        "Duplicates were skipped. No scan was started.",
                        "success",
                    )
                else:
                    flash(
                        f"Retrieved {alert_count} existing ZAP alert(s). "
                        "Nothing was imported and no scan was started.",
                        "success",
                    )

            elif action:
                flash("Unknown ZAP management action.", "error")

        except (ZapProxyError, WebSecurityError) as exc:
            error = str(exc)
            connection_status = "unavailable"
            flash(f"ZAP operation failed: {error}", "error")
        except Exception:
            app.logger.exception("Unexpected error on ZAP proxy page")
            error = "Check the application log for details."
            connection_status = "error"
            flash(
                "The requested ZAP operation failed unexpectedly. "
                "Check the application log for details.",
                "error",
            )

    return render_template(
        "zap_proxy.html",
        nav_items=NAV_ITEMS,
        active_page="zap_proxy_page",
        endpoint=endpoint,
        alerts=alerts,
        alert_count=alert_count,
        error=error,
        connection_status=connection_status,
        zap_status=detect_zap(),
        sync_status=get_sync_status(),
    )


@app.route("/web-security", methods=["GET", "POST"])
def web_security_page():
    if request.method == "POST":
        flash(
            "Standalone Web Security assessments are disabled. "
            "Use Unified Scan for Web Security checks.",
            "info",
        )
        return redirect(url_for("unified_scan_page"))

    return render_template(
        "web_security.html",
        nav_items=NAV_ITEMS,
        active_page="web_security_page",
    )


@app.route("/web-security/batch", methods=["POST"])
def start_web_security_batch():
    flash(
        "Standalone Web Security batch assessments are disabled. "
        "Use Unified Scan for Web Security checks.",
        "info",
    )
    return redirect(url_for("unified_scan_page"))


@app.route("/zap/batches/<int:batch_id>")
def zap_batch_results(batch_id):
    with get_db() as db:
        batch = db.execute(
            """
            SELECT * FROM scan_batches
            WHERE id = ? AND module = 'zap'
            """,
            (batch_id,),
        ).fetchone()

        if batch is None:
            abort(404)

        items = db.execute(
            """
            SELECT i.*,
                   z.status AS result_status,
                   z.duration_seconds AS result_duration,
                   z.error AS result_error
            FROM scan_batch_items AS i
            LEFT JOIN zap_scans AS z
              ON i.result_type = 'zap'
             AND i.result_record_id = z.id
            WHERE i.batch_id = ?
            ORDER BY i.position
            """,
            (batch_id,),
        ).fetchall()

    return render_template(
        "zap_batch_results.html",
        nav_items=NAV_ITEMS,
        active_page="unified_scan_page",
        batch=batch,
        items=items,
    )


@app.route("/web-security/batches/<int:batch_id>")
def web_security_batch_results(batch_id):
    with get_db() as db:
        batch = db.execute(
            """
            SELECT * FROM scan_batches
            WHERE id = ? AND module = 'web_security'
            """,
            (batch_id,),
        ).fetchone()

        if batch is None:
            abort(404)

        items = db.execute(
            """
            SELECT i.*, w.status AS result_status,
                   w.error AS result_error
            FROM scan_batch_items AS i
            LEFT JOIN web_security_scans AS w
              ON i.result_type = 'web_security'
             AND i.result_record_id = w.id
            WHERE i.batch_id = ?
            ORDER BY i.position
            """,
            (batch_id,),
        ).fetchall()

    return render_template(
        "web_security_batch_results.html",
        nav_items=NAV_ITEMS,
        active_page="web_security_page",
        batch=batch,
        items=items,
    )


@app.route("/firewall/batches/<int:batch_id>")
def firewall_batch_results(batch_id):
    with get_db() as db:
        batch = db.execute(
            """
            SELECT * FROM scan_batches
            WHERE id = ? AND module = 'firewall'
            """,
            (batch_id,),
        ).fetchone()

        if batch is None:
            abort(404)

        items = db.execute(
            """
            SELECT i.*, f.status AS result_status,
                   f.error AS result_error
            FROM scan_batch_items AS i
            LEFT JOIN firewall_scans AS f
              ON i.result_type = 'firewall'
             AND i.result_record_id = f.id
            WHERE i.batch_id = ?
            ORDER BY i.position
            """,
            (batch_id,),
        ).fetchall()

    return render_template(
        "firewall_batch_results.html",
        nav_items=NAV_ITEMS,
        active_page="firewall_page",
        batch=batch,
        items=items,
    )


@app.route("/web-security/results/<int:scan_id>")
def web_security_result(scan_id):
    with get_db() as db:
        record = db.execute(
            "SELECT * FROM web_security_scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

    if record is None:
        abort(404)

    result = json.loads(record["result_json"]) if record["result_json"] else None

    return render_template(
        "web_security_result.html",
        nav_items=NAV_ITEMS,
        active_page="web_security_page",
        record=record,
        result=result,
    )




@app.route("/zap/results/<int:scan_id>")
def zap_scan_result(scan_id):
    with get_db() as db:
        record = db.execute(
            "SELECT * FROM zap_scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

    if record is None:
        abort(404)

    try:
        result = json.loads(record["result_json"]) if record["result_json"] else {}
    except (TypeError, ValueError):
        result = {}

    if not isinstance(result, dict):
        result = {}

    alerts = result.get("alerts", [])
    if not isinstance(alerts, list):
        alerts = []

    return render_template(
        "zap_scan_result.html",
        nav_items=NAV_ITEMS,
        active_page="unified_scan_page",
        record=record,
        result=result,
        alerts=alerts,
    )


@app.route("/zap/results/<int:scan_id>/export.pdf")
def zap_scan_export_pdf(scan_id):
    with get_db() as db:
        record = db.execute(
            "SELECT * FROM zap_scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

    if record is None:
        abort(404)

    try:
        result = json.loads(record["result_json"]) if record["result_json"] else {}
    except (TypeError, ValueError):
        result = {}

    if not isinstance(result, dict):
        result = {}

    pdf_bytes = build_zap_pdf(scan=record, result=result)
    response = Response(pdf_bytes, mimetype="application/pdf")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="shadow-map-zap-scan-{scan_id}.pdf"'
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/zap/results/<int:scan_id>/export.csv")
def zap_scan_export_csv(scan_id):
    with get_db() as db:
        record = db.execute(
            "SELECT * FROM zap_scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

    if record is None:
        abort(404)

    try:
        result = json.loads(record["result_json"]) if record["result_json"] else {}
    except (TypeError, ValueError):
        result = {}

    if not isinstance(result, dict):
        result = {}

    alerts = result.get("alerts", [])
    if not isinstance(alerts, list):
        alerts = []

    columns = [
        "scan_id", "target", "scan_status", "started_at", "finished_at",
        "duration_seconds", "alert_name", "risk", "confidence", "url",
        "method", "parameter", "attack", "evidence", "description",
        "solution", "reference", "plugin_id", "cwe_id", "wasc_id",
        "source_id",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()

    if not alerts:
        alerts = [{}]

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        writer.writerow({
            "scan_id": record["id"],
            "target": record["target"],
            "scan_status": record["status"],
            "started_at": record["started_at"],
            "finished_at": record["finished_at"],
            "duration_seconds": record["duration_seconds"],
            "alert_name": alert.get("name") or alert.get("alert", ""),
            "risk": alert.get("risk", ""),
            "confidence": alert.get("confidence", ""),
            "url": alert.get("url", ""),
            "method": alert.get("method", ""),
            "parameter": alert.get("param", ""),
            "attack": alert.get("attack", ""),
            "evidence": alert.get("evidence", ""),
            "description": alert.get("description", ""),
            "solution": alert.get("solution", ""),
            "reference": alert.get("reference", ""),
            "plugin_id": alert.get("pluginId", ""),
            "cwe_id": alert.get("cweid", ""),
            "wasc_id": alert.get("wascid", ""),
            "source_id": alert.get("sourceid", ""),
        })

    response = Response(
        output.getvalue(),
        mimetype="text/csv",
    )
    response.headers["Content-Disposition"] = (
        f'attachment; filename="shadow-map-zap-scan-{scan_id}.csv"'
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/firewall/results/<int:scan_id>")
def firewall_result(scan_id):
    with get_db() as db:
        record = db.execute(
            "SELECT * FROM firewall_scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

    if record is None:
        abort(404)

    result = json.loads(record["result_json"]) if record["result_json"] else None

    return render_template(
        "firewall_result.html",
        nav_items=NAV_ITEMS,
        active_page="firewall_page",
        record=record,
        result=result,
    )


@app.route("/firewall/results/<int:scan_id>/export.pdf")
def export_firewall_pdf(scan_id):
    with get_db() as db:
        scan = db.execute(
            "SELECT * FROM firewall_scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

    if scan is None:
        abort(404)

    result = json.loads(scan["result_json"]) if scan["result_json"] else {}
    pdf_bytes = build_firewall_pdf(scan=scan, result=result)

    response = Response(pdf_bytes, mimetype="application/pdf")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="shadow-map-firewall-{scan_id}.pdf"'
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/web-security/results/<int:scan_id>/export.pdf")
def export_web_security_pdf(scan_id):
    with get_db() as db:
        scan = db.execute(
            "SELECT * FROM web_security_scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

    if scan is None:
        abort(404)

    result = json.loads(scan["result_json"]) if scan["result_json"] else {}
    pdf_bytes = build_web_security_pdf(scan=scan, result=result)

    response = Response(pdf_bytes, mimetype="application/pdf")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="shadow-map-web-security-{scan_id}.pdf"'
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response



@app.route("/web-security/results/<int:scan_id>/export.csv")
def export_web_security_csv(scan_id):
    with get_db() as db:
        scan = db.execute(
            "SELECT * FROM web_security_scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

    if scan is None:
        abort(404)

    try:
        result = json.loads(scan["result_json"]) if scan["result_json"] else {}
    except (TypeError, ValueError):
        result = {}
    if not isinstance(result, dict):
        result = {}

    classifications = result.get("classifications") or {}
    vulnerabilities = result.get("vulnerabilities") or {}
    if not isinstance(classifications, dict):
        classifications = {}
    if not isinstance(vulnerabilities, dict):
        vulnerabilities = {}

    def csv_value(value, limit=12000):
        if isinstance(value, (list, tuple)):
            value = "; ".join(str(item) for item in value)
        elif value is None:
            value = ""
        elif not isinstance(value, (str, int, float, bool)):
            value = ""
        value = str(value).replace("\x00", "")
        value = " ".join(value.split())[:limit]
        if value.lstrip().startswith(("=", "+", "-", "@")):
            value = "'" + value
        return value

    severity_map = {
        4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info",
    }
    output = io.StringIO(newline="")
    fieldnames = [
        "scan_id", "scan_status", "target", "finding_category", "severity",
        "module", "method", "path", "parameter", "information",
        "description", "remediation", "owasp_wstg", "references",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for category, findings in vulnerabilities.items():
        if not isinstance(findings, list):
            continue
        classification = classifications.get(category, {})
        if not isinstance(classification, dict):
            classification = {}

        for finding in findings[:500]:
            if not isinstance(finding, dict):
                continue
            writer.writerow({
                "scan_id": scan_id,
                "scan_status": csv_value(scan["status"]),
                "target": csv_value(scan["target"], 2048),
                "finding_category": csv_value(category, 300),
                "severity": severity_map.get(finding.get("level"), "Unknown"),
                "module": csv_value(finding.get("module"), 200),
                "method": csv_value(finding.get("method"), 30),
                "path": csv_value(finding.get("path"), 2048),
                "parameter": csv_value(finding.get("parameter"), 500),
                "information": csv_value(finding.get("info"), 6000),
                "description": csv_value(classification.get("desc"), 6000),
                "remediation": csv_value(classification.get("sol"), 6000),
                "owasp_wstg": csv_value(finding.get("wstg")),
                "references": csv_value(classification.get("ref")),
            })

    response = Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv; charset=utf-8",
    )
    response.headers["Content-Disposition"] = (
        f'attachment; filename="shadow-map-web-security-{scan_id}.csv"'
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/threat-intelligence/batch", methods=["POST"])
def start_threat_intel_batch():
    if request.form.get("authorized") != "yes":
        flash("Confirm you are authorized to investigate these IP addresses.", "error")
        return redirect(url_for("threat_intel_page"))

    try:
        targets = parse_batch_targets(request.form.get("targets", ""))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("threat_intel_page"))

    with get_db() as db:
        batch_id = create_batch(db, "threat_intel", "shodan_internetdb", targets)
        items = db.execute(
            """
            SELECT id, position, target
            FROM scan_batch_items
            WHERE batch_id = ?
            ORDER BY position
            """,
            (batch_id,),
        ).fetchall()

    for item in items:
        item_id = item["id"]
        raw_target = item["target"]
        started_at = now_utc()
        item_started = time.monotonic()

        with get_db() as db:
            start_batch_item(db, item_id)

        # Validate before sending anything to the external lookup service.
        try:
            validated_target = validate_public_ipv4(raw_target)
        except ThreatIntelError as exc:
            duration = time.monotonic() - item_started
            with get_db() as db:
                finish_batch_item(
                    db, item_id, "Failed", duration, error=str(exc)
                )
            continue

        # Each public IPv4 lookup is independent.
        try:
            result = lookup_ip(validated_target)
            status = "Completed"
            error = None
        except ThreatIntelError as exc:
            result = None
            status = "Failed"
            error = str(exc)
        except Exception:
            app.logger.exception(
                "Threat Intelligence batch item %s failed unexpectedly",
                item["position"],
            )
            result = None
            status = "Failed"
            error = "The Threat Intelligence lookup failed unexpectedly."

        duration = time.monotonic() - item_started

        # Persist exactly once; do not retry an insert after a database error.
        try:
            with get_db() as db:
                result_type, result_id = save_module_result(
                    db,
                    "threat_intel",
                    validated_target,
                    status,
                    started_at,
                    duration,
                    result=result,
                    error=error,
                )
                finish_batch_item(
                    db,
                    item_id,
                    status,
                    duration,
                    result_type,
                    result_id,
                    error=error,
                )
        except Exception:
            app.logger.exception(
                "Threat Intelligence batch item %s could not be persisted",
                item["position"],
            )
            try:
                with get_db() as db:
                    finish_batch_item(
                        db,
                        item_id,
                        "Failed",
                        duration,
                        error="Could not persist Threat Intelligence result.",
                    )
            except Exception:
                app.logger.exception(
                    "Could not update failed Threat Intelligence batch item %s",
                    item_id,
                )

    with get_db() as db:
        summary = finish_batch(db, batch_id)

    flash(
        (
            f"Threat Intelligence batch {batch_id}: "
            f"{summary['completed_targets']} completed, "
            f"{summary['partial_targets']} partial, "
            f"{summary['failed_targets']} failed."
        ),
        "success" if summary["status"] == "Completed" else "warning",
    )
    return redirect(
        url_for("threat_intel_batch_results", batch_id=batch_id)
    )


@app.route("/threat-intelligence/batches/<int:batch_id>")
def threat_intel_batch_results(batch_id):
    with get_db() as db:
        batch = db.execute(
            """
            SELECT * FROM scan_batches
            WHERE id = ? AND module = 'threat_intel'
            """,
            (batch_id,),
        ).fetchone()

        if batch is None:
            abort(404)

        items = db.execute(
            """
            SELECT i.*
            FROM scan_batch_items AS i
            WHERE i.batch_id = ?
            ORDER BY i.position
            """,
            (batch_id,),
        ).fetchall()

    return render_template(
        "threat_intelligence_batch_results.html",
        nav_items=NAV_ITEMS,
        active_page="threat_intel_page",
        batch=batch,
        items=items,
    )


@app.route("/threat-intelligence/results/<int:lookup_id>")
def threat_intel_result(lookup_id):
    with get_db() as db:
        record = db.execute(
            "SELECT * FROM threat_intel_lookups WHERE id = ?",
            (lookup_id,),
        ).fetchone()

    if record is None:
        abort(404)

    result = json.loads(record["result_json"]) if record["result_json"] else None

    return render_template(
        "threat_intelligence_result.html",
        nav_items=NAV_ITEMS,
        active_page="threat_intel_page",
        record=record,
        result=result,
    )




@app.route("/threat-intelligence/results/<int:lookup_id>/export.pdf")
def export_threat_intel_pdf(lookup_id):
    with get_db() as db:
        scan = db.execute(
            "SELECT * FROM threat_intel_lookups WHERE id = ?",
            (lookup_id,),
        ).fetchone()

    if scan is None:
        abort(404)

    result = json.loads(scan["result_json"]) if scan["result_json"] else {}
    pdf_bytes = build_threat_intel_pdf(scan=scan, result=result)

    response = Response(pdf_bytes, mimetype="application/pdf")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="shadow-map-threat-intel-{lookup_id}.pdf"'
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/threat-intelligence", methods=["GET", "POST"])
def threat_intel_page():
    target = ""
    result = None
    error = None

    if request.method == "POST":
        target = request.form.get("target", "").strip()

        if request.form.get("authorized") != "yes":
            error = "Confirm you are authorized to look up this IP address."
        else:
            try:
                result = lookup_ip(target)
            except ThreatIntelError as exc:
                error = str(exc)

    return render_template(
        "threat_intelligence.html",
        nav_items=NAV_ITEMS,
        active_page="threat_intel_page",
        target=target,
        result=result,
        error=error,
    )



def initialize_custom_rules():
    """Create the custom-rules table without changing existing records."""
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS custom_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                keyword TEXT NOT NULL,
                match_field TEXT NOT NULL
                    CHECK(match_field IN ('title', 'description', 'evidence')),
                severity TEXT NOT NULL
                    CHECK(severity IN ('Review', 'Low', 'Medium', 'High', 'Critical')),
                guidance TEXT NOT NULL DEFAULT '',
                iso_control TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)


@app.route("/custom-rules", methods=["GET", "POST"])
def custom_rules_page():
    initialize_custom_rules()

    if request.method == "POST":
        action = request.form.get("action", "").strip()

        if action == "create":
            name = request.form.get("name", "").strip()
            keyword = request.form.get("keyword", "").strip()
            match_field = request.form.get("match_field", "title").strip()
            severity = request.form.get("severity", "Review").strip()
            guidance = request.form.get("guidance", "").strip()
            iso_control = request.form.get("iso_control", "").strip().upper()

            if not name or len(name) > 120:
                flash("Rule name is required and must be 120 characters or fewer.", "error")
            elif not keyword or len(keyword) > 200:
                flash("Keyword is required and must be 200 characters or fewer.", "error")
            elif match_field not in {"title", "description", "evidence"}:
                flash("Choose a valid finding field.", "error")
            elif severity not in {"Review", "Low", "Medium", "High", "Critical"}:
                flash("Choose a valid severity.", "error")
            elif len(guidance) > 2000:
                flash("Remediation guidance must be 2,000 characters or fewer.", "error")
            elif iso_control and not re.fullmatch(r"A\.\d+\.\d+", iso_control):
                flash("ISO control must use a format such as A.8.20.", "error")
            else:
                with get_db() as db:
                    duplicate = db.execute(
                        "SELECT 1 FROM custom_rules "
                        "WHERE name = ? COLLATE NOCASE LIMIT 1",
                        (name,),
                    ).fetchone()

                    if duplicate:
                        flash("A rule with that name already exists.", "error")
                    else:
                        now = now_utc()
                        db.execute("""
                            INSERT INTO custom_rules (
                                name, keyword, match_field, severity, guidance,
                                iso_control, enabled, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                        """, (
                            name, keyword, match_field, severity, guidance,
                            iso_control, now, now,
                        ))
                        flash(
                            "Custom rule created. Existing findings were not changed.",
                            "success",
                        )

            return redirect(url_for("custom_rules_page"))

        if action == "toggle":
            try:
                rule_id = int(request.form.get("rule_id", ""))
            except (TypeError, ValueError):
                flash("Invalid rule ID.", "error")
                return redirect(url_for("custom_rules_page"))

            with get_db() as db:
                rule = db.execute(
                    "SELECT id, enabled FROM custom_rules WHERE id = ?",
                    (rule_id,),
                ).fetchone()

                if rule is None:
                    flash("Custom rule not found.", "error")
                else:
                    db.execute("""
                        UPDATE custom_rules
                        SET enabled = ?, updated_at = ?
                        WHERE id = ?
                    """, (0 if rule["enabled"] else 1, now_utc(), rule_id))
                    flash("Custom rule status updated.", "success")

            return redirect(url_for("custom_rules_page"))

        flash("Unknown custom-rule action.", "error")
        return redirect(url_for("custom_rules_page"))

    with get_db() as db:
        rules = db.execute("""
            SELECT * FROM custom_rules
            ORDER BY id DESC
        """).fetchall()

        findings = db.execute("""
            SELECT id, source, target, title, description, evidence,
                   status, risk_id, created_at
            FROM draft_findings
            ORDER BY id DESC
            LIMIT 1000
        """).fetchall()

    matches = []
    enabled_rules = [rule for rule in rules if rule["enabled"]]

    for rule in enabled_rules:
        keyword = rule["keyword"].casefold()
        for finding in findings:
            text_value = finding[rule["match_field"]] or ""
            if keyword in text_value.casefold():
                matches.append({
                    "rule": rule,
                    "finding": finding,
                })

    return render_template(
        "custom_rules.html",
        nav_items=NAV_ITEMS,
        active_page="custom_rules_page",
        rules=rules,
        matches=matches,
        finding_count=len(findings),
    )


@app.route("/combined-findings")
def combined_findings_page():
    allowed_sources = {"all", "nmap", "web_security", "threat_intel", "firewall"}
    allowed_statuses = {"all", "Draft", "Approved", "Dismissed"}

    selected_source = request.args.get("source", "all").strip().lower()
    selected_status = request.args.get("status", "all").strip()
    search_query = request.args.get("q", "").strip()[:200]
    requested_hosts = request.args.getlist("host")[:100]

    scan_filter = (request.args.get("scan_id") or "").strip()
    scan_source = None
    scan_record_id = None
    if scan_filter:
        try:
            scan_source, raw_id = scan_filter.split(":", 1)
            scan_record_id = int(raw_id)
            if scan_source not in {"nmap", "web_security", "threat_intel", "firewall"} or scan_record_id < 1:
                raise ValueError
        except (ValueError, TypeError):
            scan_filter = ""
            scan_source = None
            scan_record_id = None

    if selected_source not in allowed_sources:
        selected_source = "all"

    if selected_status not in allowed_statuses:
        selected_status = "all"

    conditions = []
    parameters = []

    if selected_source != "all":
        conditions.append("source = ?")
        parameters.append(selected_source)

    if selected_status != "all":
        conditions.append("status = ?")
        parameters.append(selected_status)

    if scan_source is not None:
        conditions.append("source = ? AND source_record_id = ?")
        parameters.extend([scan_source, scan_record_id])

    if search_query:
        conditions.append("(target LIKE ? OR title LIKE ?)")
        pattern = "%" + search_query + "%"
        parameters.extend([pattern, pattern])

    with get_db() as db:
        available_scans = db.execute("""
            SELECT 'nmap' AS source, id AS source_record_id, target, status
            FROM nmap_scans
            UNION ALL
            SELECT 'web_security', id, target, status
            FROM web_security_scans
            UNION ALL
            SELECT 'threat_intel', id, target, status
            FROM threat_intel_lookups
            UNION ALL
            SELECT 'firewall', id, target, status
            FROM firewall_scans
            ORDER BY source, source_record_id DESC
        """).fetchall()

        scan_statuses = {
            (row["source"], row["source_record_id"]): row["status"]
            for row in available_scans
        }

        target_rows = db.execute("""
            SELECT target FROM draft_findings
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT target FROM nmap_scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT target FROM scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT target FROM firewall_scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            ORDER BY target COLLATE NOCASE
        """).fetchall()

        # Present one filter choice per website origin while retaining
        # every original stored target for the actual database query.
        target_groups = group_targets(
            row["target"] for row in target_rows
        )
        available_targets = [group["label"] for group in target_groups]
        requested_keys = {
            value.strip().casefold() for value in requested_hosts
        }
        selected_hosts = [
            group["label"] for group in target_groups
            if group["label"].casefold() in requested_keys
        ]
        selected_target_values = [
            value
            for group in target_groups
            if group["label"] in selected_hosts
            for value in group["targets"]
        ]

        if selected_target_values:
            placeholders = ", ".join(
                "?" for _ in selected_target_values
            )
            conditions.append(
                f"LOWER(TRIM(target)) IN ({placeholders})"
            )
            parameters.extend(
                target.casefold() for target in selected_target_values
            )

        where_clause = (
            " WHERE " + " AND ".join(conditions)
            if conditions else ""
        )

        matching_count = db.execute(
            "SELECT COUNT(*) FROM draft_findings" + where_clause,
            parameters,
        ).fetchone()[0]

        per_page = 15
        page_count = max(1, (matching_count + per_page - 1) // per_page)

        try:
            current_page = max(1, int(request.args.get("page", 1)))
        except (ValueError, TypeError):
            current_page = 1

        current_page = min(current_page, page_count)
        offset = (current_page - 1) * per_page

        findings = db.execute(
            "SELECT id, source, source_record_id, target, title, "
            "description, evidence, suggested_severity, confidence, "
            "recommendation, iso_controls, status, risk_id, created_at "
            "FROM draft_findings"
            + where_clause
            + " ORDER BY CASE status "
              "WHEN 'Draft' THEN 0 WHEN 'Approved' THEN 1 "
              "WHEN 'Dismissed' THEN 2 ELSE 3 END, id DESC "
              "LIMIT ? OFFSET ?",
            parameters + [per_page, offset],
        ).fetchall()

        total_count = db.execute(
            "SELECT COUNT(*) FROM draft_findings"
        ).fetchone()[0]

        source_counts = {
            row["source"]: row["total"]
            for row in db.execute(
                "SELECT source, COUNT(*) AS total "
                "FROM draft_findings GROUP BY source"
            ).fetchall()
        }

        status_counts = {
            row["status"]: row["total"]
            for row in db.execute(
                "SELECT status, COUNT(*) AS total "
                "FROM draft_findings GROUP BY status"
            ).fetchall()
        }

    return render_template(
        "combined_findings.html",
        nav_items=NAV_ITEMS,
        active_page="combined_findings_page",
        findings=findings,
        total_count=total_count,
        matching_count=matching_count,
        current_page=current_page,
        page_count=page_count,
        per_page=per_page,
        source_counts=source_counts,
        status_counts=status_counts,
        selected_source=selected_source,
        selected_status=selected_status,
        search_query=search_query,
        available_targets=available_targets,
        selected_hosts=selected_hosts,
        available_scans=available_scans,
        scan_statuses=scan_statuses,
        scan_filter=scan_filter,
    )


@app.route("/reports")
def reports_page():
    today_date = datetime.now().date().isoformat()
    valid_sections = {"findings", "risks"}
    filter_applied = request.args.get("target_filter") == "1"

    scan_filter = (request.args.get("scan_id") or "").strip()
    scan_source = None
    scan_record_id = None
    if scan_filter:
        try:
            scan_source, raw_id = scan_filter.split(":", 1)
            scan_record_id = int(raw_id)
            if scan_source not in {"nmap", "web_security", "threat_intel", "firewall"} or scan_record_id < 1:
                raise ValueError
        except (ValueError, TypeError):
            scan_filter = ""
            scan_source = None
            scan_record_id = None

    with get_db() as db:

        available_scans = db.execute("""
            SELECT 'nmap' AS source, id AS source_record_id, target
            FROM nmap_scans
            UNION ALL
            SELECT 'web_security', id, target
            FROM web_security_scans
            UNION ALL
            SELECT 'threat_intel', id, target
            FROM threat_intel_lookups
            UNION ALL
            SELECT 'firewall', id, target
            FROM firewall_scans
            ORDER BY source, source_record_id DESC
        """).fetchall()
        target_rows = db.execute("""
            SELECT target AS target FROM draft_findings
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT asset AS target FROM risk_assessments
            WHERE asset IS NOT NULL AND TRIM(asset) != ''
            UNION
            SELECT target AS target FROM nmap_scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT target AS target FROM firewall_scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT target AS target FROM scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            ORDER BY target
        """).fetchall()
        target_groups = group_targets(
            row["target"] for row in target_rows
        )
        available_targets = [group["label"] for group in target_groups]

        if not filter_applied or request.args.get("all_targets") == "1":
            selected_targets = list(available_targets)
            all_targets_selected = True
        else:
            requested_targets = {
                value.strip().casefold()
                for value in request.args.getlist("target")
            }
            selected_targets = [
                group["label"] for group in target_groups
                if group["label"].casefold() in requested_targets
            ]
            all_targets_selected = False

        selected_target_values = [
            value
            for group in target_groups
            if group["label"] in selected_targets
            for value in group["targets"]
        ]

        if not filter_applied:
            selected_sections = ["findings", "risks"]
        else:
            selected_sections = [
                section for section in ("findings", "risks")
                if section in request.args.getlist("section")
                and section in valid_sections
            ]

        show_findings = "findings" in selected_sections
        show_risks = "risks" in selected_sections

        if selected_target_values:
            placeholders = ",".join("?" for _ in selected_target_values)
            target_params = [value.strip().casefold() for value in selected_target_values]

            findings = db.execute(f"""
                SELECT
                    f.id, f.source, f.source_record_id, f.target, f.title, f.description,
                    f.evidence, f.suggested_severity, f.confidence,
                    f.recommendation, f.iso_controls, f.status,
                    f.risk_id, f.created_at,
                    r.title AS linked_risk_title,
                    r.residual_score AS linked_residual_score,
                    r.residual_level AS linked_residual_level
                FROM draft_findings f
                LEFT JOIN risk_assessments r ON r.id = f.risk_id
                WHERE LOWER(TRIM(f.target)) IN ({placeholders})
                          AND (? IS NULL OR (f.source = ? AND f.source_record_id = ?))
                ORDER BY
                    CASE f.status
                        WHEN 'Draft' THEN 1
                        WHEN 'Approved' THEN 2
                        ELSE 3
                    END,
                    f.id DESC
            """, target_params + [scan_source, scan_source, scan_record_id]).fetchall()

            # Include risks that match the selected asset OR are linked to
            # findings for a selected target.
            risks = db.execute(f"""
                SELECT DISTINCT
                    r.id, r.title, r.asset, r.category, r.evidence,
                    r.business_impact, r.owner, r.inherent_score,
                    r.inherent_level, r.residual_score, r.residual_level,
                    r.treatment, r.iso_controls, r.status, r.due_date
                FROM risk_assessments r
                WHERE (? IS NULL AND LOWER(TRIM(r.asset)) IN ({placeholders}))
                   OR r.id IN (
                       SELECT f.risk_id
                       FROM draft_findings f
                       WHERE LOWER(TRIM(f.target)) IN ({placeholders})
                          AND (? IS NULL OR (f.source = ? AND f.source_record_id = ?))
                         AND f.risk_id IS NOT NULL
                   )
                ORDER BY
                    CASE r.residual_level
                        WHEN 'Critical' THEN 1
                        WHEN 'High' THEN 2
                        WHEN 'Medium' THEN 3
                        ELSE 4
                    END,
                    r.id DESC
            """, [scan_source] + target_params + target_params + [scan_source, scan_source, scan_record_id]).fetchall()
        else:
            findings = []
            risks = []

        finding_status_counts = {}
        for finding in findings:
            status = finding["status"] or "Unknown"
            finding_status_counts[status] = (
                finding_status_counts.get(status, 0) + 1
            )

        risk_stats = {
            "total": len(risks),
            "open": sum(1 for r in risks if r["status"] == "Open"),
            "high_critical": sum(
                1 for r in risks
                if r["residual_level"] in ("High", "Critical")
                and r["status"] != "Remediated"
            ),
            "remediated": sum(
                1 for r in risks if r["status"] == "Remediated"
            ),
            "missing_due_date": sum(
                1 for r in risks
                if not r["due_date"] or not str(r["due_date"]).strip()
            ),
            "overdue": sum(
                1 for r in risks
                if r["due_date"]
                and str(r["due_date"]).strip()
                and str(r["due_date"]) < today_date
                and r["status"] != "Remediated"
            ),
            "linked_findings": sum(
                1 for f in findings if f["risk_id"] is not None
            ),
        }

    # Prepare report-only GRC review data without changing stored records.
    findings = [dict(row) for row in findings]
    risks = [dict(row) for row in risks]

    iso_review_index = {}
    for review in current_iso_control_reviews():
        item = dict(review)
        key = (item["record_type"], item["record_id"])
        iso_review_index.setdefault(key, []).append(item)

    for finding in findings:
        finding["iso_reviews"] = sorted(
            iso_review_index.get(("finding", finding["id"]), []),
            key=lambda item: item["control_code"],
        )

    for risk in risks:
        risk["iso_reviews"] = sorted(
            iso_review_index.get(("risk", risk["id"]), []),
            key=lambda item: item["control_code"],
        )

        flags = []
        status = (risk.get("status") or "").strip()
        owner = (risk.get("owner") or "").strip()
        treatment = (risk.get("treatment") or "").strip()
        due_date = (risk.get("due_date") or "").strip()
        level = (risk.get("residual_level") or "").strip()

        if not owner:
            flags.append("Owner missing")

        if status == "Accepted" and not treatment:
            flags.append("Acceptance rationale needs recording")
        elif status != "Remediated" and not treatment:
            flags.append("Treatment plan missing")

        if status != "Remediated" and not due_date:
            flags.append("Due date missing")

        overdue = bool(
            status != "Remediated"
            and due_date
            and due_date < today_date
        )
        if overdue:
            flags.append("Overdue action")

        if overdue and level in ("High", "Critical"):
            flags.insert(0, "High-priority overdue risk")

        risk["review_flags"] = flags

    risk_stats["owner_missing"] = sum(
        1 for risk in risks if not (risk.get("owner") or "").strip()
    )
    risk_stats["treatment_missing"] = sum(
        1 for risk in risks
        if risk.get("status") != "Remediated"
        and not (risk.get("treatment") or "").strip()
    )
    risk_stats["high_critical_overdue"] = sum(
        1 for risk in risks
        if "High-priority overdue risk" in risk["review_flags"]
    )
    risk_stats["risks_with_review_flags"] = sum(
        1 for risk in risks if risk["review_flags"]
    )

    return render_template(
        "reports.html",
        nav_items=NAV_ITEMS,
        active_page="reports_page",
        findings=findings,
        risks=risks,
        finding_status_counts=finding_status_counts,
        risk_stats=risk_stats,
        today_date=today_date,
        generated_at=format_datetime(datetime.now(timezone.utc)),
        available_targets=available_targets,
        available_scans=available_scans,
        scan_filter=scan_filter,
        selected_targets=selected_targets,
        all_targets_selected=all_targets_selected,
        selected_sections=selected_sections,
        show_findings=show_findings,
        show_risks=show_risks,
        filter_applied=filter_applied,
    )

@app.route("/reports/export.pdf")
def export_reports_pdf():
    """Export the currently selected GRC report as a branded PDF."""
    valid_sections = {"findings", "risks"}
    filter_applied = request.args.get("target_filter") == "1"

    scan_filter = (request.args.get("scan_id") or "").strip()
    scan_source = None
    scan_record_id = None
    if scan_filter:
        try:
            scan_source, raw_id = scan_filter.split(":", 1)
            scan_record_id = int(raw_id)
            if scan_source not in {"nmap", "web_security", "threat_intel", "firewall"} or scan_record_id < 1:
                raise ValueError
        except (ValueError, TypeError):
            scan_filter = ""
            scan_source = None
            scan_record_id = None
    today_date = datetime.now().date().isoformat()

    with get_db() as db:

        available_scans = db.execute("""
            SELECT 'nmap' AS source, id AS source_record_id, target
            FROM nmap_scans
            UNION ALL
            SELECT 'web_security', id, target
            FROM web_security_scans
            UNION ALL
            SELECT 'threat_intel', id, target
            FROM threat_intel_lookups
            UNION ALL
            SELECT 'firewall', id, target
            FROM firewall_scans
            ORDER BY source, source_record_id DESC
        """).fetchall()
        target_rows = db.execute("""
            SELECT target AS target FROM draft_findings
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT asset AS target FROM risk_assessments
            WHERE asset IS NOT NULL AND TRIM(asset) != ''
            UNION
            SELECT target AS target FROM nmap_scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT target AS target FROM firewall_scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT target AS target FROM scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            ORDER BY target
        """).fetchall()

        target_groups = group_targets(row["target"] for row in target_rows)
        available_targets = [group["label"] for group in target_groups]

        if not filter_applied or request.args.get("all_targets") == "1":
            selected_targets = list(available_targets)
        else:
            requested_targets = {
                value.strip().casefold()
                for value in request.args.getlist("target")
            }
            selected_targets = [
                group["label"] for group in target_groups
                if group["label"].casefold() in requested_targets
            ]

        # Restrict the PDF target scope to the selected scanner run.
        if scan_source is not None:
            scan_tables = {
                "nmap": "nmap_scans",
                "web_security": "web_security_scans",
                "threat_intel": "threat_intel_lookups",
                "firewall": "firewall_scans",
            }
            scan_target_row = db.execute(
                f"SELECT target FROM {scan_tables[scan_source]} WHERE id = ?",
                (scan_record_id,),
            ).fetchone()

            if scan_target_row is None or not scan_target_row["target"]:
                selected_targets = []
            else:
                scan_target = scan_target_row["target"].strip().casefold()
                selected_targets = [
                    group["label"] for group in target_groups
                    if scan_target in {
                        value.strip().casefold() for value in group["targets"]
                    }
                    and group["label"] in selected_targets
                ]

        selected_target_values = [
            value
            for group in target_groups
            if group["label"] in selected_targets
            for value in group["targets"]
        ]

        if not filter_applied:
            selected_sections = ["findings", "risks"]
        else:
            selected_sections = [
                section for section in ("findings", "risks")
                if section in request.args.getlist("section")
                and section in valid_sections
            ]

        findings = []
        risks = []

        if selected_target_values:
            placeholders = ",".join("?" for _ in selected_target_values)
            target_params = [
                value.strip().casefold()
                for value in selected_target_values
            ]

            if "findings" in selected_sections:
                findings = [
                    dict(row) for row in db.execute(f"""
                        SELECT
                            f.id, f.source, f.source_record_id, f.target, f.title,
                            f.description, f.evidence,
                            f.suggested_severity, f.confidence,
                            f.recommendation, f.iso_controls, f.status,
                            f.risk_id, f.created_at,
                            r.title AS linked_risk_title,
                            r.residual_score AS linked_residual_score,
                            r.residual_level AS linked_residual_level
                        FROM draft_findings f
                        LEFT JOIN risk_assessments r ON r.id = f.risk_id
                        WHERE LOWER(TRIM(f.target)) IN ({placeholders})
                          AND (? IS NULL OR (f.source = ? AND f.source_record_id = ?))
                        ORDER BY
                            CASE f.status
                                WHEN 'Draft' THEN 1
                                WHEN 'Approved' THEN 2
                                ELSE 3
                            END,
                            f.id DESC
                    """, target_params + [scan_source, scan_source, scan_record_id]).fetchall()
                ]

            if "risks" in selected_sections:
                risks = [
                    dict(row) for row in db.execute(f"""
                        SELECT DISTINCT
                            r.id, r.title, r.asset, r.category, r.evidence,
                            r.business_impact, r.owner, r.inherent_score,
                            r.inherent_level, r.residual_score,
                            r.residual_level, r.treatment, r.iso_controls,
                            r.status, r.due_date
                        FROM risk_assessments r
                        WHERE (? IS NULL AND LOWER(TRIM(r.asset)) IN ({placeholders}))
                           OR r.id IN (
                               SELECT f.risk_id
                               FROM draft_findings f
                               WHERE LOWER(TRIM(f.target)) IN ({placeholders})
                          AND (? IS NULL OR (f.source = ? AND f.source_record_id = ?))
                                 AND f.risk_id IS NOT NULL
                           )
                        ORDER BY
                            CASE r.residual_level
                                WHEN 'Critical' THEN 1
                                WHEN 'High' THEN 2
                                WHEN 'Medium' THEN 3
                                ELSE 4
                            END,
                            r.id DESC
                    """, [scan_source] + target_params + target_params + [scan_source, scan_source, scan_record_id]).fetchall()
                ]

    review_index = {}
    for review in current_iso_control_reviews():
        item = dict(review)
        key = (item["record_type"], item["record_id"])
        review_index.setdefault(key, []).append(item)

    for finding in findings:
        reviews = sorted(
            review_index.get(("finding", finding["id"]), []),
            key=lambda item: item["control_code"],
        )
        finding["iso_reviews"] = reviews
        finding["iso_review_summary"] = "; ".join(
            f'{item["control_code"]}: {item["review_status"]}'
            for item in reviews
        ) or "No current ISO control reviews"

    for risk in risks:
        reviews = sorted(
            review_index.get(("risk", risk["id"]), []),
            key=lambda item: item["control_code"],
        )
        risk["iso_reviews"] = reviews
        risk["iso_review_summary"] = "; ".join(
            f'{item["control_code"]}: {item["review_status"]}'
            for item in reviews
        ) or "No current ISO control reviews"

        flags = []
        status = (risk.get("status") or "").strip()
        owner = (risk.get("owner") or "").strip()
        treatment = (risk.get("treatment") or "").strip()
        due_date = (risk.get("due_date") or "").strip()
        level = (risk.get("residual_level") or "").strip()

        if not owner:
            flags.append("Owner missing")

        if status == "Accepted" and not treatment:
            flags.append("Acceptance rationale needs recording")
        elif status != "Remediated" and not treatment:
            flags.append("Treatment plan missing")

        if status != "Remediated" and not due_date:
            flags.append("Due date missing")

        overdue = bool(
            status != "Remediated"
            and due_date
            and due_date < today_date
        )
        if overdue:
            flags.append("Overdue action")
        if overdue and level in ("High", "Critical"):
            flags.insert(0, "High-priority overdue risk")

        risk["review_flags"] = flags

    pdf = build_grc_pdf(
        title="GRC Risk & Findings Report",
        subtitle="Shadow Map GRC | Security assessment and control traceability",
        targets=selected_targets,
        findings=findings,
        risks=risks,
        summary={
            "targets": len(selected_targets),
            "findings": len(findings),
            "risks": len(risks),
        },
        scope_note=(
            "Targets: " + (", ".join(selected_targets) or "None selected")
            + " | Sections: "
            + (", ".join(selected_sections) or "None selected")
            + " | Scan ID: "
            + (
                f"{scan_source.replace('_', ' ').upper()} #{scan_record_id}"
                if scan_source is not None else "All scan runs"
            )
        ),
    )

    response = Response(pdf, mimetype="application/pdf")
    response.headers["Content-Disposition"] = (
        'attachment; filename="shadow-map-grc-report.pdf"'
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/reports/export.csv")
def export_reports_csv():
    """Export the currently selected report findings and risks as CSV."""
    valid_sections = {"findings", "risks"}
    filter_applied = request.args.get("target_filter") == "1"

    scan_filter = (request.args.get("scan_id") or "").strip()
    scan_source = None
    scan_record_id = None
    if scan_filter:
        try:
            scan_source, raw_id = scan_filter.split(":", 1)
            scan_record_id = int(raw_id)
            if scan_source not in {"nmap", "web_security", "threat_intel", "firewall"} or scan_record_id < 1:
                raise ValueError
        except (ValueError, TypeError):
            scan_filter = ""
            scan_source = None
            scan_record_id = None

    with get_db() as db:

        available_scans = db.execute("""
            SELECT 'nmap' AS source, id AS source_record_id, target
            FROM nmap_scans
            UNION ALL
            SELECT 'web_security', id, target
            FROM web_security_scans
            UNION ALL
            SELECT 'threat_intel', id, target
            FROM threat_intel_lookups
            UNION ALL
            SELECT 'firewall', id, target
            FROM firewall_scans
            ORDER BY source, source_record_id DESC
        """).fetchall()
        target_rows = db.execute("""
            SELECT target AS target FROM draft_findings
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT asset AS target FROM risk_assessments
            WHERE asset IS NOT NULL AND TRIM(asset) != ''
            UNION
            SELECT target AS target FROM nmap_scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT target AS target FROM firewall_scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT target AS target FROM scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            ORDER BY target
        """).fetchall()
        target_groups = group_targets(
            row["target"] for row in target_rows
        )
        available_targets = [group["label"] for group in target_groups]

        if not filter_applied or request.args.get("all_targets") == "1":
            selected_targets = list(available_targets)
        else:
            requested_targets = {
                value.strip().casefold()
                for value in request.args.getlist("target")
            }
            selected_targets = [
                group["label"] for group in target_groups
                if group["label"].casefold() in requested_targets
            ]

        selected_target_values = [
            value
            for group in target_groups
            if group["label"] in selected_targets
            for value in group["targets"]
        ]

        if not filter_applied:
            selected_sections = ["findings", "risks"]
        else:
            selected_sections = [
                section for section in ("findings", "risks")
                if section in request.args.getlist("section")
                and section in valid_sections
            ]

        findings = []
        risks = []

        if selected_target_values:
            placeholders = ",".join("?" for _ in selected_target_values)
            target_params = [value.strip().casefold() for value in selected_target_values]

            if "findings" in selected_sections:
                findings = db.execute(f"""
                    SELECT
                        f.id, f.source, f.source_record_id, f.target, f.title, f.description,
                        f.evidence, f.suggested_severity, f.confidence,
                        f.recommendation, f.iso_controls, f.status,
                        f.risk_id, f.created_at,
                        r.title AS linked_risk_title,
                        r.residual_score AS linked_residual_score,
                        r.residual_level AS linked_residual_level
                    FROM draft_findings f
                    LEFT JOIN risk_assessments r ON r.id = f.risk_id
                    WHERE LOWER(TRIM(f.target)) IN ({placeholders})
                          AND (? IS NULL OR (f.source = ? AND f.source_record_id = ?))
                    ORDER BY f.id DESC
                """, target_params + [scan_source, scan_source, scan_record_id]).fetchall()

            if "risks" in selected_sections:
                risks = db.execute(f"""
                    SELECT DISTINCT
                        r.id, r.title, r.asset, r.category, r.evidence,
                        r.business_impact, r.owner, r.inherent_score,
                        r.inherent_level, r.residual_score, r.residual_level,
                        r.treatment, r.iso_controls, r.status, r.due_date
                    FROM risk_assessments r
                    WHERE (? IS NULL AND LOWER(TRIM(r.asset)) IN ({placeholders}))
                       OR r.id IN (
                           SELECT f.risk_id
                           FROM draft_findings f
                           WHERE LOWER(TRIM(f.target)) IN ({placeholders})
                          AND (? IS NULL OR (f.source = ? AND f.source_record_id = ?))
                             AND f.risk_id IS NOT NULL
                       )
                    ORDER BY r.id DESC
                """, [scan_source] + target_params + target_params + [scan_source, scan_source, scan_record_id]).fetchall()

    # Include review details only for mappings represented by current source records.
    review_index = {}
    for review in current_iso_control_reviews():
        key = (review["record_type"], review["record_id"])
        review_index.setdefault(key, []).append(review)

    def review_summary(record_type, record_id, field):
        rows = review_index.get((record_type, record_id), [])
        return "\\n".join(
            f"{row['control_code']}: {row[field] or ''}"
            for row in rows
        )

    def review_details(record_type, record_id):
        rows = review_index.get((record_type, record_id), [])
        if not rows:
            return "No current ISO control mappings"

        sections = []
        for row in sorted(rows, key=lambda item: item["control_code"]):
            sections.append(
                f"{row['control_code']}\\n"
                f"Status: {row['review_status'] or 'Suggested'}\\n"
                f"Reviewer: {row['reviewed_by'] or 'Not assigned'}\\n"
                f"Rationale: {row['rationale'] or 'Not provided'}\\n"
                f"Reviewed at: {row['reviewed_at'] or 'Not yet reviewed'}"
            )
        return "\\n\\n".join(sections)

    columns = [
        "Record Type", "Record ID", "Target / Asset", "Source", "Scan ID", "Title",
        "Description", "Evidence", "Severity", "Confidence",
        "Recommendation", "ISO Controls", "Finding Status",
        "Linked Risk ID", "Linked Risk Title",
        "Linked Risk Residual Score", "Linked Risk Residual Level",
        "Category", "Business Impact", "Risk Owner",
        "Inherent Score", "Inherent Level", "Residual Score",
        "Residual Level", "Treatment", "Risk Status", "Due Date",
        "Created At",
        "ISO Review Statuses", "ISO Review Reviewers",
        "ISO Review Rationales", "ISO Review Timestamps",
        "ISO Control Review Details",
        "Risk Review Flags",
    ]

    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output, fieldnames=columns, extrasaction="ignore",
        lineterminator="\r\n"
    )
    writer.writeheader()

    def risk_review_flags(risk):
        """Calculate report-only completeness flags without modifying records."""
        flags = []
        status = (risk["status"] or "").strip()
        owner = (risk["owner"] or "").strip()
        treatment = (risk["treatment"] or "").strip()
        due_date = (risk["due_date"] or "").strip()
        residual_level = (risk["residual_level"] or "").strip()
        today = datetime.now().date().isoformat()

        if not owner:
            flags.append("Owner missing")

        if status == "Accepted" and not treatment:
            flags.append("Acceptance rationale needs recording")
        elif status != "Remediated" and not treatment:
            flags.append("Treatment plan missing")

        if status != "Remediated" and not due_date:
            flags.append("Due date missing")

        overdue = bool(
            status != "Remediated" and due_date and due_date < today
        )
        if overdue:
            flags.append("Overdue action")

        if overdue and residual_level in ("High", "Critical"):
            flags.insert(0, "High-priority overdue risk")

        return flags

    def safe_cell(value):
        if value is None:
            return ""
        if isinstance(value, str) and value.startswith(
            ("=", "+", "-", "@", "\t", "\r")
        ):
            return "'" + value
        return value

    for f in findings:
        writer.writerow({
            "Record Type": "Finding",
            "Record ID": f["id"],
            "Target / Asset": f["target"],
            "Source": f["source"],
            "Scan ID": (
                f'{(f["source"] or "").replace("_", " ").upper()} #{f["source_record_id"]}'
                if f["source"] and f["source_record_id"] is not None
                else "Unlinked"
            ),
            "Title": f["title"],
            "Description": f["description"],
            "Evidence": f["evidence"],
            "Severity": f["suggested_severity"],
            "Confidence": f["confidence"],
            "Recommendation": f["recommendation"],
            "ISO Controls": f["iso_controls"],
            "ISO Review Statuses": review_summary("finding", f["id"], "review_status"),
            "ISO Review Reviewers": review_summary("finding", f["id"], "reviewed_by"),
            "ISO Review Rationales": review_summary("finding", f["id"], "rationale"),
            "ISO Review Timestamps": review_summary("finding", f["id"], "reviewed_at"),
            "ISO Control Review Details": review_details("finding", f["id"]),
            "Finding Status": f["status"],
            "Linked Risk ID": f["risk_id"],
            "Linked Risk Title": f["linked_risk_title"],
            "Linked Risk Residual Score": f["linked_residual_score"],
            "Linked Risk Residual Level": f["linked_residual_level"],
            "Created At": f["created_at"],
        })

    for r in risks:
        writer.writerow({
            "Record Type": "Risk",
            "Record ID": r["id"],
            "Target / Asset": r["asset"],
            "Scan ID": (
                f"{scan_source.replace('_', ' ').upper()} #{scan_record_id}"
                if scan_source is not None else "Not scan-specific"
            ),
            "Title": r["title"],
            "Evidence": r["evidence"],
            "ISO Controls": r["iso_controls"],
            "ISO Review Statuses": review_summary("risk", r["id"], "review_status"),
            "ISO Review Reviewers": review_summary("risk", r["id"], "reviewed_by"),
            "ISO Review Rationales": review_summary("risk", r["id"], "rationale"),
            "ISO Review Timestamps": review_summary("risk", r["id"], "reviewed_at"),
            "ISO Control Review Details": review_details("risk", r["id"]),
            "Category": r["category"],
            "Business Impact": r["business_impact"],
            "Risk Owner": r["owner"],
            "Inherent Score": r["inherent_score"],
            "Inherent Level": r["inherent_level"],
            "Residual Score": r["residual_score"],
            "Residual Level": r["residual_level"],
            "Treatment": r["treatment"],
            "Risk Status": r["status"],
            "Due Date": r["due_date"],
            "Risk Review Flags": "; ".join(risk_review_flags(r)),
        })

    safe_csv = io.StringIO(newline="")
    safe_writer = csv.DictWriter(
        safe_csv, fieldnames=columns, lineterminator="\r\n"
    )
    safe_writer.writeheader()

    # Sanitize exported cells to reduce spreadsheet formula-injection risk.
    output.seek(0)
    reader = csv.DictReader(output)
    for row in reader:
        safe_writer.writerow({
            key: safe_cell(value) for key, value in row.items()
        })

    response = Response(
        "\ufeff" + safe_csv.getvalue(),
        mimetype="text/csv"
    )
    response.headers["Content-Disposition"] = (
        'attachment; filename="shadow-map-grc-report.csv"'
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response



def iso_control_codes(value):
    """Return normalized ISO control codes from a comma/semicolon list."""
    return sorted(set(
        code.upper()
        for code in re.findall(r"\bA\.\d+\.\d+\b", value or "", re.I)
    ))


def initialize_iso_control_reviews():
    """Create review storage and seed current mappings without overwriting reviews."""
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS iso_control_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_type TEXT NOT NULL
                    CHECK (record_type IN ('finding', 'risk')),
                record_id INTEGER NOT NULL,
                control_code TEXT NOT NULL,
                rationale TEXT NOT NULL DEFAULT '',
                review_status TEXT NOT NULL DEFAULT 'Suggested'
                    CHECK (review_status IN
                        ('Suggested', 'Reviewed', 'Approved', 'Rejected')),
                reviewed_by TEXT NOT NULL DEFAULT '',
                reviewed_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                mapping_snapshot TEXT NOT NULL DEFAULT '',
                UNIQUE(record_type, record_id, control_code)
            )
        """)

        sources = (
            ("finding", "draft_findings", "target"),
            ("risk", "risk_assessments", "asset"),
        )
        for record_type, table, asset_column in sources:
            records = db.execute(
                f"SELECT id, title, iso_controls FROM {table}"
            ).fetchall()

            for record in records:
                snapshot = record["iso_controls"] or ""
                for code in iso_control_codes(snapshot):
                    existing = db.execute("""
                        SELECT id, mapping_snapshot
                        FROM iso_control_reviews
                        WHERE record_type = ? AND record_id = ?
                          AND control_code = ?
                    """, (record_type, record["id"], code)).fetchone()

                    if existing is None:
                        timestamp = now_utc()
                        db.execute("""
                            INSERT INTO iso_control_reviews (
                                record_type, record_id, control_code,
                                rationale, review_status, created_at,
                                updated_at, mapping_snapshot
                            ) VALUES (?, ?, ?, ?, 'Suggested', ?, ?, ?)
                        """, (
                            record_type, record["id"], code,
                            "Proposed mapping. Validate against the evidence, "
                            "assessment scope, and applicable Statement of "
                            "Applicability before approval.",
                            timestamp, timestamp, snapshot,
                        ))
                    else:
                        # Compare this control with its previous mapping list.
                        # Changes to other controls must not reset this review.
                        previous_codes = iso_control_codes(
                            existing["mapping_snapshot"]
                        )

                        if code not in previous_codes:
                            # This control was not present in its prior snapshot.
                            db.execute("""
                                UPDATE iso_control_reviews
                                SET rationale = ?, review_status = 'Suggested',
                                    reviewed_by = '', reviewed_at = NULL,
                                    updated_at = ?, mapping_snapshot = ?
                                WHERE id = ?
                            """, (
                                "This ISO control mapping changed. Revalidate "
                                "against the evidence, assessment scope, and "
                                "applicable Statement of Applicability.",
                                now_utc(), snapshot, existing["id"],
                            ))
                        else:
                            # Refresh the snapshot without changing review decisions.
                            db.execute("""
                                UPDATE iso_control_reviews
                                SET mapping_snapshot = ?
                                WHERE id = ?
                            """, (snapshot, existing["id"]))

                # Track removals too, so re-adding a removed control can be
                # detected and its old decision can be sent back for review.
                db.execute("""
                    UPDATE iso_control_reviews
                    SET mapping_snapshot = ?
                    WHERE record_type = ? AND record_id = ?
                """, (snapshot, record_type, record["id"]))


def current_iso_control_reviews(limit=25, offset=0, include_total=False):
    """Return a page of current ISO reviews using source-specific lookups."""
    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    results = []

    with get_db() as db:
        for record_type, table, asset_column in (
            ("finding", "draft_findings", "target"),
            ("risk", "risk_assessments", "asset"),
        ):
            records = db.execute(
                f"SELECT id, title, iso_controls, {asset_column} AS asset "
                f"FROM {table}"
            ).fetchall()

            if not records:
                continue

            source_by_id = {row["id"]: row for row in records}
            ids = list(source_by_id)
            placeholders = ",".join("?" for _ in ids)

            reviews = db.execute(
                f"""
                SELECT *
                FROM iso_control_reviews
                WHERE record_type = ?
                  AND record_id IN ({placeholders})
                """,
                (record_type, *ids),
            ).fetchall()

            for review in reviews:
                source = source_by_id.get(review["record_id"])
                if source is None:
                    continue
                if review["control_code"] not in iso_control_codes(
                    source["iso_controls"]
                ):
                    continue

                item = dict(review)
                item["source_title"] = source["title"]
                item["source_asset"] = source["asset"] or "Not specified"
                results.append(item)

    results.sort(
        key=lambda item: (
            -item["record_id"],
            item["control_code"],
            item["record_type"],
        )
    )

    total = len(results)
    page_rows = results[offset:offset + limit]

    if include_total:
        return page_rows, total
    return page_rows


@app.route("/traceability/control-review", methods=["POST"])
def save_iso_control_review():
    """Save a reviewer decision for a mapping that still exists."""
    record_type = request.form.get("record_type", "").strip().lower()
    control_code = request.form.get("control_code", "").strip().upper()
    status = request.form.get("review_status", "").strip()
    rationale = request.form.get("rationale", "").strip()
    reviewer = request.form.get("reviewed_by", "").strip()

    try:
        record_id = int(request.form.get("record_id", ""))
    except (TypeError, ValueError):
        abort(400, description="Invalid record ID.")

    if record_type not in {"finding", "risk"} or record_id < 1:
        abort(400, description="Invalid mapping record.")
    if not re.fullmatch(r"A\.\d+\.\d+", control_code):
        abort(400, description="Invalid ISO control code.")
    if status not in {"Suggested", "Reviewed", "Approved", "Rejected"}:
        abort(400, description="Invalid review status.")
    if len(rationale) > 2000 or len(reviewer) > 100:
        abort(400, description="Reviewer or rationale text is too long.")
    if not rationale:
        flash("Please provide a review rationale.", "error")
        return redirect(url_for("traceability_page"))
    if status != "Suggested" and not reviewer:
        flash("Enter the reviewer name for a completed review decision.", "error")
        return redirect(url_for("traceability_page"))

    if status == "Approved":
        generic_rationales = (
            "proposed mapping.",
            "source iso mapping changed.",
            "this iso control mapping changed.",
        )
        if len(rationale) < 20 or rationale.casefold().startswith(
            generic_rationales
        ):
            flash(
                "Approval requires a specific rationale of at least 20 "
                "characters, not the default mapping text.",
                "error",
            )
            return redirect(url_for("traceability_page"))

    table = "draft_findings" if record_type == "finding" else "risk_assessments"
    with get_db() as db:
        source = db.execute(
            f"SELECT iso_controls FROM {table} WHERE id = ?",
            (record_id,),
        ).fetchone()

        if source is None or control_code not in iso_control_codes(
            source["iso_controls"]
        ):
            flash("The mapping no longer exists. No review was saved.", "error")
            return redirect(url_for("traceability_page"))

        existing = db.execute("""
            SELECT id FROM iso_control_reviews
            WHERE record_type = ? AND record_id = ? AND control_code = ?
        """, (record_type, record_id, control_code)).fetchone()

        if existing is None:
            flash("Review row is missing. Refresh the Traceability page and try again.", "error")
            return redirect(url_for("traceability_page"))

        timestamp = now_utc()
        reviewed_at = timestamp if status != "Suggested" else None
        db.execute("""
            UPDATE iso_control_reviews
            SET rationale = ?, review_status = ?, reviewed_by = ?,
                reviewed_at = ?, updated_at = ?
            WHERE record_type = ? AND record_id = ? AND control_code = ?
        """, (
            rationale, status, reviewer, reviewed_at, timestamp,
            record_type, record_id, control_code,
        ))

    flash("ISO control mapping review saved.", "success")
    return redirect(url_for("traceability_page"))


@app.route("/traceability")
def traceability_page():
    """Read-only traceability overview with GET filters."""
    target_filter = request.args.get("target", "All")
    status_filter = request.args.get("status", "All")
    mapping_filter = request.args.get("mapping", "All")
    link_filter = request.args.get("link", "All")

    allowed_statuses = {"All", "Draft", "Approved", "Dismissed"}
    allowed_mappings = {"All", "Mapped", "Not mapped"}
    allowed_links = {"All", "Linked", "Unlinked"}

    if status_filter not in allowed_statuses:
        status_filter = "All"
    if mapping_filter not in allowed_mappings:
        mapping_filter = "All"
    if link_filter not in allowed_links:
        link_filter = "All"

    with get_db() as db:
        targets = db.execute("""
            SELECT target AS value FROM draft_findings
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT asset AS value FROM risk_assessments
            WHERE asset IS NOT NULL AND TRIM(asset) != ''
            ORDER BY value
        """).fetchall()
        target_groups = group_targets(row["value"] for row in targets)
        target_options = [group["label"] for group in target_groups]

        if (
            target_filter != "All"
            and target_filter.casefold() not in {
                label.casefold() for label in target_options
            }
        ):
            target_filter = "All"
        elif target_filter != "All":
            target_filter = next(
                label for label in target_options
                if label.casefold() == target_filter.casefold()
            )

        finding_rows = db.execute("""
            SELECT
                f.id AS finding_id, f.title AS finding_title, f.target,
                f.status AS finding_status, f.iso_controls AS finding_controls,
                f.risk_id, r.title AS risk_title, r.status AS risk_status,
                r.iso_controls AS risk_controls, r.asset AS risk_asset
            FROM draft_findings f
            LEFT JOIN risk_assessments r ON r.id = f.risk_id
            ORDER BY f.id DESC
        """).fetchall()

        risk_rows = db.execute("""
            SELECT r.id, r.title, r.asset, r.status, r.owner, r.iso_controls
            FROM risk_assessments r
            ORDER BY r.id DESC
        """).fetchall()

    finding_links = [dict(row) for row in finding_rows]
    all_risks = [dict(row) for row in risk_rows]

    # Target and finding-status filters apply to the finding-to-risk table.
    if target_filter != "All":
        selected_target_key = next(
            group["key"] for group in target_groups
            if group["label"] == target_filter
        )
        finding_links = [
            row for row in finding_links
            if any(
                value.strip().casefold() == (row["target"] or "").strip().casefold()
                for group in target_groups
                if group["key"] == selected_target_key
                for value in group["targets"]
            )
        ]
    if status_filter != "All":
        finding_links = [
            row for row in finding_links
            if row["finding_status"] == status_filter
        ]

    # Mapping filter is based on whether the finding has a recorded mapping.
    if mapping_filter == "Mapped":
        finding_links = [
            row for row in finding_links
            if (row["finding_controls"] or "").strip()
        ]
    elif mapping_filter == "Not mapped":
        finding_links = [
            row for row in finding_links
            if not (row["finding_controls"] or "").strip()
        ]

    if link_filter == "Linked":
        finding_links = [
            row for row in finding_links
            if row["risk_id"] is not None and row["risk_title"] is not None
        ]
    elif link_filter == "Unlinked":
        finding_links = [
            row for row in finding_links
            if row["risk_id"] is None or row["risk_title"] is None
        ]

    # Keep the missing-mapping tables consistent with target/status selections.
    findings_missing_controls = [
        row for row in finding_links
        if not (row["finding_controls"] or "").strip()
    ]
    risks_missing_controls = [
        row for row in all_risks
        if not (row["iso_controls"] or "").strip()
        and (
            target_filter == "All"
            or any(
                (row["asset"] or "").strip().casefold() == value.strip().casefold()
                for group in target_groups
                if group["label"] == target_filter
                for value in group["targets"]
            )
        )
    ]

    # For the unlinked-risk table, identify risks with no finding reference.
    all_finding_risk_ids = {
        row["risk_id"] for row in finding_rows if row["risk_id"] is not None
    }
    risks_without_findings = [
        row for row in all_risks
        if row["id"] not in all_finding_risk_ids
        and (
            target_filter == "All"
            or any(
                (row["asset"] or "").strip().casefold() == value.strip().casefold()
                for group in target_groups
                if group["label"] == target_filter
                for value in group["targets"]
            )
        )
    ]
    if link_filter == "Linked":
        risks_without_findings = []
    broken_links = [
        row for row in finding_links
        if row["risk_id"] is not None and row["risk_title"] is None
    ]

    # Paginate finding tables independently.
    finding_per_page = 10
    finding_total = len(finding_links)
    finding_pages = max(1, (finding_total + finding_per_page - 1) // finding_per_page)
    finding_page = max(1, request.args.get("finding_page", 1, type=int))
    finding_page = min(finding_page, finding_pages)

    missing_per_page = 10
    missing_total = len(findings_missing_controls)
    missing_pages = max(1, (missing_total + missing_per_page - 1) // missing_per_page)
    missing_page = max(1, request.args.get("missing_page", 1, type=int))
    missing_page = min(missing_page, missing_pages)

    # Calculate summary values before slicing the tables.
    linked_count = sum(
        1 for row in finding_links
        if row["risk_id"] is not None and row["risk_title"] is not None
    )
    summary = {
        "findings": len(finding_links),
        "risks": len({
            row["risk_id"] for row in finding_links
            if row["risk_id"] is not None and row["risk_title"] is not None
        }),
        "findings_without_risk": len(finding_links) - linked_count,
        "risks_without_findings": len(risks_without_findings),
        "findings_without_controls": sum(
            1 for row in finding_links
            if not (row["finding_controls"] or "").strip()
        ),
        "risks_without_controls": len(risks_missing_controls),
    }

    finding_offset = (finding_page - 1) * finding_per_page
    missing_offset = (missing_page - 1) * missing_per_page

    finding_links = finding_links[
        finding_offset:finding_offset + finding_per_page
    ]
    findings_missing_controls = findings_missing_controls[
        missing_offset:missing_offset + missing_per_page
    ]

    # Paginate ISO control reviews independently of the other traceability filters.
    review_per_page = 10
    review_page = max(1, request.args.get("review_page", 1, type=int))

    _, review_total = current_iso_control_reviews(
        limit=review_per_page,
        offset=0,
        include_total=True,
    )
    review_pages = max(1, (review_total + review_per_page - 1) // review_per_page)
    review_page = min(review_page, review_pages)

    control_reviews, _ = current_iso_control_reviews(
        limit=review_per_page,
        offset=(review_page - 1) * review_per_page,
        include_total=True,
    )

    # When filtering for mapped findings, the missing-mapping table is empty
    # by definition; the explanatory section remains useful.
    return render_template(
        "traceability.html",
        nav_items=NAV_ITEMS,
        active_page="traceability_page",
        summary=summary,
        findings_missing_controls=findings_missing_controls,
        risks_missing_controls=risks_missing_controls,
        finding_links=finding_links,
        risks_without_findings=risks_without_findings,
        broken_links=broken_links,
        target_options=target_options,
        target_filter=target_filter,
        status_filter=status_filter,
        mapping_filter=mapping_filter,
        link_filter=link_filter,
        finding_page=finding_page,
        finding_pages=finding_pages,
        finding_total=finding_total,
        missing_page=missing_page,
        missing_pages=missing_pages,
        missing_total=missing_total,
        control_reviews=control_reviews,
        review_page=review_page,
        review_pages=review_pages,
        review_total=review_total,
    )


@app.route("/history")
@app.route("/history/all/<string:module_slug>")
def history_page(module_slug=None):
    import json

    full_history_modules = {
        "nmap": "nmap",
        "web-security": "web_security",
        "threat-intelligence": "threat_intel",
        "firewall": "firewall",
        "zap": "zap",
        "unified": "unified",
    }

    history_full_module = None
    if module_slug is not None:
        history_full_module = full_history_modules.get(module_slug)
        if history_full_module is None:
            return "History module not found", 404

    selected_history_scan = (request.args.get("scan_id") or "").strip()
    history_module = None
    history_record_id = None

    if selected_history_scan:
        try:
            history_module, raw_id = selected_history_scan.split(":", 1)
            history_record_id = int(raw_id)
            if history_module not in {
                "nmap", "web_security", "threat_intel", "firewall", "zap", "unified"
            } or history_record_id < 1:
                raise ValueError
        except (ValueError, TypeError):
            selected_history_scan = ""
            history_module = None
            history_record_id = None

    global_filter_values = {
        "global_scan_id": (request.args.get("global_scan_id") or "").strip(),
        "target": (request.args.get("target") or "").strip(),
        "scan_type": (request.args.get("scan_type") or "").strip(),
        "status": (request.args.get("status") or "").strip(),
    }

    def global_history_where(exclude=None):
        clauses = []
        params = []

        filter_columns = {
            "global_scan_id": "sr.scan_id",
            "target": "sr.target",
            "scan_type": "sr.scan_type",
            "status": "sr.status",
        }

        for key, column in filter_columns.items():
            value = global_filter_values[key]
            if key != exclude and value:
                clauses.append(f"{column} = ?")
                params.append(value)

        return (
            " WHERE " + " AND ".join(clauses) if clauses else "",
            params,
        )

    with get_db() as db:
        registry_join = """
            FROM scan_registry AS sr
            LEFT JOIN target_registry AS tr
                ON tr.target_id = sr.target_id
        """

        registry_rows = db.execute(
            """
            SELECT
                sr.scan_id, sr.scan_type, sr.source_table,
                sr.source_record_id, sr.target, sr.status,
                sr.started_at, sr.finished_at, sr.duration_seconds,
                tr.target_id, tr.target_label
            """ + registry_join + " ORDER BY sr.id DESC"
        ).fetchall()

        registry_rows = [dict(row) for row in registry_rows]

        report_endpoints = {
            "Nmap": ("nmap_results", "scan_id"),
            "Web Security": ("web_security_result", "scan_id"),
            "Threat Intelligence": ("threat_intel_result", "lookup_id"),
            "Firewall": ("firewall_result", "scan_id"),
            "OWASP ZAP": ("zap_scan_result", "scan_id"),
        }

        module_details = {
            "nmap": ("Nmap", "nmap_scans"),
            "web_security": ("Web Security", "web_security_scans"),
            "threat_intel": ("Threat Intelligence", "threat_intel_lookups"),
            "firewall": ("Firewall", "firewall_scans"),
            "zap": ("OWASP ZAP", "zap_scans"),
        }

        registry_by_source = {
            (row["source_table"], row["source_record_id"]): row
            for row in registry_rows
        }

        unified_result_keys = set()
        unified_module_rows = []

        global_unified_rows = db.execute("""
            SELECT id, targets_json, batch_ids_json, status,
                   created_at, finished_at
            FROM unified_scan_runs
            ORDER BY id DESC
        """).fetchall()

        for run in global_unified_rows:
            try:
                batch_ids = json.loads(run["batch_ids_json"] or "{}")
            except (TypeError, ValueError):
                batch_ids = {}

            if not isinstance(batch_ids, dict):
                continue

            for module, batch_id in batch_ids.items():
                if module not in module_details:
                    continue

                if (
                    isinstance(batch_id, bool)
                    or not str(batch_id).isdigit()
                    or int(batch_id) < 1
                ):
                    continue

                batch_id = int(batch_id)
                module_name, expected_source = module_details[module]

                batch = db.execute(
                    """
                    SELECT id, module, created_at, finished_at
                    FROM scan_batches
                    WHERE id = ? AND module = ?
                    """,
                    (batch_id, module),
                ).fetchone()

                if batch is None:
                    continue

                batch_items = db.execute(
                    """
                    SELECT id, target, status, started_at, finished_at,
                           duration_seconds, result_type,
                           result_record_id, request_id, error
                    FROM scan_batch_items
                    WHERE batch_id = ?
                    ORDER BY position, id
                    """,
                    (batch_id,),
                ).fetchall()

                for batch_item in batch_items:
                    item = dict(batch_item)
                    result_type = item.get("result_type") or ""
                    result_record_id = item.get("result_record_id")

                    source_table = expected_source
                    if result_type:
                        mapped = module_details.get(result_type)
                        if mapped is None or result_type != module:
                            source_table = None
                        else:
                            source_table = mapped[1]

                    registry_row = None
                    if source_table and result_record_id is not None:
                        registry_row = registry_by_source.get(
                            (source_table, result_record_id)
                        )

                    if registry_row:
                        unified_result_keys.add(
                            (source_table, result_record_id)
                        )
                        history_item = dict(registry_row)
                    else:
                        history_item = {
                            "scan_id": None,
                            "scan_type": module_name,
                            "source_table": source_table or expected_source,
                            "source_record_id": result_record_id,
                            "target": item["target"],
                            "target_id": None,
                            "target_label": None,
                        }

                    history_item.update({
                        "scan_type": module_name,
                        "target": item["target"],
                        "status": item["status"],
                        "started_at": (
                            item["started_at"]
                            or batch["created_at"]
                            or run["created_at"]
                        ),
                        "finished_at": (
                            item["finished_at"] or batch["finished_at"]
                        ),
                        "duration_seconds": item["duration_seconds"],
                        "_is_unified": True,
                        "_unified_run_id": run["id"],
                        "_batch_id": batch_id,
                        "_batch_item_id": item["id"],
                        "_request_id": item.get("request_id"),
                        "_error": item.get("error"),
                        "_result_type": result_type,
                        "_result_record_id": result_record_id,
                        "_selection_id": f"batch:{batch_id}:{item['id']}",
                    })
                    unified_module_rows.append(history_item)

        standalone_rows = [
            row for row in registry_rows
            if (
                row["source_table"],
                row["source_record_id"],
            ) not in unified_result_keys
        ]

        for item in standalone_rows:
            item["_selection_id"] = f"scan:{item['scan_id']}"

        all_global_rows = standalone_rows + unified_module_rows

        def matches_global_filters(item, exclude=None):
            for key, value in global_filter_values.items():
                if key == exclude or not value:
                    continue

                if key == "global_scan_id":
                    if str(item.get("scan_id") or "") != value:
                        return False
                elif key == "target":
                    if str(item.get("target") or "") != value:
                        return False
                elif key == "scan_type":
                    if value == "Unified Scan":
                        if not item.get("_is_unified"):
                            return False
                    elif str(item.get("scan_type") or "") != value:
                        return False
                elif str(item.get(key) or "") != value:
                    return False

            return True

        global_scan_history = [
            item for item in all_global_rows
            if matches_global_filters(item)
        ]

        global_scan_history.sort(
            key=lambda item: str(item.get("started_at") or ""),
            reverse=True,
        )

        global_history_options = {}

        for key in (
            "global_scan_id", "target", "scan_type", "status"
        ):
            option_values = set()

            for item in all_global_rows:
                if not matches_global_filters(item, exclude=key):
                    continue

                if key == "global_scan_id":
                    value = item.get("scan_id")
                    if value is not None:
                        option_values.add(str(value))
                elif key == "scan_type":
                    value = item.get("scan_type")
                    if value:
                        option_values.add(str(value))
                    if item.get("_is_unified"):
                        option_values.add("Unified Scan")
                else:
                    value = item.get(key)
                    if value is not None:
                        option_values.add(str(value))

            global_history_options[key] = sorted(option_values)

        global_scan_history = [dict(row) for row in global_scan_history]

        for item in global_scan_history:
            endpoint_info = report_endpoints.get(item["scan_type"])
            record_id = (
                item.get("_result_record_id")
                if item.get("_is_unified")
                else item.get("source_record_id")
            )

            if endpoint_info and record_id is not None:
                endpoint, argument = endpoint_info
                item["result_url"] = url_for(
                    endpoint, **{argument: record_id}
                )
            else:
                item["result_url"] = None

        nmap_scans = db.execute("""
            SELECT
                s.*,
                (SELECT COUNT(*) FROM nmap_ports p
                 WHERE p.scan_id = s.id AND p.state = 'open') AS open_ports,
                (SELECT COUNT(*) FROM draft_findings f
                 WHERE f.source = 'nmap'
                   AND CAST(f.source_record_id AS INTEGER) = s.id) AS finding_count,
                (SELECT COUNT(*) FROM draft_findings f
                 WHERE f.source = 'nmap'
                   AND f.source_record_id = s.id
                   AND f.status = 'Approved') AS approved_count
            FROM nmap_scans s
            ORDER BY s.id DESC
        """).fetchall()

        web_scans = db.execute("""
            SELECT id, target, status, started_at, finished_at
            FROM web_security_scans ORDER BY id DESC
        """).fetchall()

        threat_lookups = db.execute("""
            SELECT id, target, status, started_at, finished_at
            FROM threat_intel_lookups ORDER BY id DESC
        """).fetchall()

        firewall_scans = db.execute("""
            SELECT
                f.*,
                (SELECT COUNT(*) FROM draft_findings d
                 WHERE d.source = 'firewall'
                   AND CAST(d.source_record_id AS INTEGER) = f.id) AS finding_count,
                (SELECT COUNT(*) FROM draft_findings d
                 WHERE d.source = 'firewall'
                   AND CAST(d.source_record_id AS INTEGER) = f.id
                   AND d.status = 'Approved') AS approved_count
            FROM firewall_scans f
            ORDER BY f.id DESC
        """).fetchall()

        zap_scans = db.execute("""
            SELECT id, target, status, started_at, finished_at,
                   duration_seconds, error
            FROM zap_scans
            ORDER BY id DESC
        """).fetchall()

        unified_rows = db.execute("""
            SELECT id, targets_json, modules_json, status, created_at, finished_at
            FROM unified_scan_runs ORDER BY id DESC
        """).fetchall()

        unified_runs = []
        for row in unified_rows:
            run = dict(row)
            try:
                run["targets"] = json.loads(run.get("targets_json") or "[]")
            except (TypeError, ValueError):
                run["targets"] = []
            try:
                run["modules"] = json.loads(run.get("modules_json") or "[]")
            except (TypeError, ValueError):
                run["modules"] = []
            unified_runs.append(run)

        history_scan_options = []
        history_scan_options.extend(
            {
                "value": f"nmap:{row['id']}",
                "label": f"Nmap #{row['id']} · {row['target']}",
            }
            for row in nmap_scans
        )
        history_scan_options.extend(
            {
                "value": f"web_security:{row['id']}",
                "label": f"Web Security #{row['id']} · {row['target']}",
            }
            for row in web_scans
        )
        history_scan_options.extend(
            {
                "value": f"threat_intel:{row['id']}",
                "label": f"Threat Intelligence #{row['id']} · {row['target']}",
            }
            for row in threat_lookups
        )
        history_scan_options.extend(
            {
                "value": f"firewall:{row['id']}",
                "label": f"Firewall Detection #{row['id']} · {row['target']}",
            }
            for row in firewall_scans
        )
        history_scan_options.extend(
            {
                "value": f"zap:{row['id']}",
                "label": f"OWASP ZAP #{row['id']} · {row['target']}",
            }
            for row in zap_scans
        )
        history_scan_options.extend(
            {
                "value": f"unified:{row['id']}",
                "label": f"Unified Scan #{row['id']}",
            }
            for row in unified_runs
        )
        history_scan_options.sort(
            key=lambda item: (
                item["value"].split(":", 1)[0],
                -int(item["value"].split(":", 1)[1]),
            )
        )

        if history_module == "nmap":
            nmap_scans = [
                row for row in nmap_scans if row["id"] == history_record_id
            ]
            web_scans = []
            threat_lookups = []
            firewall_scans = []
            zap_scans = []
            unified_runs = []
        elif history_module == "web_security":
            nmap_scans = []
            web_scans = [
                row for row in web_scans if row["id"] == history_record_id
            ]
            threat_lookups = []
            firewall_scans = []
            zap_scans = []
            unified_runs = []
        elif history_module == "threat_intel":
            nmap_scans = []
            web_scans = []
            threat_lookups = [
                row for row in threat_lookups if row["id"] == history_record_id
            ]
            firewall_scans = []
            zap_scans = []
            unified_runs = []
        elif history_module == "firewall":
            nmap_scans = []
            web_scans = []
            threat_lookups = []
            firewall_scans = [
                row for row in firewall_scans if row["id"] == history_record_id
            ]
            zap_scans = []
            unified_runs = []
        elif history_module == "zap":
            nmap_scans = []
            web_scans = []
            threat_lookups = []
            firewall_scans = []
            unified_runs = []
            zap_scans = [
                row for row in zap_scans if row["id"] == history_record_id
            ]
        elif history_module == "unified":
            nmap_scans = []
            web_scans = []
            threat_lookups = []
            firewall_scans = []
            zap_scans = []
            unified_runs = [
                row for row in unified_runs if row["id"] == history_record_id
            ]

        saved_requests = db.execute("""
            SELECT * FROM scans ORDER BY id DESC LIMIT 100
        """).fetchall()

    # Preserve total counts before limiting the overview to two records.
    nmap_scan_count = len(nmap_scans)
    web_scan_count = len(web_scans)
    threat_lookup_count = len(threat_lookups)
    firewall_scan_count = len(firewall_scans)
    zap_scan_count = len(zap_scans)
    unified_run_count = len(unified_runs)

    # The overview shows only the two latest records in each category.
    # Full-history pages and individual Scan ID filters remain unrestricted.
    if not selected_history_scan and history_full_module is None:
        nmap_scans = nmap_scans[:2]
        web_scans = web_scans[:2]
        threat_lookups = threat_lookups[:2]
        firewall_scans = firewall_scans[:2]
        zap_scans = zap_scans[:2]
        unified_runs = unified_runs[:2]

    return render_template(
        "scan_history.html",
        nav_items=NAV_ITEMS,
        active_page="history_page",
        nmap_scans=nmap_scans,
        web_scans=web_scans,
        threat_lookups=threat_lookups,
        firewall_scans=firewall_scans,
        zap_scans=zap_scans,
        unified_runs=unified_runs,
        saved_requests=saved_requests,
        history_scan_options=history_scan_options,
        selected_history_scan=selected_history_scan,
        history_full_module=history_full_module,
        nmap_scan_count=nmap_scan_count,
        web_scan_count=web_scan_count,
        threat_lookup_count=threat_lookup_count,
        firewall_scan_count=firewall_scan_count,
        zap_scan_count=zap_scan_count,
        unified_run_count=unified_run_count,
        global_scan_history=global_scan_history,
        global_scan_count=len(global_scan_history),
        global_filter_values=global_filter_values,
        global_history_options=global_history_options,
    )



@app.route("/history/export", methods=["POST"])
def export_global_scan_history():
    """Export only explicitly selected global scan-history records."""
    from datetime import datetime, timezone

    module_sources = {
        "nmap": ("Nmap", "nmap_scans", "nmap"),
        "web_security": ("Web Security", "web_security_scans", "web_security"),
        "threat_intel": (
            "Threat Intelligence", "threat_intel_lookups", "threat_intel"
        ),
        "firewall": ("Firewall", "firewall_scans", "firewall"),
        "zap": ("OWASP ZAP", "zap_scans", "zap"),
    }

    def decode_result(value):
        if not value:
            return {}
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return {"raw_result": str(value)}

    def load_findings(db, source, record_id):
        if record_id is None:
            return []
        rows = db.execute(
            """
            SELECT id, source, source_record_id, target, title,
                   description, evidence, suggested_severity, confidence,
                   recommendation, iso_controls, status, risk_id,
                   created_at, updated_at
            FROM draft_findings
            WHERE source = ? AND source_record_id = ?
            ORDER BY id
            """,
            (source, record_id),
        ).fetchall()
        return [dict(row) for row in rows]

    selected_values = request.form.getlist("selected_scans")
    export_format = (request.form.get("export_format") or "").lower()

    if export_format not in {"pdf", "csv"}:
        abort(400, description="Choose PDF or CSV export.")

    if not selected_values:
        abort(400, description="Select at least one scan.")

    scans = []
    seen = set()

    with get_db() as db:
        for value in selected_values:
            if value in seen:
                continue
            seen.add(value)

            module = None
            source_table = None
            source = None
            scan_id = None
            record_id = None
            target = ""
            status = "Unknown"
            started_at = ""
            finished_at = ""
            duration_seconds = None
            error = None

            parts = value.split(":")

            if len(parts) == 2 and parts[0] == "scan":
                scan_id = parts[1]
                registry = db.execute(
                    """
                    SELECT scan_id, scan_type, source_table,
                           source_record_id, target, status,
                           started_at, finished_at, duration_seconds
                    FROM scan_registry
                    WHERE scan_id = ?
                    """,
                    (scan_id,),
                ).fetchone()

                if registry is None:
                    continue

                module = registry["scan_type"]
                source_table = registry["source_table"]
                record_id = registry["source_record_id"]
                target = registry["target"]
                status = registry["status"]
                started_at = registry["started_at"]
                finished_at = registry["finished_at"]
                duration_seconds = registry["duration_seconds"]

                allowed = {
                    details[0]: details
                    for details in module_sources.values()
                }
                if module not in allowed:
                    continue

                expected_table = allowed[module][1]
                if source_table != expected_table:
                    continue
                source = allowed[module][2]

            elif (
                len(parts) == 3
                and parts[0] == "batch"
                and parts[1].isdigit()
                and parts[2].isdigit()
            ):
                batch_id, item_id = int(parts[1]), int(parts[2])
                item = db.execute(
                    """
                    SELECT bi.id, bi.batch_id, bi.target, bi.status,
                           bi.started_at, bi.finished_at,
                           bi.duration_seconds, bi.result_type,
                           bi.result_record_id, bi.error, b.module
                    FROM scan_batch_items AS bi
                    JOIN scan_batches AS b ON b.id = bi.batch_id
                    WHERE bi.id = ? AND bi.batch_id = ?
                    """,
                    (item_id, batch_id),
                ).fetchone()

                if item is None or item["module"] not in module_sources:
                    continue

                module, source_table, source = module_sources[item["module"]]
                target = item["target"]
                status = item["status"]
                started_at = item["started_at"]
                finished_at = item["finished_at"]
                duration_seconds = item["duration_seconds"]
                record_id = item["result_record_id"]
                error = item["error"]

                if record_id is not None:
                    registry = db.execute(
                        """
                        SELECT scan_id
                        FROM scan_registry
                        WHERE source_table = ? AND source_record_id = ?
                        """,
                        (source_table, record_id),
                    ).fetchone()
                    if registry:
                        scan_id = registry["scan_id"]

            else:
                continue

            record = None
            if record_id is not None:
                # Table names come only from the server-side allowlist.
                if source_table == "nmap_scans":
                    record = db.execute(
                        """
                        SELECT *
                        FROM nmap_scans
                        WHERE id = ?
                        """,
                        (record_id,),
                    ).fetchone()
                else:
                    record = db.execute(
                        f"""
                        SELECT id, target, status, started_at, finished_at,
                               duration_seconds, result_json, error
                        FROM {source_table}
                        WHERE id = ?
                        """,
                        (record_id,),
                    ).fetchone()

            if record:
                record = dict(record)
                target = record.get("target") or target
                status = record.get("status") or status
                started_at = record.get("started_at") or started_at
                finished_at = record.get("finished_at") or finished_at
                duration_seconds = (
                    record.get("duration_seconds")
                    if record.get("duration_seconds") is not None
                    else duration_seconds
                )
                error = record.get("error") or error

                if source_table == "nmap_scans":
                    result = {
                        key: record.get(key)
                        for key in (
                            "host_state",
                            "command_display",
                            "mac_address",
                            "mac_vendor",
                            "os_match",
                            "os_accuracy",
                            "os_detection_status",
                        )
                        if record.get(key) is not None
                    }
                    result["os_matches"] = decode_result(
                        record.get("os_matches_json")
                    )
                else:
                    result = decode_result(record.get("result_json"))
            else:
                result = {}

            ports = []
            if source_table == "nmap_scans" and record_id is not None:
                ports = [
                    dict(row)
                    for row in db.execute(
                        """
                        SELECT *
                        FROM nmap_ports
                        WHERE scan_id = ?
                        ORDER BY protocol, port
                        """,
                        (record_id,),
                    ).fetchall()
                ]

            findings = load_findings(db, source, record_id)

            risk_ids = sorted({
                finding["risk_id"]
                for finding in findings
                if finding.get("risk_id") is not None
            })
            risks = []
            if risk_ids:
                placeholders = ",".join("?" for _ in risk_ids)
                risks = [
                    dict(row)
                    for row in db.execute(
                        f"""
                        SELECT *
                        FROM risk_assessments
                        WHERE id IN ({placeholders})
                        ORDER BY id
                        """,
                        risk_ids,
                    ).fetchall()
                ]

            scans.append({
                "scan_id": scan_id,
                "module": module,
                "record_id": record_id,
                "target": target,
                "status": status,
                "started_at": started_at,
                "finished_at": finished_at,
                "duration_seconds": duration_seconds,
                "error": error,
                "result": result,
                "ports": ports,
                "findings": findings,
                "risks": risks,
            })

        if not scans:
            abort(400, description="No valid selected scan records were found.")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    if export_format == "pdf":
        pdf_bytes = build_global_scan_history_pdf(scans=scans)
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition":
                    f'attachment; filename="shadow-map-global-history-{stamp}.pdf"'
            },
        )

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([
        "Record Type", "Scan ID", "Record ID", "Module", "Target",
        "Scan Status", "Started At", "Finished At", "Duration Seconds",
        "Scan Error / Limitation", "Finding ID", "Finding Title",
        "Severity", "Confidence", "Finding Status", "Description",
        "Evidence", "Recommendation", "ISO Controls", "Risk ID",
        "Risk Title", "Risk Asset", "Inherent Score", "Residual Score",
        "Risk Treatment", "Risk Status", "Technical Result JSON",
        "Nmap Ports JSON",
    ])

    for scan in scans:
        common = [
            scan.get("scan_id"), scan.get("record_id"), scan.get("module"),
            scan.get("target"), scan.get("status"), scan.get("started_at"),
            scan.get("finished_at"), scan.get("duration_seconds"),
            scan.get("error") or "",
        ]
        technical_json = json.dumps(
            scan.get("result") or {}, ensure_ascii=False, default=str
        )
        ports_json = json.dumps(
            scan.get("ports") or [], ensure_ascii=False, default=str
        )

        # Every selected scan gets a row, including scans without findings.
        writer.writerow([
            "Scan", *common, "", "", "", "", "", "", "", "", "", "", "",
            "", "", "", technical_json, ports_json,
        ])

        risks_by_id = {
            risk["id"]: risk for risk in scan.get("risks", [])
        }
        for finding in scan.get("findings", []):
            risk = risks_by_id.get(finding.get("risk_id"), {})
            writer.writerow([
                "Finding", *common,
                finding.get("id"),
                finding.get("title"),
                finding.get("suggested_severity"),
                finding.get("confidence"),
                finding.get("status"),
                finding.get("description"),
                finding.get("evidence"),
                finding.get("recommendation"),
                finding.get("iso_controls"),
                finding.get("risk_id"),
                risk.get("title"),
                risk.get("asset"),
                risk.get("inherent_score"),
                risk.get("residual_score"),
                risk.get("treatment"),
                risk.get("status"),
                technical_json,
                ports_json,
            ])

    return Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition":
                f'attachment; filename="shadow-map-global-history-{stamp}.csv"'
        },
    )


@app.route("/history/target/<string:target_id>")
def target_details(target_id):
    with get_db() as db:
        target = db.execute("""
            SELECT target_id, target_label, first_seen_at, last_seen_at
            FROM target_registry
            WHERE target_id = ?
        """, (target_id,)).fetchone()

        if target is None:
            abort(404)

        scans = db.execute("""
            SELECT scan_id, scan_type, target, status, started_at,
                   finished_at, duration_seconds, source_record_id
            FROM scan_registry
            WHERE target_id = ?
            ORDER BY id DESC
        """, (target_id,)).fetchall()

    report_endpoints = {
        "Nmap": ("nmap_results", "scan_id"),
        "Web Security": ("web_security_result", "scan_id"),
        "Threat Intelligence": ("threat_intel_result", "lookup_id"),
        "Firewall": ("firewall_result", "scan_id"),
        "OWASP ZAP": ("zap_scan_result", "scan_id"),
    }

    target_scans = [dict(scan) for scan in scans]
    for scan in target_scans:
        endpoint_info = report_endpoints.get(scan["scan_type"])
        scan["result_url"] = (
            url_for(endpoint_info[0],
                    **{endpoint_info[1]: scan["source_record_id"]})
            if endpoint_info else None
        )

    return render_template(
        "scan_history.html",
        nav_items=NAV_ITEMS,
        active_page="history_page",
        target_detail=dict(target),
        target_scans=target_scans,
    )


@app.route("/history/nmap/<int:scan_id>")
def scan_history_detail(scan_id):
    # Generate any missing draft observations for this scan only.
    generate_nmap_drafts(scan_id)

    with get_db() as db:
        scan = db.execute("""
            SELECT * FROM nmap_scans WHERE id = ?
        """, (scan_id,)).fetchone()

        if scan is None:
            abort(404)

        findings = db.execute("""
            SELECT * FROM draft_findings
            WHERE source = 'nmap' AND CAST(source_record_id AS INTEGER) = ?
            ORDER BY id DESC
        """, (scan_id,)).fetchall()

        ports = db.execute("""
            SELECT * FROM nmap_ports
            WHERE scan_id = ?
            ORDER BY port, protocol
        """, (scan_id,)).fetchall()

    return render_template(
        "scan_detail.html",
        nav_items=NAV_ITEMS,
        active_page="history_page",
        scan=scan,
        findings=findings,
        ports=ports,
    )


@app.route("/history/nmap/<int:scan_id>/delete", methods=["POST"])
def delete_nmap_scan(scan_id):
    with get_db() as db:
        scan = db.execute(
            "SELECT id FROM nmap_scans WHERE id = ?", (scan_id,)
        ).fetchone()

        if scan is None:
            flash("Scan not found.", "error")
            return redirect(url_for("history_page"))

        # Remove only this scan's draft findings and Nmap data.
        # Approved risk assessments are intentionally preserved.
        db.execute("""
            DELETE FROM draft_findings
            WHERE source = 'nmap'
              AND CAST(source_record_id AS INTEGER) = ?
        """, (scan_id,))
        db.execute("DELETE FROM nmap_ports WHERE scan_id = ?", (scan_id,))
        db.execute("DELETE FROM nmap_scans WHERE id = ?", (scan_id,))

    flash(
        f"Scan #{scan_id} and its Nmap results were deleted. "
        "Existing risk assessments were preserved.",
        "success",
    )
    return redirect(url_for("history_page"))


@app.route("/live-ping/start", methods=["POST"])
def live_ping_start_api():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A JSON request body is required."}), 400

    try:
        result = start_ping(
            data.get("target", ""),
            interval_seconds=data.get("interval_seconds", 2),
            packet_count=data.get("packet_count", 10),
        )
        return jsonify(result), 202
    except LivePingError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        app.logger.exception("Live Ping start failed")
        return jsonify({"error": "Unable to start Live Ping."}), 500


@app.route("/live-ping/stop", methods=["POST"])
def live_ping_stop_api():
    try:
        return jsonify(stop_ping())
    except LivePingError as exc:
        return jsonify({"error": str(exc)}), 409
    except Exception:
        app.logger.exception("Live Ping stop failed")
        return jsonify({"error": "Unable to stop Live Ping."}), 500


@app.route("/live-ping/status", methods=["GET"])
def live_ping_status_api():
    try:
        return jsonify(get_ping_status())
    except Exception:
        app.logger.exception("Live Ping status retrieval failed")
        return jsonify({"error": "Unable to retrieve Live Ping status."}), 500


@app.route("/live-ping/history", methods=["GET"])
def live_ping_history_api():
    try:
        return jsonify({"history": get_recent_ping_history(5)})
    except Exception:
        app.logger.exception("Live Ping history retrieval failed")
        return jsonify({"error": "Unable to retrieve Live Ping history."}), 500


@app.route("/health")
def health():
    return {"status": "ok"}



# -------------------------------------------------------------------
# GRC Risk Register
# -------------------------------------------------------------------

RISK_CONTROLS = [
    ("A.5.9", "Inventory of information and other associated assets"),
    ("A.5.15", "Access control"),
    ("A.5.18", "Access rights"),
    ("A.5.23", "Information security for use of cloud services"),
    ("A.5.24", "Information security incident management planning"),
    ("A.5.29", "Information security during disruption"),
    ("A.5.30", "ICT readiness for business continuity"),
    ("A.5.34", "Privacy and protection of PII"),
    ("A.8.5", "Secure authentication"),
    ("A.8.8", "Management of technical vulnerabilities"),
    ("A.8.9", "Configuration management"),
    ("A.8.13", "Information backup"),
    ("A.8.15", "Logging"),
    ("A.8.16", "Monitoring activities"),
    ("A.8.20", "Network security"),
    ("A.8.21", "Security of network services"),
    ("A.8.22", "Segregation of networks"),
    ("A.8.24", "Use of cryptography"),
    ("A.8.25", "Secure development life cycle"),
    ("A.8.32", "Change management"),
]

RISK_STATUSES = [
    "Open",
    "In Progress",
    "Accepted",
    "Remediated",
]


def calculate_risk_level(score):
    if score <= 4:
        return "Low"
    if score <= 9:
        return "Medium"
    if score <= 16:
        return "High"
    return "Critical"


def init_risk_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS risk_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                asset TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT 'General',
                evidence TEXT NOT NULL DEFAULT '',
                business_impact TEXT NOT NULL DEFAULT '',
                owner TEXT NOT NULL DEFAULT '',
                inherent_likelihood INTEGER NOT NULL,
                inherent_impact INTEGER NOT NULL,
                inherent_score INTEGER NOT NULL,
                inherent_level TEXT NOT NULL,
                residual_likelihood INTEGER NOT NULL,
                residual_impact INTEGER NOT NULL,
                residual_score INTEGER NOT NULL,
                residual_level TEXT NOT NULL,
                treatment TEXT NOT NULL DEFAULT '',
                iso_controls TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'Open',
                due_date TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)


def risk_form_values():
    form = request.form

    title = form.get("title", "").strip()
    if not title or len(title) > 160:
        raise ValueError("Title is required and must be 160 characters or fewer.")

    def field(name, maximum=4000):
        value = form.get(name, "").strip()
        if len(value) > maximum:
            raise ValueError(f"{name.replace('_', ' ').title()} is too long.")
        return value

    def score_field(name):
        raw = form.get(name, "").strip()
        try:
            value = int(raw)
        except (ValueError, TypeError):
            raise ValueError("Likelihood and impact scores must be from 1 to 5.")
        if value < 1 or value > 5:
            raise ValueError("Likelihood and impact scores must be from 1 to 5.")
        return value

    category = field("category", 80) or "General"
    status = form.get("status", "Open")
    if status not in RISK_STATUSES:
        raise ValueError("Choose a valid risk status.")

    due_date = field("due_date", 10)
    if due_date:
        try:
            datetime.strptime(due_date, "%Y-%m-%d")
        except ValueError:
            raise ValueError("Due date must use YYYY-MM-DD format.")

    chosen_controls = form.getlist("iso_controls")
    allowed_codes = {code for code, _ in RISK_CONTROLS}
    if any(code not in allowed_codes for code in chosen_controls):
        raise ValueError("An invalid ISO control was selected.")

    inherent_likelihood = score_field("inherent_likelihood")
    inherent_impact = score_field("inherent_impact")
    residual_likelihood = score_field("residual_likelihood")
    residual_impact = score_field("residual_impact")

    inherent_score = inherent_likelihood * inherent_impact
    residual_score = residual_likelihood * residual_impact

    return {
        "title": title,
        "description": field("description"),
        "asset": field("asset", 250),
        "category": category,
        "evidence": field("evidence"),
        "business_impact": field("business_impact"),
        "owner": field("owner", 160),
        "inherent_likelihood": inherent_likelihood,
        "inherent_impact": inherent_impact,
        "inherent_score": inherent_score,
        "inherent_level": calculate_risk_level(inherent_score),
        "residual_likelihood": residual_likelihood,
        "residual_impact": residual_impact,
        "residual_score": residual_score,
        "residual_level": calculate_risk_level(residual_score),
        "treatment": field("treatment"),
        "iso_controls": ", ".join(chosen_controls),
        "status": status,
        "due_date": due_date,
    }


@app.route("/risks")
def risk_register_page():
    edit_id = request.args.get("edit", type=int)
    edit_risk = None
    status_filter = request.args.get("status", "All")
    owner_filter = request.args.get("owner", "All")
    due_filter = request.args.get("due_filter", "All")

    allowed_statuses = {"All", *RISK_STATUSES}
    allowed_due = {"All", "Overdue", "Missing due date", "Due date set"}
    if status_filter not in allowed_statuses:
        status_filter = "All"
    if due_filter not in allowed_due:
        due_filter = "All"

    today_date = datetime.now().date().isoformat()

    with get_db() as db:
        if edit_id is not None:
            edit_risk = db.execute(
                "SELECT * FROM risk_assessments WHERE id = ?", (edit_id,)
            ).fetchone()
            if edit_risk is None:
                abort(404)

        owner_rows = db.execute("""
            SELECT DISTINCT TRIM(owner) AS owner
            FROM risk_assessments
            WHERE owner IS NOT NULL AND TRIM(owner) != ''
            ORDER BY owner COLLATE NOCASE
        """).fetchall()
        owner_options = [row["owner"] for row in owner_rows]
        if owner_filter != "All" and owner_filter not in owner_options:
            owner_filter = "All"

        risks = db.execute("""
            SELECT
                r.*,
                (SELECT df.id FROM draft_findings df
                 WHERE df.risk_id = r.id ORDER BY df.id DESC LIMIT 1)
                    AS source_finding_id,
                (SELECT df.title FROM draft_findings df
                 WHERE df.risk_id = r.id ORDER BY df.id DESC LIMIT 1)
                    AS source_finding_title,
                (SELECT df.source FROM draft_findings df
                 WHERE df.risk_id = r.id ORDER BY df.id DESC LIMIT 1)
                    AS source_finding_source,
                (SELECT ns.id FROM draft_findings df
                 JOIN nmap_scans ns
                   ON ns.id = CAST(df.source_record_id AS INTEGER)
                 WHERE df.source = 'nmap' AND df.risk_id = r.id
                 ORDER BY df.id DESC LIMIT 1)
                    AS source_scan_id,
                (SELECT ns.target FROM draft_findings df
                 JOIN nmap_scans ns
                   ON ns.id = CAST(df.source_record_id AS INTEGER)
                 WHERE df.source = 'nmap' AND df.risk_id = r.id
                 ORDER BY df.id DESC LIMIT 1)
                    AS source_scan_target,
                (SELECT ns.started_at FROM draft_findings df
                 JOIN nmap_scans ns
                   ON ns.id = CAST(df.source_record_id AS INTEGER)
                 WHERE df.source = 'nmap' AND df.risk_id = r.id
                 ORDER BY df.id DESC LIMIT 1)
                    AS source_scan_started_at
            FROM risk_assessments r
            ORDER BY
                CASE r.residual_level
                    WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3 ELSE 4
                END,
                r.updated_at DESC
        """).fetchall()

    # Convert SQLite rows to dictionaries so review flags can be added safely.
    risks = [dict(risk) for risk in risks]

    # Filters affect only the displayed list; no records are changed.
    if status_filter != "All":
        risks = [r for r in risks if r["status"] == status_filter]
    if owner_filter != "All":
        risks = [r for r in risks if (r["owner"] or "").strip() == owner_filter]
    if due_filter == "Overdue":
        risks = [r for r in risks
                 if r["due_date"] and r["due_date"] < today_date
                 and r["status"] != "Remediated"]
    elif due_filter == "Missing due date":
        risks = [r for r in risks if not (r["due_date"] or "").strip()]
    elif due_filter == "Due date set":
        risks = [r for r in risks if (r["due_date"] or "").strip()]

    # Calculate review flags in memory only. These do not change risk records.
    for risk in risks:
        flags = []
        status = (risk["status"] or "").strip()
        owner = (risk["owner"] or "").strip()
        treatment = (risk["treatment"] or "").strip()
        due_date = (risk["due_date"] or "").strip()
        level = (risk["residual_level"] or "").strip()

        if not owner:
            flags.append("Owner missing")

        if status == "Accepted" and not treatment:
            flags.append("Acceptance rationale needs recording")
        elif status != "Remediated" and not treatment:
            flags.append("Treatment plan missing")

        if status != "Remediated" and not due_date:
            flags.append("Due date missing")

        if (
            status != "Remediated"
            and due_date
            and due_date < today_date
        ):
            flags.append("Overdue action")

        if (
            status != "Remediated"
            and level in ("High", "Critical")
            and due_date
            and due_date < today_date
        ):
            flags.insert(0, "High-priority overdue risk")

        risk["review_flags"] = flags

    stats = {
        "total": len(risks),
        "open": sum(1 for r in risks if r["status"] == "Open"),
        "high_critical": sum(
            1 for r in risks
            if r["residual_level"] in ("High", "Critical")
            and r["status"] != "Remediated"
        ),
        "remediated": sum(1 for r in risks if r["status"] == "Remediated"),
    }

    return render_template(
        "risks.html",
        nav_items=NAV_ITEMS,
        active_page="risk_register_page",
        risks=risks,
        edit_risk=edit_risk,
        stats=stats,
        controls=RISK_CONTROLS,
        status_options=RISK_STATUSES,
        today_date=today_date,
        status_filter=status_filter,
        owner_filter=owner_filter,
        due_filter=due_filter,
        owner_options=owner_options,
    )


@app.route("/risks/save", methods=["POST"])
def save_risk():
    risk_id = request.form.get("risk_id", "").strip()

    try:
        values = risk_form_values()
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("risk_register_page"))

    now = now_utc()

    columns = [
        "title", "description", "asset", "category", "evidence",
        "business_impact", "owner", "inherent_likelihood",
        "inherent_impact", "inherent_score", "inherent_level",
        "residual_likelihood", "residual_impact", "residual_score",
        "residual_level", "treatment", "iso_controls", "status",
        "due_date",
    ]

    try:
        with get_db() as db:
            if risk_id:
                try:
                    parsed_id = int(risk_id)
                except ValueError:
                    raise ValueError("Invalid risk record ID.")

                exists = db.execute(
                    "SELECT id FROM risk_assessments WHERE id = ?",
                    (parsed_id,),
                ).fetchone()
                if exists is None:
                    abort(404)

                assignments = ", ".join(f"{column} = ?" for column in columns)
                db.execute(
                    f"UPDATE risk_assessments SET {assignments}, updated_at = ? "
                    "WHERE id = ?",
                    [values[column] for column in columns] + [now, parsed_id],
                )
                saved_id = parsed_id
            else:
                insert_columns = columns + ["created_at", "updated_at"]
                placeholders = ", ".join("?" for _ in insert_columns)
                db.execute(
                    f"INSERT INTO risk_assessments "
                    f"({', '.join(insert_columns)}) VALUES ({placeholders})",
                    [values[column] for column in columns] + [now, now],
                )
                saved_id = db.execute(
                    "SELECT last_insert_rowid()"
                ).fetchone()[0]
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("risk_register_page"))

    flash("Risk assessment saved.", "success")
    return redirect(url_for("risk_register_page") + f"?edit={saved_id}")


@app.route("/risks/<int:risk_id>/delete", methods=["POST"])
def delete_risk(risk_id):
    with get_db() as db:
        risk = db.execute(
            "SELECT id FROM risk_assessments WHERE id = ?",
            (risk_id,),
        ).fetchone()

        if risk is None:
            abort(404)

        linked_findings = db.execute(
            "SELECT COUNT(*) FROM draft_findings WHERE risk_id = ?",
            (risk_id,),
        ).fetchone()[0]

        if linked_findings:
            flash(
                "This risk cannot be deleted because findings reference it. "
                "Preserve the risk record and review its treatment status instead.",
                "error",
            )
            return redirect(url_for("risk_register_page"))

        db.execute(
            "DELETE FROM risk_assessments WHERE id = ?",
            (risk_id,),
        )

    flash("Risk assessment deleted.", "success")
    return redirect(url_for("risk_register_page"))



def create_records_backup():
    """Create a consistent SQLite backup before destructive record operations."""
    from pathlib import Path
    from datetime import datetime
    import sqlite3

    root = Path(__file__).resolve().parent
    backup_dir = root / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup_path = backup_dir / f"shadow-map-before-delete-{stamp}.db"
    while backup_path.exists():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        backup_path = backup_dir / f"shadow-map-before-delete-{stamp}.db"

    source = sqlite3.connect(DATABASE_PATH, timeout=15)
    destination = sqlite3.connect(str(backup_path))
    try:
        source.backup(destination)
    finally:
        destination.close()
        source.close()

    return backup_path


def records_target_key(target):
    """Group web URLs by hostname; keep non-URL targets distinct."""
    value = str(target or "").strip()
    if not value:
        return None

    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() in {"http", "https"}
            and parsed.hostname
            and not parsed.username
            and not parsed.password
        ):
            hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii")
            return hostname.casefold()
    except (ValueError, UnicodeError):
        pass

    return value.casefold().rstrip(".")


def list_record_targets(db):
    """Return one Records Management option per hostname or non-URL target."""
    rows = db.execute("""
        SELECT target AS value FROM scans
        UNION
        SELECT target AS value FROM nmap_scans
        UNION
        SELECT target AS value FROM firewall_scans
        UNION
        SELECT target AS value FROM draft_findings
        UNION
        SELECT asset AS value FROM risk_assessments
    """).fetchall()

    labels = {}
    for row in rows:
        value = (row["value"] or "").strip()
        key = records_target_key(value)
        if not key:
            continue

        # Web targets are displayed as hostnames; other targets retain
        # their original spelling for a readable dropdown.
        try:
            parsed = urlsplit(value)
            is_web_url = (
                parsed.scheme.lower() in {"http", "https"}
                and parsed.hostname
                and not parsed.username
                and not parsed.password
            )
        except ValueError:
            is_web_url = False

        label = records_target_key(value) if is_web_url else value
        labels.setdefault(key, label)

    return sorted(labels.values(), key=str.casefold)


@app.route("/records", methods=["GET"])
def records_management_page():
    initialize_custom_rules()
    with get_db() as db:
        targets = list_record_targets(db)
        counts = {}
        for table in (
            "custom_rules", "scans", "nmap_scans", "nmap_ports",
            "firewall_scans", "draft_findings", "risk_assessments",
            "iso_control_reviews",
        ):
            counts[table] = db.execute(
                f'SELECT COUNT(*) FROM "{table}"'
            ).fetchone()[0]

    return render_template(
        "records_management.html",
        nav_items=NAV_ITEMS,
        active_page=request.endpoint,
        targets=targets,
        counts=counts,
    )


@app.route("/records/delete-host", methods=["POST"])
def delete_host_records():
    target = request.form.get("target", "").strip()
    selected_key = records_target_key(target)

    if not selected_key:
        flash("Select a target before deleting its records.", "error")
        return redirect(url_for("records_management_page"))

    # Reject forged dropdown values that do not represent a currently
    # recorded target group.
    with get_db() as db:
        allowed_keys = {
            records_target_key(value)
            for value in list_record_targets(db)
        }
    if selected_key not in allowed_keys:
        flash("The selected target is not in the current records list.", "error")
        return redirect(url_for("records_management_page"))

    # Keep the existing backup-before-delete behavior.
    backup_path = create_records_backup()
    deleted = {}

    with get_db() as db:
        # Resolve matching stored targets using hostname identity.
        # This groups URL paths and HTTP/HTTPS URLs for the same hostname,
        # while preventing suffix matches against unrelated hostnames.
        def matching_ids(table, column, extra_sql="", extra_params=()):
            rows = db.execute(
                f'SELECT id, "{column}" AS value FROM "{table}" '
                f'WHERE "{column}" IS NOT NULL AND TRIM("{column}") != "" '
                + extra_sql,
                extra_params,
            ).fetchall()
            return [
                row["id"] for row in rows
                if records_target_key(row["value"]) == selected_key
            ]

        nmap_ids = matching_ids("nmap_scans", "target")
        firewall_ids = matching_ids("firewall_scans", "target")
        nmap_rows = []
        if nmap_ids:
            placeholders = ",".join("?" for _ in nmap_ids)
            nmap_rows = db.execute(
                f"SELECT id, request_id FROM nmap_scans WHERE id IN ({placeholders})",
                nmap_ids,
            ).fetchall()

        finding_ids = set(matching_ids("draft_findings", "target"))

        # Include findings linked to the Nmap scans being removed.
        if nmap_ids:
            placeholders = ",".join("?" for _ in nmap_ids)
            finding_ids.update(
                row["id"] for row in db.execute(
                    f"""SELECT id FROM draft_findings
                        WHERE lower(source) = 'nmap'
                        AND CAST(source_record_id AS INTEGER) IN ({placeholders})""",
                    nmap_ids,
                ).fetchall()
            )

        # Include findings linked to Firewall Detection scans being removed.
        if firewall_ids:
            placeholders = ",".join("?" for _ in firewall_ids)
            finding_ids.update(
                row["id"] for row in db.execute(
                    f"""SELECT id FROM draft_findings
                        WHERE lower(source) = 'firewall'
                        AND CAST(source_record_id AS INTEGER) IN ({placeholders})""",
                    firewall_ids,
                ).fetchall()
            )

        risk_ids = set()
        for row in db.execute("""
            SELECT id, asset AS value FROM risk_assessments
            WHERE asset IS NOT NULL AND TRIM(asset) != ''
        """).fetchall():
            if records_target_key(row["value"]) == selected_key:
                risk_ids.add(row["id"])

        # Delete ISO reviews before deleting their associated findings.
        if finding_ids:
            placeholders = ",".join("?" for _ in finding_ids)
            db.execute(
                f"""DELETE FROM iso_control_reviews
                    WHERE record_type = 'finding'
                    AND record_id IN ({placeholders})""",
                list(finding_ids),
            )
            deleted["findings"] = db.execute(
                f"DELETE FROM draft_findings WHERE id IN ({placeholders})",
                list(finding_ids),
            ).rowcount
        else:
            deleted["findings"] = 0

        # Never remove a risk still referenced by a surviving finding.
        removable_risks = []
        for risk_id in risk_ids:
            linked = db.execute(
                "SELECT 1 FROM draft_findings WHERE risk_id = ? LIMIT 1",
                (risk_id,),
            ).fetchone()
            if not linked:
                removable_risks.append(risk_id)

        if removable_risks:
            placeholders = ",".join("?" for _ in removable_risks)
            db.execute(
                f"""DELETE FROM iso_control_reviews
                    WHERE record_type = 'risk'
                    AND record_id IN ({placeholders})""",
                removable_risks,
            )
            deleted["risks"] = db.execute(
                f"DELETE FROM risk_assessments WHERE id IN ({placeholders})",
                removable_risks,
            ).rowcount
        else:
            deleted["risks"] = 0

        if nmap_ids:
            placeholders = ",".join("?" for _ in nmap_ids)
            deleted["ports"] = db.execute(
                f"DELETE FROM nmap_ports WHERE scan_id IN ({placeholders})",
                nmap_ids,
            ).rowcount
            deleted["nmap_scans"] = db.execute(
                f"DELETE FROM nmap_scans WHERE id IN ({placeholders})",
                nmap_ids,
            ).rowcount
        else:
            deleted["ports"] = 0
            deleted["nmap_scans"] = 0

        if firewall_ids:
            placeholders = ",".join("?" for _ in firewall_ids)
            deleted["firewall_scans"] = db.execute(
                f"DELETE FROM firewall_scans WHERE id IN ({placeholders})",
                firewall_ids,
            ).rowcount
        else:
            deleted["firewall_scans"] = 0

        # Remove matching saved requests only if no remaining Nmap scan
        # references them.
        scan_ids = matching_ids("scans", "target")
        if scan_ids:
            placeholders = ",".join("?" for _ in scan_ids)
            deleted["requests"] = db.execute(
                f"""DELETE FROM scans
                    WHERE id IN ({placeholders})
                    AND NOT EXISTS (
                        SELECT 1 FROM nmap_scans
                        WHERE nmap_scans.request_id = scans.id
                    )""",
                scan_ids,
            ).rowcount
        else:
            deleted["requests"] = 0

        # Remove orphaned reviews, but preserve reviews for surviving records.
        db.execute("""
            DELETE FROM iso_control_reviews
            WHERE (record_type = 'finding' AND NOT EXISTS (
                SELECT 1 FROM draft_findings
                WHERE draft_findings.id = iso_control_reviews.record_id
            ))
            OR (record_type = 'risk' AND NOT EXISTS (
                SELECT 1 FROM risk_assessments
                WHERE risk_assessments.id = iso_control_reviews.record_id
            ))
        """)

    flash(
        f"Deleted records for {target}. Backup: {backup_path.name}. "
        f"Removed {deleted.get('requests', 0)} requests, "
        f"{deleted.get('nmap_scans', 0)} Nmap scans, "
        f"{deleted.get('firewall_scans', 0)} Firewall scans, "
        f"{deleted.get('ports', 0)} ports, "
        f"{deleted.get('findings', 0)} findings, and "
        f"{deleted.get('risks', 0)} risks. "
        "Custom rules were preserved.",
        "success",
    )
    return redirect(url_for("records_management_page"))


@app.route("/records/delete-all", methods=["POST"])
def delete_all_database_records():
    if request.form.get("confirm_all") != "DELETE ALL":
        flash('Type DELETE ALL exactly to confirm clearing the database.', "error")
        return redirect(url_for("records_management_page"))

    backup_path = create_records_backup()

    # These are all seven application tables found in the inspected database.
    tables = (
        "iso_control_reviews",
        "nmap_ports",
        "draft_findings",
        "risk_assessments",
        "nmap_scans",
        "firewall_scans",
        "scans",
        "custom_rules",
    )

    deleted = {}
    with get_db() as db:
        for table in tables:
            deleted[table] = db.execute(
                f'DELETE FROM "{table}"'
            ).rowcount

        # Reset IDs too, while preserving the tables and their schema.
        db.execute("""
            DELETE FROM sqlite_sequence
            WHERE name IN (
                'iso_control_reviews', 'nmap_ports', 'draft_findings',
                'risk_assessments', 'nmap_scans', 'firewall_scans',
                'scans', 'custom_rules'
            )
        """)

    total = sum(max(0, count) for count in deleted.values())
    flash(
        f"Database records cleared: {total} rows across {len(tables)} tables. "
        f"Backup saved as {backup_path.name}. "
        "The database schema and application files were preserved.",
        "success",
    )
    return redirect(url_for("records_management_page"))



init_risk_db()
initialize_iso_control_reviews()


# ---------------------------------------------------------------------------
# /api/zap-status — placeholder endpoint for the unified-scan ZAP progress bar
# ---------------------------------------------------------------------------
# templates/unified_scan.html polls this endpoint expecting:
#   { "running": bool, "ascan": int (0-100), "spider": int (0-100) }
#
# Full scan-progress tracking has NOT yet been implemented. The existing
# scanner.zap_sync_worker.get_sync_status() reports *alert sync* status, not
# scan progress, so it cannot be reused here. Until ZAP-into-Unified-Scan
# progress tracking is built, always return an idle snapshot so the bar
# simply stays hidden.
@app.route("/api/zap-status")
def api_zap_status():
    from scanner.zap_proxy import get_zap_scan_progress
    try:
        return jsonify(get_zap_scan_progress())
    except Exception:
        return jsonify({"running": False, "ascan": 0, "spider": 0})


@app.route("/api/zap-stop", methods=["POST"])
def api_zap_stop():
    from scanner.zap_proxy import stop_zap_scans
    try:
        result = stop_zap_scans()
        return jsonify({"ok": True, "detail": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


_SCAN_WORKERS = set()
_SCAN_WORKERS_LOCK = threading.Lock()
_SHUTDOWN_STARTED = False


def _tracked_worker_entry(target, args):
    try:
        target(*args)
    finally:
        with _SCAN_WORKERS_LOCK:
            _SCAN_WORKERS.discard(threading.current_thread())


def _start_tracked_worker(target, args=(), name=None):
    with _SCAN_WORKERS_LOCK:
        if _SHUTDOWN_STARTED:
            raise RuntimeError("Shadow Map GRC is shutting down; new scans are disabled.")
        worker = threading.Thread(
            target=_tracked_worker_entry,
            args=(target, args),
            daemon=True,
            name=name,
        )
        _SCAN_WORKERS.add(worker)

    try:
        worker.start()
    except Exception:
        with _SCAN_WORKERS_LOCK:
            _SCAN_WORKERS.discard(worker)
        raise

    return worker


def shutdown_application():
    """Stop only background work and processes owned by this app instance."""
    global _SHUTDOWN_STARTED

    with _SCAN_WORKERS_LOCK:
        if _SHUTDOWN_STARTED:
            return
        _SHUTDOWN_STARTED = True
        workers = list(_SCAN_WORKERS)

    app.logger.info("Shadow Map GRC shutdown started")

    for stop_fn in (
        stop_zap_sync_worker,
        stop_vulnerability_monitor_worker,
        stop_attack_catalogue_worker,
    ):
        try:
            stop_fn(timeout=2)
        except Exception:
            app.logger.exception("Recurring worker shutdown failed")

    try:
        try:
            stop_ping()
        except Exception as exc:
            if "There is no active Live Ping session." not in str(exc):
                raise
        shutdown_ping(timeout=4)
    except Exception:
        app.logger.exception("Live Ping shutdown failed")

    try:
        shutdown_active_nmap_processes(grace_seconds=2)
    except Exception:
        app.logger.exception("Managed Nmap shutdown failed")

    deadline = time.monotonic() + 8
    for worker in workers:
        if worker is threading.current_thread():
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        worker.join(remaining)

    try:
        shutdown_managed_zap(grace_seconds=5)
    except Exception:
        app.logger.exception("Managed ZAP shutdown failed")

    app.logger.info("Shadow Map GRC shutdown sequence finished")


def _handle_shutdown_signal(signum, _frame):
    raise SystemExit(128 + int(signum))


if __name__ == "__main__":
    for signal_name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"):
        signal_value = getattr(signal, signal_name, None)
        if signal_value is not None:
            try:
                signal.signal(signal_value, _handle_shutdown_signal)
            except (OSError, ValueError):
                pass

    atexit.register(shutdown_application)
    try:
        start_worker()
        start_vulnerability_monitor_worker()
        start_attack_catalogue_worker()
        app.run(host=HOST, port=PORT, debug=False)
    finally:
        shutdown_application()
