import csv
import io
import sqlite3
import re
from datetime import datetime, timezone

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, abort, Response
)

from config import DATABASE_PATH, SECRET_KEY, HOST, PORT
from scanner.nmap_scanner import run_nmap, NmapError, validate_target
from grc.automatic_risks import automatic_risks_bp, generate_nmap_drafts, generate_web_security_drafts
from scanner.web_security_scanner import scan_web_security, WebSecurityError
from scanner.threat_intel import lookup_ip, ThreatIntelError

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.register_blueprint(automatic_risks_bp)

NAV_ITEMS = [
    {"endpoint": "dashboard", "label": "Dashboard", "icon": "⌂"},
    {"endpoint": "nmap_page", "label": "Nmap", "icon": "⌘"},
    {"endpoint": "web_security_page", "label": "Web Security", "icon": "◎"},
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
                FOREIGN KEY (request_id) REFERENCES scans(id)
            )
        """)

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

    return render_template(
        "index.html",
        nav_items=NAV_ITEMS,
        active_page="dashboard",
        scans=get_recent_scans(10),
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

    started_at = now_utc()

    # Save the request and scan record before executing Nmap.
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

    try:
        scan_result = run_nmap(
            target,
            scan_profile=request.form.get("scan_profile", "all_ports"),
        )

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
                    xml_output = ?, error = NULL
                WHERE id = ?
                """,
                (
                    "Completed",
                    scan_result["host_state"],
                    now_utc(),
                    scan_result["duration_seconds"],
                    scan_result["command_display"],
                    scan_result["xml_output"],
                    scan_id,
                ),
            )

            db.execute(
                "UPDATE scans SET status = ? WHERE id = ?",
                ("Completed", request_id),
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

        flash(f"Nmap scan failed: {exc}", "error")
        return redirect(url_for("nmap_results", scan_id=scan_id))

    except Exception:
        app.logger.exception("Unexpected error while saving Nmap results")
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

        flash("An unexpected error occurred while saving scan results.", "error")
        return redirect(url_for("nmap_results", scan_id=scan_id))

    return redirect(url_for("nmap_results", scan_id=scan_id))


@app.route("/nmap/results/<int:scan_id>")
def nmap_results(scan_id):
    # Idempotently generate draft observations from this completed scan.
    generate_nmap_drafts(scan_id)
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


@app.route("/web-security", methods=["GET", "POST"])
def web_security_page():
    result = None
    error = None
    target = ""

    if request.method == "POST":
        target = (request.form.get("target") or "").strip()

        if request.form.get("authorized") != "yes":
            error = "Confirm that you own the website or have permission to assess it."
        else:
            try:
                result = scan_web_security(target)
                generate_web_security_drafts(result)
            except WebSecurityError as exc:
                error = str(exc)

    return render_template(
        "web_security.html",
        nav_items=NAV_ITEMS,
        active_page="web_security_page",
        target=target,
        result=result,
        error=error,
    )


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
    allowed_sources = {"all", "nmap", "web_security"}
    allowed_statuses = {"all", "Draft", "Approved", "Dismissed"}

    selected_source = request.args.get("source", "all").strip().lower()
    selected_status = request.args.get("status", "all").strip()
    search_query = request.args.get("q", "").strip()[:200]
    requested_hosts = request.args.getlist("host")[:100]

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

    if search_query:
        conditions.append("(target LIKE ? OR title LIKE ?)")
        pattern = "%" + search_query + "%"
        parameters.extend([pattern, pattern])

    with get_db() as db:
        target_rows = db.execute("""
            SELECT target FROM draft_findings
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT target FROM nmap_scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            UNION
            SELECT target FROM scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            ORDER BY target COLLATE NOCASE
        """).fetchall()

        available_targets = [row["target"] for row in target_rows]
        targets_by_key = {
            target.strip().casefold(): target
            for target in available_targets
        }

        # Accept only targets that actually exist in saved scan records.
        selected_hosts = list(dict.fromkeys(
            targets_by_key[value.strip().casefold()]
            for value in requested_hosts
            if value.strip().casefold() in targets_by_key
        ))

        if selected_hosts:
            placeholders = ", ".join("?" for _ in selected_hosts)
            conditions.append(
                f"LOWER(TRIM(target)) IN ({placeholders})"
            )
            parameters.extend(target.casefold() for target in selected_hosts)

        where_clause = (
            " WHERE " + " AND ".join(conditions)
            if conditions else ""
        )

        findings = db.execute(
            "SELECT id, source, source_record_id, target, title, "
            "description, evidence, suggested_severity, confidence, "
            "recommendation, iso_controls, status, risk_id, created_at "
            "FROM draft_findings"
            + where_clause
            + " ORDER BY CASE status "
              "WHEN 'Draft' THEN 0 WHEN 'Approved' THEN 1 "
              "WHEN 'Dismissed' THEN 2 ELSE 3 END, id DESC",
            parameters,
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
        source_counts=source_counts,
        status_counts=status_counts,
        selected_source=selected_source,
        selected_status=selected_status,
        search_query=search_query,
        available_targets=available_targets,
        selected_hosts=selected_hosts,
    )


@app.route("/reports")
def reports_page():
    today_date = datetime.now().date().isoformat()
    valid_sections = {"findings", "risks"}
    filter_applied = request.args.get("target_filter") == "1"

    with get_db() as db:
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
            SELECT target AS target FROM scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            ORDER BY target
        """).fetchall()
        available_targets = [row["target"] for row in target_rows]

        if not filter_applied or request.args.get("all_targets") == "1":
            selected_targets = list(available_targets)
            all_targets_selected = True
        else:
            requested_targets = request.args.getlist("target")
            selected_targets = [
                target for target in available_targets
                if target in requested_targets
            ]
            all_targets_selected = False

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

        if selected_targets:
            placeholders = ",".join("?" for _ in selected_targets)
            target_params = list(selected_targets)

            findings = db.execute(f"""
                SELECT
                    f.id, f.source, f.target, f.title, f.description,
                    f.evidence, f.suggested_severity, f.confidence,
                    f.recommendation, f.iso_controls, f.status,
                    f.risk_id, f.created_at,
                    r.title AS linked_risk_title,
                    r.residual_score AS linked_residual_score,
                    r.residual_level AS linked_residual_level
                FROM draft_findings f
                LEFT JOIN risk_assessments r ON r.id = f.risk_id
                WHERE f.target IN ({placeholders})
                ORDER BY
                    CASE f.status
                        WHEN 'Draft' THEN 1
                        WHEN 'Approved' THEN 2
                        ELSE 3
                    END,
                    f.id DESC
            """, target_params).fetchall()

            # Include risks that match the selected asset OR are linked to
            # findings for a selected target.
            risks = db.execute(f"""
                SELECT DISTINCT
                    r.id, r.title, r.asset, r.category, r.evidence,
                    r.business_impact, r.owner, r.inherent_score,
                    r.inherent_level, r.residual_score, r.residual_level,
                    r.treatment, r.iso_controls, r.status, r.due_date
                FROM risk_assessments r
                WHERE r.asset IN ({placeholders})
                   OR r.id IN (
                       SELECT f.risk_id
                       FROM draft_findings f
                       WHERE f.target IN ({placeholders})
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
            """, target_params + target_params).fetchall()
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
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        available_targets=available_targets,
        selected_targets=selected_targets,
        all_targets_selected=all_targets_selected,
        selected_sections=selected_sections,
        show_findings=show_findings,
        show_risks=show_risks,
        filter_applied=filter_applied,
    )

@app.route("/reports/export.csv")
def export_reports_csv():
    """Export the currently selected report findings and risks as CSV."""
    valid_sections = {"findings", "risks"}
    filter_applied = request.args.get("target_filter") == "1"

    with get_db() as db:
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
            SELECT target AS target FROM scans
            WHERE target IS NOT NULL AND TRIM(target) != ''
            ORDER BY target
        """).fetchall()
        available_targets = [row["target"] for row in target_rows]

        if not filter_applied or request.args.get("all_targets") == "1":
            selected_targets = list(available_targets)
        else:
            requested_targets = request.args.getlist("target")
            selected_targets = [
                target for target in available_targets
                if target in requested_targets
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

        if selected_targets:
            placeholders = ",".join("?" for _ in selected_targets)
            target_params = list(selected_targets)

            if "findings" in selected_sections:
                findings = db.execute(f"""
                    SELECT
                        f.id, f.source, f.target, f.title, f.description,
                        f.evidence, f.suggested_severity, f.confidence,
                        f.recommendation, f.iso_controls, f.status,
                        f.risk_id, f.created_at,
                        r.title AS linked_risk_title,
                        r.residual_score AS linked_residual_score,
                        r.residual_level AS linked_residual_level
                    FROM draft_findings f
                    LEFT JOIN risk_assessments r ON r.id = f.risk_id
                    WHERE f.target IN ({placeholders})
                    ORDER BY f.id DESC
                """, target_params).fetchall()

            if "risks" in selected_sections:
                risks = db.execute(f"""
                    SELECT DISTINCT
                        r.id, r.title, r.asset, r.category, r.evidence,
                        r.business_impact, r.owner, r.inherent_score,
                        r.inherent_level, r.residual_score, r.residual_level,
                        r.treatment, r.iso_controls, r.status, r.due_date
                    FROM risk_assessments r
                    WHERE r.asset IN ({placeholders})
                       OR r.id IN (
                           SELECT f.risk_id
                           FROM draft_findings f
                           WHERE f.target IN ({placeholders})
                             AND f.risk_id IS NOT NULL
                       )
                    ORDER BY r.id DESC
                """, target_params + target_params).fetchall()

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
        "Record Type", "Record ID", "Target / Asset", "Source", "Title",
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


def current_iso_control_reviews():
    """Return review rows only when their mapping still exists in the source."""
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
            source_by_id = {row["id"]: row for row in records}

            reviews = db.execute("""
                SELECT * FROM iso_control_reviews
                WHERE record_type = ?
                ORDER BY record_id, control_code
            """, (record_type,)).fetchall()

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

    return results


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
        target_options = [row["value"] for row in targets]

        if target_filter != "All" and target_filter not in target_options:
            target_filter = "All"

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
        finding_links = [
            row for row in finding_links if row["target"] == target_filter
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
        and (target_filter == "All" or row["asset"] == target_filter)
    ]

    # For the unlinked-risk table, identify risks with no finding reference.
    all_finding_risk_ids = {
        row["risk_id"] for row in finding_rows if row["risk_id"] is not None
    }
    risks_without_findings = [
        row for row in all_risks
        if row["id"] not in all_finding_risk_ids
        and (target_filter == "All" or row["asset"] == target_filter)
    ]
    if link_filter == "Linked":
        risks_without_findings = []
    broken_links = [
        row for row in finding_links
        if row["risk_id"] is not None and row["risk_title"] is None
    ]

    # Counts reflect the current finding filters.
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
        control_reviews=current_iso_control_reviews(),
    )

@app.route("/history")
def history_page():
    with get_db() as db:
        nmap_scans = db.execute("""
            SELECT
                s.*,
                (SELECT COUNT(*)
                 FROM nmap_ports p
                 WHERE p.scan_id = s.id AND p.state = 'open') AS open_ports,
                (SELECT COUNT(*)
                 FROM draft_findings f
                 WHERE f.source = 'nmap'
                   AND CAST(f.source_record_id AS INTEGER) = s.id) AS finding_count,
                (SELECT COUNT(*)
                 FROM draft_findings f
                 WHERE f.source = 'nmap'
                   AND f.source_record_id = s.id
                   AND f.status = 'Approved') AS approved_count
            FROM nmap_scans s
            ORDER BY s.id DESC
        """).fetchall()

        saved_requests = db.execute("""
            SELECT * FROM scans ORDER BY id DESC LIMIT 100
        """).fetchall()

    return render_template(
        "scan_history.html",
        nav_items=NAV_ITEMS,
        active_page="history_page",
        nmap_scans=nmap_scans,
        saved_requests=saved_requests,
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


def list_record_targets(db):
    """Return targets recorded by scans, findings, Nmap, or risk assessments."""
    rows = db.execute("""
        SELECT target AS value FROM scans
        UNION
        SELECT target AS value FROM nmap_scans
        UNION
        SELECT target AS value FROM draft_findings
        UNION
        SELECT asset AS value FROM risk_assessments
    """).fetchall()
    return sorted(
        {row["value"].strip() for row in rows if row["value"] and row["value"].strip()},
        key=str.casefold,
    )


@app.route("/records", methods=["GET"])
def records_management_page():
    with get_db() as db:
        targets = list_record_targets(db)
        counts = {}
        for table in (
            "custom_rules", "scans", "nmap_scans", "nmap_ports",
            "draft_findings", "risk_assessments", "iso_control_reviews",
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

    if not target:
        flash("Select a target before deleting its records.", "error")
        return redirect(url_for("records_management_page"))

    backup_path = create_records_backup()
    deleted = {}

    with get_db() as db:
        # Find Nmap scans and requests belonging to this target.
        nmap_rows = db.execute("""
            SELECT id, request_id FROM nmap_scans
            WHERE lower(trim(target)) = lower(trim(?))
        """, (target,)).fetchall()
        nmap_ids = [row["id"] for row in nmap_rows]
        request_ids = {
            row["request_id"] for row in nmap_rows
            if row["request_id"] is not None
        }

        # Also include findings created from these Nmap scan IDs.
        finding_ids = {
            row["id"] for row in db.execute("""
                SELECT id FROM draft_findings
                WHERE lower(trim(target)) = lower(trim(?))
            """, (target,)).fetchall()
        }
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

        # Candidate risks are only removed when their asset matches this target.
        risk_ids = {
            row["id"] for row in db.execute("""
                SELECT id FROM risk_assessments
                WHERE lower(trim(asset)) = lower(trim(?))
            """, (target,)).fetchall()
        }

        # Remove ISO reviews before deleting their associated findings.
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

        # Remove matching saved requests only when no Nmap scan still references them.
        deleted["requests"] = db.execute("""
            DELETE FROM scans
            WHERE lower(trim(target)) = lower(trim(?))
              AND NOT EXISTS (
                  SELECT 1 FROM nmap_scans
                  WHERE nmap_scans.request_id = scans.id
              )
        """, (target,)).rowcount

        # Reviews for deleted records are removed above. Keep unrelated records.
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
                'risk_assessments', 'nmap_scans', 'scans', 'custom_rules'
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


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False)
