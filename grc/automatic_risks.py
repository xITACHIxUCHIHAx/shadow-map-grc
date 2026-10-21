import hashlib
import sqlite3
from datetime import datetime, timezone

from flask import (
    Blueprint, abort, current_app, flash, redirect,
    render_template, request, url_for
)

from config import DATABASE_PATH

automatic_risks_bp = Blueprint("automatic_risks", __name__)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect_db():
    db = sqlite3.connect(DATABASE_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    return db


def risk_level(score):
    if score <= 4:
        return "Low"
    if score <= 9:
        return "Medium"
    if score <= 16:
        return "High"
    return "Critical"


def initialize_automatic_risks():
    with connect_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS draft_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                source_record_id INTEGER,
                fingerprint TEXT NOT NULL UNIQUE,
                target TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL DEFAULT '',
                suggested_severity TEXT NOT NULL DEFAULT 'Review',
                confidence TEXT NOT NULL DEFAULT 'Low',
                recommendation TEXT NOT NULL DEFAULT '',
                iso_controls TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'Draft',
                risk_id INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_draft_findings_status
            ON draft_findings(status, created_at)
        """)
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


def get_nav_items():
    available = current_app.view_functions
    candidates = [
        ("dashboard", "Dashboard", "⌂"),
        ("nmap_page", "Nmap", "⌘"),
        ("web_security_page", "Web Security", "◎"),
        ("threat_intel_page", "Threat Intelligence", "◈"),
        ("custom_rules_page", "Custom Rules", "⚙"),
        ("combined_findings_page", "Combined Findings", "▤"),
        ("traceability_page", "Traceability", "↔"),
        ("automatic_risks.findings_page", "Findings Review", "✓"),
        ("reports_page", "Reports & GRC", "▧"),
        ("history_page", "Scan History", "◷"),
        ("risk_register_page", "Risk Register", "⚑"),
    ]
    return [
        {"endpoint": endpoint, "label": label, "icon": icon}
        for endpoint, label, icon in candidates
        if endpoint in available
    ]



def service_recommendation(port_number, service_name):
    """Return practical remediation guidance for a detected service."""
    service = (service_name or "").lower()
    try:
        port = int(port_number)
    except (TypeError, ValueError):
        port = 0

    if port == 21 or "ftp" in service:
        return (
            "Check whether FTP is required; prefer SFTP or FTPS for "
            "encrypted transfers; disable anonymous access if unnecessary; "
            "restrict access to trusted networks and review account permissions."
        )
    if port == 22 or "ssh" in service:
        return (
            "Restrict SSH to approved source networks; prefer key-based "
            "authentication where suitable; disable unused accounts and "
            "review password-login and privileged-access settings."
        )
    if port == 23 or "telnet" in service:
        return (
            "Verify whether Telnet is required; replace it with SSH where "
            "possible because Telnet does not encrypt sessions; restrict "
            "network access until it can be disabled or replaced."
        )
    if port in (25, 465, 587) or "smtp" in service or "mail" in service:
        return (
            "Review mail-server exposure and relay restrictions; require "
            "authentication for message submission; configure TLS where "
            "supported and verify that the server is not an open relay."
        )
    if port == 53 or "dns" in service:
        return (
            "Confirm whether the DNS service must be publicly reachable; "
            "restrict zone transfers to authorized servers; review recursion "
            "settings and keep DNS software supported and updated."
        )
    if port in (80, 8080, 8000) or service in ("http", "http-proxy"):
        return (
            "Identify the hosted application; remove default pages and "
            "unneeded endpoints; update the web server and application; "
            "use HTTPS for sensitive traffic and restrict administrative routes."
        )
    if port in (443, 8443) or "https" in service or "ssl" in service:
        return (
            "Review TLS certificates, protocol versions and cipher settings; "
            "update the web server and application; check for exposed "
            "administrative endpoints and unnecessary public content."
        )
    if port in (139, 445) or "smb" in service or "netbios" in service:
        return (
            "Restrict SMB/NetBIOS to trusted internal networks; disable "
            "unneeded file sharing and SMBv1; review share permissions and "
            "guest access, and apply supported security updates."
        )
    if port == 161 or "snmp" in service:
        return (
            "Restrict SNMP to authorized management hosts; prefer SNMPv3 "
            "with authentication and privacy; replace default community "
            "strings and disable SNMP if it is not required."
        )
    if port == 3306 or "mysql" in service or "mariadb" in service:
        return (
            "Keep the database off public networks unless explicitly required; "
            "allow access only from approved application hosts; review account "
            "privileges, authentication and software updates."
        )
    if port == 5432 or "postgres" in service:
        return (
            "Restrict database access to approved application hosts; review "
            "authentication and role privileges; avoid public exposure and "
            "apply supported PostgreSQL security updates."
        )
    if port == 3389 or "ms-wbt" in service or "rdp" in service:
        return (
            "Restrict Remote Desktop to trusted networks or a VPN; require "
            "strong authentication and Network Level Authentication where "
            "supported; review account access and security updates."
        )
    if port == 6379 or "redis" in service:
        return (
            "Keep Redis on trusted networks; bind it only to required "
            "interfaces; configure authentication and access controls, "
            "and never expose an unauthenticated instance publicly."
        )
    if port == 27017 or "mongodb" in service or "mongo" in service:
        return (
            "Restrict MongoDB to approved application hosts; enable "
            "authentication and least-privilege roles; verify network "
            "binding and supported software updates."
        )

    label = service_name or "unknown service"
    return (
        f"Identify and verify the purpose of {label} on port {port}; "
        "check vendor security guidance and the supported version; restrict "
        "access to approved networks where appropriate and disable the "
        "service if it is not needed."
    )


def generate_nmap_drafts(scan_id):
    """Create reviewable observations from open TCP ports, not confirmed vulns."""
    with connect_db() as db:
        scan = db.execute(
            "SELECT id, target, status FROM nmap_scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

        if scan is None or scan["status"] != "Completed":
            return 0

        ports = db.execute("""
            SELECT port, protocol, state, service, product, version,
                   extra_info, reason
            FROM nmap_ports
            WHERE scan_id = ?
            ORDER BY protocol, port
        """, (scan_id,)).fetchall()

        created = 0
        for port in ports:
            # An open port is an exposure observation, not proof of a flaw.
            if port["state"] != "open":
                continue

            service_label = port["service"] or "unknown service"
            version_label = " ".join(
                value for value in (port["product"], port["version"])
                if value
            )
            if version_label:
                service_label += " (" + version_label + ")"

            title = (
                f"Review exposed {port['protocol'].upper()} "
                f"port {port['port']} on {scan['target']}"
            )
            evidence = (
                f"Nmap scan #{scan_id}; target={scan['target']}; "
                f"protocol={port['protocol']}; port={port['port']}; "
                f"state=open; service={service_label}; "
                f"reason={port['reason'] or 'not reported'}"
            )
            fingerprint_source = (
                f"nmap|{scan['target']}|{port['protocol']}|{port['port']}"
            )
            fingerprint = hashlib.sha256(
                fingerprint_source.encode("utf-8")
            ).hexdigest()

            description = (
                "Nmap reported this port as open. This is an exposure "
                "observation only; it does not establish that the service "
                "is vulnerable or improperly configured. Confirm that the "
                "service is required, identify its owner, and assess whether "
                "network access is appropriate."
            )
            recommendation = service_recommendation(
                port["port"], port["service"]
            )

            cursor = db.execute("""
                INSERT OR IGNORE INTO draft_findings (
                    source, source_record_id, fingerprint, target, title,
                    description, evidence, suggested_severity, confidence,
                    recommendation, iso_controls, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Draft', ?, ?)
            """, (
                "nmap", scan_id, fingerprint, scan["target"], title,
                description, evidence, "Review", "Low", recommendation,
                "A.8.20, A.8.21", utc_now(), utc_now(),
            ))
            created += cursor.rowcount

        return created


@automatic_risks_bp.route("/findings")
def findings_page():
    initialize_automatic_risks()

    status_filter = request.args.get("status", "Draft")
    allowed_statuses = {"Draft", "Approved", "Dismissed", "All"}
    if status_filter not in allowed_statuses:
        status_filter = "Draft"

    source_filter = request.args.get("source", "all")
    allowed_sources = {"all", "nmap", "web_security"}
    if source_filter not in allowed_sources:
        source_filter = "all"

    search_query = (request.args.get("q") or "").strip()[:200]
    requested_hosts = request.args.getlist("host")[:100]

    with connect_db() as db:
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

        available_targets = []
        targets_by_key = {}
        for row in target_rows:
            target = (row["target"] or "").strip()
            key = target.casefold()
            if target and key not in targets_by_key:
                targets_by_key[key] = target
                available_targets.append(target)

        selected_hosts = []
        seen_hosts = set()
        for requested in requested_hosts:
            key = requested.strip().casefold()
            if key in targets_by_key and key not in seen_hosts:
                selected_hosts.append(targets_by_key[key])
                seen_hosts.add(key)

        conditions = []
        params = []

        if status_filter != "All":
            conditions.append("status = ?")
            params.append(status_filter)

        if source_filter != "all":
            conditions.append("source = ?")
            params.append(source_filter)

        if selected_hosts:
            placeholders = ",".join("?" for _ in selected_hosts)
            conditions.append(
                f"LOWER(TRIM(target)) IN ({placeholders})"
            )
            params.extend(target.casefold() for target in selected_hosts)

        if search_query:
            conditions.append("(target LIKE ? OR title LIKE ?)")
            pattern = f"%{search_query}%"
            params.extend([pattern, pattern])

        where_clause = (
            "WHERE " + " AND ".join(conditions)
            if conditions else ""
        )

        findings = db.execute(
            f"""
                SELECT * FROM draft_findings
                {where_clause}
                ORDER BY id DESC LIMIT 500
            """,
            params,
        ).fetchall()

        counts = {
            "Draft": db.execute(
                "SELECT COUNT(*) FROM draft_findings WHERE status='Draft'"
            ).fetchone()[0],
            "Approved": db.execute(
                "SELECT COUNT(*) FROM draft_findings WHERE status='Approved'"
            ).fetchone()[0],
            "Dismissed": db.execute(
                "SELECT COUNT(*) FROM draft_findings WHERE status='Dismissed'"
            ).fetchone()[0],
        }

    return render_template(
        "findings.html",
        nav_items=get_nav_items(),
        active_page="automatic_risks.findings_page",
        findings=findings,
        counts=counts,
        status_filter=status_filter,
        source_filter=source_filter,
        search_query=search_query,
        available_targets=available_targets,
        selected_hosts=selected_hosts,
    )


@automatic_risks_bp.route("/findings/generate/nmap/<int:scan_id>", methods=["POST"])
def generate_for_scan(scan_id):
    initialize_automatic_risks()
    with connect_db() as db:
        exists = db.execute(
            "SELECT id FROM nmap_scans WHERE id = ? AND status = 'Completed'",
            (scan_id,),
        ).fetchone()
    if exists is None:
        abort(404)

    created = generate_nmap_drafts(scan_id)
    flash(f"Generated {created} new draft finding(s). Existing findings were not duplicated.", "success")
    return redirect(url_for("automatic_risks.findings_page"))


@automatic_risks_bp.route("/findings/<int:finding_id>/approve", methods=["POST"])
def approve_finding(finding_id):
    initialize_automatic_risks()

    try:
        likelihood = int(request.form.get("likelihood", ""))
        impact = int(request.form.get("impact", ""))
    except (TypeError, ValueError):
        flash("Select valid likelihood and impact scores.", "error")
        return redirect(url_for("automatic_risks.findings_page"))

    if likelihood not in range(1, 6) or impact not in range(1, 6):
        flash("Likelihood and impact must each be between 1 and 5.", "error")
        return redirect(url_for("automatic_risks.findings_page"))

    with connect_db() as db:
        # Serialize approval checks and writes to prevent concurrent approvals.
        db.execute("BEGIN IMMEDIATE")
        finding = db.execute(
            "SELECT * FROM draft_findings WHERE id = ?",
            (finding_id,),
        ).fetchone()
        if finding is None:
            abort(404)
        if finding["status"] != "Draft":
            flash("Only draft findings can be approved.", "error")
            return redirect(url_for("automatic_risks.findings_page"))

        now = utc_now()
        score = likelihood * impact

        # Do not assume that proposed remediation has already reduced risk.
        # Residual score starts equal to inherent score for human reassessment.
        cursor = db.execute("""
            INSERT INTO risk_assessments (
                title, description, asset, category, evidence,
                business_impact, owner, inherent_likelihood, inherent_impact,
                inherent_score, inherent_level, residual_likelihood,
                residual_impact, residual_score, residual_level, treatment,
                iso_controls, status, due_date, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding["title"],
            finding["description"],
            finding["target"],
            "Technical Security" if finding["source"] == "nmap" else "General",
            finding["evidence"],
            "Potential business impact must be assessed by the asset or risk owner.",
            "",
            likelihood, impact, score, risk_level(score),
            likelihood, impact, score, risk_level(score),
            finding["recommendation"], finding["iso_controls"],
            "Open", "", now, now,
        ))
        risk_id = cursor.lastrowid
        updated = db.execute("""
            UPDATE draft_findings
            SET status = 'Approved', risk_id = ?, updated_at = ?
            WHERE id = ? AND status = 'Draft'
        """, (risk_id, now, finding_id))

        if updated.rowcount != 1:
            # Roll back the risk insertion too if the finding was not updated.
            db.rollback()
            flash("This finding was already reviewed. No new risk was saved.", "error")
            return redirect(url_for("automatic_risks.findings_page"))

    flash(f"Finding approved and added to the risk register as risk #{risk_id}.", "success")
    return redirect(url_for("automatic_risks.findings_page", status="Approved"))



@automatic_risks_bp.route("/findings/bulk-approve", methods=["POST"])
def bulk_approve_findings():
    """Approve selected drafts or all pending drafts atomically."""
    initialize_automatic_risks()

    try:
        likelihood = int(request.form.get("likelihood", "3"))
        impact = int(request.form.get("impact", "3"))
    except (TypeError, ValueError):
        flash("Likelihood and impact must be valid numbers.", "error")
        return redirect(url_for("automatic_risks.findings_page"))

    if likelihood not in range(1, 6) or impact not in range(1, 6):
        flash("Likelihood and impact must each be between 1 and 5.", "error")
        return redirect(url_for("automatic_risks.findings_page"))

    approve_all = request.form.get("action") == "all"
    selected_ids = []

    if not approve_all:
        for value in request.form.getlist("finding_ids"):
            try:
                finding_id = int(value)
                if finding_id > 0:
                    selected_ids.append(finding_id)
            except (TypeError, ValueError):
                continue

        selected_ids = list(dict.fromkeys(selected_ids))
        if not selected_ids:
            flash("Select at least one draft finding first.", "error")
            return redirect(url_for("automatic_risks.findings_page"))

    score = likelihood * impact
    level = risk_level(score)
    now = utc_now()
    approved_count = 0

    try:
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")

            if approve_all:
                findings = db.execute("""
                    SELECT * FROM draft_findings
                    WHERE status = 'Draft'
                    ORDER BY id
                """).fetchall()
            else:
                placeholders = ",".join("?" for _ in selected_ids)
                findings = db.execute(
                    f"""
                    SELECT * FROM draft_findings
                    WHERE status = 'Draft' AND id IN ({placeholders})
                    ORDER BY id
                    """,
                    selected_ids,
                ).fetchall()

            for finding in findings:
                cursor = db.execute("""
                    INSERT INTO risk_assessments (
                        title, description, asset, category, evidence,
                        business_impact, owner, inherent_likelihood,
                        inherent_impact, inherent_score, inherent_level,
                        residual_likelihood, residual_impact, residual_score,
                        residual_level, treatment, iso_controls, status,
                        due_date, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    finding["title"],
                    finding["description"],
                    finding["target"],
                    "Technical Security" if finding["source"] == "nmap" else "General",
                    finding["evidence"],
                    "Potential business impact must be assessed by the asset or risk owner.",
                    "",
                    likelihood, impact, score, level,
                    likelihood, impact, score, level,
                    finding["recommendation"], finding["iso_controls"],
                    "Open", "", now, now,
                ))

                risk_id = cursor.lastrowid
                updated = db.execute("""
                    UPDATE draft_findings
                    SET status = 'Approved', risk_id = ?, updated_at = ?
                    WHERE id = ? AND status = 'Draft'
                """, (risk_id, now, finding["id"]))

                if updated.rowcount != 1:
                    raise sqlite3.IntegrityError(
                        "Finding status changed during bulk approval."
                    )
                approved_count += 1

        if approved_count:
            flash(
                f"Approved {approved_count} finding(s) and added them to the Risk Register. "
                f"Likelihood: {likelihood}/5; impact: {impact}/5. Review these provisional scores.",
                "success",
            )
        else:
            flash("No pending drafts were approved. They may already have been reviewed.", "error")

    except sqlite3.Error:
        current_app.logger.exception("Bulk approval failed; database transaction rolled back.")
        flash("Bulk approval failed. No partial batch was saved; check the application log.", "error")

    return redirect(url_for("automatic_risks.findings_page", status="Approved"))


@automatic_risks_bp.route("/findings/<int:finding_id>/dismiss", methods=["POST"])
def dismiss_finding(finding_id):
    initialize_automatic_risks()
    with connect_db() as db:
        result = db.execute("""
            UPDATE draft_findings SET status='Dismissed', updated_at=?
            WHERE id=? AND status='Draft'
        """, (utc_now(), finding_id))
        if result.rowcount == 0:
            abort(404)

    flash("Draft finding dismissed.", "success")
    return redirect(url_for("automatic_risks.findings_page"))


initialize_automatic_risks()

def generate_web_security_drafts(result):
    """Create deduplicated, review-only HTTPS configuration observations."""
    target = (result.get("target") or "").strip()
    if not target:
        return 0

    status_code = result.get("status_code", "unknown")
    created = 0

    with connect_db() as db:
        for header in result.get("headers", []):
            if not header.get("issue", not header.get("present")):
                continue

            header_name = (header.get("header") or "").strip().lower()
            display_name = (header.get("name") or header_name).strip()
            if not header_name:
                continue

            present = bool(header.get("present"))
            issue_type = "value-review" if present else "missing"

            # Preserve the existing fingerprint for missing-header findings.
            fingerprint_source = (
                f"web_security|{target.rstrip('/').lower()}|{header_name}"
                if not present else
                f"web_security|{target.rstrip('/').lower()}|{header_name}|{issue_type}"
            )
            fingerprint = hashlib.sha256(
                fingerprint_source.encode("utf-8")
            ).hexdigest()

            assessment = header.get("assessment", "Review configuration")
            title = (
                f"Review {display_name} configuration on {target}"
                if present else
                f"Review missing {display_name} on {target}"
            )
            description = (
                f"The HTTPS response header {display_name} was observed, "
                f"but its value triggered this basic check: {assessment}. "
                "This is a preliminary configuration observation, not proof "
                "of an exploitable vulnerability. Validate the full header "
                "syntax and application requirements before deciding on action."
                if present else
                f"The HTTPS response did not include the {display_name} "
                "header. This is a configuration observation, not proof "
                "of an exploitable vulnerability. Review the site's "
                "architecture and compatibility requirements."
            )
            evidence = (
                f"Source: authorized HTTPS check; target={target}; "
                f"HTTP status={status_code}; header={header_name}; "
                f"observed={'present' if present else 'missing'}; "
                f"value={header.get('value', '')}; assessment={assessment}"
            )
            recommendation = (
                f"Validate the {display_name} value against the relevant "
                "browser and server specifications, test any proposed "
                "change, and document the decision and exceptions."
            )

            cursor = db.execute("""
                INSERT OR IGNORE INTO draft_findings (
                    source, source_record_id, fingerprint, target, title,
                    description, evidence, suggested_severity, confidence,
                    recommendation, iso_controls, status, created_at, updated_at
                ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Draft', ?, ?)
            """, (
                "web_security", fingerprint, target, title, description,
                evidence, "Review", "Low", recommendation, "",
                utc_now(), utc_now(),
            ))
            created += cursor.rowcount

        cookie_flags = (
            ("secure", "Secure"),
            ("httponly", "HttpOnly"),
            ("samesite", "SameSite"),
        )
        for cookie in result.get("cookies", []):
            number = cookie.get("number", "unknown")
            for key, label in cookie_flags:
                if cookie.get(key):
                    continue

                fingerprint_source = (
                    f"web_security|{target.rstrip('/').lower()}|"
                    f"cookie|{number}|{key}"
                )
                fingerprint = hashlib.sha256(
                    fingerprint_source.encode("utf-8")
                ).hexdigest()

                title = (
                    f"Review cookie {label} attribute on {target} "
                    f"(response cookie {number})"
                )
                description = (
                    f"A Set-Cookie response was observed without the {label} "
                    "attribute. This may be appropriate for some cookie types "
                    "or contexts, so review the cookie's purpose and exposure "
                    "before deciding whether to change it."
                )
                evidence = (
                    f"Source: authorized HTTPS check; target={target}; "
                    f"HTTP status={status_code}; response cookie={number}; "
                    f"attribute={label}; observed=not present"
                )
                recommendation = (
                    f"Review whether the {label} attribute is appropriate "
                    "for this cookie, considering its purpose and browser "
                    "behavior. Test any change before deployment."
                )

                cursor = db.execute("""
                    INSERT OR IGNORE INTO draft_findings (
                        source, source_record_id, fingerprint, target, title,
                        description, evidence, suggested_severity, confidence,
                        recommendation, iso_controls, status, created_at, updated_at
                    ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Draft', ?, ?)
                """, (
                    "web_security", fingerprint, target, title, description,
                    evidence, "Review", "Low", recommendation, "",
                    utc_now(), utc_now(),
                ))
                created += cursor.rowcount

    return created
