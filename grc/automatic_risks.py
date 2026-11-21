import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import csv
import io
import json
import requests
import time
import tempfile
from datetime import datetime, timezone

from flask import (
    Blueprint, abort, current_app, flash, redirect,
    render_template, request, url_for, Response, session
)

from target_identity import group_targets

from config import DATABASE_PATH
from grc.cve_matching import (
    _numeric_version_parts,
    _match_cve_version_range,
    _match_nvd_cpe,
    _match_nvd_configuration,
)
from grc.attack_catalogue import (
    initialize_attack_catalogue,
    get_latest_attack_version,
    get_attack_technique,
    import_attack_stix_file,
    MAX_STIX_FILE_BYTES,
)
from grc.attack_coverage import (
    build_attack_coverage,
    build_navigator_layer,
)
from scanner.attack_catalogue_worker import (
    get_sync_status as get_attack_sync_status,
    request_update as request_attack_update,
)
from reporting.pdf_generator import build_grc_pdf

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
            CREATE INDEX IF NOT EXISTS idx_draft_findings_status_id
            ON draft_findings(status, id DESC)
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS finding_intelligence (
                finding_id INTEGER PRIMARY KEY,
                cve_ids TEXT NOT NULL DEFAULT '',
                owasp_category TEXT NOT NULL DEFAULT '',
                mitre_tactic TEXT NOT NULL DEFAULT '',
                mitre_technique TEXT NOT NULL DEFAULT '',
                mapping_rationale TEXT NOT NULL DEFAULT '',
                mapping_confidence TEXT NOT NULL DEFAULT 'Unassessed',
                validation_status TEXT NOT NULL DEFAULT 'Unreviewed',
                source_reference TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                FOREIGN KEY(finding_id) REFERENCES draft_findings(id) ON DELETE CASCADE
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS finding_intelligence (
                finding_id INTEGER PRIMARY KEY,
                cve_ids TEXT NOT NULL DEFAULT '',
                owasp_category TEXT NOT NULL DEFAULT '',
                mitre_tactic TEXT NOT NULL DEFAULT '',
                mitre_technique TEXT NOT NULL DEFAULT '',
                mapping_rationale TEXT NOT NULL DEFAULT '',
                mapping_confidence TEXT NOT NULL DEFAULT 'Unassessed',
                validation_status TEXT NOT NULL DEFAULT 'Unreviewed',
                source_reference TEXT NOT NULL DEFAULT '',
                auto_cve_ids TEXT NOT NULL DEFAULT '',
                auto_owasp_category TEXT NOT NULL DEFAULT '',
                auto_source_summary TEXT NOT NULL DEFAULT '',
                last_enriched_at TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                FOREIGN KEY(finding_id) REFERENCES draft_findings(id) ON DELETE CASCADE
            )
        """)
        intelligence_columns = {r["name"] for r in db.execute("PRAGMA table_info(finding_intelligence)").fetchall()}
        for column, definition in {
            "auto_cve_ids": "TEXT NOT NULL DEFAULT ''",
            "auto_owasp_category": "TEXT NOT NULL DEFAULT ''",
            "auto_source_summary": "TEXT NOT NULL DEFAULT ''",
            "last_enriched_at": "TEXT NOT NULL DEFAULT ''",
            "auto_security_category": "TEXT NOT NULL DEFAULT ''",
            "auto_mitre_tactic": "TEXT NOT NULL DEFAULT ''",
            "auto_mitre_technique": "TEXT NOT NULL DEFAULT ''",
            "auto_mitre_rationale": "TEXT NOT NULL DEFAULT ''",
            "auto_mitre_confidence": "TEXT NOT NULL DEFAULT 'Unassessed'",
            "auto_cve_match_status": "TEXT NOT NULL DEFAULT 'Unassessed'",
            "auto_cve_match_details": "TEXT NOT NULL DEFAULT ''",
            "auto_cve_checked_at": "TEXT NOT NULL DEFAULT ''",
            "local_cve_ids": "TEXT NOT NULL DEFAULT ''",
            "local_cve_match_status": "TEXT NOT NULL DEFAULT 'Unassessed'",
            "local_cve_match_details": "TEXT NOT NULL DEFAULT ''",
            "local_cve_checked_at": "TEXT NOT NULL DEFAULT ''",
            "local_owasp_category": "TEXT NOT NULL DEFAULT ''",
            "local_security_category": "TEXT NOT NULL DEFAULT ''",
            "local_source_summary": "TEXT NOT NULL DEFAULT ''",
        }.items():
            if column not in intelligence_columns:
                db.execute(f"ALTER TABLE finding_intelligence ADD COLUMN {column} {definition}")
        db.execute("CREATE INDEX IF NOT EXISTS idx_finding_intelligence_status ON finding_intelligence(validation_status)")

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

    initialize_attack_catalogue()


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
        ("automatic_risks.finding_intelligence_page", "Finding Intelligence", "⌘"),
        ("automatic_risks.attack_coverage_page", "MITRE ATT&CK", "⌘"),
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
            # Exclude scan_id so a re-scan updates the existing finding
            # instead of creating a new one each time.
            fingerprint_source = (
                f"nmap|{scan['target']}|"
                f"{port['protocol']}|{port['port']}"
            )
            fingerprint = hashlib.sha256(
                fingerprint_source.encode("utf-8")
            ).hexdigest()

            service_name = port["service"] or "unknown service"
            description = (
                f"Nmap reported TCP port {port['port']} ({service_name}) as open on "
                f"{scan['target']}. This is an exposure observation only; "
                "it does not establish that the service is vulnerable or "
                "improperly configured. Confirm that the service is required, "
                "identify its owner, and assess whether network access is appropriate."
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


def _ensure_intelligence_row(db, finding_id):
    db.execute("INSERT OR IGNORE INTO finding_intelligence (finding_id, updated_at) VALUES (?, ?)", (finding_id, utc_now()))


def _suggest_owasp(title, description, evidence):
    text = " ".join((title or "", description or "", evidence or "")).lower()
    rules = [
        (("security header", "content-security-policy", "hsts", "http header", "tls", "ssl", "cookie flag"), "A05:2021 – Security Misconfiguration"),
        (("sql injection", "sqli", "command injection", "code injection"), "A03:2021 – Injection"),
        (("cross-site scripting", "xss", "html injection"), "A03:2021 – Injection"),
        (("authentication", "weak password", "default credential", "session fixation", "session management"), "A07:2021 – Identification and Authentication Failures"),
        (("access control", "idor", "authorization bypass", "privilege escalation"), "A01:2021 – Broken Access Control"),
        (("sensitive data", "cleartext", "unencrypted", "cryptographic"), "A02:2021 – Cryptographic Failures"),
        (("outdated component", "vulnerable component", "unsupported version", "known vulnerability"), "A06:2021 – Vulnerable and Outdated Components"),
    ]
    for terms, category in rules:
        if any(term in text for term in terms):
            return category
    return ""



def _suggest_mitre(title, description, evidence, source=""):
    """Automatically suggest ATT&CK mappings based on technical indicators."""
    text = " ".join(str(v or "") for v in (title, description, evidence, source)).casefold()

    rules = [
        # Behavior-based (kept from original)
        (r"\b(?:brute[\s-]?force attack|password spraying|repeated authentication failures|repeated failed login attempts)\b",
         "T1110", "Evidence describes authentication guessing activity.", "Medium"),
        (r"\b(?:confirmed shell command execution|command execution confirmed|unix shell command executed|os command execution observed)\b",
         "T1059.004", "Evidence confirms Unix shell execution.", "Medium"),
        (r"\b(?:successful exploitation observed|exploitation confirmed|confirmed exploitation of (?:the )?(?:public[- ]facing )?application)\b",
         "T1190", "Evidence describes successful exploitation.", "Medium"),

        # Service / Asset based (new)
        (r"\b(?:ssh|port 22)\b", "T1021", "Exposed SSH service provides a remote access vector.", "Low"),
        (r"\b(?:rdp|port 3389|ms-wbt)\b", "T1021", "Exposed RDP service provides a remote access vector.", "Low"),
        (r"\b(?:smb|port 445|netbios)\b", "T1021", "Exposed SMB service provides lateral movement capability.", "Low"),
        (r"\b(?:open tcp port|open udp port|nmap|service exposure|service discovery)\b", "T1046", "Network service discovery identifies exposed endpoints.", "Low"),
        (r"\b(?:unassessed software observation|version match|potential version match)\b", "T1190", "Unverified software version exposed, potential exploitation vector.", "Low"),

        # Web Security based (new)
        (r"\b(?:missing content-security-policy|csp header|missing hsts|x-frame-options)\b", "T1189", "Missing web security headers increase exposure to client-side attacks.", "Low"),
        (r"\b(?:sql injection|sqli|command injection|code injection)\b", "T1190", "Potential injection vulnerability on a public-facing app.", "Low"),
        (r"\b(?:api endpoint|form discovery|web crawl)\b", "T1595", "Active web discovery reveals attack surface.", "Low"),
        (r"\b(?:port \d+|tcp port|udp port)\b", "T1046", "Exposed network port identified.", "Low"),
        (r"\b(?:missing x-frame-options|missing hsts|missing content-security-policy|missing x-content-type-options|missing referrer-policy|missing permissions-policy|missing header|content security policy header not set|strict-transport-security header not set)\b", "T1189", "Missing security header increases client-side attack surface.", "Low"),
        (r"\b(?:user controllable html|potential xss|cross-site scripting|xss)\b", "T1190", "Potential cross-site scripting exposure on a web application.", "Low"),
        (r"\b(?:tech detected|technology detected|modern web application)\b", "T1592", "Technology fingerprinting reveals attacker-relevant information.", "Low"),

        # CVE based (new)
        (r"\b(?:cve-\d{4}-\d+)\b", "T1190", "Known CVE exposure against a public or internal service.", "Low"),
    ]

    empty_result = {
        "tactic": "",
        "technique": "",
        "name": "",
        "rationale": "No ATT&CK technique was assigned.",
        "confidence": "Unassessed",
    }

    for pattern, technique_id, rationale, confidence in rules:
        if not re.search(pattern, text):
            continue

        try:
            version = get_latest_attack_version(DATABASE_PATH)
            if not version:
                return empty_result.copy()

            technique = get_attack_technique(
                technique_id,
                version=version,
                database_path=DATABASE_PATH,
            )
            if not technique or technique.get("revoked") or technique.get("deprecated"):
                return empty_result.copy()

            db = sqlite3.connect(DATABASE_PATH, timeout=15)
            try:
                tactics = db.execute(
                    """
                    SELECT a.name
                    FROM attack_technique_tactics x
                    JOIN attack_tactics a
                      ON a.framework_id = x.framework_id
                     AND a.version = x.version
                     AND a.tactic_id = x.tactic_id
                    WHERE x.framework_id = 'mitre-attack'
                      AND x.version = ?
                      AND x.technique_id = ?
                    ORDER BY a.name
                    """,
                    (version, technique_id),
                ).fetchall()
            finally:
                db.close()

            # If multiple tactics, we pick the first one alphabetically to avoid crashing.
            if not tactics:
                return empty_result.copy()

            return {
                "tactic": tactics[0][0],
                "technique": technique_id,
                "name": technique["name"],
                "rationale": rationale,
                "confidence": confidence,
            }

        except (sqlite3.Error, OSError, ValueError):
            return empty_result.copy()

    return empty_result


def _suggest_general_category(title, description, evidence, source=""):
    """Classify a finding without pretending it is a confirmed attack."""
    text = " ".join(str(v or "") for v in (
        title, description, evidence, source
    )).casefold()

    rules = [
        (r"\b(?:content.security.policy|csp|hsts|security header|"
         r"tls configuration|cookie flag|security misconfiguration)\b",
         "Security Misconfiguration"),
        (r"\b(?:sql injection|command injection|code injection|"
         r"cross.site scripting|xss|injection vulnerability)\b",
         "Potential Injection Vulnerability"),
        (r"\b(?:authentication weakness|weak password|default credential|"
         r"missing authentication|authentication failure)\b",
         "Authentication Weakness"),
        (r"\b(?:access control|idor|authorization bypass|"
         r"privilege escalation)\b",
         "Access Control Weakness"),
        (r"\b(?:sensitive data|cleartext|unencrypted|"
         r"cryptographic weakness|data exposure)\b",
         "Data Protection Weakness"),
        (r"\b(?:outdated component|unsupported version|"
         r"known vulnerability|vulnerable component)\b",
         "Vulnerable or Outdated Component"),
        (r"\b(?:open tcp port|open udp port|service exposure|"
         r"exposed network service|port exposure)\b",
         "Exposed Network Service"),
        (r"\b(?:brute.force|password spraying|repeated failed login)\b",
         "Suspicious Authentication Activity"),
        (r"\b(?:exploit|exploitation|attack attempt|malicious payload)\b",
         "Potential Malicious Activity"),
    ]

    for pattern, category in rules:
        if re.search(pattern, text):
            return category

    return "Unclassified Finding"



def _nvd_candidates(product, version):
    """Return candidate CVEs from NVD; these are leads, never confirmations."""
    if not product or not version or len(product) < 2 or len(version) < 1:
        return []
    query = " ".join((product + " " + version).split())[:180]
    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": query, "resultsPerPage": 8},
            headers={"User-Agent": "Shadow-Map-GRC/1.1 (defensive assessment)"},
            timeout=(4, 12),
        )
        response.raise_for_status()
        payload = response.json()
        candidates = []
        for item in payload.get("vulnerabilities", [])[:8]:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                candidates.append(cve_id)
        return candidates
    except (requests.RequestException, ValueError, TypeError):
        return []



def _nvd_lookup(product, version):
    """Return bounded NVD candidates and conservative CPE applicability."""
    result = {
        "lookup_status": "Skipped",
        "candidates": [],
        "match_status": "Unassessed",
        "match_details": "",
    }

    if (
        not isinstance(product, str)
        or not product.strip()
        or not isinstance(version, str)
        or not version.strip()
        or len(product) < 2
    ):
        result["match_details"] = "Product or version unavailable."
        return result

    query = " ".join((product + " " + version).split())[:180]

    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": query, "resultsPerPage": 8},
            headers={"User-Agent": "Shadow-Map-GRC/1.1 (defensive assessment)"},
            timeout=(4, 12),
        )
        response.raise_for_status()
        payload = response.json()

        if not isinstance(payload, dict):
            raise ValueError("Unexpected NVD response structure.")

        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise ValueError("NVD response has no valid vulnerabilities list.")

        result["lookup_status"] = "Succeeded"
        details = []
        statuses = []

        for item in vulnerabilities[:8]:
            if not isinstance(item, dict):
                continue

            cve = item.get("cve")
            if not isinstance(cve, dict):
                continue

            cve_id = cve.get("id", "")
            if not isinstance(cve_id, str) or not re.fullmatch(
                r"CVE-\d{4}-\d{4,}", cve_id
            ):
                continue

            result["candidates"].append(cve_id)

            configurations = cve.get("configurations")
            status = _match_nvd_configuration(
                product, version, configurations
            )
            statuses.append(status)
            details.append(f"{cve_id}: {status}")

        if "Version Match" in statuses:
            result["match_status"] = "Version Match"
        elif statuses and all(s == "Not Matched" for s in statuses):
            result["match_status"] = "Not Matched"

        if result["candidates"]:
            details.append(
                "CPE applicability is based on product/version evidence; "
                "vendor identity was not independently verified."
            )

        result["match_details"] = "; ".join(details)[:4000]

        if not result["candidates"]:
            result["match_details"] = "NVD lookup succeeded; no CVE candidates returned."

    except (requests.RequestException, ValueError, TypeError):
        result["lookup_status"] = "Failed"
        result["match_details"] = "NVD lookup failed; applicability remains unassessed."

    return result


def _sync_existing_findings():
    """Backfill drafts from scan records already stored in Shadow Map GRC."""
    created = {"nmap": 0, "web_security": 0, "threat_intel": 0}
    with connect_db() as db:
        nmap_ids = [r[0] for r in db.execute("SELECT id FROM nmap_scans WHERE status='Completed' ORDER BY id DESC LIMIT 500")]
        web_rows = db.execute("SELECT id, result_json FROM web_security_scans WHERE status='Completed' ORDER BY id DESC LIMIT 250").fetchall()
        intel_rows = db.execute("SELECT id, target, result_json FROM threat_intel_lookups WHERE status='Completed' ORDER BY id DESC LIMIT 250").fetchall()
    for scan_id in nmap_ids:
        try:
            created["nmap"] += generate_nmap_drafts(scan_id)
        except Exception:
            continue
    for row in web_rows:
        try:
            result = json.loads(row["result_json"] or "{}")
            if isinstance(result, dict):
                created["web_security"] += generate_web_security_drafts(result, source_record_id=row["id"])
        except Exception:
            continue
    # Shodan InternetDB CVEs become review-only drafts, never confirmed findings.
    with connect_db() as db:
        for row in intel_rows:
            try:
                result = json.loads(row["result_json"] or "{}")
            except (TypeError, ValueError):
                continue
            if not isinstance(result, dict):
                continue
            vulns = result.get("vulns", [])
            if not isinstance(vulns, list):
                continue
            for cve in vulns[:100]:
                cve = str(cve).strip().upper()
                if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
                    continue
                fingerprint = hashlib.sha256(f"shodan|{row['id']}|{row['target']}|{cve}".encode()).hexdigest()
                cursor = db.execute("""INSERT OR IGNORE INTO draft_findings
                    (source, source_record_id, fingerprint, target, title, description, evidence,
                     suggested_severity, confidence, recommendation, iso_controls, status, created_at, updated_at)
                    VALUES ('threat_intel', ?, ?, ?, ?, ?, ?, 'Review', 'Low', ?, '', 'Draft', ?, ?)""",
                    (row["id"], fingerprint, row["target"], f"Review InternetDB CVE reference {cve}",
                     "Shodan InternetDB lists this CVE for the public IP address. This is an external intelligence lead and does not prove that the detected service or version is affected.",
                     f"Source: Shodan InternetDB lookup #{row['id']}; target={row['target']}; listed_cve={cve}",
                     "Verify the affected product, exact version, exposure and vendor advisory before approving or assigning risk.", utc_now(), utc_now()))
                created["threat_intel"] += cursor.rowcount
    return created



def _enrich_existing_findings(limit=30):
    """Enrich findings with non-authoritative CVE and framework suggestions."""
    counts = {
        "processed": 0,
        "nvd_candidates": 0,
        "owasp_suggestions": 0,
        "mitre_suggestions": 0,
        "general_classifications": 0,
    }
    nvd_cache = {}
    nvd_queries = 0
    prepared = []

    with connect_db() as db:
        rows = db.execute("""
            SELECT f.id, f.source, f.source_record_id, f.target, f.title,
                   f.description, f.evidence,
                   COALESCE(i.auto_cve_ids, '') AS old_auto_cves,
                   COALESCE(i.auto_owasp_category, '') AS old_auto_owasp
            FROM draft_findings f
            LEFT JOIN finding_intelligence i ON i.finding_id=f.id
            ORDER BY f.id DESC LIMIT ?
        """, (max(1, min(int(limit), 100)),)).fetchall()

        for f in rows:
            product = version = ""
            if f["source"] == "nmap" and f["source_record_id"]:
                port = db.execute("""
                    SELECT product, version FROM nmap_ports
                    WHERE scan_id=? AND state='open'
                      AND product IS NOT NULL AND version IS NOT NULL
                      AND instr(?, 'port=' || port) > 0
                    ORDER BY id DESC LIMIT 1
                """, (f["source_record_id"], f["evidence"] or "")).fetchone()
                if port:
                    product = (port["product"] or "").strip()
                    version = (port["version"] or "").strip()

            prepared.append((dict(f), product, version))

    enriched = []

    for f, product, version in prepared:
        owasp = _suggest_owasp(
            f["title"], f["description"], f["evidence"]
        )
        mitre = _suggest_mitre(
            f["title"], f["description"], f["evidence"], f["source"]
        )
        general_category = _suggest_general_category(
            f["title"], f["description"], f["evidence"], f["source"]
        )

        cache_key = (product.casefold(), version.casefold())
        lookup = None

        if product and version:
            if cache_key not in nvd_cache and nvd_queries < 5:
                if nvd_queries:
                    time.sleep(6.5)
                nvd_cache[cache_key] = _nvd_lookup(product, version)
                nvd_queries += 1

            lookup = nvd_cache.get(cache_key)

        candidates = []
        match_status = "Unassessed"
        match_details = "Product/version applicability not assessed."
        checked_at = ""

        if f["source"] == "threat_intel":
            candidates = list(dict.fromkeys(re.findall(
                r"CVE-\d{4}-\d{4,}",
                (f["title"] or "") + " " + (f["evidence"] or "")
            )))
            match_details = (
                "Shodan InternetDB CVE references are external intelligence "
                "leads and have not been validated against an affected version."
            )

        elif lookup:
            match_status = lookup["match_status"]
            match_details = lookup["match_details"]
            checked_at = utc_now()

            if lookup["lookup_status"] == "Succeeded":
                candidates = lookup["candidates"]
            elif lookup["lookup_status"] == "Failed":
                candidates = [
                    item.strip()
                    for item in (f["old_auto_cves"] or "").split(",")
                    if item.strip()
                ]

        auto_cves = (
            ", ".join(candidates)
            if candidates or (lookup and lookup["lookup_status"] == "Succeeded")
            else f["old_auto_cves"]
        )
        auto_owasp = owasp or f["old_auto_owasp"]

        sources = []
        if f["source"] == "threat_intel" and candidates:
            sources.append(
                "Shodan InternetDB CVE references; applicability unassessed"
            )
        elif lookup:
            if lookup["lookup_status"] == "Succeeded":
                sources.append(
                    f"NVD keyword lookup succeeded for {product} {version}"
                    if candidates else
                    f"NVD keyword lookup returned no candidates for {product} {version}"
                )
            elif lookup["lookup_status"] == "Failed":
                sources.append(
                    f"NVD lookup failed for {product} {version}"
                )

        if owasp:
            sources.append("Rule-based OWASP category suggestion")

        enriched.append((
            f, auto_cves, auto_owasp, "; ".join(sources) or
            "No automated CVE/OWASP source matched",
            general_category, mitre, match_status,
            match_details, checked_at
        ))

        counts["processed"] += 1
        counts["nvd_candidates"] += len(candidates)
        counts["owasp_suggestions"] += bool(owasp)
        counts["mitre_suggestions"] += bool(mitre["technique"])
        counts["general_classifications"] += bool(general_category)

    with connect_db() as db:
        for (
            f, auto_cves, auto_owasp, sources, general_category,
            mitre, match_status, match_details, checked_at
        ) in enriched:
            _ensure_intelligence_row(db, f["id"])

            db.execute("""
                UPDATE finding_intelligence SET
                    auto_cve_ids=?,
                    auto_cve_match_status=?,
                    auto_cve_match_details=?,
                    auto_cve_checked_at=CASE
                        WHEN ? != '' THEN ?
                        ELSE auto_cve_checked_at
                    END,
                    auto_owasp_category=?,
                    auto_security_category=?,
                    auto_mitre_tactic=?,
                    auto_mitre_technique=?,
                    auto_mitre_rationale=?,
                    auto_mitre_confidence=?,
                    auto_source_summary=?,
                    last_enriched_at=?,
                    updated_at=?
                WHERE finding_id=?
            """, (
                auto_cves,
                match_status,
                match_details,
                checked_at,
                checked_at,
                auto_owasp,
                general_category,
                mitre["tactic"],
                (mitre["technique"] + " – " + mitre["name"]).strip(" –"),
                mitre["rationale"],
                mitre["confidence"],
                sources,
                utc_now(),
                utc_now(),
                f["id"],
            ))

    return counts

def _host_register_rows(search=""):
    """Build a read-only, aggregated register of unique IPs and web origins."""
    with connect_db() as db:
        findings = db.execute("""
            SELECT
                f.id,
                f.source,
                f.target,
                f.suggested_severity,
                f.title,
                f.description,
                f.evidence,
                COALESCE(i.validation_status, 'Unreviewed') AS validation_status,
                COALESCE(i.cve_ids, '') AS analyst_cve_ids,
                COALESCE(i.auto_cve_ids, '') AS auto_cve_ids,
                COALESCE(i.local_cve_ids, '') AS local_cve_ids,
                COALESCE(i.mitre_technique, '') AS analyst_mitre_technique,
                COALESCE(i.auto_mitre_technique, '') AS auto_mitre_technique
            FROM draft_findings AS f
            LEFT JOIN finding_intelligence AS i
                ON i.finding_id = f.id
            WHERE TRIM(COALESCE(f.target, '')) != ''
            ORDER BY f.id DESC
        """).fetchall()

    groups = group_targets(row["target"] for row in findings)
    target_to_group = {}
    register = {}

    for group in groups:
        host = group["label"]
        register[host] = {
            "host": host,
            "aliases": list(group["targets"]),
            "total_findings": 0,
            "severity_counts": {},
            "validation_counts": {},
            "cve_candidates": 0,
            "mitre_suggestions": 0,
            "source_counts": {},
            "latest_finding_id": 0,
        }
        for target in group["targets"]:
            target_to_group[target] = host

    for finding in findings:
        target = str(finding["target"] or "").strip()
        host = target_to_group.get(target)
        if not host:
            continue

        item = register[host]
        item["total_findings"] += 1
        item["latest_finding_id"] = max(
            item["latest_finding_id"], finding["id"]
        )

        severity = str(finding["suggested_severity"] or "Review").strip() or "Review"
        item["severity_counts"][severity] = (
            item["severity_counts"].get(severity, 0) + 1
        )

        validation = str(finding["validation_status"] or "Unreviewed").strip()
        item["validation_counts"][validation] = (
            item["validation_counts"].get(validation, 0) + 1
        )

        source = str(finding["source"] or "Unknown").strip() or "Unknown"
        item["source_counts"][source] = item["source_counts"].get(source, 0) + 1

        if (
            finding["analyst_cve_ids"]
            or finding["auto_cve_ids"]
            or finding["local_cve_ids"]
        ):
            item["cve_candidates"] += 1

        if finding["auto_mitre_technique"]:
            item["mitre_suggestions"] += 1

    query = str(search or "").strip().casefold()
    rows = list(register.values())

    if query:
        rows = [
            item for item in rows
            if query in item["host"].casefold()
            or any(query in alias.casefold() for alias in item["aliases"])
        ]

    return sorted(rows, key=lambda item: item["host"].casefold())


def _intelligence_query(args, limit=1000):
    sql = """
        SELECT f.id, f.target, f.title, f.source, f.description, f.evidence,
               f.suggested_severity, f.confidence, f.recommendation,
               f.iso_controls, f.status AS finding_status,
               COALESCE(i.cve_ids, '') AS cve_ids,
               COALESCE(i.auto_cve_ids, '') AS auto_cve_ids,
               COALESCE(i.local_cve_ids, '') AS local_cve_ids,
               COALESCE(i.local_cve_match_status, 'Unassessed') AS local_cve_match_status,
               COALESCE(i.local_cve_checked_at, '') AS local_cve_checked_at,
               COALESCE(i.owasp_category, '') AS owasp_category,
               COALESCE(i.auto_owasp_category, '') AS auto_owasp_category,
               COALESCE(i.local_owasp_category, '') AS local_owasp_category,
               COALESCE(i.auto_security_category, '') AS auto_security_category,
               COALESCE(i.local_security_category, '') AS local_security_category,
               COALESCE(i.local_source_summary, '') AS local_source_summary,
               COALESCE(i.auto_mitre_tactic, '') AS auto_mitre_tactic,
               COALESCE(i.auto_mitre_technique, '') AS auto_mitre_technique,
               COALESCE(i.auto_mitre_rationale, '') AS auto_mitre_rationale,
               COALESCE(i.auto_mitre_confidence, 'Unassessed') AS auto_mitre_confidence,
               COALESCE(i.mitre_tactic, '') AS analyst_mitre_tactic,
               COALESCE(NULLIF(i.mitre_tactic, ''), i.auto_mitre_tactic, '') AS mitre_tactic,
               COALESCE(i.mitre_technique, '') AS mitre_technique,
               COALESCE(i.mapping_rationale, '') AS mapping_rationale,
               COALESCE(i.mapping_confidence, 'Unassessed') AS mapping_confidence,
               COALESCE(i.validation_status, 'Unreviewed') AS validation_status,
               COALESCE(i.source_reference, '') AS source_reference,
               COALESCE(i.auto_source_summary, '') AS auto_source_summary,
               COALESCE(i.last_enriched_at, '') AS last_enriched_at,
               COALESCE(h.summary, '') AS hexbrain_summary,
               COALESCE(h.testing_context_json, '[]') AS hexbrain_testing_context,
               COALESCE(h.references_json, '[]') AS hexbrain_references
        FROM draft_findings f
        LEFT JOIN finding_intelligence i ON i.finding_id=f.id
        LEFT JOIN hexbrain_enrichment h ON h.cve_id = COALESCE(NULLIF(i.local_cve_ids, ''), i.auto_cve_ids)
        WHERE 1=1
    """
    params = []
    if args.get("finding_id"):
        sql += " AND f.id = ?"
        params.append(int(args["finding_id"]))
    for key, column in (("source", "f.source"), ("severity", "f.suggested_severity"), ("status", "COALESCE(i.validation_status, 'Unreviewed')"), ("confidence", "f.confidence")):
        value = (args.get(key) or "").strip()
        if value:
            sql += f" AND {column} = ?"
            params.append(value)
    for key, expression in (("cve", "(i.cve_ids || ' ' || i.auto_cve_ids || ' ' || i.local_cve_ids)"), ("owasp", "(i.owasp_category || ' ' || i.auto_owasp_category || ' ' || i.local_owasp_category)"), ("mitre", "(i.mitre_tactic || ' ' || i.mitre_technique || ' ' || i.auto_mitre_tactic || ' ' || i.auto_mitre_technique || ' ' || i.auto_security_category || ' ' || i.local_security_category)")):
        value = (args.get(key) or "").strip()
        if value:
            sql += f" AND {expression} LIKE ?"
            params.append("%" + value[:160] + "%")
    host = (args.get("host") or "").strip()
    if host:
        host_targets = [host[:255]]

        # Resolve either a canonical host label or an original page URL
        # to every stored target belonging to the same website origin.
        with connect_db() as db:
            stored_targets = db.execute(
                "SELECT DISTINCT target FROM draft_findings "
                "WHERE target IS NOT NULL AND TRIM(target) <> ''"
            ).fetchall()

        matching_group = next(
            (
                group for group in group_targets(
                    row["target"] for row in stored_targets
                )
                if group["label"].casefold() == host.casefold()
                or any(
                    value.casefold() == host.casefold()
                    for value in group["targets"]
                )
            ),
            None,
        )

        if matching_group:
            host_targets = matching_group["targets"]

        placeholders = ",".join("?" for _ in host_targets)
        sql += f" AND LOWER(TRIM(f.target)) IN ({placeholders})"
        params.extend(value.casefold() for value in host_targets)
    target = (args.get("target") or "").strip()
    if target:
        sql += " AND f.target LIKE ?"
        params.append("%" + target[:200] + "%")
    search = (args.get("q") or "").strip()
    if search:
        like = "%" + search[:200] + "%"
        sql += """ AND (
            f.target LIKE ? OR f.title LIKE ? OR f.description LIKE ?
            OR f.evidence LIKE ? OR i.cve_ids LIKE ? OR i.auto_cve_ids LIKE ?
            OR i.local_cve_ids LIKE ?
            OR i.owasp_category LIKE ? OR i.auto_owasp_category LIKE ?
            OR i.local_owasp_category LIKE ?
            OR i.mitre_technique LIKE ? OR i.auto_mitre_technique LIKE ?
            OR i.auto_mitre_tactic LIKE ? OR i.auto_security_category LIKE ?
            OR i.local_security_category LIKE ?
        )"""
        params.extend([like] * 15)
    sql += " ORDER BY f.id DESC"
    if limit is not None:
        limit = int(limit)
        if limit < 1:
            raise ValueError("Query limit must be positive or None.")
        sql += " LIMIT ?"
        params.append(limit)
    with connect_db() as db:
        return db.execute(sql, params).fetchall()


def _load_attack_coverage():
    """Build coverage from analyst-confirmed mappings and the imported catalogue."""
    initialize_attack_catalogue()

    version = get_latest_attack_version(DATABASE_PATH)
    findings = _intelligence_query({}, limit=None)

    if not version:
        return build_attack_coverage(
            findings, [], [], [], version=None
        )

    with connect_db() as db:
        techniques = db.execute(
            """
            SELECT technique_id, name, url, is_subtechnique,
                   parent_technique_id, deprecated, revoked
            FROM attack_techniques
            WHERE framework_id = ? AND version = ?
            ORDER BY technique_id
            """,
            ("mitre-attack", version),
        ).fetchall()

        tactics = db.execute(
            """
            SELECT tactic_id, name, short_name, description, url
            FROM attack_tactics
            WHERE framework_id = ? AND version = ?
            ORDER BY name
            """,
            ("mitre-attack", version),
        ).fetchall()

        relationships = db.execute(
            """
            SELECT technique_id, tactic_id
            FROM attack_technique_tactics
            WHERE framework_id = ? AND version = ?
            ORDER BY technique_id, tactic_id
            """,
            ("mitre-attack", version),
        ).fetchall()

    return build_attack_coverage(
        findings,
        techniques,
        tactics,
        relationships,
        version=version,
    )


@automatic_risks_bp.route("/attack-coverage")
def attack_coverage_page():
    initialize_automatic_risks()
    coverage = _load_attack_coverage()
    attack_sync_status = get_attack_sync_status()

    with connect_db() as db:
        recent_scans = db.execute(
            """
            SELECT
                sr.scan_id,
                sr.scan_type,
                sr.source_table,
                sr.source_record_id,
                sr.target,
                sr.status,
                sr.started_at,
                tr.target_id
            FROM scan_registry AS sr
            LEFT JOIN target_registry AS tr
                ON tr.target_id = sr.target_id
            ORDER BY sr.id DESC
            LIMIT 5
            """
        ).fetchall()

    scan_rows = recent_scans
    recent_scans = []
    for scan in scan_rows:
        scan_data = dict(scan)
        scan_data["result_url"] = (
            url_for(
                "automatic_risks.attack_target_report",
                scan_id=scan_data["scan_id"],
            )
            if scan_data["target"]
            else None
        )
        recent_scans.append(scan_data)

    return render_template(
        "attack_coverage.html",
        coverage=coverage,
        attack_sync_status=attack_sync_status,
        recent_scans=recent_scans,
        nav_items=get_nav_items(),
        active_page="automatic_risks.attack_coverage_page",
        attack_import_csrf_token=session.setdefault(
            "attack_import_csrf_token",
            secrets.token_urlsafe(32),
        ),
    )


@automatic_risks_bp.route("/attack-coverage/report/<scan_id>")
def attack_target_report(scan_id):
    initialize_automatic_risks()

    with connect_db() as db:
        selected_scan = db.execute(
            """
            SELECT scan_id, target
            FROM scan_registry
            WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchone()

    if not selected_scan or not str(selected_scan["target"] or "").strip():
        abort(404)

    selected_scan = dict(selected_scan)
    selected_target = str(selected_scan["target"])

    # Include mapped findings for this exact target across its scan history.
    target_report_findings = [
        dict(finding)
        for finding in _intelligence_query({}, limit=None)
        if str(finding["target"] or "") == selected_target
        and any((
            finding["mitre_tactic"],
            finding["mitre_technique"],
            finding["auto_mitre_tactic"],
            finding["auto_mitre_technique"],
        ))
    ]

    return render_template(
        "attack_target_report.html",
        selected_scan=selected_scan,
        target_report_target=selected_target,
        target_report_findings=target_report_findings,
        nav_items=get_nav_items(),
        active_page="automatic_risks.attack_target_report",
    )


@automatic_risks_bp.route("/attack-coverage/sync", methods=["POST"])
def attack_coverage_sync():
    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("attack_import_csrf_token", "")

    if (
        not submitted_token
        or not expected_token
        or not hmac.compare_digest(submitted_token, expected_token)
    ):
        abort(400, description="Invalid or missing security token. Reload the page and try again.")

    if request_attack_update():
        flash("An immediate MITRE ATT&CK update check has been queued.", "success")
    else:
        flash("The automatic ATT&CK updater is not running. Restart Shadow Map GRC and try again.", "error")

    return redirect(url_for("automatic_risks.attack_coverage_page"))


@automatic_risks_bp.route("/attack-coverage/import", methods=["POST"])
def attack_coverage_import():
    initialize_automatic_risks()

    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("attack_import_csrf_token", "")

    if (
        not submitted_token
        or not expected_token
        or not hmac.compare_digest(submitted_token, expected_token)
    ):
        abort(400, description="Invalid or missing security token. Reload the page and try again.")

    upload = request.files.get("stix_file")
    version = request.form.get("version", "").strip()
    release_date = request.form.get("release_date", "").strip()
    source_reference = request.form.get("source_reference", "").strip()

    if not upload or not upload.filename:
        flash("Select an ATT&CK STIX JSON file to import.", "error")
        return redirect(url_for("automatic_risks.attack_coverage_page"))

    if not upload.filename.lower().endswith(".json"):
        flash("The uploaded file must have a .json extension.", "error")
        return redirect(url_for("automatic_risks.attack_coverage_page"))

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", version):
        flash("Enter a valid ATT&CK release version (maximum 64 characters).", "error")
        return redirect(url_for("automatic_risks.attack_coverage_page"))

    if release_date:
        try:
            datetime.strptime(release_date, "%Y-%m-%d")
        except ValueError:
            flash("Release date must use YYYY-MM-DD format.", "error")
            return redirect(url_for("automatic_risks.attack_coverage_page"))

    if len(source_reference) > 500:
        flash("Source reference must be 500 characters or fewer.", "error")
        return redirect(url_for("automatic_risks.attack_coverage_page"))

    temporary_path = None
    total_bytes = 0

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix="shadow-map-attack-",
            suffix=".json",
            delete=False,
        ) as temporary_file:
            temporary_path = temporary_file.name

            while True:
                chunk = upload.stream.read(1024 * 1024)
                if not chunk:
                    break

                total_bytes += len(chunk)
                if total_bytes > MAX_STIX_FILE_BYTES:
                    raise ValueError(
                        f"ATT&CK file exceeds the {MAX_STIX_FILE_BYTES // (1024 * 1024)} MB upload limit."
                    )

                temporary_file.write(chunk)

        if total_bytes == 0:
            raise ValueError("The uploaded file is empty.")

        result = import_attack_stix_file(
            temporary_path,
            version,
            database_path=DATABASE_PATH,
            release_date=release_date,
            source_reference=source_reference,
        )

    except (ValueError, OSError, sqlite3.Error) as exc:
        flash(f"ATT&CK import failed: {exc}", "error")
        return redirect(url_for("automatic_risks.attack_coverage_page"))

    finally:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass

    flash(
        f"ATT&CK {result['version']} imported successfully: "
        f"{result['tactics_imported']} tactics, "
        f"{result['techniques_imported']} techniques and "
        f"{result['relationships_imported']} relationships.",
        "success",
    )
    return redirect(url_for("automatic_risks.attack_coverage_page"))


@automatic_risks_bp.route("/attack-coverage/export.navigator.json")
def attack_coverage_export_navigator():
    initialize_automatic_risks()
    coverage = _load_attack_coverage()

    if not coverage["catalogue_available"]:
        abort(404, description="Import an Enterprise ATT&CK catalogue before exporting.")

    layer = build_navigator_layer(coverage)

    return Response(
        json.dumps(layer, indent=2),
        mimetype="application/json",
        headers={
            "Content-Disposition":
                'attachment; filename="shadow-map-attack-coverage.json"'
        },
    )


@automatic_risks_bp.route("/finding-intelligence/sync", methods=["POST"])
def finding_intelligence_sync():
    initialize_automatic_risks()
    backfill = _sync_existing_findings()
    enriched = _enrich_existing_findings(limit=30)
    flash(f"Source sync complete. New drafts: Nmap {backfill['nmap']}, Web Security {backfill['web_security']}, Threat Intelligence {backfill['threat_intel']}. Intelligence reviewed: {enriched['processed']}; NVD candidates: {enriched['nvd_candidates']}; OWASP suggestions: {enriched['owasp_suggestions']}; MITRE suggestions: {enriched.get('mitre_suggestions', 0)}; general classifications: {enriched.get('general_classifications', 0)}. CVE matches are candidates, not confirmations. MITRE suggestions require analyst validation.", "success")
    return redirect(url_for("automatic_risks.finding_intelligence_page", **request.args.to_dict()))


@automatic_risks_bp.route("/finding-intelligence/export.csv")
def finding_intelligence_export_csv():
    rows = _intelligence_query(request.args)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    columns = ["id", "target", "title", "source", "suggested_severity", "finding_status", "validation_status", "confidence", "cve_ids", "auto_cve_ids", "local_cve_ids", "owasp_category", "auto_owasp_category", "local_owasp_category", "mitre_tactic", "mitre_technique", "mapping_confidence", "mapping_rationale", "description", "evidence", "recommendation", "auto_source_summary", "local_source_summary", "last_enriched_at", "hexbrain_summary", "hexbrain_references"]
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row[c] for c in columns])
    return Response("\ufeff" + output.getvalue(), mimetype="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename=shadow-map-finding-intelligence.csv"})


@automatic_risks_bp.route("/finding-intelligence/export.pdf")
def finding_intelligence_export_pdf():
    rows = _intelligence_query(request.args)
    findings = []
    for row in rows:
        findings.append({
            "title": row["title"], "target": row["target"], "source": row["source"],
            "suggested_severity": row["suggested_severity"], "status": row["finding_status"],
            "description": row["description"],
            "evidence": row["evidence"] + "\nCVE candidates: " + (row["auto_cve_ids"] or "None") + "\nLocal correlation CVE: " + (row["local_cve_ids"] or "None") + "\nAnalyst CVEs: " + (row["cve_ids"] or "None") + "\nOWASP suggestion: " + (row["auto_owasp_category"] or "None") + "\nOWASP local correlation: " + (row["local_owasp_category"] or "None") + "\nOWASP analyst mapping: " + (row["owasp_category"] or "None") + "\nMITRE: " + (row["mitre_tactic"] or "") + " " + (row["mitre_technique"] or "") + "\nValidation: " + row["validation_status"] + "\nAutomated source: " + row["auto_source_summary"],
            "recommendation": row["recommendation"], "iso_controls": "",
        })
    pdf = build_grc_pdf(title="Finding Intelligence Report", subtitle="Automated source candidates and analyst-reviewed mappings", findings=findings, summary={"targets": len({r["target"] for r in rows}), "findings": len(rows), "risks": 0}, scope_note="Filtered Finding Intelligence export. NVD matches are candidate references and do not establish vulnerability applicability.")
    return Response(pdf, mimetype="application/pdf", headers={"Content-Disposition": "attachment; filename=shadow-map-finding-intelligence.pdf"})


@automatic_risks_bp.route("/finding-intelligence/<int:finding_id>/export.csv")
def finding_intelligence_single_csv(finding_id):
    rows = _intelligence_query({"finding_id": finding_id})
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    columns = ["id", "target", "title", "source", "suggested_severity", "finding_status", "validation_status", "confidence", "cve_ids", "auto_cve_ids", "local_cve_ids", "owasp_category", "auto_owasp_category", "local_owasp_category", "mitre_tactic", "mitre_technique", "mapping_confidence", "mapping_rationale", "description", "evidence", "recommendation", "auto_source_summary", "local_source_summary", "last_enriched_at", "hexbrain_summary", "hexbrain_references"]
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row[c] for c in columns])
    return Response("\ufeff" + output.getvalue(), mimetype="text/csv; charset=utf-8", headers={"Content-Disposition": f"attachment; filename=shadow-map-finding-{finding_id}-intelligence.csv"})


@automatic_risks_bp.route("/finding-intelligence/<int:finding_id>/export.pdf")
def finding_intelligence_single_pdf(finding_id):
    rows = _intelligence_query({"finding_id": finding_id})
    if not rows:
        abort(404)
    row = rows[0]
    finding = {"title": row["title"], "target": row["target"], "source": row["source"], "suggested_severity": row["suggested_severity"], "status": row["finding_status"], "description": row["description"], "evidence": row["evidence"] + "\nCVE candidates: " + (row["auto_cve_ids"] or "None") + "\nLocal correlation CVE: " + (row["local_cve_ids"] or "None") + "\nAnalyst CVEs: " + (row["cve_ids"] or "None") + "\nOWASP suggestion: " + (row["auto_owasp_category"] or "None") + "\nOWASP local correlation: " + (row["local_owasp_category"] or "None") + "\nOWASP analyst mapping: " + (row["owasp_category"] or "None") + "\nMITRE: " + (row["mitre_tactic"] or "") + " " + (row["mitre_technique"] or "") + "\nValidation: " + row["validation_status"], "recommendation": row["recommendation"], "iso_controls": ""}
    pdf = build_grc_pdf(title=f"Finding #{finding_id} Intelligence Report", subtitle="Finding evidence and enrichment", findings=[finding], summary={"targets": 1, "findings": 1, "risks": 0}, scope_note="Individual finding export. NVD matches are candidate references, not confirmation.")
    return Response(pdf, mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename=shadow-map-finding-{finding_id}-intelligence.pdf"})



def _host_report_filters():
    return {
        key: request.args.get(key, "").strip()
        for key in ("q", "source", "severity", "status", "confidence",
                    "cve", "owasp", "mitre")
    }


def _host_report_rows(host, filters=None):
    query = dict(filters or {})
    query["host"] = host
    return _intelligence_query(query, limit=None)


def _host_report_pdf(host, rows, title):
    findings = []
    for row in rows:
        auto_mitre = (
            (row["auto_mitre_tactic"] or "") + " " +
            (row["auto_mitre_technique"] or "")
        ).strip()
        analyst_mitre = (
            (row["mitre_tactic"] or "") + " " +
            (row["mitre_technique"] or "")
        ).strip()
        evidence = (
            (row["evidence"] or "") +
            "\nAutomated CVE candidates: " + (row["auto_cve_ids"] or "None") +
            "\nLocal correlation CVE: " + (row["local_cve_ids"] or "None") +
            "\nAnalyst CVE references: " + (row["cve_ids"] or "None") +
            "\nAutomated OWASP suggestion: " +
            (row["auto_owasp_category"] or "None") +
            "\nLocal OWASP correlation: " +
            (row["local_owasp_category"] or "None") +
            "\nAnalyst OWASP mapping: " + (row["owasp_category"] or "None") +
            "\nAutomated MITRE suggestion: " + (auto_mitre or "Not mapped") +
            "\nAutomated general classification: " +
            (row["auto_security_category"] or "None") +
            "\nAnalyst MITRE mapping: " + (analyst_mitre or "Not mapped") +
            "\nAnalyst mapping rationale: " +
            (row["mapping_rationale"] or "Not supplied") +
            "\nValidation: " + (row["validation_status"] or "Unreviewed") +
            "\nAutomated source notes: " +
            (row["auto_source_summary"] or "None") +
            "\nLocal correlation source: " +
            (row["local_source_summary"] or "None")
        )
        findings.append({
            "title": row["title"],
            "target": row["target"],
            "source": row["source"],
            "suggested_severity": row["suggested_severity"],
            "status": row["finding_status"],
            "description": row["description"],
            "evidence": evidence,
            "recommendation": row["recommendation"],
            "iso_controls": row["iso_controls"] or "",
        })

    pdf = build_grc_pdf(
        title=title,
        subtitle=f"Host-specific Finding Intelligence: {host}",
        findings=findings,
        summary={
            "targets": 1,
            "findings": len(rows),
            "risks": 0,
        },
        scope_note=(
            "Host-specific report. CVE references are candidates, not "
            "confirmed vulnerabilities. Automated MITRE suggestions and "
            "general classifications are separate from analyst mappings. "
            "Only evidence-supported ATT&CK mappings should be treated "
            "as analyst conclusions."
        ),
    )
    return pdf


@automatic_risks_bp.route("/finding-intelligence/host/<path:host>")
def finding_intelligence_host_report(host):
    initialize_automatic_risks()
    filters = _host_report_filters()
    all_rows = _host_report_rows(host)
    if not all_rows:
        abort(404)

    rows = _host_report_rows(host, filters)
    selected_id = request.args.get("finding", type=int)
    selected = next(
        (row for row in rows if row["id"] == selected_id),
        None,
    ) if selected_id else None

    with connect_db() as db:
        sources = [
            row[0] for row in db.execute(
                "SELECT DISTINCT source FROM draft_findings ORDER BY source"
            )
        ]
        severities = [
            row[0] for row in db.execute(
                "SELECT DISTINCT suggested_severity FROM draft_findings "
                "ORDER BY suggested_severity"
            )
        ]

    severity_counts = {}
    validation_counts = {}
    for row in all_rows:
        severity = row["suggested_severity"] or "Review"
        validation = row["validation_status"] or "Unreviewed"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        validation_counts[validation] = validation_counts.get(validation, 0) + 1

    summary = {
        "total": len(all_rows),
        "critical": severity_counts.get("Critical", 0),
        "high": severity_counts.get("High", 0),
        "medium": severity_counts.get("Medium", 0),
        "low": severity_counts.get("Low", 0),
        "review": severity_counts.get("Review", 0),
        "validated": validation_counts.get("Evidence-supported", 0),
        "needs_validation": validation_counts.get("Needs-validation", 0),
        "unreviewed": validation_counts.get("Unreviewed", 0),
        "rejected": validation_counts.get("Rejected", 0),
        "cve_candidates": sum(
            bool(
                row["auto_cve_ids"]
                or row["local_cve_ids"]
                or row["cve_ids"]
            )
            for row in all_rows
        ),
        "mitre_suggestions": sum(
            bool(row["auto_mitre_technique"])
            for row in all_rows
        ),
    }

    return render_template(
        "finding_intelligence_host.html",
        host=host,
        findings=rows,
        selected=selected,
        filters=filters,
        source_options=sources,
        severity_options=severities,
        confidence_options=["Unassessed", "Low", "Medium", "High"],
        status_options=[
            "Unreviewed", "Needs-validation",
            "Evidence-supported", "Rejected",
        ],
        summary=summary,
        nav_items=get_nav_items(),
        active_page="automatic_risks.finding_intelligence_page",
    )


@automatic_risks_bp.route(
    "/finding-intelligence/host/<path:host>/export-filtered.csv"
)
def finding_intelligence_host_filtered_csv(host):
    filters = _host_report_filters()
    rows = _host_report_rows(host)
    if not rows:
        abort(404)
    rows = _host_report_rows(host, filters)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    columns = [
        "id", "target", "title", "source", "suggested_severity",
        "finding_status", "validation_status", "confidence",
        "cve_ids", "auto_cve_ids", "local_cve_ids",
        "owasp_category", "auto_owasp_category", "local_owasp_category",
        "auto_security_category", "local_security_category",
        "mitre_tactic", "mitre_technique", "mapping_confidence",
        "mapping_rationale", "auto_mitre_tactic",
        "auto_mitre_technique", "auto_mitre_rationale",
        "auto_mitre_confidence", "description", "evidence",
        "recommendation", "iso_controls", "auto_source_summary", "last_enriched_at",
    ]
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row[column] for column in columns])

    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", host).strip("._-")[:80] or "target"
    return Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition":
                f"attachment; filename=shadow-map-host-{safe}-filtered-findings.csv"
        },
    )


@automatic_risks_bp.route(
    "/finding-intelligence/host/<path:host>/export-filtered.pdf"
)
def finding_intelligence_host_filtered_pdf(host):
    filters = _host_report_filters()
    all_rows = _host_report_rows(host)
    if not all_rows:
        abort(404)
    rows = _host_report_rows(host, filters)
    pdf = _host_report_pdf(
        host, rows, f"Filtered Host Findings Report - {host}"
    )
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", host).strip("._-")[:80] or "target"
    return Response(
        pdf,
        mimetype="application/pdf",
        headers={
            "Content-Disposition":
                f"attachment; filename=shadow-map-host-{safe}-filtered-findings.pdf"
        },
    )


@automatic_risks_bp.route("/finding-intelligence/host/<path:host>/export.csv")
def finding_intelligence_host_csv(host):
    rows = _intelligence_query({"host": host}, limit=None)
    if not rows:
        abort(404)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    columns = ["id", "target", "title", "source", "suggested_severity", "finding_status", "validation_status", "confidence", "cve_ids", "auto_cve_ids", "local_cve_ids", "owasp_category", "auto_owasp_category", "local_owasp_category", "mitre_tactic", "mitre_technique", "mapping_confidence", "mapping_rationale",
        "auto_security_category", "auto_mitre_tactic", "auto_mitre_technique",
        "auto_mitre_rationale", "auto_mitre_confidence", "description",
        "evidence", "recommendation", "iso_controls", "auto_source_summary",
        "last_enriched_at"]
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row[c] for c in columns])
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", host).strip("._-")[:80] or "target"
    return Response("\ufeff" + output.getvalue(), mimetype="text/csv; charset=utf-8", headers={"Content-Disposition": f"attachment; filename=shadow-map-host-{safe}-findings.csv"})


@automatic_risks_bp.route("/finding-intelligence/host/<path:host>/export.pdf")
def finding_intelligence_host_pdf(host):
    rows = _intelligence_query({"host": host}, limit=None)
    if not rows:
        abort(404)
    findings = []
    for row in rows:
        mitre = (row["mitre_tactic"] or "") + " " + (row["mitre_technique"] or "")
        evidence = (row["evidence"] or "") + "\nCVE candidates: " + (row["auto_cve_ids"] or "None") + "\nLocal correlation CVE: " + (row["local_cve_ids"] or "None") + "\nAnalyst CVEs: " + (row["cve_ids"] or "None") + "\nOWASP suggestion: " + (row["auto_owasp_category"] or "None") + "\nOWASP local correlation: " + (row["local_owasp_category"] or "None") + "\nOWASP analyst mapping: " + (row["owasp_category"] or "None") + "\nAutomated security category: " + (row["auto_security_category"] or "None") + "\nAutomated MITRE suggestion: " + ((row["auto_mitre_tactic"] or "") + " " + (row["auto_mitre_technique"] or "")).strip() + "\nAnalyst MITRE mapping: " + (mitre.strip() or "Not mapped") + "\nAutomated MITRE rationale: " + (row["auto_mitre_rationale"] or "None") + "\nAnalyst MITRE rationale: " + (row["mapping_rationale"] or "Not supplied") + "\nValidation: " + (row["validation_status"] or "Unreviewed") + "\nAutomated source: " + (row["auto_source_summary"] or "None")
        findings.append({"title": row["title"], "target": row["target"], "source": row["source"], "suggested_severity": row["suggested_severity"], "status": row["finding_status"], "description": row["description"], "evidence": evidence, "recommendation": row["recommendation"], "iso_controls": row["iso_controls"] or ""})
    pdf = build_grc_pdf(title=f"Host Findings Report - {host}", subtitle="All Finding Intelligence records for this exact IP address or hostname", findings=findings, summary={"targets": 1, "findings": len(rows), "risks": 0}, scope_note="Host-specific export. CVE results are candidates. MITRE ATT&CK mappings are analyst-reviewed; unmapped items are not inferred.")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", host).strip("._-")[:80] or "target"
    return Response(pdf, mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename=shadow-map-host-{safe}-findings.pdf"})


@automatic_risks_bp.route("/finding-intelligence", methods=["GET", "POST"])
def finding_intelligence_page():
    initialize_automatic_risks()
    allowed_confidence = {"Unassessed", "Low", "Medium", "High"}
    allowed_status = {"Unreviewed", "Needs-validation", "Evidence-supported", "Rejected"}
    if request.method == "POST":
        try:
            finding_id = int(request.form.get("finding_id", ""))
        except (TypeError, ValueError):
            abort(400)
        return_host = (request.form.get("return_host") or "").strip()[:255]

        def review_redirect():
            if return_host:
                matching = _intelligence_query(
                    {"host": return_host, "finding_id": finding_id},
                    limit=1,
                )
                if matching:
                    return redirect(url_for(
                        "automatic_risks.finding_intelligence_host_report",
                        host=return_host,
                        finding=finding_id,
                    ))
            return redirect(url_for(
                "automatic_risks.finding_intelligence_page",
                finding=finding_id,
            ))

        cve_ids = (request.form.get("cve_ids") or "").strip().upper()[:1000]
        cve_values = [v.strip() for v in cve_ids.split(",") if v.strip()]
        if any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", value) for value in cve_values):
            flash("Use valid CVE identifiers, separated by commas (for example CVE-2024-1234).", "error")
            return review_redirect()
        cve_ids = ", ".join(dict.fromkeys(cve_values))
        owasp = (request.form.get("owasp_category") or "").strip()[:160]
        tactic = (request.form.get("mitre_tactic") or "").strip()[:100]
        technique = (request.form.get("mitre_technique") or "").strip().upper()[:32]
        rationale = (request.form.get("mapping_rationale") or "").strip()[:4000]
        confidence = request.form.get("mapping_confidence", "Unassessed")
        status = request.form.get("validation_status", "Unreviewed")
        reference = (request.form.get("source_reference") or "").strip()[:500]
        if confidence not in allowed_confidence or status not in allowed_status:
            abort(400)
        catalogue_notice = None

        if technique and not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
            flash("MITRE technique must use an ID such as T1190 or T1059.001.", "error")
            return review_redirect()

        if technique:
            try:
                catalogue_version = get_latest_attack_version()

                if catalogue_version:
                    catalogue_technique = get_attack_technique(
                        technique,
                        version=catalogue_version,
                    )

                    if catalogue_technique is None:
                        flash(
                            f"{technique} is not present in the imported "
                            f"MITRE ATT&CK Enterprise catalogue ({catalogue_version}).",
                            "error",
                        )
                        return review_redirect()

                    if catalogue_technique["revoked"]:
                        flash(
                            f"{technique} is revoked in ATT&CK {catalogue_version} "
                            "and cannot be used for a new analyst mapping.",
                            "error",
                        )
                        return review_redirect()

                    if catalogue_technique["deprecated"]:
                        catalogue_notice = (
                            f"{technique} is deprecated in ATT&CK "
                            f"{catalogue_version}. The mapping was retained "
                            "for historical accuracy."
                        )
                else:
                    catalogue_notice = (
                        "No MITRE ATT&CK catalogue has been imported. "
                        "The technique ID was saved as unverified."
                    )

            except (sqlite3.Error, OSError):
                flash(
                    "MITRE ATT&CK catalogue validation failed because "
                    "the catalogue database could not be read. "
                    "The analyst mapping was not saved.",
                    "error",
                )
                return review_redirect()
        if reference:
            from urllib.parse import urlsplit
            parsed = urlsplit(reference)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
                flash("Source reference must be a valid HTTP or HTTPS URL without credentials.", "error")
                return review_redirect()
        with connect_db() as db:
            exists = db.execute("SELECT id FROM draft_findings WHERE id = ?", (finding_id,)).fetchone()
            if exists is None:
                abort(404)
            _ensure_intelligence_row(db, finding_id)
            db.execute("""UPDATE finding_intelligence SET cve_ids=?, owasp_category=?, mitre_tactic=?, mitre_technique=?, mapping_rationale=?, mapping_confidence=?, validation_status=?, source_reference=?, updated_at=? WHERE finding_id=?""", (cve_ids, owasp, tactic, technique, rationale, confidence, status, reference, utc_now(), finding_id))
        flash("Analyst intelligence metadata saved.", "success")
        if catalogue_notice:
            flash(catalogue_notice, "warning")
        return review_redirect()
    search = (request.args.get("q") or "").strip()[:255]
    hosts = _host_register_rows(search)

    return render_template(
        "finding_intelligence.html",
        hosts=hosts,
        search=search,
        nav_items=get_nav_items(),
        active_page="automatic_risks.finding_intelligence_page",
    )


@automatic_risks_bp.route("/findings")
def findings_page():
    status_filter = request.args.get("status", "Draft")
    allowed_statuses = {"Draft", "Approved", "Dismissed", "All"}
    if status_filter not in allowed_statuses:
        status_filter = "Draft"

    source_filter = request.args.get("source", "all")
    allowed_sources = {"all", "nmap", "web_security", "threat_intel", "zap"}
    if source_filter not in allowed_sources:
        source_filter = "all"

    scan_filter = (request.args.get("scan_id") or "").strip()
    scan_source = None
    scan_record_id = None
    if scan_filter:
        try:
            scan_source, raw_scan_id = scan_filter.split(":", 1)
            scan_record_id = int(raw_scan_id)
            if scan_source not in allowed_sources - {"all"} or scan_record_id < 1:
                raise ValueError
        except (ValueError, TypeError):
            scan_filter = ""
            scan_source = None
            scan_record_id = None

    search_query = (request.args.get("q") or "").strip()[:200]
    requested_hosts = request.args.getlist("host")[:100]

    per_page = 15
    try:
        current_page = max(1, int(request.args.get("page", "1")))
    except (TypeError, ValueError):
        current_page = 1

    with connect_db() as db:
        available_scans = db.execute("""
            SELECT 'nmap' AS source, id AS source_record_id, target
            FROM nmap_scans
            UNION ALL
            SELECT 'web_security', id, target
            FROM web_security_scans
            UNION ALL
            SELECT 'threat_intel', id, target
            FROM threat_intel_lookups
            ORDER BY source, source_record_id DESC
        """).fetchall()

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

        # Group web-page URLs by website origin for filtering only.
        target_groups = group_targets(
            (row["target"] or "").strip() for row in target_rows
        )
        available_targets = [group["label"] for group in target_groups]

        requested_keys = {
            requested.strip().casefold() for requested in requested_hosts
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

        conditions = []
        params = []

        if status_filter != "All":
            conditions.append("status = ?")
            params.append(status_filter)

        if source_filter != "all":
            conditions.append("source = ?")
            params.append(source_filter)

        if scan_source is not None:
            conditions.extend(["source = ?", "source_record_id = ?"])
            params.extend([scan_source, scan_record_id])

        if selected_target_values:
            placeholders = ",".join(
                "?" for _ in selected_target_values
            )
            conditions.append(
                f"LOWER(TRIM(target)) IN ({placeholders})"
            )
            params.extend(
                target.casefold() for target in selected_target_values
            )

        if search_query:
            conditions.append("(target LIKE ? OR title LIKE ?)")
            pattern = f"%{search_query}%"
            params.extend([pattern, pattern])

        where_clause = (
            "WHERE " + " AND ".join(conditions)
            if conditions else ""
        )

        matching_count = db.execute(
            f"SELECT COUNT(*) FROM draft_findings {where_clause}",
            params,
        ).fetchone()[0]

        page_count = max(1, (matching_count + per_page - 1) // per_page)
        current_page = min(current_page, page_count)
        offset = (current_page - 1) * per_page

        findings = db.execute(
            f"""
                SELECT * FROM draft_findings
                {where_clause}
                ORDER BY id DESC
                LIMIT ? OFFSET ?
            """,
            params + [per_page, offset],
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
        matching_count=matching_count,
        current_page=current_page,
        page_count=page_count,
        per_page=per_page,
        counts=counts,
        status_filter=status_filter,
        source_filter=source_filter,
        scan_filter=scan_filter,
        available_scans=available_scans,
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


def sync_cve_exposures_to_findings(database_path=None, asset_key=None):
    """Synchronize local CVE exposure intelligence into GRC draft findings.

    One stable finding is maintained per CVE and asset. Version matches and
    unassessed observations remain explicitly unconfirmed. Existing finding
    status and manually maintained intelligence fields are preserved.
    """
    db_path = database_path or DATABASE_PATH
    db = sqlite3.connect(db_path, timeout=15)
    db.row_factory = sqlite3.Row

    now = utc_now()
    created = 0
    updated = 0
    synchronized = 0

    try:
        query = """
            SELECT
                e.id AS exposure_id,
                e.cve_id,
                e.asset_key,
                e.observation_id,
                e.match_status,
                e.confidence,
                e.evidence_json,
                e.first_detected_at,
                e.last_checked_at,
                v.description AS cve_description,
                v.severity,
                v.cvss_version,
                v.cvss_score,
                v.references_json,
                v.is_kev,
                v.epss_score,
                v.epss_percentile,
                v.epss_date,
                v.kev_date_added,
                v.kev_due_date,
                v.kev_required_action
            FROM vulnerability_exposures e
            JOIN vulnerability_records v ON v.cve_id = e.cve_id
        """
        parameters = []

        if asset_key:
            query += " WHERE e.asset_key = ?"
            parameters.append(asset_key)

        query += " ORDER BY e.asset_key, e.cve_id"

        exposures = db.execute(query, parameters).fetchall()

        for exposure in exposures:
            try:
                evidence = json.loads(exposure["evidence_json"] or "{}")
            except (TypeError, ValueError):
                evidence = {}

            if not isinstance(evidence, dict):
                evidence = {}

            cve_id = exposure["cve_id"]
            current_status = exposure["match_status"] or "Unassessed"
            confidence = exposure["confidence"] or "Unassessed"
            target = str(evidence.get("target") or exposure["asset_key"])
            product = str(evidence.get("product") or "Unknown product")
            version = str(evidence.get("detected_version") or "Unknown version")
            service = str(evidence.get("service") or "Unknown service")
            port = evidence.get("port")
            protocol = str(evidence.get("protocol") or "")
            is_kev = bool(exposure["is_kev"])

            if current_status in ("Unassessed", "Not Matched"):
                # Historical update path: if a per-CVE finding already exists
                # (e.g. transitioned from Version Match), update it in place
                # rather than creating a grouped duplicate.
                _cve_fp_source = (
                    f"local_cve_intelligence|{exposure['asset_key']}|{cve_id}"
                )
                _cve_fp = hashlib.sha256(
                    _cve_fp_source.encode("utf-8")
                ).hexdigest()
                _existing = db.execute(
                    "SELECT id FROM draft_findings WHERE fingerprint = ?",
                    (_cve_fp,),
                ).fetchone()

                if _existing:
                    fingerprint_source = _cve_fp_source
                else:
                    fingerprint_source = (
                        f"local_cve_intelligence|{exposure['asset_key']}|{product}|{current_status}"
                    )
            else:
                fingerprint_source = (
                    f"local_cve_intelligence|{exposure['asset_key']}|{cve_id}"
                )
            fingerprint = hashlib.sha256(
                fingerprint_source.encode("utf-8")
            ).hexdigest()

            if current_status == "Version Match":
                state_label = "Potential version match"
                description = (
                    f"Local software fingerprinting identified {product} "
                    f"version {version} on asset {target}, which matches "
                    f"the locally stored affected-version criteria for "
                    f"{cve_id}. This is a potential exposure, not proof "
                    "that the vulnerability is exploitable, present in the "
                    "deployed build, or unmitigated. Verify vendor guidance, "
                    "package provenance, configuration, and patch state."
                )
            elif current_status == "Not Matched":
                state_label = "No current version match"
                description = (
                    f"The latest available observation for {product} on "
                    f"{target} no longer matches the locally stored "
                    f"affected-version criteria for {cve_id}. This updates "
                    "the historical intelligence record; it does not prove "
                    "that the asset is remediated or that no vulnerable "
                    "component remains."
                )
            else:
                state_label = "Unassessed software observation"
                description = (
                    f"Asset {target} has an observation associated with "
                    f"{service}, but available product/version evidence "
                    f"is insufficient to assess {cve_id}. This is an "
                    "unassessed intelligence lead, not a confirmed or "
                    "version-matched vulnerability."
                )

            title = (
                f"{cve_id} — {state_label}: {product} on {target}"
            )

            evidence_payload = {
                "assessment_type": "Passive local CVE correlation",
                "confirmation": False,
                "exposure_id": exposure["exposure_id"],
                "cve_id": cve_id,
                "asset_key": exposure["asset_key"],
                "target": target,
                "match_status": current_status,
                "confidence": confidence,
                "product": product,
                "detected_version": version,
                "service": service,
                "port": port,
                "protocol": protocol,
                "observation_id": exposure["observation_id"],
                "observation_source": evidence.get("source"),
                "supporting_observations": evidence.get(
                    "supporting_observations", []
                ),
                "severity": exposure["severity"] or "Unknown",
                "cvss_version": exposure["cvss_version"],
                "cvss_score": exposure["cvss_score"],
                "is_kev": is_kev,
                "epss_score": exposure["epss_score"],
                "epss_percentile": exposure["epss_percentile"],
                "epss_date": exposure["epss_date"],
                "kev_date_added": exposure["kev_date_added"],
                "kev_due_date": exposure["kev_due_date"],
                "kev_required_action": exposure["kev_required_action"],
                "cve_description": exposure["cve_description"],
                "references": [],
                "first_detected_at": exposure["first_detected_at"],
                "last_checked_at": exposure["last_checked_at"],
                "limitations": evidence.get("limitations", [
                    "Software fingerprinting may be incomplete or inaccurate.",
                    "Version correlation does not confirm vulnerability.",
                    "No exploitability or patch-state validation was performed.",
                ]),
            }

            try:
                references = json.loads(exposure["references_json"] or "[]")
                if isinstance(references, list):
                    evidence_payload["references"] = references[:30]
            except (TypeError, ValueError):
                pass

            evidence_text = json.dumps(
                evidence_payload, sort_keys=True
            )[:20000]

            severity = str(exposure["severity"] or "").strip().title()
            if severity not in {"Critical", "High", "Medium", "Low"}:
                severity = "Review"

            if current_status != "Version Match":
                severity = "Review"

            recommendation_parts = [
                f"Verify {cve_id} against the vendor's affected-version "
                "guidance and confirm the deployed package and patch state."
            ]
            if exposure["epss_score"] is not None:
                recommendation_parts.append(
                    "FIRST EPSS estimates a "
                    f"{float(exposure['epss_score']) * 100:.2f}% "
                    "probability of exploitation in the next 30 days. "
                    "Use this as a prioritisation signal alongside CVSS, "
                    "KEV status and the asset's business context."
                )
            if is_kev:
                recommendation_parts.append(
                    "This CVE is listed in CISA Known Exploited "
                    "Vulnerabilities; prioritize exposure and remediation "
                    "assessment. KEV listing does not prove this asset is "
                    "vulnerable."
                )
            recommendation_parts.append(
                "Confirm asset ownership and service exposure, then patch "
                "or apply vendor-recommended mitigations if affected."
            )
            recommendation = " ".join(recommendation_parts)

            finding = db.execute("""
                SELECT id, status
                FROM draft_findings
                WHERE fingerprint = ?
            """, (fingerprint,)).fetchone()

            if current_status == "Not Matched" and not finding:
                continue

            if finding is None:
                cursor = db.execute("""
                    INSERT INTO draft_findings (
                        source, source_record_id, fingerprint, target, title,
                        description, evidence, suggested_severity, confidence,
                        recommendation, iso_controls, status, created_at, updated_at
                    ) VALUES (
                        'local_cve_intelligence', ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        'A.8.8, A.8.9, A.8.20',
                        'Draft', ?, ?
                    )
                """, (
                    exposure["exposure_id"],
                    fingerprint,
                    target,
                    title,
                    description,
                    evidence_text,
                    severity,
                    confidence,
                    recommendation,
                    now,
                    now,
                ))
                finding_id = cursor.lastrowid
                created += 1
            else:
                finding_id = finding["id"]
                db.execute("""
                    UPDATE draft_findings
                    SET source_record_id = ?,
                        target = ?,
                        title = ?,
                        description = ?,
                        evidence = ?,
                        suggested_severity = ?,
                        confidence = ?,
                        recommendation = ?,
                        updated_at = ?
                    WHERE id = ?
                """, (
                    exposure["exposure_id"],
                    target,
                    title,
                    description,
                    evidence_text,
                    severity,
                    confidence,
                    recommendation,
                    now,
                    finding_id,
                ))
                updated += 1

            _ensure_intelligence_row(db, finding_id)

            auto_cve_ids = cve_id
            auto_match_details = json.dumps({
                "source": "local_cve_intelligence",
                "exposure_id": exposure["exposure_id"],
                "asset_key": exposure["asset_key"],
                "match_status": current_status,
                "confidence": confidence,
                "is_kev": is_kev,
                "last_checked_at": exposure["last_checked_at"],
                "confirmation": False,
            }, sort_keys=True)

            auto_owasp = (
                "A06:2021 – Vulnerable and Outdated Components"
                if current_status == "Version Match" else ""
            )

            db.execute("""
                UPDATE finding_intelligence
                SET local_cve_ids = ?,
                    local_cve_match_status = ?,
                    local_cve_match_details = ?,
                    local_cve_checked_at = ?,
                    local_owasp_category = ?,
                    local_security_category = ?,
                    local_source_summary = ?,
                    last_enriched_at = ?,
                    updated_at = ?
                WHERE finding_id = ?
            """, (
                auto_cve_ids,
                current_status,
                auto_match_details,
                exposure["last_checked_at"] or now,
                auto_owasp,
                "Vulnerability Intelligence",
                (
                    f"Local CVE database; {state_label}; "
                    f"KEV={'Yes' if is_kev else 'No'}"
                ),
                now,
                now,
                finding_id,
            ))

            synchronized += 1

        db.commit()

        return {
            "exposures_processed": len(exposures),
            "findings_created": created,
            "findings_updated": updated,
            "findings_synchronized": synchronized,
        }

    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def generate_web_security_drafts(result, source_record_id=None):
    """Create scan-linked, review-only HTTPS configuration observations."""
    target = (result.get("target") or "").strip()
    if not target:
        return 0

    status_code = result.get("status_code", "unknown")
    created = 0

    def make_fingerprint(source):
        if source_record_id is not None:
            source += f"|scan|{source_record_id}"
        return hashlib.sha256(source.encode("utf-8")).hexdigest()

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

            fingerprint_source = (
                f"web_security|{target.rstrip('/').lower()}|{header_name}"
                if not present else
                f"web_security|{target.rstrip('/').lower()}|{header_name}|{issue_type}"
            )
            fingerprint = make_fingerprint(fingerprint_source)

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
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Draft', ?, ?)
            """, (
                "web_security", source_record_id, fingerprint, target,
                title, description, evidence, "Review", "Low",
                recommendation, "", utc_now(), utc_now(),
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
                fingerprint = make_fingerprint(fingerprint_source)

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
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Draft', ?, ?)
                """, (
                    "web_security", source_record_id, fingerprint, target,
                    title, description, evidence, "Review", "Low",
                    recommendation, "", utc_now(), utc_now(),
                ))
                created += cursor.rowcount

        # 4. SQL Injection Findings
        sql_res = result.get("sql_injection_assessment") or {}
        for check in sql_res.get("checks", []):
            if check.get("status") == "suspected":
                param = check.get("parameter")
                loc = check.get("location")
                fingerprint_source = f"web_security|{target}|sqli|{param}"
                fingerprint = make_fingerprint(fingerprint_source)

                title = f"Potential SQL Injection on {target} (Parameter: {param})"
                description = "A database error signature was detected in the response to a modified request. This is a suspected vulnerability, not a confirmed exploit. Manual verification is required."
                evidence = f"Location: {loc}; Parameter: {param}; Probe: {check.get('probe')}; Indicators: {check.get('database_error_indicators')}"
                recommendation = "Review the application code for unsanitized input in this parameter. Use parameterized queries. Manually verify this finding."

                cursor = db.execute("""
                    INSERT OR IGNORE INTO draft_findings (
                        source, source_record_id, fingerprint, target, title,
                        description, evidence, suggested_severity, confidence,
                        recommendation, iso_controls, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Draft', ?, ?)
                """, (
                    "web_security", source_record_id, fingerprint, target,
                    title, description, evidence, "High", "Medium",
                    recommendation, "A.8.28", utc_now(), utc_now(),
                ))
                created += cursor.rowcount

        # 5. Cross-Site Scripting (XSS) Findings
        xss_res = result.get("reflected_input_assessment") or {}
        for check in xss_res.get("checks", []):
            if check.get("status") == "suspected":
                param = check.get("parameter")
                loc = check.get("location")
                fingerprint_source = f"web_security|{target}|xss|{param}"
                fingerprint = make_fingerprint(fingerprint_source)

                title = f"Potential Cross-Site Scripting (XSS) on {target} (Parameter: {param})"
                description = "A unique marker was sent in a request and was reflected in the response. Depending on the context, this could lead to Cross-Site Scripting. This is an unverified indicator, not a confirmed exploit."
                evidence = f"Location: {loc}; Parameter: {param}; Probe: {check.get('probe')}; Contexts: {check.get('contexts')}"
                recommendation = "Review the application context where the input is reflected. Ensure output encoding is correctly applied for the specific context (HTML, JavaScript, attribute). Manually verify this finding."

                cursor = db.execute("""
                    INSERT OR IGNORE INTO draft_findings (
                        source, source_record_id, fingerprint, target, title,
                        description, evidence, suggested_severity, confidence,
                        recommendation, iso_controls, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Draft', ?, ?)
                """, (
                    "web_security", source_record_id, fingerprint, target,
                    title, description, evidence, "High", "Low",
                    recommendation, "A.8.28", utc_now(), utc_now(),
                ))
                created += cursor.rowcount

        # 6. OWASP ZAP Alerts
        zap_alerts = result.get("zap_alerts", [])
        if zap_alerts:
            created += import_zap_alerts_to_drafts(zap_alerts)

        discovery = result.get("discovery") or {}
        api_endpoints = discovery.get("api_endpoints") or []
        forms = discovery.get("forms") or []

        if api_endpoints or forms:
            endpoint_evidence = [
                str(endpoint).strip()
                for endpoint in api_endpoints
                if isinstance(endpoint, str) and endpoint.strip()
            ]

            form_evidence = []
            for form in forms:
                if not isinstance(form, dict):
                    continue

                fields = form.get("fields") or []
                field_names = [
                    str(field.get("name")).strip()
                    for field in fields
                    if isinstance(field, dict) and field.get("name")
                ]

                form_evidence.append(
                    "page={page}; method={method}; action={action}; "
                    "encoding={encoding}; fields={fields}".format(
                        page=form.get("page") or "",
                        method=form.get("method") or "GET",
                        action=form.get("action") or "",
                        encoding=form.get("enctype") or "",
                        fields=", ".join(field_names) or "(none identified)",
                    )
                )

            if endpoint_evidence or form_evidence:
                fingerprint_source = (
                    f"web_security|{target.rstrip('/').lower()}|"
                    "attack-surface-review"
                )
                fingerprint = make_fingerprint(fingerprint_source)

                title = f"Review discovered web application attack surface on {target}"
                description = (
                    "The read-only web crawler identified API routes and/or "
                    "HTML forms. Their presence is attack-surface information, "
                    "not evidence of a vulnerability. Review authentication, "
                    "authorization, input validation, exposed functionality, "
                    "and the application's intended access requirements."
                )
                evidence_parts = [
                    f"Source: authorized read-only web discovery; target={target}",
                    f"HTTP status={status_code}",
                ]
                if endpoint_evidence:
                    evidence_parts.append(
                        "Likely API endpoints: " + "; ".join(endpoint_evidence[:100])
                    )
                if form_evidence:
                    evidence_parts.append(
                        "Observed forms: " + " | ".join(form_evidence[:100])
                    )
                evidence = "; ".join(evidence_parts)[:12000]

                recommendation = (
                    "Review discovered routes and forms against the approved "
                    "application inventory. Validate authentication, "
                    "authorization, input handling, and business logic using "
                    "approved assessment procedures. Record confirmed issues "
                    "separately with supporting evidence."
                )

                cursor = db.execute("""
                    INSERT OR IGNORE INTO draft_findings (
                        source, source_record_id, fingerprint, target, title,
                        description, evidence, suggested_severity, confidence,
                        recommendation, iso_controls, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Draft', ?, ?)
                """, (
                    "web_security", source_record_id, fingerprint, target,
                    title, description, evidence, "Review", "Low",
                    recommendation, "", utc_now(), utc_now(),
                ))
                created += cursor.rowcount

    return created


def import_zap_alerts_to_drafts(alerts):
    """Import existing ZAP alerts as review-only GRC drafts."""
    from urllib.parse import urlsplit

    if not isinstance(alerts, list):
        return 0

    def clean(value, limit=4000):
        if not isinstance(value, (str, int, float)):
            return ""
        return " ".join(str(value).replace("\x00", "").split())[:limit]

    def valid_target(value):
        try:
            parsed = urlsplit(value)
            return (
                parsed.scheme.lower() in ("http", "https")
                and bool(parsed.hostname)
                and parsed.username is None
                and parsed.password is None
            )
        except (TypeError, ValueError):
            return False

    risk_map = {
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Info",
        "info": "Info",
    }
    confidence_map = {
        "high": "High", "medium": "Medium", "low": "Low"
    }
    created = 0

    with connect_db() as db:
        for alert in alerts[:500]:
            if not isinstance(alert, dict):
                continue

            target = clean(alert.get("url"), 2048)
            if not target or not valid_target(target):
                continue

            name = clean(alert.get("name") or alert.get("alert"), 300)
            name = name or "Unnamed ZAP alert"
            plugin_id = clean(alert.get("pluginId"), 100)
            alert_id = clean(alert.get("alert"), 300)

            fingerprint_source = (
                f"zap|{target.rstrip('/')}|{plugin_id}|"
                f"{name.casefold()}|{alert_id.casefold()}"
            )
            fingerprint = hashlib.sha256(
                fingerprint_source.encode("utf-8")
            ).hexdigest()

            risk = clean(alert.get("risk"), 40)
            confidence_raw = clean(alert.get("confidence"), 40).lower()
            severity = risk_map.get(risk.lower(), "Review")
            confidence = confidence_map.get(confidence_raw, "Low")

            description = clean(alert.get("description"), 4000) or (
                "ZAP reported an alert without a description. "
                "Validate applicability before taking action."
            )
            solution = clean(alert.get("solution"), 4000) or (
                "Review the affected component and vendor guidance; "
                "verify the issue before choosing remediation."
            )
            evidence = (
                f"Source: OWASP ZAP existing alert; URL={target}; "
                f"risk={risk or 'Unknown'}; "
                f"confidence={clean(alert.get('confidence'), 40) or 'Unknown'}; "
                f"pluginId={plugin_id or 'not reported'}; "
                f"alert={alert_id or name}"
            )[:5000]

            cursor = db.execute("""
                INSERT OR IGNORE INTO draft_findings (
                    source, source_record_id, fingerprint, target, title,
                    description, evidence, suggested_severity, confidence,
                    recommendation, iso_controls, status, created_at, updated_at
                ) VALUES (
                    'zap', NULL, ?, ?, ?, ?, ?, ?, ?, ?, '',
                    'Draft', ?, ?
                )
            """, (
                fingerprint, target, f"Review ZAP alert: {name}"[:500],
                description, evidence, severity, confidence, solution,
                utc_now(), utc_now(),
            ))
            created += cursor.rowcount

    return created


def generate_firewall_drafts(result, source_record_id=None):
    """Create review-only findings for directly observed open TCP ports."""
    if not isinstance(result, dict) or not source_record_id:
        return 0

    target = str(result.get("target") or "").strip()
    tcp = result.get("tcp") or {}
    ports = tcp.get("ports", [])

    if not target or not isinstance(ports, list):
        return 0

    created = 0

    with connect_db() as db:
        for item in ports:
            if not isinstance(item, dict):
                continue

            if (
                str(item.get("state", "")).lower() != "open"
                or str(item.get("protocol", "tcp")).lower() != "tcp"
            ):
                continue

            port = item.get("port")
            address = str(item.get("address") or "").strip()

            if type(port) is not int or not 1 <= port <= 65535:
                continue

            fingerprint_source = (
                f"firewall|{source_record_id}|{address}|tcp|{port}"
            )
            fingerprint = hashlib.sha256(
                fingerprint_source.encode("utf-8")
            ).hexdigest()

            title = f"Review exposed TCP port {port} on {target}"
            description = (
                f"The Firewall Detection assessment established a TCP "
                f"connection to port {port} on {address or target}. "
                "This is an exposure observation, not proof of a "
                "vulnerability or an incorrectly configured firewall. "
                "Confirm the service purpose, ownership, and intended "
                "network accessibility."
            )
            evidence = (
                f"Source: Shadow Map GRC Firewall Detection; "
                f"scan_record_id={source_record_id}; target={target}; "
                f"address={address or 'not reported'}; protocol=tcp; "
                f"port={port}; state=open; "
                f"reason={item.get('reason') or 'not reported'}"
            )
            recommendation = (
                "Identify the listening service and its business owner. "
                "Confirm that external or network access is required, "
                "restrict access to approved sources where appropriate, "
                "and document the exposure decision."
            )

            cursor = db.execute("""
                INSERT OR IGNORE INTO draft_findings (
                    source, source_record_id, fingerprint, target, title,
                    description, evidence, suggested_severity, confidence,
                    recommendation, iso_controls, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Draft', ?, ?)
            """, (
                "firewall",
                source_record_id,
                fingerprint,
                target,
                title,
                description,
                evidence,
                "Review",
                "Low",
                recommendation,
                "A.8.20, A.8.21",
                utc_now(),
                utc_now(),
            ))
            created += cursor.rowcount

    return created
