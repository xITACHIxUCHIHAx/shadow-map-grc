"""Versioned MITRE ATT&CK catalogue parsing, storage and import."""

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from config import DATABASE_PATH


FRAMEWORK_ID = "mitre-attack"
FRAMEWORK_NAME = "MITRE ATT&CK"
DEFAULT_DOMAIN = "enterprise-attack"

TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
TACTIC_ID_PATTERN = re.compile(r"^TA\d{4}$")


def _valid_attack_id(value, pattern):
    return isinstance(value, str) and bool(pattern.fullmatch(value))



def _external_attack_id(obj, expected_type):
    """Return and validate the MITRE ATT&CK external ID."""
    references = obj.get("external_references", [])

    if not isinstance(references, list):
        raise ValueError("Invalid external_references metadata.")

    pattern = (
        TACTIC_ID_PATTERN
        if expected_type == "tactic"
        else TECHNIQUE_ID_PATTERN
    )

    matching = [
        reference
        for reference in references
        if isinstance(reference, dict)
        and reference.get("source_name") == "mitre-attack"
    ]

    if not matching:
        return None

    if len(matching) != 1:
        raise ValueError("Duplicate MITRE ATT&CK external references.")

    external_id = matching[0].get("external_id")
    if not _valid_attack_id(external_id, pattern):
        raise ValueError(
            f"Object has an invalid MITRE ATT&CK external ID: {external_id!r}"
        )

    return external_id


def _require_boolean(obj, field, default=False):
    """Require an actual JSON boolean for an optional STIX flag."""
    value = obj.get(field, default)
    if not isinstance(value, bool):
        raise ValueError(f"STIX field {field} must be a boolean.")
    return value


def parse_attack_stix(document, domain=DEFAULT_DOMAIN):
    """Validate and extract Enterprise ATT&CK data without database writes."""
    if not isinstance(document, dict):
        raise ValueError("STIX document must be a JSON object.")

    if document.get("type") != "bundle":
        raise ValueError("STIX document must be a bundle.")

    objects = document.get("objects")
    if not isinstance(objects, list):
        raise ValueError("STIX bundle must contain an objects list.")

    if domain != DEFAULT_DOMAIN:
        raise ValueError("Only Enterprise ATT&CK domain is supported.")

    tactics = {}
    techniques = {}
    relationships = set()
    tactic_short_names = {}

    for obj in objects:
        if not isinstance(obj, dict):
            raise ValueError("STIX bundle contains a non-object entry.")

        object_type = obj.get("type")

        if object_type == "x-mitre-tactic":
            tactic_id = _external_attack_id(obj, "tactic")
            if not tactic_id:
                continue

            short_name = obj.get("x_mitre_shortname")
            name = obj.get("name")

            if not isinstance(short_name, str) or not short_name.strip():
                raise ValueError(f"Tactic {tactic_id} has no short name.")
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"Tactic {tactic_id} has no name.")

            short_name = short_name.strip()
            if tactic_id in tactics:
                raise ValueError(f"Duplicate tactic ID: {tactic_id}")
            if short_name in tactic_short_names:
                raise ValueError(
                    f"Duplicate tactic short name: {short_name}"
                )

            tactic_short_names[short_name] = tactic_id
            tactics[tactic_id] = {
                "tactic_id": tactic_id,
                "name": name.strip(),
                "short_name": short_name,
                "description": obj.get("description") or "",
                "url": next(
                    (
                        ref.get("url", "")
                        for ref in obj.get("external_references", [])
                        if isinstance(ref, dict)
                        and ref.get("source_name") == "mitre-attack"
                    ),
                    "",
                ),
            }

        elif object_type == "attack-pattern":
            domains = obj.get("x_mitre_domains", [])
            if not isinstance(domains, list) or not all(
                isinstance(item, str) for item in domains
            ):
                raise ValueError(
                    "Technique has invalid x_mitre_domains metadata."
                )

            if domain not in domains:
                continue

            technique_id = _external_attack_id(obj, "technique")
            if not technique_id:
                continue

            name = obj.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ValueError(
                    f"Technique {technique_id} has no name."
                )
            if technique_id in techniques:
                raise ValueError(
                    f"Duplicate technique ID: {technique_id}"
                )

            is_subtechnique = _require_boolean(
                obj, "x_mitre_is_subtechnique"
            )
            deprecated = _require_boolean(
                obj, "x_mitre_deprecated"
            )
            revoked = _require_boolean(obj, "revoked")

            if is_subtechnique != ("." in technique_id):
                raise ValueError(
                    f"Sub-technique flag does not match ID {technique_id}."
                )

            parent_id = (
                technique_id.split(".", 1)[0]
                if is_subtechnique
                else None
            )

            external_url = next(
                (
                    ref.get("url", "")
                    for ref in obj.get("external_references", [])
                    if isinstance(ref, dict)
                    and ref.get("source_name") == "mitre-attack"
                ),
                "",
            )

            techniques[technique_id] = {
                "technique_id": technique_id,
                "name": name.strip(),
                "description": obj.get("description") or "",
                "url": external_url,
                "is_subtechnique": int(is_subtechnique),
                "parent_technique_id": parent_id,
                "deprecated": int(deprecated),
                "revoked": int(revoked),
                "tactic_short_names": set(),
            }

            phases = obj.get("kill_chain_phases", [])
            if not isinstance(phases, list):
                raise ValueError(
                    f"Technique {technique_id} has invalid kill chain phases."
                )

            for phase in phases:
                if not isinstance(phase, dict):
                    raise ValueError(
                        f"Technique {technique_id} has an invalid phase."
                    )

                if phase.get("kill_chain_name") == "mitre-attack":
                    short_name = phase.get("phase_name")
                    if not isinstance(short_name, str) or not short_name:
                        raise ValueError(
                            f"Technique {technique_id} has an invalid ATT&CK tactic phase."
                        )
                    techniques[technique_id][
                        "tactic_short_names"
                    ].add(short_name)

    for technique_id, technique in techniques.items():
        parent_id = technique["parent_technique_id"]

        if parent_id and parent_id not in techniques:
            raise ValueError(
                f"Missing parent technique {parent_id} "
                f"for {technique_id}."
            )

        if parent_id and techniques[parent_id]["is_subtechnique"]:
            raise ValueError(
                f"Sub-technique {technique_id} has a sub-technique parent."
            )

        for short_name in technique.pop("tactic_short_names"):
            tactic_id = tactic_short_names.get(short_name)
            if tactic_id is None:
                raise ValueError(
                    f"Technique {technique_id} references unknown ATT&CK tactic: {short_name}"
                )
            relationships.add((technique_id, tactic_id))

    return {
        "domain": domain,
        "tactics": list(tactics.values()),
        "techniques": list(techniques.values()),
        "relationships": sorted(relationships),
    }


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def initialize_attack_catalogue(database_path=None):
    """Create the versioned ATT&CK catalogue schema safely and idempotently."""
    path = database_path if database_path is not None else DATABASE_PATH
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row

    try:
        db.execute("PRAGMA foreign_keys = OFF")
        db.execute("BEGIN IMMEDIATE")

        db.execute("""
            CREATE TABLE IF NOT EXISTS attack_frameworks (
                framework_id TEXT NOT NULL,
                version TEXT NOT NULL,
                framework_name TEXT NOT NULL,
                domain TEXT NOT NULL,
                release_date TEXT NOT NULL DEFAULT '',
                source_reference TEXT NOT NULL DEFAULT '',
                imported_at TEXT NOT NULL,
                PRIMARY KEY (framework_id, version)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS attack_tactics (
                framework_id TEXT NOT NULL,
                version TEXT NOT NULL,
                tactic_id TEXT NOT NULL,
                name TEXT NOT NULL,
                short_name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                url TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (framework_id, version, tactic_id),
                FOREIGN KEY (framework_id, version)
                    REFERENCES attack_frameworks(framework_id, version)
                    ON DELETE CASCADE
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS attack_techniques (
                framework_id TEXT NOT NULL,
                version TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                url TEXT NOT NULL DEFAULT '',
                is_subtechnique INTEGER NOT NULL DEFAULT 0
                    CHECK (is_subtechnique IN (0, 1)),
                parent_technique_id TEXT,
                deprecated INTEGER NOT NULL DEFAULT 0
                    CHECK (deprecated IN (0, 1)),
                revoked INTEGER NOT NULL DEFAULT 0
                    CHECK (revoked IN (0, 1)),
                PRIMARY KEY (framework_id, version, technique_id),
                FOREIGN KEY (framework_id, version)
                    REFERENCES attack_frameworks(framework_id, version)
                    ON DELETE CASCADE,
                FOREIGN KEY (
                    framework_id, version, parent_technique_id
                )
                    REFERENCES attack_techniques(
                        framework_id, version, technique_id
                    )
                    ON DELETE CASCADE
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS attack_technique_tactics (
                framework_id TEXT NOT NULL,
                version TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                tactic_id TEXT NOT NULL,
                PRIMARY KEY (
                    framework_id, version, technique_id, tactic_id
                ),
                FOREIGN KEY (framework_id, version, technique_id)
                    REFERENCES attack_techniques(
                        framework_id, version, technique_id
                    )
                    ON DELETE CASCADE,
                FOREIGN KEY (framework_id, version, tactic_id)
                    REFERENCES attack_tactics(
                        framework_id, version, tactic_id
                    )
                    ON DELETE CASCADE
            )
        """)

        # Migrate older databases whose parent-technique foreign key
        # still uses ON DELETE RESTRICT.
        parent_fk = [
            row for row in db.execute(
                "PRAGMA foreign_key_list(attack_techniques)"
            )
            if row[2] == "attack_techniques"
            and row[3] == "parent_technique_id"
        ]

        if parent_fk and parent_fk[0][6].upper() != "CASCADE":
            db.execute("""
                CREATE TABLE attack_techniques_new (
                    framework_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    technique_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    url TEXT NOT NULL DEFAULT '',
                    is_subtechnique INTEGER NOT NULL DEFAULT 0
                        CHECK (is_subtechnique IN (0, 1)),
                    parent_technique_id TEXT,
                    deprecated INTEGER NOT NULL DEFAULT 0
                        CHECK (deprecated IN (0, 1)),
                    revoked INTEGER NOT NULL DEFAULT 0
                        CHECK (revoked IN (0, 1)),
                    PRIMARY KEY (framework_id, version, technique_id),
                    FOREIGN KEY (framework_id, version)
                        REFERENCES attack_frameworks(framework_id, version)
                        ON DELETE CASCADE,
                    FOREIGN KEY (
                        framework_id, version, parent_technique_id
                    )
                        REFERENCES attack_techniques_new(
                            framework_id, version, technique_id
                        )
                        ON DELETE CASCADE
                )
            """)

            db.execute("""
                INSERT INTO attack_techniques_new (
                    framework_id, version, technique_id, name,
                    description, url, is_subtechnique,
                    parent_technique_id, deprecated, revoked
                )
                SELECT
                    framework_id, version, technique_id, name,
                    description, url, is_subtechnique,
                    parent_technique_id, deprecated, revoked
                FROM attack_techniques
            """)

            db.execute("DROP TABLE attack_techniques")
            db.execute("""
                ALTER TABLE attack_techniques_new
                RENAME TO attack_techniques
            """)

        db.execute("PRAGMA foreign_key_check")
        violations = db.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise sqlite3.IntegrityError(
                f"ATT&CK catalogue migration found foreign-key violations: "
                f"{violations[:5]}"
            )

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_attack_techniques_name
            ON attack_techniques(framework_id, version, name)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_attack_techniques_parent
            ON attack_techniques(
                framework_id, version, parent_technique_id
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_attack_technique_tactics_tactic
            ON attack_technique_tactics(
                framework_id, version, tactic_id
            )
        """)

        db.commit()
        db.execute("PRAGMA foreign_keys = ON")
        return True

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def import_attack_stix(
    document,
    version,
    database_path=None,
    release_date="",
    source_reference="",
):
    """Import one Enterprise ATT&CK release atomically."""
    if not isinstance(version, str) or not version.strip():
        raise ValueError("An explicit ATT&CK framework version is required.")

    version = version.strip()

    # Parse and validate everything before opening the write transaction.
    catalogue = parse_attack_stix(document)

    initialize_attack_catalogue(database_path)

    path = database_path if database_path is not None else DATABASE_PATH
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row

    try:
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("BEGIN IMMEDIATE")

        existing = db.execute(
            """
            SELECT 1 FROM attack_frameworks
            WHERE framework_id = ? AND version = ?
            """,
            (FRAMEWORK_ID, version),
        ).fetchone()

        if existing:
            raise ValueError(
                f"ATT&CK version {version} is already imported."
            )

        db.execute(
            """
            INSERT INTO attack_frameworks (
                framework_id, version, framework_name, domain,
                release_date, source_reference, imported_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                FRAMEWORK_ID,
                version,
                FRAMEWORK_NAME,
                catalogue["domain"],
                release_date,
                source_reference,
                _utc_now(),
            ),
        )

        db.executemany(
            """
            INSERT INTO attack_tactics (
                framework_id, version, tactic_id, name,
                short_name, description, url
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    FRAMEWORK_ID,
                    version,
                    item["tactic_id"],
                    item["name"],
                    item["short_name"],
                    item["description"],
                    item["url"],
                )
                for item in catalogue["tactics"]
            ],
        )

        # Parents must exist before their sub-techniques.
        ordered_techniques = sorted(
            catalogue["techniques"],
            key=lambda item: (
                item["is_subtechnique"],
                item["technique_id"],
            ),
        )

        db.executemany(
            """
            INSERT INTO attack_techniques (
                framework_id, version, technique_id, name,
                description, url, is_subtechnique,
                parent_technique_id, deprecated, revoked
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    FRAMEWORK_ID,
                    version,
                    item["technique_id"],
                    item["name"],
                    item["description"],
                    item["url"],
                    item["is_subtechnique"],
                    item["parent_technique_id"],
                    item["deprecated"],
                    item["revoked"],
                )
                for item in ordered_techniques
            ],
        )

        db.executemany(
            """
            INSERT INTO attack_technique_tactics (
                framework_id, version, technique_id, tactic_id
            ) VALUES (?, ?, ?, ?)
            """,
            [
                (
                    FRAMEWORK_ID,
                    version,
                    technique_id,
                    tactic_id,
                )
                for technique_id, tactic_id
                in catalogue["relationships"]
            ],
        )

        violations = db.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

        if violations:
            raise sqlite3.IntegrityError(
                f"ATT&CK import produced foreign-key violations: "
                f"{violations[:5]}"
            )

        db.commit()

        return {
            "framework_id": FRAMEWORK_ID,
            "version": version,
            "domain": catalogue["domain"],
            "tactics_imported": len(catalogue["tactics"]),
            "techniques_imported": len(catalogue["techniques"]),
            "relationships_imported": len(catalogue["relationships"]),
            "status": "success",
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()



MAX_STIX_FILE_BYTES = 100 * 1024 * 1024


def load_attack_stix_file(path):
    """Load and validate a local STIX JSON file without importing it."""
    try:
        file_path = Path(path)
        file_size = file_path.stat().st_size

        if file_size <= 0:
            raise ValueError("STIX file is empty.")

        if file_size > MAX_STIX_FILE_BYTES:
            raise ValueError(
                "STIX file exceeds the 100 MB size limit."
            )

        with file_path.open("r", encoding="utf-8") as handle:
            document = json.load(handle)

    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Unable to read valid STIX JSON file: {exc}"
        ) from exc
    except ValueError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ValueError(
            f"Unable to read valid STIX JSON file: {exc}"
        ) from exc

    # Validate structure and Enterprise ATT&CK content.
    parse_attack_stix(document)

    return document


def import_attack_stix_file(
    path,
    version,
    database_path=None,
    release_date="",
    source_reference="",
):
    """Load a local STIX file and import it as a versioned release."""
    document = load_attack_stix_file(path)

    return import_attack_stix(
        document,
        version,
        database_path=database_path,
        release_date=release_date,
        source_reference=source_reference,
    )


def get_latest_attack_version(database_path=None):
    """Return the most recently imported Enterprise ATT&CK version."""
    path = database_path if database_path is not None else DATABASE_PATH
    db = sqlite3.connect(path, timeout=15)

    try:
        row = db.execute(
            """
            SELECT version
            FROM attack_frameworks
            WHERE framework_id = ? AND domain = ?
            ORDER BY imported_at DESC, version DESC
            LIMIT 1
            """,
            (FRAMEWORK_ID, DEFAULT_DOMAIN),
        ).fetchone()

        return row[0] if row else None
    finally:
        db.close()


def get_attack_technique(technique_id, version=None, database_path=None):
    """Retrieve a technique and its catalogue status."""
    if not _valid_attack_id(technique_id, TECHNIQUE_ID_PATTERN):
        return None

    path = database_path if database_path is not None else DATABASE_PATH
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row

    try:
        selected_version = version or get_latest_attack_version(database_path)
        if not selected_version:
            return None

        row = db.execute(
            """
            SELECT
                technique_id, name, description, url,
                is_subtechnique, parent_technique_id,
                deprecated, revoked
            FROM attack_techniques
            WHERE framework_id = ? AND version = ?
              AND technique_id = ?
            """,
            (FRAMEWORK_ID, selected_version, technique_id),
        ).fetchone()

        return dict(row) if row else None
    finally:
        db.close()
