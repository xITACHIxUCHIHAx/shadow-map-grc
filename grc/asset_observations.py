"""Normalize and store asset fingerprints from existing scan results."""

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit


def _now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean(value):
    if value is None:
        return ""
    return str(value).strip()[:512]


def _asset_identity(target):
    """Return a stable asset key and display target."""
    raw_target = _clean(target)
    parsed = urlsplit(
        raw_target if "://" in raw_target else f"//{raw_target}"
    )
    host = (parsed.hostname or raw_target).strip().lower().rstrip(".")

    if not host:
        host = "unknown"

    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        pass

    return f"host:{host}", host


def _confidence(value):
    value = _clean(value).lower()

    if value in {"high", "medium", "low"}:
        return value.title()
    if value == "likely":
        return "Medium"
    if value == "possible":
        return "Low"
    return "Unassessed"


def _store_observation(
    db,
    *,
    asset_key,
    target,
    source,
    source_record_id,
    vendor="",
    product="",
    version="",
    service="",
    port=None,
    protocol="",
    confidence="Unassessed",
    evidence=None,
    observed_at=None,
):
    """Insert or refresh one deterministic observation."""
    product = _clean(product)
    version = _clean(version)

    # Do not let protocol dialects masquerade as software versions.
    if _clean(service).lower() in {"smb", "rdp", "dns"}:
        version = ""

    normalized = {
        "asset_key": asset_key,
        "source": _clean(source).lower(),
        "protocol": _clean(protocol).lower(),
        "port": port,
        "service": _clean(service).lower(),
        "vendor": _clean(vendor),
        "product": product,
        "version": version,
    }
    fingerprint = hashlib.sha256(
        json.dumps(
            normalized, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()

    timestamp = observed_at or _now_utc()
    evidence_json = json.dumps(
        evidence if isinstance(evidence, (dict, list)) else {},
        ensure_ascii=False,
        sort_keys=True,
    )

    db.execute(
        """
        INSERT INTO asset_observations (
            asset_key, asset_type, target, source, source_record_id,
            vendor, product, version, service, port, protocol,
            observed_at, confidence, evidence_json, fingerprint, created_at
        )
        VALUES (?, 'Host', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint) DO UPDATE SET
            target = excluded.target,
            source_record_id = excluded.source_record_id,
            vendor = excluded.vendor,
            product = excluded.product,
            version = excluded.version,
            service = excluded.service,
            observed_at = excluded.observed_at,
            confidence = excluded.confidence,
            evidence_json = excluded.evidence_json
        """,
        (
            asset_key,
            _clean(target),
            normalized["source"],
            _clean(source_record_id),
            _clean(vendor),
            product,
            version,
            _clean(service),
            port if type(port) is int and 1 <= port <= 65535 else None,
            normalized["protocol"],
            timestamp,
            _confidence(confidence),
            evidence_json,
            fingerprint,
            timestamp,
        ),
    )

    row = db.execute(
        "SELECT id FROM asset_observations WHERE fingerprint = ?",
        (fingerprint,),
    ).fetchone()
    return row["id"]


def ingest_nmap_observations(
    db, target, result, observed_at=None, source_record_id=""
):
    """Store open-port Nmap service and software observations."""
    if not isinstance(result, dict):
        return []

    asset_key, display_target = _asset_identity(target)
    observations = []

    for item in result.get("ports", []):
        if not isinstance(item, dict) or item.get("state") != "open":
            continue

        port = item.get("port")
        protocol = _clean(item.get("protocol")).lower()
        if type(port) is not int or not 1 <= port <= 65535:
            continue
        if protocol not in {"tcp", "udp"}:
            continue

        service = _clean(item.get("service"))
        product = _clean(item.get("product"))
        version = _clean(item.get("version"))

        evidence = {
            "state": "open",
            "extra_info": _clean(item.get("extra_info")),
            "reason": _clean(item.get("reason")),
            "service_method": _clean(item.get("service_method")),
            "service_confidence": _clean(
                item.get("service_confidence")
            ),
            "service_tunnel": _clean(item.get("service_tunnel")),
            "service_cpe": [
                _clean(value)
                for value in item.get("service_cpe", [])
                if _clean(value)
            ] if isinstance(item.get("service_cpe", []), list) else [],
        }

        observations.append(_store_observation(
            db,
            asset_key=asset_key,
            target=display_target,
            source="nmap",
            source_record_id=source_record_id,
            product=product,
            version=version,
            service=service,
            port=port,
            protocol=protocol,
            confidence="High" if product and version else "Medium",
            evidence=evidence,
            observed_at=observed_at,
        ))

    return observations


def ingest_firewall_observations(
    db, target, result, observed_at=None, source_record_id=""
):
    """Store firewall service, HTTP application and WAF observations."""
    if not isinstance(result, dict):
        return []

    asset_key, display_target = _asset_identity(
        result.get("host") or target
    )
    observations = []
    seen = set()

    def store_service(item, source="firewall"):
        if not isinstance(item, dict):
            return

        address = _clean(item.get("address"))
        port = item.get("port")
        protocol = _clean(item.get("protocol")).lower()
        service = _clean(item.get("service"))
        vendor = _clean(item.get("vendor"))
        product = _clean(item.get("product"))
        version = _clean(item.get("version"))

        # A protocol fingerprint is useful evidence, but not a
        # software product/version fingerprint.
        if service.lower() in {"smb", "rdp", "dns"}:
            version = ""

        identity = (
            source, protocol, port, service.lower(),
            vendor.lower(), product.lower(), version.lower(),
        )
        if identity in seen:
            return
        seen.add(identity)

        evidence = {
            "address": address,
            "fingerprint_evidence": item.get("evidence", []),
        }
        for key in ("banner", "error"):
            if item.get(key):
                evidence[key] = _clean(item[key])

        observations.append(_store_observation(
            db,
            asset_key=asset_key,
            target=display_target,
            source=source,
            source_record_id=source_record_id,
            vendor=vendor,
            product=product,
            version=version,
            service=service,
            port=port,
            protocol=protocol,
            confidence=item.get("confidence"),
            evidence=evidence,
            observed_at=observed_at,
        ))

    services = result.get("services", {})
    service_items = (
        services.get("items", []) if isinstance(services, dict) else []
    )

    for item in service_items:
        if not isinstance(item, dict):
            continue

        application = item.get("application")
        if isinstance(application, dict):
            store_service(application)
        else:
            store_service(item)

    # Covers an HTTP application when it was not attached to a service item.
    https = result.get("https", {})
    application = (
        https.get("application") if isinstance(https, dict) else None
    )
    if isinstance(application, dict):
        store_service(application)

    waf = result.get("waf", {})
    waf_items = (
        waf.get("vendor_identification", [])
        if isinstance(waf, dict) else []
    )
    for item in waf_items:
        if not isinstance(item, dict):
            continue

        # WAF clues are retained as technology evidence, not software
        # product/version matches for CVE correlation.
        observations.append(_store_observation(
            db,
            asset_key=asset_key,
            target=display_target,
            source="firewall_waf",
            source_record_id=source_record_id,
            vendor=item.get("vendor", ""),
            service="waf",
            confidence=item.get("confidence"),
            evidence={
                "product_hint": _clean(item.get("product")),
                "evidence": item.get("evidence", []),
                "cve_matchable": False,
            },
            observed_at=observed_at,
        ))

    return observations
