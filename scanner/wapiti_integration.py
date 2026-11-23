"""Isolated, scope-restricted Wapiti integration for Web Security."""

import asyncio
import inspect
import threading
import tempfile
from urllib.parse import urlsplit

_WAPITI_LOCK = threading.Lock()

ALLOWED_ACTIVE_MODULES = {
    "sql": {"GET"},
    "xss": {"GET"},
}

MAX_DEPTH = 2
MAX_LINKS_PER_PAGE = 10
MAX_SCAN_SECONDS = 45


class WapitiIntegrationError(Exception):
    """Expected Wapiti integration failure."""


def _origin(value):
    parsed = urlsplit(str(value))

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise WapitiIntegrationError("Wapiti produced an invalid or unsupported URL.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise WapitiIntegrationError("Wapiti produced an invalid target port.") from exc

    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    return parsed.scheme.lower(), parsed.hostname.lower(), port


def _safe_text(value, limit=1000):
    if value is None:
        return ""
    return " ".join(str(value).replace("\x00", "").split())[:limit]


def _payload_to_finding(payload):
    request = getattr(payload, "evil_request", None)
    request_url = getattr(request, "url", "")
    request_path = ""

    if request_url:
        try:
            request_path = urlsplit(str(request_url)).path[:1000]
        except (TypeError, ValueError):
            request_path = ""

    if not request_path:
        request_path = _safe_text(getattr(request, "path", ""), 1000)
        request_path = request_path.split("?", 1)[0]

    raw_severity = getattr(payload, "level", None)
    severity = (
        raw_severity
        if isinstance(raw_severity, int)
        and not isinstance(raw_severity, bool)
        and 0 <= raw_severity <= 4
        else None
    )

    return {
        "category": _safe_text(getattr(payload, "category", "Web vulnerability"), 160),
        "severity": severity,
        "module": _safe_text(getattr(payload, "module", "Wapiti"), 100),
        "method": _safe_text(getattr(request, "method", "GET"), 12).upper(),
        "path": request_path,
        "parameter": _safe_text(getattr(payload, "parameter", ""), 160),
        "information": _safe_text(getattr(payload, "info", ""), 2000),
        "description": _safe_text(getattr(payload, "info", ""), 2000),
        "remediation": "",
        "owasp_wstg": _safe_text(getattr(payload, "wstg", ""), 200),
        "references": "",
        "evidence_status": "unverified",
    }


async def _run_wapiti(target, request_budget):
    """Run bounded Wapiti checks through the shared, same-origin request budget."""
    import os
    import tempfile

    from wapitiCore.controller.wapiti import Wapiti
    from wapitiCore.net.crawler import AsyncCrawler
    from wapitiCore.net.sql_persister import SqlPersister
    from wapitiCore.net.web import Request

    target_origin = _origin(target)
    controller = None
    original_factory_descriptor = AsyncCrawler.__dict__["with_configuration"]
    original_factory = AsyncCrawler.with_configuration
    original_data_dir = SqlPersister.CRAWLER_DATA_DIR
    original_config_dir = SqlPersister.CONFIG_DIR
    temporary_directory = tempfile.TemporaryDirectory(prefix="shadowmap-wapiti-")

    try:
        data_dir = os.path.join(temporary_directory.name, "data")
        config_dir = os.path.join(temporary_directory.name, "config")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(config_dir, exist_ok=True)

        SqlPersister.CRAWLER_DATA_DIR = data_dir
        SqlPersister.CONFIG_DIR = config_dir

        controller = Wapiti(
            Request(target),
            scope="folder",
            session_dir=data_dir,
            config_dir=config_dir,
        )

        controller._max_depth = MAX_DEPTH
        controller._max_links_per_page = MAX_LINKS_PER_PAGE
        controller._max_scan_time = MAX_SCAN_SECONDS

        active = controller._active_scanner
        active._activated_modules = {
            name: set(methods)
            for name, methods in ALLOWED_ACTIVE_MODULES.items()
        }
        active._max_attack_time = MAX_SCAN_SECONDS
        active._bug_report = False

        def guarded_factory(cls, configuration):
            crawler = original_factory(configuration)
            client = crawler._client
            original_send = client.send

            async def guarded_send(request, *args, **kwargs):
                method = str(getattr(request, "method", "")).upper()
                if method not in {"GET", "HEAD"}:
                    raise WapitiIntegrationError(
                        "Wapiti request blocked: only GET and HEAD are permitted."
                    )

                request_url = str(getattr(request, "url", ""))
                try:
                    request_origin = _origin(request_url)
                except WapitiIntegrationError:
                    raise

                if request_origin != target_origin:
                    raise WapitiIntegrationError(
                        "Wapiti request blocked: URL is outside the authorized origin."
                    )

                request_budget.consume()
                return await original_send(request, *args, **kwargs)

            client.send = guarded_send
            return crawler

        AsyncCrawler.with_configuration = classmethod(guarded_factory)

        await controller.init_persister()
        await controller.browse(asyncio.Event())
        await active.attack()

        findings = []
        async for payload in controller.persister.get_payloads():
            payload_type = getattr(payload, "type", None)
            if payload_type and str(payload_type).lower() != "vulnerability":
                continue
            findings.append(_payload_to_finding(payload))

        return findings

    finally:
        AsyncCrawler.with_configuration = original_factory_descriptor
        SqlPersister.CRAWLER_DATA_DIR = original_data_dir
        SqlPersister.CONFIG_DIR = original_config_dir

        if controller is not None:
            persister = getattr(controller, "persister", None)
            close = getattr(persister, "close", None)
            if callable(close):
                close_result = close()
                if inspect.isawaitable(close_result):
                    await close_result

        temporary_directory.cleanup()


def run_wapiti_assessment(target, request_budget):
    """Run restricted Wapiti checks using the existing shared request budget."""

    if request_budget is None:
        raise WapitiIntegrationError("A shared Web Security request budget is required.")

    result = {
        "status": "not_run",
        "engine": "Wapiti 3.3.4",
        "findings": [],
        "requests_used": 0,
        "requests_remaining": request_budget.remaining,
        "verified_vulnerabilities": 0,
        "enabled_active_modules": ["sql (GET only)", "xss (GET only)"],
        "notes": [
            "Only same-origin GET/HEAD requests are permitted.",
            "SQL injection and XSS results are unverified assessment evidence.",
            "Raw HTTP requests and response bodies are not retained in findings.",
            "Destructive, time-based, upload, brute-force and out-of-scope modules are disabled.",
        ],
    }

    before = request_budget.used

    try:
        with _WAPITI_LOCK:
            findings = asyncio.run(
                asyncio.wait_for(
                    _run_wapiti(target, request_budget),
                    timeout=MAX_SCAN_SECONDS * 2 + 15,
                )
            )

        result["status"] = "completed"
        result["findings"] = findings

    except Exception as exc:
        result["status"] = "partial" if request_budget.used > before else "failed"
        result["notes"].append(
            "Wapiti stopped safely: " + _safe_text(exc, 300)
        )

    result["requests_used"] = request_budget.used - before
    result["requests_remaining"] = request_budget.remaining
    return result
