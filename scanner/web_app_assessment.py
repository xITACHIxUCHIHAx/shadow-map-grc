"""Structured attack-surface analysis for discovered web applications."""

import ipaddress
import hashlib
import json
import re
import secrets
import socket
import time
from html.parser import HTMLParser
from urllib.parse import (
    parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit,
)

import requests
import sys
from requests.adapters import HTTPAdapter
from urllib3 import PoolManager
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import (
    ConnectTimeoutError,
    NameResolutionError,
    NewConnectionError,
)
from urllib3.util.connection import create_connection

import config



class _PinnedHTTPConnectionMixin:
    """Connect to a validated IP while retaining the original hostname."""

    def __init__(self, *args, pinned_ip, **kwargs):
        self._pinned_ip = str(ipaddress.ip_address(pinned_ip))
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        try:
            sock = create_connection(
                (self._pinned_ip, self.port),
                self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
        except socket.gaierror as exc:
            raise NameResolutionError(self.host, self, exc) from exc
        except socket.timeout as exc:
            raise ConnectTimeoutError(
                self,
                f"Connection to {self.host} timed out. "
                f"(connect timeout={self.timeout})",
            ) from exc
        except OSError as exc:
            raise NewConnectionError(
                self, f"Failed to establish a pinned connection: {exc}"
            ) from exc

        sys.audit("http.client.connect", self, self.host, self.port)
        return sock


class _PinnedHTTPConnection(_PinnedHTTPConnectionMixin, HTTPConnection):
    """HTTP connection pinned to a validated IP address."""


class _PinnedHTTPSConnection(_PinnedHTTPConnectionMixin, HTTPSConnection):
    """HTTPS connection pinned to an IP while retaining hostname TLS identity."""


class _PinnedHTTPConnectionPool(HTTPConnectionPool):
    """HTTP pool using connections pinned to a validated IP."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ConnectionCls = _PinnedHTTPConnection


class _PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    """HTTPS pool preserving hostname-based TLS identity."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ConnectionCls = _PinnedHTTPSConnection


class _PinnedPoolManager(PoolManager):
    """Pool manager that injects one validated destination IP per adapter."""

    def __init__(self, pinned_ip, *args, **kwargs):
        self.pinned_ip = str(ipaddress.ip_address(pinned_ip))
        super().__init__(*args, **kwargs)

        # Copy the mapping so this adapter cannot modify urllib3 globals.
        self.pool_classes_by_scheme = dict(self.pool_classes_by_scheme)
        self.pool_classes_by_scheme["http"] = _PinnedHTTPConnectionPool
        self.pool_classes_by_scheme["https"] = _PinnedHTTPSConnectionPool

    def _new_pool(
        self, scheme, host, port, request_context=None
    ):
        context = (
            self.connection_pool_kw.copy()
            if request_context is None
            else request_context.copy()
        )
        context["pinned_ip"] = self.pinned_ip
        return super()._new_pool(
            scheme, host, port, request_context=context
        )


class _PinnedHTTPAdapter(HTTPAdapter):
    """Requests adapter isolated to one validated destination IP."""

    def __init__(self, pinned_ip, *args, **kwargs):
        self.pinned_ip = str(ipaddress.ip_address(pinned_ip))
        super().__init__(*args, **kwargs)

    def init_poolmanager(
        self, connections, maxsize, block=False, **pool_kwargs
    ):
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = _PinnedPoolManager(
            self.pinned_ip,
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )
AUTH_INDICATORS = (
    "login", "log-in", "signin", "sign-in", "auth",
    "oauth", "session", "account", "password", "token",
)

SENSITIVE_PARAMETER_NAMES = {
    "url", "uri", "path", "file", "filename", "redirect",
    "return", "returnurl", "next", "dest", "destination",
    "callback", "webhook", "host", "domain", "endpoint",
    "query", "search", "id", "user", "username", "email",
}


PARAMETER_CATEGORIES = {
    "sql_injection": {
        "id", "query", "search", "filter", "sort",
        "order", "category", "product", "user", "account",
    },
    "xss": {
        "q", "query", "search", "message", "comment",
        "name", "title", "description", "content",
    },
    "ssrf": {
        "url", "uri", "callback", "webhook", "host",
        "endpoint", "image_url", "fetch_url", "target_url",
    },
    "path_traversal": {
        "file", "filename", "path", "filepath",
        "document", "template", "include", "download",
        "page", "inc", "module", "view",
    },
    "command_injection": {
        "cmd", "command", "exec", "execute",
        "shell", "ping",
    },
    "authentication_session": {
        "username", "user", "email", "password",
        "passwd", "token", "access_token", "session",
        "sessionid", "authorization", "csrf", "code",
    },
}


def _classify_parameter(name):
    """Return potential assessment categories based on a parameter name."""
    lowered = str(name or "").strip().lower()
    categories = [
        category
        for category, names in PARAMETER_CATEGORIES.items()
        if lowered in names
    ]

    if not lowered:
        return categories

    parts = lowered.replace("-", "_").split("_")

    if (
        "ssrf" not in categories
        and len(parts) >= 2
        and parts[-1] in {"url", "uri"}
        and any(part in {"redirect", "return", "callback", "webhook", "fetch", "target", "image", "avatar"} for part in parts[:-1])
    ):
        categories.append("ssrf")

    if (
        "path_traversal" not in categories
        and len(parts) >= 2
        and (
            parts[-1] in {"file", "filename", "filepath", "path", "template"}
            or parts[0] in {"file", "filepath"}
        )
    ):
        categories.append("path_traversal")

    return categories


def _classify_form_field(name, field_type=None, autocomplete=None):
    """Classify form fields using their name and authentication metadata."""
    categories = _classify_parameter(name)

    normalized_type = str(field_type or "").strip().lower()
    normalized_autocomplete = str(
        autocomplete or ""
    ).strip().lower()

    authentication_autocomplete = {
        "username",
        "current-password",
        "new-password",
        "one-time-code",
        "webauthn",
    }

    if (
        normalized_type == "password"
        or normalized_autocomplete in authentication_autocomplete
        or normalized_autocomplete.startswith("cc-")
    ):
        if "authentication_session" not in categories:
            categories.append("authentication_session")

    return categories


def _valid_url(value):
    if not isinstance(value, str) or not value or len(value) > 4096:
        return False

    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme.lower() in {"http", "https"}
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and parsed.port != 0
        )
    except ValueError:
        return False


def _url_indicates_authentication(value):
    if not _valid_url(value):
        return False

    parsed = urlsplit(value)
    path = parsed.path.lower()
    return any(
        indicator in path
        for indicator in AUTH_INDICATORS
    )


def _parameter_record(name, source, location, value_present):
    name = str(name or "").strip()[:100]
    if not name:
        return None

    lowered = name.lower()
    return {
        "name": name,
        "source": source,
        "location": location,
        "value_present": bool(value_present),
        "sensitive_input": lowered in SENSITIVE_PARAMETER_NAMES,
        "assessment_categories": _classify_parameter(lowered),
        # SQL syntax context cannot be reliably inferred from a parameter
        # name or observed value. Keep automatic discovery review-only.
        "sql_context": "unknown",
    }


def analyze_attack_surface(discovery):
    """Inventory discovered parameters, forms, API and authentication surfaces.

    Query-string values are never copied into the assessment result.
    Discovery metadata is treated as untrusted input.
    """
    if not isinstance(discovery, dict):
        discovery = {}

    pages = discovery.get("pages")
    discovered_urls = discovery.get("discovered_urls")
    api_endpoints = discovery.get("api_endpoints")
    discovered_forms = discovery.get("forms")

    if not isinstance(pages, list):
        pages = []
    if not isinstance(discovered_urls, list):
        discovered_urls = []
    if not isinstance(api_endpoints, list):
        api_endpoints = []
    if not isinstance(discovered_forms, list):
        discovered_forms = []

    parameters = []
    parameter_keys = set()
    normalized_forms = []
    form_security = []
    authentication_surfaces = []
    auth_keys = set()

    def add_authentication_surface(surface_type, location, method=None):
        key = (surface_type, location, method)
        if key in auth_keys:
            return
        auth_keys.add(key)
        item = {
            "type": surface_type,
            "location": location,
        }
        if method:
            item["method"] = method
        authentication_surfaces.append(item)

    def add_query_parameters(value, source):
        if not _valid_url(value):
            return

        try:
            parsed = urlsplit(value)
            query_items = parse_qsl(
                parsed.query,
                keep_blank_values=True,
                max_num_fields=200,
            )
        except ValueError:
            return

        for name, parameter_value in query_items:
            record = _parameter_record(
                name,
                "query",
                urlunsplit((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    "",
                    "",
                )),
                bool(parameter_value),
            )
            if record is None:
                continue

            key = (record["name"].lower(), record["location"])
            if key not in parameter_keys:
                parameter_keys.add(key)
                parameters.append(record)

    url_candidates = []

    for page in pages:
        if isinstance(page, dict):
            url_candidates.append((page.get("url"), "page"))

    for url in discovered_urls:
        url_candidates.append((url, "discovered_url"))

    for value, source in url_candidates:
        add_query_parameters(value, source)

        if _url_indicates_authentication(value):
            add_authentication_surface("url", value)

    valid_api_endpoints = []
    for endpoint in api_endpoints:
        if not _valid_url(endpoint):
            continue
        if endpoint not in valid_api_endpoints:
            valid_api_endpoints.append(endpoint)
        if _url_indicates_authentication(endpoint):
            add_authentication_surface("api_endpoint", endpoint)

    for form in discovered_forms:
        if not isinstance(form, dict):
            continue

        page = form.get("page")
        action = form.get("action")
        method = str(form.get("method") or "get").lower()
        enctype = str(form.get("enctype") or "")[:100]
        fields = form.get("fields")

        if not _valid_url(page) or not _valid_url(action):
            continue
        if method not in {"get", "post", "put", "patch", "delete"}:
            method = "unknown"
        if not isinstance(fields, list):
            fields = []

        normalized_fields = []
        has_password = False

        for field in fields[:100]:
            if not isinstance(field, dict):
                continue

            name = str(field.get("name") or "").strip()[:100]
            element = str(field.get("element") or "")[:30]
            field_type = str(field.get("type") or "")[:30].lower()

            normalized = {
                "name": name,
                "element": element,
                "type": field_type,
                "required": bool(field.get("required")),
                "autocomplete": str(
                    field.get("autocomplete") or ""
                )[:100],
            }

            if field_type == "password":
                has_password = True

            if name:
                record = _parameter_record(
                    name,
                    "form",
                    action,
                    False,
                )
                key = (name.lower(), "form", action)
                if record and key not in parameter_keys:
                    parameter_keys.add(key)
                    parameters.append(record)

            options = field.get("options")
            if isinstance(options, list):
                normalized["options"] = [
                    str(option)[:200] for option in options[:100]
                ]

            normalized_fields.append(normalized)

        action_authorized = form.get("action_authorized")
        if not isinstance(action_authorized, bool):
            action_authorized = None

        normalized_form = {
            "page": page,
            "method": method,
            "action": action,
            "action_authorized": action_authorized,
            "enctype": enctype,
            "fields": normalized_fields,
        }
        normalized_forms.append(normalized_form)

        # Passive security observations are generated only for actions
        # explicitly authorized by the crawler's approved-scope check.
        if action_authorized is True:
            for field in normalized_fields:
                field_name = field["name"]
                field_type = field["type"]

                if field_type == "password" and urlsplit(action).scheme.lower() == "http":
                    form_security.append({
                        "type": "password_field_over_http",
                        "form_action": action,
                        "method": method,
                        "parameter": field_name or None,
                        "status": "not_tested",
                        "confidence": "none",
                        "evidence": [],
                        "observation": (
                            "A password field is associated with an HTTP "
                            "form action; transport protection has not "
                            "been independently verified."
                        ),
                    })

                csrf_name = field_name.lower().replace("-", "_")
                csrf_markers = (
                    "csrf",
                    "xsrf",
                    "requestverificationtoken",
                    "authenticity_token",
                )
                if (
                    field_type == "hidden"
                    and any(marker in csrf_name for marker in csrf_markers)
                ):
                    form_security.append({
                        "type": "csrf_token_field_observed",
                        "form_action": action,
                        "method": method,
                        "parameter": field_name,
                        "status": "not_tested",
                        "confidence": "none",
                        "evidence": [],
                        "observation": (
                            "A hidden field name resembles CSRF token "
                            "metadata; its presence does not establish "
                            "token validity or effective CSRF protection."
                        ),
                    })

        if (
            has_password
            or _url_indicates_authentication(page)
            or _url_indicates_authentication(action)
        ):
            add_authentication_surface(
                "form",
                action,
                method,
            )

    return {
        "parameters": parameters,
        "forms": normalized_forms,
        "form_security": form_security,
        "api_endpoints": valid_api_endpoints,
        "authentication_surfaces": authentication_surfaces,
        "notes": [
            "This is an attack-surface inventory, not a vulnerability confirmation.",
            "Query-string values are not retained in the assessment output.",
            "Form fields and API routes are discovered metadata; forms are not submitted.",
        ],
    }




class _ReflectionContextParser(HTMLParser):
    """Classify marker occurrences by their surrounding HTML context."""

    def __init__(self, marker):
        super().__init__(convert_charrefs=False)
        self.marker = marker
        self.contexts = []
        self.has_markup = False

    def handle_data(self, data):
        if self.marker not in data:
            return

        if self.cdata_elem == "script":
            context = "script"
        elif self.cdata_elem == "style":
            context = "style"
        else:
            context = "text"

        self.contexts.append(context)

    def handle_starttag(self, tag, attrs):
        self.has_markup = True

        if not any(
            value is not None and self.marker in value
            for _, value in attrs
        ):
            return

        url_attributes = {
            "action",
            "cite",
            "data",
            "formaction",
            "href",
            "manifest",
            "poster",
            "src",
            "xlink:href",
        }

        matching_attributes = [
            name.lower()
            for name, value in attrs
            if value is not None and self.marker in value
        ]

        if any(name in url_attributes for name in matching_attributes):
            self.contexts.append("html_url_attribute")
        else:
            self.contexts.append("html_attribute")

    def handle_endtag(self, tag):
        self.has_markup = True

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_comment(self, data):
        self.has_markup = True
        if self.marker in data:
            self.contexts.append("other")

    def handle_decl(self, decl):
        self.has_markup = True
        if self.marker in decl:
            self.contexts.append("other")

    def unknown_decl(self, data):
        self.has_markup = True
        if self.marker in data:
            self.contexts.append("other")


def _classify_reflection_contexts(body, marker):
    parser = _ReflectionContextParser(marker)

    try:
        parser.feed(body)
        parser.close()
    except Exception:
        return ["other"]

    contexts = []
    for context in parser.contexts:
        if context == "text":
            context = "html_text" if parser.has_markup else "other"
        if context not in contexts:
            contexts.append(context)

    return contexts or ["other"]



def detect_reflected_input(response_body, marker, truncated=False):
    """Identify exact marker reflection without claiming executable XSS."""
    if (
        not isinstance(marker, str)
        or not marker
        or len(marker) > 128
        or not marker.isascii()
        or not re.fullmatch(r"[A-Za-z0-9_-]+", marker)
    ):
        raise ValueError("Invalid reflected-input marker.")

    if truncated is True:
        return {
            "status": "inconclusive",
            "confidence": "none",
            "occurrences": 0,
            "evidence": [],
            "contexts": [],
            "verified": False,
            "notes": [
                "Response was truncated; reflection inspection is incomplete.",
                "Marker reflection does not establish executable XSS.",
            ],
        }

    if isinstance(response_body, bytes):
        body = response_body[:ASSESSMENT_MAX_BODY_BYTES].decode(
            "utf-8", errors="replace"
        )
    elif isinstance(response_body, str):
        body = response_body[:ASSESSMENT_MAX_BODY_BYTES]
    else:
        body = ""

    positions = []
    start = 0

    while len(positions) < 20:
        position = body.find(marker, start)
        if position < 0:
            break
        positions.append(position)
        start = position + len(marker)

    evidence = []
    for position in positions:
        context_start = max(0, position - 60)
        context_end = min(len(body), position + len(marker) + 60)
        evidence.append({
            "context": body[context_start:context_end],
            "position": position,
        })

    reflected = bool(positions)
    contexts = (
        _classify_reflection_contexts(body, marker)
        if reflected else []
    )

    return {
        "status": "suspected" if reflected else "not_detected",
        "confidence": "low" if reflected else "none",
        "occurrences": len(positions),
        "evidence": evidence,
        "contexts": contexts,
        "verified": False,
        "notes": [
            "Exact marker reflection was checked in a bounded response body.",
            "Reflection alone does not establish executable cross-site scripting.",
            "HTML context and output encoding require separate analysis.",
        ],
    }


SQL_ERROR_PATTERNS = {
    "mysql": (
        r"you have an error in your sql syntax",
        r"warning:\s*mysql_",
        r"mysqli?_",
        r"unknown column .+ in .+",
    ),
    "postgresql": (
        r"postgresql.*error",
        r"pg_query\(\).*failed",
        r"unterminated quoted string at or near",
        r"syntax error at or near",
    ),
    "microsoft_sql_server": (
        r"unclosed quotation mark after the character string",
        r"microsoft sql server",
        r"\bODBC SQL Server Driver\b",
        r"\bSQLServer JDBC Driver\b",
    ),
    "oracle": (
        r"\bORA-\d{5}\b",
        r"oracle error",
        r"quoted string not properly terminated",
    ),
    "sqlite": (
        r"sqlite(?:3)?\.OperationalError",
        r"sqlite error",
        r"SQLITE_ERROR",
        r"near .+: syntax error",
    ),
}


def detect_sql_error_indicators(response_body):
    """Passively identify database error signatures in response content."""
    if isinstance(response_body, bytes):
        body = response_body[:ASSESSMENT_MAX_BODY_BYTES].decode(
            "utf-8", errors="replace"
        )
    elif isinstance(response_body, str):
        body = response_body[:ASSESSMENT_MAX_BODY_BYTES]
    else:
        body = ""

    matches = []
    matched_families = set()

    for family, patterns in SQL_ERROR_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                matched_families.add(family)
                matches.append({
                    "database_family": family,
                    "indicator": pattern,
                    "evidence": match.group(0)[:200],
                })

    if not matches:
        status = "not_detected"
        confidence = "none"
    elif len(matched_families) > 1:
        status = "suspected"
        confidence = "medium"
    else:
        status = "suspected"
        confidence = "low"

    return {
        "status": status,
        "confidence": confidence,
        "database_families": sorted(matched_families),
        "indicators": matches,
        "verified": False,
        "notes": [
            "Passive response inspection only; no HTTP requests are performed.",
            "Database error signatures do not independently confirm SQL injection.",
            "Response content is not retained beyond matched evidence.",
        ],
    }




def _normalize_response_body_for_fingerprint(body):
    """Normalize only recognized ISO-8601 text inside HTML time elements."""
    timestamp_pattern = re.compile(
        rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
        rb"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    )

    time_element_pattern = re.compile(
        rb"(<time\b[^>]*>)(.*?)(</time\s*>)",
        re.IGNORECASE | re.DOTALL,
    )

    def replace_time(match):
        content = match.group(2).strip()
        if timestamp_pattern.fullmatch(content):
            return match.group(1) + b"[normalized-time]" + match.group(3)
        return match.group(0)

    return time_element_pattern.sub(replace_time, body)


def build_response_baseline(response):
    """Create a bounded, content-minimizing fingerprint of an HTTP response."""
    if not isinstance(response, dict):
        raise ValueError("Response must be a dictionary.")

    status_code = response.get("status_code")
    if not isinstance(status_code, int) or not 100 <= status_code <= 599:
        raise ValueError("Response contains an invalid HTTP status code.")

    body = response.get("body", b"")
    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")
    elif not isinstance(body, bytes):
        body = b""

    headers = response.get("headers", {})
    if not isinstance(headers, dict):
        headers = {}

    content_type = str(headers.get("content-type", ""))[:200]
    body_hash = hashlib.sha256(body).hexdigest()
    normalized_body = _normalize_response_body_for_fingerprint(body)
    normalized_body_hash = hashlib.sha256(normalized_body).hexdigest()

    title_match = re.search(
        rb"<title\b[^>]*>(.*?)</title\s*>",
        body[:ASSESSMENT_MAX_BODY_BYTES],
        re.IGNORECASE | re.DOTALL,
    )
    title_hash = None
    if title_match:
        normalized_title = re.sub(
            rb"\s+", b" ", title_match.group(1)
        ).strip().lower()
        title_hash = hashlib.sha256(normalized_title).hexdigest()

    truncated = response.get("truncated") is True

    return {
        "status_code": status_code,
        "body_length": len(body),
        "body_sha256": body_hash,
        "normalized_body_sha256": normalized_body_hash,
        "content_type": content_type,
        "title_sha256": title_hash,
        "truncated": truncated,
        "complete": not truncated,
        "notes": [
            "Baseline contains response metadata and fingerprints only.",
            "Response body and sensitive parameter values are not retained.",
            "A response difference alone does not confirm a vulnerability.",
        ],
    }




def compare_sql_responses(baseline_response, test_response):
    """Compare responses and identify only newly introduced SQL indicators."""
    baseline = build_response_baseline(baseline_response)
    tested = build_response_baseline(test_response)

    if not baseline["complete"] or not tested["complete"]:
        return {
            "status": "inconclusive",
            "confidence": "none",
            "verified": False,
            "reason": "A baseline or test response was truncated.",
            "baseline": baseline,
            "test": tested,
            "differences": [],
            "database_error_indicators": [],
        }

    differences = []

    if baseline["status_code"] != tested["status_code"]:
        differences.append("http_status_changed")

    length_delta = tested["body_length"] - baseline["body_length"]
    length_percentage = (
        abs(length_delta) / max(baseline["body_length"], 1)
    ) * 100

    if baseline["body_length"] != tested["body_length"]:
        differences.append("response_length_changed")

    if (
        baseline["normalized_body_sha256"]
        != tested["normalized_body_sha256"]
    ):
        differences.append("response_body_changed")

    baseline_sql = detect_sql_error_indicators(
        baseline_response.get("body", b"")
    )
    test_sql = detect_sql_error_indicators(
        test_response.get("body", b"")
    )

    baseline_signatures = {
        (item["database_family"], item["indicator"])
        for item in baseline_sql["indicators"]
    }
    new_indicators = [
        item for item in test_sql["indicators"]
        if (
            item["database_family"],
            item["indicator"],
        ) not in baseline_signatures
    ]

    if new_indicators:
        differences.append("database_error_indicator_detected")

    new_families = {
        item["database_family"] for item in new_indicators
    }

    if new_indicators:
        status = "suspected"
        confidence = "low"
    elif differences:
        status = "inconclusive"
        confidence = "none"
    else:
        status = "not_detected"
        confidence = "none"

    return {
        "status": status,
        "confidence": confidence,
        "verified": False,
        "baseline": baseline,
        "test": tested,
        "differences": differences,
        "body_length_delta": length_delta,
        "body_length_change_percent": round(length_percentage, 2),
        "database_error_indicators": new_indicators,
        "baseline_database_families": baseline_sql["database_families"],
        "new_database_families": sorted(new_families),
        "notes": [
            "Only SQL error indicators absent from the baseline are treated as new evidence.",
            "Response differences are indicators, not proof of SQL injection.",
            "No vulnerability is marked verified by response comparison.",
            "Manual or independent verification is required before confirmation.",
        ],
    }




def compare_boolean_sql_responses(true_response, false_response):
    """Compare paired Boolean-condition responses without confirming SQLi."""
    true_baseline = build_response_baseline(true_response)
    false_baseline = build_response_baseline(false_response)

    differences = []

    if not true_baseline["complete"] or not false_baseline["complete"]:
        return {
            "status": "inconclusive",
            "confidence": "none",
            "verified": False,
            "reason": "A Boolean-condition response was truncated.",
            "true_response": true_baseline,
            "false_response": false_baseline,
            "differences": [],
        }

    if true_baseline["status_code"] != false_baseline["status_code"]:
        differences.append("http_status_changed")

    if true_baseline["content_type"].lower() != (
        false_baseline["content_type"].lower()
    ):
        differences.append("content_type_changed")

    if differences:
        status = "inconclusive"
        confidence = "none"
    elif (
        true_baseline["normalized_body_sha256"]
        != false_baseline["normalized_body_sha256"]
    ):
        differences.append("response_body_changed")
        status = "suspected"
        confidence = "low"
    else:
        status = "not_detected"
        confidence = "none"

    return {
        "status": status,
        "confidence": confidence,
        "verified": False,
        "true_response": true_baseline,
        "false_response": false_baseline,
        "differences": differences,
        "notes": [
            "Only paired Boolean-condition response metadata and fingerprints are retained.",
            "A response difference alone does not confirm Boolean-based SQL injection.",
            "Dynamic application content may produce false positives.",
            "Manual or independent verification is required before confirmation.",
        ],
    }



ASSESSMENT_TIMEOUT = (3, 7)
ASSESSMENT_MAX_BODY_BYTES = 262144
ASSESSMENT_MAX_REDIRECTS = 5
ASSESSMENT_MAX_REQUESTS = config.WEB_ASSESSMENT_HARD_LIMITS["max_requests"]
ASSESSMENT_USER_AGENT = "ShadowMapGRC-WebAssessment/1.0"


def get_assessment_profile(profile=None):
    """Return a copy of validated settings for an assessment profile."""
    name = (
        config.WEB_ASSESSMENT_DEFAULT_PROFILE
        if profile is None
        else profile
    )

    if not isinstance(name, str):
        raise ValueError("Assessment profile must be a string.")

    name = name.strip().lower()
    settings = config.WEB_ASSESSMENT_PROFILES.get(name)

    if settings is None:
        raise ValueError("Unknown Web App Assessment profile.")

    limits = config.WEB_ASSESSMENT_HARD_LIMITS
    for key in (
        "max_requests",
        "max_body_bytes",
        "max_redirects",
        "connect_timeout",
        "read_timeout",
        "max_sqli_candidates",
        "max_boolean_sqli_candidates",
        "max_reflected_input_candidates",
    ):
        value = settings.get(key)
        maximum = limits[key]

        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 1
            or value > maximum
        ):
            raise ValueError(
                f"Invalid {key} setting for assessment profile {name}."
            )

    return {"name": name, **settings}


class WebAssessmentRequestError(Exception):
    """Controlled HTTP assessment request failed."""


class AssessmentTargetValidationError(ValueError):
    """Authorized assessment scope data is invalid."""


def normalize_assessment_target(value):
    """Normalize a scope target without resolving its hostname."""
    if not isinstance(value, str):
        raise AssessmentTargetValidationError("Assessment target must be a string.")

    value = value.strip()
    if not value or len(value) > 4096:
        raise AssessmentTargetValidationError("Assessment target is empty or too long.")

    if any(char.isspace() for char in value):
        raise AssessmentTargetValidationError("Assessment target must not contain whitespace.")

    candidate = value
    if "://" not in candidate:
        candidate = f"http://{candidate}"

    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise AssessmentTargetValidationError("Assessment target has an invalid URL or port.") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise AssessmentTargetValidationError("Only HTTP and HTTPS assessment targets are supported.")

    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise AssessmentTargetValidationError("Assessment target contains unsupported URL components.")

    host = parsed.hostname.rstrip(".").lower()
    if not host:
        raise AssessmentTargetValidationError("Assessment target hostname is invalid.")

    try:
        address = ipaddress.ip_address(host)
        host = f"[{host}]" if address.version == 6 else str(address)
    except ValueError:
        if len(host) > 253:
            raise AssessmentTargetValidationError("Assessment hostname is too long.")

        labels = host.split(".")
        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise AssessmentTargetValidationError("Assessment hostname is malformed.")

    netloc = host
    if port is not None:
        netloc = f"{netloc}:{port}"

    return urlunsplit((
        scheme,
        netloc,
        parsed.path or "/",
        parsed.query,
        "",
    ))




class AssessmentRequestBudget:
    """Track profile-wide HTTP request limits."""

    def __init__(self, maximum=None, profile=None, run_guard=None):
        self.profile = get_assessment_profile(profile)
        profile_maximum = self.profile["max_requests"]

        if maximum is None:
            maximum = profile_maximum

        if not isinstance(maximum, int) or isinstance(maximum, bool):
            raise ValueError("Request budget must be an integer.")
        if maximum < 1 or maximum > profile_maximum:
            raise ValueError(
                "Request budget exceeds the selected profile limit."
            )

        self.maximum = maximum
        self.used = 0
        self.run_guard = run_guard

    def _check_run_guard(self):
        if self.run_guard is None:
            return None

        try:
            return self.run_guard.check()
        except Exception as exc:
            raise WebAssessmentRequestError(str(exc)) from exc

    def request_timeout(self, connect_timeout, read_timeout):
        if self.run_guard is None:
            return (connect_timeout, read_timeout)

        try:
            return self.run_guard.request_timeout(
                connect_timeout, read_timeout
            )
        except Exception as exc:
            raise WebAssessmentRequestError(str(exc)) from exc

    @property
    def remaining(self):
        return self.maximum - self.used

    def consume(self):
        self._check_run_guard()

        if self.used >= self.maximum:
            raise WebAssessmentRequestError(
                "Assessment HTTP request budget exhausted."
            )

        if self.run_guard is not None:
            try:
                self.run_guard.consume()
            except Exception as exc:
                raise WebAssessmentRequestError(str(exc)) from exc

        self.used += 1


def _validate_and_resolve_assessment_destination(value):
    """Validate an assessment URL and resolve its destination exactly once."""
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise WebAssessmentRequestError("Invalid assessment URL.")

    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError as exc:
        raise WebAssessmentRequestError("Invalid URL or port.") from exc

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise WebAssessmentRequestError("Unsupported assessment URL.")

    host = parsed.hostname.rstrip(".")
    if not host or any(char.isspace() for char in host):
        raise WebAssessmentRequestError("Invalid assessment hostname.")

    scheme = parsed.scheme.lower()
    effective_port = port or (443 if scheme == "https" else 80)

    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        try:
            records = socket.getaddrinfo(
                host, effective_port, type=socket.SOCK_STREAM
            )
            addresses = list(dict.fromkeys(
                ipaddress.ip_address(record[4][0])
                for record in records
            ))
        except (OSError, ValueError) as exc:
            raise WebAssessmentRequestError(
                "Assessment hostname could not be resolved."
            ) from exc

    if not addresses:
        raise WebAssessmentRequestError(
            "Assessment hostname has no addresses."
        )

    for address in addresses:
        if (
            address.is_unspecified
            or address.is_multicast
            or address.is_link_local
            or address.is_reserved
            or not (
                address.is_global
                or address.is_private
                or address.is_loopback
            )
        ):
            raise WebAssessmentRequestError(
                "Assessment destination resolves to an unsupported address."
            )

    validated_url = urlunsplit((
        scheme,
        parsed.netloc,
        parsed.path or "/",
        parsed.query,
        "",
    ))

    return validated_url, str(addresses[0])


def _validate_assessment_url(value):
    """Validate an HTTP/HTTPS destination, including private authorized targets."""
    validated_url, _ = (
        _validate_and_resolve_assessment_destination(value)
    )
    return validated_url


def _resolve_assessment_destination(value):
    """Resolve and validate one IP address for a pinned HTTP connection."""
    return _validate_and_resolve_assessment_destination(value)


def _send_pinned_request(
    session,
    method,
    url,
    *,
    params=None,
    data=None,
    headers=None,
    timeout=None,
):
    """Send one prepared request through an isolated, IP-pinned adapter.

    Returns (response, adapter). The caller must close both after consuming
    the response so the pinned connection pool cannot outlive this request.
    """
    if not isinstance(session, requests.Session):
        raise WebAssessmentRequestError("Invalid assessment HTTP session.")

    try:
        request = requests.Request(
            method=method,
            url=url,
            params=params,
            data=data,
            headers=headers,
        )
        prepared = session.prepare_request(request)
    except (requests.RequestException, TypeError, ValueError) as exc:
        raise WebAssessmentRequestError(
            "Assessment request could not be prepared."
        ) from exc

    validated_url, pinned_ip = _resolve_assessment_destination(
        prepared.url
    )
    prepared.url = validated_url

    try:
        verify_setting = session.verify
        if not isinstance(verify_setting, str):
            verify_setting = True

        environment = session.merge_environment_settings(
            prepared.url,
            proxies={},
            stream=True,
            verify=verify_setting,
            cert=None,
        )
    except (requests.RequestException, TypeError, ValueError) as exc:
        raise WebAssessmentRequestError(
            "Assessment transport settings could not be prepared."
        ) from exc

    proxies = environment.get("proxies") or {}
    if any(
        value and requests.utils.select_proxy(prepared.url, {key: value})
        for key, value in proxies.items()
    ):
        raise WebAssessmentRequestError(
            "Assessment requests through proxies are not supported."
        )

    # Use a shallow session copy to preserve authentication, cookies,
    # hooks, and settings without mutating the caller's adapter registry.
    pinned_session = __import__("copy").copy(session)
    adapter = _PinnedHTTPAdapter(pinned_ip)

    pinned_session.adapters = {
        "https://": adapter,
        "http://": adapter,
    }
    pinned_session.trust_env = False

    try:
        response = pinned_session.send(
            prepared,
            timeout=timeout,
            allow_redirects=False,
            **environment,
        )
    except requests.RequestException as exc:
        adapter.close()
        raise WebAssessmentRequestError(
            f"Assessment HTTP request failed: {type(exc).__name__}"
        ) from exc
    except Exception:
        adapter.close()
        raise

    return response, adapter

def _assessment_request(
    session, method, url, *, params=None, data=None, headers=None,
    max_body_bytes=None, budget=None,
):
    """Send a bounded request and validate every redirect destination."""
    if not isinstance(method, str) or method.upper() not in {"GET", "HEAD", "POST"}:
        raise WebAssessmentRequestError("Unsupported assessment request method.")

    if budget is not None and not isinstance(budget, AssessmentRequestBudget):
        raise WebAssessmentRequestError("Invalid assessment request budget.")

    if budget is not None:
        profile = budget.profile
        timeout = budget.request_timeout(
            profile["connect_timeout"],
            profile["read_timeout"],
        )
        max_redirects = profile["max_redirects"]
        profile_body_limit = profile["max_body_bytes"]
    else:
        timeout = ASSESSMENT_TIMEOUT
        max_redirects = ASSESSMENT_MAX_REDIRECTS
        profile_body_limit = ASSESSMENT_MAX_BODY_BYTES

    if max_body_bytes is None:
        max_body_bytes = profile_body_limit

    hard_body_limit = config.WEB_ASSESSMENT_HARD_LIMITS["max_body_bytes"]
    if (
        not isinstance(max_body_bytes, int)
        or isinstance(max_body_bytes, bool)
        or max_body_bytes < 1
        or max_body_bytes > profile_body_limit
        or max_body_bytes > hard_body_limit
    ):
        raise WebAssessmentRequestError("Invalid response size limit.")

    current_url = _validate_assessment_url(url)
    request_headers = {
        "User-Agent": ASSESSMENT_USER_AGENT,
        "Accept": "text/html,application/json;q=0.9,*/*;q=0.1",
    }
    if isinstance(headers, dict):
        request_headers.update(headers)

    for redirect_number in range(max_redirects + 1):
        current_url = _validate_assessment_url(current_url)

        if budget is not None:
            budget.consume()

        response, pinned_adapter = _send_pinned_request(
            session,
            method.upper(),
            current_url,
            params=params,
            data=data,
            headers=request_headers,
            timeout=timeout,
        )

        if response.status_code in {301, 302, 303, 307, 308}:
            redirect_status = response.status_code
            location = response.headers.get("Location")
            try:
                response.close()
            finally:
                pinned_adapter.close()

            if not location:
                raise WebAssessmentRequestError(
                    "Redirect response did not include a destination."
                )
            if redirect_number >= max_redirects:
                raise WebAssessmentRequestError("Redirect limit exceeded.")

            current_url = urljoin(current_url, location)
            if redirect_status == 303 or (
                redirect_status in {301, 302}
                and method.upper() == "POST"
            ):
                method, data, params = "GET", None, None
            continue

        body = bytearray()
        truncated = False
        try:
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                remaining = max_body_bytes - len(body)
                body.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    break

            return {
                "url": current_url,
                "status_code": response.status_code,
                "headers": {
                    str(key).lower(): str(value)
                    for key, value in response.headers.items()
                },
                "body": bytes(body),
                "truncated": truncated,
            }
        finally:
            try:
                response.close()
            finally:
                pinned_adapter.close()

    raise WebAssessmentRequestError("Assessment request did not complete.")

NON_REPLAYABLE_PARAMETER_NAMES = {
    "username", "user", "email",
    "password", "passwd", "token", "access_token",
    "session", "sessionid", "authorization", "csrf",
    "code", "secret", "api_key", "apikey",
}


def _mutate_query_parameter(
    candidate, expected_category, replacement_value, occurrence=0
):
    """Mutate a query parameter only from an eligible planner candidate."""
    if not isinstance(candidate, dict):
        raise WebAssessmentRequestError("Invalid assessment candidate.")

    if candidate.get("replay_eligible") is not True:
        raise WebAssessmentRequestError(
            "Assessment candidate is not eligible for replay."
        )

    if candidate.get("source") != "query":
        raise WebAssessmentRequestError(
            "Only query-parameter candidates may be replayed."
        )

    allowed_categories = {
        "sql_injection", "sql_boolean_based",
        "xss", "ssrf", "path_traversal",
    }
    if (
        not isinstance(expected_category, str)
        or expected_category not in allowed_categories
        or candidate.get("category") != expected_category
    ):
        raise WebAssessmentRequestError(
            "Assessment candidate category does not match."
        )

    parameter_name = candidate.get("parameter")
    if not isinstance(parameter_name, str):
        raise WebAssessmentRequestError("Invalid query parameter name.")

    name = parameter_name.strip()
    if (
        not name
        or len(name) > 100
        or name.lower() in NON_REPLAYABLE_PARAMETER_NAMES
        or "authentication_session" in _classify_parameter(name)
    ):
        raise WebAssessmentRequestError(
            "Query parameter is not eligible for replay."
        )

    if (
        not isinstance(replacement_value, str)
        or len(replacement_value) > 1000
    ):
        raise WebAssessmentRequestError("Invalid replacement value.")

    if (
        not isinstance(occurrence, int)
        or isinstance(occurrence, bool)
        or occurrence < 0
    ):
        raise WebAssessmentRequestError("Invalid query parameter occurrence.")

    location = candidate.get("location")
    if not isinstance(location, str) or not location:
        raise WebAssessmentRequestError(
            "Assessment candidate has no valid location."
        )

    validated_url = _validate_assessment_url(location)
    parsed = urlsplit(validated_url)

    try:
        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            max_num_fields=200,
        )
    except ValueError as exc:
        raise WebAssessmentRequestError(
            "Invalid or oversized query string."
        ) from exc

    matching_indexes = [
        index for index, (key, _) in enumerate(pairs) if key == name
    ]

    if occurrence >= len(matching_indexes):
        raise WebAssessmentRequestError(
            "Selected query parameter occurrence was not found."
        )

    selected_index = matching_indexes[occurrence]
    pairs[selected_index] = (pairs[selected_index][0], replacement_value)

    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        urlencode(pairs),
        "",
    ))


def run_reflected_input_checks(
    checks, profile="standard", session=None, budget=None,
    progress_callback=None,
):
    """Run bounded GET checks using harmless reflection markers."""

    def notify(task):
        if progress_callback is None:
            return
        try:
            progress_callback({"task": task, "percent": None})
        except Exception:
            pass

    try:
        settings = get_assessment_profile(profile)
    except ValueError as exc:
        raise WebAssessmentRequestError(
            "Invalid vulnerability assessment profile."
        ) from exc

    if not isinstance(checks, list):
        raise WebAssessmentRequestError("Invalid reflected-input checks.")

    if budget is None:
        budget = AssessmentRequestBudget(profile=settings["name"])
    elif not isinstance(budget, AssessmentRequestBudget):
        raise WebAssessmentRequestError("Invalid assessment request budget.")

    if budget.profile["name"] != settings["name"]:
        raise WebAssessmentRequestError(
            "Request budget profile does not match assessment profile."
        )

    if len(checks) > settings["max_reflected_input_candidates"]:
        raise WebAssessmentRequestError(
            "Reflected-input checks exceed the selected profile limit."
        )

    http = session if session is not None else requests.Session()
    results = []

    try:
        for index, check in enumerate(checks, start=1):
            notify(f"Reflected-input candidate {index}/{len(checks)}")
            if not isinstance(check, dict):
                raise WebAssessmentRequestError(
                    "Invalid reflected-input check."
                )

            if (
                check.get("category") != "xss"
                or check.get("method") != "GET"
                or check.get("probe") != "unique_reflection_marker"
                or check.get("status") != "not_tested"
                or check.get("verified") is not False
            ):
                raise WebAssessmentRequestError(
                    "Reflected-input check is not an eligible planner check."
                )

            candidate = {
                "category": "xss",
                "parameter": check.get("parameter"),
                "source": "query",
                "location": check.get("location"),
                "replay_eligible": True,
            }

            marker = "SMGRC_REFLECT_" + secrets.token_hex(8)
            mutated_url = _mutate_query_parameter(
                candidate, "xss", marker
            )

            try:
                response = _assessment_request(
                    http, "GET", mutated_url, budget=budget,
                )
            except WebAssessmentRequestError as exc:
                if "budget exhausted" not in str(exc).lower():
                    raise

                results.append({
                    "category": "xss",
                    "parameter": check["parameter"],
                    "method": "GET",
                    "url": mutated_url,
                    "status": "not_tested",
                    "confidence": "none",
                    "occurrences": 0,
                    "evidence": [],
                    "contexts": [],
                    "verified": False,
                    "notes": (
                        "The reflected-input check could not be completed "
                        "because the global request budget was exhausted. "
                        "No conclusion can be drawn."
                    ),
                })
                continue

            detection = detect_reflected_input(
                response["body"],
                marker,
                truncated=response["truncated"],
            )

            results.append({
                "category": "xss",
                "parameter": check["parameter"],
                "method": "GET",
                "url": response["url"],
                "status_code": response["status_code"],
                "status": detection["status"],
                "confidence": detection["confidence"],
                "occurrences": detection["occurrences"],
                "evidence": detection["evidence"],
                "contexts": detection["contexts"],
                "verified": False,
                "notes": detection["notes"],
            })
    finally:
        if session is None:
            http.close()

    return {
        "status": "completed",
        "profile": settings["name"],
        "checks": results,
        "requests_used": budget.used,
        "requests_remaining": budget.remaining,
        "verified_vulnerabilities": 0,
        "notes": [
            "Only GET query checks were executed.",
            "Unique harmless markers identify exact reflection only.",
            "Reflection does not establish executable cross-site scripting.",
            "No forms were submitted and no scripts or destructive payloads were used.",
        ],
    }


def run_sql_injection_checks(
    checks, profile="standard", session=None, budget=None,
    progress_callback=None,
):
    """Run bounded SQL error-indicator checks using GET only."""

    def notify(task):
        if progress_callback is None:
            return
        try:
            progress_callback({"task": task, "percent": None})
        except Exception:
            pass

    try:
        settings = get_assessment_profile(profile)
    except ValueError as exc:
        raise WebAssessmentRequestError(
            "Invalid vulnerability assessment profile."
        ) from exc

    if not isinstance(checks, list):
        raise WebAssessmentRequestError("Invalid SQL injection checks.")

    if budget is None:
        budget = AssessmentRequestBudget(profile=settings["name"])
    elif not isinstance(budget, AssessmentRequestBudget):
        raise WebAssessmentRequestError("Invalid assessment request budget.")

    if budget.profile["name"] != settings["name"]:
        raise WebAssessmentRequestError(
            "Request budget profile does not match assessment profile."
        )

    if len(checks) > settings["max_sqli_candidates"]:
        raise WebAssessmentRequestError(
            "SQL injection checks exceed the selected profile limit."
        )

    http = session if session is not None else requests.Session()
    results = []

    try:
        for index, check in enumerate(checks, start=1):
            notify(f"SQL injection candidate {index}/{len(checks)}")
            if not isinstance(check, dict):
                raise WebAssessmentRequestError(
                    "Invalid SQL injection check."
                )

            if (
                check.get("category") != "sql_injection"
                or check.get("method") != "GET"
                or check.get("probe") != "single_quote"
                or check.get("status") != "not_tested"
                or check.get("verified") is not False
            ):
                raise WebAssessmentRequestError(
                    "SQL injection check is not an eligible planner check."
                )

            candidate = {
                "category": "sql_injection",
                "parameter": check.get("parameter"),
                "source": "query",
                "location": check.get("location"),
                "replay_eligible": True,
            }

            mutated_url = _mutate_query_parameter(
                candidate, "sql_injection", "'"
            )

            if budget.remaining < 2:
                results.append({
                    "category": "sql_injection",
                    "parameter": check["parameter"],
                    "method": "GET",
                    "url": check["location"],
                    "status": "not_tested",
                    "confidence": "none",
                    "verified": False,
                    "notes": [
                        "Insufficient request budget for a complete "
                        "baseline and test pair; no request was sent."
                    ],
                })
                continue

            try:
                baseline_response = _assessment_request(
                    http, "GET", check["location"], budget=budget,
                )

                test_response = _assessment_request(
                    http, "GET", mutated_url, budget=budget,
                )
            except WebAssessmentRequestError as exc:
                if "budget exhausted" not in str(exc).lower():
                    raise

                results.append({
                    "category": "sql_injection",
                    "parameter": check["parameter"],
                    "method": "GET",
                    "url": check["location"],
                    "status": "not_tested",
                    "confidence": "none",
                    "verified": False,
                    "notes": [
                        "The baseline and test request pair could not be "
                        "completed because the global request budget "
                        "was exhausted. No conclusion can be drawn."
                    ],
                })
                continue

            comparison = compare_sql_responses(
                baseline_response, test_response
            )

            results.append({
                "category": "sql_injection",
                "parameter": check["parameter"],
                "method": "GET",
                "url": test_response["url"],
                "baseline_url": baseline_response["url"],
                "baseline_status_code": baseline_response["status_code"],
                "status_code": test_response["status_code"],
                "status": comparison["status"],
                "confidence": comparison["confidence"],
                "differences": comparison["differences"],
                "body_length_delta": comparison.get("body_length_delta"),
                "body_length_change_percent": comparison.get(
                    "body_length_change_percent"
                ),
                "database_error_indicators": comparison.get(
                    "database_error_indicators", []
                ),
                "verified": False,
                "notes": comparison.get("notes", [
                    "Response comparison does not confirm SQL injection."
                ]),
            })
    finally:
        if session is None:
            http.close()

    return {
        "status": "completed",
        "profile": settings["name"],
        "checks": results,
        "requests_used": budget.used,
        "requests_remaining": budget.remaining,
        "verified_vulnerabilities": 0,
        "notes": [
            "Only GET query checks were executed.",
            "Each candidate uses one original-value baseline and one "
            "single-quote variation.",
            "No forms, POST requests, authentication fields, or destructive "
            "payloads were used.",
            "Database error indicators and response differences are "
            "unverified evidence requiring independent review.",
        ],
    }


    return {
        "status": "completed",
        "profile": settings["name"],
        "checks": results,
        "requests_used": budget.used,
        "requests_remaining": budget.remaining,
        "verified_vulnerabilities": 0,
        "notes": [
            "Only GET query checks were executed.",
            "Each candidate uses one original-value baseline and one "
            "single-quote variation.",
            "No forms, POST requests, authentication fields, or destructive "
            "payloads were used.",
            "Database error indicators and response differences are "
            "unverified evidence requiring independent review.",
        ],
    }


def plan_vulnerability_assessment(attack_surface, profile=None):
    """Create a passive, profile-aware plan without sending HTTP requests."""
    try:
        settings = get_assessment_profile(profile)
    except ValueError as exc:
        raise WebAssessmentRequestError(
            "Invalid vulnerability assessment profile."
        ) from exc

    if not isinstance(attack_surface, dict):
        attack_surface = {}

    parameters = attack_surface.get("parameters")
    forms = attack_surface.get("forms")
    authentication = attack_surface.get("authentication_surfaces")

    if not isinstance(parameters, list):
        parameters = []
    if not isinstance(forms, list):
        forms = []
    if not isinstance(authentication, list):
        authentication = []

    candidates = []
    seen = set()

    def add_candidate(category, name, source, location, replay_eligible):
        key = (category, name.lower(), source, location)
        if key in seen:
            return
        seen.add(key)
        indicators = []
        if category == "ssrf":
            indicators.append({
                "type": "parameter_name_pattern",
                "description": (
                    "URL-like input identified; server-side request "
                    "behavior has not been tested."
                ),
            })
        elif category == "path_traversal":
            indicators.append({
                "type": "parameter_name_pattern",
                "description": (
                    "File, path, page or include-like input identified; "
                    "filesystem handling has not been tested."
                ),
            })
        elif category == "command_injection":
            indicators.append({
                "type": "parameter_name_pattern",
                "description": (
                    "Command-related input identified; operating-system "
                    "command execution has not been tested."
                ),
            })

        candidates.append({
            "category": category,
            "parameter": name,
            "source": source,
            "location": location,
            "status": "not_tested",
            "replay_eligible": bool(
                replay_eligible
                and category in {"sql_injection", "xss"}
            ),
            "indicators": indicators,
            "evidence": [],
            "confidence": "none",
        })

    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue

        name = str(parameter.get("name") or "").strip()[:100]
        source = str(parameter.get("source") or "unknown")[:30]
        location = str(parameter.get("location") or "")[:4096]
        if not name:
            continue

        # Reclassify untrusted discovery metadata from the parameter name.
        # Never let supplied categories introduce assessment candidates.
        categories = _classify_parameter(name)

        replay_eligible = (
            name.lower() not in NON_REPLAYABLE_PARAMETER_NAMES
            and source == "query"
            and "authentication_session" not in categories
        )

        for category in categories:
            if category not in {
                "sql_injection",
                "xss",
                "ssrf",
                "path_traversal",
                "command_injection",
                "authentication_session",
            }:
                continue

            add_candidate(
                category,
                name,
                source,
                location,
                replay_eligible,
            )

    for form in forms:
        if not isinstance(form, dict):
            continue

        action = str(form.get("action") or "")[:4096]
        method = str(form.get("method") or "unknown").lower()
        fields = form.get("fields")

        if not isinstance(fields, list):
            continue

        for field in fields[:100]:
            if not isinstance(field, dict):
                continue

            name = str(field.get("name") or "").strip()[:100]
            field_type = str(field.get("type") or "").lower()

            if not name:
                continue

            categories = _classify_form_field(
                name,
                field_type=field_type,
                autocomplete=field.get("autocomplete"),
            )
            # Form fields remain review-only until a separately scoped,
            # safe form-assessment workflow is implemented.
            replay_eligible = False

            for category in categories:
                add_candidate(
                    category,
                    name,
                    "form",
                    action,
                    replay_eligible,
                )

    for surface in authentication:
        if not isinstance(surface, dict):
            continue

        location = str(surface.get("location") or "")[:4096]
        surface_type = str(surface.get("type") or "unknown")[:30]

        add_candidate(
            "authentication_session",
            surface_type,
            "authentication_surface",
            location,
            False,
        )

    sql_injection_checks = []
    seen_sql_checks = set()

    for candidate in candidates:
        if (
            candidate["category"] != "sql_injection"
            or candidate["source"] != "query"
            or not candidate["replay_eligible"]
        ):
            continue

        key = (
            candidate["parameter"].lower(),
            candidate["location"],
        )
        if key in seen_sql_checks:
            continue
        seen_sql_checks.add(key)

        sql_injection_checks.append({
            "category": "sql_injection",
            "parameter": candidate["parameter"],
            "location": candidate["location"],
            "method": "GET",
            "probe": "single_quote",
            "status": "not_tested",
            "confidence": "none",
            "verified": False,
            "rationale": (
                "A single quote is a low-impact input variation intended "
                "to identify possible database error handling."
            ),
        })

        if len(sql_injection_checks) >= settings["max_sqli_candidates"]:
            break

    sql_boolean_based_checks = []
    seen_boolean_checks = set()

    for candidate in candidates:
        if (
            candidate["category"] != "sql_injection"
            or candidate["source"] != "query"
            or not candidate["replay_eligible"]
        ):
            continue

        key = (
            candidate["parameter"].lower(),
            candidate["location"],
        )
        if key in seen_boolean_checks:
            continue
        seen_boolean_checks.add(key)

        sql_boolean_based_checks.append({
            "category": "sql_boolean_based",
            "parameter": candidate["parameter"],
            "location": candidate["location"],
            "method": "GET",
            "probe": "boolean_condition_pair",
            "sql_context": "unknown",
            "review_only": True,
            "status": "not_tested",
            "confidence": "none",
            "verified": False,
            "rationale": (
                "A controlled pair of logically equivalent and "
                "contradictory Boolean conditions is planned to identify "
                "possible response differences."
            ),
        })

        if (
            len(sql_boolean_based_checks)
            >= settings["max_boolean_sqli_candidates"]
        ):
            break

    reflected_input_checks = []
    seen_reflected_checks = set()

    for candidate in candidates:
        if (
            candidate["category"] != "xss"
            or candidate["source"] != "query"
            or not candidate["replay_eligible"]
        ):
            continue

        key = (
            candidate["parameter"].lower(),
            candidate["location"],
        )
        if key in seen_reflected_checks:
            continue
        seen_reflected_checks.add(key)

        reflected_input_checks.append({
            "category": "xss",
            "parameter": candidate["parameter"],
            "location": candidate["location"],
            "method": "GET",
            "probe": "unique_reflection_marker",
            "status": "not_tested",
            "confidence": "none",
            "verified": False,
            "rationale": (
                "A unique harmless marker is intended to identify exact "
                "input reflection without testing script execution."
            ),
        })

        if (
            len(reflected_input_checks)
            >= settings["max_reflected_input_candidates"]
        ):
            break

    return {
        "status": "planned",
        "profile": settings["name"],
        "profile_limits": {
            "max_requests": settings["max_requests"],
            "max_body_bytes": settings["max_body_bytes"],
            "max_redirects": settings["max_redirects"],
            "max_sqli_candidates": settings["max_sqli_candidates"],
            "max_boolean_sqli_candidates": (
                settings["max_boolean_sqli_candidates"]
            ),
            "max_reflected_input_candidates": (
                settings["max_reflected_input_candidates"]
            ),
        },
        "candidates": candidates,
        "sql_injection_checks": sql_injection_checks,
        "sql_boolean_based_checks": sql_boolean_based_checks,
        "reflected_input_checks": reflected_input_checks,
        "summary": {
            "total": len(candidates),
            "replay_eligible": sum(
                item["replay_eligible"] for item in candidates
            ),
            "not_replay_eligible": sum(
                not item["replay_eligible"] for item in candidates
            ),
            "not_tested": len(candidates),
        },
        "notes": [
            "Planning only; no HTTP requests or form submissions are performed.",
            "Candidate classification does not establish a vulnerability.",
            "Password, token, session, authorization and CSRF inputs are not replayed.",
            "Only eligible GET query and form parameters may be considered for later controlled checks.",
            "POST and other non-GET forms are not submitted by this planner.",
            "SQL injection planning is capped by the selected profile limit for eligible GET query checks.",
            "SQL injection checks are plans only; no probe is sent and no vulnerability is confirmed.",
            "Boolean-based SQL injection checks are separately planned and capped by the selected profile.",
            "Boolean-based SQL injection checks are plans only; no HTTP requests are sent and no vulnerability is confirmed.",
            "Reflected-input checks are limited to eligible GET query parameters and capped by the selected profile.",
            "Reflected-input checks are plans only; no marker is sent and no vulnerability is confirmed.",
        ],
    }
