"""Read-only discovery for authorized HTTP/HTTPS web targets."""

from collections import deque
from html.parser import HTMLParser
import re
from urllib.parse import urljoin, urlsplit, urldefrag

import requests

from config import (
    WEB_CRAWLER_MAX_PAGES,
    WEB_CRAWLER_MAX_REQUESTS,
    WEB_CRAWLER_MAX_BODY_BYTES,
    WEB_CRAWLER_MAX_URLS,
)
from scanner.web_app_assessment import (
    AssessmentRequestBudget,
    AssessmentTargetValidationError,
    WebAssessmentRequestError,
    get_assessment_profile,
    normalize_assessment_target,
)
from scanner.web_security_scanner import (
    WebSecurityError,
    _validate_authorized_web_url,
)


MAX_PAGES = WEB_CRAWLER_MAX_PAGES
MAX_REQUESTS = WEB_CRAWLER_MAX_REQUESTS
MAX_BODY_BYTES = WEB_CRAWLER_MAX_BODY_BYTES
MAX_URLS = WEB_CRAWLER_MAX_URLS
REDIRECT_LIMIT = 5
USER_AGENT = "ShadowMapGRC-ReadOnlyCrawler/1.0"


class _DiscoveryParser(HTMLParser):
    """Extract URL references and detailed form metadata without execution."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.script_sources = []
        self.inline_scripts = []
        self.forms = []
        self._form = None
        self._field = None
        self._inside_script = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()

        if tag == "script":
            self._inside_script = True
            if attrs.get("src"):
                self.script_sources.append(attrs["src"])

        if tag == "form":
            self._form = {
                "method": (attrs.get("method") or "get").lower(),
                "action": attrs.get("action") or "",
                "enctype": (attrs.get("enctype") or
                            "application/x-www-form-urlencoded").lower(),
                "fields": [],
            }
            self.forms.append(self._form)
            return

        if tag in {"input", "textarea", "select", "button"}:
            if self._form is not None and len(self._form["fields"]) < 100:
                field = {
                    "element": tag,
                    "name": (attrs.get("name") or "")[:100],
                    "required": "required" in attrs,
                }

                if tag == "input":
                    field["type"] = (attrs.get("type") or "text").lower()[:30]
                    field["autocomplete"] = (
                        attrs.get("autocomplete") or ""
                    )[:100]
                elif tag == "textarea":
                    field["type"] = "textarea"
                elif tag == "select":
                    field["type"] = "select"
                    field["options"] = []
                else:
                    field["type"] = (
                        attrs.get("type") or "submit"
                    ).lower()[:30]
                    field["form"] = (attrs.get("form") or "")[:100]

                self._form["fields"].append(field)

                if tag in {"select", "textarea"}:
                    self._field = field

        elif tag == "option" and self._field is not None:
            if self._field["element"] == "select":
                value = attrs.get("value", "")
                if len(self._field["options"]) < 100:
                    self._field["options"].append(value[:200])

        if tag in {"a", "area", "link"} and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag == "script" and attrs.get("src"):
            self.links.append(attrs["src"])

    def handle_data(self, data):
        if self._inside_script and data.strip():
            self.inline_scripts.append(data)

    def handle_endtag(self, tag):
        tag = tag.lower()

        if tag == "script":
            self._inside_script = False
        elif tag in {"select", "textarea"}:
            self._field = None
        elif tag == "form":
            self._form = None
            self._field = None



API_ROUTE_PATTERN = re.compile(
    r"""["'`](?P<path>(?:/|\.\.?/)[^"'`\s<>]{1,500})["'`]""",
    re.I,
)

API_ROUTE_INDICATOR = re.compile(
    r"/(?:api|graphql|auth|login|logout|oauth|v[0-9]+|"
    r"swagger|openapi|ws|websocket|token|session)(?:/|$|[?#])",
    re.I,
)


def _extract_javascript_endpoints(body):
    """Extract likely API routes from JavaScript without executing it."""
    if isinstance(body, bytes):
        text = body.decode("utf-8", errors="replace")
    else:
        text = str(body or "")

    endpoints = set()

    for match in API_ROUTE_PATTERN.finditer(text):
        path = match.group("path")
        if API_ROUTE_INDICATOR.search(path):
            endpoints.add(path)

    return sorted(endpoints)

def _origin(url):
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    return (
        scheme,
        (parsed.hostname or "").lower().rstrip("."),
        parsed.port or default_port,
    )


def _clean_reference(base_url, reference, origin=None):
    """Resolve and normalize an HTTP/HTTPS reference without authorizing it."""
    if not isinstance(reference, str) or not reference or len(reference) > 2048:
        return None

    try:
        candidate = urljoin(base_url, reference.strip())
        candidate, _fragment = urldefrag(candidate)
        candidate = normalize_assessment_target(candidate)
        if origin is not None and _origin(candidate) != origin:
            return None
        return candidate
    except (AssessmentTargetValidationError, ValueError):
        return None


def _read_bounded_body(response, limit):
    """Read at most limit bytes from a streamed response."""
    chunks = []
    total = 0

    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue

        remaining = limit - total
        if remaining <= 0:
            break

        chunk = chunk[:remaining]
        chunks.append(chunk)
        total += len(chunk)

        if total >= limit:
            break

    return b"".join(chunks), total >= limit


def _get_checked(
    session,
    url,
    body_limit,
    origin,
    request_budget,
):
    """GET only same-origin URLs with bounded data and checked redirects."""
    current = url

    for redirect_number in range(REDIRECT_LIMIT + 1):
        if _origin(current) != origin:
            raise WebSecurityError(
                "URL is outside the supplied target origin; request blocked."
            )

        # Target boundary is checked before DNS validation and network access.
        safe_url = _validate_authorized_web_url(current)

        request_budget.consume()
        response = session.get(
            safe_url,
            timeout=request_budget.request_timeout(3, 5),
            allow_redirects=False,
            stream=True,
            verify=True,
            headers={"User-Agent": USER_AGENT},
        )

        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location")
            if not location:
                response.close()
                raise WebSecurityError("Redirect had no destination.")

            if redirect_number >= REDIRECT_LIMIT:
                response.close()
                raise WebSecurityError("Crawler redirect limit reached.")

            destination = _clean_reference(
                safe_url, location, origin=origin
            )
            if not destination:
                status_code = response.status_code
                response.close()
                return {
                    "url": safe_url,
                    "status_code": status_code,
                    "content_type": "",
                    "body": b"",
                    "truncated": False,
                    "blocked_redirect": "cross-origin or invalid destination",
                }

            response.close()
            current = destination
            continue

        try:
            content_type = response.headers.get(
                "Content-Type", ""
            ).split(";", 1)[0].strip().lower()
        except AttributeError:
            content_type = ""

        try:
            body, truncated = _read_bounded_body(response, body_limit)
            return {
                "url": safe_url,
                "status_code": response.status_code,
                "content_type": content_type,
                "body": body,
                "truncated": truncated,
                "blocked_redirect": None,
            }
        finally:
            response.close()

    raise WebSecurityError("Crawler redirect limit reached.")


def _extract_sitemap_locations(body):
    text = body.decode("utf-8", errors="replace")
    return re.findall(r"<loc>\s*(.*?)\s*</loc>", text, flags=re.I | re.S)


def crawl_public_site(
    target,
    max_pages=MAX_PAGES,
    max_requests=MAX_REQUESTS,
    max_body_bytes=MAX_BODY_BYTES,
    max_urls=MAX_URLS,
    profile="standard",
    request_budget=None,
    progress_callback=None,
):
    """
    Crawl the supplied target origin using bounded, read-only GET requests.

    Does not submit forms, execute JavaScript, or test exploit payloads.
    """
    limits = {
        "max_pages": max_pages,
        "max_requests": max_requests,
        "max_body_bytes": max_body_bytes,
        "max_urls": max_urls,
    }
    for name, value in limits.items():
        if type(value) is not int or value < 1:
            raise WebSecurityError(f"{name} must be a positive integer.")

    if max_body_bytes < 1024:
        raise WebSecurityError("max_body_bytes must be at least 1024.")

    try:
        profile_settings = get_assessment_profile(profile)
        start_url = normalize_assessment_target(target)
    except (AssessmentTargetValidationError, ValueError) as exc:
        raise WebSecurityError(str(exc)) from exc

    # The supplied target establishes the temporary crawl boundary.
    origin = _origin(start_url)

    if request_budget is None:
        request_budget = AssessmentRequestBudget(
            maximum=min(max_requests, profile_settings["max_requests"]),
            profile=profile,
        )

    if not isinstance(request_budget, AssessmentRequestBudget):
        raise WebSecurityError("Invalid assessment request budget.")

    starting_used = request_budget.used
    queue = deque([start_url])
    queued = {start_url}
    visited = set()
    pages = []
    discovered = set()
    api_endpoints = set()
    forms = []
    errors = []
    blocked_urls = []
    deferred_urls = []
    truncated_pages = 0
    discovery_files_seeded = False

    session = requests.Session()
    session.trust_env = False

    try:
        while (
            queue
            and len(pages) < max_pages
            and request_budget.remaining > 0
            and request_budget.used - starting_used < max_requests
        ):
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)

            try:
                item = _get_checked(
                    session,
                    current,
                    max_body_bytes,
                    origin,
                    request_budget,
                )
            except WebAssessmentRequestError as exc:
                errors.append({
                    "url": current,
                    "message": str(exc)[:200],
                })
                break
            except (WebSecurityError, requests.RequestException) as exc:
                errors.append({
                    "url": current,
                    "message": str(exc)[:200],
                })
                continue

            content_type = item["content_type"]
            is_html = content_type in {
                "text/html", "application/xhtml+xml"
            }
            is_javascript = (
                "javascript" in content_type
                or current.lower().split("?", 1)[0].endswith(".js")
            )
            is_text_discovery = (
                current.lower().endswith(("/robots.txt", "/sitemap.xml"))
                or content_type in {
                    "text/plain", "application/xml", "text/xml",
                    "application/xhtml+xml",
                }
            )

            page = {
                "url": item["url"],
                "status_code": item["status_code"],
                "content_type": content_type or "unknown",
                "truncated": item["truncated"],
                "blocked_redirect": item.get("blocked_redirect"),
            }
            pages.append(page)

            if item.get("blocked_redirect"):
                blocked_urls.append({
                    "url": item["blocked_redirect"],
                    "reason": "Redirect destination is not covered by an approved scope.",
                })

            if item["truncated"]:
                truncated_pages += 1

            references = []
            javascript_references = set()

            if is_html and item["body"]:
                parser = _DiscoveryParser()
                try:
                    parser.feed(
                        item["body"].decode("utf-8", errors="replace")
                    )
                    references.extend(parser.links)

                    for script in parser.inline_scripts:
                        endpoints = _extract_javascript_endpoints(script)
                        references.extend(endpoints)
                        javascript_references.update(endpoints)

                    for form in parser.forms:
                        action = _clean_reference(
                            item["url"],
                            form["action"] or item["url"],
                            origin=origin,
                        )
                        action_authorized = bool(action)
                        forms.append({
                            "page": item["url"],
                            "method": form["method"],
                            "action": (
                                action
                                if action
                                else "not followed (invalid URL)"
                            ),
                            "action_authorized": action_authorized,
                            "enctype": form["enctype"],
                            "fields": form["fields"],
                            "submission": "not submitted",
                        })
                except Exception:
                    errors.append({
                        "url": item["url"],
                        "message": (
                            "HTML parsing failed; remaining page skipped."
                        ),
                    })

            if is_javascript and item["body"]:
                endpoints = _extract_javascript_endpoints(item["body"])
                references.extend(endpoints)
                javascript_references.update(endpoints)

            if is_text_discovery and item["body"]:
                text_body = item["body"].decode(
                    "utf-8", errors="replace"
                )
                if current.lower().endswith("/robots.txt"):
                    for line in text_body.splitlines():
                        key, separator, value = line.partition(":")
                        if separator and key.strip().lower() == "sitemap":
                            references.append(value.strip())

                if current.lower().endswith("/sitemap.xml") or (
                    content_type in {"application/xml", "text/xml"}
                ):
                    references.extend(
                        _extract_sitemap_locations(item["body"])
                    )

            for reference in references:
                safe_url = _clean_reference(
                    item["url"], reference, origin=origin
                )
                if not safe_url:
                    continue

                if safe_url in queued or safe_url in visited:
                    continue

                discovered.add(safe_url)
                if reference in javascript_references:
                    api_endpoints.add(safe_url)

                if len(queued) >= max_urls:
                    deferred_urls.append({
                        "url": safe_url,
                        "reason": "Crawler URL limit reached.",
                    })
                    continue

                queue.append(safe_url)
                queued.add(safe_url)

            # Queue standard discovery files after homepage links.
            if current == start_url and not discovery_files_seeded:
                discovery_files_seeded = True
                for path_suffix in ("/robots.txt", "/sitemap.xml"):
                    candidate = _clean_reference(
                        start_url, path_suffix, origin=origin
                    )
                    if (
                        not candidate
                        or candidate in queued
                        or candidate in visited
                    ):
                        continue

                    if len(queued) >= max_urls:
                        deferred_urls.append({
                            "url": candidate,
                            "reason": "Crawler URL limit reached.",
                        })
                        continue

                    queue.append(candidate)
                    queued.add(candidate)

            if progress_callback is not None:
                try:
                    completed = len(pages)
                    progress_callback({
                        "task": (
                            f"Discovering pages ({completed}/{max_pages})"
                        ),
                        "completed": completed,
                        "total": max_pages,
                        "percent": min(
                            100.0, completed * 100.0 / max_pages
                        ),
                    })
                except Exception:
                    pass

    finally:
        session.close()

    requests_used = request_budget.used - starting_used
    request_limit_reached = (
        bool(queue)
        and (
            request_budget.remaining <= 0
            or requests_used >= max_requests
        )
    )

    if queue and len(pages) >= max_pages:
        deferred_urls.extend({
            "url": url,
            "reason": "Crawler page limit reached.",
        } for url in queue)

    elif request_limit_reached:
        deferred_urls.extend({
            "url": url,
            "reason": "Assessment request budget exhausted.",
        } for url in queue)

    return {
        "target": start_url,
        "pages": pages,
        "discovered_urls": sorted(discovered),
        "api_endpoints": sorted(api_endpoints),
        "forms": forms,
        "errors": errors,
        "blocked_urls": blocked_urls,
        "deferred_urls": deferred_urls,
        "limits": {
            "max_pages": max_pages,
            "max_requests": max_requests,
            "requests_used": requests_used,
            "max_body_bytes_per_response": max_body_bytes,
            "max_urls": max_urls,
            "urls_queued": len(queued),
            "truncated_pages": truncated_pages,
            "page_limit_reached": (
                len(pages) >= max_pages and bool(queue)
            ),
            "request_limit_reached": request_limit_reached,
        },
        "notes": [
            "Read-only GET requests only; forms are recorded but never submitted.",
            "JavaScript is not executed; likely API routes are extracted using static pattern matching.",
            "Each requested URL and redirect destination must independently match an approved scope.",
            "Discovered paths are observations, not proof of vulnerabilities.",
            "DNS is validated before each request; this is not a complete defense against DNS rebinding.",
        ],
    }
