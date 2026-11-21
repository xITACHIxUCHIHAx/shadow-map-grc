"""Read-only HTTP/HTTPS header checks for authorized web targets."""

import ipaddress
import re
import socket
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from scanner.web_app_assessment import (
    AssessmentRequestBudget,
    AssessmentTargetValidationError,
    WebAssessmentRequestError,
    get_assessment_profile,
    normalize_assessment_target,
)


class WebSecurityError(Exception):
    """Expected validation or connection error."""


SECURITY_HEADERS = {
    "strict-transport-security": (
        "HSTS",
        "Helps browsers enforce HTTPS on future visits."
    ),
    "content-security-policy": (
        "Content Security Policy",
        "Can reduce the impact of some content-injection attacks."
    ),
    "x-content-type-options": (
        "X-Content-Type-Options",
        "Helps prevent MIME-type sniffing; commonly set to nosniff."
    ),
    "x-frame-options": (
        "X-Frame-Options",
        "Can help prevent clickjacking; CSP frame-ancestors is an alternative."
    ),
    "referrer-policy": (
        "Referrer Policy",
        "Controls how much referrer information browsers send."
    ),
    "permissions-policy": (
        "Permissions Policy",
        "Controls access to selected browser features."
    ),
}


def _validate_public_https_url(value):
    value = (value or "").strip()

    if not value or len(value) > 2048:
        raise WebSecurityError("Enter a valid public website URL or hostname.")

    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise WebSecurityError("The URL or port is invalid.") from exc

    if parsed.scheme.lower() != "https":
        raise WebSecurityError(
            "Enter a hostname or HTTPS URL. This version checks HTTPS only."
        )

    if not parsed.hostname or parsed.username or parsed.password:
        raise WebSecurityError("The URL must not contain login credentials.")

    if port not in (None, 443):
        raise WebSecurityError("Only the standard HTTPS port 443 is allowed.")

    host = parsed.hostname.rstrip(".")
    if not host or any(char.isspace() for char in host):
        raise WebSecurityError("The hostname is invalid.")

    # Resolve the hostname and reject private, loopback, reserved and
    # otherwise non-public addresses before making a request.
    try:
        literal_ip = ipaddress.ip_address(host)
        addresses = [literal_ip]
    except ValueError:
        try:
            records = socket.getaddrinfo(
                host, 443, type=socket.SOCK_STREAM
            )
            addresses = [
                ipaddress.ip_address(record[4][0])
                for record in records
            ]
        except (OSError, ValueError) as exc:
            raise WebSecurityError(
                "The hostname could not be resolved."
            ) from exc

    if not addresses:
        raise WebSecurityError("The hostname has no usable IP address.")

    if any(not address.is_global for address in addresses):
        raise WebSecurityError(
            "The target resolves to a non-public IP address and was blocked."
        )

    netloc = f"[{host}]" if ":" in host else host
    if port:
        netloc += f":{port}"

    safe_path = parsed.path or "/"
    return urlunsplit(("https", netloc, safe_path, parsed.query, ""))



def _validate_authorized_web_url(value):
    """
    Validate an authorized HTTP/HTTPS target, including private networks.

    Public, private, and loopback addresses are supported. Link-local,
    multicast, unspecified, and reserved addresses are rejected.
    """
    value = (value or "").strip()

    if not value or len(value) > 2048:
        raise WebSecurityError("Enter a valid authorized website URL or hostname.")

    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise WebSecurityError("The URL or port is invalid.") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise WebSecurityError("Only HTTP and HTTPS targets are supported.")

    if not parsed.hostname or parsed.username or parsed.password:
        raise WebSecurityError("The URL must not contain login credentials.")

    if port is not None and not 1 <= port <= 65535:
        raise WebSecurityError("The target port must be between 1 and 65535.")

    host = parsed.hostname.rstrip(".")
    if not host or any(char.isspace() for char in host):
        raise WebSecurityError("The hostname is invalid.")

    effective_port = port or (443 if scheme == "https" else 80)

    try:
        literal_ip = ipaddress.ip_address(host)
        addresses = [literal_ip]
    except ValueError:
        try:
            records = socket.getaddrinfo(
                host, effective_port, type=socket.SOCK_STREAM
            )
            addresses = [
                ipaddress.ip_address(record[4][0])
                for record in records
            ]
        except (OSError, ValueError) as exc:
            raise WebSecurityError(
                "The hostname could not be resolved."
            ) from exc

    if not addresses:
        raise WebSecurityError("The hostname has no usable IP address.")

    for address in addresses:
        if (
            address.is_unspecified
            or address.is_multicast
            or address.is_link_local
            or address.is_reserved
        ):
            raise WebSecurityError(
                "The target resolves to an unsupported or unsafe IP address."
            )

        # Allow global, private, and loopback addresses. Reject other
        # special-purpose ranges such as shared address space.
        if not (
            address.is_global
            or address.is_private
            or address.is_loopback
        ):
            raise WebSecurityError(
                "The target resolves to an unsupported IP address."
            )

    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"

    safe_path = parsed.path or "/"
    return urlunsplit((scheme, netloc, safe_path, parsed.query, ""))

def _assess_header(key, value, headers):
    """Perform conservative checks on selected security-header values."""
    if not value:
        return "Missing", True

    normalized = value.strip().lower()

    if key == "strict-transport-security":
        match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", normalized)
        if not match or int(match.group(1)) == 0:
            return "Review: missing or zero max-age", True

    elif key == "content-security-policy":
        if "unsafe-inline" in normalized or "unsafe-eval" in normalized:
            return "Review: contains unsafe-inline or unsafe-eval", True

    elif key == "x-content-type-options":
        if normalized != "nosniff":
            return "Review: expected nosniff", True

    elif key == "x-frame-options":
        if normalized not in {"deny", "sameorigin"}:
            csp = headers.get("content-security-policy", "").lower()
            if "frame-ancestors" not in csp:
                return "Review: check clickjacking protection", True

    elif key == "referrer-policy":
        policies = {
            "no-referrer", "no-referrer-when-downgrade", "origin",
            "origin-when-cross-origin", "same-origin", "strict-origin",
            "strict-origin-when-cross-origin", "unsafe-url",
        }
        selected = [part.strip() for part in normalized.split(",")]
        if not selected or selected[-1] not in policies:
            return "Review: unrecognized policy value", True
        if selected[-1] == "unsafe-url":
            return "Review: unsafe-url may disclose referrer details", True

    return "Present; value needs contextual review", False


def scan_web_security(
    target,
    profile="standard",
    request_budget=None,
    run_guard=None,
    progress_callback=None,
):
    """Check headers and discover attack surfaces using bounded requests."""

    def emit(task, percent=None, detail=None):
        if progress_callback is None:
            return
        event = {"task": task, "percent": percent}
        if detail is not None:
            event["detail"] = detail
        try:
            progress_callback(event)
        except Exception:
            pass

    emit("Validating web target")

    from scanner.web_app_assessment import (
        analyze_attack_surface,
        plan_vulnerability_assessment,
        run_reflected_input_checks,
        run_sql_injection_checks,
    )

    raw_target = (target or "").strip()
    if raw_target and "://" not in raw_target:
        raw_target = "https://" + raw_target

    try:
        current_url = normalize_assessment_target(raw_target)
        profile_settings = get_assessment_profile(profile)
    except (AssessmentTargetValidationError, ValueError) as exc:
        raise WebSecurityError(str(exc)) from exc

    if request_budget is None:
        request_budget = AssessmentRequestBudget(
            profile=profile,
            run_guard=run_guard,
        )
    elif run_guard is not None and request_budget.run_guard is not run_guard:
        raise WebSecurityError(
            "Request budget does not use the supplied Unified Scan guard."
        )

    if not isinstance(request_budget, AssessmentRequestBudget):
        raise WebSecurityError("Invalid assessment request budget.")

    if request_budget.profile["name"] != profile_settings["name"]:
        raise WebSecurityError(
            "Request budget profile does not match assessment profile."
        )

    session = requests.Session()
    session.trust_env = False

    emit("Checking HTTP response and security headers")
    headers = {}
    cookie_headers = []
    status_code = None
    max_redirects = profile_settings["max_redirects"]

    try:
        # Initial request and manually validated redirects.
        for redirect_number in range(max_redirects + 1):
            safe_url = _validate_authorized_web_url(current_url)

            try:
                request_budget.consume()
                response = session.get(
                    safe_url,
                    timeout=request_budget.request_timeout(3, 5),
                    allow_redirects=False,
                    stream=True,
                    verify=True,
                    headers={
                        "User-Agent": "ShadowMapGRC-HeaderCheck/1.0"
                    },
                )
            except WebAssessmentRequestError:
                raise
            except requests.exceptions.SSLError as exc:
                raise WebSecurityError(
                    "TLS certificate verification failed. Check the "
                    "website's certificate and hostname."
                ) from exc
            except requests.RequestException as exc:
                raise WebSecurityError(
                    "The HTTP/HTTPS request failed or timed out."
                ) from exc

            is_redirect = response.status_code in (
                301, 302, 303, 307, 308
            )

            if is_redirect:
                location = response.headers.get("Location")
                if not location:
                    response.close()
                    raise WebSecurityError(
                        "The website returned a redirect without a destination."
                    )

                if redirect_number >= max_redirects:
                    response.close()
                    raise WebSecurityError("Too many redirects.")

                try:
                    destination = normalize_assessment_target(
                        urljoin(safe_url, location)
                    )
                except (AssessmentTargetValidationError, ValueError):
                    response.close()
                    raise WebSecurityError(
                        "The redirect destination is invalid and was blocked."
                    )

                response.close()
                current_url = destination
                continue

            status_code = response.status_code
            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }

            try:
                cookie_headers = response.raw.headers.getlist("Set-Cookie")
            except (AttributeError, TypeError):
                cookie_value = response.headers.get("Set-Cookie")
                cookie_headers = [cookie_value] if cookie_value else []

            response.close()
            current_url = safe_url
            break
        else:
            raise WebSecurityError("The website could not be checked.")

        header_results = []
        for key, (label, purpose) in SECURITY_HEADERS.items():
            value = headers.get(key)
            assessment, issue = _assess_header(key, value, headers)
            header_results.append({
                "name": label,
                "header": key,
                "present": bool(value),
                "value": value or "",
                "purpose": purpose,
                "assessment": assessment,
                "issue": issue,
            })

        cookie_results = []
        for index, cookie in enumerate(cookie_headers, start=1):
            lower_cookie = cookie.lower()
            cookie_results.append({
                "number": index,
                "secure": "; secure" in ("; " + lower_cookie),
                "httponly": "; httponly" in ("; " + lower_cookie),
                "samesite": "samesite=" in lower_cookie,
            })

        discovery = None
        discovery_error = None

        try:
            from scanner.web_crawler import crawl_public_site

            emit("Discovering same-origin pages")
            def crawler_progress(event):
                completed = event.get("completed")
                total = event.get("total")
                detail = (
                    f"{completed} pages visited"
                    if isinstance(completed, int) else None
                )
                emit(event.get("task", "Discovering pages"), detail=detail)

            discovery = crawl_public_site(
                current_url,
                profile=profile,
                request_budget=request_budget,
                progress_callback=crawler_progress,
            )
        except (
            WebSecurityError,
            WebAssessmentRequestError,
            requests.RequestException,
        ) as exc:
            discovery_error = (
                f"Page discovery could not be completed: {str(exc)[:200]}"
            )

        attack_surface = analyze_attack_surface(discovery)
        assessment_plan = plan_vulnerability_assessment(
            attack_surface, profile=profile
        )

        def prepare_checks(checks):
            """Normalize planned candidate URLs without scope approval."""
            prepared_checks = []

            for check in checks:
                try:
                    candidate_url = normalize_assessment_target(
                        urljoin(current_url, check.get("location"))
                    )
                except (AssessmentTargetValidationError, ValueError, TypeError):
                    continue

                prepared = dict(check)
                prepared["location"] = candidate_url
                prepared_checks.append(prepared)

            return prepared_checks

        xss_checks = prepare_checks(
            assessment_plan["reflected_input_checks"]
        )
        sql_checks = prepare_checks(
            assessment_plan["sql_injection_checks"]
        )

        def not_run_result(category, reason):
            return {
                "status": "not_run",
                "profile": profile_settings["name"],
                "checks": [],
                "requests_used": 0,
                "requests_remaining": request_budget.remaining,
                "verified_vulnerabilities": 0,
                "notes": [reason],
            }

        emit(
            "Preparing vulnerability checks",
            detail=f"{len(xss_checks)} reflected-input and {len(sql_checks)} SQL candidates",
        )
        xss_result = not_run_result(
            "xss",
            "No reflected-input checks ran because discovery was "
            "incomplete or no valid candidate was available.",
        )
        sql_result = not_run_result(
            "sql_injection",
            "No SQL injection checks ran because discovery was "
            "incomplete or no valid candidate was available.",
        )

        # Never run active checks on incomplete discovery.
        if discovery is not None and discovery_error is None:
            if xss_checks:
                try:
                    emit("Testing reflected-input candidates")
                    xss_result = run_reflected_input_checks(
                        xss_checks,
                        profile=profile,
                        session=session,
                        budget=request_budget,
                        progress_callback=progress_callback,
                    )
                except WebAssessmentRequestError as exc:
                    xss_result = not_run_result(
                        "xss",
                        f"Reflected-input assessment stopped safely: {str(exc)[:200]}",
                    )

            if sql_checks:
                try:
                    emit("Testing SQL injection indicators")
                    sql_result = run_sql_injection_checks(
                        sql_checks,
                        profile=profile,
                        session=session,
                        budget=request_budget,
                        progress_callback=progress_callback,
                    )
                except WebAssessmentRequestError as exc:
                    sql_result = not_run_result(
                        "sql_injection",
                        f"SQL injection assessment stopped safely: {str(exc)[:200]}",
                    )

        # OWASP ZAP runs only as its own explicitly selected Unified Scan
        # module. Web Security must not start or query a hidden ZAP scan.
        emit("Web Security assessment complete", percent=100)

        result = {
            "target": current_url,
            "status_code": status_code,
            "headers": header_results,
            "cookies": cookie_results,
            "missing_headers": sum(
                not item["present"] for item in header_results
            ),
            "discovery": discovery,
            "discovery_error": discovery_error,
            "attack_surface": attack_surface,
            "assessment_plan": assessment_plan,
            "reflected_input_assessment": xss_result,
            "sql_injection_assessment": sql_result,
            "request_budget": {
                "maximum": request_budget.maximum,
                "used": request_budget.used,
                "remaining": request_budget.remaining,
            },
            "verified_vulnerabilities": 0,
            "notes": [
                "A missing header is an observation, not proof of a vulnerability.",
                "Header requirements depend on the website's architecture and application.",
                "Cookie flags are assessed only for cookies returned in the initial response.",
                "Page discovery uses read-only GET requests and does not submit forms.",
                "JavaScript is not executed; client-side execution vulnerabilities are not verified.",
                "Reflection and database error indicators are unverified evidence, not confirmed vulnerabilities.",
                "No forms are submitted, no authentication fields are replayed, and no destructive payloads are used.",
            ],
        }

        return result

    finally:
        session.close()
