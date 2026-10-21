"""Read-only HTTPS header checks for authorized public websites."""

import ipaddress
import re
import socket
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests


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


def scan_web_security(target):
    """Check HTTPS response headers without downloading the page body."""
    current_url = _validate_public_https_url(target)
    session = requests.Session()
    session.trust_env = False

    try:
        for redirect_number in range(5):
            # Validate every redirect destination before requesting it.
            current_url = _validate_public_https_url(current_url)

            try:
                response = session.get(
                    current_url,
                    timeout=(3, 5),
                    allow_redirects=False,
                    stream=True,
                    verify=True,
                    headers={"User-Agent": "ShadowMapGRC-HeaderCheck/1.0"},
                )
            except requests.exceptions.SSLError as exc:
                raise WebSecurityError(
                    "TLS certificate verification failed. Check the "
                    "website's certificate and hostname."
                ) from exc
            except requests.RequestException as exc:
                raise WebSecurityError(
                    "The HTTPS request failed or timed out."
                ) from exc

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                response.close()

                if not location:
                    raise WebSecurityError(
                        "The website returned a redirect without a destination."
                    )

                if redirect_number == 4:
                    raise WebSecurityError("Too many redirects.")

                current_url = urljoin(current_url, location)
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
            break
        else:
            raise WebSecurityError("The website could not be checked.")
    finally:
        session.close()

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

    return {
        "target": current_url,
        "status_code": status_code,
        "headers": header_results,
        "cookies": cookie_results,
        "missing_headers": sum(not item["present"] for item in header_results),
        "notes": [
            "A missing header is an observation, not proof of a vulnerability.",
            "Header requirements depend on the website's architecture and application.",
            "Cookie flags are assessed only for cookies returned in this response.",
            "This check does not crawl pages or test for application exploits.",
        ],
    }
