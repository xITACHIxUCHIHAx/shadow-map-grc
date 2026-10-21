"""Read-only Shodan InternetDB lookups for public IPv4 addresses."""

import ipaddress

import requests


class ThreatIntelError(Exception):
    """Expected validation, API, or connection error."""


API_BASE = "https://internetdb.shodan.io/"


def validate_public_ipv4(value):
    value = (value or "").strip()

    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ThreatIntelError(
            "Enter a valid public IPv4 address."
        ) from exc

    if not isinstance(address, ipaddress.IPv4Address):
        raise ThreatIntelError("Only public IPv4 addresses are supported.")

    if not address.is_global:
        raise ThreatIntelError(
            "Private or non-public IP addresses are not allowed."
        )

    return str(address)


def lookup_ip(value):
    """Return public InternetDB context without changing local records."""
    target = validate_public_ipv4(value)
    session = requests.Session()
    session.trust_env = False

    try:
        response = session.get(
            API_BASE + target,
            timeout=(3, 7),
            headers={"User-Agent": "ShadowMapGRC-ThreatIntel/1.0"},
        )

        if response.status_code == 404:
            return {
                "ip": target,
                "found": False,
                "ports": [],
                "hostnames": [],
                "tags": [],
                "vulns": [],
            }

        if response.status_code == 429:
            raise ThreatIntelError(
                "The lookup service is rate-limiting requests. Try again later."
            )

        response.raise_for_status()
        data = response.json()

    except ThreatIntelError:
        raise
    except requests.RequestException as exc:
        raise ThreatIntelError(
            "The InternetDB lookup failed or timed out."
        ) from exc
    except ValueError as exc:
        raise ThreatIntelError(
            "The lookup service returned an unreadable response."
        ) from exc

    if not isinstance(data, dict):
        raise ThreatIntelError(
            "The lookup service returned an unexpected response."
        )

    def clean_list(key):
        value = data.get(key, [])
        if not isinstance(value, list):
            return []
        return [str(item)[:200] for item in value[:100]]

    return {
        "ip": target,
        "found": True,
        "ports": clean_list("ports"),
        "hostnames": clean_list("hostnames"),
        "tags": clean_list("tags"),
        "vulns": clean_list("vulns"),
    }
