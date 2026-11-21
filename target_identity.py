"""Shared target identity helpers for Shadow Map GRC."""

from urllib.parse import urlsplit


def target_group_key(target):
    """
    Return a stable grouping key for a saved target.

    HTTP/HTTPS URLs are grouped by scheme, hostname, and effective port.
    Paths, query strings, and fragments do not affect website identity.
    Non-URL targets remain separate from web origins.
    """
    value = str(target or "").strip()
    if not value:
        return ("empty", "")

    try:
        parsed = urlsplit(value)

        if (
            parsed.scheme.lower() in {"http", "https"}
            and parsed.hostname
            and not parsed.username
            and not parsed.password
        ):
            scheme = parsed.scheme.lower()
            hostname = parsed.hostname.rstrip(".").lower()

            # Normalize internationalized hostnames where possible.
            try:
                hostname = hostname.encode("idna").decode("ascii")
            except UnicodeError:
                return ("raw", value.casefold())

            port = parsed.port
            default_port = 80 if scheme == "http" else 443

            if port == default_port:
                port = None

            return ("web", scheme, hostname, port)

    except (ValueError, UnicodeError):
        # Malformed URLs should not accidentally group with valid websites.
        pass

    return ("raw", value.casefold())


def target_group_label(target):
    """Return the display label for a target group."""
    value = str(target or "").strip()
    key = target_group_key(value)

    if key[0] != "web":
        return value

    _, scheme, hostname, port = key

    # IPv6 hostnames require brackets when rendered in an authority.
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    authority = hostname if port is None else f"{hostname}:{port}"
    return f"{scheme}://{authority}"


def group_targets(targets):
    """
    Build sorted display groups.

    Each group contains a label and the original stored target values.
    Original values are preserved for queries and evidence.
    """
    groups = {}

    for target in targets:
        value = str(target or "").strip()
        if not value:
            continue

        key = target_group_key(value)
        if key not in groups:
            groups[key] = {
                "key": key,
                "label": target_group_label(value),
                "targets": [],
            }

        if value not in groups[key]["targets"]:
            groups[key]["targets"].append(value)

    return sorted(
        groups.values(),
        key=lambda group: group["label"].casefold(),
    )
