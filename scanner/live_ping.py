import ipaddress
import re
import shutil
import socket
import sys
import subprocess
from urllib.parse import urlsplit


class LivePingError(ValueError):
    pass


def normalize_ping_target(value):
    """Accept an IP, hostname, or HTTP(S) URL and return its host."""
    raw = (value or "").strip()

    if not raw or len(raw) > 2048:
        raise LivePingError("Enter a valid IP address, hostname or URL.")

    if any(ord(char) < 32 or char.isspace() for char in raw):
        raise LivePingError("Target must not contain whitespace or control characters.")

    if any(char in raw for char in (";", "|", "&", "`", "$", "<", ">", "\\", '"', "'")):
        raise LivePingError("Target contains unsupported characters.")

    try:
        return str(ipaddress.ip_address(raw.strip("[]")))
    except ValueError:
        pass

    candidate = raw

    if "://" in raw:
        try:
            parsed = urlsplit(raw)
        except ValueError as exc:
            raise LivePingError("Invalid URL.") from exc

        if parsed.scheme.lower() not in ("http", "https"):
            raise LivePingError("Only HTTP and HTTPS URLs are supported.")

        if not parsed.hostname or parsed.username or parsed.password:
            raise LivePingError("URL must contain a hostname and no credentials.")

        try:
            port = parsed.port
        except ValueError as exc:
            raise LivePingError("URL contains an invalid port.") from exc

        if port is not None and not 1 <= port <= 65535:
            raise LivePingError("URL port must be between 1 and 65535.")

        candidate = parsed.hostname

    elif "/" in raw or "?" in raw or "#" in raw:
        try:
            parsed = urlsplit("//" + raw)
        except ValueError as exc:
            raise LivePingError("Invalid hostname or URL.") from exc

        if not parsed.hostname or parsed.username or parsed.password:
            raise LivePingError("Enter a valid hostname or URL.")

        candidate = parsed.hostname

    candidate = candidate.rstrip(".").lower()

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    try:
        hostname = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise LivePingError("Invalid internationalized hostname.") from exc

    if len(hostname) > 253:
        raise LivePingError("Hostname is too long.")

    labels = hostname.split(".")
    if not labels or any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise LivePingError("Enter a valid hostname or URL.")

    return hostname



def resolve_ping_target(target):
    """Return unique DNS addresses for a validated IP or hostname."""
    normalized = normalize_ping_target(target)

    try:
        return [str(ipaddress.ip_address(normalized))]
    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(
            normalized,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise LivePingError(
            f"Could not resolve {normalized}: {exc}"
        ) from exc

    addresses = []
    for result in results:
        address = result[4][0]
        if address not in addresses:
            addresses.append(address)

    if not addresses:
        raise LivePingError(f"No IPv4 or IPv6 addresses found for {normalized}.")

    return addresses


def _build_ping_command(ping_binary, target, timeout_seconds, platform):
    """Build a bounded ICMP command for Windows, Linux, or macOS."""
    timeout_ms = max(1, int(timeout_seconds * 1000))

    if platform == "win32":
        return [
            ping_binary,
            "-n", "1",
            "-w", str(timeout_ms),
            target,
        ]

    if platform == "darwin":
        return [
            ping_binary,
            "-n",
            "-c", "1",
            "-W", str(timeout_ms),
            target,
        ]

    return [
        ping_binary,
        "-n",
        "-c", "1",
        "-W", str(max(1, int(timeout_seconds))),
        "-3",
        target,
    ]


def ping_once(target, timeout_seconds=2):
    """Send one bounded ICMP probe and return its measured result."""
    ping_binary = shutil.which("ping")
    if not ping_binary:
        raise LivePingError("The system ping utility is not installed.")

    command = _build_ping_command(
        ping_binary,
        target,
        timeout_seconds,
        sys.platform,
    )

    process_timeout = timeout_seconds + 2
    if sys.platform == "win32":
        process_timeout = timeout_seconds + 3

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=process_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "reachable": False,
            "latency_ms": None,
            "message": "Request timed out.",
        }
    except OSError as exc:
        raise LivePingError(f"Could not execute ping: {exc}") from exc

    output = (result.stdout or "") + "\n" + (result.stderr or "")

    # Windows: time<1ms or time=1ms
    # Linux/macOS: time=0.03 ms
    match = re.search(
        r"time\s*[=<]\s*([\d.]+)\s*ms",
        output,
        re.IGNORECASE,
    )

    if result.returncode == 0 and match:
        latency = float(match.group(1))
        return {
            "reachable": True,
            "latency_ms": latency,
            "message": f"Reply from {target}: time={latency:.2f} ms",
        }

    lowered_output = output.lower()

    if (
        "name or service not known" in lowered_output
        or "temporary failure in name resolution" in lowered_output
        or "could not find host" in lowered_output
        or "unknown host" in lowered_output
    ):
        message = "Hostname could not be resolved."
    elif "network is unreachable" in lowered_output:
        message = "Network is unreachable."
    elif (
        "operation not permitted" in lowered_output
        or "permission denied" in lowered_output
    ):
        message = "ICMP permission denied."
    else:
        message = "No ICMP reply (timeout or host may block ping)."

    return {
        "reachable": False,
        "latency_ms": None,
        "message": message,
    }
