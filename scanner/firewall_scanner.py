"""Native, conservative network-filtering and WAF observation scanner."""

import ipaddress
import socket
import ssl
import time
from urllib.parse import urlsplit

import requests

from scanner.local_firewall_detector import detect_local_firewall


DEFAULT_TCP_PORTS = (22, 53, 80, 443, 445, 3389, 8080, 8443)
TCP_TIMEOUT_SECONDS = 1.2
HTTP_TIMEOUT = (2.0, 4.0)


class FirewallScanError(ValueError):
    """Raised when a firewall assessment target is invalid."""


def _parse_target(target):
    """Normalize a host or HTTP(S) origin without accepting URL paths."""
    value = (target or "").strip()
    if not value:
        raise FirewallScanError(
            "Enter a hostname, IP address, or HTTP(S) URL."
        )

    if "://" in value:
        try:
            parsed = urlsplit(value)
            scheme = parsed.scheme.lower()

            if scheme not in {"http", "https"}:
                raise FirewallScanError(
                    "Only HTTP and HTTPS URLs are supported."
                )

            if parsed.username or parsed.password:
                raise FirewallScanError(
                    "Credentials in target URLs are not allowed."
                )

            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise FirewallScanError(
                "The target URL or port is invalid."
            ) from exc

        if not host:
            raise FirewallScanError("The target hostname is invalid.")

        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise FirewallScanError(
                "Enter an origin URL without a path, query, or fragment."
            )

        default_port = 443 if scheme == "https" else 80
        effective_port = port if port is not None else default_port

        if not 1 <= effective_port <= 65535:
            raise FirewallScanError("The target port must be 1–65535.")

        url_host = f"[{host}]" if ":" in host else host
        normalized_url = f"{scheme}://{url_host}"
        if port is not None:
            normalized_url += f":{port}"
        normalized_url += "/"

        return host, normalized_url

    if any(char in value for char in ("/", "\\", "@", " ", "\\t", "\\n")):
        raise FirewallScanError(
            "Enter only a hostname or IP address."
        )

    try:
        literal = ipaddress.ip_address(value)
        host = str(literal)
        url_host = f"[{host}]" if literal.version == 6 else host
        return host, f"https://{url_host}/"
    except ValueError:
        pass

    try:
        parsed = urlsplit(f"//{value}")
        if not parsed.hostname or parsed.port is not None:
            raise FirewallScanError(
                "Enter a hostname or IP address without a port."
            )
        host = parsed.hostname
    except ValueError as exc:
        raise FirewallScanError(
            "The target hostname or port is invalid."
        ) from exc

    url_host = f"[{host}]" if ":" in host else host
    return host, f"https://{url_host}/"


def _resolve_target_addresses(host, port=443):
    """Resolve a target to unique IPv4/IPv6 addresses.

    Private, loopback and public addresses are supported. The caller is
    responsible for ensuring the target is authorized for assessment.
    """
    if not host:
        raise FirewallScanError("The target hostname is invalid.")

    try:
        literal = ipaddress.ip_address(host)
        return [str(literal)]
    except ValueError:
        pass

    try:
        records = socket.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise FirewallScanError(
            "The target hostname could not be resolved."
        ) from exc

    addresses = []
    for record in records:
        try:
            address = str(ipaddress.ip_address(record[4][0]))
        except (ValueError, IndexError):
            continue

        if address not in addresses:
            addresses.append(address)

    if not addresses:
        raise FirewallScanError("The target has no usable IP addresses.")

    return addresses



def _connect_to_address(address, port, timeout=TCP_TIMEOUT_SECONDS):
    """Open a TCP connection directly to a previously resolved IP address."""
    try:
        normalized = str(ipaddress.ip_address(address))
    except ValueError as exc:
        raise FirewallScanError("Invalid resolved IP address.") from exc

    return socket.create_connection(
        (normalized, port),
        timeout=timeout,
    )


def _probe_tcp(address, port):
    started = time.monotonic()
    try:
        with _connect_to_address(address, port):
            state = "open"
            reason = "TCP connection established"
    except ConnectionRefusedError:
        state = "closed"
        reason = "Connection actively refused"
    except socket.timeout:
        state = "no_response"
        reason = "Connection timed out; filtering or silent host is possible"
    except OSError as exc:
        if getattr(exc, "errno", None) in (111, 61, 10061):
            state = "closed"
            reason = "Connection actively refused"
        else:
            state = "indeterminate"
            reason = f"Connection error: {exc.__class__.__name__}"

    return {
        "port": port,
        "protocol": "tcp",
        "state": state,
        "reason": reason,
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
    }


def _inspect_tls(host, address, port=443):
    """Inspect TLS on a selected port, verifying the original hostname."""
    result = {"available": False, "error": None}
    context = ssl.create_default_context()

    try:
        with _connect_to_address(address, port) as raw_socket:
            with context.wrap_socket(
                raw_socket,
                server_hostname=host,
            ) as tls:
                certificate = tls.getpeercert()
                result.update({
                    "available": True,
                    "version": tls.version(),
                    "subject": certificate.get("subject", ()),
                    "issuer": certificate.get("issuer", ()),
                    "not_after": certificate.get("notAfter"),
                    "subject_alt_names": certificate.get("subjectAltName", ()),
                    "connected_address": address,
                    "port": port,
                })
    except (OSError, ssl.SSLError, ValueError) as exc:
        result["error"] = exc.__class__.__name__

    return result


class _PinnedHTTPSAdapter(requests.adapters.HTTPAdapter):
    """Pin HTTPS to an IP while retaining hostname verification and SNI."""

    def __init__(self, address, hostname, port=443, **kwargs):
        self.address = str(ipaddress.ip_address(address))
        self.hostname = hostname
        self.port = port

        from urllib3 import HTTPSConnectionPool

        tls_context = ssl.create_default_context()
        tls_context.check_hostname = True
        tls_context.verify_mode = ssl.CERT_REQUIRED

        self.pool = HTTPSConnectionPool(
            host=self.address,
            port=self.port,
            maxsize=1,
            block=True,
            cert_reqs=ssl.CERT_REQUIRED,
            assert_hostname=self.hostname,
            server_hostname=self.hostname,
            ssl_context=tls_context,
        )
        super().__init__(**kwargs)

    def get_connection(self, url, proxies=None):
        return self.pool

    def send(self, request, **kwargs):
        authority = self.hostname
        if self.port != 443:
            authority = f"{authority}:{self.port}"
        request.headers["Host"] = authority
        return super().send(request, **kwargs)

    def close(self):
        self.pool.close()
        super().close()


class _PinnedHTTPAdapter(requests.adapters.HTTPAdapter):
    """Pin plain HTTP to a resolved IP while preserving the Host header."""

    def __init__(self, address, hostname, port=80, **kwargs):
        self.address = str(ipaddress.ip_address(address))
        self.hostname = hostname
        self.port = port

        from urllib3 import HTTPConnectionPool

        self.pool = HTTPConnectionPool(
            host=self.address,
            port=self.port,
            maxsize=1,
            block=True,
        )
        super().__init__(**kwargs)

    def get_connection(self, url, proxies=None):
        return self.pool

    def send(self, request, **kwargs):
        authority = self.hostname
        if self.port != 80:
            authority = f"{authority}:{self.port}"
        request.headers["Host"] = authority
        return super().send(request, **kwargs)

    def close(self):
        self.pool.close()
        super().close()


def _summarize_set_cookie(set_cookie_headers):
    """Keep cookie names and security attributes; redact all values."""
    if isinstance(set_cookie_headers, str):
        set_cookie_headers = [set_cookie_headers]

    summaries = []
    safe_attributes = {
        "secure", "httponly", "samesite",
        "path", "domain", "max-age", "expires",
    }

    for header in set_cookie_headers or []:
        parts = str(header).split(";")
        if not parts:
            continue

        name, separator, _value = parts[0].strip().partition("=")
        if not separator or not name:
            continue

        summary = [f"{name}=<redacted>"]

        for part in parts[1:]:
            attribute, has_value, value = part.strip().partition("=")
            attribute = attribute.strip()
            if attribute.lower() not in safe_attributes:
                continue

            if has_value:
                summary.append(f"{attribute}={value.strip()}")
            else:
                summary.append(attribute)

        summaries.append("; ".join(summary))

    return " | ".join(summaries)

def _read_bounded_response_body(response, max_bytes=4096):
    """Read a small, bounded response sample without retaining raw content."""
    collected = bytearray()

    try:
        for chunk in response.iter_content(chunk_size=1024):
            if not chunk:
                continue

            remaining = max_bytes - len(collected)
            collected.extend(chunk[:remaining])

            if len(collected) >= max_bytes:
                break
    except (requests.RequestException, OSError):
        pass

    return bytes(collected).decode("utf-8", errors="replace")


def _fingerprint_http_application(address, port, scheme, headers, body):
    """Identify web products only from explicit response evidence."""
    import re

    server = str(headers.get("Server", "") or "").strip()
    lowered_server = server.lower()
    lowered_body = str(body or "").lower()

    result = {
        "address": address,
        "port": port,
        "protocol": scheme,
        "service": "https" if scheme == "https" else "http",
        "product": None,
        "version": None,
        "confidence": "medium",
        "evidence": ["An HTTP response was received from the target origin."],
    }

    def identify(product, clue, confidence="high", version=None):
        result["product"] = product
        result["version"] = version
        result["confidence"] = confidence
        result["evidence"].append(clue)

    # Explicit product page markers take precedence over generic server names.
    if (
        "welcome to xampp" in lowered_body
        or "xampp dashboard" in lowered_body
        or "xampp control panel" in lowered_body
    ):
        identify(
            "XAMPP",
            "Explicit XAMPP dashboard or welcome-page text observed.",
        )
    elif (
        "wazuh dashboard" in lowered_body
        or "wazuh api" in lowered_body
        or "wazuh server" in lowered_body
    ):
        identify(
            "Wazuh",
            "Explicit Wazuh dashboard or API text observed.",
        )
    elif "apache-coyote" in lowered_server:
        match = re.search(r"Apache-Coyote/([0-9.]+)", server, re.I)
        identify(
            "Apache Tomcat",
            "Apache-Coyote server header observed.",
            version=match.group(1) if match else None,
        )
    elif lowered_server == "nginx" or lowered_server.startswith("nginx/"):
        match = re.search(r"nginx/([0-9.]+)", server, re.I)
        identify(
            "Nginx",
            "Nginx server header observed.",
            version=match.group(1) if match else None,
        )
    elif lowered_server == "apache" or lowered_server.startswith("apache/"):
        match = re.search(r"Apache/([0-9.]+)", server, re.I)
        identify(
            "Apache HTTP Server",
            "Apache server header observed; this does not establish XAMPP.",
            version=match.group(1) if match else None,
        )

    return result


def _identify_waf(headers, set_cookie):
    evidence = []
    lowered = {str(key).lower(): str(value).lower()
               for key, value in headers.items()}
    cookies = set_cookie.lower()

    def add(vendor, product, clue, confidence):
        evidence.append({
            "vendor": vendor,
            "product": product,
            "evidence": clue,
            "confidence": confidence,
        })

    if "cf-ray" in lowered or "cloudflare" in lowered.get("server", ""):
        add("Cloudflare", "Cloudflare edge / WAF indicators",
            "Cloudflare response header signature", "likely")
    if "akamai" in lowered.get("server", "") or "akamai" in cookies:
        add("Akamai", "Akamai edge security indicators",
            "Akamai server or cookie signature", "likely")
    if any(token in cookies for token in ("incap_ses", "visid_incap")) \
            or "x-iinfo" in lowered:
        add("Imperva", "Imperva / Incapsula indicators",
            "Imperva cookie or response-header signature", "likely")
    if "bigipserver" in cookies or "f5" in lowered.get("server", ""):
        add("F5", "BIG-IP indicators",
            "BIG-IP persistence cookie or server signature", "likely")
    if "x-sucuri-id" in lowered or "sucuri" in lowered.get("server", ""):
        add("Sucuri", "Sucuri WAF indicators",
            "Sucuri response-header signature", "likely")
    if "x-cdn" in lowered or "x-cache" in lowered:
        add("Unknown", "Generic proxy / CDN indicator",
            "Generic cache or CDN response header; not WAF-specific",
            "possible")

    return evidence



def _fingerprint_tcp_service(address, port):
    """Identify a service from a short, passive TCP greeting.

    No application commands or credentials are sent. Only services that
    send a greeting immediately after connection can be identified here.
    """
    result = {
        "address": address,
        "port": port,
        "protocol": "tcp",
        "service": "unknown",
        "product": None,
        "version": None,
        "confidence": "unknown",
        "evidence": [],
    }

    try:
        with _connect_to_address(address, port, timeout=1.0) as connection:
            connection.settimeout(1.0)
            banner = connection.recv(1024)
    except (OSError, socket.timeout, FirewallScanError) as exc:
        result["error"] = exc.__class__.__name__
        return result

    if not banner:
        result["evidence"].append(
            "TCP connection accepted but no service greeting was received."
        )
        return result

    decoded = banner.decode("utf-8", errors="replace").strip()
    safe_banner = " ".join(decoded.split())[:256]
    lowered = safe_banner.lower()

    result["banner"] = safe_banner
    result["evidence"].append(
        "Service supplied an unsolicited TCP greeting."
    )

    # SSH servers may send informational lines before their identification.
    # Inspect only the unsolicited greeting already received; send no commands.
    ssh_banner = next(
        (
            line.strip()
            for line in decoded.splitlines()
            if line.strip().lower().startswith("ssh-")
        ),
        None,
    )

    if ssh_banner:
        result["service"] = "ssh"
        result["confidence"] = "high"
        result["evidence"].append("SSH identification banner observed.")

        parts = ssh_banner.split("-", 2)
        if len(parts) >= 3:
            software = parts[2].split()[0]
            result["product"] = software.split("_")[0]
            if "_" in software:
                result["version"] = software.split("_", 1)[1]

    elif lowered.startswith("220") and "ftp" in lowered:
        result["service"] = "ftp"
        result["confidence"] = "medium"
        result["evidence"].append("FTP-style 220 greeting observed.")

        for product in ("vsftpd", "proftpd", "pure-ftpd", "filezilla"):
            if product in lowered:
                result["product"] = product
                result["confidence"] = "high"
                break

    elif lowered.startswith("220") and (
        "smtp" in lowered or "esmtp" in lowered
    ):
        result["service"] = "smtp"
        result["confidence"] = "medium"
        result["evidence"].append("SMTP-style 220 greeting observed.")

        for product in ("postfix", "exim", "sendmail", "exchange"):
            if product in lowered:
                result["product"] = product
                result["confidence"] = "high"
                break

    elif lowered.startswith("* ok"):
        result["service"] = "imap"
        result["confidence"] = "medium"
        result["evidence"].append("IMAP-style greeting observed.")

    elif lowered.startswith("+ok"):
        result["service"] = "pop3"
        result["confidence"] = "medium"
        result["evidence"].append("POP3-style greeting observed.")

    return result





def _fingerprint_smb_service(address, port=445):
    """Identify SMB using a bounded, unauthenticated SMB2 negotiation."""
    import struct

    result = {
        "address": address,
        "port": port,
        "protocol": "tcp",
        "service": "unknown",
        "product": None,
        "version": None,
        "confidence": "unknown",
        "evidence": [],
    }

    header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB", 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        b"\x00" * 16,
    )

    negotiate = struct.pack(
        "<HHHHI16sIHH",
        36, 1, 1, 0, 0, b"\x00" * 16, 0, 0, 0,
    ) + struct.pack("<H", 0x0202)

    smb_message = header + negotiate
    packet = (
        b"\x00"
        + len(smb_message).to_bytes(3, "big")
        + smb_message
    )

    try:
        with _connect_to_address(
            address, port, timeout=1.0
        ) as connection:
            connection.settimeout(1.0)
            connection.sendall(packet)

            session_header = connection.recv(4)
            if len(session_header) != 4 or session_header[0] != 0:
                result["evidence"].append(
                    "No valid NetBIOS session response was received."
                )
                return result

            response_length = int.from_bytes(
                session_header[1:4], "big"
            )

            if not 128 <= response_length <= 4096:
                result["evidence"].append(
                    "SMB response length was outside the inspection limit."
                )
                return result

            response = bytearray()
            while len(response) < response_length:
                chunk = connection.recv(
                    min(1024, response_length - len(response))
                )
                if not chunk:
                    break
                response.extend(chunk)

        if len(response) != response_length:
            result["evidence"].append(
                "SMB negotiation response was incomplete."
            )
            return result

        if response[:4] != b"\xfeSMB":
            result["evidence"].append(
                "Response did not contain the SMB2 protocol signature."
            )
            return result

        structure_size = int.from_bytes(response[4:6], "little")
        status = int.from_bytes(response[8:12], "little")
        command = int.from_bytes(response[12:14], "little")

        if structure_size != 64 or command != 0 or status != 0:
            result["evidence"].append(
                "Response did not contain a successful SMB2 NEGOTIATE header."
            )
            return result

        negotiate_size = int.from_bytes(response[64:66], "little")
        dialect = int.from_bytes(response[68:70], "little")

        dialect_names = {
            0x0202: "2.0.2",
            0x0210: "2.1",
            0x0300: "3.0",
            0x0302: "3.0.2",
            0x0311: "3.1.1",
        }

        if negotiate_size != 65 or dialect not in dialect_names:
            result["evidence"].append(
                "SMB2 negotiation response contained an unsupported structure or dialect."
            )
            return result

        result.update({
            "service": "smb",
            "version": dialect_names[dialect],
            "confidence": "high",
        })
        result["evidence"].append(
            "Successful SMB2 NEGOTIATE response observed; "
            f"server selected dialect {dialect_names[dialect]}."
        )

    except (OSError, socket.timeout, ValueError, struct.error) as exc:
        result["error"] = exc.__class__.__name__

    return result



def _fingerprint_rdp_service(address, port=3389):
    """Identify RDP using a bounded, unauthenticated X.224 negotiation."""
    result = {
        "address": address,
        "port": port,
        "protocol": "tcp",
        "service": "unknown",
        "product": None,
        "version": None,
        "confidence": "unknown",
        "evidence": [],
    }

    negotiation = (
        b"\x01\x00\x08\x00"
        + (0x0000000B).to_bytes(4, "little")
    )

    x224 = (
        b"\x0e\xe0"
        + b"\x00\x00\x00\x00\x00"
        + negotiation
    )

    packet_length = 4 + len(x224)
    packet = (
        b"\x03\x00"
        + packet_length.to_bytes(2, "big")
        + x224
    )

    try:
        with _connect_to_address(
            address, port, timeout=1.0
        ) as connection:
            connection.settimeout(1.0)
            connection.sendall(packet)

            tpkt_header = connection.recv(4)

            if (
                len(tpkt_header) != 4
                or tpkt_header[0] != 3
                or tpkt_header[1] != 0
            ):
                result["evidence"].append(
                    "No valid TPKT response was received."
                )
                return result

            response_length = int.from_bytes(
                tpkt_header[2:4], "big"
            )

            if not 19 <= response_length <= 4096:
                result["evidence"].append(
                    "RDP response length was outside the inspection limit."
                )
                return result

            response = bytearray()
            while len(response) < response_length - 4:
                chunk = connection.recv(
                    min(1024, response_length - 4 - len(response))
                )
                if not chunk:
                    break
                response.extend(chunk)

        if len(response) != response_length - 4:
            result["evidence"].append(
                "RDP negotiation response was incomplete."
            )
            return result

        if len(response) < 15 or response[1] != 0xD0:
            result["evidence"].append(
                "Response did not contain an X.224 Connection Confirm."
            )
            return result

        li = response[0]
        if li < 14 or 1 + li > len(response):
            result["evidence"].append(
                "X.224 response contained an invalid length indicator."
            )
            return result

        negotiation_offset = 7
        negotiation_response = response[
            negotiation_offset:negotiation_offset + 8
        ]

        if len(negotiation_response) != 8:
            result["evidence"].append(
                "RDP negotiation structure was incomplete."
            )
            return result

        response_type = negotiation_response[0]
        structure_length = int.from_bytes(
            negotiation_response[2:4], "little"
        )

        if structure_length != 8:
            result["evidence"].append(
                "RDP negotiation structure length was invalid."
            )
            return result

        if response_type == 2:
            selected_protocol = int.from_bytes(
                negotiation_response[4:8], "little"
            )

            protocol_names = {
                0: "Standard RDP Security",
                1: "TLS",
                2: "CredSSP",
                8: "CredSSP with Early User Authorization",
            }

            if selected_protocol not in protocol_names:
                result["evidence"].append(
                    "RDP response selected an unrecognized security protocol."
                )
                return result

            result.update({
                "service": "rdp",
                "confidence": "high",
                "version": protocol_names[selected_protocol],
            })
            result["evidence"].append(
                "Valid X.224 Connection Confirm and RDP negotiation "
                f"response observed; selected protocol: "
                f"{protocol_names[selected_protocol]}."
            )

        elif response_type == 3:
            failure_code = int.from_bytes(
                negotiation_response[4:8], "little"
            )
            result.update({
                "service": "rdp",
                "confidence": "high",
            })
            result["evidence"].append(
                "Valid RDP negotiation failure response observed; "
                f"failure code: {failure_code}."
            )

        else:
            result["evidence"].append(
                "Response contained an unsupported RDP negotiation type."
            )

    except (OSError, socket.timeout, ValueError) as exc:
        result["error"] = exc.__class__.__name__

    return result

def _fingerprint_dns_service(address, port=53):
    """Identify DNS using a bounded, read-only DNS query."""
    import secrets

    result = {
        "address": address,
        "port": port,
        "protocol": "udp",
        "service": "unknown",
        "product": None,
        "version": None,
        "confidence": "unknown",
        "evidence": [],
    }

    transaction_id = secrets.randbelow(65536)
    question = (
        b"\x07example\x03com\x00"
        + b"\x00\x01"  # A record.
        + b"\x00\x01"  # IN class.
    )
    query = (
        transaction_id.to_bytes(2, "big")
        + b"\x01\x00"  # Standard query, recursion desired.
        + b"\x00\x01"  # One question.
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + question
    )

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(1.0)
            connection.sendto(query, (address, port))
            response, _peer = connection.recvfrom(513)

        if len(response) < 12:
            result["evidence"].append(
                "DNS response was shorter than its header."
            )
            return result

        if len(response) > 512:
            result["evidence"].append(
                "DNS response exceeded the 512-byte inspection limit."
            )
            return result

        response_id = int.from_bytes(response[:2], "big")
        flags = int.from_bytes(response[2:4], "big")
        question_count = int.from_bytes(response[4:6], "big")

        if response_id != transaction_id:
            result["evidence"].append(
                "DNS transaction ID did not match."
            )
            return result

        is_response = bool(flags & 0x8000)
        opcode = (flags >> 11) & 0x0F

        if not is_response or opcode != 0 or question_count != 1:
            result["evidence"].append(
                "Response did not contain the expected standard DNS header."
            )
            return result

        question_end = 12 + len(question)
        if (
            len(response) < question_end
            or response[12:question_end] != question
        ):
            result["evidence"].append(
                "DNS response question did not match the query."
            )
            return result

        result.update({
            "service": "dns",
            "confidence": "high",
        })
        result["evidence"].append(
            "A DNS response with matching transaction ID, standard response "
            "header, and matching example.com A/IN question was observed."
        )

    except (OSError, socket.timeout, ValueError) as exc:
        result["error"] = (
            "TimeoutError" if isinstance(exc, TimeoutError)
            else exc.__class__.__name__
        )

    return result


def scan_firewall(target, tcp_ports=None, progress_callback=None):
    """Run bounded TCP probes and HTTP(S)/TLS/WAF observations.

    Web connections are pinned to addresses resolved at the beginning of
    the scan. Private, loopback and public targets are supported.
    """
    started = time.monotonic()

    def emit(task, percent=None):
        if progress_callback is None:
            return
        try:
            progress_callback({"task": task, "percent": percent})
        except Exception:
            pass

    emit("Resolving firewall assessment target")
    host, web_url = _parse_target(target)
    parsed_url = urlsplit(web_url)
    scheme = parsed_url.scheme.lower()
    web_port = parsed_url.port or (443 if scheme == "https" else 80)

    addresses = _resolve_target_addresses(host, web_port)

    ports = tuple(DEFAULT_TCP_PORTS if tcp_ports is None else tcp_ports)
    if not ports or len(ports) > 16:
        raise FirewallScanError("Select between 1 and 16 TCP ports.")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise FirewallScanError("TCP ports must be integers from 1 to 65535.")

    # Probe every resolved address so multi-address DNS results are visible.
    tcp_results = []
    total_probes = len(addresses) * len(ports)
    completed_probes = 0
    emit("Probing selected TCP ports", 0)
    for address in addresses:
        for port in ports:
            result = _probe_tcp(address, port)
            completed_probes += 1
            emit(
                f"TCP port probes ({completed_probes}/{total_probes})",
                completed_probes * 100.0 / max(total_probes, 1),
            )
            result["address"] = address
            tcp_results.append(result)

    # Fingerprint only ports confirmed open by the TCP connection probe.
    # The fingerprint helper sends no application commands or credentials.
    service_results = []
    open_items = [item for item in tcp_results if item["state"] == "open"]
    total_fingerprints = len(open_items) + (len(addresses) if 53 in ports else 0)
    completed_fingerprints = 0
    for item in open_items:
        if item["port"] == 445:
            service_result = _fingerprint_smb_service(
                item["address"], item["port"]
            )
        elif item["port"] == 3389:
            service_result = _fingerprint_rdp_service(
                item["address"], item["port"]
            )
        else:
            service_result = _fingerprint_tcp_service(
                item["address"], item["port"]
            )

        service_results.append(service_result)
        completed_fingerprints += 1
        emit(
            f"Fingerprinting discovered services ({completed_fingerprints}/{max(total_fingerprints, 1)})",
            100.0 * completed_fingerprints / max(total_fingerprints, 1),
        )

    # UDP DNS protocol fingerprinting is independent of TCP port state.
    # Port 53 must be selected; only a valid DNS response identifies DNS.
    if 53 in ports:
        for address in addresses:
            dns_result = _fingerprint_dns_service(address, 53)
            dns_result["protocol"] = "udp"
            service_results.append(dns_result)
            completed_fingerprints += 1
            emit(
                f"Fingerprinting discovered services ({completed_fingerprints}/{max(total_fingerprints, 1)})",
                100.0 * completed_fingerprints / max(total_fingerprints, 1),
            )

    # TLS inspection applies only to HTTPS targets and uses the URL port.
    tls_result = {
        "available": False,
        "error": (
            "TLS inspection is not applicable to an HTTP target."
            if scheme == "http"
            else "No resolved address completed a verified TLS handshake."
        ),
        "port": web_port if scheme == "https" else None,
    }

    if scheme == "https":
        emit("Inspecting TLS configuration")
        for address in addresses:
            candidate = _inspect_tls(host, address, web_port)
            if candidate["available"]:
                tls_result = candidate
                break
            tls_result = candidate

    web_result = {
        "checked": False,
        "url": web_url,
        "scheme": scheme,
        "port": web_port,
        "status_code": None,
        "server": None,
        "headers": {},
        "set_cookie": "",
        "error": None,
        "connected_address": None,
        "application": None,
    }

    last_web_error = None

    # Try each resolved address directly. The adapter retains the original
    # hostname for HTTP Host, TLS SNI and certificate verification.
    emit("Inspecting HTTP response and application fingerprint")
    for address in addresses:
        session = requests.Session()
        session.trust_env = False

        if scheme == "https":
            adapter = _PinnedHTTPSAdapter(address, host, web_port)
        else:
            adapter = _PinnedHTTPAdapter(address, host, web_port)

        session.mount(f"{scheme}://", adapter)

        try:
            response = session.get(
                web_url,
                headers={"User-Agent": "ShadowMapGRC/1.0 SecurityAssessment"},
                timeout=HTTP_TIMEOUT,
                allow_redirects=False,
                stream=True,
                verify=True,
            )
            try:
                selected_headers = {
                    key: value for key, value in response.headers.items()
                    if key.lower() in {
                        "server", "via", "cf-ray", "x-cdn", "x-cache",
                        "x-iinfo", "x-sucuri-id", "x-amz-cf-id",
                        "x-amz-cf-pop", "x-akamai-transformed",
                        "strict-transport-security",
                    }
                }
                web_result.update({
                    "checked": True,
                    "status_code": response.status_code,
                    "server": response.headers.get("Server"),
                    "headers": selected_headers,
                    "set_cookie": _summarize_set_cookie(
                        response.raw.headers.getlist("Set-Cookie")
                        if hasattr(response.raw.headers, "getlist")
                        else response.headers.get("Set-Cookie", "")
                    ),
                    "redirect_not_followed": response.is_redirect,
                    "connected_address": address,
                })

                # Reuse this response; read at most 4 KB and never retain
                # the raw page content in scan results or the database.
                body_sample = _read_bounded_response_body(response)
                application = _fingerprint_http_application(
                    address,
                    web_port,
                    scheme,
                    response.headers,
                    body_sample,
                )
                web_result["application"] = application

                matching_service = next(
                    (
                        item for item in service_results
                        if item["address"] == address
                        and item["port"] == web_port
                    ),
                    None,
                )

                if matching_service is not None:
                    matching_service["application"] = application
                else:
                    service_results.append(application)

            finally:
                response.close()

            break
        except requests.RequestException as exc:
            last_web_error = exc.__class__.__name__
        finally:
            session.close()

    if not web_result["checked"]:
        web_result["error"] = last_web_error or "ConnectionFailed"

    waf_evidence = _identify_waf(
        web_result["headers"], web_result["set_cookie"]
    )

    counts = {
        state: sum(1 for item in tcp_results if item["state"] == state)
        for state in ("open", "closed", "no_response", "indeterminate")
    }

    emit("Checking local firewall evidence")
    local_firewall_result = detect_local_firewall()
    emit("Firewall assessment complete", 100)

    return {
        "target": target,
        "local_firewall": local_firewall_result,
        "host": host,
        "resolved_addresses": addresses,
        "tcp": {
            "ports": tcp_results,
            "counts": counts,
            "interpretation": (
                "No-response ports may be filtered, silently dropped, "
                "or unreachable. They do not independently prove a firewall."
            ),
        },
        "services": {
            "items": service_results,
            "interpretation": (
                "TCP service labels are based on unsolicited greetings. UDP DNS "
                "identification requires a valid protocol response. HTTP(S) "
                "application identification uses response headers and a bounded "
                "response sample. Services that do not disclose identifying "
                "information may remain unknown. A port number alone is never "
                "treated as service or product evidence."
            ),
        },
        "https": web_result,
        "tls": tls_result,
        "waf": {
            "detected": bool(waf_evidence),
            "vendor_identification": waf_evidence,
            "confidence": (
                "likely" if any(
                    item["confidence"] == "likely"
                    for item in waf_evidence
                ) else "possible" if waf_evidence else "unknown"
            ),
            "limitation": (
                "Fingerprint clues are indicative, can be spoofed or shared "
                "by CDN services, and do not prove a specific WAF deployment."
            ),
        },
        "duration_seconds": round(time.monotonic() - started, 3),
        "limitations": [
            "Remote TCP observations cannot reliably distinguish a network "
            "firewall from ACLs, host firewalls, routing, or unavailable services.",
            "A successful HTTPS response does not prove that no WAF is present.",
            "No-response TCP probes are ambiguous and are not treated as "
            "confirmed firewall detection.",
            "Remote observations cannot reliably identify a network firewall "
            "appliance vendor or model.",
        ],
    }
