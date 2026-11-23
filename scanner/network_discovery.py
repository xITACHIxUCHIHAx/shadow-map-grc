"""Read-only LAN device discovery and bounded TCP service inventory."""

import ipaddress
import json
import math
import platform
import psutil
import re
import shutil
import socket
import struct
import time
import subprocess
import xml.etree.ElementTree as ET

from scanner.dependency_paths import find_nmap_executable


MAX_DISCOVERY_HOSTS = 4096
MAX_SERVICE_SCAN_HOSTS = 256
TOP_TCP_PORTS = 100

DEFAULT_TIMEOUT = 600
MIN_DISCOVERY_TIMEOUT = 1
MAX_DISCOVERY_TIMEOUT = 1800


class NetworkDiscoveryError(Exception):
    """Raised when an authorized LAN discovery cannot be completed."""


def _run_ip_json(command):
    """Run an ip command and return parsed JSON."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NetworkDiscoveryError(
            f"Could not inspect local network configuration: {exc}"
        ) from exc

    if result.returncode != 0:
        raise NetworkDiscoveryError(
            result.stderr.strip() or "Could not inspect network configuration."
        )

    try:
        return json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise NetworkDiscoveryError(
            "The system returned invalid network configuration data."
        ) from exc


def _get_default_gateways():
    """Return default gateways keyed by network interface name."""
    system = platform.system()
    gateways = {}

    if system == "Linux":
        ip_binary = shutil.which("ip")
        if ip_binary:
            try:
                routes = _run_ip_json([
                    ip_binary, "-j", "route", "show", "default"
                ])
                return {
                    route["dev"]: route["gateway"]
                    for route in routes
                    if route.get("dev") and route.get("gateway")
                }
            except NetworkDiscoveryError:
                pass

        # Linux fallback when the ip command is unavailable.
        try:
            with open("/proc/net/route", encoding="ascii") as route_file:
                next(route_file, None)
                for line in route_file:
                    fields = line.split()
                    if len(fields) < 4 or fields[1] != "00000000":
                        continue
                    if not (int(fields[3], 16) & 0x2):
                        continue
                    gateway = socket.inet_ntoa(
                        struct.pack("<I", int(fields[2], 16))
                    )
                    if gateway != "0.0.0.0":
                        gateways[fields[0]] = gateway
        except (OSError, ValueError, struct.error):
            pass

    elif system == "Windows":
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if powershell:
            script = (
                "Get-NetIPConfiguration | "
                "Where-Object { $_.IPv4DefaultGateway } | "
                "ForEach-Object { "
                "[PSCustomObject]@{ "
                "name=$_.InterfaceAlias; "
                "gateway=$_.IPv4DefaultGateway.NextHop "
                "} } | ConvertTo-Json -Compress"
            )
            try:
                result = subprocess.run(
                    [powershell, "-NoProfile", "-NonInteractive",
                     "-Command", script],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                if result.returncode == 0 and result.stdout.strip():
                    data = json.loads(result.stdout)
                    if isinstance(data, dict):
                        data = [data]
                    gateways = {
                        item["name"]: item["gateway"]
                        for item in data
                        if item.get("name") and item.get("gateway")
                    }
            except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
                pass

    elif system == "Darwin":
        route_binary = shutil.which("route") or "/sbin/route"
        try:
            result = subprocess.run(
                [route_binary, "-n", "get", "default"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if result.returncode == 0:
                interface_name = None
                gateway = None
                for line in result.stdout.splitlines():
                    key, separator, value = line.partition(":")
                    if not separator:
                        continue
                    if key.strip() == "interface":
                        interface_name = value.strip()
                    elif key.strip() == "gateway":
                        gateway = value.strip()
                if interface_name and gateway:
                    gateways[interface_name] = gateway
        except (OSError, subprocess.TimeoutExpired):
            pass

    return gateways


def get_network_interfaces():
    """Return active non-loopback IPv4 interfaces and default gateways."""
    try:
        addresses_by_interface = psutil.net_if_addrs()
        stats_by_interface = psutil.net_if_stats()
    except (OSError, psutil.Error) as exc:
        raise NetworkDiscoveryError(
            f"Could not inspect local network interfaces: {exc}"
        ) from exc

    gateways = _get_default_gateways()
    interfaces = []

    for name, addresses in addresses_by_interface.items():
        stats = stats_by_interface.get(name)

        if (
            not name
            or name.lower() in {"lo", "lo0"}
            or stats is None
            or not stats.isup
        ):
            continue

        for address in addresses:
            if address.family != socket.AF_INET:
                continue

            local_address = address.address
            netmask = address.netmask

            try:
                ip = ipaddress.ip_address(local_address)
                if ip.is_loopback or ip.is_link_local:
                    continue

                network_interface = ipaddress.ip_interface(
                    f"{local_address}/{netmask}"
                )
            except (ValueError, TypeError):
                continue

            mac_address = "Unavailable"
            for link_address in addresses:
                if link_address.family != psutil.AF_LINK:
                    continue

                candidate_mac = str(link_address.address).strip().lower().replace("-", ":")
                if (
                    re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", candidate_mac)
                    and candidate_mac != "00:00:00:00:00:00"
                ):
                    mac_address = candidate_mac
                    break

            interfaces.append({
                "name": name,
                "address": local_address,
                "mac_address": mac_address,
                "prefix_length": network_interface.network.prefixlen,
                "network": str(network_interface.network),
                "gateway": gateways.get(name),
            })

    # Prefer interfaces with a default gateway. In host-network mode this
    # puts the active physical LAN interface ahead of Docker bridges.
    interfaces.sort(
        key=lambda item: (
            not bool(item.get("gateway")),
            item["name"],
        )
    )

    return interfaces


def validate_discovery_subnet(
    subnet_text,
    interface_name,
    *,
    return_interface=False,
):
    """Validate an IPv4 subnet contained by the selected active interface."""
    if not isinstance(subnet_text, str) or not subnet_text.strip():
        raise NetworkDiscoveryError("Enter an IPv4 subnet.")

    try:
        requested_network = ipaddress.ip_network(
            subnet_text.strip(),
            strict=False,
        )
    except ValueError as exc:
        raise NetworkDiscoveryError(
            "Enter a valid IPv4 subnet, such as 192.168.1.0/24."
        ) from exc

    if requested_network.version != 4:
        raise NetworkDiscoveryError("Only IPv4 subnets are supported.")

    if requested_network.num_addresses > MAX_DISCOVERY_HOSTS:
        raise NetworkDiscoveryError(
            f"The subnet exceeds the {MAX_DISCOVERY_HOSTS}-address limit."
        )

    interfaces = get_network_interfaces()
    selected = next(
        (
            item for item in interfaces
            if item["name"] == interface_name
        ),
        None,
    )

    if selected is None:
        raise NetworkDiscoveryError(
            "The selected interface is not currently active."
        )

    assigned_network = ipaddress.ip_network(
        selected["network"],
        strict=False,
    )

    if not requested_network.subnet_of(assigned_network):
        raise NetworkDiscoveryError(
            "The requested subnet must be contained within the "
            "selected interface's assigned IPv4 network."
        )

    if return_interface:
        return requested_network, selected

    return requested_network


# Device identification combines independent, conservative evidence.
_HOSTNAME_ROLES = {
    "router": ("router", "gateway"),
    "printer": ("printer", "printserver"),
    "camera": ("camera", "cctv", "webcam", "ipcam"),
    "server_nas": ("server", "srv", "nas", "fileserver"),
    "computer": (
        "laptop", "notebook", "desktop", "workstation", "computer", "pc",
    ),
    "mobile": ("mobile", "phone", "iphone", "android", "tablet"),
    "network_switch": ("switch", "sw"),
    "access_point": ("accesspoint", "access-point", "wirelessap", "wlanap"),
    "smart_tv": ("smarttv", "smart-tv", "television"),
    "iot": ("iot", "smartdevice"),
}

# Vendor names are weak hints, not verified device identities.
_VENDOR_ROLE_HINTS = {
    "router": ("arcadyan",),
    "set_top_box": ("shenzhen sdmc", "sdmc technology"),
    "computer": ("intel corporate", "intel corporation"),
}



def classify_device(device):
    """Estimate device type using hostname, vendor, services and multicast."""
    evidence_by_role = {}

    def add_evidence(role, source, description):
        evidence_by_role.setdefault(role, {}).setdefault(source, [])
        evidence_by_role[role][source].append(description)

    for hostname in device.get("hostnames") or []:
        raw_tokens = re.findall(
            r"[a-z]+[0-9]*|[0-9]+",
            hostname.lower(),
        )
        tokens = {
            re.sub(r"\d+$", "", token)
            for token in raw_tokens
        }
        tokens.discard("")

        for role, indicators in _HOSTNAME_ROLES.items():
            for indicator in indicators:
                indicator_tokens = indicator.replace("-", " ").split()
                if all(token in tokens for token in indicator_tokens):
                    add_evidence(
                        role, "hostname",
                        f"Hostname indicator: {indicator}",
                    )

    vendor = (device.get("vendor") or "").lower()
    for role, indicators in _VENDOR_ROLE_HINTS.items():
        if any(indicator in vendor for indicator in indicators):
            add_evidence(
                role, "vendor",
                f"MAC vendor suggests this category: {device.get('vendor')}",
            )

    open_ports = device.get("open_ports") or []
    service_names = {
        (item.get("service") or "").lower()
        for item in open_ports
    }
    open_port_numbers = {item.get("port") for item in open_ports}

    has_dns = bool(service_names.intersection({"domain", "dns"}))
    has_web_management = bool(
        open_port_numbers.intersection({80, 443, 8080, 8443})
        and service_names.intersection({
            "http", "https", "http-proxy", "https-alt",
        })
    )

    if (
        "router" in evidence_by_role
        and has_dns
        and has_web_management
    ):
        add_evidence(
            "router", "services",
            "DNS and web-management services were detected together.",
        )

    # Multicast hints are supporting evidence, not verified identity.
    allowed_roles = {
        "router", "printer", "camera", "server_nas", "computer",
        "mobile", "network_switch", "access_point", "smart_tv",
        "iot", "set_top_box",
    }
    for hint in device.get("multicast_hints") or []:
        role = hint.get("role")
        source = hint.get("source")
        description = hint.get("description", "")
        if role in allowed_roles and source in {"mdns", "ssdp"}:
            add_evidence(role, source, description[:240])

    if len(evidence_by_role) > 1:
        descriptions = []
        for sources in evidence_by_role.values():
            for source_items in sources.values():
                descriptions.extend(source_items)
        return {
            "device_type": "unknown",
            "classification_confidence": "low",
            "classification_evidence": [
                "Conflicting device-category evidence was found: "
                + "; ".join(descriptions)
            ],
        }

    if not evidence_by_role:
        return {
            "device_type": "unknown",
            "classification_confidence": "low",
            "classification_evidence": [
                "Insufficient hostname, vendor, service or multicast "
                "evidence to estimate the device category."
            ],
        }

    role, sources = next(iter(evidence_by_role.items()))
    source_names = set(sources)

    if (
        role == "router"
        and "vendor" in source_names
        and "services" in source_names
        and has_dns
        and has_web_management
    ):
        confidence = "high"
    elif "hostname" in source_names:
        confidence = "medium"
    elif {"mdns", "ssdp"}.issubset(source_names):
        confidence = "medium"
    else:
        confidence = "low"

    descriptions = [
        item
        for source_items in sources.values()
        for item in source_items
    ]

    return {
        "device_type": role,
        "classification_confidence": confidence,
        "classification_evidence": descriptions + [
            "Classification is an estimate, not verified identification."
        ],
    }


def _read_dns_name(packet, offset):
    """Read a DNS name, including compression pointers, safely."""
    labels = []
    cursor = offset
    return_offset = None
    visited = set()

    for _ in range(128):
        if cursor >= len(packet):
            raise ValueError("DNS name exceeds packet bounds")

        length = packet[cursor]

        if length == 0:
            cursor += 1
            return ".".join(labels).lower(), (
                return_offset if return_offset is not None else cursor
            )

        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise ValueError("Truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= len(packet) or pointer in visited:
                raise ValueError("Invalid DNS compression pointer")
            visited.add(pointer)
            if return_offset is None:
                return_offset = cursor + 2
            cursor = pointer
            continue

        if length & 0xC0 or length > 63:
            raise ValueError("Invalid DNS label length")

        cursor += 1
        if cursor + length > len(packet):
            raise ValueError("Truncated DNS label")

        labels.append(
            packet[cursor:cursor + length].decode("ascii", "ignore")
        )
        cursor += length

    raise ValueError("DNS name contains too many labels")


def parse_mdns_response(packet):
    """Extract DNS-SD service types and local hostnames from an mDNS packet."""
    result = {"services": [], "hostnames": []}
    if len(packet) < 12:
        return result

    try:
        _, _, questions, answers, authorities, additionals = struct.unpack(
            "!HHHHHH", packet[:12]
        )
        offset = 12

        for _ in range(min(questions, 128)):
            _, offset = _read_dns_name(packet, offset)
            offset += 4
            if offset > len(packet):
                raise ValueError("Truncated DNS question")

        names = []
        total_records = min(answers + authorities + additionals, 128)

        for _ in range(total_records):
            owner, offset = _read_dns_name(packet, offset)
            if offset + 10 > len(packet):
                raise ValueError("Truncated DNS record")

            record_type, _, _, data_length = struct.unpack(
                "!HHIH", packet[offset:offset + 10]
            )
            offset += 10
            data_offset = offset
            data_end = data_offset + data_length

            if data_end > len(packet):
                raise ValueError("Truncated DNS record data")

            names.append(owner)

            if record_type == 12:  # PTR
                target, _ = _read_dns_name(packet, data_offset)
                names.append(target)
            elif record_type == 33 and data_length >= 7:  # SRV
                target, _ = _read_dns_name(packet, data_offset + 6)
                names.append(target)

            offset = data_end

        services = set()
        hostnames = set()

        for name in names:
            for match in re.findall(
                r"_[a-z0-9-]+\._(?:tcp|udp)\.local",
                name,
                re.IGNORECASE,
            ):
                services.add(match.lower())

            if (
                name.endswith(".local")
                and "._" not in name
                and not name.startswith("_")
            ):
                hostnames.add(name.lower())

        result["services"] = sorted(services)
        result["hostnames"] = sorted(hostnames)

    except (ValueError, struct.error, IndexError):
        # A malformed advertisement must not interrupt the LAN scan.
        return {"services": [], "hostnames": []}

    return result


def parse_ssdp_response(response):
    """Parse bounded SSDP response headers."""
    headers = {}
    lines = response.decode("utf-8", "replace").splitlines()

    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key in {"server", "st", "usn", "location", "nt"}:
            headers[key] = value.strip()[:240]

    return headers


def _mdns_role_for_service(service):
    service = service.lower()

    if service in {
        "_ipp._tcp.local",
        "_printer._tcp.local",
        "_pdl-datastream._tcp.local",
    }:
        return "printer"

    if service in {
        "_googlecast._tcp.local",
        "_androidtvremote2._tcp.local",
        "_airplay._tcp.local",
    }:
        return "smart_tv"

    if service == "_workstation._tcp.local":
        return "computer"

    return None


def _ssdp_role_for_headers(headers):
    device_type = (
        headers.get("st", "") + " " + headers.get("nt", "")
        + " " + headers.get("usn", "")
    ).lower()

    if "internetgatewaydevice" in device_type:
        return "router"
    if "mediarenderer" in device_type:
        return "smart_tv"
    if "mediaserver" in device_type:
        return "server_nas"
    if "printer" in device_type:
        return "printer"
    if "basic:" in device_type:
        return "iot"

    return None

def _normalize_mac_address(value):
    """Return a normalized unicast MAC address, or None if invalid."""
    candidate = str(value or "").strip().upper()
    candidate = candidate.replace("-", ":")

    if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", candidate):
        return None

    octets = bytes.fromhex(candidate.replace(":", ""))

    # Reject the unspecified address and multicast/group addresses.
    if octets == bytes(6) or octets[0] & 1:
        return None

    return candidate


def parse_discovery_xml(xml_text):
    """Parse Nmap host-discovery XML and return responding IPv4 hosts."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NetworkDiscoveryError(
            f"Nmap returned invalid host-discovery XML: {exc}"
        ) from exc

    devices = []

    for host in root.findall("host"):
        status_element = host.find("status")
        if (
            status_element is None
            or status_element.get("state") != "up"
        ):
            continue

        ip_address = None
        mac_address = None
        vendor = None

        for address in host.findall("address"):
            address_type = address.get("addrtype")

            if address_type == "ipv4":
                ip_address = address.get("addr")

            elif address_type == "mac":
                candidate = _normalize_mac_address(
                    address.get("addr")
                )

                if candidate:
                    mac_address = candidate
                    vendor = address.get("vendor") or None

        try:
            ip_address = str(ipaddress.IPv4Address(ip_address))
        except (ipaddress.AddressValueError, ValueError, TypeError):
            continue

        hostnames = []
        for hostname in host.findall("./hostnames/hostname"):
            value = hostname.get("name")
            if value and value not in hostnames:
                hostnames.append(value)

        device = {
            "ip_address": ip_address,
            "mac_address": mac_address,
            "mac_source": "nmap" if mac_address else "unavailable",
            "mac_neighbour_state": None,
            "vendor": vendor,
            "hostnames": hostnames,
            "status": "online",
            "open_ports": [],
            "discovery_method": "nmap_host_discovery",
        }
        device.update(classify_device(device))
        devices.append(device)

    return devices


def parse_service_xml(xml_text):
    """Return open TCP ports and detected service details keyed by IPv4."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NetworkDiscoveryError(
            f"Nmap returned invalid service-scan XML: {exc}"
        ) from exc

    services_by_ip = {}

    for host in root.findall("host"):
        ip_address = None

        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                try:
                    ip_address = str(
                        ipaddress.IPv4Address(address.get("addr"))
                    )
                except (ipaddress.AddressValueError, ValueError, TypeError):
                    ip_address = None
                break

        if not ip_address:
            continue

        open_ports = []

        for port_element in host.findall("./ports/port"):
            if port_element.get("protocol") != "tcp":
                continue

            state_element = port_element.find("state")
            if (
                state_element is None
                or state_element.get("state") != "open"
            ):
                continue

            try:
                port_number = int(port_element.get("portid"))
            except (ValueError, TypeError):
                continue

            if not 1 <= port_number <= 65535:
                continue

            service_element = port_element.find("service")
            service = {
                "port": port_number,
                "protocol": "tcp",
                "service": None,
                "product": None,
                "version": None,
                "extra_info": None,
            }

            if service_element is not None:
                service["service"] = service_element.get("name")
                service["product"] = service_element.get("product")
                service["version"] = service_element.get("version")
                service["extra_info"] = service_element.get("extrainfo")

            open_ports.append(service)

        services_by_ip[ip_address] = sorted(
            open_ports,
            key=lambda item: item["port"],
        )

    return services_by_ip


def _validate_timeout(timeout):
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not MIN_DISCOVERY_TIMEOUT <= timeout <= MAX_DISCOVERY_TIMEOUT
    ):
        raise NetworkDiscoveryError(
            f"Timeout must be a number between "
            f"{MIN_DISCOVERY_TIMEOUT} and {MAX_DISCOVERY_TIMEOUT} seconds."
        )


def _run_nmap(command, timeout, stage_name):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NetworkDiscoveryError(
            f"{stage_name} timed out after {timeout} seconds."
        ) from exc
    except OSError as exc:
        raise NetworkDiscoveryError(
            f"Could not start Nmap for {stage_name.lower()}: {exc}"
        ) from exc

    if result.returncode != 0:
        error = result.stderr.strip() or (
            f"Nmap returned a non-zero exit code during {stage_name.lower()}."
        )
        raise NetworkDiscoveryError(error)

    return result.stdout




def discover_multicast_evidence(devices, interface_ip):
    """Collect bounded mDNS and SSDP evidence for already-discovered hosts."""
    by_ip = {device["ip_address"]: device for device in devices}

    for device in devices:
        device.setdefault("discovery_evidence", [])
        device.setdefault("multicast_hints", [])
        device.setdefault("mdns_hostnames", [])

    mdns_name = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    mdns_query = (
        struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
        + mdns_name
        + struct.pack("!HH", 12, 1)
    )

    ssdp_query = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")

    counts = {"mdns": 0, "ssdp": 0}

    for protocol, destination, payload in (
        ("mdns", ("224.0.0.251", 5353), mdns_query),
        ("ssdp", ("239.255.255.250", 1900), ssdp_query),
    ):
        sock = None
        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM,
                socket.IPPROTO_UDP,
            )
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_MULTICAST_IF,
                socket.inet_aton(interface_ip),
            )

            if protocol == "mdns":
                # mDNS replies are commonly multicast to 224.0.0.251:5353.
                sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
                )
                sock.bind(("", 5353))
                membership = (
                    socket.inet_aton("224.0.0.251")
                    + socket.inet_aton(interface_ip)
                )
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_ADD_MEMBERSHIP,
                    membership,
                )

            sock.settimeout(0.2)
            sock.sendto(payload, destination)

            deadline = time.monotonic() + 1.0
            received = 0

            while received < 32 and time.monotonic() < deadline:
                try:
                    response, address = sock.recvfrom(8192)
                except socket.timeout:
                    continue

                received += 1
                device = by_ip.get(address[0])
                if device is None:
                    continue

                if protocol == "mdns":
                    parsed = parse_mdns_response(response)

                    for hostname in parsed["hostnames"]:
                        if hostname not in device["mdns_hostnames"]:
                            device["mdns_hostnames"].append(hostname)

                    for service in parsed["services"]:
                        role = _mdns_role_for_service(service)
                        if role:
                            hint = {
                                "role": role,
                                "source": "mdns",
                                "description": f"mDNS DNS-SD service: {service}",
                            }
                            if hint not in device["multicast_hints"]:
                                device["multicast_hints"].append(hint)

                    description = (
                        "mDNS response"
                        + (
                            ": " + ", ".join(parsed["services"][:8])
                            if parsed["services"] else ""
                        )
                    )
                else:
                    headers = parse_ssdp_response(response)
                    role = _ssdp_role_for_headers(headers)

                    if role:
                        details = headers.get("st") or headers.get("nt") or ""
                        hint = {
                            "role": role,
                            "source": "ssdp",
                            "description": (
                                "SSDP UPnP device advertisement"
                                + (f": {details}" if details else "")
                            ),
                        }
                        if hint not in device["multicast_hints"]:
                            device["multicast_hints"].append(hint)

                    selected = {
                        key: headers[key]
                        for key in ("st", "nt", "server", "usn")
                        if key in headers
                    }
                    description = "SSDP response"
                    if selected:
                        description += ": " + "; ".join(
                            f"{key.upper()}={value}"
                            for key, value in sorted(selected.items())
                        )

                if description not in device["discovery_evidence"]:
                    device["discovery_evidence"].append(description)
                    counts[protocol] += 1

        except OSError:
            # Multicast may be unavailable; Nmap results remain usable.
            continue
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    return counts


def _get_neighbour_mac(ip_address, interface_name):
    """Return a valid neighbour MAC and state on supported operating systems."""
    system = platform.system()
    target_ip = str(ipaddress.IPv4Address(ip_address))

    if system == "Linux":
        ip_binary = shutil.which("ip")
        if not ip_binary:
            return None

        command = [
            ip_binary, "neigh", "show", "to",
            target_ip, "dev", interface_name,
        ]

    elif system == "Windows":
        powershell = shutil.which("powershell") or shutil.which("pwsh")

        if powershell:
            # PowerShell single-quoted strings escape an embedded quote by doubling it.
            safe_interface_name = interface_name.replace("'", "''")
            script = (
                "Get-NetNeighbor -IPAddress "
                f"'{target_ip}' -InterfaceAlias "
                f"'{safe_interface_name}' -ErrorAction SilentlyContinue | "
                "Select-Object -First 1 LinkLayerAddress,State | "
                "ConvertTo-Json -Compress"
            )
            try:
                result = subprocess.run(
                    [
                        powershell, "-NoProfile", "-NonInteractive",
                        "-Command", script,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if result.returncode == 0 and result.stdout.strip():
                    data = json.loads(result.stdout)
                    if isinstance(data, dict):
                        mac = _normalize_mac_address(
                            str(data.get("LinkLayerAddress", "")).upper()
                        )
                        state = str(data.get("State", "UNKNOWN")).upper()
                        if mac and state not in {"INCOMPLETE", "UNREACHABLE", "FAILED"}:
                            return mac, state
            except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
                pass

        arp_binary = shutil.which("arp")
        if not arp_binary:
            return None

        command = [arp_binary, "-a", target_ip]

    elif system == "Darwin":
        arp_binary = shutil.which("arp") or "/usr/sbin/arp"
        command = [arp_binary, "-n", target_ip]

    else:
        return None

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        if target_ip not in line:
            continue

        if system == "Linux":
            fields = line.split()
            if not fields or fields[0] != target_ip:
                continue
            if any(state in fields for state in ("FAILED", "INCOMPLETE")):
                continue
            try:
                marker = fields.index("lladdr")
                candidate = fields[marker + 1].upper()
            except (ValueError, IndexError):
                continue

            normalized = _normalize_mac_address(candidate)
            if normalized:
                known_states = {
                    "REACHABLE", "STALE", "DELAY", "PROBE",
                    "PERMANENT", "NOARP",
                }
                state = next(
                    (field.upper() for field in fields if field.upper() in known_states),
                    "UNKNOWN",
                )
                return normalized, state

        else:
            match = re.search(
                r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}",
                line,
            )
            if not match:
                continue

            normalized = _normalize_mac_address(match.group(0).upper())
            if normalized:
                return normalized, "UNKNOWN"

    return None



def _nmap_interface_arguments(interface_name):
    """Return Nmap interface arguments supported by the current platform."""
    if platform.system() == "Linux":
        return ["-e", interface_name]

    # Windows and macOS use their routing tables to select the interface.
    # The requested subnet is independently validated against that interface.
    return []

def discover_hosts(
    subnet_text,
    interface_name,
    *,
    authorized=False,
    timeout=DEFAULT_TIMEOUT,
):
    """
    Discover hosts, then identify open TCP ports and services.

    Both stages are read-only. Only discovered host IPs are passed to the
    second stage. No exploitation, authentication, UDP scan, full port scan,
    or vulnerability testing is performed.
    """
    if authorized is not True:
        raise NetworkDiscoveryError(
            "Scanning requires explicit confirmation that you are "
            "authorized to assess this network."
        )

    _validate_timeout(timeout)

    nmap_binary = find_nmap_executable()
    if not nmap_binary:
        raise NetworkDiscoveryError(
            "Nmap was not found. Install Nmap before scanning."
        )

    network, selected_interface = validate_discovery_subnet(
        subnet_text,
        interface_name,
        return_interface=True,
    )

    discovery_command = [
        nmap_binary,
        *_nmap_interface_arguments(interface_name),
        "-sn",
        "-oX", "-",
        str(network),
    ]

    discovery_xml = _run_nmap(
        discovery_command,
        timeout,
        "Host discovery",
    )
    devices = parse_discovery_xml(discovery_xml)

    # Neighbour entries are meaningful as endpoint MACs only for addresses
    # on the selected interface's directly connected subnet. Never use a
    # default-gateway MAC for a routed destination.
    # The validated scan network is directly contained within the
    # selected interface's assigned network.
    assigned_network = network

    for device in devices:
        if device.get("mac_address"):
            continue

        target_ip = ipaddress.IPv4Address(device["ip_address"])
        if target_ip not in assigned_network:
            device["mac_source"] = "unavailable"
            continue

        neighbour_mac = _get_neighbour_mac(
            device["ip_address"],
            interface_name,
        )
        if neighbour_mac:
            device["mac_address"], device["mac_neighbour_state"] = neighbour_mac
            device["mac_source"] = {
                "Linux": "linux_neighbour_table",
                "Windows": "windows_neighbour_table",
                "Darwin": "macos_neighbour_table",
            }.get(platform.system(), "system_neighbour_table")
        else:
            device["mac_source"] = "unavailable"
            device["mac_neighbour_state"] = None

    service_command = None

    if devices:
        if len(devices) > MAX_SERVICE_SCAN_HOSTS:
            raise NetworkDiscoveryError(
                f"{len(devices)} devices responded. The service scan is "
                f"limited to {MAX_SERVICE_SCAN_HOSTS} hosts per run. "
                "Narrow the subnet and try again."
            )

        discovered_ips = [
            device["ip_address"] for device in devices
        ]

        service_command = [
            nmap_binary,
            *_nmap_interface_arguments(interface_name),
            "-sT",
            "-Pn",
            "-n",
            "-T3",
            "--top-ports", str(TOP_TCP_PORTS),
            "-sV",
            "--version-light",
            "-oX", "-",
            *discovered_ips,
        ]

        service_xml = _run_nmap(
            service_command,
            timeout,
            "TCP service scan",
        )
        services_by_ip = parse_service_xml(service_xml)

        for device in devices:
            device["open_ports"] = services_by_ip.get(
                device["ip_address"],
                [],
            )

        multicast_counts = discover_multicast_evidence(
            devices,
            selected_interface["address"],
        )

        # Reclassify after multicast so its hints influence the estimate.
        for device in devices:
            device.update(classify_device(device))

            evidence = device.setdefault("classification_evidence", [])
            for item in device.get("discovery_evidence", []):
                if item not in evidence:
                    evidence.append(item)

            for hostname in device.get("mdns_hostnames", []):
                item = f"mDNS hostname observed: {hostname}"
                if item not in evidence:
                    evidence.append(item)
    else:
        multicast_counts = {"mdns": 0, "ssdp": 0}

    return {
        "interface": interface_name,
        "subnet": str(network),
        "scan_type": "host_discovery_and_top_100_tcp_service_scan",
        "discovery_command": discovery_command,
        "service_command": service_command,
        "devices_found": len(devices),
        "multicast_discovery": multicast_counts,
        "devices": devices,
    }
