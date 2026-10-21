import ipaddress
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$"
)


class NmapError(Exception):
    """An expected scanner or input error."""


def validate_target(target):
    target = (target or "").strip()

    if not target or len(target) > 253:
        raise NmapError("Enter a valid IP address or hostname.")

    # Accept IP addresses first, including IPv6.
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Hostnames only: no URL schemes, paths, ports, spaces or shell syntax.
    if not DOMAIN_PATTERN.fullmatch(target):
        raise NmapError(
            "Use an IP address or hostname only, without http://, paths or ports."
        )

    if target.startswith("-"):
        raise NmapError("Invalid target.")

    return target


def parse_nmap_xml(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapError("Nmap returned unreadable XML output.") from exc

    host = root.find("host")
    host_state = "unknown"

    if host is not None:
        state_element = host.find("status")
        if state_element is not None:
            host_state = state_element.get("state", "unknown")

    ports = []

    for port_element in root.findall(".//port"):
        state_element = port_element.find("state")
        service_element = port_element.find("service")

        state = (
            state_element.get("state", "unknown")
            if state_element is not None else "unknown"
        )

        reason = (
            state_element.get("reason", "")
            if state_element is not None else ""
        )

        service = ""
        product = ""
        version = ""
        extra_info = ""

        if service_element is not None:
            service = service_element.get("name", "")
            product = service_element.get("product", "")
            version = service_element.get("version", "")
            extra_info = service_element.get("extrainfo", "")

        ports.append({
            "port": int(port_element.get("portid", "0")),
            "protocol": port_element.get("protocol", "tcp"),
            "state": state,
            "service": service,
            "product": product,
            "version": version,
            "extra_info": extra_info,
            "reason": reason,
        })

    return {
        "host_state": host_state,
        "ports": sorted(ports, key=lambda item: (item["protocol"], item["port"])),
    }


def run_nmap(target, scan_profile="all_ports", timeout_seconds=180):
    target = validate_target(target)

    if scan_profile not in {"all_ports", "service_detection"}:
        raise NmapError("Choose a valid Nmap scan profile.")

    executable = shutil.which("nmap")
    if not executable:
        raise NmapError(
            "Nmap is not installed or is not available in PATH. "
            "Install Nmap and try again."
        )

    command = [
        executable,
        "-sT",
        "-Pn",
        "-n",
        "-T3",
        "--top-ports",
        "100",
        "--reason",
        "-oX", "-",
        target,
    ]

    if scan_profile == "service_detection":
        command.insert(1, "-sV")

    start = time.monotonic()

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapError(
            f"Nmap exceeded the {timeout_seconds}-second time limit."
        ) from exc
    except OSError as exc:
        raise NmapError(f"Could not start Nmap: {exc}") from exc

    duration = round(time.monotonic() - start, 2)
    xml_output = result.stdout or ""

    if result.returncode != 0:
        detail = (result.stderr or "").strip()
        raise NmapError(
            f"Nmap exited with code {result.returncode}. "
            f"{detail[:500]}"
        )

    parsed = parse_nmap_xml(xml_output)

    counts = {
        "open": sum(p["state"] == "open" for p in parsed["ports"]),
        "closed": sum(p["state"] == "closed" for p in parsed["ports"]),
        "filtered": sum(p["state"] == "filtered" for p in parsed["ports"]),
        "other": sum(
            p["state"] not in {"open", "closed", "filtered"}
            for p in parsed["ports"]
        ),
    }

    command_display = (
        "nmap -sT -Pn -n -T3 --top-ports 100 --reason -oX -"
    )
    if scan_profile == "service_detection":
        command_display = (
            "nmap -sV -sT -Pn -n -T3 --top-ports 100 --reason -oX -"
        )

    return {
        "target": target,
        "host_state": parsed["host_state"],
        "ports": parsed["ports"],
        "counts": counts,
        "duration_seconds": duration,
        "xml_output": xml_output,
        "command_display": command_display,
    }
