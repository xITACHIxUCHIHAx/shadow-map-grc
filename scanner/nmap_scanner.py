import ipaddress
import math
import json
import os
import platform
import re
import signal
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

from scanner.dependency_paths import find_nmap_executable


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$"
)


SCAN_PROFILES = {
    "quick": {
        "label": "Quick — top 100 TCP ports + service detection",
        "port_args": ["--top-ports", "100"],
        "timeout_seconds": 180,
    },
    "standard": {
        "label": "Standard — top 1,000 TCP ports + service detection",
        "port_args": ["--top-ports", "1000"],
        "timeout_seconds": 300,
    },
    "full_tcp": {
        "label": "Full TCP — ports 1–65535 + service detection",
        "port_args": ["-p-"],
        "timeout_seconds": 1200,
    },
}


class NmapError(Exception):
    """An expected scanner or input error."""


def validate_target(target):
    target = (target or "").strip()

    if not target or len(target) > 253:
        raise NmapError("Enter a valid IP address or hostname.")

    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    if not DOMAIN_PATTERN.fullmatch(target) or target.startswith("-"):
        raise NmapError(
            "Use an IP address or hostname only, without http://, paths or ports."
        )

    return target


def parse_custom_ports(value):
    """Validate comma-separated TCP ports or an integer port list."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None

    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",")]
        if any(not part or not part.isascii() or not part.isdigit() for part in parts):
            raise NmapError("Use comma-separated TCP ports, for example 22,443.")
        ports = [int(part) for part in parts]

    elif isinstance(value, list):
        if any(isinstance(port, bool) or not isinstance(port, int) for port in value):
            raise NmapError("Custom ports must be integer TCP port numbers.")
        ports = value[:]

    else:
        raise NmapError("Enter custom TCP ports as comma-separated numbers.")

    if not ports:
        raise NmapError("Enter at least one custom TCP port.")

    if any(port < 1 or port > 65535 for port in ports):
        raise NmapError("TCP ports must be between 1 and 65535.")

    if len(ports) != len(set(ports)):
        raise NmapError("Duplicate TCP ports are not allowed.")

    return ports


def parse_nmap_xml(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapError("Nmap returned unreadable XML output.") from exc

    hosts = root.findall("host")
    if len(hosts) > 1:
        raise NmapError(
            "Nmap returned multiple hosts; only single-host results are supported."
        )

    host = hosts[0] if hosts else None
    host_state = "unknown"

    if host is not None:
        state_element = host.find("status")
        if state_element is not None:
            host_state = state_element.get("state", "unknown")

    mac_address = ""
    mac_vendor = ""
    os_matches = []

    if host is not None:
        for address in host.findall("address"):
            if address.get("addrtype") == "mac":
                mac_address = address.get("addr", "")
                mac_vendor = address.get("vendor", "")
                break

        os_element = host.find("os")
        if os_element is not None:
            for match in os_element.findall("osmatch"):
                for osclass in match.findall("osclass"):
                    os_matches.append({
                        "name": match.get("name", ""),
                        "match_accuracy": match.get("accuracy", ""),
                        "type": osclass.get("type", ""),
                        "vendor": osclass.get("vendor", ""),
                        "family": osclass.get("osfamily", ""),
                        "generation": osclass.get("osgen", ""),
                        "accuracy": osclass.get("accuracy", ""),
                        "cpe": [
                            item.text or ""
                            for item in osclass.findall("cpe")
                        ],
                    })

    best_os = os_matches[0] if os_matches else {}

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
        service_method = ""
        service_confidence = ""
        service_tunnel = ""
        service_cpe = []

        if service_element is not None:
            service = service_element.get("name", "")
            product = service_element.get("product", "")
            version = service_element.get("version", "")
            extra_info = service_element.get("extrainfo", "")
            service_method = service_element.get("method", "")
            service_confidence = service_element.get("conf", "")
            service_tunnel = service_element.get("tunnel", "")
            service_cpe = [
                item.text or ""
                for item in service_element.findall("cpe")
            ]

        raw_port = port_element.get("portid", "")

        try:
            port_number = int(raw_port)
        except (TypeError, ValueError) as exc:
            raise NmapError(
                "Nmap returned an invalid port identifier."
            ) from exc

        if not 1 <= port_number <= 65535:
            raise NmapError(
                "Nmap returned an invalid port identifier."
            )

        protocol = port_element.get("protocol", "").strip().lower()

        if not protocol:
            raise NmapError(
                "Nmap returned an invalid port protocol."
            )

        ports.append({
            "port": port_number,
            "protocol": protocol,
            "state": state,
            "service": service,
            "product": product,
            "version": version,
            "extra_info": extra_info,
            "reason": reason,
            "service_method": service_method,
            "service_confidence": service_confidence,
            "service_tunnel": service_tunnel,
            "service_cpe": service_cpe,
        })

    return {
        "host_state": host_state,
        "mac_address": mac_address,
        "mac_vendor": mac_vendor,
        "os_matches": os_matches,
        "os_match": best_os.get("name", ""),
        "os_accuracy": best_os.get(
            "match_accuracy", best_os.get("accuracy", "")
        ),
        "ports": sorted(
            ports, key=lambda item: (item["protocol"], item["port"])
        ),
    }


def build_nmap_command(target, scan_profile, detect_os=False, custom_ports=None):
    """Build a validated Nmap command; every profile enables service detection."""
    if scan_profile not in SCAN_PROFILES:
        raise NmapError("Choose a valid Nmap scan profile.")

    custom_ports = parse_custom_ports(custom_ports)

    executable = find_nmap_executable()
    if not executable:
        raise NmapError(
            "Nmap is not installed or is not available in PATH. "
            "Install Nmap and try again."
        )

    profile = SCAN_PROFILES[scan_profile]

    command = [
        executable,
        "-sS" if detect_os else "-sT",
        "-sV",
    ]

    if detect_os:
        command.append("-O")

    command.extend([
        "-Pn",
        "-n",
        "-T3",
        *(["-p", ",".join(map(str, custom_ports))]
          if custom_ports else profile["port_args"]),
        "--reason",
        "--stats-every",
        "1s",
        "-oX",
        "-",
        target,
    ])

    return command


def _output_text(value):
    """Normalize subprocess output; timeout output can be bytes or text."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _parse_partial_nmap_xml(xml_text):
    """Recover only fully closed port elements from incomplete XML."""
    host_state = "unknown"
    state_match = re.search(
        r"""<status\b[^>]*\bstate=["']([^"']+)["']""",
        xml_text or "",
    )
    if state_match:
        host_state = state_match.group(1)

    ports = []
    # A complete </port> is required: unfinished records are ignored.
    blocks = re.findall(
        r"<port\b[^>]*>.*?</port\s*>",
        xml_text or "",
        flags=re.DOTALL,
    )

    for block in blocks:
        wrapped = (
            "<nmaprun><host><ports>"
            + block
            + "</ports></host></nmaprun>"
        )
        try:
            parsed = parse_nmap_xml(wrapped)
        except (NmapError, ET.ParseError, ValueError):
            continue
        ports.extend(parsed["ports"])

    ports.sort(key=lambda item: (item["protocol"], item["port"]))
    return {"host_state": host_state, "ports": ports}


def _port_counts(ports):
    return {
        "open": sum(port["state"] == "open" for port in ports),
        "closed": sum(port["state"] == "closed" for port in ports),
        "filtered": sum(port["state"] == "filtered" for port in ports),
        "other": sum(
            port["state"] not in {"open", "closed", "filtered"}
            for port in ports
        ),
    }



def _read_nmap_stream(stream, output_parts, progress_callback=None):
    """Read a Nmap stream without blocking the other output stream."""
    progress_pattern = re.compile(r"<taskprogress\b([^>]*)/?>", re.IGNORECASE)
    attribute_pattern = re.compile(r"""([a-zA-Z_]+)=["\']([^"\']*)["\']""")

    try:
        for line in iter(stream.readline, ""):
            output_parts.append(line)

            if progress_callback is None:
                continue

            match = progress_pattern.search(line)
            if not match:
                continue

            attributes = dict(attribute_pattern.findall(match.group(1)))
            try:
                percent = float(attributes.get("percent", ""))
            except (TypeError, ValueError):
                continue

            # Reject invalid values instead of disguising them by clamping.
            if not math.isfinite(percent) or not 0.0 <= percent <= 100.0:
                continue

            task = attributes.get("task", "Nmap scan").strip() or "Nmap scan"

            # Nmap's remaining-time estimates can be highly unstable.
            # Keep only genuine phase progress; the UI does not show ETA.
            event = {
                "task": task,
                "percent": percent,
                "remaining_seconds": None,
                "estimated_completion": None,
            }

            try:
                progress_callback(event)
            except Exception:
                # A UI/progress consumer must never interrupt the scan.
                pass
    finally:
        try:
            stream.close()
        except Exception:
            pass



def _terminate_process_group(process, grace_seconds=2):
    """Stop the Nmap process and its child processes where supported."""
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return process.wait()

        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            pass

        # The group leader may exit while a child remains alive.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

        return process.wait()

    # Windows: terminate the process tree, not only the Nmap parent.
    try:
        process.terminate()
    except OSError:
        pass

    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )

    return process.wait()


# Tracks only Nmap subprocesses created by this application instance.
_ACTIVE_NMAP_PROCESSES = {}
_ACTIVE_NMAP_PROCESSES_LOCK = threading.Lock()


def _register_nmap_process(process):
    with _ACTIVE_NMAP_PROCESSES_LOCK:
        _ACTIVE_NMAP_PROCESSES[process.pid] = process


def _unregister_nmap_process(process):
    with _ACTIVE_NMAP_PROCESSES_LOCK:
        if _ACTIVE_NMAP_PROCESSES.get(process.pid) is process:
            del _ACTIVE_NMAP_PROCESSES[process.pid]


def shutdown_active_nmap_processes(grace_seconds=2):
    """Terminate only Nmap processes launched and registered by this app."""
    with _ACTIVE_NMAP_PROCESSES_LOCK:
        processes = list(_ACTIVE_NMAP_PROCESSES.values())

    stopped = 0
    for process in processes:
        try:
            if process.poll() is None:
                _terminate_process_group(
                    process,
                    grace_seconds=grace_seconds,
                )
                stopped += 1
        except (OSError, ProcessLookupError, subprocess.SubprocessError):
            # Continue shutting down other registered scans.
            pass
        finally:
            _unregister_nmap_process(process)

    return stopped



def _is_windows_administrator():
    """Return whether this Windows process has administrator privileges."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _prepare_os_detection_command(target, scan_profile, custom_ports=None):
    """Select a privileged OS-detection method for the current platform."""
    system = platform.system()

    if system == "Linux":
        port_display = (
            f"custom ports: {','.join(map(str, custom_ports))}"
            if custom_ports
            else f"profile: {scan_profile}"
        )
        get_effective_uid = getattr(os, "geteuid", None)
        if get_effective_uid is not None and get_effective_uid() == 0:
            command = build_nmap_command(
                target,
                scan_profile,
                detect_os=True,
                custom_ports=custom_ports,
            )
            return (
                command,
                f"Nmap OS detection (root execution; {port_display})",
                False,
            )

        return (
            ["sudo", "-n", "/usr/local/sbin/shadow-map-nmap-os-helper"],
            f"sudo -n shadow-map-nmap-os-helper "
            f"(Nmap OS detection; {port_display})",
            True,
        )

    if system == "Darwin":
        get_effective_uid = getattr(os, "geteuid", None)
        if get_effective_uid is None or get_effective_uid() != 0:
            raise NmapError(
                "Nmap OS detection on macOS requires root privileges. "
                "Restart Shadow Map GRC with appropriate administrator "
                "privileges, then try again."
            )

    elif system == "Windows":
        if not _is_windows_administrator():
            raise NmapError(
                "Nmap OS detection on Windows requires an elevated "
                "Administrator session. Close Shadow Map GRC and restart "
                "it using Run as administrator. Npcap must also be installed."
            )

    else:
        raise NmapError(
            f"Nmap OS detection is not supported on this platform: {system}."
        )

    command = build_nmap_command(
        target,
        scan_profile,
        detect_os=True,
        custom_ports=custom_ports,
    )
    port_display = (
        f"custom ports: {','.join(map(str, custom_ports))}"
        if custom_ports
        else f"profile: {scan_profile}"
    )
    return (
        command,
        f"Nmap OS detection (native privileged execution; {port_display})",
        False,
    )


def run_nmap(
    target,
    scan_profile="standard",
    timeout_seconds=None,
    progress_callback=None,
    detect_os=False,
    custom_ports=None,
):
    target = validate_target(target)
    custom_ports = parse_custom_ports(custom_ports)

    if scan_profile not in SCAN_PROFILES:
        raise NmapError("Choose a valid Nmap scan profile.")

    if not isinstance(detect_os, bool):
        raise NmapError("OS detection setting must be true or false.")

    profile = SCAN_PROFILES[scan_profile]
    if timeout_seconds is None:
        timeout_seconds = profile["timeout_seconds"]

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise NmapError("The scan timeout must be a positive number.")

    if timeout_seconds > profile["timeout_seconds"]:
        raise NmapError(
            f"The {scan_profile} profile timeout cannot exceed "
            f"{profile['timeout_seconds']} seconds."
        )

    use_os_helper = False

    if detect_os:
        command, command_display, use_os_helper = (
            _prepare_os_detection_command(
                target,
                scan_profile,
                custom_ports=custom_ports,
            )
        )
    else:
        command = build_nmap_command(
            target, scan_profile, custom_ports=custom_ports
        )
        port_display = (
            f"-p {','.join(map(str, custom_ports))}"
            if custom_ports else " ".join(profile["port_args"])
        )
        command_display = (
            f"nmap -sT -sV -Pn -n -T3 "
            f"{port_display} "
            "--reason --stats-every 1s -oX -"
        )

    start = time.monotonic()
    timed_out = False
    stdout_parts = []
    stderr_parts = []

    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if use_os_helper else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            **(
                {"start_new_session": True}
                if os.name == "posix"
                else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
            ),
        )
    except OSError as exc:
        raise NmapError(f"Could not start Nmap: {exc}") from exc

    _register_nmap_process(process)

    if use_os_helper:
        try:
            helper_request = {
                "target": target,
                "profile": scan_profile,
            }
            if custom_ports:
                helper_request["ports"] = custom_ports
            process.stdin.write(json.dumps(helper_request))
            process.stdin.close()
        except OSError as exc:
            try:
                _terminate_process_group(process)
            finally:
                _unregister_nmap_process(process)
            raise NmapError(
                f"Could not send the OS-detection request to Nmap: {exc}"
            ) from exc

    stdout_thread = threading.Thread(
        target=_read_nmap_stream,
        args=(process.stdout, stdout_parts, progress_callback),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_read_nmap_stream,
        args=(process.stderr, stderr_parts),
        daemon=True,
    )

    stdout_thread.start()
    stderr_thread.start()

    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_group(process)
        return_code = process.returncode

    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)

    _unregister_nmap_process(process)

    xml_output = "".join(stdout_parts)
    stderr_text = "".join(stderr_parts)
    duration = round(time.monotonic() - start, 2)

    if timed_out:
        parsed = _parse_partial_nmap_xml(xml_output)
        status = "Partial"
        error = (
            f"Nmap reached its {timeout_seconds}-second time limit. "
            "Any recovered ports are incomplete results; rerun the scan "
            "if a complete assessment is required."
        )
    else:
        if return_code != 0:
            detail = stderr_text.strip()
            if detect_os:
                system = platform.system()
                if system == "Linux":
                    get_effective_uid = getattr(os, "geteuid", None)
                    if get_effective_uid is not None and get_effective_uid() == 0:
                        message = (
                            "Linux Nmap OS detection failed. Check that "
                            "the container has the Docker NET_RAW capability "
                            "and can access the target network. "
                        )
                    else:
                        message = (
                            "OS detection could not start or complete. Check "
                            "that the restricted sudo helper is installed and "
                            "permitted for this user. "
                        )
                elif system == "Windows":
                    message = (
                        "Windows Nmap OS detection failed. Confirm that "
                        "Shadow Map GRC is running as Administrator and "
                        "Npcap is installed and working. "
                    )
                elif system == "Darwin":
                    message = (
                        "macOS Nmap OS detection failed. Confirm that "
                        "Shadow Map GRC has root privileges and that Nmap "
                        "can access raw network sockets. "
                    )
                else:
                    message = "Nmap OS detection failed. "

                raise NmapError(message + detail[:400])
            raise NmapError(
                f"Nmap exited with code {return_code}. {detail[:500]}"
            )

        parsed = parse_nmap_xml(xml_output)
        status = "Completed"
        error = None

    return {
        "target": target,
        "scan_profile": scan_profile,
        "profile_label": (
            f"Custom TCP ports: {','.join(map(str, custom_ports))} + service detection"
            if custom_ports else profile["label"]
        ),
        "custom_ports": custom_ports or [],
        "timeout_seconds": timeout_seconds,
        "status": status,
        "error": error,
        "host_state": parsed["host_state"],
        "mac_address": parsed.get("mac_address", ""),
        "mac_vendor": parsed.get("mac_vendor", ""),
        "os_matches": parsed.get("os_matches", []),
        "os_match": parsed.get("os_match", ""),
        "os_accuracy": parsed.get("os_accuracy", ""),
        "os_detection_requested": detect_os,
        "os_detection_status": (
            "detected"
            if detect_os and parsed.get("os_match")
            else "not_detected"
            if detect_os
            else "disabled"
        ),
        "ports": parsed["ports"],
        "counts": _port_counts(parsed["ports"]),
        "duration_seconds": duration,
        "xml_output": xml_output,
        "command_display": command_display,
    }
