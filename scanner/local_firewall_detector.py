"""Read-only local firewall discovery for Linux, Windows and macOS."""

import json
import platform
import shutil
import subprocess


COMMAND_TIMEOUT = 10


def _run(argv, timeout=COMMAND_TIMEOUT):
    """Execute a fixed read-only command without invoking a shell."""
    executable = shutil.which(argv[0]) or (
        argv[0] if argv[0].startswith("/") else None
    )

    if not executable:
        return {
            "available": False,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": "Command not installed or not found.",
        }

    try:
        completed = subprocess.run(
            [executable, *argv[1:]],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "available": True,
            "returncode": completed.returncode,
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
            "error": None,
        }
    except subprocess.TimeoutExpired:
        error = "Inspection command timed out."
    except (OSError, subprocess.SubprocessError) as exc:
        error = exc.__class__.__name__

    return {
        "available": True,
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "error": error,
    }


def _permission_denied(result):
    message = (
        result.get("stderr", "") + " " + result.get("stdout", "")
    ).lower()
    return any(
        phrase in message
        for phrase in (
            "permission denied",
            "operation not permitted",
            "must be root",
            "access is denied",
            "access denied",
            "requires elevation",
            "administrator privilege",
        )
    )


def _technology(name, category, result, evidence=None, status=None):
    output = (result.get("stdout") or "").strip()
    error = (result.get("stderr") or "").strip()

    if status is None:
        if not result.get("available"):
            status = "not_installed"
        elif _permission_denied(result):
            status = "unknown"
        elif result.get("returncode") is None:
            status = "unknown"
        elif result["returncode"] == 0:
            # Successful execution proves that the command ran, not
            # that packet filtering is enabled or disabled.
            status = "unknown"
        else:
            status = "unknown"

    return {
        "name": name,
        "category": category,
        "status": status,
        "available": bool(result.get("available")),
        "evidence": evidence or [],
        "error": (
            result.get("error")
            or ("Permission denied during inspection."
                if _permission_denied(result) else None)
            or (error[:300] if error else None)
        ),
    }


def _nftables_status(output):
    """Classify nftables output using base-chain policies and rule expressions."""
    import re

    if not output or not output.strip():
        return "inactive"

    in_chain = False
    has_base_chain = False

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if re.match(r"^chain\s+\S+\s*\{", line):
            in_chain = True
            has_base_chain = False
            continue

        if line == "}":
            in_chain = False
            continue

        if not in_chain:
            continue

        if re.search(r"\bhook\s+\w+", line):
            has_base_chain = True

        if has_base_chain and re.search(
            r"\bpolicy\s+(drop|reject)\b", line, re.IGNORECASE
        ):
            return "active"

        if has_base_chain and not re.match(
            r"^(type|hook|priority|policy)\b", line
        ):
            return "active"

    if re.search(r"^\s*table\s+\S+", output, re.MULTILINE):
        if not re.search(r"^\s*chain\s+\S+\s*\{", output, re.MULTILINE):
            return "inactive"
        return "unknown"

    return "inactive"



def _iptables_status(output):
    """Classify iptables-save or iptables -S output conservatively."""
    import re

    if not output or not output.strip():
        return "inactive"

    policies = []

    for match in re.finditer(
        r"^\s*:([A-Za-z0-9_-]+)\s+(ACCEPT|DROP|REJECT)\b",
        output,
        flags=re.MULTILINE | re.IGNORECASE,
    ):
        policies.append(match.group(2).upper())

    for match in re.finditer(
        r"^\s*-P\s+[A-Za-z0-9_-]+\s+(ACCEPT|DROP|REJECT)\b",
        output,
        flags=re.MULTILINE | re.IGNORECASE,
    ):
        policies.append(match.group(1).upper())

    if any(policy in ("DROP", "REJECT") for policy in policies):
        return "active"

    # -A represents an actual appended rule. -P is only a policy.
    if re.search(r"^\s*-A\s+\S+", output, flags=re.MULTILINE):
        return "active"

    if policies:
        return "inactive"

    if re.search(r"^\s*\*filter\s*$", output, re.MULTILINE):
        return "unknown"

    if re.search(r"^\s*-\w+\s+", output, re.MULTILINE):
        return "unknown"

    return "inactive"



def _ufw_status(output):
    """Parse UFW's explicit Status line."""
    import re

    match = re.search(
        r"^\s*Status:\s*(active|inactive)\s*$",
        output or "",
        flags=re.IGNORECASE | re.MULTILINE,
    )
    if not match:
        return "unknown"
    return match.group(1).lower()


def _firewalld_status(output):
    """Parse firewall-cmd's explicit running-state response."""
    import re

    lines = [
        line.strip().lower()
        for line in (output or "").splitlines()
        if line.strip()
    ]

    if any(re.fullmatch(r"not running", line) for line in lines):
        return "inactive"
    if any(re.fullmatch(r"running", line) for line in lines):
        return "active"
    return "unknown"


def _systemd_service_observations():
    observations = []
    if not shutil.which("systemctl"):
        return observations

    units = (
        "nftables", "firewalld", "ufw", "netfilter-persistent",
        "iptables", "ip6tables", "shorewall", "csf",
    )

    for unit in units:
        result = _run(["systemctl", "is-active", unit])
        value = (result.get("stdout") or "").strip().lower()

        if result.get("returncode") == 0 and value == "active":
            status = "active"
        elif value in ("inactive", "failed", "activating", "deactivating"):
            status = value
        elif value in ("not-found", "not found"):
            status = "not_found"
        else:
            status = "unknown"

        observations.append({
            "source": "systemd",
            "name": unit,
            "status": status,
            "error": (
                "Permission denied during service inspection."
                if _permission_denied(result)
                else result.get("error")
            ),
        })

    return observations



def _linux_third_party_runtime(product_name):
    """Inspect third-party firewall service/process state without changing it."""
    product_runtime = {
        "APF": {
            "services": ("apf.service",),
            "processes": ("apf",),
        },
        "OpenSnitch": {
            "services": ("opensnitch.service", "opensnitchd.service"),
            "processes": ("opensnitchd",),
        },
        "Douane": {
            "services": ("douane.service", "douane-daemon.service"),
            "processes": ("douane", "douane-daemon"),
        },
        "ConfigServer Firewall": {
            "services": (),
            "processes": (),
        },
        "Shorewall": {
            "services": (),
            "processes": (),
        },
    }

    config = product_runtime.get(product_name, {})
    checks = []
    evidence = []
    observations = []

    for service in config.get("services", ()):
        result = _run(["systemctl", "is-active", service])
        value = (result.get("stdout") or "").strip().lower()

        if result.get("returncode") == 0 and value == "active":
            checks.append(True)
            evidence.append(f"Active service: {service}")
            status = "active"
        elif value in ("inactive", "failed", "not-found", "not found"):
            checks.append(False)
            status = "not_running"
        else:
            checks.append(None)
            status = "unknown"

        observations.append({
            "source": "systemd",
            "name": service,
            "status": status,
            "error": (
                "Permission denied during service inspection."
                if _permission_denied(result)
                else result.get("error")
            ),
        })

    for process in config.get("processes", ()):
        result = _run(["pgrep", "-x", process])

        if result.get("returncode") == 0:
            checks.append(True)
            evidence.append(f"Running process: {process}")
        elif result.get("returncode") == 1 and result.get("available"):
            checks.append(False)
        else:
            checks.append(None)

    if any(check is True for check in checks):
        running = True
    elif checks and all(check is False for check in checks):
        running = False
    else:
        running = None

    return running, evidence, observations


def _shorewall_status(output):
    """Return a state only when Shorewall explicitly reports it."""
    text = (output or "").lower()

    running_markers = (
        "shorewall is running",
        "shorewall is started",
        "shorewall status: running",
    )
    stopped_markers = (
        "shorewall is stopped",
        "shorewall is not running",
        "shorewall status: stopped",
    )

    if any(marker in text for marker in running_markers):
        return "active"
    if any(marker in text for marker in stopped_markers):
        return "inactive"
    return None


def _opensnitch_rule_observation(netfilter_observations):
    """Look for product-identifiable OpenSnitch queue rules.

    Generic NFQUEUE/QUEUE rules are deliberately insufficient. A matching
    rule must also carry an OpenSnitch-specific table, chain, or comment clue.
    """
    readable = []
    matched = []

    for item in netfilter_observations:
        if item.get("status") != "observed":
            continue

        name = (item.get("name") or "").lower()
        evidence = item.get("evidence") or ""
        if not evidence:
            continue

        readable.append(item.get("name") or "Netfilter ruleset")
        lines = evidence.splitlines()

        if "nftables" in name:
            # nft output is block-oriented. Require an OpenSnitch marker
            # and queue expression in the same table block.
            block_lines = []
            in_table = False
            depth = 0

            for line in lines:
                stripped = line.strip()
                if stripped.startswith("table ") and "{" in stripped:
                    in_table = True
                    depth = stripped.count("{") - stripped.count("}")
                    block_lines = [line]
                    continue

                if in_table:
                    block_lines.append(line)
                    depth += line.count("{") - line.count("}")
                    if depth <= 0:
                        block = "\n".join(block_lines).lower()
                        if (
                            "opensnitch" in block
                            and ("queue" in block or "nfqueue" in block)
                        ):
                            matched.append(
                                "OpenSnitch-identifiable nftables table "
                                "contains a queue expression."
                            )
                        in_table = False
                        block_lines = []

            # Also accept an identifiable single-line rule.
            for line in lines:
                lower = line.lower()
                if (
                    "opensnitch" in lower
                    and ("queue" in lower or "nfqueue" in lower)
                ):
                    matched.append(
                        "OpenSnitch marker and queue expression appear "
                        "in the same nftables rule."
                    )
                    break

        else:
            # iptables-save: identify OpenSnitch-named chains first.
            opensnitch_chains = set()
            for line in lines:
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith(":"):
                    chain = parts[0][1:]
                    if "opensnitch" in chain.lower():
                        opensnitch_chains.add(chain)

            for line in lines:
                lower = line.lower()
                parts = line.split()
                chain_match = (
                    len(parts) >= 2
                    and parts[0] == "-A"
                    and parts[1] in opensnitch_chains
                )
                marker_match = "opensnitch" in lower
                queue_match = "nfqueue" in lower or " -j queue" in lower

                if queue_match and (chain_match or marker_match):
                    matched.append(
                        "OpenSnitch-identifiable iptables rule uses "
                        "a queue target."
                    )
                    break

    if matched:
        status = "observed"
        evidence = sorted(set(matched))
        error = None
    elif readable:
        status = "not_observed"
        evidence = [
            "Readable Netfilter rulesets contained no identifiable "
            "OpenSnitch-specific queue rule."
        ]
        error = None
    else:
        status = "unknown"
        evidence = []
        error = (
            "No readable Netfilter ruleset was available to identify "
            "OpenSnitch-specific queue rules."
        )

    return {
        "source": "OpenSnitch rule inspection",
        "name": "OpenSnitch queue configuration",
        "status": status,
        "evidence": evidence,
        "error": error,
        "readable_rulesets": readable,
        "limitation": (
            "A queue rule is configuration evidence only; packet "
            "interception or enforcement was not verified."
        ),
    }


def _linux_third_party_discovery():
    """Discover installed third-party Linux firewall products, read-only."""
    products = (
        {
            "name": "APF",
            "category": "host_firewall_frontend",
            "packages": {"apf"},
            "executables": ("apf",),
        },
        {
            "name": "OpenSnitch",
            "category": "application_network_monitor",
            "packages": {"opensnitch", "opensnitch-ui"},
            "executables": ("opensnitchd", "opensnitch-ui"),
        },
        {
            "name": "Douane",
            "category": "application_network_monitor",
            "packages": {"douane", "douane-daemon", "douane-ui"},
            "executables": ("douane", "douane-daemon"),
        },
        {
            "name": "ConfigServer Firewall",
            "category": "host_firewall_frontend",
            "packages": {"csf", "configserver-security-and-firewall"},
            "executables": ("csf",),
        },
        {
            "name": "Shorewall",
            "category": "host_firewall_frontend",
            "packages": {"shorewall", "shorewall6"},
            "executables": ("shorewall",),
        },
    )

    installed_packages = set()
    package_sources = []

    queries = (
        ("dpkg-query", ["dpkg-query", "-W", "-f=${binary:Package}\n"]),
        ("rpm", ["rpm", "-qa", "--qf", "%{NAME}\n"]),
    )

    for manager, command in queries:
        result = _run(command)
        if result.get("returncode") == 0:
            package_sources.append(manager)
            installed_packages.update(
                line.strip().lower().split(":", 1)[0]
                for line in (result.get("stdout") or "").splitlines()
                if line.strip()
            )

    discovered = []

    for product in products:
        matched_packages = sorted(
            product["packages"] & installed_packages
        )
        matched_executables = [
            executable
            for executable in product["executables"]
            if shutil.which(executable)
        ]

        if not matched_packages and not matched_executables:
            continue

        evidence = []

        if matched_packages:
            evidence.append(
                "Installed package(s): " + ", ".join(matched_packages)
            )

        if matched_executables:
            evidence.append(
                "Executable(s) found: " + ", ".join(matched_executables)
            )

        running, runtime_evidence, service_observations = (
            _linux_third_party_runtime(product["name"])
        )

        discovered.append({
            "name": product["name"],
            "category": product["category"],
            "installed": True,
            "running": running,
            "status": "unknown",
            "firewall_state": "unknown",
            "evidence": evidence,
            "runtime_evidence": runtime_evidence,
            "service_observations": service_observations,
            "package_managers_checked": package_sources,
        })

    return discovered



def _linux_douane_module_observations():
    """Inspect loaded Douane kernel modules without changing system state."""
    observations = []
    try:
        with open("/proc/modules", encoding="utf-8") as modules_file:
            loaded_modules = {
                line.split()[0].lower()
                for line in modules_file
                if line.split()
            }
        status = (
            "loaded"
            if any("douane" in name for name in loaded_modules)
            else "not_loaded"
        )
        error = None
    except OSError as exc:
        status = "unknown"
        error = exc.__class__.__name__

    observations.append({
        "source": "Linux kernel modules",
        "name": "Douane kernel module",
        "status": status,
        "evidence": (
            "A Douane-related kernel module is listed in /proc/modules."
            if status == "loaded" else ""
        ),
        "error": error,
    })
    return observations


def _linux_netfilter_observations():
    """Collect read-only Linux kernel firewall configuration evidence."""
    observations = []

    commands = (
        ("nftables ruleset", ["nft", "list", "ruleset"]),
        ("IPv4 iptables ruleset", ["iptables-save"]),
        ("IPv6 iptables ruleset", ["ip6tables-save"]),
    )

    for name, command in commands:
        result = _run(command)
        output = (result.get("stdout") or "").strip()

        if (
            not result.get("available")
            or result.get("returncode") != 0
            or _permission_denied(result)
            or not output
        ):
            status = "unknown"
        else:
            status = "observed"

        observations.append({
            "source": "Linux Netfilter",
            "name": name,
            "status": status,
            "evidence": output[:4000] if status == "observed" else "",
            "error": (
                "Permission denied during Netfilter inspection."
                if _permission_denied(result)
                else result.get("error")
                or (
                    result.get("stderr", "").strip()
                    if status == "unknown" else None
                )
            ),
        })

    return observations


def _linux_detection():
    technologies = []
    netfilter_observations = _linux_netfilter_observations()
    observations = (
        netfilter_observations
        + [
            _opensnitch_rule_observation(netfilter_observations),
        ]
        + _linux_douane_module_observations()
    )

    # Inspect every available common Linux firewall interface.
    inspections = (
        ("nftables", "nft", ["nft", "list", "ruleset"]),
        ("iptables", "iptables-save", ["iptables-save"]),
        ("IPv6 iptables", "ip6tables-save", ["ip6tables-save"]),
        ("iptables rules", "iptables", ["iptables", "-S"]),
        ("IPv6 iptables rules", "ip6tables", ["ip6tables", "-S"]),
        ("UFW", "ufw", ["ufw", "status", "verbose"]),
        ("firewalld", "firewall-cmd", ["firewall-cmd", "--list-all-zones"]),
        ("Shorewall", "shorewall", ["shorewall", "status"]),
        ("ConfigServer Firewall", "csf", ["csf", "-l"]),
    )

    for name, category, command in inspections:
        result = _run(command)

        output = result["stdout"]
        evidence = []

        if output.strip():
            evidence.append("Read-only inspection returned configuration or rules.")

        lower_output = output.lower()

        if name == "nftables":
            status = (
                _nftables_status(output)
                if result["returncode"] == 0
                else None
            )
        elif name in (
            "iptables", "IPv6 iptables",
            "iptables rules", "IPv6 iptables rules",
        ):
            status = (
                _iptables_status(output)
                if result["returncode"] == 0
                else None
            )
        elif name == "UFW":
            status = _ufw_status(output)
        elif name == "firewalld":
            status = _firewalld_status(output)
        elif name == "Shorewall":
            status = (
                _shorewall_status(output)
                if result.get("returncode") == 0
                and not _permission_denied(result)
                else None
            )
            if status == "active":
                evidence.append(
                    "Shorewall explicitly reported that it is running; "
                    "packet enforcement was not independently verified."
                )
            elif status == "inactive":
                evidence.append(
                    "Shorewall explicitly reported that it is stopped."
                )
        elif name == "ConfigServer Firewall":
            status = None
            if (
                result.get("returncode") == 0
                and output.strip()
                and not _permission_denied(result)
            ):
                evidence.append(
                    "CSF read-only rules listing returned output; "
                    "this does not verify packet enforcement."
                )
        else:
            status = None

        if name in ("nftables", "iptables", "IPv6 iptables",
                    "iptables rules", "IPv6 iptables rules"):
            if result["returncode"] == 0:
                if output.strip():
                    evidence.append("Firewall ruleset was readable.")
                else:
                    evidence.append("Command succeeded; no rules were returned.")

        technologies.append(
            _technology(
                name,
                category,
                result,
                evidence=evidence,
                status=status,
            )
        )

    technologies.extend(_linux_third_party_discovery())

    return technologies, observations



def _third_party_product_discovery(
    products, package_managers, runtime_detector=None
):
    """Discover installed third-party products without changing system state."""
    installed_packages = set()
    package_sources = []

    for manager, command in package_managers:
        result = _run(command)
        if result.get("returncode") == 0:
            package_sources.append(manager)
            installed_packages.update(
                line.strip().lower()
                for line in (result.get("stdout") or "").splitlines()
                if line.strip()
            )

    discovered = []

    for product in products:
        packages = sorted(product["packages"] & installed_packages)
        executables = [
            executable for executable in product["executables"]
            if shutil.which(executable)
        ]

        if not packages and not executables:
            continue

        evidence = []
        if packages:
            evidence.append("Installed package(s): " + ", ".join(packages))
        if executables:
            evidence.append("Executable(s) found: " + ", ".join(executables))

        running = None
        runtime_evidence = []
        service_observations = []

        if runtime_detector:
            running, runtime_evidence, service_observations = (
                runtime_detector(product["name"])
            )

        discovered.append({
            "name": product["name"],
            "category": product["category"],
            "status": "unknown",
            "available": True,
            "installed": True,
            "running": running,
            "firewall_state": "unknown",
            "evidence": evidence,
            "runtime_evidence": runtime_evidence,
            "service_observations": service_observations,
            "package_managers_checked": package_sources,
        })

    return discovered



def _windows_third_party_runtime(product_name):
    """Inspect third-party Windows security service/process state read-only."""
    product_runtime = {
        "ZoneAlarm": {
            "services": ("vsmon",),
            "processes": ("vsmon",),
        },
        "Comodo": {
            "services": ("cmdagent",),
            "processes": ("cmdagent",),
        },
        "ESET": {
            "services": ("ekrn",),
            "processes": ("ekrn",),
        },
        "Bitdefender": {
            "services": ("bdservicehost",),
            "processes": ("bdservicehost",),
        },
        "Norton": {
            "services": (),
            "processes": ("NortonSecurity.exe",),
        },
        "Sophos": {
            "services": (),
            "processes": ("SophosFileScanner.exe", "SophosUI.exe"),
        },
        "FortiClient": {
            "services": (),
            "processes": ("fortifws",),
        },
        "Check Point": {
            "services": (),
            "processes": ("trac.exe",),
        },
    }

    config = product_runtime.get(product_name, {})
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    checks = []
    evidence = []
    observations = []

    if not powershell:
        return None, evidence, [{
            "source": "PowerShell",
            "name": product_name,
            "status": "unknown",
            "error": "PowerShell is unavailable.",
        }]

    for service in config.get("services", ()):
        script = (
            f"Get-Service -Name '{service}' -ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty Status"
        )
        result = _run([
            powershell, "-NoProfile", "-NonInteractive",
            "-Command", script,
        ])
        value = (result.get("stdout") or "").strip().lower()

        if result.get("returncode") == 0 and value == "running":
            checks.append(True)
            evidence.append(f"Running service: {service}")
            status = "running"
        elif result.get("returncode") == 0 and value == "stopped":
            checks.append(False)
            status = "not_running"
        else:
            checks.append(None)
            status = "unknown"

        observations.append({
            "source": "Windows Service",
            "name": service,
            "status": status,
            "error": (
                "Permission denied during service inspection."
                if _permission_denied(result)
                else result.get("error")
            ),
        })

    for process in config.get("processes", ()):
        script = (
            f"Get-Process -Name '{process.removesuffix('.exe')}' "
            "-ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty ProcessName"
        )
        result = _run([
            powershell, "-NoProfile", "-NonInteractive",
            "-Command", script,
        ])
        value = (result.get("stdout") or "").strip()

        if result.get("returncode") == 0 and value:
            checks.append(True)
            evidence.append(f"Running process: {process}")
        elif result.get("returncode") == 0:
            checks.append(False)
        else:
            checks.append(None)

    if any(check is True for check in checks):
        running = True
    elif checks and all(check is False for check in checks):
        running = False
    else:
        running = None

    return running, evidence, observations



def _windows_wfp_observations():
    """Collect read-only Windows Filtering Platform diagnostic evidence."""
    observations = []

    commands = (
        (
            "WFP state",
            ["netsh", "wfp", "show", "state", "file=-"],
        ),
        (
            "WFP network events",
            ["netsh", "wfp", "show", "netevents", "file=-"],
        ),
    )

    for name, command in commands:
        result = _run(command)
        output = (result.get("stdout") or "").strip()

        if not result.get("available") or result.get("returncode") is None:
            status = "unknown"
        elif _permission_denied(result):
            status = "unknown"
        elif result.get("returncode") != 0:
            status = "unknown"
        elif not output:
            status = "unknown"
        else:
            status = "observed"

        observations.append({
            "source": "Windows Filtering Platform",
            "name": name,
            "status": status,
            "evidence": (
                output[:4000] if status == "observed" else ""
            ),
            "error": (
                "Permission denied during WFP inspection."
                if _permission_denied(result)
                else result.get("error")
                or (
                    result.get("stderr", "").strip()
                    if status == "unknown" else None
                )
            ),
        })

    return observations


def _windows_third_party_discovery():
    products = (
        ("ZoneAlarm", "endpoint_security_firewall", {"zonealarm"}, ("vsmon",)),
        ("Comodo", "endpoint_security_firewall", {"comodo"}, ("cmdagent",)),
        ("ESET", "endpoint_security_firewall", {"eset", "eset security"}, ("ekrn",)),
        ("Bitdefender", "endpoint_security_firewall", {"bitdefender"}, ("bdservicehost",)),
        ("Norton", "endpoint_security_firewall", {"norton"}, ("nortonsecurity.exe",)),
        ("Sophos", "endpoint_security_firewall", {"sophos"}, ("sophos",)),
        ("FortiClient", "endpoint_security_firewall", {"forticlient"}, ("fortitray",)),
        ("Check Point", "endpoint_security_firewall", {"checkpoint"}, ("trac.exe",)),
    )

    products = tuple({
        "name": name,
        "category": category,
        "packages": packages,
        "executables": executables,
    } for name, category, packages, executables in products)

    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        return []

    result = _run([
        powershell, "-NoProfile", "-NonInteractive", "-Command",
        "Get-ItemProperty "
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
        "| Select-Object -ExpandProperty DisplayName | ConvertTo-Json -Compress",
    ])

    if result.get("returncode") != 0:
        return []

    try:
        names = json.loads(result.get("stdout") or "[]")
        if isinstance(names, str):
            names = [names]
    except (ValueError, TypeError):
        return []

    discovered = []
    for product in products:
        matches = [
            name for name in names
            if isinstance(name, str)
            and any(package in name.lower() for package in product["packages"])
        ]
        if matches:
            running, runtime_evidence, service_observations = (
                _windows_third_party_runtime(product["name"])
            )
            discovered.append({
                "name": product["name"],
                "category": product["category"],
                "status": "unknown",
                "available": True,
                "installed": True,
                "running": running,
                "firewall_state": "unknown",
                "evidence": ["Installed application(s): " + ", ".join(matches)],
                "runtime_evidence": runtime_evidence,
                "service_observations": service_observations,
            })

    return discovered


def _macos_third_party_runtime(product_name):
    """Inspect macOS third-party firewall processes and extensions read-only."""
    product_runtime = {
        "Little Snitch": {
            "processes": ("Little Snitch", "littlesnitch"),
            "extensions": ("at.obdev.littlesnitch",),
        },
        "LuLu": {
            "processes": ("LuLu", "lulu"),
            "extensions": ("com.objective-see.lulu",),
        },
        "Radio Silence": {
            "processes": ("Radio Silence",),
            "extensions": (),
        },
        "Hands Off!": {
            "processes": ("Hands Off!",),
            "extensions": (),
        },
        "Vallum": {
            "processes": ("Vallum",),
            "extensions": ("com.murus.vallum",),
        },
        "Murus": {
            "processes": ("Murus",),
            "extensions": (),
        },
    }

    config = product_runtime.get(product_name, {})
    checks = []
    evidence = []
    observations = []

    pgrep = shutil.which("pgrep")
    if pgrep:
        for process in config.get("processes", ()):
            result = _run([pgrep, "-x", process])
            if result.get("returncode") == 0 and (
                result.get("stdout") or ""
            ).strip():
                checks.append(True)
                evidence.append(f"Running process: {process}")
                status = "running"
            elif result.get("returncode") == 1:
                checks.append(False)
                status = "not_running"
            else:
                checks.append(None)
                status = "unknown"

            observations.append({
                "source": "macOS process",
                "name": process,
                "status": status,
                "error": (
                    "Permission denied during process inspection."
                    if _permission_denied(result)
                    else result.get("error")
                ),
            })
    else:
        observations.append({
            "source": "macOS process",
            "name": product_name,
            "status": "unknown",
            "error": "pgrep is unavailable.",
        })

    extension_ids = config.get("extensions", ())
    if extension_ids:
        systemextensionsctl = shutil.which("systemextensionsctl")
        if systemextensionsctl:
            result = _run([systemextensionsctl, "list"])
            output = (result.get("stdout") or "").lower()

            for extension_id in extension_ids:
                if result.get("returncode") == 0 and extension_id.lower() in output:
                    evidence.append(
                        f"System extension listed: {extension_id}"
                    )
                    status = "listed"
                elif result.get("returncode") == 0:
                    status = "not_listed"
                else:
                    status = "unknown"

                observations.append({
                    "source": "macOS system extension",
                    "name": extension_id,
                    "status": status,
                    "error": (
                        "Permission denied during extension inspection."
                        if _permission_denied(result)
                        else result.get("error")
                    ),
                })
        else:
            observations.append({
                "source": "macOS system extension",
                "name": product_name,
                "status": "unknown",
                "error": "systemextensionsctl is unavailable.",
            })

    if any(check is True for check in checks):
        running = True
    elif checks and all(check is False for check in checks):
        running = False
    else:
        running = None

    return running, evidence, observations


def _macos_third_party_discovery():
    products = (
        {
            "name": "Little Snitch",
            "category": "application_network_monitor",
            "packages": {"at.obdev.littlesnitch", "little snitch"},
            "executables": ("Little Snitch", "littlesnitch"),
        },
        {
            "name": "LuLu",
            "category": "application_network_monitor",
            "packages": {"com.objective-see.lulu", "lulu"},
            "executables": ("LuLu", "lulu"),
        },
        {
            "name": "Radio Silence",
            "category": "application_network_monitor",
            "packages": {"radio silence"},
            "executables": ("Radio Silence",),
        },
        {
            "name": "Hands Off!",
            "category": "application_network_monitor",
            "packages": {"hands off"},
            "executables": ("Hands Off!",),
        },
        {
            "name": "Vallum",
            "category": "application_network_monitor",
            "packages": {"vallum"},
            "executables": ("Vallum",),
        },
        {
            "name": "Murus",
            "category": "host_firewall_frontend",
            "packages": {"murus"},
            "executables": ("Murus",),
        },
    )

    package_managers = (
        ("pkgutil", ["pkgutil", "--pkgs"]),
    )
    return _third_party_product_discovery(
        products,
        package_managers,
        runtime_detector=_macos_third_party_runtime,
    )


def _windows_detection():
    technologies = []
    observations = []

    powershell = (
        shutil.which("powershell")
        or shutil.which("pwsh")
    )

    if powershell:
        script = (
            "Get-NetFirewallProfile | "
            "Select-Object Name,Enabled,DefaultInboundAction,"
            "DefaultOutboundAction | ConvertTo-Json -Compress"
        )
        result = _run([
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])

        evidence = []
        status = None

        if result["returncode"] == 0 and result["stdout"].strip():
            try:
                profiles = json.loads(result["stdout"])
                if isinstance(profiles, dict):
                    profiles = [profiles]

                enabled = [
                    item for item in profiles
                    if item.get("Enabled") is True
                ]
                disabled = [
                    item for item in profiles
                    if item.get("Enabled") is False
                ]

                for profile in profiles:
                    observations.append({
                        "source": "Windows Defender Firewall",
                        "name": str(profile.get("Name", "Unknown")),
                        "status": (
                            "enabled" if profile.get("Enabled") is True
                            else "disabled" if profile.get("Enabled") is False
                            else "unknown"
                        ),
                        "default_inbound": str(
                            profile.get("DefaultInboundAction", "Unknown")
                        ),
                        "default_outbound": str(
                            profile.get("DefaultOutboundAction", "Unknown")
                        ),
                    })

                status = (
                    "active" if enabled and not disabled
                    else "partially_active" if enabled
                    else "inactive" if disabled
                    else "unknown"
                )
                evidence.append("Windows firewall profiles inspected.")
            except (ValueError, TypeError):
                evidence.append("PowerShell returned unrecognized profile data.")

        technologies.append(
            _technology(
                "Windows Defender Firewall",
                "host_firewall",
                result,
                evidence=evidence,
                status=status,
            )
        )

    netsh = _run([
        "netsh",
        "advfirewall",
        "show",
        "allprofiles",
    ])

    if netsh["available"]:
        output = netsh["stdout"]
        lower = output.lower()
        evidence = []

        if "state" in lower:
            evidence.append("netsh returned firewall profile state.")

        if "state" in lower and "on" in lower:
            status = "active"
        elif "state" in lower and "off" in lower:
            status = "inactive"
        else:
            status = None

        technologies.append(
            _technology(
                "Windows Advanced Firewall (netsh)",
                "host_firewall",
                netsh,
                evidence=evidence,
                status=status,
            )
        )

    observations.extend(_windows_wfp_observations())
    technologies.extend(_windows_third_party_discovery())
    return technologies, observations


def _macos_detection():
    technologies = []
    observations = []

    socketfilterfw = _run([
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        "--getglobalstate",
    ])

    if socketfilterfw["available"]:
        output = socketfilterfw["stdout"].lower()
        status = (
            "active" if "enabled" in output
            else "inactive" if "disabled" in output
            else None
        )
        technologies.append(
            _technology(
                "macOS Application Firewall",
                "host_firewall",
                socketfilterfw,
                evidence=["Application Firewall global state inspected."]
                if socketfilterfw["stdout"].strip() else [],
                status=status,
            )
        )

    pfctl = _run(["/sbin/pfctl", "-s", "info"])

    if pfctl["available"]:
        output = pfctl["stdout"].lower()
        status = (
            "active" if "status: enabled" in output
            else "inactive" if "status: disabled" in output
            else None
        )
        technologies.append(
            _technology(
                "PF (Packet Filter)",
                "packet_filter",
                pfctl,
                evidence=["PF status inspected."]
                if pfctl["stdout"].strip() else [],
                status=status,
            )
        )

    technologies.extend(_macos_third_party_discovery())
    return technologies, observations


def detect_local_firewall():
    """Discover local firewall technologies and inspect their state."""
    system = platform.system().lower()

    if system == "linux":
        technologies, observations = _linux_detection()
    elif system == "windows":
        technologies, observations = _windows_detection()
    elif system == "darwin":
        technologies, observations = _macos_detection()
    else:
        technologies, observations = [], []

    statuses = [item["status"] for item in technologies]

    if "active" in statuses or "partially_active" in statuses:
        overall = "active"
    elif statuses and all(
        status in ("inactive", "not_installed")
        for status in statuses
    ):
        overall = "inactive"
    elif not technologies:
        overall = "unknown"
    else:
        overall = "unknown"

    return {
        "scope": "Local machine running Shadow Map GRC",
        "platform": platform.platform(),
        "operating_system": system or "unknown",
        "status": overall,
        "technologies": technologies,
        "service_observations": observations,
        "limitations": [
            "Local firewall detection describes the machine running "
            "Shadow Map GRC, not the remote assessment target.",
            "Installed firewall software does not by itself prove that "
            "packet filtering is active.",
            "Permission-denied inspections are reported as unknown.",
            "Multiple firewall backends may expose overlapping rules.",
            "Third-party or custom firewall products may require "
            "product-specific inspection support.",
        ],
    }
