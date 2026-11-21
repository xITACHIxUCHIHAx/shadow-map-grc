#!/usr/bin/python3
"""Restricted privileged Nmap helper for Shadow Map GRC OS detection."""

import ipaddress
import json
import os
import re
import sys


NMAP = "/usr/bin/nmap"

PROFILES = {
    "quick": ["--top-ports", "100"],
    "standard": ["--top-ports", "1000"],
    "full_tcp": ["-p-"],
}

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)


def validate_target(target):
    if not isinstance(target, str) or not target or len(target) > 253:
        raise ValueError("Invalid target.")

    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    if target.startswith("-") or not DOMAIN_PATTERN.fullmatch(target):
        raise ValueError("Invalid target.")

    return target


def main():
    if len(sys.argv) != 1:
        raise ValueError("Command-line arguments are not accepted.")

    raw = sys.stdin.read(1025)
    if len(raw) > 1024:
        raise ValueError("Request is too large.")

    request = json.loads(raw)

    if not isinstance(request, dict) or set(request) != {"target", "profile"}:
        raise ValueError("Request must contain only target and profile.")

    target = validate_target(request["target"])
    profile = request["profile"]

    if not isinstance(profile, str) or profile not in PROFILES:
        raise ValueError("Invalid scan profile.")

    if not os.path.isfile(NMAP) or not os.access(NMAP, os.X_OK):
        raise RuntimeError("Nmap is unavailable at the configured path.")

    command = [
        NMAP,
        "-sS",
        "-sV",
        "-O",
        "-Pn",
        "-n",
        "-T3",
        *PROFILES[profile],
        "--reason",
        "--stats-every",
        "1s",
        "-oX",
        "-",
        target,
    ]

    os.execv(NMAP, command)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Shadow Map OS helper: {exc}", file=sys.stderr)
        sys.exit(2)
