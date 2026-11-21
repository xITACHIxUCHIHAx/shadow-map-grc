"""Cross-platform discovery of external tool executables."""

import os
import shutil
import sys
from pathlib import Path


def find_nmap_executable():
    """Return an existing Nmap executable, including common install paths."""
    explicit_path = os.environ.get("NMAP_PATH")
    if explicit_path:
        candidate = Path(explicit_path).expanduser()
        if candidate.is_file():
            return str(candidate)

    path_executable = shutil.which("nmap")
    if path_executable:
        candidate = Path(path_executable)
        if candidate.is_file():
            return str(candidate)

    candidates = []
    if sys.platform == "win32":
        for variable, fallback in (
            ("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            ("ProgramFiles", r"C:\Program Files"),
        ):
            root = Path(os.environ.get(variable, fallback))
            candidates.append(root / "Nmap" / "nmap.exe")
    else:
        candidates.extend(
            Path(path)
            for path in (
                "/usr/bin/nmap",
                "/usr/local/bin/nmap",
                "/opt/homebrew/bin/nmap",
                "/opt/local/bin/nmap",
                "/snap/bin/nmap",
            )
        )

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    return None
