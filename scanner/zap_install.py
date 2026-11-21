"""Detect and install a managed, verified OWASP ZAP distribution."""

import hashlib
import os
import platform
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

import requests


ZAP_VERSION = "2.17.0"
ZAP_ARCHIVE_URL = (
    "https://github.com/zaproxy/zaproxy/releases/download/"
    f"v{ZAP_VERSION}/ZAP_{ZAP_VERSION}_Crossplatform.zip"
)
ZAP_ARCHIVE_SHA256 = (
    "94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0"
)
MAX_DOWNLOAD_BYTES = 500 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1500 * 1024 * 1024


def managed_zap_root():
    """Return a per-user installation directory outside the repository."""
    system = platform.system().lower()
    home = Path.home()

    if system == "windows":
        base = Path(
            os.environ.get("LOCALAPPDATA", home / "AppData" / "Local")
        )
        return base / "ShadowMapGRC" / "tools" / "zap"

    if system == "darwin":
        return (
            home / "Library" / "Application Support"
            / "ShadowMapGRC" / "tools" / "zap"
        )

    data_home = Path(
        os.environ.get("XDG_DATA_HOME", home / ".local" / "share")
    )
    return data_home / "shadow-map-grc" / "tools" / "zap"


def _managed_zap_jar():
    """Find the managed ZAP JAR, if it has already been installed."""
    version_dir = managed_zap_root() / ZAP_VERSION
    if not version_dir.is_dir():
        return None

    expected_name = f"zap-{ZAP_VERSION}.jar"
    matches = list(version_dir.rglob(expected_name))
    return matches[0] if matches else None


def detect_zap():
    """Detect common system installations and the managed ZAP installation."""
    system = platform.system().lower()

    # Prefer the installed ZAP JAR so Shadow Map can launch it directly
    # with its own isolated profile and session directory.
    if system == "linux":
        system_jar = Path("/usr/share/zaproxy") / f"zap-{ZAP_VERSION}.jar"
        if system_jar.is_file():
            return {
                "installed": True,
                "system": system,
                "path": str(system_jar),
                "method": "system JAR",
                "version": ZAP_VERSION,
            }

    for command in ("zaproxy", "zap.sh", "zap", "zap.bat", "ZAP.exe"):
        found = shutil.which(command)
        if found:
            return {
                "installed": True,
                "system": system,
                "path": found,
                "method": "PATH",
            }

    home = Path.home()
    candidates = []

    if system == "linux":
        candidates.extend([
            Path("/usr/bin/zaproxy"),
            Path("/usr/share/zaproxy/zap.sh"),
            Path("/opt/zaproxy/zap.sh"),
            home / "ZAP" / "zap.sh",
            home / ".ZAP" / "zap.sh",
        ])
    elif system == "darwin":
        candidates.extend([
            Path("/Applications/OWASP ZAP.app"),
            Path("/Applications/ZAP.app"),
            home / "Applications" / "OWASP ZAP.app",
            home / "ZAP" / "zap.sh",
        ])
    elif system == "windows":
        for root in (
            os.environ.get("ProgramFiles"),
            os.environ.get("ProgramFiles(x86)"),
            os.environ.get("LOCALAPPDATA"),
        ):
            if root:
                candidates.extend([
                    Path(root) / "OWASP" / "Zed Attack Proxy" / "ZAP.exe",
                    Path(root) / "ZAP" / "ZAP.exe",
                ])

    for candidate in candidates:
        if candidate.exists():
            return {
                "installed": True,
                "system": system,
                "path": str(candidate),
                "method": "known location",
            }

    managed_jar = _managed_zap_jar()
    if managed_jar:
        return {
            "installed": True,
            "system": system,
            "path": str(managed_jar),
            "method": "Shadow Map managed installation",
            "version": ZAP_VERSION,
        }

    guidance = {
        "linux": "ZAP can be installed automatically by Shadow Map. Java 17 or newer is required.",
        "windows": "ZAP can be installed automatically by Shadow Map. Java 17 or newer is required.",
        "darwin": "ZAP can be installed automatically by Shadow Map. Java 17 or newer is required.",
    }.get(system, "Check the official OWASP ZAP download page.")

    return {
        "installed": False,
        "system": system,
        "path": None,
        "method": None,
        "guidance": guidance,
        "download_url": "https://www.zaproxy.org/download/",
    }


def _safe_extract_zip(archive_path, destination):
    """Extract a ZIP while rejecting path traversal and oversized archives."""
    destination = Path(destination).resolve()
    total_uncompressed = 0

    with zipfile.ZipFile(archive_path, "r") as archive:
        for info in archive.infolist():
            # ZIP paths may use either separator, regardless of the
            # operating system performing the extraction.
            member_name = info.filename
            posix_member = PurePosixPath(member_name.replace("\\", "/"))
            windows_member = PureWindowsPath(member_name)

            if (
                posix_member.is_absolute()
                or windows_member.is_absolute()
                or bool(windows_member.drive)
                or ".." in posix_member.parts
                or ".." in windows_member.parts
            ):
                raise RuntimeError(
                    "The ZAP archive contains an unsafe file path."
                )

            target = destination.joinpath(*posix_member.parts).resolve()
            if target != destination and destination not in target.parents:
                raise RuntimeError(
                    "The ZAP archive contains an unsafe extraction path."
                )

            total_uncompressed += info.file_size
            if total_uncompressed > MAX_EXTRACTED_BYTES:
                raise RuntimeError(
                    "The ZAP archive exceeds the permitted extraction size."
                )

        archive.extractall(destination)


def install_zap(progress_callback=None):
    """
    Download and install the pinned ZAP cross-platform package.

    progress_callback, when supplied, receives (downloaded_bytes, total_bytes).
    """
    existing = _managed_zap_jar()
    if existing:
        return {
            "installed": True,
            "system": platform.system().lower(),
            "path": str(existing),
            "method": "Shadow Map managed installation",
            "version": ZAP_VERSION,
            "install_dir": str(existing.parent),
        }

    root = managed_zap_root()
    root.mkdir(parents=True, exist_ok=True)

    work_dir = Path(tempfile.mkdtemp(prefix="zap-install-", dir=root))
    archive_path = work_dir / "zap-download.zip"
    extract_dir = work_dir / "extracted"
    extract_dir.mkdir()

    response = None

    try:
        response = requests.get(
            ZAP_ARCHIVE_URL,
            stream=True,
            timeout=(15, 120),
        )
        response.raise_for_status()

        total_bytes = int(response.headers.get("Content-Length", "0") or 0)
        downloaded = 0
        digest = hashlib.sha256()

        with archive_path.open("wb") as output:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue

                downloaded += len(chunk)
                if downloaded > MAX_DOWNLOAD_BYTES:
                    raise RuntimeError(
                        "The ZAP download exceeds the permitted size."
                    )

                digest.update(chunk)
                output.write(chunk)

                if progress_callback:
                    progress_callback(downloaded, total_bytes)

        if digest.hexdigest().lower() != ZAP_ARCHIVE_SHA256:
            raise RuntimeError(
                "ZAP download checksum verification failed. "
                "The archive was not installed."
            )

        _safe_extract_zip(archive_path, extract_dir)

        expected_jar = f"zap-{ZAP_VERSION}.jar"
        jar_matches = list(extract_dir.rglob(expected_jar))
        if not jar_matches:
            raise RuntimeError(
                f"The downloaded ZAP archive does not contain {expected_jar}."
            )

        install_dir = root / ZAP_VERSION

        # Replace only an incomplete managed installation of this version.
        if install_dir.exists():
            shutil.rmtree(install_dir)

        shutil.move(str(extract_dir), str(install_dir))

        installed_matches = list(install_dir.rglob(expected_jar))
        if not installed_matches:
            raise RuntimeError(
                "ZAP extraction completed, but its launcher JAR is missing."
            )

        return {
            "installed": True,
            "system": platform.system().lower(),
            "path": str(installed_matches[0]),
            "method": "Shadow Map managed installation",
            "version": ZAP_VERSION,
            "install_dir": str(install_dir),
        }

    except requests.RequestException as exc:
        raise RuntimeError(f"Could not download OWASP ZAP: {exc}") from exc
    finally:
        if response is not None:
            response.close()
        shutil.rmtree(work_dir, ignore_errors=True)
