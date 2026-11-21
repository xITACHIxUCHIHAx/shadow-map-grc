#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$(readlink -f "$0")")/.."

APP_URL="http://127.0.0.1:5000"

confirm_install() {
    local package_name="$1"
    local answer

    echo
    echo "$package_name is not installed or does not meet the required version."
    read -r -p "Install it using your system package manager? [y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

install_packages() {
    local packages=("$@")
    local sudo_cmd=()

    if [[ "$(id -u)" -ne 0 ]]; then
        if ! command -v sudo >/dev/null 2>&1; then
            echo "Installation requires root privileges or sudo."
            return 1
        fi
        sudo_cmd=(sudo)
    fi

    if command -v apt-get >/dev/null 2>&1; then
        "${sudo_cmd[@]}" apt-get update &&
        "${sudo_cmd[@]}" apt-get install -y "${packages[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        "${sudo_cmd[@]}" dnf install -y "${packages[@]}"
    elif command -v pacman >/dev/null 2>&1; then
        "${sudo_cmd[@]}" pacman -Sy --needed --noconfirm "${packages[@]}"
    elif command -v zypper >/dev/null 2>&1; then
        "${sudo_cmd[@]}" zypper --non-interactive install "${packages[@]}"
    else
        echo "Unsupported package manager. Install manually: ${packages[*]}"
        return 1
    fi
}

python_ok() {
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
        >/dev/null 2>&1
}

if ! command -v python3 >/dev/null 2>&1 || ! python_ok; then
    echo "Python 3.11 or newer is required."
    echo "Install or upgrade Python, then run this launcher again."
    exit 1
fi

if ! python3 -c 'import venv' >/dev/null 2>&1; then
    echo "Python virtual environment support is missing."

    if confirm_install "Python virtual environment support"; then
        if command -v apt-get >/dev/null 2>&1; then
            install_packages python3-venv || {
                echo "Could not install Python venv support."
                exit 1
            }
        elif command -v dnf >/dev/null 2>&1; then
            install_packages python3 || {
                echo "Could not install Python venv support."
                exit 1
            }
        elif command -v pacman >/dev/null 2>&1; then
            install_packages python || {
                echo "Could not install Python venv support."
                exit 1
            }
        elif command -v zypper >/dev/null 2>&1; then
            install_packages python3-venv || {
                echo "Could not install Python venv support."
                exit 1
            }
        else
            echo "Install Python venv support manually."
            exit 1
        fi
    else
        echo "Python venv support is required. Exiting."
        exit 1
    fi
fi

if ! python3 -c 'import venv' >/dev/null 2>&1; then
    echo "Python venv support is still unavailable. Exiting."
    exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
    if confirm_install "Nmap (required for network scanning)"; then
        install_packages nmap || echo "Nmap installation failed. Application startup will continue."
    else
        echo "Skipping Nmap. Network scanning will be unavailable."
    fi
fi

java_version=0
if command -v java >/dev/null 2>&1; then
    java_output="$(java -version 2>&1 || true)"
    java_version="$(
        printf '%s\n' "$java_output" |
        sed -nE '1s/.*version "([0-9]+).*/\1/p'
    )"
    java_version="${java_version:-0}"
fi

if [[ "$java_version" -lt 17 ]]; then
    if confirm_install "Java 17 or newer (required only for OWASP ZAP)"; then
        if command -v apt-get >/dev/null 2>&1; then
            install_packages openjdk-17-jre || echo "Java installation failed. Application startup will continue."
        elif command -v dnf >/dev/null 2>&1; then
            install_packages java-17-openjdk || echo "Java installation failed. Application startup will continue."
        elif command -v pacman >/dev/null 2>&1; then
            install_packages jre17-openjdk || echo "Java installation failed. Application startup will continue."
        elif command -v zypper >/dev/null 2>&1; then
            install_packages java-17-openjdk || echo "Java installation failed. Application startup will continue."
        else
            echo "Install Java 17+ manually if OWASP ZAP is required."
        fi
    else
        echo "Skipping Java. OWASP ZAP will be unavailable."
    fi
fi

if [[ ! -x venv/bin/python ]]; then
    python3 -m venv venv
fi

venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install -r requirements.txt

echo
echo "Starting Shadow Map GRC at $APP_URL"
echo "Keep this terminal open. Press Ctrl+C to stop."
exec venv/bin/python app.py
