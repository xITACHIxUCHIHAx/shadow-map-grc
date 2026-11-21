#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")/.."

APP_URL="http://127.0.0.1:5000"

confirm_install() {
    local package_name="$1"
    local answer

    echo
    echo "$package_name is not installed or does not meet the required version."
    read -r -p "Install it using Homebrew? [y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3.11 or newer is required."
    echo "Install Python from https://www.python.org/downloads/macos/"
    exit 1
fi

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
    echo "Python 3.11 or newer is required."
    python3 --version
    exit 1
fi

if ! python3 -c 'import venv' >/dev/null 2>&1; then
    echo "Python virtual environment support is missing."
    echo "Repair your Python installation, then rerun this launcher."
    exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
    if confirm_install "Nmap (required for network scanning)"; then
        if command -v brew >/dev/null 2>&1; then
            brew install nmap || echo "Nmap installation failed. Application startup will continue."
        else
            echo "Homebrew is unavailable. Install Nmap manually:"
            echo "https://nmap.org/download.html"
        fi
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
        if command -v brew >/dev/null 2>&1; then
            brew install --cask temurin@17 || echo "Java installation failed. Application startup will continue."
            echo "If Java was installed, open a new terminal if necessary."
        else
            echo "Homebrew is unavailable. Install Java 17+ manually:"
            echo "https://adoptium.net/temurin/releases/"
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
