#!/usr/bin/env bash
set -e
cd "$(dirname "$(readlink -f "$0")")/.."

install_pkg() {
    if command -v apt-get >/dev/null 2>&1; then
        if [ "$(id -u)" -eq 0 ]; then
            apt-get update
            apt-get install -y "$@"
        elif command -v sudo >/dev/null 2>&1; then
            sudo apt-get update
            sudo apt-get install -y "$@"
        else
            echo "Cannot install packages: root or sudo required."
            exit 1
        fi
    else
        echo "Install these packages manually: $*"
        exit 1
    fi
}

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 is required. Install Python 3, then rerun."
    exit 1
fi

if ! python3 -c 'import venv' >/dev/null 2>&1; then
    install_pkg python3-venv
fi

if ! command -v nmap >/dev/null 2>&1; then
    echo "Nmap missing. Attempting installation..."
    install_pkg nmap
fi

if [ ! -x venv/bin/python ]; then
    python3 -m venv venv
fi

venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install -r requirements.txt

echo "Starting Shadow Map GRC at http://127.0.0.1:5000"
exec venv/bin/python app.py
