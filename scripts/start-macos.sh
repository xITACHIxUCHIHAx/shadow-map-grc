#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 is required. Install Python 3, then rerun."
    exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
    echo "Nmap missing."
    if command -v brew >/dev/null 2>&1; then
        brew install nmap
    else
        echo "Homebrew is required for automatic Nmap installation."
        echo "Install Homebrew and rerun, or install Nmap manually."
        exit 1
    fi
fi

if [ ! -x venv/bin/python ]; then
    python3 -m venv venv
fi

venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install -r requirements.txt

echo "Starting Shadow Map GRC at http://127.0.0.1:5000"
exec venv/bin/python app.py
