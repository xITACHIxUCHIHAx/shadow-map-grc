# Shadow Map GRC

A lightweight, local security assessment and Governance, Risk, and Compliance (GRC) application built with Python, Flask, and SQLite.

## Features

- Dashboard and scan history
- Nmap port and service scanning
- Web security scanning
- Threat intelligence lookups
- Combined findings and findings review
- Risk assessments and risk register
- Custom detection rules
- ISO 27001:2022 control mapping and traceability
- Reports and CSV exports
- Records management and database cleanup

Available features depend on the configured modules and installed tools.

## Requirements

- Python 3
- Internet access for initial dependency installation
- Nmap for Nmap scanning
- An operating-system package manager for automatic Nmap installation, or Nmap installed manually
- Administrator privileges or sudo may be required to install system packages

## Quick Start

First, download or clone the project and open a terminal in the project root directory.

### Kali Linux and other Linux distributions

Run:

    bash scripts/start-linux.sh

The launcher checks for Python and Nmap, attempts to install missing packages using apt-get when available, creates a Python virtual environment, installs the Python requirements, and starts the application.

Automatic system-package installation is supported only where apt-get and suitable permissions are available.

### macOS

Run:

    bash scripts/start-macos.sh

The launcher checks for Python and Nmap, attempts to install Nmap using Homebrew when available, creates a Python virtual environment, installs the Python requirements, and starts the application.

Install Python 3 and Homebrew first if they are missing. The launcher does not install Python or Homebrew automatically.

### Windows

Open Command Prompt in the project root directory and run:

    scripts\start-windows.bat

The launcher checks for Python and Nmap, attempts to install Nmap using winget when available, creates a Python virtual environment, installs the Python requirements, and starts the application.

Install Python 3 and ensure the Python launcher (`py`) is available. If automatic Nmap installation fails, install Nmap manually and run the launcher again.

## Open the Application

Once the launcher starts successfully, open:

    http://127.0.0.1:5000

Keep the terminal open while using the application. Press Ctrl+C in the terminal to stop it.

If startup fails, read the terminal error, install the missing prerequisite, and rerun the launcher.

## Database and Backups

The application stores records in SQLite. The active database is normally located in the `data/` directory; its exact path is controlled by the application configuration.

Keep the database and any backups safe. Deleting records can be destructive. Back up important data before performing database cleanup.

## Project Structure

- `app.py` - Flask application and routes
- `config.py` - Application configuration
- `data/` - Application database
- `grc/` - Risk and GRC logic
- `scanner/` - Scanning and security assessment modules
- `scripts/` - Linux, macOS, and Windows launchers
- `static/` - Static assets
- `templates/` - HTML templates
- `requirements.txt` - Python dependencies

## Development Checks

To check the main Python files:

    python -m py_compile app.py config.py

To install Python dependencies manually:

Linux/macOS:

    python3 -m venv venv
    source venv/bin/activate
    python -m pip install -r requirements.txt

Windows:

    py -3 -m venv venv
    venv\Scripts\activate
    python -m pip install -r requirements.txt

## Responsible Use

Only scan systems you own or have explicit permission to assess. Follow applicable laws and organizational policies. Treat scan results, IP addresses, database records, and exported reports as potentially sensitive information.

ISO 27001:2022 mappings support assessment and documentation; they do not certify compliance. Review findings and mappings before relying on them.

## Limitations

- Scanner results depend on installed tools, network access, permissions, and target configuration.
- Some security checks may require elevated privileges or additional tools.
- Automatic dependency installation depends on the operating system, package manager, network availability, and permissions.
- The launchers have not necessarily been tested on every supported operating system.

## License

No license is implied unless a license file is included in this project.
