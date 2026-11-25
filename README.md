# Shadow Map GRC

**Security Assessment and Governance, Risk & Compliance Platform**

Shadow Map GRC is a Flask-based application that combines security assessment, risk management and GRC documentation in one platform.

| Information | Details |
|---|---|
| Project | Shadow Map GRC |
| Author | [xITACHIxUCHIHAx](https://github.com/xITACHIxUCHIHAx) |
| License | MIT |
| Technology | Python, Flask, SQLite |
| Deployment | Docker and Docker Compose |

## Screenshots

### Dashboard
![Dashboard](docs/screenshots/dashboard.png)

### Unified Scan
![Unified Scan](docs/screenshots/unified-scan.png)

### Risk Register
![Risk Register](docs/screenshots/risk-register.png)

## Features

- Unified security assessments
- Nmap network and service scanning
- LAN Monitor
- Web Security and Wapiti integration
- OWASP ZAP integration
- Firewall assessment
- Threat Intelligence
- Findings Review and Risk Register
- Custom Rules
- ISO/IEC 27001:2022 control traceability
- PDF reports and CSV exports
- Scan history and Records Management

## Requirements

- Windows, macOS or Linux/Kali
- Docker and Docker Compose
- Internet connection for the initial Docker image pull
- Sufficient disk space for Docker images and application data

The supplied Docker image includes Python, Nmap, Java 21 and OWASP ZAP 2.17.0.

The prebuilt image is available on Docker Hub:

```bash
docker pull xitachixuchihax/shadow-map-grc:latest
```

The `start` and `restart` commands pull the latest published image. To build
and publish changes from your local source tree, authenticate to Docker Hub and
run the `publish` command; it builds the image, pushes the configured tag, and
deploys that same locally built image.

## Installing Git

Git is required to clone the Shadow Map GRC repository.

### Windows

```powershell
winget install --id Git.Git -e --source winget
```

Official installer: https://git-scm.com/downloads/win

### Linux

**Ubuntu / Debian / Kali**
```bash
sudo apt update && sudo apt install git -y
```

**Fedora**
```bash
sudo dnf install git -y
```

**RHEL / CentOS**
```bash
sudo yum install git -y
```

**Arch Linux / Manjaro**
```bash
sudo pacman -S git
```

**openSUSE**
```bash
sudo zypper install git
```

**Alpine Linux**
```bash
sudo apk add git
```

### macOS

```bash
brew install git
```

Alternatively: `xcode-select --install`

### Other Operating Systems

https://git-scm.com/install

### Verify Git Installation

```bash
git --version
```

### Clone Shadow Map GRC

```bash
git clone https://github.com/xITACHIxUCHIHAx/shadow-map-grc.git
```

## Installation

### 1. Download the project

Clone the repository:

```bash
git clone https://github.com/xITACHIxUCHIHAx/shadow-map-grc.git
cd shadow-map-grc
```

Alternatively, download the ZIP from GitHub and extract it.

### 2. Install Docker

Install Docker for your operating system:

- [Windows – Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/)
- [macOS – Docker Desktop](https://docs.docker.com/desktop/setup/install/mac-install/)
- [Linux – Docker Engine](https://docs.docker.com/engine/install/)

For Kali Linux, follow the Docker Debian installation instructions appropriate to your system.

Start Docker Desktop on Windows/macOS.

On Linux:

```bash
sudo systemctl enable --now docker
```

Verify installation:

```bash
docker --version
docker compose version
```

### 3. Configure the application

**Important:** Run all commands in this section inside the Shadow Map GRC project root directory — the folder containing `docker-compose.yml`, `Dockerfile` and `.env.example`.

If you are not already in the project directory:

**Linux/macOS:**

```bash
cd ~/shadow-map-grc
```

**Windows PowerShell:**

```powershell
cd C:\path\to\shadow-map-grc
```

Replace the example Windows path with your actual project location.

**Create the `.env` file:**

Linux/macOS:

```bash
cp .env.example .env
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

**Generate a secure secret:**

Linux/macOS:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Windows PowerShell:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Copy the generated value.

**Open `.env` in a text editor:**

Linux:

```bash
nano .env
```

macOS:

```bash
open -e .env
```

Windows:

```powershell
notepad .env
```

Replace the example value with your generated secret:

```env
SHADOW_MAP_SECRET_KEY=paste-your-generated-secret-here
```

Save the file and close the editor.

**Important:**
- `.env` must be in the project root, alongside `docker-compose.yml`.
- Do not create it in another directory.
- Do not upload `.env` to GitHub.
- Keep your secret private.

### 4. Start Shadow Map GRC

Run the command from the project root directory.

**Linux:**

```bash
./scripts/grc start
```

**macOS:**

The macOS launcher is a Bash script. Run it without changing file permissions:

```bash
./scripts/grc start
```

If you prefer to execute it directly, grant execute permission once:

```bash
chmod 755 scripts/grc
./scripts/grc start
```

If macOS reports that the file is from an unidentified developer, do not disable
Gatekeeper globally. First verify that the file came from the official project
source. If the trusted file has a quarantine attribute and you deliberately
choose to clear it, remove that attribute only from this launcher:

```bash
xattr -d com.apple.quarantine scripts/grc
```

This is not a general antivirus exclusion and should not be used for files whose
origin you have not verified.

**Windows CMD and PowerShell:**

No PowerShell execution-policy change is required.

Then start Shadow Map GRC:

```powershell
.\scripts\grc.cmd start
```

The first startup downloads the published Docker image. This may take some time depending on your internet connection.

### 5. Open the application

Once the container has started, open:

**http://127.0.0.1:5000**

Health check:

**http://127.0.0.1:5000/health**

Expected response:

```json
{"status":"ok"}
```

## Management Commands

Run these commands from the project root.

| Action | Linux / macOS | Windows CMD / PowerShell |
|---|---|---|
| Start | `./scripts/grc start` | `.\scripts\grc.cmd start` |
| Stop | `./scripts/grc stop` | `.\scripts\grc.cmd stop` |
| Restart | `./scripts/grc restart` | `.\scripts\grc.cmd restart` |
| Status | `./scripts/grc status` | `.\scripts\grc.cmd status` |
| Logs | `./scripts/grc logs` | `.\scripts\grc.cmd logs` |
| Build, publish and deploy | `./scripts/grc publish` | `.\scripts\grc.cmd publish` |

## Publishing an Updated Docker Image

The Network Monitor source includes authenticated host-agent integration. The
host agent provides the host operating system's active IPv4 interfaces to the
Network Configuration page and performs authorized discovery on that host
interface. The running container must use an image built from this source for
those application-side changes to appear in the browser.

To publish and deploy your current local source in one operation:

1. Sign in to Docker Hub using the same Docker account/context used by the
   launcher. On Linux systems where the launcher uses `sudo docker`, log in
   with `sudo docker login`.
2. Run the platform launcher with the `publish` action.

Linux:

```bash
./scripts/grc publish
```

macOS:

```bash
./scripts/grc publish
```

Windows PowerShell:

```powershell
.\scripts\grc.cmd publish
```

The command validates the Compose configuration, builds
`xitachixuchihax/shadow-map-grc:latest` from the current project directory,
starts the host discovery agent, deploys the locally built image, and checks
`/health`. It pushes the image to Docker Hub only after the local deployment
passes its health check. It does not modify GitHub or commit source files.
Docker Hub credentials are managed by Docker; never put a registry password
or access token in `.env`.

## Host-side LAN Discovery Agent

The Network Monitor uses a small authenticated Python agent on the host so that
LAN interface discovery and neighbour-table lookups run in the host operating
system rather than inside Docker.

- The launcher creates a random `SHADOW_MAP_HOST_AGENT_TOKEN` on first start
  and stores it in `.env`; the token is not printed.
- On Linux, the launcher creates the Compose network, discovers its gateway,
  and binds the agent to that gateway address.
- On Windows and macOS with Docker Desktop, the agent listens on the host
  interfaces and the container connects through `host.docker.internal`.
- The dashboard remains bound to `127.0.0.1:5000`.
- The launcher records only processes it starts. `stop` never terminates an
  independently started host agent.
- Keep host firewall protection enabled. On Windows/macOS, restrict inbound
  TCP port `5001` to the Docker Desktop/WSL source network; do not create a
  public internet port-forward for this service.
- **Security limitation:** the current host-agent connection uses HTTP rather
  than TLS, and the Windows/macOS launcher binds to host interfaces so Docker
  Desktop can reach it. The bearer token is therefore not protected against
  capture by an attacker who can observe that traffic. This launcher does not
  install firewall rules automatically. Do not use this host-agent mode on an
  untrusted network unless your host firewall is configured to permit only the
  Docker Desktop/WSL source and block other inbound access. A TLS-protected
  transport and native Windows/macOS firewall verification are release blockers
  for wider distribution.
- If the host Python environment does not already have the agent dependencies,
  install the small host-only set with
  `python -m pip install -r requirements-host-agent.txt`.

The host agent uses bearer-token authentication. Rotate the token by stopping
Shadow Map GRC, replacing `SHADOW_MAP_HOST_AGENT_TOKEN` in `.env` with a newly
generated random value, and starting it again. Never commit or share `.env`.

## Windows and macOS Security-Tool Exclusions

**Normal installation should not require antivirus exclusions.** Keep Microsoft
Defender, Gatekeeper, XProtect, macOS System Integrity Protection (SIP), and
third-party endpoint protection enabled. Do not exclude the entire drive, home
directory, Python installation, Docker installation, `data/`, reports, or scan
targets.

### Windows Defender (only for a confirmed false positive)

First verify the project source and identify the exact file Defender blocked.
Prefer submitting a suspected false positive to Microsoft or asking your
administrator to review it. If an administrator explicitly approves a temporary
exception, run PowerShell as Administrator and add only the specific blocked
launcher file:

```powershell
$BlockedFile = (Resolve-Path "scripts\grc.cmd").Path
Add-MpPreference -ExclusionPath $BlockedFile
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

Remove the exception when it is no longer required:

```powershell
Remove-MpPreference -ExclusionPath $BlockedFile
```

Use the actual blocked file path if needed. An exclusion
reduces protection for that file; it does not establish that the file is safe.
Do not add broad process, interpreter, folder, or drive exclusions.

### macOS

macOS does not provide a universal command for adding a folder exclusion to
Gatekeeper or XProtect. Do not disable Gatekeeper, SIP, or XProtect to run this
project. For a verified launcher blocked because of its quarantine metadata,
follow the file-specific `xattr` guidance in the macOS startup section above.
For third-party antivirus or endpoint products, use that vendor's documented
per-file exception workflow only after administrator approval; the command and
scope are product-specific.

If your organization manages endpoint protection, follow its policy rather than
adding local exclusions yourself.

## Background Process Management

Shadow Map GRC runs inside a Docker container in the background.

Docker Compose uses `restart: unless-stopped`. Docker may automatically restart
the container after a Docker service or host restart, unless it was explicitly
stopped.


### Check whether the application is running

Check all running containers:

```bash
docker ps
```

Check the Shadow Map GRC container:

```bash
docker ps --filter "name=grc"
```

Check Compose service status:

```bash
docker compose ps
```

### View background logs

Follow live application logs:

```bash
docker logs -f grc
```

View the last 100 log lines:

```bash
docker logs --tail 100 grc
```

Press `Ctrl+C` to stop viewing live logs. This does not stop the application.

### Stop the application

**Linux/macOS:**

```bash
./scripts/grc stop
```

**Windows PowerShell:**

```powershell
.\scripts\grc.cmd stop
```

This stops the application container while preserving project data.

### Restart the application

**Linux/macOS:**

```bash
./scripts/grc restart
```

**Windows PowerShell:**

```powershell
.\scripts\grc.cmd restart
```

### Find a process using port 5000

**Linux:**

```bash
sudo ss -ltnp | grep ':5000'
```

**macOS:**

```bash
lsof -i :5000
```

**Windows PowerShell:**

```powershell
Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue
```

### Terminate a conflicting process

First identify the process and confirm that it is safe to stop.

**Linux:**

```bash
sudo kill <PID>
```

If it does not stop:

```bash
sudo kill -9 <PID>
```

**macOS:**

```bash
kill <PID>
```

If necessary:

```bash
kill -9 <PID>
```

**Windows PowerShell:**

```powershell
Stop-Process -Id <PID>
```

If necessary:

```powershell
Stop-Process -Id <PID> -Force
```

Replace `<PID>` with the actual process ID.

**Important:**
- Prefer `./scripts/grc stop` or `.\scripts\grc.cmd stop` over manually terminating processes.
- If Docker is using port 5000, stop Shadow Map GRC through its management script.
- Do not kill Docker, system processes, or unidentified processes.
- Use `kill -9` or `Stop-Process -Force` only as a last resort.

## Troubleshooting

| Problem | Solution |
|---|---|
| Docker is not running | Start Docker Desktop or start the Docker service on Linux. |
| Docker Compose not found | Install the Docker Compose plugin. |
| Missing secret key | Check that `.env` exists in the project root and contains `SHADOW_MAP_SECRET_KEY`. |
| Port 5000 already in use | Stop the conflicting process or change the host port mapping in `docker-compose.yml`. |
| Application does not open | Check `docker compose ps` and `docker logs --tail 100 grc`. |
| Docker build fails | Check internet connectivity, disk space and Docker build output. |
| Nmap unavailable | Check with `docker exec grc nmap --version`. |

For additional diagnostics:

```bash
docker compose ps
docker logs --tail 200 grc
```

## MITRE ATT&CK Catalogue

When the application starts, a background worker checks the official MITRE
Enterprise ATT&CK release index and imports the catalogue when the local
database is empty or outdated.

- Internet access is required for the initial download and update checks.
- After a successful check, updates are checked every 24 hours.
- If synchronization fails, the worker retries after 15 minutes.
- The catalogue is stored in the local SQLite database.

## Data Storage

Application data is stored in:

```text
data/
```

Default SQLite database:

```text
data/shadow_map.db
```

Back up the `data/` directory before upgrades or maintenance. Stopping or rebuilding the container does not normally remove the mounted application data.

## Security Notice

- Use the application only on systems you own or have explicit authorization to assess.
- Wapiti findings are unverified indicators and require manual validation.
- Protect database files, reports and environment secrets.
- The supplied Docker configuration uses elevated container privileges for network assessment capabilities.
- ISO/IEC 27001:2022 mappings support traceability and do not constitute certification.

## Project Structure

| Path | Purpose |
|---|---|
| `app.py` | Flask application and routes |
| `config.py` | Application configuration |
| `data/` | Application data |
| `grc/` | Governance, risk and compliance logic |
| `scanner/` | Security assessment modules |
| `reporting/` | Report generation |
| `scripts/` | Cross-platform application and host-agent launchers |
| `static/` | Static assets |
| `templates/` | HTML templates |
| `tests/` | Automated tests |
| `requirements.txt` | Application Python dependencies |
| `requirements-host-agent.txt` | Minimal host-agent dependencies |

## Development Checks

The automated test suite can be run in a Python development environment
with the project dependencies installed.

Install pytest if it is not already available:

```bash
python -m pip install pytest
```

Run the tests:

```bash
python -m pytest
```

## Assessment Limitations

- Results depend on available tools, network access, target configuration and permissions.
- Nmap OS detection may require additional platform-specific privileges.
- Some integrations require separate configuration.
- The application is intended for local use by default. Shared or production deployment requires additional security review.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.