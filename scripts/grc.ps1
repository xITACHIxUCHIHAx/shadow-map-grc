param(
    [Parameter(Position = 0)]
    [ValidateSet("start", "stop", "restart", "status", "logs")]
    [string]$Action
)

$ErrorActionPreference = "Stop"
$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is not installed or is not available in PATH."
}

docker info | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Docker Desktop is not running. Start Docker Desktop first."
}

Push-Location $ProjectDir

try {
    switch ($Action) {
        "start"   { docker compose pull grc; if ($LASTEXITCODE -ne 0) { throw "Docker image pull failed." }; docker compose up -d }
        "stop"    { docker compose down }
        "restart" { docker compose pull grc; if ($LASTEXITCODE -ne 0) { throw "Docker image pull failed." }; docker compose up -d }
        "status"  { docker compose ps }
        "logs"    { docker compose logs -f }
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Shadow Map GRC command failed."
    }
}
finally {
    Pop-Location
}
