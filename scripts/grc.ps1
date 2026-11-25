param(
    [Parameter(Position = 0)]
    [ValidateSet("start", "stop", "restart", "status", "logs", "publish")]
    [string]$Action
)

# Use a temporary execution-policy bypass for this process only.
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

$ErrorActionPreference = "Stop"
$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvPython = Join-Path $ProjectDir "venv\Scripts\python.exe"

if (Test-Path $VenvPython) {
    $Python = $VenvPython
}
else {
    $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $PythonCommand) {
        throw "Python 3 is required and was not found in PATH."
    }
    $Python = $PythonCommand.Source
}

$Launcher = Join-Path $PSScriptRoot "grc_launcher.py"
& $Python $Launcher $Action
if ($LASTEXITCODE -ne 0) {
    throw "Shadow Map GRC command failed with exit code $LASTEXITCODE."
}
