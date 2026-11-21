@echo off
setlocal
cd /d "%~dp0.."

set "APP_URL=http://127.0.0.1:5000"

where py >nul 2>nul
if errorlevel 1 (
    echo Python 3.11 or newer is required.
    echo Install Python from https://www.python.org/downloads/windows/
    goto error
)

py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)"
if errorlevel 1 (
    echo Python 3.11 or newer is required.
    py -3 --version
    goto error
)

py -3 -c "import venv" >nul 2>nul
if errorlevel 1 (
    echo Python virtual environment support is missing.
    goto error
)

where nmap >nul 2>nul
if errorlevel 1 goto install_nmap
goto check_java

:install_nmap
echo.
echo Nmap is required for network scanning.
set "INSTALL_NMAP="
set /p "INSTALL_NMAP=Install Nmap using winget? [y/N]: "
if /I not "%INSTALL_NMAP%"=="Y" goto nmap_skipped

where winget >nul 2>nul
if errorlevel 1 (
    echo winget is unavailable. Install Nmap manually:
    echo https://nmap.org/download.html
    goto check_java
)

echo Refreshing winget sources...
winget source update
if errorlevel 1 (
    echo winget source update failed. Skipping automatic Nmap installation.
    echo Install Nmap manually: https://nmap.org/download.html
    goto check_java
)
echo Checking Nmap package...
winget search --id Insecure.Nmap --exact
if errorlevel 1 (
    echo Nmap package was not found. Install it manually:
    echo https://nmap.org/download.html
    goto check_java
)

winget install --id Insecure.Nmap --exact --accept-package-agreements --accept-source-agreements
if errorlevel 1 (
    echo Nmap installation failed. Install it manually:
    echo https://nmap.org/download.html
    goto check_java
)

if exist "%ProgramFiles(x86)%\Nmap" set "PATH=%PATH%;%ProgramFiles(x86)%\Nmap"
if exist "%ProgramFiles%\Nmap" set "PATH=%PATH%;%ProgramFiles%\Nmap"

where nmap >nul 2>nul
if errorlevel 1 (
    echo Nmap may be installed but is not available in this terminal.
    echo Reopen Command Prompt after installation.
)
goto check_java

:nmap_skipped
echo Skipping Nmap. Network scanning will be unavailable.

:check_java
set "JAVA_OK="
where java >nul 2>nul
if not errorlevel 1 (
    powershell -NoProfile -Command "$v = (java -version 2^>^&1 ^| Select-Object -First 1).ToString(); $m = [regex]::Match($v, 'version.{0,2}([0-9]+)'); if ($m.Success -and [int]$m.Groups[1].Value -ge 17) { exit 0 }; exit 1"
    if not errorlevel 1 set "JAVA_OK=1"
)
if defined JAVA_OK goto setup_python

echo.
echo Java 17 or newer is required only for OWASP ZAP.
set "INSTALL_JAVA="
set /p "INSTALL_JAVA=Install Java 17 JRE using winget? [y/N]: "
if /I not "%INSTALL_JAVA%"=="Y" goto java_skipped

where winget >nul 2>nul
if errorlevel 1 (
    echo winget is unavailable. Install Java manually:
    echo https://adoptium.net/temurin/releases/
    goto setup_python
)

echo Refreshing winget sources...
winget source update
if errorlevel 1 (
    echo winget source update failed. Skipping automatic Java installation.
    echo Install Java manually: https://adoptium.net/temurin/releases/
    goto setup_python
)
echo Checking Java package...
winget search --id EclipseAdoptium.Temurin.17.JRE --exact
if errorlevel 1 (
    echo Java package was not found. Install it manually:
    echo https://adoptium.net/temurin/releases/
    goto setup_python
)

winget install --id EclipseAdoptium.Temurin.17.JRE --exact --accept-package-agreements --accept-source-agreements
if errorlevel 1 (
    echo Java installation failed. Install it manually:
    echo https://adoptium.net/temurin/releases/
    goto setup_python
)
echo If Java is not detected, reopen Command Prompt after installation.
goto setup_python

:java_skipped
echo Skipping Java. OWASP ZAP will be unavailable.

:setup_python
if not exist venv\Scripts\python.exe (
    py -3 -m venv venv
    if errorlevel 1 goto error
)

venv\Scripts\python.exe -m pip install --upgrade pip
if errorlevel 1 goto error

venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto error

echo.
echo Starting Shadow Map GRC at %APP_URL%
echo Keep this window open. Press Ctrl+C to stop.
venv\Scripts\python.exe app.py
goto end

:error
echo.
echo Startup failed. Check the error above.
pause
exit /b 1

:end
pause
endlocal
