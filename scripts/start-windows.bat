@echo off
setlocal
cd /d "%~dp0.."

where py >nul 2>nul
if errorlevel 1 (
    echo Python 3 is required. Install Python 3 and rerun.
    pause
    exit /b 1
)

where nmap >nul 2>nul
if errorlevel 1 (
    echo Nmap missing. Attempting installation with winget...
    where winget >nul 2>nul
    if errorlevel 1 (
        echo winget is unavailable. Install Nmap manually, then rerun.
        pause
        exit /b 1
    )
    winget install --id Insecure.Nmap --exact --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo Nmap installation failed. Install it manually, then rerun.
        pause
        exit /b 1
    )
    where nmap >nul 2>nul
    if errorlevel 1 (
        echo Nmap was installed, but this terminal cannot find it yet.
        echo Reopen Command Prompt and run this launcher again.
        pause
        exit /b 1
    )
)

if not exist venv\Scripts\python.exe (
    py -3 -m venv venv
    if errorlevel 1 goto error
)

venv\Scripts\python.exe -m pip install --upgrade pip
if errorlevel 1 goto error

venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto error

echo Starting Shadow Map GRC at http://127.0.0.1:5000
venv\Scripts\python.exe app.py
goto end

:error
echo Startup failed. Check the error above.
pause
exit /b 1

:end
pause
endlocal
