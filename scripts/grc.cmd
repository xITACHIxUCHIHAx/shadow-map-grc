@echo off
setlocal
cd /d "%~dp0.."

where py >nul 2>&1
if not errorlevel 1 goto use_py

where python >nul 2>&1
if not errorlevel 1 goto use_python

echo ERROR: Python 3 is required.
exit /b 1

:use_py
py -3 "%~dp0grc_launcher.py" %*
exit /b %ERRORLEVEL%

:use_python
python "%~dp0grc_launcher.py" %*
exit /b %ERRORLEVEL%
