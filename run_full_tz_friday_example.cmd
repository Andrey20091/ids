@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_full_tz_friday_example.ps1"
exit /b %ERRORLEVEL%
