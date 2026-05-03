@echo off
REM UTF-8 launcher for Windows console readability.
chcp 65001 >nul
set PYTHONUTF8=1
cd /d "%~dp0"
if "%~1"=="" (
  echo Usage: run_utf8.cmd ^<python args^>
  echo Example: run_utf8.cmd main.py detect --detect-limit 2000
  exit /b 2
)
set PY=%~dp0.venv\Scripts\python.exe
if not exist "%PY%" set PY=python
%PY% %*
exit /b %ERRORLEVEL%
