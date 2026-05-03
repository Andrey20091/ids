@echo off
REM One-click pre-demo smoke for Windows.
chcp 65001 >nul
set PYTHONUTF8=1
cd /d "%~dp0"
set PY=%~dp0.venv\Scripts\python.exe
if not exist "%PY%" set PY=python

if /I "%~1"=="full" (
  %PY% scripts\pre_demo_smoke.py --with-soak --with-perf
) else (
  %PY% scripts\pre_demo_smoke.py
)
exit /b %ERRORLEVEL%
