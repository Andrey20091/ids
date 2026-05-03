@echo off
set "ROOT=%~dp0"
"%ROOT%.venv\Scripts\python.exe" %*
if errorlevel 1 exit /b %ERRORLEVEL%
