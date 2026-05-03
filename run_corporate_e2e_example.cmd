@echo off
REM Корпоративный дамп: валидация → prepare → train (без torch для скорости) → detect
cd /d "%~dp0"
echo Building / refreshing labeled_flows_e2e.csv ...
"%~dp0.venv\Scripts\python.exe" "%~dp0scripts\build_corporate_e2e_dataset.py" 2>nul
if errorlevel 1 py -3 "%~dp0scripts\build_corporate_e2e_dataset.py"
echo Validate CSV ...
"%~dp0.venv\Scripts\python.exe" "%~dp0scripts\validate_corporate_csv.py" --input "%~dp0data\raw\corporate_example\labeled_flows_e2e.csv"
if errorlevel 1 exit /b 1
echo Prepare ...
"%~dp0.venv\Scripts\python.exe" "%~dp0main.py" prepare --input "%~dp0data\raw\corporate_example\labeled_flows_e2e.csv"
if errorlevel 1 exit /b 1
echo Train (skip torch) ...
"%~dp0.venv\Scripts\python.exe" "%~dp0main.py" train --skip-torch
if errorlevel 1 exit /b 1
echo Detect ...
"%~dp0.venv\Scripts\python.exe" "%~dp0main.py" detect --detect-limit 500
exit /b %ERRORLEVEL%
