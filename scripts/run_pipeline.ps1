# Полный прогон демо после активации venv и установки зависимостей.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    Write-Error "Нет .venv. Сначала: powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1"
}

& $py scripts/check_env.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $py scripts/00_generate_demo_data.py
& $py scripts/01_prepare_data.py --input data/raw/synthetic_cicids_demo.csv
& $py scripts/02_train_all.py --skip-torch
& $py scripts/03_run_detection_batch.py
Write-Host "Дашборд: streamlit run dashboard/app.py"
