# Запуск из корня репозитория.
# Если политика блокирует скрипты: запустите run_full_tz_friday_example.cmd
#   или: powershell -NoProfile -ExecutionPolicy Bypass -File .\run_full_tz_friday_example.ps1

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$inner = Join-Path $root "scripts\run_full_tz_friday_example.ps1"
if (-not (Test-Path $inner)) {
    Write-Error "Script not found: $inner"
    exit 1
}

& $inner
