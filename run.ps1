# Запуск через venv без Activate.ps1 (если ExecutionPolicy блокирует .ps1 активацию).
$py = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    Write-Error "Нет $py — выполните: py -3 -m venv .venv ; & '$py' -m pip install -r requirements.txt"
    exit 1
}
& $py @args
