# Установка окружения под Windows (запуск из корня проекта).
#
# Ошибка ProxyError / WinError 10061: pip идёт на «битый» прокси.
#   1) В этом скрипте прокси для сессии отключается + pip вызывается с --proxy "".
#   2) Если не помогло: Параметры Windows → Сеть и Интернет → Прокси → отключите ручной прокси.
#   3) Проверьте переменные среды пользователя (HTTP_PROXY, HTTPS_PROXY) — удалите или исправьте.
#   4) Админ: cmd → netsh winhttp reset proxy
#   5) Постоянно сбросить в user-окружении: setx HTTP_PROXY ""  и  setx HTTPS_PROXY ""  (закройте терминал и откройте снова).

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

# Убрать прокси из текущего процесса (в т.ч. регистронезависимые дубликаты)
foreach ($name in @(
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "all_proxy", "no_proxy"
    )) {
    if (Test-Path "Env:\$name") {
        Remove-Item "Env:\$name" -ErrorAction SilentlyContinue
    }
}

if (-not (Test-Path ".venv")) {
    python -m venv .venv
}

$pip = Join-Path $Root ".venv\Scripts\pip.exe"
$py = Join-Path $Root ".venv\Scripts\python.exe"

# Общие флаги: не использовать прокси + доверенные хосты (корпоративные сети / SSL)
$pipTrust = @(
    "--proxy", "",
    "--trusted-host", "pypi.org",
    "--trusted-host", "pypi.python.org",
    "--trusted-host", "files.pythonhosted.org"
)

function Invoke-ProjectPip {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$PipArgs)
    & $pip @PipArgs @pipTrust
    if ($LASTEXITCODE -ne 0) {
        throw "pip failed: $pip $($PipArgs -join ' ')"
    }
}

Write-Host "Installing / upgrading pip..."
Invoke-ProjectPip install -U pip

Write-Host "Installing requirements.txt..."
Invoke-ProjectPip install -r requirements.txt

Write-Host "Trying CPU PyTorch (optional)..."
& $pip install -r requirements-ml.txt --index-url https://download.pytorch.org/whl/cpu @pipTrust `
    --trusted-host "download.pytorch.org" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Note: torch not installed. Use: python scripts/02_train_all.py --skip-torch"
}

& $py scripts/00_generate_demo_data.py
Write-Host "Done. Activate: .\.venv\Scripts\Activate.ps1"
Write-Host "Then: python scripts/01_prepare_data.py --input data/raw/synthetic_cicids_demo.csv"
