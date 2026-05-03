# Сборка ids-cli.exe (PyInstaller). Запуск из корня репозитория.
# Перед сборкой: pip install -r requirements.txt -r requirements-ml.txt
#   (для CPU torch: см. комментарий в requirements-ml.txt — index-url PyTorch).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { throw "python not on PATH" }

python -c "import torch" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Warning 'torch is not importable: DL stack will be missing from the bundle. Install requirements-ml.txt or use skip-torch at runtime.'
}

& $py -m pip show pyinstaller 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing PyInstaller..."
    & $py -m pip install pyinstaller
}

& $py -m PyInstaller --noconfirm --clean ids-cli.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with code $LASTEXITCODE" }
Write-Host "Output: dist\ids-cli\"
