# Create .venv with Python 3.12 or 3.11 (PyTorch-friendly). Avoids 3.14-only stacks.
# Run from repo root:  powershell -ExecutionPolicy Bypass -File scripts\setup_venv.ps1
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

function Test-PyLauncherVersion {
    param([string]$Tag)
    try {
        $null = & py "-$Tag" -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        $out = & py "-$Tag" -c "import sys; print(sys.executable)"
        return ($out | Select-Object -Last 1).ToString().Trim()
    } catch {
        return $null
    }
}

$chosen = $null
foreach ($ver in @("3.12", "3.11")) {
    $exe = Test-PyLauncherVersion $ver
    if ($exe -and (Test-Path $exe)) {
        Write-Host "Using Python $ver : $exe"
        $chosen = $exe
        break
    }
}

if (-not $chosen) {
    Write-Host "Python 3.12 or 3.11 not found (try: py -3.12 / py -3.11)."
    Write-Host "Install 3.12: winget install Python.Python.3.12"
    Write-Host "Or: https://www.python.org/downloads/ (enable Add to PATH)"
    Write-Host "Then run this script again."
    exit 1
}

if (Test-Path ".venv") {
    Write-Host ".venv already exists. Remove or rename it, then re-run."
    exit 1
}

& $chosen -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -U pip
& .\.venv\Scripts\pip.exe install -r requirements.txt
Write-Host "Done. Interpreter: $Root\.venv\Scripts\python.exe"
Write-Host "Optional (torch + stack): .\.venv\Scripts\pip.exe install -r requirements-ml.txt"
