# Full TZ example: Friday PCAP + TrafficLabelling + hb_* + train + detect.
# From repo root: powershell -ExecutionPolicy Bypass -File scripts/run_full_tz_friday_example.ps1
# (ASCII-only script text so Windows PowerShell 5.1 parses without UTF-8 BOM.)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

Set-Location $root

& $py main.py bootstrap

& $py scripts/17_build_cicids_training_slice.py `
  --benign-csv TrafficLabelling/Friday-WorkingHours-Morning.pcap_ISCX.csv `
  --benign-rows 22000 `
  --attack-csvs Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv `
  --attack-rows-each 5000 `
  --output data/raw/cicids2017/cicids2017_friday_pcap_aligned.csv

# Smaller --max-pcap-packets speeds huge PCAP; 0 = read full pcap.
& $py scripts/16_build_header_byte_dataset.py `
  --pcap Friday-WorkingHours.pcap `
  --flows-csv data/raw/cicids2017/cicids2017_friday_pcap_aligned.csv `
  --output data/processed/header_bytes.npz `
  --max-pcap-packets 400000

& $py main.py prepare --input data/raw/cicids2017/cicids2017_friday_pcap_aligned.csv --header-bytes-npz data/processed/header_bytes.npz
& $py main.py train
& $py main.py detect

Write-Host "Done. Alerts: storage/alerts_latest.json"
