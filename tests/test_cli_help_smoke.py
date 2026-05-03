import subprocess
import sys
from pathlib import Path


def test_detect_script_help_exits_zero():
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "03_run_detection_batch.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    combined = (proc.stdout + proc.stderr).lower()
    assert proc.returncode == 0
    assert "usage:" in combined


def test_prepare_script_help_exits_zero():
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "01_prepare_data.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    combined = (proc.stdout + proc.stderr).lower()
    assert proc.returncode == 0
    assert "usage:" in combined


def _assert_help_ok(script_name: str):
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / script_name
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    combined = (proc.stdout + proc.stderr).lower()
    assert proc.returncode == 0
    assert "usage:" in combined


def test_proxy_ingest_script_help_exits_zero():
    _assert_help_ok("07_ingest_proxy_ndjson.py")


def test_pcap_to_flow_script_help_exits_zero():
    _assert_help_ok("15_pcap_to_flow_csv.py")


def test_header_bytes_script_help_exits_zero():
    _assert_help_ok("16_build_header_byte_dataset.py")
