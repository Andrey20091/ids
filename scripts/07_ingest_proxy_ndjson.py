# =============================================================================
# Скрипт 07: NDJSON прокси → CSV в формате, совместимом с 01_prepare_data.py.
# =============================================================================
"""Перевод записей прокси в широкий CICIDS-подобный CSV (метки BENIGN по умолчанию)."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

# Те же имена колонок, что в scripts/00_generate_demo_data.py (минимум для enrich + yaml)
_COLS = [
    "Timestamp",
    "Source IP",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Max",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "FIN Flag Count",
    "RST Flag Count",
    "Protocol",
    "Destination Port",
    "http_request_uri",
    "dns_qname",
    "Label",
]


def _record_to_row(r: dict) -> dict[str, str]:
    ts = r.get("ts", 0)
    if isinstance(ts, (int, float)):
        ts_str = datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    else:
        ts_str = str(ts)

    dur_s = max(float(r.get("duration_ms", 0)) / 1000.0, 1e-6)
    b_up = int(r.get("bytes_up", 0) or 0)
    b_down = int(r.get("bytes_down", 0) or 0)
    total_b = b_up + b_down

    fwd_pkts = max(1, b_up // 512) if b_up else 1
    bwd_pkts = max(0, b_down // 512)

    flow_bytes_s = min(float(total_b) / dur_s, 1e9)
    flow_pkts_s = min(float(fwd_pkts + bwd_pkts) / dur_s, 1e6)

    host = str(r.get("host", "") or "unknown")
    port = int(r.get("port", 443) or 443)
    path = str(r.get("path", "") or "")
    scheme = str(r.get("scheme", "https") or "https")
    method = str(r.get("method", "") or "CONNECT")

    if path and not path.startswith("/"):
        path = "/" + path
    if method.upper() == "CONNECT" and not path:
        uri = f"{scheme}://{host}:{port}/"
    else:
        uri = f"{scheme}://{host}:{port}{path or '/'}"

    syn = 1 if method.upper() == "CONNECT" else 0
    fin = 1 if int(r.get("status", 0) or 0) in (200, 204) else 0
    rst = 1 if "error" in r else 0

    fmax = str(min(1500, max(b_up, 64)))
    fmin = str(min(100, max(b_up // max(fwd_pkts, 1), 0)))
    fmean = str(float(b_up) / max(fwd_pkts, 1))
    bmax = str(min(1500, max(b_down, 0)))

    return {
        "Timestamp": ts_str,
        "Source IP": str(r.get("client_ip", "0.0.0.0")),
        "Flow Duration": f"{dur_s:.6f}",
        "Total Fwd Packets": str(fwd_pkts),
        "Total Backward Packets": str(bwd_pkts),
        "Fwd Packet Length Max": fmax,
        "Fwd Packet Length Min": fmin,
        "Fwd Packet Length Mean": fmean,
        "Bwd Packet Length Max": bmax,
        "Flow Bytes/s": f"{flow_bytes_s:.6f}",
        "Flow Packets/s": f"{flow_pkts_s:.6f}",
        "SYN Flag Count": str(syn),
        "FIN Flag Count": str(fin),
        "RST Flag Count": str(rst),
        "Protocol": "6",
        "Destination Port": str(port),
        "http_request_uri": uri,
        "dns_qname": host if "." in host else f"{host}.local",
        "Label": "BENIGN",
    }


def main() -> None:
    from src.utils.console_encoding import configure_stdio_utf8

    configure_stdio_utf8()
    parser = argparse.ArgumentParser(description="NDJSON proxy -> CSV for prepare")
    parser.add_argument(
        "--ndjson",
        type=str,
        default=str(_ROOT / "data/raw/proxy_traffic.ndjson"),
        help="Входной NDJSON (по строке на JSON-объект)",
    )
    parser.add_argument(
        "--csv-out",
        type=str,
        default=str(_ROOT / "data/raw/proxy_cicids_like.csv"),
        help="Выходной CSV",
    )
    parser.add_argument(
        "--state-file",
        type=str,
        default="",
        help="Путь к JSON checkpoint (byte offset) для инкрементального чтения NDJSON",
    )
    parser.add_argument(
        "--incremental",
        action="store_true",
        help="Обрабатывать только новые строки NDJSON от сохранённого offset",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Добавлять строки в существующий CSV (вместо полной перезаписи)",
    )
    args = parser.parse_args()

    src = Path(args.ndjson)
    if not src.is_absolute():
        src = _ROOT / src
    dst = Path(args.csv_out)
    if not dst.is_absolute():
        dst = _ROOT / dst

    if not src.is_file():
        raise SystemExit(f"Файл не найден: {src}")

    state_path: Path | None = None
    prev_offset = 0
    if args.state_file:
        state_path = Path(args.state_file)
        if not state_path.is_absolute():
            state_path = _ROOT / state_path
        if args.incremental and state_path.is_file():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
                prev_offset = int(state.get("offset", 0) or 0)
            except Exception:
                prev_offset = 0

    rows: list[dict[str, str]] = []
    counters = {
        "processed_lines": 0,
        "valid_records": 0,
        "empty_lines": 0,
        "invalid_json": 0,
        "invalid_type": 0,
        "missing_required_fields": 0,
    }
    final_offset = prev_offset
    with open(src, encoding="utf-8") as f:
        if args.incremental and prev_offset > 0:
            try:
                f.seek(prev_offset)
            except OSError:
                prev_offset = 0
                f.seek(0)
        for raw_line in f:
            counters["processed_lines"] += 1
            line = raw_line.strip()
            if not line:
                counters["empty_lines"] += 1
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                counters["invalid_json"] += 1
                continue
            if not isinstance(rec, dict):
                counters["invalid_type"] += 1
                continue
            if any(k not in rec for k in ("ts", "client_ip", "host")):
                counters["missing_required_fields"] += 1
                continue
            rows.append(_record_to_row(rec))
            counters["valid_records"] += 1
        final_offset = f.tell()

    if not rows:
        print(
            "No new valid proxy records.",
            f"processed={counters['processed_lines']}",
            f"invalid_json={counters['invalid_json']}",
            f"invalid_type={counters['invalid_type']}",
            f"missing_required={counters['missing_required_fields']}",
        )
        if state_path is not None and args.incremental:
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(
                json.dumps({"offset": final_offset, "source": str(src)}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        raise SystemExit(0 if args.incremental else "Нет валидных записей в NDJSON — сначала соберите трафик через прокси.")

    dst.parent.mkdir(parents=True, exist_ok=True)
    write_mode = "a" if args.append and dst.exists() else "w"
    need_header = write_mode == "w" or dst.stat().st_size == 0
    with open(dst, write_mode, newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_COLS)
        if need_header:
            w.writeheader()
        w.writerows(rows)
    if state_path is not None and args.incremental:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(
            json.dumps({"offset": final_offset, "source": str(src)}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    print(
        f"Wrote {len(rows)} rows to {dst}",
        f"processed={counters['processed_lines']}",
        f"invalid_json={counters['invalid_json']}",
        f"invalid_type={counters['invalid_type']}",
        f"missing_required={counters['missing_required_fields']}",
        f"incremental={bool(args.incremental)}",
    )


if __name__ == "__main__":
    main()
