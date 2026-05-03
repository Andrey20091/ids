# =============================================================================
# Soak-тест SIEM HTTP: latency spikes / timeout / 5xx / bad payload.
# =============================================================================
"""Run: python scripts/qa_siem_http_soak.py --iterations 120 --timeout 1"""

from __future__ import annotations

import argparse
import json
import os
import runpy
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pandas as pd
import yaml

_bundle = Path(__file__).resolve().parents[1]
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle

from src.features.feature_config import load_merged_feature_config
from src.utils.flows_io import read_flows_csv


class _State:
    req_count = 0
    mode_counts: dict[str, int] = {"ok": 0, "slow": 0, "http_500": 0, "bad_payload": 0}


class _QuietHTTPServer(HTTPServer):
    def handle_error(self, _request, _client_address):
        # В soak timeout клиента ожидаем; suppress noisy stacktrace.
        return


class _Handler(BaseHTTPRequestHandler):
    server_version = "ids-qa-siem-http/1.0"
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802
        _State.req_count += 1
        mode = self._mode_from_path(self.path, _State.req_count)
        _State.mode_counts[mode] = _State.mode_counts.get(mode, 0) + 1

        if mode == "slow":
            # Таймаут на клиенте (обычно timeout=1), сервер потом всё равно отвечает.
            time.sleep(2.5)

        if mode == "http_500":
            body = b'{"error":"siem backend failure"}'
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass
            return

        if mode == "bad_payload":
            body = b'{"unexpected":"shape"}'
        else:
            body = json.dumps(
                [
                    {"ip": "10.0.0.5", "event_type": "failed_login", "timestamp": "2026-01-01T00:00:00Z"},
                    {"client_ip": "10.0.0.7", "evt": "config_change", "timestamp": "2026-01-01T00:01:00Z"},
                ]
            ).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, _fmt, *_args):  # noqa: D401
        return

    @staticmethod
    def _mode_from_path(path: str, idx: int) -> str:
        # Детерминированный цикл деградаций.
        if "mode=ok" in path:
            return "ok"
        cycle = idx % 10
        if cycle in (1, 2, 3, 4, 5):
            return "ok"
        if cycle == 6:
            return "slow"
        if cycle == 7:
            return "http_500"
        if cycle == 8:
            return "bad_payload"
        return "ok"


def _start_server(port: int) -> HTTPServer:
    srv = _QuietHTTPServer(("127.0.0.1", port), _Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--iterations", type=int, default=120)
    p.add_argument("--timeout", type=int, default=1)
    p.add_argument("--port", type=int, default=8877)
    p.add_argument("--detect-every", type=int, default=10, help="Run detect component each N iterations")
    args = p.parse_args()

    server = _start_server(args.port)
    base_url = f"http://127.0.0.1:{args.port}/events"

    module = runpy.run_path(str(_ROOT / "scripts" / "03_run_detection_batch.py"))
    load_siem = module["_load_siem"]
    run_detect_df = module["run_detection_on_dataframe"]

    with open(_ROOT / "config/settings.yaml", encoding="utf-8") as f:
        settings = yaml.safe_load(f) or {}
    feat_cfg = load_merged_feature_config(_ROOT / "config/feature_columns.yaml")
    # Малый in-memory фрейм для detect smoke при деградации SIEM.
    flows = read_flows_csv(
        _ROOT / "data/processed/flows.csv",
        row_limit=500,
        parquet_cache=False,
        csv_engine=None,
    )
    settings_local = dict(settings)
    settings_local["siem"] = {
        "source": "http",
        "http_url": base_url,
        "timeout_seconds": int(args.timeout),
        "retries": 1,
        "retry_backoff_seconds": 0.05,
    }

    ok_loads = 0
    empty_loads = 0
    errors = 0
    detect_runs = 0
    detect_errors = 0
    t0 = time.perf_counter()

    try:
        for i in range(1, int(args.iterations) + 1):
            try:
                df = load_siem(settings_local)
                if len(df) > 0:
                    ok_loads += 1
                else:
                    empty_loads += 1
            except Exception:
                errors += 1

            if args.detect_every > 0 and i % int(args.detect_every) == 0:
                detect_runs += 1
                try:
                    _ = run_detect_df(
                        flows,
                        settings=settings_local,
                        feat_cfg=feat_cfg,
                        no_lstm=False,
                        no_embedding=False,
                    )
                except Exception:
                    detect_errors += 1
    finally:
        server.shutdown()
        server.server_close()

    elapsed = time.perf_counter() - t0
    out = {
        "iterations": int(args.iterations),
        "siem_http_timeout_seconds": int(args.timeout),
        "ok_loads": ok_loads,
        "empty_or_fallback_loads": empty_loads,
        "loader_exceptions": errors,
        "detect_runs": detect_runs,
        "detect_exceptions": detect_errors,
        "server_mode_counts": _State.mode_counts,
        "elapsed_seconds": round(elapsed, 3),
    }
    out_path = _ROOT / "storage" / "qa_siem_http_soak_report.json"
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"Saved soak report: {out_path}")


if __name__ == "__main__":
    main()
