from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


def _run(cmd: list[str], cwd: Path) -> tuple[int, str, str, float]:
    t0 = time.perf_counter()
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    dt = time.perf_counter() - t0
    return p.returncode, p.stdout, p.stderr, dt


def main() -> None:
    parser = argparse.ArgumentParser(description="Proxy soak runner with incremental ingest evidence.")
    parser.add_argument("--duration-seconds", type=int, default=600)
    parser.add_argument("--tick-seconds", type=int, default=30)
    parser.add_argument("--append-lines-per-tick", type=int, default=50)
    parser.add_argument("--source-ndjson", type=str, default="data/raw/proxy_traffic.ndjson")
    parser.add_argument("--work-ndjson", type=str, default="storage/qa_proxy_soak_stream.ndjson")
    parser.add_argument("--work-csv", type=str, default="storage/qa_proxy_soak.csv")
    parser.add_argument("--work-flows", type=str, default="storage/qa_proxy_soak_flows.csv")
    parser.add_argument("--state-file", type=str, default="storage/qa_proxy_soak_state.json")
    parser.add_argument("--alerts-out", type=str, default="storage/qa_proxy_soak_alerts.json")
    parser.add_argument("--report-out", type=str, default="storage/qa_proxy_soak_report.json")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    src = (root / args.source_ndjson).resolve()
    work = (root / args.work_ndjson).resolve()
    work_csv = (root / args.work_csv).resolve()
    work_flows = (root / args.work_flows).resolve()
    state = (root / args.state_file).resolve()
    alerts = (root / args.alerts_out).resolve()
    report = (root / args.report_out).resolve()

    if not src.is_file():
        raise SystemExit(f"source ndjson not found: {src}")

    lines = src.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise SystemExit("source ndjson is empty")

    for p in (work, work_csv, work_flows, state, alerts):
        if p.exists():
            p.unlink()
    work.parent.mkdir(parents=True, exist_ok=True)
    work.write_text("", encoding="utf-8")

    idx = 0
    ticks = 0
    ingest_ok = 0
    detect_ok = 0
    realtime_ok = 0
    ingest_fail = 0
    detect_fail = 0
    realtime_fail = 0
    exceptions = 0
    alerts_counts: list[int] = []
    ingest_times: list[float] = []
    detect_times: list[float] = []
    rt_times: list[float] = []
    started = time.time()
    deadline = started + max(1, int(args.duration_seconds))

    while time.time() < deadline:
        ticks += 1
        batch = [lines[(idx + i) % len(lines)] for i in range(max(1, int(args.append_lines_per_tick)))]
        idx = (idx + len(batch)) % len(lines)
        with work.open("a", encoding="utf-8") as f:
            f.write("\n".join(batch) + "\n")

        try:
            rc, so, se, dt = _run(
                [
                    sys.executable,
                    "scripts/07_ingest_proxy_ndjson.py",
                    "--ndjson",
                    str(work),
                    "--csv-out",
                    str(work_csv),
                    "--state-file",
                    str(state),
                    "--incremental",
                    "--append",
                ],
                cwd=root,
            )
            ingest_times.append(dt)
            if rc == 0:
                ingest_ok += 1
            else:
                ingest_fail += 1

            rc, so2, se2, _dt2 = _run(
                [
                    sys.executable,
                    "main.py",
                    "ingest-new-data",
                    "--input",
                    str(work_csv),
                    "--prepare-output",
                    str(work_flows),
                ],
                cwd=root,
            )
            # treat prepare failures as ingest failures for soak accounting
            if rc != 0:
                ingest_fail += 1

            rc, so3, se3, dt3 = _run(
                [
                    sys.executable,
                    "scripts/03_run_detection_batch.py",
                    "--data",
                    str(work_flows),
                    "--output-alerts",
                    str(alerts),
                    "--dedup-window-seconds",
                    "30",
                    "--disable-proxy-rules",
                ],
                cwd=root,
            )
            detect_times.append(dt3)
            if rc == 0:
                detect_ok += 1
            else:
                detect_fail += 1

            rc, so4, se4, dt4 = _run(
                [
                    sys.executable,
                    "main.py",
                    "realtime",
                    "--realtime-data",
                    str(work_flows),
                    "--realtime-output-alerts",
                    str(alerts),
                    "--realtime-iterations",
                    "1",
                ],
                cwd=root,
            )
            rt_times.append(dt4)
            if rc == 0:
                realtime_ok += 1
            else:
                realtime_fail += 1

            if alerts.is_file():
                try:
                    payload = json.loads(alerts.read_text(encoding="utf-8"))
                    alerts_counts.append(len(payload) if isinstance(payload, list) else 0)
                except Exception:
                    alerts_counts.append(0)

        except Exception:
            exceptions += 1

        time.sleep(max(0, int(args.tick_seconds)))

    ended = time.time()
    fail_sum = ingest_fail + detect_fail + realtime_fail + exceptions
    report_payload = {
        "started_at": started,
        "ended_at": ended,
        "elapsed_seconds": round(ended - started, 3),
        "ticks": ticks,
        "ingest_ok": ingest_ok,
        "ingest_fail": ingest_fail,
        "detect_ok": detect_ok,
        "detect_fail": detect_fail,
        "realtime_ok": realtime_ok,
        "realtime_fail": realtime_fail,
        "exceptions": exceptions,
        "all_steps_ok": bool(fail_sum == 0 and ticks > 0),
        "failure_events": int(fail_sum),
        "alerts_count_min": min(alerts_counts) if alerts_counts else 0,
        "alerts_count_max": max(alerts_counts) if alerts_counts else 0,
        "alerts_count_last": alerts_counts[-1] if alerts_counts else 0,
        "avg_ingest_seconds": round(sum(ingest_times) / max(len(ingest_times), 1), 4),
        "avg_detect_seconds": round(sum(detect_times) / max(len(detect_times), 1), 4),
        "avg_realtime_seconds": round(sum(rt_times) / max(len(rt_times), 1), 4),
        "silent_loss_detected": bool(ingest_ok > 0 and detect_ok == 0),
    }
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(report_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Proxy soak report: {report}")
    print(json.dumps(report_payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
