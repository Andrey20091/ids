from __future__ import annotations

import argparse
import json
import runpy
import sys
import time
import warnings
from io import StringIO
from pathlib import Path

import pandas as pd

_bundle = Path(__file__).resolve().parents[1]
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

from src.features.feature_config import load_merged_feature_config
from src.utils_config import load_settings, project_root

_ROOT = project_root()


def _load_detection_callable():
    module = runpy.run_path(str(_bundle / "scripts" / "03_run_detection_batch.py"))
    return module["run_detection_on_dataframe"]


def _read_appended_csv_rows(
    data_path: Path,
    *,
    last_pos: int,
    columns: list[str] | None,
) -> tuple[pd.DataFrame, int, list[str] | None]:
    if not data_path.is_file():
        return pd.DataFrame(), 0, columns
    cur_size = data_path.stat().st_size
    if cur_size < last_pos:
        last_pos = 0
        columns = None
    with open(data_path, "rb") as f:
        f.seek(last_pos)
        payload = f.read()
    new_pos = last_pos + len(payload)
    if not payload:
        return pd.DataFrame(), new_pos, columns
    text = payload.decode("utf-8", errors="replace")
    if columns is None:
        try:
            df = pd.read_csv(StringIO(text))
        except Exception as e:
            warnings.warn(
                f"Realtime parser: failed to read initial CSV chunk; waiting for next append ({e})",
                UserWarning,
                stacklevel=2,
            )
            return pd.DataFrame(), last_pos, columns
        return df, new_pos, list(df.columns)
    body = text.lstrip("\r\n")
    if not body.strip():
        return pd.DataFrame(columns=columns), new_pos, columns
    try:
        if body.startswith(",".join(columns)):
            df = pd.read_csv(StringIO(body))
            return df, new_pos, list(df.columns)
        df = pd.read_csv(StringIO(body), header=None, names=columns)
        return df, new_pos, columns
    except Exception as e:
        warnings.warn(
            f"Realtime parser: failed to parse appended chunk; waiting for next append ({e})",
            UserWarning,
            stacklevel=2,
        )
        return pd.DataFrame(columns=columns), last_pos, columns


def main() -> None:
    parser = argparse.ArgumentParser(description="Near-realtime IDS loop over appended flows.csv")
    parser.add_argument("--data", type=str, default=str(_ROOT / "data/processed/flows.csv"))
    parser.add_argument("--output-alerts", type=str, default=str(_ROOT / "storage/alerts_latest.json"))
    parser.add_argument("--max-alerts", type=int, default=200)
    parser.add_argument("--iterations", type=int, default=0, help="0 = infinite loop")
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=None,
        help="Override realtime.poll_interval_seconds from settings.yaml.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help="Override realtime.batch_size from settings.yaml.",
    )
    parser.add_argument(
        "--features-yaml",
        type=str,
        default=str(_ROOT / "config/feature_columns.yaml"),
        help="Path to feature_columns.yaml (loaded with canonical merged config).",
    )
    parser.add_argument(
        "--auto-online-retrain",
        action="store_true",
        help="Also run one online retrain iteration periodically during realtime loop.",
    )
    parser.add_argument(
        "--auto-online-every-iters",
        type=int,
        default=1,
        help="When --auto-online-retrain is enabled, run retrain every N loop iterations.",
    )
    args = parser.parse_args()

    settings = load_settings()
    feat_cfg = load_merged_feature_config(args.features_yaml)

    poll_seconds = (
        int(args.poll_seconds)
        if args.poll_seconds is not None
        else int(settings.get("realtime", {}).get("poll_interval_seconds", 15))
    )
    batch_size = (
        int(args.batch_size)
        if args.batch_size is not None
        else int(settings.get("realtime", {}).get("batch_size", 512))
    )
    auto_retrain_every = max(1, int(args.auto_online_every_iters))
    detect_fn = _load_detection_callable()
    retrain_fn = None
    if args.auto_online_retrain:
        from src.online.retrain_scheduler import run_one_retrain_iteration

        retrain_fn = run_one_retrain_iteration

    data_path = Path(args.data)
    outp = Path(args.output_alerts)
    outp.parent.mkdir(parents=True, exist_ok=True)

    file_pos = 0
    csv_columns: list[str] | None = None
    pending_df = pd.DataFrame()
    all_alerts: list[dict] = []
    it = 0

    while args.iterations == 0 or it < args.iterations:
        if not data_path.is_file():
            file_pos = 0
            csv_columns = None
            pending_df = pd.DataFrame()
            time.sleep(poll_seconds)
            continue

        appended, file_pos, csv_columns = _read_appended_csv_rows(data_path, last_pos=file_pos, columns=csv_columns)
        if not appended.empty:
            pending_df = appended if pending_df.empty else pd.concat([pending_df, appended], ignore_index=True)
        if not pending_df.empty:
            chunk = pending_df.iloc[:batch_size].copy()
            pending_df = pending_df.iloc[batch_size:].reset_index(drop=True)
            alerts = detect_fn(chunk, settings=settings, feat_cfg=feat_cfg)
            all_alerts.extend(alerts)
            all_alerts = all_alerts[-args.max_alerts :]
            with open(outp, "w", encoding="utf-8") as f:
                json.dump(all_alerts, f, ensure_ascii=False, indent=2)
            print(
                f"Realtime: processed {len(chunk)} rows, pending={len(pending_df)}, total alerts in file: {len(all_alerts)}"
            )
        if retrain_fn is not None and ((it + 1) % auto_retrain_every == 0):
            try:
                retrain_result = retrain_fn(data_path)
                print(f"Realtime: online retrain result: {retrain_result}")
            except Exception as e:
                print(f"Предупреждение: auto online retrain failed ({e}); продолжаем realtime detect.")
        it += 1
        time.sleep(poll_seconds)


if __name__ == "__main__":
    main()
