# =============================================================================
# Скрипт 01: сырой CICIDS/демо CSV → data/processed/flows.csv
# Кейс 4: HTTP, DNS, hdr_*; опционально hb_* из PCAP (сырые байты заголовков).
# =============================================================================
"""Raw CICIDS CSV -> processed CSV with numeric features + is_attack."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

import numpy as np
import pandas as pd

from src.features.case_enrichment import enrich_case4_features
from src.features.feature_config import header_byte_columns, load_merged_feature_config
from src.features.flow_key import flow_key_series
from src.ingest.cicids2017 import ensure_flow_schema_for_ml, normalize_cicids2017_dataframe
from src.online.buffer_rotation import increment_rotation_generation
from src.utils.pipeline_validate import validate_prepared_flows
from src.utils_config import load_settings, resolve_from_project_root


def _rotate_file_backups(path: Path, max_backups: int) -> None:
    max_backups = max(1, int(max_backups or 1))
    oldest = path.with_name(f"{path.name}.{max_backups}")
    if oldest.exists():
        oldest.unlink()
    for idx in range(max_backups - 1, 0, -1):
        src = path.with_name(f"{path.name}.{idx}")
        dst = path.with_name(f"{path.name}.{idx + 1}")
        if src.exists():
            src.replace(dst)
    if path.exists():
        path.replace(path.with_name(f"{path.name}.1"))


def _maybe_rotate_online_buffer(out_path: Path, *, append_output: bool) -> None:
    if not append_output or not out_path.exists():
        return
    try:
        settings = load_settings()
        online_buf = resolve_from_project_root(
            (settings.get("paths", {}) or {}).get("flows_online_buffer", "data/processed/flows_online_buffer.csv")
        ).resolve()
        if out_path.resolve() != online_buf:
            return
        buf_cfg = settings.get("buffering", {}) or {}
        max_mb = int(buf_cfg.get("flows_online_rotation_max_mb", 0) or 0)
        backups = int(buf_cfg.get("flows_online_rotation_backups", 3) or 3)
        if max_mb <= 0:
            return
        if out_path.stat().st_size < max_mb * 1024 * 1024:
            return
        _rotate_file_backups(out_path, max_backups=backups)
        try:
            increment_rotation_generation(out_path.resolve())
        except Exception as e:
            print(f"Предупреждение: не удалось обновить meta generation буфера ({e})")
        print(f"Online buffer rotated: {out_path} (max_mb={max_mb}, backups={backups})")
    except Exception as e:
        print(f"Предупреждение: не удалось выполнить ротацию online buffer ({e})")


def main() -> None:
    """Чтение CSV, обогащение признаками кейса 4, выбор колонок, сохранение flows.csv."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, required=True, help="Path to CICIDS CSV")
    parser.add_argument("--output", type=str, default=str(_ROOT / "data/processed/flows.csv"))
    parser.add_argument(
        "--features-yaml",
        type=str,
        default=str(_ROOT / "config/feature_columns.yaml"),
    )
    parser.add_argument(
        "--no-cicids-normalize",
        action="store_true",
        help="Не нормализовать имена колонок CICIDS2017 (BOM/пробелы/label->Label).",
    )
    parser.add_argument(
        "--header-bytes-npz",
        type=str,
        default="",
        help="NPZ с ключом X (n_rows, D) в том же порядке строк, что и --input, D = hb_ признаков",
    )
    parser.add_argument(
        "--pcap-enrichment",
        type=str,
        default="",
        help="Доп. признаки DNS/HTTP plaintext из PCAP (без TLS decryption), merge по flow_key.",
    )
    parser.add_argument(
        "--allow-missing-columns",
        action="store_true",
        help="Compatibility mode: allow missing critical input columns (fills may degrade quality).",
    )
    parser.add_argument(
        "--append-output",
        action="store_true",
        help="Append rows to existing output CSV with strict schema check (header is not duplicated).",
    )
    args = parser.parse_args()

    feat_cfg = load_merged_feature_config(args.features_yaml)

    inp = Path(args.input)
    if not inp.is_file():
        raise SystemExit(f"Файл не найден: {inp.resolve()}")

    try:
        # Читаем строго как UTF-8: файлы в иной кодировке (например UTF-16) должны падать
        # с понятной диагностикой, а не приводить к «тихой» порче колонок.
        df = pd.read_csv(args.input, encoding="utf-8", low_memory=False)
    except UnicodeDecodeError as e:
        raise SystemExit(
            "Не удалось прочитать CSV в UTF-8. "
            "Преобразуйте файл в UTF-8 (без BOM) и повторите prepare."
        ) from e
    except pd.errors.EmptyDataError as e:
        raise SystemExit("CSV пустой — нечего обрабатывать.") from e
    if df.empty:
        raise SystemExit("CSV пустой — нечего обрабатывать.")
    if not args.no_cicids_normalize:
        df = normalize_cicids2017_dataframe(df)
    label_col = str(feat_cfg.get("label_column", "Label"))
    ts_col_cfg = str(feat_cfg.get("timestamp_column", "Timestamp"))
    cat_cfg = feat_cfg.get("categorical_for_embedding", {}) or {}
    proto_col_cfg = str(cat_cfg.get("protocol_column", "Protocol"))
    port_col_cfg = str(cat_cfg.get("port_column", "Destination Port"))
    critical_candidates = [
        "Source IP",
        label_col,
        ts_col_cfg,
        proto_col_cfg,
        port_col_cfg,
    ]
    critical_cols = [c for c in dict.fromkeys(critical_candidates) if c]
    missing_critical = [c for c in critical_cols if c not in df.columns]
    if missing_critical and not args.allow_missing_columns:
        raise SystemExit(
            "Критичные входные колонки отсутствуют: "
            + ", ".join(missing_critical)
            + ".\nИсправьте входной CSV/маппинг колонок или используйте --allow-missing-columns "
            "для режима совместимости (не рекомендуется для production)."
        )
    if missing_critical and args.allow_missing_columns:
        print(
            "Предупреждение: missing critical columns (compat mode enabled): "
            + ", ".join(missing_critical)
        )
    df = ensure_flow_schema_for_ml(df, feat_cfg)
    df = enrich_case4_features(df)
    df["flow_key"] = flow_key_series(df)

    pcap_enr = str(args.pcap_enrichment).strip()
    if pcap_enr:
        pp = Path(pcap_enr)
        pp = (_ROOT / pp) if not pp.is_absolute() else pp
        if pp.is_file():
            from src.ingest.pcap_plaintext_features import (
                collect_plaintext_flow_stats,
                merge_plaintext_stats_into_df,
            )

            stats = collect_plaintext_flow_stats(pp)
            df = merge_plaintext_stats_into_df(df, stats)
            print(f"PCAP plaintext enrichment: {pp} ({len(stats)} keys matched ad hoc)")
        else:
            print(f"Предупреждение: --pcap-enrichment файл не найден: {pp}")

    hb_cols = header_byte_columns(feat_cfg)
    hb_missing = [c for c in hb_cols if c not in df.columns]
    if hb_missing:
        df = pd.concat([df, pd.DataFrame({c: 0.0 for c in hb_missing}, index=df.index)], axis=1)
    if args.header_bytes_npz:
        npz_path = Path(args.header_bytes_npz)
        if not npz_path.is_file():
            raise SystemExit(f"Нет NPZ: {npz_path}")
        blob = np.load(npz_path)
        Xb = np.asarray(blob["X"])
        if Xb.shape[0] != len(df):
            raise SystemExit(
                f"header_bytes: ожидалось {len(df)} строк, в NPZ {Xb.shape[0]} — тот же CSV что для16_build..."
            )
        if Xb.shape[1] != len(hb_cols):
            raise SystemExit(f"header_bytes: X.shape[1]={Xb.shape[1]}, ожидалось {len(hb_cols)} hb признаков")
        for j, c in enumerate(hb_cols):
            df[c] = Xb[:, j].astype(np.float32) / 255.0

    label_col = feat_cfg.get("label_column", "Label")
    expected_num = feat_cfg.get("numeric_features", [])
    num_cols = [c for c in expected_num if c in df.columns]
    missing_num = [c for c in expected_num if c not in df.columns]
    if missing_num:
        print(
            "Предупреждение: в данных нет части numeric_features:",
            ", ".join(missing_num[:16]) + ("..." if len(missing_num) > 16 else ""),
            "\n  Проверьте генерацию CSV и config/feature_columns.yaml.",
            sep="",
        )
    if not num_cols:
        raise SystemExit(
            "Ни одна числовая колонка из feature_columns.yaml не найдена после обогащения. "
            "Исправьте имена в config/feature_columns.yaml или расширьте входной CSV."
        )
    if label_col not in df.columns:
        raise SystemExit(
            f"Колонка меток «{label_col}» не найдена в CSV. Задайте label_column в feature_columns.yaml."
        )
    cat_cols = []
    for key in ("protocol_column", "port_column"):
        col = feat_cfg.get("categorical_for_embedding", {}).get(key)
        if col and col in df.columns:
            cat_cols.append(col)

    ts_col = feat_cfg.get("timestamp_column")
    ts_extra = [ts_col] if ts_col and ts_col in df.columns and ts_col not in num_cols + cat_cols else []

    seen = set(ts_extra + num_cols + cat_cols)
    wanted_ctx = feat_cfg.get("context_columns", [])
    ctx_cols = [c for c in wanted_ctx if c in df.columns and c not in seen]
    seen.update(ctx_cols)
    for c in wanted_ctx:
        if c not in df.columns:
            print(
                f"Предупреждение: context_columns содержит «{c}», но такой колонки нет в CSV — "
                "в алертах будет подставляться синтетический IP."
            )

    ts_name = feat_cfg.get("timestamp_column")
    if ts_name and ts_name not in df.columns:
        print(
            f"Предупреждение: timestamp_column «{ts_name}» не найден — L1 по времени и сортировка LSTM недоступны."
        )

    use = (
        ts_extra
        + num_cols
        + cat_cols
        + ctx_cols
        + ["flow_key"]
        + ([label_col] if label_col in df.columns else [])
    )
    out = df[use].copy()
    if label_col in out.columns:
        out["is_attack"] = (
            out[label_col].astype(str).str.upper().ne("BENIGN").astype(int)
        )
    for msg in validate_prepared_flows(out, feat_cfg):
        print(f"Предупреждение (инварианты данных): {msg}")
    outp = Path(args.output)
    out_path = outp if outp.is_absolute() else _ROOT / outp
    out_path.parent.mkdir(parents=True, exist_ok=True)
    _maybe_rotate_online_buffer(out_path, append_output=bool(args.append_output))
    if args.append_output and out_path.exists():
        try:
            with open(out_path, encoding="utf-8", newline="") as ef:
                header_line = ef.readline()
            if not header_line:
                raise ValueError("existing output is empty")
            import csv as _csv

            existing_cols = next(_csv.reader([header_line.rstrip("\r\n")]))
        except Exception as e:
            raise SystemExit(f"Не удалось прочитать заголовок существующего output CSV для append: {e}") from e
        new_cols = out.columns.tolist()
        if existing_cols != new_cols:
            raise SystemExit(
                "Append output schema mismatch:\n"
                f"  existing={existing_cols[:12]}{'...' if len(existing_cols) > 12 else ''}\n"
                f"  new={new_cols[:12]}{'...' if len(new_cols) > 12 else ''}\n"
                "Используйте другой --output или отключите --append-output."
            )
        out.to_csv(out_path, mode="a", header=False, index=False)
    else:
        out.to_csv(out_path, index=False)
    print(f"Wrote {out_path} with shape {out.shape}")


if __name__ == "__main__":
    main()
