# =============================================================================
# Скрипт 03: пакетная детекция L1→L2 (RF, AE, LSTM, embedding) + SIEM-скоринг.
# =============================================================================
"""Offline batch detection demo: L1 aggregation → L2 models + optional SIEM scoring."""

from __future__ import annotations

import argparse
import collections
import json
import math
import sys
import time
import warnings
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

import pandas as pd

from src.features.feature_config import load_merged_feature_config
from src.utils.flows_io import read_flows_csv
from src.utils.model_health import json_write, train_reports_dir, ts_token
from src.utils_config import load_settings, project_root, resolve_from_project_root

_ROOT = project_root()


def _detect_incremental_load(path: Path) -> dict:
    if not path.is_file():
        return {"paths": {}}
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {"paths": {}}
    except Exception:
        return {"paths": {}}


def _detect_incremental_save(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _numeric_feature_frame(df: pd.DataFrame, num_cols: list[str]) -> pd.DataFrame:
    """Один проход: числовая матрица для L2 (совпадает по индексу с df)."""
    return df[num_cols].apply(pd.to_numeric, errors="coerce").fillna(0)


def _network_score(row: pd.Series) -> float:
    """Агрегированная оценка угрозы по выходам L2 (взвешенный blend без насыщения max=1.0)."""
    rf = float(row.get("l2_rf_attack_score", 0.0))
    lstm = float(row.get("l2_lstm_attack_score", 0.0))
    lstm_pkt = float(row.get("l2_lstm_pkt_score", 0.0))
    emb = float(row.get("l2_emb_attack_score", 0.0))
    hdr = float(row.get("l2_hdr_cnn_attack_score", 0.0))
    ae_ratio = max(0.0, float(row.get("l2_ae_ratio", 0.0)))
    # AE ratio -> [0,1): экспоненциальная нормализация снижает «плато» после порога.
    ae = 1.0 - math.exp(-ae_ratio / 3.0)
    score = (
        0.34 * rf
        + 0.10 * lstm
        + 0.06 * lstm_pkt
        + 0.11 * emb
        + 0.20 * ae
        + 0.14 * hdr
    )
    # Небольшой штраф за «полное насыщение» нескольких каналов одновременно.
    if rf >= 0.999 and emb >= 0.999 and ae >= 0.98:
        score -= 0.08
    score = max(0.0, min(1.0, score))
    return score


def _proxy_effective_flow_rates(row_src: pd.Series) -> tuple[float, float]:
    """
    Canonical proxy CSV uses Flow Packets/s and Flow Bytes/s; prepared exports may only
    keep Fwd/Bwd Packets/s and Total Length * (CICIDS names). Prefer explicit columns when present.
    """
    idx = row_src.index
    if "Flow Packets/s" in idx:
        pps = float(row_src.get("Flow Packets/s", 0.0) or 0.0)
    else:
        pps = float(row_src.get("Fwd Packets/s", 0.0) or 0.0) + float(
            row_src.get("Bwd Packets/s", 0.0) or 0.0
        )
    if "Flow Bytes/s" in idx:
        bps = float(row_src.get("Flow Bytes/s", 0.0) or 0.0)
    else:
        t_fwd = float(row_src.get("Total Length of Fwd Packets", 0.0) or 0.0)
        t_bwd = float(row_src.get("Total Length of Bwd Packets", 0.0) or 0.0)
        dur = float(row_src.get("Flow Duration", 0.0) or 0.0)
        bps = (t_fwd + t_bwd) / dur if dur > 1e-9 else 0.0
    return pps, bps


def _proxy_rule_signals(row_src: pd.Series) -> tuple[list[str], float]:
    """Lightweight proxy heuristics: return triggered rules and additive score boost."""
    rules: list[str] = []
    flow_pps, flow_bps = _proxy_effective_flow_rates(row_src)
    syn_cnt = float(row_src.get("SYN Flag Count", 0.0) or 0.0)
    rst_cnt = float(row_src.get("RST Flag Count", 0.0) or 0.0)
    dst_port = int(float(row_src.get("Destination Port", 0.0) or 0.0))
    uri = str(row_src.get("http_request_uri", "") or "").lower()

    # Пороги чуть выше «типичного» браузерного трафика, чтобы снизить шум на демо-данных.
    if flow_pps > 400:
        rules.append("high_packet_rate")
    if flow_bps > 350_000:
        rules.append("high_byte_rate")
    if syn_cnt >= 1 and rst_cnt >= 1:
        rules.append("syn_rst_combo")
    if dst_port not in (80, 443, 53) and dst_port > 0:
        rules.append("unusual_destination_port")
    if any(x in uri for x in ("/admin", "/wp-login", "/.env", "/login", "/phpmyadmin")):
        rules.append("suspicious_uri_pattern")

    per_rule = 0.035
    cap = 0.16
    return rules, min(cap, per_rule * len(rules))


def _severity_from_score(score: float) -> str:
    if score >= 90:
        return "Emergency"
    if score >= 80:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 50:
        return "Medium"
    if score >= 30:
        return "Low"
    return "Info"


def _should_alert(row: pd.Series, gate_on_l1: bool) -> bool:
    """Пороги алертов по подсистемам L2 (настраиваемые эвристики)."""
    if gate_on_l1 and not bool(row.get("l1_triggered", True)):
        return False
    rf = float(row.get("l2_rf_attack_score", 0.0))
    lstm = float(row.get("l2_lstm_attack_score", 0.0))
    emb = float(row.get("l2_emb_attack_score", 0.0))
    hdr = float(row.get("l2_hdr_cnn_attack_score", 0.0))
    lstm_pkt = float(row.get("l2_lstm_pkt_score", 0.0))
    ae = float(row.get("l2_ae_ratio", 0.0))
    return (
        rf >= 0.5
        or lstm >= 0.5
        or lstm_pkt >= 0.5
        or ae >= 1.5
        or emb >= 0.5
        or hdr >= 0.5
    )


def _packet_lstm_scores_from_npz(df: pd.DataFrame, npz_path: Path) -> pd.Series | None:
    """Скоры по ключу потока из NPZ (scripts/21_train_packet_lstm или ручной infer)."""
    if not npz_path.is_file():
        return None
    import numpy as np

    from src.features.flow_key import flow_key_series

    blob = np.load(npz_path, allow_pickle=True)
    fk_df = df["flow_key"].astype(str) if "flow_key" in df.columns else flow_key_series(df)
    keys_arr = blob["flow_keys"].astype(str)
    sc_arr = blob["scores"].astype(float)
    m = dict(zip(keys_arr.tolist(), sc_arr.tolist()))
    return fk_df.map(lambda k: float(m.get(str(k), 0.0)))


def _load_siem(settings: dict) -> pd.DataFrame:
    from src.correlation.siem_loader import (
        load_siem_events,
        load_siem_events_http,
        load_siem_events_ndjson,
    )

    siem_cfg = settings.get("siem", {})
    source = str(siem_cfg.get("source", "json_file")).lower().strip()
    try:
        if source == "http":
            return load_siem_events_http(
                siem_cfg.get("http_url", ""),
                timeout_seconds=int(siem_cfg.get("timeout_seconds", 5)),
                retries=int(siem_cfg.get("retries", 0)),
                retry_backoff_seconds=float(siem_cfg.get("retry_backoff_seconds", 0.2)),
            )
        if source == "ndjson_file":
            nd_path = siem_cfg.get("ndjson_path") or settings["paths"].get(
                "siem_events_ndjson", "storage/siem_events_sample.ndjson"
            )
            sp = resolve_from_project_root(nd_path)
            return load_siem_events_ndjson(sp) if sp.is_file() else pd.DataFrame()
        siem_path = resolve_from_project_root(settings["paths"]["siem_events"])
        return load_siem_events(siem_path) if Path(siem_path).is_file() else pd.DataFrame()
    except Exception as e:
        print(f"Предупреждение: SIEM источник недоступен ({e}), продолжаем без SIEM-корреляции.")
        return pd.DataFrame()


def run_detection_on_dataframe(
    df: pd.DataFrame,
    settings: dict,
    feat_cfg: dict,
    no_lstm: bool = False,
    no_embedding: bool = False,
    l2_only_after_l1: bool | None = None,
    packet_lstm_scores_npz: str | None = None,
    demo_preset: bool = False,
    enable_proxy_rules: bool = True,
    dedup_window_seconds: int = 0,
) -> list[dict]:
    """Прогон L1→L2 + SIEM-корреляции для уже загруженного DataFrame."""
    ts_col = feat_cfg.get("timestamp_column")
    num_cols = [c for c in feat_cfg.get("numeric_features", []) if c in df.columns]
    if not num_cols:
        raise SystemExit(
            "No numeric feature columns in processed CSV. Check config/feature_columns.yaml and 01_prepare_data."
        )

    artifacts = resolve_from_project_root(settings["paths"]["artifacts"])
    if not (artifacts / "rf_model.joblib").is_file():
        raise SystemExit(
            f"Нет модели RF: {artifacts / 'rf_model.joblib'}. Сначала выполните: python scripts/02_train_all.py"
        )
    if not any((artifacts / nm).is_file() for nm in ("if_agg_model.joblib", "if_model_agg.joblib", "if_model.joblib")):
        print("Предупреждение: нет IF-артефактов (if_agg_model/if_model_agg/if_model) — L1 IF будет отключён.")

    use_lstm = (
        not no_lstm
        and (artifacts / "lstm_model.pt").is_file()
        and (artifacts / "lstm_label_encoder.joblib").is_file()
    )
    if use_lstm and ts_col and ts_col in df.columns:
        df = df.sort_values(ts_col).reset_index(drop=True)

    X = _numeric_feature_frame(df, num_cols)

    use_hdr = (artifacts / "raw_header_cnn.pt").is_file() and (
        artifacts / "raw_header_cnn_label_encoder.joblib"
    ).is_file()

    from src.pipeline.ensemble_orchestrator import run_cascade

    agg_freq = settings.get("aggregation", {}).get("resample_freq", "1min")
    l2_only = (
        l2_only_after_l1
        if l2_only_after_l1 is not None
        else settings.get("pipeline", {}).get("l2_only_after_l1", True)
    )
    min_threat_score = float(settings.get("threat_scoring", {}).get("alert_threshold", 0.0))
    if demo_preset:
        min_threat_score = 0.0

    pls = None
    if packet_lstm_scores_npz:
        pls = _packet_lstm_scores_from_npz(df, Path(packet_lstm_scores_npz))

    scores = run_cascade(
        X,
        artifacts_dir=artifacts,
        flow_context=df if ts_col and ts_col in df.columns else None,
        timestamp_col=ts_col if ts_col in df.columns else None,
        agg_freq=agg_freq,
        syn_multiplier=settings["aggregation"]["syn_spike_multiplier"],
        use_rf=True,
        use_ae=(artifacts / "ae_model.pt").is_file(),
        use_lstm=use_lstm,
        use_embedding=not no_embedding,
        use_header_cnn=use_hdr,
        l2_only_after_l1=l2_only,
        packet_lstm_scores=pls,
    )

    if "Source IP" in df.columns:
        ips = df["Source IP"].astype(str)
    else:
        ips = pd.Series([f"10.0.0.{i % 250}" for i in range(len(df))])
    dst_ips = df["Destination IP"].astype(str) if "Destination IP" in df.columns else None

    from src.correlation.threat_scoring import score_alert
    from src.correlation.geoip_lookup import lookup_lat_lon_for_flow

    _geo_cfg = settings.get("geoip") or {}
    _geo_raw = str(_geo_cfg.get("city_db", "")).strip()
    _geo_db: str | None = None
    if _geo_raw:
        gp = Path(_geo_raw)
        _geo_db = str((_ROOT / _geo_raw) if not gp.is_absolute() else gp)

    siem_df = _load_siem(settings)

    alerts = []
    dedup_seen: dict[tuple[str, str], pd.Timestamp] = {}
    geo_cache: dict[tuple[str, str], tuple[float | None, float | None]] = {}
    geo_lookup_warned = False
    for i in range(len(scores)):
        row = scores.iloc[i]
        src_row = df.iloc[i]
        prob_raw = _network_score(row)
        prob = prob_raw
        triggered_rules: list[str] = []
        if enable_proxy_rules:
            try:
                triggered_rules, boost = _proxy_rule_signals(src_row)
            except Exception:
                triggered_rules, boost = ([], 0.0)
            prob = min(1.0, max(0.0, prob_raw + boost))
        should_alert = _should_alert(row, gate_on_l1=l2_only)
        if demo_preset and not should_alert:
            should_alert = True
        if not should_alert:
            continue
        ip = ips.iloc[i]
        ts_val = None
        if ts_col and ts_col in df.columns:
            ts_val = str(df.iloc[i][ts_col])
        base = score_alert(ip, prob, siem_df) if len(siem_df) else {
            "ip": ip,
            "threat_score": round(100 * min(prob, 1.0), 2),
            "severity": _severity_from_score(round(100 * min(prob, 1.0), 2)),
            "recommendation": "No SIEM file — network score only.",
        }
        if "severity" not in base:
            base["severity"] = _severity_from_score(float(base.get("threat_score", 0.0) or 0.0))
        if "status" not in base:
            base["status"] = "new"
        if float(base.get("threat_score", 0.0) or 0.0) < min_threat_score:
            continue
        base["ts"] = ts_val
        base["l1_triggered"] = bool(row.get("l1_triggered", False))
        base["l2_rf_attack_score"] = round(float(row.get("l2_rf_attack_score", 0.0)), 4)
        base["l2_ae_ratio"] = round(float(row.get("l2_ae_ratio", 0.0)), 4)
        base["l2_lstm_attack_score"] = round(float(row.get("l2_lstm_attack_score", 0.0)), 4)
        base["l2_emb_attack_score"] = round(float(row.get("l2_emb_attack_score", 0.0)), 4)
        base["l2_hdr_cnn_attack_score"] = round(float(row.get("l2_hdr_cnn_attack_score", 0.0)), 4)
        base["l2_lstm_pkt_score"] = round(float(row.get("l2_lstm_pkt_score", 0.0)), 4)
        base["model_signals"] = {
            "network_score": round(float(prob_raw), 6),
            "network_score_with_rules": round(float(prob), 6),
        }
        base["triggered_rules"] = triggered_rules
        base["reason"] = "rule+ml fusion" if triggered_rules else "ml-only"
        try:
            dip = str(dst_ips.iloc[i]) if dst_ips is not None else ""
            gk = (str(ip), str(dip))
            if gk in geo_cache:
                la, lo = geo_cache[gk]
            else:
                la, lo = lookup_lat_lon_for_flow(ip, dip, db_path=_geo_db)
                geo_cache[gk] = (la, lo)
            if la is not None and lo is not None:
                base["latitude"] = la
                base["longitude"] = lo
        except Exception as e:
            if not geo_lookup_warned:
                warnings.warn(
                    f"GeoIP lookup failed; continuing without coordinates ({e}).",
                    UserWarning,
                    stacklevel=2,
                )
                geo_lookup_warned = True
        if dedup_window_seconds > 0:
            key = (str(base.get("ip", "")), str(base.get("severity", "")))
            ts_parsed = pd.to_datetime(base.get("ts"), errors="coerce")
            if pd.isna(ts_parsed):
                ts_parsed = pd.Timestamp.utcnow().tz_localize(None)
            prev = dedup_seen.get(key)
            if prev is not None and (ts_parsed - prev).total_seconds() <= dedup_window_seconds:
                continue
            dedup_seen[key] = ts_parsed
        alerts.append(base)

    return alerts


def _alerts_summary(alerts: list[dict]) -> dict:
    sev = collections.Counter(str(a.get("severity", "unknown")) for a in alerts)
    scores = [float(a.get("threat_score", 0.0) or 0.0) for a in alerts]
    l2_fields = {
        "rf": "l2_rf_attack_score",
        "ae": "l2_ae_ratio",
        "lstm": "l2_lstm_attack_score",
        "embedding": "l2_emb_attack_score",
        "hdr": "l2_hdr_cnn_attack_score",
        "lstm_pkt": "l2_lstm_pkt_score",
    }
    l2_contrib = {}
    for key, fld in l2_fields.items():
        vals = [float(a.get(fld, 0.0) or 0.0) for a in alerts]
        s = pd.Series(vals, dtype=float)
        l2_contrib[key] = {
            "mean": round(sum(vals) / max(len(vals), 1), 6),
            "non_zero_count": int(sum(1 for v in vals if abs(v) > 1e-12)),
            "std": round(float(s.std()) if len(s) > 1 else 0.0, 8),
            "is_non_constant": bool((float(s.std()) if len(s) > 1 else 0.0) > 1e-12),
        }
    l1_vals = [bool(a.get("l1_triggered", False)) for a in alerts if "l1_triggered" in a]
    n = len(scores)
    mean_sc = round(sum(scores) / max(n, 1), 4)
    med_sc = round(float(pd.Series(scores).median()) if scores else 0.0, 4)
    return {
        "alert_count": n,
        "severity_distribution": dict(sev),
        "threat_score_mean": mean_sc,
        "threat_score_median": med_sc,
        "l2_channel_contribution": l2_contrib,
        "l1_triggered_true_count": int(sum(1 for x in l1_vals if x)),
        "l1_triggered_present": bool(len(l1_vals) > 0),
    }


def _write_detect_compare_report(
    df: pd.DataFrame,
    settings: dict,
    feat_cfg: dict,
    args: argparse.Namespace,
    *,
    output_path: str | None = None,
) -> Path:
    dflt = run_detection_on_dataframe(
        df,
        settings=settings,
        feat_cfg=feat_cfg,
        no_lstm=args.no_lstm,
        no_embedding=args.no_embedding,
        l2_only_after_l1=None,
        packet_lstm_scores_npz=(str(args.packet_lstm_scores).strip() or None),
    )
    par = run_detection_on_dataframe(
        df,
        settings=settings,
        feat_cfg=feat_cfg,
        no_lstm=args.no_lstm,
        no_embedding=args.no_embedding,
        l2_only_after_l1=False,
        packet_lstm_scores_npz=(str(args.packet_lstm_scores).strip() or None),
    )
    dflt_s = _alerts_summary(dflt)
    par_s = _alerts_summary(par)
    payload = {
        "timestamp": ts_token(),
        "data_path": str(args.data),
        "dataset_rows": int(len(df)),
        "default_l1_gated": dflt_s,
        "parallel_l2": par_s,
        "hybrid_participation_check": {
            "rf_non_constant_output": bool(par_s["l2_channel_contribution"]["rf"]["is_non_constant"]),
            "ae_non_zero_output": bool(par_s["l2_channel_contribution"]["ae"]["non_zero_count"] > 0),
            "lstm_non_constant_output": bool(par_s["l2_channel_contribution"]["lstm"]["is_non_constant"]),
            "if_participation_observed_via_l1_field": bool(dflt_s["l1_triggered_present"] or par_s["l1_triggered_present"]),
        },
        "mode_guidance": (
            "default (L1 gated): use for stricter production-like filtering and lower noise; "
            "parallel-l2: use for analysis/reporting when you need full L2 visibility."
        ),
    }
    if output_path:
        out = Path(output_path)
    else:
        out = train_reports_dir(settings, _ROOT) / f"detect_compare_{ts_token()}.json"
    json_write(out, payload)
    return out


def main() -> None:
    """Чтение flows.csv, прогон каскада, запись JSON алертов."""
    from src.utils.console_encoding import configure_stdio_utf8

    configure_stdio_utf8()
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=str, default=str(_ROOT / "data/processed/flows.csv"))
    parser.add_argument(
        "--limit",
        type=int,
        default=100_000,
        help="Макс. строк flows.csv (0 = весь файл). Чтение через nrows — не загружает весь CSV в RAM.",
    )
    parser.add_argument("--output-alerts", type=str, default=str(_ROOT / "storage/alerts_latest.json"))
    parser.add_argument("--no-lstm", action="store_true", help="Skip LSTM inference")
    parser.add_argument("--no-embedding", action="store_true", help="Skip embedding classifier")
    parser.add_argument(
        "--parquet-cache",
        action="store_true",
        help="Кэш parquet рядом с CSV (data/processed/.cache/) для повторных запусков с тем же --limit.",
    )
    parser.add_argument(
        "--csv-engine",
        type=str,
        default="",
        choices=["", "c", "pyarrow"],
        help="Движок pandas.read_csv (pyarrow быстрее при установленном pyarrow; при ошибке — fallback).",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Вывести top-40 по cProfile после прогона (узкие места инференса).",
    )
    parser.add_argument(
        "--parallel-l2",
        action="store_true",
        help="Скоринг L2 для всех потоков без гейта L1 (отчёт; игнорирует l2_only_after_l1 в YAML на этот запуск).",
    )
    parser.add_argument(
        "--packet-lstm-scores",
        type=str,
        default="",
        help="NPZ с flow_keys и scores (scripts/21_train_packet_lstm.py -> packet_lstm_scores.npz); слияние по flow_key.",
    )
    parser.add_argument(
        "--stream-chunk-rows",
        type=int,
        default=0,
        help="Режим «streaming batch»: читать CSV чанками pandas (0 = один проход как раньше).",
    )
    parser.add_argument(
        "--log-wall-time",
        action="store_true",
        help="Печатать wall-clock времени по чанкам / всему прогону.",
    )
    parser.add_argument(
        "--compare-modes-report",
        action="store_true",
        help="Сформировать сравнение default L1-gated vs --parallel-l2 и сохранить JSON отчёт.",
    )
    parser.add_argument(
        "--compare-report-path",
        type=str,
        default="",
        help="Путь к JSON отчёту сравнения режимов detect (опционально).",
    )
    parser.add_argument(
        "--features-yaml",
        type=str,
        default=str(_ROOT / "config/feature_columns.yaml"),
        help="Path to feature_columns.yaml (loaded with canonical merged config).",
    )
    parser.add_argument(
        "--demo-preset",
        action="store_true",
        help="Demo-friendly detect mode: parallel L2 + relaxed alert gate + threshold=0 for interpretable output.",
    )
    parser.add_argument(
        "--dedup-window-seconds",
        type=int,
        default=0,
        help="Подавлять дубли алертов по (ip,severity) в окне N секунд (0 = выключено).",
    )
    parser.add_argument(
        "--disable-proxy-rules",
        action="store_true",
        help="Отключить rule+ML fusion для proxy-подобных фичей.",
    )
    args = parser.parse_args()

    settings = load_settings()
    feat_cfg = load_merged_feature_config(args.features_yaml)
    min_threat_score = float(settings.get("threat_scoring", {}).get("alert_threshold", 0.0))
    print(f"Detect config: alert_threshold={min_threat_score:.2f}")
    if args.demo_preset:
        print("Detect demo preset enabled: relaxed alert gate, parallel L2, effective threshold=0.")

    data_path = Path(args.data)
    if not data_path.is_file():
        hint = ""
        low = str(data_path).replace("\\", "/").lower()
        if "flows_online_buffer" in low:
            hint = (
                " Онлайн-буфер ещё не создан или был очищен: после трафика через прокси выполните "
                "`python main.py proxy-sync-buffer`."
            )
        raise SystemExit(f"Data file not found: {data_path}. Run scripts/01_prepare_data.py first.{hint}")

    lim = None if args.limit == 0 else args.limit
    engine = args.csv_engine or None

    l2_gate = False if (args.parallel_l2 or args.demo_preset) else None
    pkt_npz = str(args.packet_lstm_scores).strip() or None

    def _run_one(df: pd.DataFrame) -> list[dict]:
        return run_detection_on_dataframe(
            df,
            settings=settings,
            feat_cfg=feat_cfg,
            no_lstm=args.no_lstm,
            no_embedding=args.no_embedding,
            l2_only_after_l1=l2_gate,
            packet_lstm_scores_npz=pkt_npz,
            demo_preset=bool(args.demo_preset),
            enable_proxy_rules=not bool(args.disable_proxy_rules),
            dedup_window_seconds=max(0, int(args.dedup_window_seconds or 0)),
        )

    def _run() -> list[dict]:
        if getattr(args, "incremental_new_rows", False):
            inc_path = Path(args.incremental_state)
            if not inc_path.is_absolute():
                inc_path = (_ROOT / inc_path).resolve()
            key = str(data_path.resolve())
            st = _detect_incremental_load(inc_path)
            paths_map: dict = st.get("paths") if isinstance(st.get("paths"), dict) else {}
            prev = int(paths_map.get(key, 0) or 0)
            df_full = read_flows_csv(
                data_path,
                row_limit=0,
                parquet_cache=bool(args.parquet_cache),
                csv_engine=engine,
            )
            total = len(df_full)
            if total < prev:
                prev = 0
            df_run = df_full.iloc[prev:].reset_index(drop=True)
            print(
                f"[incremental-detect] file_rows={total} previously_processed_data_rows={prev} "
                f"new_rows={len(df_run)} state={inc_path.name}"
            )
            print(
                "Замечание: L1 (минутные окна) считается только по хвосту; на стыке с прошлым прогоном возможны отличия от полного файла."
            )
            if df_run.empty:
                paths_map[key] = total
                st["paths"] = paths_map
                _detect_incremental_save(inc_path, st)
                return []
            t0 = time.perf_counter()
            out = _run_one(df_run)
            paths_map[key] = total
            st["paths"] = paths_map
            _detect_incremental_save(inc_path, st)
            if getattr(args, "log_wall_time", False):
                print(f"[detect] incremental elapsed_s={time.perf_counter() - t0:.4f} rows={len(df_run)} alerts={len(out)}")
            return out

        chunk = int(getattr(args, "stream_chunk_rows", 0) or 0)
        if chunk > 0:
            kw: dict = {"encoding": "utf-8", "encoding_errors": "replace", "low_memory": False}
            if engine == "pyarrow":
                kw["engine"] = "pyarrow"
            elif engine == "c":
                kw["engine"] = "c"
            if lim is not None:
                kw["nrows"] = lim
            t0 = time.perf_counter()
            alerts_all: list[dict] = []
            for i, part in enumerate(pd.read_csv(data_path, chunksize=chunk, **kw)):
                part_alerts = _run_one(part)
                alerts_all.extend(part_alerts)
                if getattr(args, "log_wall_time", False):
                    print(f"[stream] chunk={i} rows={len(part)} elapsed_s={time.perf_counter() - t0:.4f}")
            if getattr(args, "log_wall_time", False):
                print(f"[stream] total elapsed_s={time.perf_counter() - t0:.4f} alerts_raw={len(alerts_all)}")
            return alerts_all

        df = read_flows_csv(
            data_path,
            row_limit=lim,
            parquet_cache=bool(args.parquet_cache),
            csv_engine=engine,
        )
        t0 = time.perf_counter()
        out = _run_one(df)
        if getattr(args, "log_wall_time", False):
            print(f"[detect] elapsed_s={time.perf_counter() - t0:.4f} rows={len(df)} alerts={len(out)}")
        return out

    if args.benchmark:
        import cProfile
        import pstats
        from io import StringIO

        prof = cProfile.Profile()
        prof.enable()
        alerts = _run()
        prof.disable()
        buf = StringIO()
        pstats.Stats(prof, stream=buf).sort_stats("cumtime").print_stats(40)
        print(buf.getvalue())
    else:
        alerts = _run()

    outp = Path(args.output_alerts)
    outp.parent.mkdir(parents=True, exist_ok=True)
    with open(outp, "w", encoding="utf-8") as f:
        json.dump(alerts[:200], f, ensure_ascii=False, indent=2)
    print(f"Wrote {len(alerts)} alerts (capped 200 in file) to {outp}")
    if args.compare_modes_report:
        cmp_df = read_flows_csv(
            data_path,
            row_limit=lim,
            parquet_cache=bool(args.parquet_cache),
            csv_engine=engine,
        )
        cmp_path = _write_detect_compare_report(
            cmp_df,
            settings=settings,
            feat_cfg=feat_cfg,
            args=args,
            output_path=(args.compare_report_path.strip() or None),
        )
        print(f"Detect compare report: {cmp_path}")
        print("Рекомендация: default(L1-gated) для строгого режима; parallel-l2 для аналитики и отчётов.")
    if len(alerts) == 0:
        print(
            "Подсказка: 0 алертов — снизьте пороги в коде _should_alert, увеличьте --limit, "
            "или в config/settings.yaml выставьте pipeline.l2_only_after_l1: false и "
            "aggregation.syn_spike_multiplier поменьше (если используете строгий L1->L2)."
        )


if __name__ == "__main__":
    main()
