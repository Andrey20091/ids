# =============================================================================
# Признаки уровня L2: HTTP — эвристики и контекст «последовательности» (ТЗ).
# =============================================================================
"""HTTP context: URI stats + per-source temporal rate (session-like bursts)."""

from __future__ import annotations

import pandas as pd


def enrich_http_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Добавить признаки по HTTP-подобным колонкам и (если есть время + IP) — частоту в минуту.

    URI: длина, число «/», доля «небуквенно-цифровых» символов.
    При ``Timestamp`` + ``Source IP``: число потоков с тем же IP в той же минуте
    (агрегат последовательности запросов); скользящее std длины URI внутри IP (5 потоков).
    """
    out = df.copy()
    uri_col = None
    for col in df.columns:
        name = str(col).lower()
        if any(k in name for k in ("url", "uri", "http.request", "request_uri")):
            uri_col = col
            break

    if uri_col is not None:
        s = df[uri_col].fillna("").astype(str)
        out["http_token_len"] = s.str.len()
        out["http_slash_count"] = s.str.count("/")
        alnum = s.str.replace(r"[^a-zA-Z0-9]", "", regex=True).str.len()
        denom = out["http_token_len"].replace(0, 1)
        out["http_non_alnum_ratio"] = (out["http_token_len"] - alnum).div(denom).fillna(0.0)

        ts_col = "Timestamp" if "Timestamp" in out.columns else None
        ip_col = "Source IP" if "Source IP" in out.columns else None
        if ts_col and ip_col:
            t = pd.to_datetime(out[ts_col], errors="coerce")
            minute = t.dt.floor("min")
            gkey = out[ip_col].astype(str) + "|" + minute.astype(str)
            out["http_flows_same_ip_60s"] = out.groupby(gkey)[uri_col].transform("count").astype(float)

            df2 = pd.DataFrame(
                {
                    "_idx": out.index,
                    ip_col: out[ip_col].astype(str),
                    "_t": t,
                    "_len": out["http_token_len"].astype(float),
                }
            )
            df2 = df2.sort_values([ip_col, "_t"], kind="mergesort")
            df2["_rs"] = (
                df2.groupby(ip_col, group_keys=False)["_len"]
                .rolling(5, min_periods=1)
                .std()
                .reset_index(level=0, drop=True)
            )
            df2 = df2.set_index("_idx")
            out["http_uri_len_roll_std"] = df2["_rs"].reindex(out.index).fillna(0.0)
        else:
            out["http_flows_same_ip_60s"] = 1.0
            out["http_uri_len_roll_std"] = 0.0
    else:
        for c in (
            "http_token_len",
            "http_slash_count",
            "http_non_alnum_ratio",
            "http_flows_same_ip_60s",
            "http_uri_len_roll_std",
        ):
            out[c] = 0.0

    for col in df.columns:
        name = str(col).lower()
        if name in ("method", "http_method", "request_method"):
            s = df[col].fillna("").astype(str)
            out["http_method_hash"] = (s.map(hash) % 997).astype(float)
            break
    if "http_method_hash" not in out.columns:
        out["http_method_hash"] = 0.0

    return out


def http_sequence_stub(df: pd.DataFrame) -> pd.DataFrame:
    """Обратно совместимый алиас для ``enrich_http_features``."""
    return enrich_http_features(df)
