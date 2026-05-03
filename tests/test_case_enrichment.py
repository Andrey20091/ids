# =============================================================================
# Тесты обогащения признаками кейса 4 (HTTP, DNS, hdr_*).
# =============================================================================
"""Tests for src.features.case_enrichment."""

from __future__ import annotations

import pandas as pd

from src.features.case_enrichment import enrich_case4_features


def test_enrich_adds_http_dns_and_hdr():
    """После enrich должны появиться http_*, dns_* и hdr_* при исходных колонках."""
    df = pd.DataFrame(
        {
            "Flow Duration": [1.0, 2.0],
            "Fwd Packet Length Max": [100, 200],
            "Bwd Packet Length Max": [50, 60],
            "Flow Bytes/s": [1e3, 2e3],
            "Flow Packets/s": [10.0, 20.0],
            "SYN Flag Count": [0, 5],
            "http_request_uri": ["/a", "/b/c/d"],
            "dns_qname": ["a.example.com.", "x.y.z.tld."],
        }
    )
    out = enrich_case4_features(df)
    assert "http_token_len" in out.columns
    assert "dns_qname_entropy" in out.columns
    assert "hdr_Flow_Duration" in out.columns
