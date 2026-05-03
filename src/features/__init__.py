# =============================================================================
# Подпакет features: агрегация, HTTP/DNS, обогащение кейса 4.
# =============================================================================
"""Feature engineering: aggregates, HTTP/DNS, case enrichment."""

from src.features.aggregate_traffic import aggregate_flows_by_time

__all__ = ["aggregate_flows_by_time"]
