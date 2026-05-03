from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _geoip_quiet_stderr() -> None:
    """Не засорять stderr GeoIP-подсказкой при отсутствии MMDB в тестах."""
    prev = os.environ.get("IDS_GEOIP_QUIET")
    os.environ["IDS_GEOIP_QUIET"] = "1"
    yield
    if prev is None:
        os.environ.pop("IDS_GEOIP_QUIET", None)
    else:
        os.environ["IDS_GEOIP_QUIET"] = prev
