# =============================================================================
# GeoIP: частные адреса и порядок перебора IP без реального .mmdb.
# =============================================================================
from src.correlation.geoip_lookup import lookup_lat_lon, lookup_lat_lon_for_flow


def test_lookup_skips_private_without_db():
    assert lookup_lat_lon("192.168.10.5") == (None, None)
    assert lookup_lat_lon("10.0.0.1") == (None, None)


def test_lookup_invalid_ip():
    assert lookup_lat_lon("not-an-ip") == (None, None)


def test_for_flow_no_crash_without_db():
    assert lookup_lat_lon_for_flow("192.168.1.1", "8.8.8.8", db_path=None) == (None, None)
