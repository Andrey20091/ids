# =============================================================================
# Опциональная геолокация IP для дашборда (MaxMind GeoLite2, ТЗ: карта атак).
# =============================================================================
"""Путь к БД: переменная GEOIP2_CITY_DB или config/settings.yaml -> geoip.city_db."""

from __future__ import annotations

import ipaddress
import logging
import os
import sys
import warnings
from pathlib import Path

_LOG = logging.getLogger("ids.geoip")
_GEOIP_WARNED: set[str] = set()
_GEOIP_INFO_ONCE: set[str] = set()


def _warn_once(key: str, msg: str) -> None:
    if key in _GEOIP_WARNED:
        return
    _GEOIP_WARNED.add(key)
    warnings.warn(msg, UserWarning, stacklevel=2)


def _info_once(key: str, msg: str) -> None:
    if key in _GEOIP_INFO_ONCE:
        return
    _GEOIP_INFO_ONCE.add(key)
    _LOG.info(msg)
    quiet = os.environ.get("IDS_GEOIP_QUIET", "").strip().lower() in ("1", "true", "yes")
    if quiet:
        return
    try:
        print(msg, file=sys.stderr, flush=True)
    except OSError:
        pass


def _resolve_db_path(explicit: str | None) -> str | None:
    candidates: list[str] = []
    if explicit and str(explicit).strip():
        candidates.append(str(explicit).strip())
    env = os.environ.get("GEOIP2_CITY_DB", "").strip()
    if env:
        candidates.append(env)
    for raw in candidates:
        p = Path(raw).expanduser()
        if p.is_file():
            return str(p.resolve())
    return None


def lookup_lat_lon(ip: str, db_path: str | None = None) -> tuple[float | None, float | None]:
    """Вернуть (latitude, longitude) или (None, None) если БД не задана / IP не публичный / ошибка."""
    s = str(ip).strip()
    if not s or s.lower() == "nan":
        return None, None
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None, None
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        return None, None

    db = _resolve_db_path(db_path)
    if not db:
        _info_once(
            "geoip_db_missing",
            "GeoIP MMDB не найден — координаты отключены. Установите: `python main.py bootstrap` "
            "или укажите `geoip.city_db` в config/settings.yaml / переменную GEOIP2_CITY_DB.",
        )
        return None, None
    try:
        import geoip2.database
    except ImportError as e:
        _warn_once("geoip_import_error", f"geoip2 is unavailable ({e}); coordinates are disabled.")
        return None, None
    try:
        with geoip2.database.Reader(db) as reader:
            rec = reader.city(s)
            lat, lon = rec.location.latitude, rec.location.longitude
            if lat is None or lon is None:
                return None, None
            return float(lat), float(lon)
    except Exception as e:
        _warn_once("geoip_reader_error", f"GeoIP lookup failed with DB {db}: {e}")
        return None, None


def lookup_lat_lon_for_flow(
    source_ip: str,
    destination_ip: str,
    db_path: str | None = None,
) -> tuple[float | None, float | None]:
    """
    Для CICIDS2017 часто Source в частной сети; пробуем Destination, затем Source.
    Первый успешный геолookup возвращается.
    """
    seen: set[str] = set()
    for ip in (destination_ip, source_ip):
        t = str(ip).strip()
        if not t or t.lower() == "nan" or t in seen:
            continue
        seen.add(t)
        la, lo = lookup_lat_lon(t, db_path=db_path)
        if la is not None and lo is not None:
            return la, lo
    return None, None
