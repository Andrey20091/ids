# =============================================================================
# Автоустановка окружения ТЗ: pip-зависимости + MMDB геолокации (DB-IP Lite, без ключей).
# =============================================================================
"""Run: python main.py bootstrap  OR  python scripts/bootstrap_environment.py"""

from __future__ import annotations

import argparse
import gzip
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))


def _run_pip_install(args: list[str]) -> int:
    cmd = [sys.executable, "-m", "pip", "install", *args]
    print("+", " ".join(cmd))
    return subprocess.call(cmd, cwd=str(_ROOT))


def _prev_month(y: int, m: int) -> tuple[int, int]:
    if m <= 1:
        return y - 1, 12
    return y, m - 1


def _month_candidates(n: int = 5) -> list[tuple[int, int]]:
    d = date.today().replace(day=1)
    out: list[tuple[int, int]] = []
    y, m = d.year, d.month
    for _ in range(n):
        out.append((y, m))
        y, m = _prev_month(y, m)
    return out


def _download_dbip_city_mmdb(dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    final_mmdb = dest_dir / "dbip-city-lite.mmdb"
    gz_path = dest_dir / "dbip-city-lite.mmdb.gz.download"

    for y, m in _month_candidates(6):
        url = f"https://download.db-ip.com/free/dbip-city-lite-{y}-{m:02d}.mmdb.gz"
        print(f"Пробую загрузить: {url}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ids-ml-project-bootstrap/1.0"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                if resp.status != 200:
                    continue
                with open(gz_path, "wb") as out:
                    shutil.copyfileobj(resp, out)
        except urllib.error.HTTPError as e:
            if e.code in (403, 404):
                continue
            raise
        except OSError as e:
            print(f"  сеть/ошибка: {e}")
            continue

        with gzip.open(gz_path, "rb") as zf, open(final_mmdb, "wb") as raw:
            shutil.copyfileobj(zf, raw)
        gz_path.unlink(missing_ok=True)
        print(f"OK: {final_mmdb} ({final_mmdb.stat().st_size // (1024 * 1024)} MiB)")
        return final_mmdb

    raise SystemExit(
        "Не удалось скачать DB-IP City Lite (проверьте сеть). "
        "Вручную: https://db-ip.com/db/download/ip-to-city-lite — положите .mmdb в data/third_party/"
    )


def _set_geoip_city_db_in_settings(rel_path: str, *, force: bool) -> None:
    cfg = _ROOT / "config" / "settings.yaml"
    text = cfg.read_text(encoding="utf-8")
    needle = "city_db:"
    if needle not in text:
        raise SystemExit("В config/settings.yaml нет ключа geoip.city_db — добавьте блок geoip вручную.")
    lines = text.splitlines()
    out_lines: list[str] = []
    changed = False
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("city_db:"):
            cur = stripped.split(":", 1)[1].strip().strip('"').strip("'")
            if cur and not force:
                print(f"geoip.city_db уже задан ({cur}), пропуск (--force-geo-settings для перезаписи).")
                out_lines.append(line)
            else:
                indent = line[: len(line) - len(stripped)]
                new_line = f'{indent}city_db: "{rel_path}"'
                if new_line != line:
                    changed = True
                out_lines.append(new_line)
        else:
            out_lines.append(line)
    if changed:
        cfg.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
        print(f"Обновлён {cfg}: geoip.city_db = {rel_path}")


def main() -> int:
    p = argparse.ArgumentParser(description="Установка pip-зависимостей и MMDB геолокации (DB-IP Lite).")
    p.add_argument("--skip-pip", action="store_true", help="Не вызывать pip install")
    p.add_argument("--skip-geo", action="store_true", help="Не скачивать MMDB")
    p.add_argument("--force-geo-settings", action="store_true", help="Перезаписать geoip.city_db в settings.yaml")
    args = p.parse_args()

    if not args.skip_pip:
        if _run_pip_install(["-r", str(_ROOT / "requirements.txt")]) != 0:
            return 1
        ml = _ROOT / "requirements-ml.txt"
        if ml.is_file():
            # CPU-колёса PyTorch (Windows); при ошибке не валим bootstrap целиком
            code = _run_pip_install(
                ["-r", str(ml), "--index-url", "https://download.pytorch.org/whl/cpu"]
            )
            if code != 0:
                print("Предупреждение: pip install requirements-ml.txt завершился с ошибкой (torch?). Продолжаем.")

    if not args.skip_geo:
        third = _ROOT / "data" / "third_party"
        mmdb = _download_dbip_city_mmdb(third)
        rel = str(mmdb.relative_to(_ROOT)).replace("\\", "/")
        _set_geoip_city_db_in_settings(rel, force=args.force_geo_settings)

        try:
            from src.correlation.geoip_lookup import lookup_lat_lon_for_flow

            os.environ.pop("GEOIP2_CITY_DB", None)
            la, lo = lookup_lat_lon_for_flow("192.168.1.1", "8.8.8.8", db_path=str(mmdb))
            print(f"Проверка геолookup 8.8.8.8: lat={la} lon={lo}")
        except Exception as e:
            print(f"Предупреждение: проверка геолookup не удалась: {e}")

    print("Bootstrap завершён.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
