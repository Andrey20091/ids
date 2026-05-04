# =============================================================================
# Единая точка входа: полный демо-пайплайн кейса 4 или отдельные команды.
# =============================================================================
"""
Единая точка входа IDS ML (ТЗ): проверка окружения, демо-данные, подготовка,
обучение, детекция; опционально Streamlit-дашборд.

Запуск из корня проекта:
  python main.py              # полный демо-пайплайн
  python main.py --dashboard  # то же + запуск дашборда
  python main.py train        # только обучение
  python main.py proxy        # локальный HTTP/HTTPS-прокси → data/raw/proxy_traffic.ndjson
  python main.py proxy-ingest # NDJSON → CSV + опционально prepare
  python main.py proxy-sync-buffer  # инкремент NDJSON→CSV + append в flows_online_buffer (онлайн-дообучение)
  python main.py pcap-flows --pcap path/to/file.pcap  # PCAP → CSV (scapy), затем prepare
  python main.py incidents-sync
  python main.py incidents-status
  python main.py labels-import
  python main.py sandbox-eval
  python main.py model-approve / model-deploy
  python main.py dashboard    # открыть дашборд в любой момент
  python main.py detect --detect-use-online-buffer   # детект по flows_online_buffer из settings.yaml
  python main.py clear-online-buffer   # усечь online-буфер, сбросить watermark / инкремент detect
  python main.py bootstrap    # pip + MMDB геолокации (DB-IP Lite), см. scripts/bootstrap_environment.py
  python main.py validate     # проверка paths, flows.csv, наличие rf_model после prepare
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent

try:
    import yaml
except ModuleNotFoundError as _yaml_err:
    _venv_py = _ROOT / ".venv" / "Scripts" / "python.exe"
    sys.stderr.write(
        "Не установлены зависимости проекта (например PyYAML).\n"
        f"Сейчас запущен интерпретатор:\n  {sys.executable}\n\n"
        "Запускайте команды через venv (без Activate.ps1):\n"
        f"  {_venv_py} main.py check\n"
        f"  {_ROOT / 'run.cmd'} main.py check\n"
        f"  {_venv_py} -m pip install -r requirements.txt\n"
        f"  {_venv_py} -m pytest tests -q\n\n"
        "Если папки .venv нет: py -3 -m venv .venv\n"
        f"Обход блокировки Activate.ps1: cmd /c \"{_venv_py}\" main.py check\n"
    )
    raise SystemExit(1) from _yaml_err

from src.utils.console_encoding import configure_stdio_utf8


def _ensure_frozen_writable_root() -> None:
    """
    У frozen-приложения каталог с exe часто только для чтения — данные и артефакты в %LOCALAPPDATA%\\IDS_ML_Project.
    Скрипты и src/utils_config читают IDS_PROJECT_ROOT из окружения.
    """
    if not getattr(sys, "frozen", False):
        return
    if os.environ.get("IDS_PROJECT_ROOT"):
        return
    local_base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    wr = (local_base / "IDS_ML_Project").resolve()
    for sub in ("data/raw", "data/processed", "storage", "artifacts"):
        (wr / sub).mkdir(parents=True, exist_ok=True)
    cfg_src = _ROOT / "config"
    cfg_dst = wr / "config"
    cfg_dst.mkdir(parents=True, exist_ok=True)
    if cfg_src.is_dir():
        for name in ("settings.yaml", "feature_columns.yaml"):
            src_f, dst_f = cfg_src / name, cfg_dst / name
            if src_f.is_file() and not dst_f.is_file():
                shutil.copy2(src_f, dst_f)
    os.environ["IDS_PROJECT_ROOT"] = str(wr)


def _resolve_data_path(rel_or_abs: str) -> str:
    """Относительные пути к данным: от IDS_PROJECT_ROOT (frozen) или от _ROOT (разработка)."""
    p = Path(rel_or_abs)
    if p.is_absolute():
        return str(p)
    base = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _ROOT
    return str(base / p)


def _py() -> str:
    return sys.executable


def _read_alert_threshold() -> float:
    """Текущий порог алертов из settings.yaml (с fallback на 0.0)."""
    base = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _ROOT
    cfg_candidates = [base / "config" / "settings.yaml", _ROOT / "config" / "settings.yaml"]
    for cfg in cfg_candidates:
        if not cfg.is_file():
            continue
        try:
            with open(cfg, encoding="utf-8") as f:
                settings = yaml.safe_load(f) or {}
            return float(settings.get("threat_scoring", {}).get("alert_threshold", 0.0))
        except Exception:
            continue
    return 0.0


def _read_path_default(path_key: str, fallback: str) -> str:
    """Путь из settings.paths.<key> с fallback на legacy значение."""
    base = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _ROOT
    cfg_candidates = [base / "config" / "settings.yaml", _ROOT / "config" / "settings.yaml"]
    for cfg in cfg_candidates:
        if not cfg.is_file():
            continue
        try:
            with open(cfg, encoding="utf-8") as f:
                settings = yaml.safe_load(f) or {}
            paths = settings.get("paths", {}) or {}
            val = str(paths.get(path_key, "")).strip()
            if val:
                return val
        except Exception:
            continue
    return fallback


def _run_script(rel: str, *args: str) -> int:
    script_path = str(_ROOT / rel)
    if getattr(sys, "frozen", False):
        old_argv = sys.argv[:]
        old_main = sys.modules.get("__main__")
        try:
            sys.argv = [script_path, *args]
            # runpy.run_path ломается на части сборок Python 3.14 + PyInstaller для .py в _internal
            spec = importlib.util.spec_from_file_location("__main__", script_path)
            if spec is None or spec.loader is None:
                print(f"Ошибка: не удалось загрузить скрипт: {script_path}")
                return 1
            mod = importlib.util.module_from_spec(spec)
            sys.modules["__main__"] = mod
            spec.loader.exec_module(mod)
            return 0
        except SystemExit as e:
            return int(e.code) if isinstance(e.code, int) else 1
        finally:
            sys.argv = old_argv
            if old_main is not None:
                sys.modules["__main__"] = old_main
    cmd = [_py(), script_path, *args]
    try:
        return subprocess.call(cmd, cwd=_ROOT)
    except KeyboardInterrupt:
        print("Операция остановлена пользователем (Ctrl+C).")
        return 130


def _torch_probe() -> tuple[bool, str | None]:
    """
    Проверка импорта torch в *текущем* интерпретаторе (sys.executable).

    Torch часто ставят в venv, а `main.py` запускают системным `python` — тогда
    модуль «есть в проекте», но не в этом окружении.
    """
    try:
        import torch  # noqa: F401
    except ImportError as e:
        return False, f"{type(e).__name__}: {e}"
    except OSError as e:
        return False, f"{type(e).__name__}: {e}"
    return True, None


def _sibling_dashboard_exe() -> Path | None:
    """Путь к ids-dashboard.exe рядом со сборкой: .../ids-cli/ids-cli.exe → .../ids-dashboard/ids-dashboard.exe."""
    if not getattr(sys, "frozen", False):
        return None
    exe = Path(sys.executable).resolve()
    cand = exe.parent.parent / "ids-dashboard" / "ids-dashboard.exe"
    return cand if cand.is_file() else None


def _run_dashboard() -> int:
    """
    Дашборд: в venv — streamlit subprocess; в frozen CLI — отдельный IDS Dashboard.exe
    (Streamlit в CLI не тащим — оптимальный размер и один процесс без self-spawn).
    """
    if getattr(sys, "frozen", False):
        dash = _sibling_dashboard_exe()
        if dash is not None:
            print(f"Запуск IDS Dashboard: {dash}")
            try:
                if sys.platform == "win32":
                    subprocess.Popen(
                        [str(dash)],
                        cwd=str(dash.parent),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=subprocess.DETACHED_PROCESS
                        | subprocess.CREATE_NEW_PROCESS_GROUP,
                    )
                else:
                    subprocess.Popen(
                        [str(dash)],
                        cwd=str(dash.parent),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
            except OSError as e:
                print(f"Не удалось запустить IDS Dashboard: {e}")
                print("Запустите дашборд вручную: ids-dashboard.exe из папки ids-dashboard или из исходников: python main.py dashboard")
                return 0
            print("IDS Dashboard запущен отдельно; откройте URL в браузере (см. окно/лог дашборда).")
            return 0
        print(
            "IDS Dashboard не найден рядом с CLI (ожидался каталог ..\\ids-dashboard\\ids-dashboard.exe). "
            "Соберите дашборд рядом с ids-cli (PyInstaller, ids-dashboard.spec) либо запустите из репозитория: python main.py dashboard"
        )
        return 0

    app_path = _ROOT / "dashboard" / "app.py"
    if not app_path.is_file():
        print(f"Ошибка: не найден файл дашборда: {app_path}")
        return 1
    try:
        return subprocess.call(
            [_py(), "-m", "streamlit", "run", str(app_path)],
            cwd=_ROOT,
        )
    except KeyboardInterrupt:
        print("Дашборд остановлен пользователем (Ctrl+C).")
        return 130


def main() -> int:
    """Разбор аргументов и запуск выбранной команды или полного сценария ``all``."""
    configure_stdio_utf8()
    parser = argparse.ArgumentParser(description="IDS ML — единая точка входа")
    parser.add_argument(
        "command",
        nargs="?",
        default="all",
        choices=(
            "all",
            "baseline-train",
            "ingest-new-data",
            "bootstrap",
            "check",
            "generate",
            "prepare",
            "train",
            "detect",
            "clear-online-buffer",
            "online",
            "realtime",
            "proxy",
            "proxy-ingest",
            "proxy-sync-buffer",
            "pcap-flows",
            "incidents-sync",
            "incidents-status",
            "labels-import",
            "retrain-report",
            "sandbox-eval",
            "model-approve",
            "model-deploy",
            "dashboard",
            "validate",
        ),
        help="Шаг или полный прогон (по умолчанию: all)",
    )
    parser.add_argument(
        "--input",
        default="data/raw/synthetic_cicids_demo.csv",
        help="Сырой CSV для prepare (после generate)",
    )
    parser.add_argument(
        "--gen-seed",
        type=int,
        default=42,
        help="Seed генерации synthetic-данных для команд generate/all (по умолчанию: 42).",
    )
    parser.add_argument(
        "--gen-random-seed",
        action="store_true",
        help="Для generate/all: случайный seed (каждый запуск разные synthetic-данные).",
    )
    parser.add_argument(
        "--skip-torch",
        action="store_true",
        help="Не обучать AE/LSTM даже при установленном torch",
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Разрешить частичный режим без torch (только RF/IF).",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="После all: запустить дашборд",
    )
    parser.add_argument(
        "--demo-mode",
        action="store_true",
        help="Разрешить demo-only сценарий для команды all (без implicit retrain).",
    )
    parser.add_argument(
        "--dataset-tag",
        default="",
        help="Команды train/baseline-train: метка датасета для policy gate (например cicids2017).",
    )
    parser.add_argument(
        "--dataset-source",
        default="",
        help="Команды train/baseline-train: произвольное описание источника датасета.",
    )
    parser.add_argument(
        "--force-rebaseline",
        action="store_true",
        help="Команда baseline-train/train: разрешить перезапись baseline при allow_force_rebaseline=true.",
    )
    parser.add_argument(
        "--train-data",
        default="",
        help="Команды train/baseline-train: путь к prepared flows CSV.",
    )
    parser.add_argument(
        "--baseline-data",
        default="",
        help="Команда baseline-train: путь к prepared CICIDS2017 flows CSV.",
    )
    parser.add_argument(
        "--baseline-features-yaml",
        default="",
        help="Команда baseline-train: путь к feature_columns.yaml (опционально).",
    )
    parser.add_argument(
        "--proxy-bind",
        default="127.0.0.1",
        help="Команда proxy: адрес прослушивания",
    )
    parser.add_argument(
        "--proxy-port",
        type=int,
        default=8899,
        help="Команда proxy: порт",
    )
    parser.add_argument(
        "--proxy-output",
        default="data/raw/proxy_traffic.ndjson",
        help="Команда proxy: путь к NDJSON-логу (от IDS_PROJECT_ROOT или корня проекта)",
    )
    parser.add_argument(
        "--proxy-host-filter",
        default="",
        help="Команда proxy: только хосты, содержащие подстроку (без учёта регистра)",
    )
    parser.add_argument(
        "--proxy-max-log-mb",
        type=int,
        default=0,
        help="Команда proxy: ротация NDJSON при превышении размера в MB (0=выкл).",
    )
    parser.add_argument(
        "--proxy-max-log-backups",
        type=int,
        default=5,
        help="Команда proxy: число backup файлов ротации NDJSON.",
    )
    parser.add_argument(
        "--ingest-ndjson",
        default="data/raw/proxy_traffic.ndjson",
        help="Команда proxy-ingest: входной NDJSON",
    )
    parser.add_argument(
        "--ingest-csv-out",
        default="data/raw/proxy_cicids_like.csv",
        help="Команда proxy-ingest: выходной CSV для prepare",
    )
    parser.add_argument(
        "--ingest-state-file",
        default="",
        help="Команда proxy-ingest: JSON checkpoint offset для инкрементального чтения NDJSON.",
    )
    parser.add_argument(
        "--ingest-incremental",
        action="store_true",
        help="Команда proxy-ingest: обработать только новые записи NDJSON по checkpoint.",
    )
    parser.add_argument(
        "--ingest-append",
        action="store_true",
        help="Команда proxy-ingest: добавить строки в существующий CSV вместо полной перезаписи.",
    )
    parser.add_argument(
        "--ingest-prepare",
        action="store_true",
        help="Команда proxy-ingest: после CSV запустить prepare с --ingest-csv-out",
    )
    parser.add_argument(
        "--pcap",
        default="",
        help="Команда pcap-flows: путь к .pcap/.pcapng (от IDS_PROJECT_ROOT или абсолютный)",
    )
    parser.add_argument(
        "--pcap-output",
        default="data/raw/pcap_flows_raw.csv",
        help="Команда pcap-flows: выходной CSV перед prepare",
    )
    parser.add_argument(
        "--pcap-prepare",
        action="store_true",
        help="Команда pcap-flows: после CSV вызвать prepare с --input = --pcap-output",
    )
    parser.add_argument(
        "--header-bytes-npz",
        default="",
        help="Команда prepare/all: NPZ с X (сырые байты заголовков), см. scripts/16_build_header_byte_dataset.py",
    )
    parser.add_argument(
        "--prepare-output",
        default="",
        help="Команда prepare/all: выходной flows.csv (по умолчанию scripts/01_prepare_data.py).",
    )
    parser.add_argument(
        "--prepare-append-output",
        action="store_true",
        help="Команда prepare/ingest-new-data: append в --prepare-output с проверкой схемы (header не дублируется).",
    )
    parser.add_argument(
        "--ingest-append-output",
        action="store_true",
        help="Команда ingest-new-data: alias для --prepare-append-output.",
    )
    parser.add_argument(
        "--prepare-features-yaml",
        default="",
        help="Команда prepare/all: путь к feature_columns.yaml.",
    )
    parser.add_argument(
        "--prepare-no-cicids-normalize",
        action="store_true",
        help="Команда prepare/all: отключить нормализацию CICIDS (advanced).",
    )
    parser.add_argument(
        "--prepare-pcap-enrichment",
        default="",
        help="Команда prepare/all: PCAP для доп. признаков DNS/HTTP plaintext (без TLS), см. scripts/01_prepare_data.py",
    )
    parser.add_argument("--incident-id", default="", help="Команда incidents-status: incident_id")
    parser.add_argument("--incident-status", default="triaged", help="Команда incidents-status: новый статус")
    parser.add_argument("--incident-owner", default="", help="Команда incidents-status: владелец")
    parser.add_argument("--incident-comment", default="", help="Команда incidents-status: комментарий")
    parser.add_argument("--incident-actor", default="cli_user", help="Команда incidents-status: кто изменил")
    parser.add_argument("--labels-input", default="", help="Команда labels-import: входной CSV/JSON")
    parser.add_argument("--labels-output", default="storage/labels_dataset.csv", help="Команда labels-import: выходной CSV")
    parser.add_argument("--report-limit", type=int, default=10, help="Команда retrain-report: число последних записей")
    parser.add_argument("--candidate-model-set-id", default="", help="Команда sandbox-eval: ID candidate model set")
    parser.add_argument("--sandbox-min-delta-f1", type=float, default=0.01, help="Команда sandbox-eval: min delta F1")
    parser.add_argument("--sandbox-min-precision", type=float, default=0.65, help="Команда sandbox-eval: min precision")
    parser.add_argument("--model-set-id", default="", help="Команды model-approve/model-deploy: ID model set")
    parser.add_argument("--approved-by", default="cli_user", help="Команда model-approve: кто утвердил")
    parser.add_argument(
        "--training-profile",
        default="production",
        help="Команда train: production | development (см. training_profiles в config/settings.yaml)",
    )
    parser.add_argument(
        "--detect-limit",
        type=int,
        default=None,
        help="Команда detect: лимит строк flows.csv (по умолчанию как у scripts/03_run_detection_batch.py)",
    )
    parser.add_argument(
        "--detect-parquet-cache",
        action="store_true",
        help="Команда detect: включить parquet-кэш рядом с CSV",
    )
    parser.add_argument(
        "--detect-csv-engine",
        default="",
        choices=["", "c", "pyarrow"],
        help="Команда detect: движок read_csv",
    )
    parser.add_argument(
        "--detect-benchmark",
        action="store_true",
        help="Команда detect: cProfile топ функций после прогона",
    )
    parser.add_argument(
        "--detect-parallel-l2",
        action="store_true",
        help="Команда detect: L2 для всех потоков (отчёт; см. docs/TZ_CASE4.md §2)",
    )
    parser.add_argument(
        "--detect-packet-lstm-scores",
        default="",
        help="Команда detect: NPZ flow_keys+scores для packet-LSTM (docs/TZ_CASE4 extended).",
    )
    parser.add_argument(
        "--detect-stream-chunk-rows",
        type=int,
        default=0,
        help="Команда detect: streaming batch по чанкам CSV (0 = как раньше).",
    )
    parser.add_argument(
        "--detect-log-wall-time",
        action="store_true",
        help="Команда detect: wall-clock в лог",
    )
    parser.add_argument(
        "--detect-compare-modes-report",
        action="store_true",
        help="Команда detect: сохранить отчёт сравнения default L1-gated vs parallel-l2.",
    )
    parser.add_argument(
        "--detect-compare-report-path",
        default="",
        help="Команда detect: путь к JSON отчёту сравнения режимов (опционально).",
    )
    parser.add_argument(
        "--detect-features-yaml",
        default="",
        help="Команда detect: путь к feature_columns.yaml.",
    )
    parser.add_argument(
        "--detect-demo-preset",
        action="store_true",
        help="Команда detect: demo-friendly режим (parallel L2 + relaxed gate + threshold=0).",
    )
    parser.add_argument(
        "--detect-dedup-window-seconds",
        type=int,
        default=0,
        help="Команда detect: подавление дублей алертов по (ip,severity) в окне N секунд (0=выкл).",
    )
    parser.add_argument(
        "--detect-disable-proxy-rules",
        action="store_true",
        help="Команда detect: отключить rule+ML fusion для proxy-подобных фичей.",
    )
    parser.add_argument(
        "--detect-data",
        default="",
        help="Команда detect: путь к flows CSV для scripts/03_run_detection_batch.py --data (от корня проекта или абсолютный).",
    )
    parser.add_argument(
        "--detect-use-online-buffer",
        action="store_true",
        help="Команда detect: то же, что --data paths.flows_online_buffer из config/settings.yaml (прокси-буфер).",
    )
    parser.add_argument(
        "--detect-new-rows-only",
        action="store_true",
        help="Команда detect: только строки после последнего прогона (scripts/03 --incremental-new-rows).",
    )
    parser.add_argument(
        "--detect-incremental-state",
        default="",
        help="Команда detect: путь к JSON инкрементального состояния (по умолчанию storage/detect_incremental_state.json).",
    )
    parser.add_argument(
        "--clear-buffer",
        default="",
        help="Команда clear-online-buffer: явный путь к буферу CSV (пусто = paths.flows_online_buffer из settings).",
    )
    parser.add_argument(
        "--online-data",
        default="",
        help="Команда online: путь к входному flows CSV (по умолчанию paths.flows_online_buffer из settings).",
    )
    parser.add_argument(
        "--online-loop",
        action="store_true",
        help="Команда online: запускать бесконечный цикл (аналог scripts/04_run_online_loop.py --loop).",
    )
    parser.add_argument(
        "--online-delayed-first-tick",
        action="store_true",
        help="Команда online: в loop-режиме ждать interval до первого тика.",
    )
    parser.add_argument(
        "--realtime-data",
        default="",
        help="Команда realtime: путь к входному flows CSV (по умолчанию paths.flows_online_buffer из settings).",
    )
    parser.add_argument(
        "--realtime-output-alerts",
        default="",
        help="Команда realtime: путь к выходному alerts JSON.",
    )
    parser.add_argument(
        "--realtime-max-alerts",
        type=int,
        default=200,
        help="Команда realtime: число последних алертов в файле.",
    )
    parser.add_argument(
        "--realtime-iterations",
        type=int,
        default=0,
        help="Команда realtime: число итераций цикла (0 = бесконечно).",
    )
    parser.add_argument(
        "--realtime-features-yaml",
        default="",
        help="Команда realtime: путь к feature_columns.yaml.",
    )
    parser.add_argument(
        "--realtime-poll-seconds",
        type=int,
        default=None,
        help="Команда realtime: override poll interval (сек).",
    )
    parser.add_argument(
        "--realtime-batch-size",
        type=int,
        default=None,
        help="Команда realtime: override batch size.",
    )
    parser.add_argument(
        "--realtime-auto-online-retrain",
        action="store_true",
        help="Команда realtime: периодически вызывать online retrain в том же loop.",
    )
    parser.add_argument(
        "--realtime-auto-online-every-iters",
        type=int,
        default=1,
        help="Команда realtime: retrain каждые N итераций (с --realtime-auto-online-retrain).",
    )
    args = parser.parse_args()
    _ensure_frozen_writable_root()

    if args.command == "check":
        print(f"Активный alert_threshold: {_read_alert_threshold():.2f}")
        return _run_script("scripts/check_env.py")

    if args.command == "bootstrap":
        return _run_script("scripts/bootstrap_environment.py")

    torch_ok, torch_err = _torch_probe()
    if not torch_ok and not args.skip_torch and not args.allow_partial and args.command in ("all", "train"):
        print("Ошибка: в этом окружении Python не удаётся загрузить torch (полный стек кейса 4 недоступен).")
        print(f"  Интерпретатор: {sys.executable}")
        if torch_err:
            print(f"  Детали: {torch_err}")
        print("Установите torch именно для этого интерпретатора, например:")
        print(f'  "{sys.executable}" -m pip install torch')
        print("Либо активируйте venv, где torch уже установлен, или используйте: --skip-torch / --allow-partial")
        return 2
    skip_torch = args.skip_torch or (not torch_ok and args.allow_partial)
    default_flows_current = _read_path_default("flows_current", "data/processed/flows.csv")
    default_flows_online = _read_path_default("flows_online_buffer", "data/processed/flows_online_buffer.csv")

    def _prepare_output_path() -> str:
        out_rel = str(getattr(args, "prepare_output", "")).strip() or default_flows_current
        return _resolve_data_path(out_rel)

    def _ensure_prepare_output_not_overwritten() -> int:
        # Перезапись prepare output разрешена по умолчанию.
        out_path = Path(_prepare_output_path())
        out_path.parent.mkdir(parents=True, exist_ok=True)
        return 0

    def _prepare_argv() -> list[str]:
        argv = ["scripts/01_prepare_data.py", "--input", _resolve_data_path(args.input)]
        if getattr(args, "prepare_output", "").strip():
            argv.extend(["--output", _resolve_data_path(args.prepare_output)])
        if getattr(args, "prepare_features_yaml", "").strip():
            argv.extend(["--features-yaml", _resolve_data_path(args.prepare_features_yaml)])
        if getattr(args, "header_bytes_npz", "").strip():
            argv.extend(["--header-bytes-npz", _resolve_data_path(args.header_bytes_npz)])
        if getattr(args, "prepare_pcap_enrichment", "").strip():
            argv.extend(["--pcap-enrichment", _resolve_data_path(args.prepare_pcap_enrichment)])
        if getattr(args, "prepare_no_cicids_normalize", False):
            argv.append("--no-cicids-normalize")
        if bool(getattr(args, "prepare_append_output", False) or getattr(args, "ingest_append_output", False)):
            argv.append("--append-output")
        return argv

    def pipeline_from_generate() -> int:
        gen_args = ["scripts/00_generate_demo_data.py", "--seed", str(args.gen_seed)]
        if args.gen_random_seed:
            gen_args.append("--random-seed")
        code = _run_script(*gen_args)
        if code != 0:
            return code
        code = _ensure_prepare_output_not_overwritten()
        if code != 0:
            return code
        code = _run_script(*_prepare_argv())
        if code != 0:
            return code
        print(
            "Demo-mode: training step is intentionally skipped in `main.py all`.\n"
            "Use `main.py baseline-train` once (CICIDS2017 baseline), then run detect/online on new data."
        )
        return _run_script("scripts/03_run_detection_batch.py")

    if args.command == "all":
        if not args.demo_mode:
            print(
                "Команда `all` больше не выполняет implicit retrain.\n"
                "Для строгого lifecycle используйте:\n"
                "  1) python main.py baseline-train --baseline-data <cicids_flows.csv> --dataset-tag cicids2017\n"
                "  2) python main.py ingest-new-data ...\n"
                "  3) python main.py detect / python main.py online ...\n"
                "Если нужен demo-only прогон, добавьте --demo-mode."
            )
            return 2
        code = _run_script("scripts/check_env.py")
        if code != 0:
            return code
        code = pipeline_from_generate()
        if code != 0:
            return code
        alerts_loc = (
            "%LOCALAPPDATA%\\IDS_ML_Project\\storage\\alerts_latest.json (дашборд читает оттуда автоматически)"
            if getattr(sys, "frozen", False)
            else "storage/alerts_latest.json"
        )
        print(f"Пайлайн завершён. Алерты: {alerts_loc}")
        if args.dashboard:
            return _run_dashboard()
        print("Дашборд: python main.py dashboard или python main.py all --dashboard")
        return 0

    if args.command == "generate":
        gen_args = ["scripts/00_generate_demo_data.py", "--seed", str(args.gen_seed)]
        if args.gen_random_seed:
            gen_args.append("--random-seed")
        return _run_script(*gen_args)
    if args.command == "ingest-new-data":
        code = _ensure_prepare_output_not_overwritten()
        if code != 0:
            return code
        return _run_script(*_prepare_argv())
    if args.command == "prepare":
        code = _ensure_prepare_output_not_overwritten()
        if code != 0:
            return code
        return _run_script(*_prepare_argv())
    if args.command == "baseline-train":
        train_args = ["scripts/02_train_all.py", "--training-profile", str(args.training_profile), "--baseline-train"]
        data_candidate = (args.baseline_data or args.train_data or "").strip()
        if data_candidate:
            train_args.extend(["--data", _resolve_data_path(data_candidate)])
        if getattr(args, "baseline_features_yaml", "").strip():
            train_args.extend(["--features-yaml", _resolve_data_path(args.baseline_features_yaml)])
        tag = (args.dataset_tag or "cicids2017").strip()
        train_args.extend(["--dataset-tag", tag])
        if args.dataset_source.strip():
            train_args.extend(["--dataset-source", args.dataset_source.strip()])
        if args.force_rebaseline:
            train_args.append("--force-rebaseline")
        if skip_torch:
            train_args.append("--skip-torch")
        return _run_script(*train_args)
    if args.command == "train":
        train_args = ["scripts/02_train_all.py", "--training-profile", str(args.training_profile)]
        if getattr(args, "train_data", "").strip():
            train_args.extend(["--data", _resolve_data_path(args.train_data)])
        if args.dataset_tag.strip():
            train_args.extend(["--dataset-tag", args.dataset_tag.strip()])
        if args.dataset_source.strip():
            train_args.extend(["--dataset-source", args.dataset_source.strip()])
        if args.force_rebaseline:
            train_args.append("--force-rebaseline")
        if skip_torch:
            train_args.append("--skip-torch")
        return _run_script(*train_args)
    if args.command == "detect":
        print(f"Старт detect: alert_threshold={_read_alert_threshold():.2f}")
        detect_args = ["scripts/03_run_detection_batch.py"]
        ddata = (getattr(args, "detect_data", "") or "").strip()
        if ddata and getattr(args, "detect_use_online_buffer", False):
            print("Предупреждение: заданы --detect-data и --detect-use-online-buffer — используется --detect-data.")
        if ddata:
            detect_args.extend(["--data", _resolve_data_path(ddata)])
        elif getattr(args, "detect_use_online_buffer", False):
            detect_args.extend(["--data", _resolve_data_path(default_flows_online)])
        if args.detect_limit is not None:
            detect_args.extend(["--limit", str(args.detect_limit)])
        if args.detect_parquet_cache:
            detect_args.append("--parquet-cache")
        if getattr(args, "detect_csv_engine", ""):
            detect_args.extend(["--csv-engine", args.detect_csv_engine])
        if getattr(args, "detect_benchmark", False):
            detect_args.append("--benchmark")
        if getattr(args, "detect_parallel_l2", False):
            detect_args.append("--parallel-l2")
        if getattr(args, "detect_packet_lstm_scores", "").strip():
            detect_args.extend(
                ["--packet-lstm-scores", _resolve_data_path(args.detect_packet_lstm_scores)]
            )
        dcr = int(getattr(args, "detect_stream_chunk_rows", 0) or 0)
        if dcr > 0:
            detect_args.extend(["--stream-chunk-rows", str(dcr)])
        if getattr(args, "detect_log_wall_time", False):
            detect_args.append("--log-wall-time")
        if getattr(args, "detect_compare_modes_report", False):
            detect_args.append("--compare-modes-report")
        if getattr(args, "detect_compare_report_path", "").strip():
            detect_args.extend(["--compare-report-path", _resolve_data_path(args.detect_compare_report_path)])
        if getattr(args, "detect_features_yaml", "").strip():
            detect_args.extend(["--features-yaml", _resolve_data_path(args.detect_features_yaml)])
        if getattr(args, "detect_demo_preset", False):
            detect_args.append("--demo-preset")
        ddw = int(getattr(args, "detect_dedup_window_seconds", 0) or 0)
        if ddw > 0:
            detect_args.extend(["--dedup-window-seconds", str(ddw)])
        if getattr(args, "detect_disable_proxy_rules", False):
            detect_args.append("--disable-proxy-rules")
        if getattr(args, "detect_new_rows_only", False):
            detect_args.append("--incremental-new-rows")
            dis = (getattr(args, "detect_incremental_state", "") or "").strip()
            if dis:
                detect_args.extend(["--incremental-state", _resolve_data_path(dis)])
        return _run_script(*detect_args)
    if args.command == "clear-online-buffer":
        cargv = ["scripts/clear_online_buffer.py"]
        cb = (getattr(args, "clear_buffer", "") or "").strip()
        if cb:
            cargv.extend(["--buffer", _resolve_data_path(cb)])
        return _run_script(*cargv)
    if args.command == "validate":
        return _run_script("scripts/validate_project_state.py")
    if args.command == "online":
        online_args = ["scripts/04_run_online_loop.py"]
        if getattr(args, "online_data", "").strip():
            online_args.extend(["--data", _resolve_data_path(args.online_data)])
        else:
            online_args.extend(["--data", _resolve_data_path(default_flows_online)])
        if getattr(args, "online_loop", False):
            online_args.append("--loop")
        if getattr(args, "online_delayed_first_tick", False):
            online_args.append("--delayed-first-tick")
        return _run_script(*online_args)
    if args.command == "realtime":
        rt_args = ["scripts/05_run_realtime_detection.py"]
        if args.realtime_data:
            rt_args.extend(["--data", _resolve_data_path(args.realtime_data)])
        else:
            rt_args.extend(["--data", _resolve_data_path(default_flows_online)])
        if args.realtime_output_alerts:
            rt_args.extend(["--output-alerts", _resolve_data_path(args.realtime_output_alerts)])
        rt_args.extend(["--max-alerts", str(int(args.realtime_max_alerts))])
        rt_args.extend(["--iterations", str(int(args.realtime_iterations))])
        if args.realtime_features_yaml:
            rt_args.extend(["--features-yaml", _resolve_data_path(args.realtime_features_yaml)])
        if args.realtime_poll_seconds is not None:
            rt_args.extend(["--poll-seconds", str(int(args.realtime_poll_seconds))])
        if args.realtime_batch_size is not None:
            rt_args.extend(["--batch-size", str(int(args.realtime_batch_size))])
        if args.realtime_auto_online_retrain:
            rt_args.append("--auto-online-retrain")
            rt_args.extend(["--auto-online-every-iters", str(int(args.realtime_auto_online_every_iters))])
        return _run_script(*rt_args)
    if args.command == "proxy":
        prox_args = [
            "--bind",
            args.proxy_bind,
            "--port",
            str(args.proxy_port),
            "--output",
            _resolve_data_path(args.proxy_output),
        ]
        if args.proxy_host_filter:
            prox_args.extend(["--host-filter", args.proxy_host_filter])
        if int(getattr(args, "proxy_max_log_mb", 0) or 0) > 0:
            prox_args.extend(["--max-log-mb", str(int(args.proxy_max_log_mb))])
            prox_args.extend(["--max-log-backups", str(int(args.proxy_max_log_backups))])
        return _run_script("scripts/06_proxy_capture.py", *prox_args)
    if args.command == "proxy-ingest":
        ndj = _resolve_data_path(args.ingest_ndjson)
        csv_out = _resolve_data_path(args.ingest_csv_out)
        if args.ingest_state_file.strip():
            code = _run_script(
                "scripts/07_ingest_proxy_ndjson.py",
                "--ndjson",
                ndj,
                "--csv-out",
                csv_out,
                "--state-file",
                _resolve_data_path(args.ingest_state_file),
                *(["--incremental"] if args.ingest_incremental else []),
                *(["--append"] if args.ingest_append else []),
            )
        else:
            code = _run_script(
                "scripts/07_ingest_proxy_ndjson.py",
                "--ndjson",
                ndj,
                "--csv-out",
                csv_out,
                *(["--incremental"] if args.ingest_incremental else []),
                *(["--append"] if args.ingest_append else []),
            )
        if code != 0:
            return code
        if args.ingest_prepare:
            old_input = args.input
            try:
                args.input = csv_out  # type: ignore[misc]
                code = _ensure_prepare_output_not_overwritten()
                if code != 0:
                    return code
                return _run_script(*_prepare_argv())
            finally:
                args.input = old_input  # type: ignore[misc]
        return 0
    if args.command == "proxy-sync-buffer":
        # Эквивалент: proxy-ingest --ingest-incremental --ingest-append
        # --ingest-state-file storage/proxy_ingest_state.json --ingest-prepare
        # --prepare-output <flows_online_buffer> --prepare-append-output
        ndj = _resolve_data_path(args.ingest_ndjson)
        csv_out = _resolve_data_path(args.ingest_csv_out)
        st_rel = (getattr(args, "ingest_state_file", "") or "").strip() or "storage/proxy_ingest_state.json"
        st = _resolve_data_path(st_rel)
        code = _run_script(
            "scripts/07_ingest_proxy_ndjson.py",
            "--ndjson",
            ndj,
            "--csv-out",
            csv_out,
            "--state-file",
            st,
            "--incremental",
            "--append",
        )
        if code != 0:
            return code
        old_input = args.input
        old_prepare = str(getattr(args, "prepare_output", "") or "")
        old_pao = bool(getattr(args, "prepare_append_output", False))
        old_iao = bool(getattr(args, "ingest_append_output", False))
        try:
            args.input = csv_out  # type: ignore[misc]
            args.prepare_output = default_flows_online  # type: ignore[misc]
            setattr(args, "prepare_append_output", True)
            setattr(args, "ingest_append_output", True)
            code = _ensure_prepare_output_not_overwritten()
            if code != 0:
                return code
            return _run_script(*_prepare_argv())
        finally:
            args.input = old_input  # type: ignore[misc]
            args.prepare_output = old_prepare  # type: ignore[misc]
            setattr(args, "prepare_append_output", old_pao)
            setattr(args, "ingest_append_output", old_iao)
    if args.command == "pcap-flows":
        if not args.pcap:
            print("Ошибка: для pcap-flows укажите --pcap path/to/file.pcap")
            return 2
        csv_out = _resolve_data_path(args.pcap_output)
        code = _run_script(
            "scripts/15_pcap_to_flow_csv.py",
            "--pcap",
            _resolve_data_path(args.pcap),
            "--output",
            csv_out,
        )
        if code != 0:
            return code
        if args.pcap_prepare:
            old_input = args.input
            try:
                args.input = csv_out  # type: ignore[misc]
                code = _ensure_prepare_output_not_overwritten()
                if code != 0:
                    return code
                return _run_script(*_prepare_argv())
            finally:
                args.input = old_input  # type: ignore[misc]
        return 0
    if args.command == "incidents-sync":
        return _run_script("scripts/08_sync_incidents.py")
    if args.command == "incidents-status":
        if not args.incident_id:
            print("Ошибка: для incidents-status укажите --incident-id")
            return 2
        return _run_script(
            "scripts/09_set_incident_status.py",
            "--incident-id",
            args.incident_id,
            "--status",
            args.incident_status,
            "--owner",
            args.incident_owner,
            "--comment",
            args.incident_comment,
            "--actor",
            args.incident_actor,
        )
    if args.command == "labels-import":
        if not args.labels_input:
            print("Ошибка: для labels-import укажите --labels-input")
            return 2
        return _run_script(
            "scripts/10_import_labels.py",
            "--input",
            _resolve_data_path(args.labels_input),
            "--output",
            _resolve_data_path(args.labels_output),
        )
    if args.command == "retrain-report":
        return _run_script(
            "scripts/11_retrain_report.py",
            "--limit",
            str(args.report_limit),
        )
    if args.command == "sandbox-eval":
        if not args.candidate_model_set_id:
            print("Ошибка: для sandbox-eval укажите --candidate-model-set-id")
            return 2
        return _run_script(
            "scripts/12_sandbox_eval.py",
            "--candidate-model-set-id",
            args.candidate_model_set_id,
            "--min-delta-f1",
            str(args.sandbox_min_delta_f1),
            "--min-precision",
            str(args.sandbox_min_precision),
        )
    if args.command == "model-approve":
        if not args.model_set_id:
            print("Ошибка: для model-approve укажите --model-set-id")
            return 2
        return _run_script(
            "scripts/13_model_approve.py",
            "--model-set-id",
            args.model_set_id,
            "--approved-by",
            args.approved_by,
        )
    if args.command == "model-deploy":
        if not args.model_set_id:
            print("Ошибка: для model-deploy укажите --model-set-id")
            return 2
        return _run_script(
            "scripts/14_model_deploy.py",
            "--model-set-id",
            args.model_set_id,
        )
    if args.command == "dashboard":
        return _run_dashboard()

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
