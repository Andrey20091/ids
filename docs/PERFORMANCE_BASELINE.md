# Базовая производительность detect (Windows, воспроизведение)

## Датасет 50k строк

Файл: `storage/bench_detect_50k.csv` — 50 000 строк, схема как у `data/processed/flows.csv` (подготовленный пайплайном набор признаков, совместимый с `rf_model.joblib`).

Сборка файла (повтор строк исходного `flows.csv`):

```powershell
cd <корень репозитория>
python -c "import pandas as pd; from pathlib import Path; d=pd.read_csv('data/processed/flows.csv'); rep=(50000+len(d)-1)//len(d); d50=pd.concat([d]*rep,ignore_index=True).head(50000); d50.to_csv('storage/bench_detect_50k.csv', index=False)"
```

## Измерения (один прогон, `--parallel-l2`, proxy-правила выключены)

| Профиль | Команда | Wall time (50k) |
|--------|---------|-----------------|
| Полный inference (RF + IF L1/AE/LSTM/embedding/header CNN по наличию артефактов) | `python scripts/03_run_detection_batch.py --data storage/bench_detect_50k.csv --limit 0 --log-wall-time --parallel-l2 --disable-proxy-rules` | **~260 s** |
| Облегчённый (без LSTM и embedding-классификатора) | то же + `--no-lstm --no-embedding` | **~173 s** |

Окружение фиксации: локальная машина разработки; при другом CPU/GPU ожидайте пропорциональный сдвиг.

## Потоковый режим

Для больших CSV можно использовать `--stream-chunk-rows N` и при необходимости `--csv-engine pyarrow` (если установлен pyarrow).

## Soak proxy-контура (стабильность)

```powershell
python scripts/qa_proxy_soak.py --duration-seconds 3600 --tick-seconds 60 --source-ndjson data/raw/proxy_traffic.ndjson --report-out storage/qa_proxy_soak_report.json
```

Критерий: в отчёте `all_steps_ok: true` и `failure_events: 0`.
