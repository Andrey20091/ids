# Model Health And Reports

Краткий гайд по новым отчётам обучения/детекции и “паспорту моделей”.

## 1) Train report

После `python main.py baseline-train ...` (и разрешённого policy `python main.py train ...`) создаётся:

- `storage/train_reports/train_report_<timestamp>.json`

Ключевые поля:

- `dataset_path`, `dataset_rows`, `timestamp`
- `config_hash`, `git_hash`, `training_profile`, `random_state`
- `models.<name>.train_status`
- `models.<name>.artifact_exists`
- `models.<name>.metrics`
- `models.<name>.detect_participation_ready`
- `hb_signal_quality` (доля ненулевых/variance по `hb_*`)

Интерпретация:

- `detect_participation_ready=false` для `raw_header_cnn` обычно означает слабый/нулевой `hb_*` сигнал.
- `health.status`:
  - `healthy` — метрика в пределах baseline,
  - `warning` — метрики недостаточно/модель пропущена,
  - `degraded` — хуже baseline за допустимый порог.

## 2) Detect compare report

Команда:

```powershell
python main.py detect --detect-compare-modes-report
```

Файл:

- `storage/train_reports/detect_compare_<timestamp>.json`

Содержит:

- сравнение `default_l1_gated` и `parallel_l2`
- `alert_count`
- `severity_distribution`
- `threat_score_mean` / `threat_score_median`
- `l2_channel_contribution` (mean/std/non_zero)
- `hybrid_participation_check` (RF/AE/LSTM/IF участие в inference)

Важно:

- `l2_channel_contribution` считается по итоговым алертам после `threat_scoring.alert_threshold`.
- При высоком пороге часть каналов (включая `hdr`) может выглядеть как "константа на полке" из-за сильной фильтрации выборки.
- Для диагностики информативности `hb_*`/`raw_header_cnn` используйте compare-прогон с пониженным порогом (например, временно `alert_threshold: 0`) и проверяйте `hdr.std` + `hdr.is_non_constant`.

## 3) Model status report

После каждого `baseline-train`/`train` и `online` автоматически обновляется:

- `storage/model_status_report.json`
- `storage/train_reports/model_status_report_<timestamp>.json`

Ключевые поля:

- `model`
- `artifacts` (path, size, mtime, exists)
- `ready_for_detect`
- `last_train_metrics`
- `used_in_last_detect`
- `online_outcome_global` (общий итог последней online-итерации)
- `models[].last_online_outcome` (per-model, только если модель реально затронута итерацией)
- `usage_parse_error` (причина, если не удалось прочитать alerts для usage-аналитики)

## 4) Baselines deep-моделей

Файл baseline:

- `storage/model_baselines.json`

Хранит reference-метрики и допуски для:

- `autoencoder` (`val_mse_mean`)
- `lstm` (`val_f1`)
- `embedding` (`val_acc`)

Baseline инициализируется автоматически при первом валидном запуске с метрикой.

## 5) Полный smoke-прогон

```powershell
python main.py generate
python main.py prepare
python main.py baseline-train --baseline-data data/processed/flows.csv --dataset-tag cicids2017
python main.py detect --detect-compare-modes-report
python main.py detect --detect-parallel-l2
python main.py online
```

Проверьте, что появились:

- `storage/train_reports/train_report_*.json`
- `storage/train_reports/detect_compare_*.json`
- `storage/model_status_report.json`
- `storage/retrain_history.jsonl`
