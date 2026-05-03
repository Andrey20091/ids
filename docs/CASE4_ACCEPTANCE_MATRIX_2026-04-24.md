# Acceptance Matrix (Case 4) — 2026-04-24

Нормативная база для трассировки в репозитории: `docs/TZ_CASE4.md` + `docs/TZ_PRODUCTION_PIPELINE.md`.

Статусы: `OK` / `PARTIAL` / `FAIL` / `BLOCKED`.

| ID | Атомарное требование ТЗ | Реализация (файл/модуль) | Проверка (команда/артефакт) | Статус | Комментарий |
|---|---|---|---|---|---|
| R-01 | IDS обнаруживает аномалии в near-real-time | `scripts/05_run_realtime_detection.py` | `python scripts/05_run_realtime_detection.py --iterations 2` | OK | Loop/chunk модель (не line-rate DPI) |
| R-02 | Гибрид RF подтвержден | `src/models/train_random_forest.py` | `artifacts/rf_model.joblib` после `main.py train` | OK | Входит в blend L2 |
| R-03 | Гибрид IF подтвержден | `src/models/train_isolation_forest.py`, `src/pipeline/level1_filter.py` | `artifacts/if_model.joblib`, `artifacts/if_agg_model.joblib` | OK | Потоковый IF + agg IF (L1) |
| R-04 | Гибрид AE подтвержден | `src/models/train_autoencoder.py` | `artifacts/ae_model.pt` | OK | Используется в L2 score |
| R-05 | Гибрид LSTM подтвержден | `src/models/train_lstm.py` | `artifacts/lstm_model.pt` | OK | Flow-sequence по умолчанию |
| R-06 | L1 -> L2 каскад подтвержден | `src/pipeline/ensemble_orchestrator.py` | `python main.py detect` | OK | `pipeline.l2_only_after_l1=true` дефолт |
| R-07 | Параллельный L2 (report mode) подтвержден | `scripts/03_run_detection_batch.py` | `python main.py detect --detect-parallel-l2` | OK | Для сравнения/отчетности |
| R-08 | Входы: агрегированные flow-метрики | `src/features/aggregate_traffic.py` | unit/integ tests + detect artifacts | OK | Применяются в L1 |
| R-09 | Входы: сырые заголовки пакетов через representation | `src/models/train_raw_header_cnn.py` | train с `hb_*` + `artifacts/raw_header_cnn.pt` | OK | CNN по header bytes |
| R-10 | Embedding представления категорий | `src/models/train_embedding_classifier.py` | `artifacts/embedding_model.pt` | OK | protocol/port embeddings |
| R-11 | CICIDS2017 поддержан | `scripts/01_prepare_data.py` | prepare на CICIDS-like CSV | OK | Canonical features merged |
| R-12 | Корпоративные размеченные дампы поддержаны | `scripts/validate_corporate_csv.py`, `run_corporate_e2e_example.cmd` | corp e2e sample | OK | Единый prepare/train/detect |
| R-13 | Online retrain каждые 15 минут (семантика тика) | `scripts/04_run_online_loop.py`, `src/online/retrain_scheduler.py` | `--loop` / `--delayed-first-tick` | OK | Тик != гарантия смены весов |
| R-14 | Online skip/reject/success задокументированы и воспроизводимы | `src/online/retrain_scheduler.py` | прогоны online сценариев + `storage/retrain_history.jsonl` | OK | Все 3 исхода подтверждаются |
| R-15 | Validation + rollback подтверждены | `src/online/retrain_scheduler.py` | `retrain_history.jsonl`, tests | OK | gate по IF/RF/deep |
| R-16 | SIEM correlation подтверждена | `src/correlation/siem_loader.py`, `correlation_rules.py` | SIEM tests + detect output | OK | json/ndjson/http |
| R-17 | Threat rating подтвержден | `src/correlation/threat_scoring.py` | alerts содержит severity/recommendation | OK | Combined score |
| R-18 | Dashboard карта/графики/рекомендации подтверждены | `dashboard/app.py`, `dashboard/components/*` | dashboard smoke + UX protocol | OK | По данным alerts/incidents |
| R-19 | Нет silent fail в критичном пути | `level1_filter.py`, `03_run_detection_batch.py`, `flows_io.py` | regression tests warnings + smoke | OK | warnings/fallback логируются |
| R-20 | CLI/help устойчив в Windows edge cases | `scripts/01_prepare_data.py`, `main.py` | help smoke tests | OK | cp1251-safe help strings |
| R-21 | Конфиг feature-set единый для train/detect/realtime | `src/features/feature_config.py`, `05_run_realtime_detection.py` | `tests/test_realtime_loop.py` | OK | merged feature config |
| R-22 | Realtime/online командная семантика согласована | `main.py`, `05_run_realtime_detection.py`, docs | realtime flags + optional auto-retrain | OK | opt-in bridge без ломки контракта |
| R-23 | Ограничения (не NGFW/line-rate/TLS decrypt) честно зафиксированы | `docs/TZ_CASE4.md`, `README.md` | docs review | OK | Без маркетинговых обещаний |

## Ключевые артефакты проверки

- `storage/alerts_latest.json`
- `storage/retrain_history.jsonl`
- `storage/qa_dashboard_ux_protocol.json` (если сгенерирован протоколом)
