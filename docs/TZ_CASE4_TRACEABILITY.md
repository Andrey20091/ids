# Трассировка соответствия ТЗ кейса 4

Документ фиксирует цепочку: **требование -> реализация -> как проверить -> статус**.

## 1) Гибрид ML (RF + IF)

- Требование: RF классификация потоков, IF для статистических аномалий и L1-агрегатов.
- Реализация: `src/models/train_random_forest.py`, `src/models/train_isolation_forest.py`, `scripts/02_train_all.py`, `src/pipeline/level1_filter.py`.
- Проверка:
  - `python main.py baseline-train --baseline-data data/processed/flows.csv --dataset-tag cicids2017 --skip-torch`
  - проверить `artifacts/rf_model.joblib`, `artifacts/if_model.joblib`, `artifacts/if_agg_model.joblib`
- Статус: **Implemented**

## 2) Глубокие модели (AE + LSTM flow + optional packet-LSTM)

- Требование: AE anomaly score; LSTM временной контекст.
- Реализация:
  - AE/LSTM(flow): `src/models/train_autoencoder.py`, `src/models/train_lstm.py`, `scripts/02_train_all.py`
  - Packet-LSTM (опция): `scripts/20_build_packet_lstm_dataset.py`, `scripts/21_train_packet_lstm.py`, `src/models/train_lstm_packets.py`
- Проверка:
  - `python main.py baseline-train --baseline-data data/processed/flows.csv --dataset-tag cicids2017` (torch path)
  - `python scripts/20_build_packet_lstm_dataset.py ...` + `python scripts/21_train_packet_lstm.py ...`
- Статус: **Implemented (packet-LSTM optional)**

## 3) Заголовки/embedding

- Требование: представление заголовков + embedding категорий.
- Реализация:
  - CNN по hb_*: `src/models/train_raw_header_cnn.py`, prepare с `--header-bytes-npz`
  - embedding protocol/port: `src/models/train_embedding_classifier.py`
- Проверка:
  - `python main.py prepare --input ... --header-bytes-npz ...`
  - `python main.py baseline-train --baseline-data data/processed/flows.csv --dataset-tag cicids2017`
- Статус: **Implemented**

## 4) L1->L2 каскад

- Требование: L1 fast filter, L2 deep/context models, режим параллельного L2.
- Реализация: `src/pipeline/ensemble_orchestrator.py`, `src/pipeline/level1_filter.py`, `scripts/03_run_detection_batch.py`.
- Проверка:
  - `python main.py detect`
  - `python main.py detect --detect-parallel-l2`
- Статус: **Implemented**

## 5) SIEM корреляция и threat scoring

- Требование: JSON/NDJSON/HTTP, IP correlation, score/severity/recommendation.
- Реализация: `src/correlation/siem_loader.py`, `src/correlation/threat_scoring.py`, `_load_siem` в `scripts/03_run_detection_batch.py`.
- Проверка:
  - `python -m pytest tests/test_siem_http.py tests/test_siem_ndjson.py -q`
  - `python scripts/qa_siem_http_soak.py --iterations 120 --timeout 1 --detect-every 10`
  - артефакт: `storage/qa_siem_http_soak_report.json`
- Статус: **Implemented (soak validated with fallback)**

## 6) Online-retrain semantics (15 min + rollback)

- Требование: периодический retrain, skip/rollback, лог истории.
- Реализация: `scripts/04_run_online_loop.py`, `src/online/retrain_scheduler.py`, `storage/retrain_history.jsonl`.
- Проверка:
  - `python main.py online`
  - `python scripts/04_run_online_loop.py --help` (фиксирует immediate first tick и `--delayed-first-tick`)
  - `python -m pytest tests/test_online_loop_config_validation.py -q`
- Статус: **Implemented**

## 6.1) Online loop first tick semantics

- Требование: однозначная семантика первого запуска в loop-режиме.
- Реализация: `src/online/retrain_scheduler.py::sleep_loop` (`initial_delay`), `scripts/04_run_online_loop.py --delayed-first-tick`.
- Проверка:
  - `python -m pytest tests/test_online_sleep_loop_semantics.py -q`
- Статус: **Implemented**

## 7) Dashboard (графики/карта/рекомендации)

- Требование: таймсерия, карта, рекомендации, устойчивость к пустым/частичным данным.
- Реализация: `dashboard/app.py`, `dashboard/components/*`, `dashboard/data_connector.py`.
- Проверка:
  - `python -m streamlit run dashboard/app.py --server.headless true --server.port 8780`
  - `python scripts/qa_dashboard_ux_protocol.py`
  - `python -m pytest tests/test_dashboard_data_connector.py tests/test_dashboard_components_smoke.py -q`
  - артефакт: `storage/qa_dashboard_ux_protocol.json`
- Статус: **Implemented (deep UX protocol passed)**

## 8) Ограничения и честные границы

- Требование: зафиксировать, что не full NGFW/TLS decryption/line-rate.
- Реализация: `docs/TZ_CASE4.md` §6, `README.md` (раздел ограничений), `docs/TZ_PRODUCTION_PIPELINE.md`.
- Проверка: ручной review docs + отсутствие TLS decryption path в коде.
- Статус: **Documented and consistent**

## 9) Realtime detect config consistency + observability

- Требование: realtime должен использовать тот же feature-config, что train/detect; критичные ошибки не должны быть silent.
- Реализация:
  - merged feature config в `scripts/05_run_realtime_detection.py` (`load_merged_feature_config`);
  - warnings вместо silent pass в `src/pipeline/level1_filter.py`, `scripts/03_run_detection_batch.py`, `src/utils/flows_io.py`;
  - безопасный fallback при сбое загрузки L1 IF-модели (в т.ч. `MemoryError`) в `src/pipeline/level1_filter.py`.
- Проверка:
  - `python -m pytest tests/test_realtime_loop.py tests/test_level1_if_alignment.py tests/test_packet_lstm_and_streaming.py -q`
  - `python scripts/05_run_realtime_detection.py --data data/processed/flows.csv --iterations 1`
- Статус: **Implemented**

## 10) Command semantics consistency (prepare/train/detect/realtime/online)

- Требование: команды не противоречат друг другу; retrain отделён от detect, но может быть опционально встроен для демо.
- Реализация:
  - `main.py` проксирует явные realtime-флаги (data/output/iterations/features/poll/batch);
  - `scripts/05_run_realtime_detection.py` добавляет opt-in `--auto-online-retrain` + `--auto-online-every-iters`;
  - `docs/TZ_CASE4.md`, `docs/TZ_PRODUCTION_PIPELINE.md`, `README.md` синхронизированы по контракту.
- Проверка:
  - `python main.py --help`
  - `python scripts/05_run_realtime_detection.py --help`
  - `python main.py realtime --realtime-iterations 1 --realtime-auto-online-retrain --realtime-auto-online-every-iters 1`
- Статус: **Implemented**
