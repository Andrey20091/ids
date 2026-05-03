# Полная документация проекта `ids-ml-project`

Версия документа: 2026-04-28  
Язык: русский  
Источник фактов: код и конфиги репозитория (`main.py`, `scripts/*`, `src/*`, `dashboard/*`, `config/*`, `tests/*`, `README.md`, `docs/*`).

---

## Часть 1. Введение

### 1.1 Что это за проект

`ids-ml-project` — это учебно-прикладная платформа для **IDS (Intrusion Detection System, система обнаружения вторжений)** на основе анализа сетевого трафика и алгоритмов машинного обучения.

Проект предоставляет:
- подготовку данных из CSV/PCAP;
- обучение набора моделей (классические + deep);
- batch-детекцию и near-realtime цикл;
- online-retrain с валидацией/откатом;
- SIEM-корреляцию;
- dashboard для оператора.

### 1.2 Какую проблему решает

Проект решает задачу практической демонстрации и проверки IDS-пайплайна:
- преобразовать сетевые события в признаки;
- обучить модели атака/норма;
- ранжировать угрозы (`threat_score`, `severity`);
- дать оператору готовые алерты, рекомендации и состояние моделей.

### 1.3 Где границы проекта (что он делает и чего не делает)

Что делает:
- работает с flow-таблицами (CICIDS-подобный CSV), опционально с PCAP;
- строит гибридный каскад L1/L2;
- пишет отчёты обучения/детекта/здоровья моделей;
- поддерживает online-переобучение по расписанию.

Что **не** делает (важные ограничения):
- не является line-rate DPI (глубокая пакетная инспекция на скорости канала);
- не декодирует TLS payload (plaintext enrichment ограничен DNS/HTTP без расшифровки);
- не гарантирует обновление весов каждый тик online (тик = попытка retrain, возможны `skipped`/`rejected`);
- не является готовым SOC-продуктом из коробки без операционной настройки.

### 1.4 Кому предназначен

- **Аналитик ИБ / SOC**: смотреть алерты, severity, рекомендации, тренды online.
- **ML-инженер**: обучать/сравнивать модели, интерпретировать метрики и деградацию.
- **Backend/MLOps инженер**: настраивать пайплайн, артефакты, планировщик, отчёты.
- **Исследователь/преподаватель**: воспроизводить сценарии, объяснять архитектуру IDS.

---

## Часть 2. Полный словарь терминов

Ниже для каждого термина: простое определение, техническое определение, место в проекте, пример.

### IDS
- **Просто:** система, которая обнаруживает подозрительную сетевую активность.
- **Технически:** программный pipeline для выделения признаков трафика и вычисления вероятности атаки.
- **Где:** весь проект.
- **Пример:** `python main.py detect`.

### SIEM (Security Information and Event Management)
- **Просто:** система централизованных событий безопасности.
- **Технически:** внешний источник событий, которые коррелируются с сетевым score.
- **Где:** `src/correlation/siem_loader.py`, `src/correlation/threat_scoring.py`.
- **Пример:** `siem.source: ndjson_file` в `config/settings.yaml`.

### APT (Advanced Persistent Threat)
- **Просто:** длительная целевая атака.
- **Технически:** сложный класс угроз; в проекте отдельная APT-модель не выделена.
- **Где:** концептуально в предметной области IDS.
- **Пример:** в текущем коде классификация через общие `attack/benign`.

### DDoS (Distributed Denial of Service)
- **Просто:** перегрузка сервиса большим трафиком.
- **Технически:** массовый аномальный/вредоносный поток, который должен получить высокий риск.
- **Где:** обучающие метки CICIDS и итоговый `threat_score`.
- **Пример:** алерт с `severity=High/Critical`.

### Exfiltration
- **Просто:** утечка данных наружу.
- **Технически:** паттерн подозрительной передачи данных; в проекте без отдельного специализированного детектора.
- **Где:** концептуально в наборе атак.
- **Пример:** рост `Flow Bytes/s` + SIEM-события могут повысить score.

### Zero-day
- **Просто:** новая уязвимость, для которой нет патча/сигнатуры.
- **Технически:** атака, которую сигнатурные системы плохо ловят; поэтому важны аномальные модели IF/AE.
- **Где:** логика аномалий (IF/AE).
- **Пример:** высокий `l2_ae_ratio` при неизвестной сигнатуре.

### Flow
- **Просто:** агрегированная запись о сетевом соединении.
- **Технически:** строка CSV с числовыми/категориальными признаками 5-tuple.
- **Где:** `data/processed/flows.csv`.
- **Пример:** одна строка с `Source IP`, `Destination Port`, `Flow Duration`.

### Packet
- **Просто:** отдельный сетевой пакет.
- **Технически:** исходный объект PCAP; используется для доп. признаков и `hb_*`.
- **Где:** `scripts/15`, `scripts/16`, `src/ingest/*`.
- **Пример:** извлечение header-bytes в `header_bytes.npz`.

### Feature
- **Просто:** числовой/категориальный признак для модели.
- **Технически:** столбец в `feature_columns.yaml`, используемый в train/inference.
- **Где:** `config/feature_columns.yaml`, `src/features/feature_config.py`.
- **Пример:** `Flow Packets/s`, `SYN Flag Count`, `hb_0`.

### Label
- **Просто:** правильный класс строки при обучении.
- **Технически:** колонка `Label`, бинаризация в `is_attack`.
- **Где:** `scripts/01_prepare_data.py`.
- **Пример:** `BENIGN` -> `is_attack=0`, остальное -> `1`.

### Inference
- **Просто:** применение модели к новым данным.
- **Технически:** прогон `run_cascade` и `score_alert`.
- **Где:** `scripts/03_run_detection_batch.py`, `src/pipeline/ensemble_orchestrator.py`.
- **Пример:** `python main.py detect`.

### Retrain
- **Просто:** повторное обучение модели на новых данных.
- **Технически:** online-итерация с валидацией baseline.
- **Где:** `src/online/retrain_scheduler.py`.
- **Пример:** `python main.py online`.

### Rollback
- **Просто:** откат к предыдущей версии модели.
- **Технически:** восстановление старого артефакта при ухудшении val-метрик.
- **Где:** `retrain_scheduler.py`.
- **Пример:** `result: rejected` в `retrain_history.jsonl`.

### RF (Random Forest)
- **Просто:** ансамбль деревьев решений.
- **Технически:** L2-классификатор `BENIGN/ATTACK`.
- **Где:** `src/models/train_random_forest.py`, `level2_deep.random_forest_predict_proba`.
- **Пример:** `l2_rf_attack_score`.

### IF (Isolation Forest)
- **Просто:** модель аномалий через изоляцию точек.
- **Технически:** используется для L1-гейтинга (особенно агрегатный IF).
- **Где:** `src/models/train_isolation_forest.py`, `src/pipeline/level1_filter.py`.
- **Пример:** `l1_triggered`.

### AE (Autoencoder)
- **Просто:** нейросеть, восстанавливающая нормальные данные.
- **Технически:** рост reconstruction error = аномалия.
- **Где:** `src/models/train_autoencoder.py`, `level2_deep.autoencoder_anomaly_score`.
- **Пример:** `l2_ae_ratio`.

### LSTM (Long Short-Term Memory)
- **Просто:** рекуррентная сеть для последовательностей.
- **Технически:** score атаки по окнам признаков потока.
- **Где:** `src/models/train_lstm.py`, `level2_deep.lstm_attack_score`.
- **Пример:** `l2_lstm_attack_score`.

### Embedding model
- **Просто:** модель, которая учит компактные представления категорий.
- **Технически:** embedding порта/протокола + numeric features.
- **Где:** `src/models/train_embedding_classifier.py`.
- **Пример:** `l2_emb_attack_score`.

### CNN (в проекте raw header CNN)
- **Просто:** сверточная сеть по байтам заголовков.
- **Технически:** классификатор по `hb_*` из PCAP.
- **Где:** `src/models/train_raw_header_cnn.py`, `level2_deep.raw_header_cnn_attack_score`.
- **Пример:** `l2_hdr_cnn_attack_score`.

### L1/L2 cascade
- **Просто:** двухуровневая схема: быстрый фильтр -> глубокий скоринг.
- **Технически:** L1 (`l1_triggered`) и L2 каналы в `run_cascade`.
- **Где:** `src/pipeline/ensemble_orchestrator.py`.
- **Пример:** `pipeline.l2_only_after_l1: true`.

### Threat score
- **Просто:** итоговый риск 0..100.
- **Технически:** сетевой score + SIEM boost, с cap=100.
- **Где:** `src/correlation/threat_scoring.py`.
- **Пример:** `threat_score=72.4`.

### Severity
- **Просто:** уровень критичности (Info..Emergency).
- **Технически:** маппинг порогов score.
- **Где:** `src/correlation/threat_scoring.py`, `scripts/03_run_detection_batch.py`.
- **Пример:** score 80 -> `Critical`.

---

## Часть 3. Архитектура системы

### 3.1 Общая схема

`raw data/pcap -> prepare -> flows.csv -> train -> artifacts -> detect/realtime -> alerts -> incidents/dashboard`

Параллельно:
- `online` периодически обновляет модели и пишет историю;
- SIEM-корреляция добавляет контекст и повышает/понижает приоритет.

### 3.2 Подсистемы и ответственность

- `main.py`: единый CLI orchestration.
- `scripts/*`: исполняемые шаги.
- `src/features`: конфиг/фичи/обогащение/flow_key.
- `src/models`: обучение моделей.
- `src/pipeline`: L1/L2 inference-каскад.
- `src/online`: retrain scheduler + gate/rollback.
- `src/correlation`: SIEM ingestion и threat scoring.
- `dashboard/*`: Streamlit UI.
- `src/utils*`: path/config/report/IO сервисные функции.

### 3.3 Взаимодействие `main.py`, `scripts`, `src`, `dashboard`

- `main.py` парсит аргументы и вызывает `scripts/*` через subprocess/loader.
- Скрипты используют `src/*` как библиотечные модули.
- Dashboard читает файлы из `storage/*`, которые создают `detect/online/governance`.

### 3.4 Потоки данных между папками

- `data/raw/*` -> вход prepare
- `data/processed/flows*.csv` -> вход train/detect/online/realtime
- `artifacts/*` -> модели и энкодеры
- `storage/*` -> alerts/incidents/retrain history/reports

### 3.5 Какие артефакты где появляются

- `data/processed/flows.csv` — `scripts/01_prepare_data.py`
- `artifacts/rf_model.joblib`, `if_model.joblib`, `if_agg_model.joblib`, `*.pt`, encoder joblib — `scripts/02_train_all.py`
- `storage/alerts_latest.json` — `scripts/03_run_detection_batch.py` / realtime
- `storage/retrain_history.jsonl` — online
- `storage/train_reports/train_report_*.json` — train
- `storage/train_reports/detect_compare_*.json` — detect compare
- `storage/model_status_report.json` — train/online status writer

---

## Часть 4. Карта репозитория (что где лежит)

### 4.1 Верхний уровень

#### `main.py`
- **Назначение:** единый CLI entrypoint.
- **Входы/выходы:** принимает команду и флаги, делегирует в `scripts/*`.
- **Кто использует:** пользователь, CI, smoke-скрипты.
- **Когда выполняется:** почти во всех основных сценариях.
- **Риски:** часть низкоуровневых флагов есть только у прямых `scripts/*.py`.

#### `README.md`
- **Назначение:** быстрый старт и рабочие сценарии.
- **Входы/выходы:** документация для людей.
- **Кто использует:** новый пользователь/ревьюер.
- **Когда:** перед первым запуском.
- **Риски:** запуск по старым командам без учёта новых guard-флагов.

#### `ids-cli.spec`
- **Назначение:** сборка исполняемого файла (PyInstaller).
- **Кто использует:** упаковка релиза.
- **Риски:** frozen-режим имеет отдельную path-семантику.

### 4.2 Папка `scripts/`

#### Базовый пайплайн
- `00_generate_demo_data.py` — генерация synthetic CSV.
- `01_prepare_data.py` — подготовка `flows.csv`, schema-check, enrichment.
- `02_train_all.py` — обучение всех моделей, формирование train reports.
- `03_run_detection_batch.py` — batch detect + SIEM + alerts.
- `04_run_online_loop.py` — online retrain one-shot/loop.
- `05_run_realtime_detection.py` — near-realtime polling + detect.

#### Источники трафика и ingestion
- `06_proxy_capture.py` — локальный HTTP-proxy capture в NDJSON.
- `07_ingest_proxy_ndjson.py` — NDJSON -> CICIDS-like CSV.
- `15_pcap_to_flow_csv.py` — PCAP -> flow CSV.
- `16_build_header_byte_dataset.py` — PCAP+CSV -> `header_bytes.npz`.

#### Governance / lifecycle
- `08_sync_incidents.py`, `09_set_incident_status.py`, `10_import_labels.py`.
- `11_retrain_report.py`, `12_sandbox_eval.py`, `13_model_approve.py`, `14_model_deploy.py`.

#### Валидация/служебные
- `check_env.py`, `bootstrap_environment.py`, `validate_project_state.py`.
- QA/smoke: `pre_demo_smoke.py`, `qa_*`, `error_resilience_smoke.py`.

### 4.3 Папка `src/` (ядро логики)

#### `src/features`
- **Назначение:** конфиг фич, enrichment, aggregate признаки.
- **Кто использует:** prepare/train/online.
- **Риски:** несовпадение feature config ломает train/detect parity.

#### `src/models`
- **Назначение:** функции обучения RF/IF/AE/LSTM/Embedding/CNN.
- **Кто использует:** `scripts/02_train_all.py`, online retrain.
- **Риски:** отсутствующий артефакт = канал не участвует в inference.

#### `src/pipeline`
- **Назначение:** L1/L2 inference.
- **Кто использует:** detect/realtime.
- **Риски:** неправильный контекст timestamp/IP искажает L1.

#### `src/online`
- **Назначение:** retrain scheduler, gate, rollback, history.
- **Риски:** малый объём/плохая вал-метрика -> частые `skipped/rejected`.

#### `src/correlation`
- **Назначение:** SIEM загрузка и корреляция, threat scoring.
- **Риски:** некорректный формат SIEM файла -> нет буста событий.

#### `src/utils*`
- **Назначение:** settings/path/report IO и health.
- **Риски:** path-policy критична для Windows/frozen режима.

### 4.4 Папки данных и отчётов

#### `config/`
- **Содержит:** `settings.yaml`, `feature_columns.yaml`, canonical numeric list.
- **Риски:** неверные значения влияют на все этапы пайплайна.

#### `data/raw/`
- **Содержит:** исходные CSV/NDJSON/корпоративные/PCAP-derived таблицы.
- **Риски:** «грязный» вход даёт ложные алерты.

#### `data/processed/`
- **Содержит:** `flows.csv`, `flows_tiny_online.csv`, perf/demo варианты, `header_bytes*.npz`.
- **Риски:** перепутать production-like и synthetic/perf файлы.

#### `artifacts/`
- **Содержит:** модели и энкодеры.
- **Риски:** ручное удаление ломает detect.

#### `storage/`
- **Содержит:** алерты, инциденты, retrain history, train/detect reports.
- **Риски:** потеря истории ухудшает трассируемость качества.

---

## Часть 5. Команды и режимы работы

> Важно: у `main.py` покрыт основной production path. Расширенные флаги некоторых скриптов доступны только через прямой запуск `scripts/*.py`.

### 5.1 Все команды из `main.py`

Список команд:
- `all` (по умолчанию), `check`, `bootstrap`, `generate`, `prepare`, `train`, `detect`, `validate`
- `online`, `realtime`
- `proxy`, `proxy-ingest`, `pcap-flows`
- `incidents-sync`, `incidents-status`, `labels-import`, `retrain-report`
- `sandbox-eval`, `model-approve`, `model-deploy`, `dashboard`

Ключевые дефолты:
- `command` по умолчанию: `all`
- `--training-profile`: `production`
- `--detect-limit`: не передаётся (скрипт detect использует свой default `100000`)
- `--realtime-iterations`: `0` (бесконечный цикл)
- `--realtime-auto-online-every-iters`: `1`
- `--incident-status`: `triaged`

#### Полный reference команд `main.py`

| Команда | Что делает | Ключевые флаги | Читает | Пишет | Когда запускать |
|---|---|---|---|---|---|
| `all` | `generate -> prepare -> train -> detect` | `--allow-partial`, `--dashboard` | `config/*` | `data/processed`, `artifacts`, `storage/alerts_latest.json` | быстрый end-to-end |
| `check` | проверка окружения | — | python env | stdout | перед первым запуском |
| `bootstrap` | установка deps и GeoIP | — | `requirements.txt`, `config/settings.yaml` | venv deps, mmdb | если окружение не готово |
| `generate` | синтетические данные | `--gen-seed`, `--gen-random-seed` | — | `data/raw/synthetic_cicids_demo.csv` | демо/тест без внешних датасетов |
| `prepare` | raw -> flows | `--input`, `--prepare-output`, `--prepare-features-yaml`, `--header-bytes-npz`, `--prepare-pcap-enrichment`, `--prepare-no-cicids-normalize` | `data/raw/*` | `data/processed/flows*.csv` | перед train/detect |
| `train` | обучение моделей | `--training-profile`, `--skip-torch`, `--allow-partial` | `flows.csv` | `artifacts/*`, train reports | после prepare |
| `detect` | batch детекция | `--detect-limit`, `--detect-parquet-cache`, `--detect-csv-engine`, `--detect-benchmark`, `--detect-parallel-l2`, `--detect-packet-lstm-scores`, `--detect-stream-chunk-rows`, `--detect-log-wall-time`, `--detect-compare-modes-report`, `--detect-compare-report-path`, `--detect-features-yaml`, `--detect-demo-preset`, `--detect-dedup-window-seconds`, `--detect-disable-proxy-rules` | `flows.csv`, `artifacts/*`, SIEM | `storage/alerts_latest.json`, compare report | production-like анализ |
| `validate` | проверка готовности state | — | config + данные + RF артефакт | exit code/stdout | pre-flight |
| `online` | online retrain | `--online-data`, `--online-loop`, `--online-delayed-first-tick` | `flows.csv`, artifacts | retrain history, обновлённые модели | дообучение во времени |
| `realtime` | near-realtime detect loop | `--realtime-data`, `--realtime-output-alerts`, `--realtime-max-alerts`, `--realtime-iterations`, `--realtime-features-yaml`, `--realtime-poll-seconds`, `--realtime-batch-size`, `--realtime-auto-online-retrain`, `--realtime-auto-online-every-iters` | append-only CSV, artifacts | alerts json | псевдо-реальное время |
| `proxy` | локальный прокси-capture | `--proxy-bind`, `--proxy-port`, `--proxy-output`, `--proxy-host-filter`, `--proxy-max-log-mb`, `--proxy-max-log-backups` | входящий HTTP трафик | NDJSON (+ ротация) | сбор тестового потока |
| `proxy-ingest` | NDJSON -> CSV (+ optional prepare) | `--ingest-ndjson`, `--ingest-csv-out`, `--ingest-state-file`, `--ingest-incremental`, `--ingest-append`, `--ingest-prepare` | proxy ndjson | raw csv и опц. flows | после proxy capture |
| `pcap-flows` | PCAP -> CSV (+ optional prepare) | `--pcap` (required), `--pcap-output`, `--pcap-prepare` | pcap | raw csv и опц. flows | при работе с pcap |
| `incidents-sync` | alerts -> incidents | — | `alerts_latest.json` | `incidents.jsonl` | governance |
| `incidents-status` | смена статуса инцидента | `--incident-id` (required), `--incident-status`, `--incident-owner`, `--incident-comment`, `--incident-actor` | incidents | incidents + actions log | triage |
| `labels-import` | импорт внешней разметки | `--labels-input` (required), `--labels-output` | входной labels csv | `labels_dataset.csv` | расширение training set |
| `retrain-report` | печать истории retrain | `--report-limit` | `retrain_history.jsonl` | stdout | мониторинг online |
| `sandbox-eval` | сравнение candidate vs active | `--candidate-model-set-id` (required), `--sandbox-min-delta-f1`, `--sandbox-min-precision` | labels + registry | `sandbox_reports.jsonl` | release gate |
| `model-approve` | approve model set | `--model-set-id` (required), `--approved-by` | registry | registry | lifecycle governance |
| `model-deploy` | deploy approved model set | `--model-set-id` (required) | registry | registry | rollout |
| `dashboard` | запуск Streamlit UI | — | `storage/*` | web UI | визуальный анализ |

### 5.2 Все отдельные scripts

#### Scripts базового контура

| Скрипт | Важные флаги (включая defaults) | Что читает/пишет | Типичные ошибки |
|---|---|---|---|
| `00_generate_demo_data.py` | `--rows` (8000), `--output` (`data/raw/synthetic_cicids_demo.csv`), `--seed` (42), `--random-seed` | пишет synthetic csv | неверный путь вывода |
| `01_prepare_data.py` | `--input` (required), `--output` (`data/processed/flows.csv`), `--features-yaml`, `--no-cicids-normalize`, `--header-bytes-npz`, `--pcap-enrichment`, `--allow-missing-columns` | raw csv -> flows | missing critical columns, bad encoding, mismatch NPZ |
| `02_train_all.py` | `--data` (`data/processed/flows.csv`), `--features-yaml`, `--skip-torch`, `--training-profile` (`production`) | flows -> artifacts + reports | no numeric features, missing data, torch unavailable |
| `03_run_detection_batch.py` | `--data`, `--output-alerts` (`storage/alerts_latest.json`), `--limit` (100000), `--no-lstm`, `--no-embedding`, `--parquet-cache`, `--csv-engine`, `--benchmark`, `--parallel-l2`, `--packet-lstm-scores`, `--stream-chunk-rows`, `--log-wall-time`, `--compare-modes-report`, `--compare-report-path`, `--features-yaml`, `--demo-preset` | flows + artifacts -> alerts | missing RF model, no data, no numeric features |
| `04_run_online_loop.py` | `--data`, `--loop`, `--delayed-first-tick` | flows + artifacts -> retrain history | invalid `online.retrain_interval_minutes` |
| `05_run_realtime_detection.py` | `--data`, `--output-alerts`, `--max-alerts` (200), `--iterations` (0), `--poll-seconds`, `--batch-size`, `--features-yaml`, `--auto-online-retrain`, `--auto-online-every-iters` (1) | append-csv + artifacts -> alerts | ошибка чтения данных, авто-online исключение в логах |

#### Scripts ingestion/governance/qa

| Скрипт | Назначение | Ключевые флаги |
|---|---|---|
| `06_proxy_capture.py` | proxy capture в NDJSON | `--bind` (127.0.0.1), `--port` (8899), `--output`, `--host-filter` |
| `07_ingest_proxy_ndjson.py` | NDJSON -> CSV | `--ndjson`, `--csv-out` |
| `08_sync_incidents.py` | sync alerts->incidents | `--alerts`, `--incidents` |
| `09_set_incident_status.py` | статус и аудит-трек | `--incident-id` (required), `--status`, `--owner`, `--comment`, `--actor`, `--actions` |
| `10_import_labels.py` | импорт labels | `--input` (required), `--output`, `--source` |
| `11_retrain_report.py` | печать retrain history | `--path`, `--limit` (10) |
| `12_sandbox_eval.py` | sandbox gate | `--candidate-model-set-id` (required), `--min-delta-f1` (0.01), `--min-precision` (0.65), paths |
| `13_model_approve.py` | approve registry entry | `--model-set-id` (required), `--approved-by`, `--registry` |
| `14_model_deploy.py` | deploy approved model | `--model-set-id` (required), `--registry` |
| `15_pcap_to_flow_csv.py` | pcap to flow csv | `--pcap` (required), `--output` |
| `16_build_header_byte_dataset.py` | pcap+flows to NPZ | `--pcap` (required), `--flows-csv` (required), `--output` |
| `17_build_cicids_training_slice.py` | сбор CICIDS slice | `--benign-csv`, `--attack-csvs`, `--output` |
| `20_build_packet_lstm_dataset.py` | подготовка packet-lstm dataset | `--pcap` (required), `--flows-csv` |
| `21_train_packet_lstm.py` | обучение packet-lstm | `--dataset` (required), `--output-model`, `--output-scores` |
| `check_env.py` | проверка зависимостей | без флагов |
| `bootstrap_environment.py` | bootstrap deps/mmdb | `--skip-pip`, `--skip-geo`, `--force-geo-settings` |
| `online_buffer_maintain.py` | архив старых строк online-буфера | `--buffer`, `--archive-dir`, `--keep-last-mb`, `--keep-last-rows`, `--execute` |
| `validate_project_state.py` | validate state | `--flows-rows` (8000) |
| `pre_demo_smoke.py` | смоук прогон | `--with-soak`, `--with-perf` |

### 5.3 Формат описания команды (шаблон и примеры)

#### Пример 1: `main.py prepare`
- **Синтаксис:** `python main.py prepare --input <raw.csv> [flags]`
- **Что делает:**
  1. Вызывает `scripts/01_prepare_data.py`.
  2. Перезаписывает указанный `--prepare-output` (или `data/processed/flows.csv` по умолчанию).
  3. При флаге `--prepare-append-output`/`--ingest-append-output` дописывает строки в output без дубля header и с проверкой схемы.
  4. Для `paths.flows_online_buffer` при превышении `buffering.flows_online_rotation_max_mb` выполняется ротация файла и инкремент `rotation_generation` в `.<stem>.meta.json` рядом с буфером; watermark (`online.watermark`) хранит то же поколение и `rows_processed`.
  5. Долгоживущие потоки: при необходимости усечь буфер без полной ротации — `python scripts/online_buffer_maintain.py` (dry-run по умолчанию; `--execute` переносит «голову» в архив и увеличивает поколение).
- **Читает/пишет:** `data/raw/*` -> `data/processed/flows.csv` (или `--prepare-output`)
- **Типичные ошибки:**
  - missing critical columns (strict default),
  - UTF-8 decode error.
- **Когда запускать:** после генерации/получения нового raw CSV.

#### Пример 2: `main.py detect`
- **Синтаксис:** `python main.py detect [--detect-demo-preset] [...]`
- **Что делает:** L1/L2 inference, SIEM correlation, записывает `alerts_latest.json`.
- **Типичные ошибки:** нет `rf_model.joblib`, нет данных.
- **Когда запускать:** после `train` или на уже обученных артефактах.

#### Пример 3: `scripts/16_build_header_byte_dataset.py`
- **Синтаксис:** `python scripts/16_build_header_byte_dataset.py --pcap ... --flows-csv ... --output ...`
- **Что делает:** строит `header_bytes.npz` (матрица `X`) для `prepare --header-bytes-npz`.
- **Ошибки:** если `header_raw_bytes.enabled=false` в feature config.

---

## Часть 6. Конфигурация

### 6.1 Полный разбор `config/settings.yaml` (ключевые блоки)

| Ключ | Тип/диапазон | Где используется | Влияние на результат | Рекомендуемое значение |
|---|---|---|---|---|
| `paths.artifacts`, `paths.processed_data`, `paths.storage`, `paths.siem_events*`, `paths.flows_current`, `paths.flows_online_buffer`, `paths.flows_baseline` | путь | train/detect/online/realtime | потоковый буфер по умолчанию для `main.py online` / `main.py realtime` — `flows_online_buffer` | не смешивать snapshot (`flows_current`) и append-буфер |
| `aggregation.resample_freq` | строка частоты (`1min`, `5min`) | `level1_filter`, online IF agg | granularity L1 чувствительности | `1min` для детального мониторинга |
| `aggregation.syn_spike_multiplier` | float > 0 | `level1_filter` | порог SYN-spike (ложноположительные/ложноотрицательные) | 2.0–3.5 в зависимости от шума |
| `aggregation.time_window_seconds` | int | в текущем коде не используется | сейчас не влияет | держать для будущей совместимости |
| `pipeline.l2_only_after_l1` | bool | detect/realtime, `run_cascade` | true: строгий каскад, false: параллельный анализ | `true` для снижения шума, `false` для диагностики |
| `pipeline.require_timestamp_for_l1` | bool | в текущем коде фактически не применяется | не влияет напрямую | оставить как документируемый флаг |
| `online.retrain_interval_minutes` | int >= 0 | online loop/scheduler | частота попытки retrain | 15 для TZ-сценария |
| `online.min_samples_retrain` | int > 0 | scheduler | предотвращает retrain на слишком маленьком срезе | подберите по объёму потока (например 200+) |
| `online.validation_size_ratio` | float (0,1) | scheduler split | стабильность val-gate | 0.2–0.3 |
| `online.if_accept_equal_f1` | bool | scheduler gate | строгость принятия IF обновления | `true` для мягкого gate |
| `online.retrain_deep_models` | bool | scheduler | включает/выключает online для AE/LSTM/embedding | `true` при наличии torch и ресурсов |
| `online.deep_models_epochs.*` | int >= 1 | scheduler | скорость/качество online deep retrain | 1–3 для online |
| `online.agg_if_validation.*`, `online.deep_validation.*` | float/bool | scheduler | политика reject/rollback | ужесточайте постепенно |
| `online.watermark.enabled`, `online.watermark.state_path` | bool / путь | online scheduler | пропуск повторной обработки хвоста; JSON с `rotation_generation` + `rows_processed` | `state_path`: `storage/online_buffer_watermark.json` |
| `buffering.flows_online_rotation_max_mb`, `buffering.flows_online_rotation_backups` | int | `01_prepare_data` append | ротация при росте append-буфера; +1 к `.<stem>.meta.json` | напр. 256 MiB, 3 бэкапа |
| `realtime.poll_interval_seconds` | float > 0 | realtime loop | задержка реакции и нагрузка CPU | 1–5 сек |
| `realtime.batch_size` | int > 0 | realtime loop | throughput и latency | 500–5000 |
| `siem.source` | enum: `json_file/ndjson_file/http` | detect | источник внешнего контекста | `ndjson_file` для локальных стендов |
| `siem.http_url`, timeout/retries/backoff | URL/int/float | siem loader | устойчивость к сетевым ошибкам | реальные retry+timeout под сеть |
| `training_profiles.development` | map | `apply_training_profile` | ускорение train для dev | использовать только для локальной отладки |
| `models.*` | map параметров | train/online | качество и производительность моделей | согласованно с данными |
| `threat_scoring.siem_boost_*`, `alert_threshold` | float | scoring/detect | уровень алертов и пороги | калибровать по validation набору |
| `geoip.city_db` | путь к `.mmdb` | geo lookup в detect | наличие геокоординат и карты | валидный локальный файл MMDB |

### 6.2 Полный разбор `config/feature_columns.yaml`

| Ключ | Тип/диапазон | Где используется | Влияние на результат | Рекомендуемое значение |
|---|---|---|---|---|
| `cicids2017.include_all_canonical_numeric` | bool | `load_merged_feature_config` | дополняет список признаков canonical CICIDS | `true` для максимальной совместимости |
| `cicids2017.canonical_exclude` | list[str] | `feature_config` | убирает нежелательные колонки | исключать только действительно шумные поля |
| `header_raw_bytes.enabled` | bool | prepare/train/detect (через merge config) | включает канал `hb_*` и raw_header_cnn | `true`, если есть PCAP/NPZ |
| `header_raw_bytes.max_packets` | int >= 1 | `header_byte_dim` | размерность `hb_*` | 16–64 по ресурсам |
| `header_raw_bytes.bytes_per_packet` | int >= 1 | `header_byte_dim` | детализация заголовка | 32–96 |
| `header_raw_bytes.column_prefix` | строка | merge config | префикс колонок (`hb_`) | не менять без миграции |
| `numeric_features` | list[str] | prepare/train/detect/realtime | основа матрицы признаков | держать согласованно с данными |
| `categorical_for_embedding.protocol_column` | строка | embedding train/inference | источник протокола для embedding | валидная колонка в flows |
| `categorical_for_embedding.port_column` | строка | embedding train/inference | источник порта для embedding | валидная колонка в flows |
| `label_column` | строка | prepare/train/online | truth label | `Label` |
| `timestamp_column` | строка | prepare/L1/reports | time-based агрегации | `Timestamp` |
| `context_columns` | list[str] | reports/context | удобство анализа и UX | Source/Destination IP/ports/protocol |

---

## Часть 7. Модели

### RF
- **Как работает:** классификация `BENIGN/ATTACK` по numeric features.
- **Обучение:** `scripts/02_train_all.py`.
- **Артефакты:** `rf_model.joblib`, `rf_label_encoder.joblib`.
- **Inference:** `l2_rf_attack_score`.
- **Проверка работы:** модель существует + score не константа в `detect_compare`.
- **Риски:** рассогласование encoder/model (в проекте добавлена защита fallback в inference).

### IF (flow/agg)
- **Как работает:** аномалия на потоке и на агрегатах.
- **Артефакты:** `if_model.joblib`, `if_agg_model.joblib`, `if_model_agg.joblib`.
- **Inference:** L1 `l1_triggered` через `level1_filter`.
- **Проверка:** присутствие IF-артефактов + поля L1 в алертах/отчётах.

### AE
- **Как работает:** reconstruction MSE.
- **Артефакт:** `ae_model.pt`.
- **Inference:** `l2_ae_ratio`, `l2_ae_mse`.
- **Проверка:** train report `ae.health`, detect contribution.

### LSTM
- **Как работает:** sequence score по окнам.
- **Артефакты:** `lstm_model.pt`, `lstm_label_encoder.joblib`.
- **Inference:** `l2_lstm_attack_score`.
- **Ограничение:** первые `seq_len-1` строк имеют нулевой score.

### Embedding classifier
- **Как работает:** embedding категорий + numeric block.
- **Артефакты:** `embedding_classifier.pt`, encoders.
- **Inference:** `l2_emb_attack_score`.
- **Health:** учитывается `val_acc`, добавлены OOV-фракции стабильности.

### raw_header_cnn
- **Как работает:** CNN по `hb_*`.
- **Артефакты:** `raw_header_cnn.pt`, encoder.
- **Inference:** `l2_hdr_cnn_attack_score`.
- **Критично:** нужен информативный `hb_*` (без `header_bytes.npz` обычно нули).
- **Ограничение:** online retrain для этого канала не реализован (offline only).

---

## Часть 8. Online и Realtime

### 8.1 Что такое online в проекте

Online — это retrain-итерация (или цикл), которая пытается обновить модели и проходит val-gate.

### 8.2 Что такое realtime

Realtime — near-realtime цикл детекции по дозаписываемому CSV.

### 8.3 Разница

- online меняет веса моделей;
- realtime считает алерты;
- опционально realtime может триггерить online (`--auto-online-retrain`).

### 8.4 Как работают вместе

Сценарий: realtime крутится постоянно, каждые N итераций делает online one-shot.

### 8.5 Семантика 15-минутного тика

`online.retrain_interval_minutes=15` = частота попытки, не гарантия обновления.

### 8.6 Где смотреть исходы

- `storage/retrain_history.jsonl` (`ok/skipped/rejected`, причины)
- `storage/model_status_report.json` (`online_outcome_global`, per-model outcomes)

---

## Часть 9. SIEM и threat scoring

### 9.1 Источники SIEM

- `json_file` (массив JSON)
- `ndjson_file` (JSON per line)
- `http` (GET endpoint, JSON-массив)

### 9.2 Корреляция

По IP и типам событий (`failed_login`, `config_change`, ...), с нормализацией колонок (`client_ip` -> `ip`, `evt` -> `event_type`).

### 9.3 Формирование threat score

`network_score` (L2 blend) -> 0..100 + SIEM boosts -> cap 100.

### 9.4 Severity

Пороги: 30/50/65/80/90 -> Low/Medium/High/Critical/Emergency (ниже — Info).

### 9.5 Рекомендации

Формируются в `threat_scoring.score_alert` с учётом severity и SIEM контекста.

---

## Часть 10. Dashboard

### 10.1 Блоки

- фильтры,
- time series,
- карта источников,
- таблица алертов/рекомендаций,
- карточка инцидента,
- пост-внедренческий мониторинг.

### 10.2 Источники данных

Главный: `storage/alerts_latest.json`, плюс `incidents.jsonl`, `incident_actions.jsonl`, `retrain_history.jsonl`, `sandbox_reports.jsonl`.

### 10.3 Фильтры

Status/Severity/IP contains/min threat score.

### 10.4 Интерпретация графиков

- time series: средний score по часам (`ts`);
- карта: geo-координаты или логическая IP-проекция.

### 10.5 Пустой экран / одна точка / один severity

- пустой alerts -> demo placeholder + warning;
- одна точка часто = один уникальный IP;
- один severity может быть реальным результатом фильтра/порога.

---

## Часть 11. Сценарии использования (минимум 12)

### 1) Быстрый smoke-check
```powershell
python main.py check
python main.py validate
```

### 2) Полный e2e demo
```powershell
python main.py all --demo-mode --allow-partial
```

### 3) Генерация + prepare вручную
```powershell
python main.py generate --gen-seed 42
python main.py prepare --input data/raw/synthetic_cicids_demo.csv
```

### 4) Обучение только классических моделей
```powershell
python main.py baseline-train --baseline-data data/processed/flows.csv --dataset-tag cicids2017 --skip-torch
```

### 5) Полное обучение с deep-моделями
```powershell
python main.py baseline-train --baseline-data data/processed/flows.csv --dataset-tag cicids2017 --training-profile production
```

### 6) Batch detect (production-like)
```powershell
python main.py detect
```

### 7) Detect compare report
```powershell
python main.py detect --detect-compare-modes-report
```

### 8) Demo detect preset (интерпретируемые демо-алерты)
```powershell
python main.py detect --detect-demo-preset --detect-compare-modes-report
```

### 9) Online one-shot
```powershell
python main.py online --online-data data/processed/flows_online_buffer.csv
```

### 10) Online loop
```powershell
python scripts/04_run_online_loop.py --loop
```

### 11) Online loop с задержкой первого тика
```powershell
python scripts/04_run_online_loop.py --loop --delayed-first-tick
```

### 12) Realtime short-loop
```powershell
python main.py realtime --realtime-iterations 3 --realtime-data data/processed/flows_online_buffer.csv
```

### 13) Realtime + periodic online bridge
```powershell
python main.py realtime --realtime-iterations 10 --realtime-auto-online-retrain --realtime-auto-online-every-iters 5
```

### 14) Proxy ingest pipeline
```powershell
python main.py proxy --proxy-bind 127.0.0.1 --proxy-port 8899
python main.py proxy-ingest --ingest-prepare
```

Инкрементальный ingest для длительных прогонов:

```powershell
python main.py proxy-ingest --ingest-ndjson data/raw/proxy_traffic.ndjson --ingest-csv-out data/raw/proxy_cicids_like.csv --ingest-state-file storage/proxy_ingest_state.json --ingest-incremental --ingest-append
```

Примечания:
- `0 alerts` в strict detect на benign-трафике — штатный результат, не ошибка runtime.
- Для демонстрации повышенной видимости алертов: `python main.py detect --detect-demo-preset`.
- Долгие команды `proxy`/`dashboard`/`realtime` корректно завершаются через `Ctrl+C`.

Soak-проверка стабильности proxy контура:

```powershell
python scripts/qa_proxy_soak.py --duration-seconds 600 --tick-seconds 30 --append-lines-per-tick 40 --source-ndjson data/raw/proxy_traffic.ndjson --report-out storage/qa_proxy_soak_report.json
```

Ключевые поля отчёта: `ingest_ok`, `detect_ok`, `realtime_ok`, `exceptions`, `silent_loss_detected`, средние времена итераций.

### 15) PCAP -> flows pipeline
```powershell
python main.py pcap-flows --pcap data/corporate_pcap/capture.pcap --pcap-output data/raw/pcap_flows_raw.csv --pcap-prepare
```

### 16) Header-bytes pipeline для raw_header_cnn
```powershell
python scripts/16_build_header_byte_dataset.py --pcap Friday-WorkingHours.pcap --flows-csv data/raw/cicids2017/cicids2017_friday_pcap_aligned.csv --output data/processed/header_bytes_friday_hb.npz
python scripts/01_prepare_data.py --input data/raw/cicids2017/cicids2017_friday_pcap_aligned.csv --header-bytes-npz data/processed/header_bytes_friday_hb.npz --output data/processed/flows_friday_hb.csv
```

### 17) Governance: инциденты
```powershell
python main.py incidents-sync
python main.py incidents-status --incident-id inc_001 --incident-status triaged --incident-comment "manual review"
```

### 18) Dashboard
```powershell
python main.py dashboard
```

---

## Примечания по ограничениям и честности

- Если в `flows.csv` `hb_*` в основном нулевые — канал `raw_header_cnn` будет слабым/формальным.
- `flows_perf_large.csv` может содержать нулевые `hb_*` в perf-only сценариях, это допустимо.
- Для production-like стабильности храните рабочий датасет отдельно и используйте отдельные имена `flows_*.csv`, чтобы не затирать эталонный набор.

