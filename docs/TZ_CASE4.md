# Кейс 4 (гибридная IDS): соответствие ТЗ и реализации

Этот документ — **единый источник правды**, как формулировки учебного ТЗ сопоставлены с кодом и где явно зафиксированы ограничения. Противоречий между README, пайплайном и реализацией быть не должно.

---

## 1. Модели и уровни L1 / L2

| ТЗ (суть) | Реализация | Где |
|-----------|------------|-----|
| Isolation Forest + статистика | IF на признаках потока + **IF на минутных агрегатах** (`if_agg_model.joblib`); отдельный proxy **val-gate** agg в online-retrain | `scripts/02_train_all.py`, `level1_filter`, `retrain_scheduler` |
| Random Forest | Бинарная/многоклассовая классификация по числовым признакам | `train_random_forest` |
| Autoencoder | Обучение на BENIGN, anomaly score по реконструкции | `train_autoencoder` |
| LSTM, «временной контекст» | **По умолчанию:** скользящие окна по строкам CSV. **Опция:** LSTM по **K пакетам** на поток (PCAP) + join по `flow_key` | `train_lstm` / `train_lstm_packets` |
| Заголовки / embedding | Сырые байты IP-заголовков → **1D CNN** (сверточное представление последовательности байт); отдельно **embedding** протокола и порта + числовой вектор | `train_raw_header_cnn`, `train_embedding_classifier` |

### 1.1 LSTM по строкам потоков (дефолт) и опционально по пакетам PCAP

**Базовый режим (без изменений контракта `flows.csv`):** «временной контекст» — **окна подряд идущих строк потоков** по `Timestamp`, см. `sequence_length` в `config/settings.yaml` → `models.lstm`.

**Расширенный режим (опционально):** LSTM по **первым K пакетам** внутри каждого 5-tuple потока — отдельный артефакт `artifacts/lstm_packets_model.pt`, датасет из `scripts/20_build_packet_lstm_dataset.py`, обучение `scripts/21_train_packet_lstm.py`, скоринг в детекции через NPZ `flow_keys` + `scores` и флаг **`--packet-lstm-scores`** у `scripts/03_run_detection_batch.py` / `main.py detect --detect-packet-lstm-scores`. Признак на пакет — фиксированный вектор заголовков IP/TCP/UDP (длина, TTL, флаги, порты), **без payload приложения и без TLS**.

Ограничения packet-LSTM: большие PCAP требуют `--max-pcap-packets`; ключ потока должен совпадать с `flow_key` в CSV (см. `src/features/flow_key.py`, `src/ingest/pcap_packet_sequences.py`).

### 1.2 «Embedding слоёв для заголовков» в терминах ТЗ

В тексте ТЗ встречается формулировка про embedding заголовков. В коде:

- **Сырые байты заголовков** (hb_*) проходят через **сверточную сеть по байтовой последовательности** (`raw_header_cnn`). В контексте глубокого обучения это **обучаемое представление (representation)** последовательности байт; по смыслу кейса это принимается как **эквивалент постановки «embedding для сырых заголовков»** наряду с классическим token/byte embedding + MLP.

- Отдельный **tabular embedding** используется для **категориальных полей протокол/порт** (`embedding_classifier`), не для hb_*.

Итого: **CNN по байтам заголовков + categorical embeddings для порта/протокола** — зафиксированная терминология кейса 4 в этом репозитории.

### 1.3 Isolation Forest: поток vs минутные агрегаты L1

| Файл | Обучение | Применение |
|------|-----------|------------|
| `artifacts/if_model.joblib` | Числовые признаки **потока** | Не для L1; online-retrain с val-gate по `is_attack`. |
| **`artifacts/if_agg_model.joblib`** (каноническое имя) | Только **`make_aggregate_numeric_frame`** / те же колонки, что у `aggregate_flows_by_time` на L1 | **Приоритет** для IF на L1 (`level1_filter`). |
| `artifacts/if_model_agg.joblib` | То же обучение | **Копия** для обратной совместимости (пишется при `02_train_all` и успешном online agg-retrain). |

Приоритет загрузки на L1: `if_agg_model.joblib` → `if_model_agg.joblib` → `if_model.joblib`.

Если потоковый IF применить к матрице агрегатов нельзя (несовпадение колонок), ветка IF на L1 отключается с **UserWarning**.

**Val-gate agg-IF в online-retrain** (отдельно от потокового IF): proxy **F1** между предсказанием IF «-1» и меткой **`max(is_attack)` по минутному бакету** на валидационных окнах; настройки `online.agg_if_validation` в `config/settings.yaml`; лог поля `if_aggregate`, при отклонении — без записи новой модели. Метод **proxy**: не истинная разметка аномалий, а согласование с наличием атакующих потоков в том же временном окне.

Полное переобучение с нуля — по-прежнему `scripts/02_train_all.py`.

### 1.4 «HTTP-последовательности» и DNS-туннелирование — трактовка маркетингового ТЗ

Формулировки кейса про «последовательности HTTP» и «DNS-туннелирование» в полном DPI **не реализованы**: нет расшифровки TLS и построчной инспекции содержимого приложения.

В репозитории это **приближено на уровне табличного потока** и **опционально из PCAP** (не line-rate DPI):

- **HTTP:** колонки URI в CSV (`http_sequence_features`) — эвристики длины/частоты; **plaintext TCP/80**: дополнительные признаки из PCAP через `prepare --pcap-enrichment` → `pcap_http_*` (`src/ingest/pcap_plaintext_features.py`). **HTTPS/TLS не декодируется.**
- **DNS:** колонка `dns_qname` в CSV или **UDP/53 в PCAP** — max длина/энтропия QNAME в колонках `pcap_dns_*`.

Итого для отчёта: **flow-level / plaintext метаданные**, не полноценный DPI TLS.

---

## 2. Каскад L1 → L2 и режим «отчёта»

| Параметр | Значение по умолчанию | Смысл |
|----------|------------------------|------|
| `pipeline.l2_only_after_l1` | `true` | L2-модели считают вклад только для потоков, прошедших L1-триггер (SYN-спайки / окна). **Меньше ложных срабатываний L2 на «тихом» фоне**, но возможны пропуски, если L1 слишком строгий. |
| то же = `false` | демо / отчёт | **Параллельный скоринг L2** для всех строк: выше нагрузка и больше кандидатов в алерты; удобно для отчётности и сравнения моделей. |

CLI без правки YAML: `python scripts/03_run_detection_batch.py --parallel-l2` или `python main.py detect --detect-parallel-l2`.

---

## 3. Online-retrain (каждые 15 минут)

- **Policy lifecycle:** baseline должен быть обучен один раз на CICIDS2017 (`baseline-train`) с созданием `storage/baseline_manifest.json`.  
  При `training_policy.require_baseline_before_online: true` online без валидного manifest возвращает `skipped` с причиной `baseline policy gate`.
- **Запрет full retrain на новых данных:** при `training_policy.prohibit_full_retrain_on_new_data: true` команда `train` без режима baseline блокируется и предлагает использовать online.

- **Таймер 15 минут** — это интервал **запуска попытки** дообучения (`online.retrain_interval_minutes`), см. `scripts/04_run_online_loop.py` и `sleep_loop`. Это **не** гарантия обновления весов на каждом тике.

- **Пропуск итерации:** если строк в `flows.csv` меньше `online.min_samples_retrain`, в лог пишется `status: skipped` с причиной (см. `retrain_history.jsonl`).

- **Откат (IF/RF):** если валидационный F1 не улучшает baseline — модель откатывается к предыдущей копии.
- **RF online/offline контракт:** online обновляет `rf_model.joblib` вместе с синхронным `rf_label_encoder.joblib` в бинарном контракте `BENIGN/ATTACK`; detect использует этот же encoder для корректной интерпретации `predict_proba`.

- **Deep-модели:** при `online.deep_validation.enabled: true` откат по val-метрикам (AE MSE, LSTM F1, embedding acc) — см. `src/online/retrain_scheduler.py`. `raw_header_cnn` в online-контур не входит и переобучается офлайн через `scripts/02_train_all.py` при наличии `hb_*`.

- **Feature-config consistency:** online использует тот же merged feature-config (`load_merged_feature_config`), что train/detect/realtime; рассинхрон списков numeric/hb_* между режимами исключается.

- **IF на агрегатах L1:** при успешном принятии потокового IF кандидат **agg-IF** проходит **отдельный val-gate** (см. §1.3); в логе `if_aggregate`, артефакты `if_agg_model.joblib` + копия `if_model_agg.joblib`.

В каждой записи `retrain_history.jsonl` фиксируются `retrain_interval_minutes`, `min_samples_retrain_threshold`, `deep_validation_enabled`, текстовое поле `iteration_semantics` (одна строка лога = одна попытка дообучения; интервал 15 минут — частота тика, не гарантия обновления весов). В loop-режиме `scripts/04_run_online_loop.py --loop` первая итерация выполняется сразу (immediate first tick); опция `--delayed-first-tick` включает паузу до первого запуска.

### 3.1 Realtime vs Online (контракт команд)

- `realtime` (`scripts/05_run_realtime_detection.py`, `main.py realtime`) — near-realtime детекция чанками в цикле.
- `online` (`scripts/04_run_online_loop.py`, `main.py online`) — retrain one-shot или loop с валидацией/rollback.
- Для стендового сценария доступен опциональный мост: `realtime --auto-online-retrain --auto-online-every-iters N` (или через `main.py` флаги `--realtime-auto-online-retrain`, `--realtime-auto-online-every-iters`). По умолчанию выключено, чтобы не смешивать роли команд.

### 3.2 Train/Detect/Health отчёты

- После `train` формируется воспроизводимый отчёт `storage/train_reports/train_report_<timestamp>.json` (датасет, параметры, артефакты, метрики, hb-signal quality).
- После `train` и `online` обновляется `storage/model_status_report.json` (+ timestamp-копия): готовность моделей к detect, глобальный итог online (`online_outcome_global`), per-model online outcome (только для реально затронутых моделей), участие в последнем detect.
- Для сравнения режимов детекции есть `storage/train_reports/detect_compare_<timestamp>.json` (`python main.py detect --detect-compare-modes-report`), включая проверку фактического участия каналов RF/AE/LSTM/IF.

---

## 4. SIEM и корреляция

- По умолчанию — **демонстрационный JSON** (`paths.siem_events`). Формат строк событий: минимум поля **`ip`**, **`event_type`** (см. `src/correlation/correlation_rules.py`).

- Поддерживается **`siem.source: ndjson_file`** — один JSON-объект на строку (частый формат экспорта логов). Пример: `storage/siem_events_sample.ndjson`.

- **`http`** — GET JSON-массива по `siem.http_url`.

Нормализация имён: в NDJSON допускаются поля `client_ip` → приводится к `ip`, `evt` → `event_type` (см. `siem_loader`).

---

## 5. Корпоративные размеченные дампы

Минимальный воспроизводимый сценарий: каталог **`data/raw/corporate_example/`**, пример CSV и проверка колонок **`python scripts/validate_corporate_csv.py --input ...`**. Далее — тот же **`main.py prepare --input ...`**, что и для CICIDS-подобных схем.

**Полный цикл без ручных правок (prepare → train → detect):** файл **`labeled_flows_e2e.csv`** (~150 строк, опционально пересборка `python scripts/build_corporate_e2e_dataset.py`), затем из корня проекта **`run_corporate_e2e_example.cmd`** (или те же команды вручную с `--skip-torch` для train, если torch не нужен для демо).

---

## 6. Ограничения платформы и честные обещания

Исследовательская / демонстрационная платформа **полного пайплайна** кейса 4, не commodity **line-rate** NGFW.

| Обещаем в рамках кода / доков | Не обещаем как у промышленного NGFW |
|-------------------------------|-------------------------------------|
| Гибрид RF/IF/AE/LSTM/embedding/CNN + packet-LSTM при наличии артефактов | Sub-second latency на любом канале и полной скорости линии |
| Каскад L1→L2, SIEM-корреляция, GeoIP при MMDB | TLS decryption и инспекция содержимого приложений |
| Опциональный **streaming batch** detect (`--stream-chunk-rows`, `--log-wall-time`) для измерения wall-clock по чанкам | Line-rate mirroring 40G+ без специализированного железа |
| Отдельный proxy **val-gate для agg-IF** в online-retrain | Истинная разметка «аномалия минутного окна» без привязки к `is_attack` |

Подробнее по extended-сценарию (Friday + packet-LSTM + PCAP enrichment): `docs/TZ_PRODUCTION_PIPELINE.md` и **`run_extended_tz_friday_example.cmd`**.

---

## 7. Расширения (extended case) — краткий чеклист

1. **Packet-LSTM:** `scripts/20_build_packet_lstm_dataset.py` → `scripts/21_train_packet_lstm.py` → `data/processed/packet_lstm_scores.npz` → detect `--packet-lstm-scores`.
2. **PCAP plaintext признаки в prepare:** `main.py prepare ... --prepare-pcap-enrichment path.pcap` (или `01_prepare_data.py --pcap-enrichment`).
3. **Agg-IF gate:** `online.agg_if_validation` в `settings.yaml`; лог `if_aggregate` в `retrain_history.jsonl`.

---

## Связанные файлы

| Файл | Назначение |
|------|------------|
| `README.md` | Обзор, ограничения, ссылки |
| `docs/TZ_CASE4_TRACEABILITY.md` | Матрица соответствия: требование -> реализация -> проверка |
| `docs/TZ_PRODUCTION_PIPELINE.md` | Полный «продакшен»-пейзаж CICIDS + PCAP |
| `config/settings.yaml` | Пороги, SIEM, pipeline, online |
