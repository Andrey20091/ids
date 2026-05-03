# Полный пайплайн кейса 4 (CICIDS2017 + PCAP заголовки)

Исследовательский / демонстрационный сценарий «как в ТЗ»: не промышленный line-rate DPI; ограничения и терминология — в `docs/TZ_CASE4.md`, формальная матрица соответствия — в `docs/TZ_CASE4_TRACEABILITY.md`.

Корпоративный поток без CICIDS: см. **`run_corporate_e2e_example.cmd`** и §5 в `docs/TZ_CASE4.md`.

## 1. Данные CICIDS2017

1. Скачайте **MachineLearningCSV** (папка **TrafficLabelling**) с [CIC-IDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html) — нужны CSV **с Flow ID, IP, Timestamp, Label** (не урезанные выгрузки без IP).
2. Положите дневные `*.pcap_ISCX.csv` в **`TrafficLabelling/`** в корне проекта.
3. Срез для обучения без загрузки всех дней в RAM:

   `python scripts/17_build_cicids_training_slice.py`

   затем `python main.py prepare --input data/raw/cicids2017/cicids2017_tz_slice.csv`. Либо один полный день: `python main.py prepare --input TrafficLabelling/Monday-WorkingHours.pcap_ISCX.csv`.

4. Включён **полный числовой вектор CICFlowMeter** (`cicids2017.include_all_canonical_numeric: true` в `config/feature_columns.yaml`).

## 2. Сырые заголовки пакетов → embedding / CNN (ТЗ)

Сообщение **`WARNING: No libpcap provider available`** на Windows означает: не установлен **Npcap** (или WinPcap). Scapy всё равно **читает PCAP с диска** через `PcapReader`; предупреждение относится к **захвату с интерфейса**. Чтобы убрать предупреждение и иметь захват трафика с адаптера — установите [Npcap](https://npcap.com/) (опционально). В репозитории при импорте модулей пайплайна это сообщение подавляется в логах, чтобы не путать с ошибкой.

1. Установите `pip install scapy`.
2. Соберите NPZ с байтами IP-заголовков по потокам (тот же CSV, что для `prepare --input`):

   `python scripts/16_build_header_byte_dataset.py --pcap Friday-WorkingHours.pcap --flows-csv data/raw/cicids2017/cicids2017_friday_pcap_aligned.csv --output data/processed/header_bytes.npz --max-pcap-packets 2000000`  
   (CSV должен быть **с тем же днём**, что PCAP; `--max-pcap-packets` ускоряет огромные PCAP, `0` = читать весь файл.)

3. Подмешайте в признаки:

   `python main.py prepare --input data/raw/cicids2017/cicids2017_friday_pcap_aligned.csv --header-bytes-npz data/processed/header_bytes.npz`

4. Обучение baseline: `python main.py baseline-train --baseline-data data/processed/flows.csv --dataset-tag cicids2017` — при ненулевых `hb_*` обучится **raw_header_cnn** (`artifacts/raw_header_cnn.pt`).

## 3. Геокарта дашборда

1. Автоматически: **`python main.py bootstrap`** — ставит зависимости из `requirements.txt` / `requirements-ml.txt` и скачивает **DB-IP City Lite** `.mmdb` (без регистрации; лицензия [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), атрибуция в дашборде).
2. Вручную вместо DB-IP: [GeoLite2-City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) → `geoip.city_db` в **`config/settings.yaml`** или `GEOIP2_CITY_DB`.
3. Затем `python main.py detect` — в алерты попадут `latitude` / `longitude` (для частных `Source IP` пробуется **Destination IP**).

## 4. Online-retrain 15 мин

См. `docs/online_retrain_windows.md` и `scripts/04_run_online_loop.py`.

Важно: в online deep-retrain входят AE/LSTM/embedding; `raw_header_cnn` остаётся офлайн-моделью и обновляется через baseline-train/разрешённый policy train при наличии `hb_*`. В режиме `--loop` первая итерация по умолчанию запускается сразу, а `--delayed-first-tick` откладывает первый запуск на интервал.

`realtime` и `online` имеют разные роли: realtime только детектирует, online только переобучает. Для демонстраций можно включить auto-retrain внутри realtime (флаги `--auto-online-retrain`, `--auto-online-every-iters` в `scripts/05_run_realtime_detection.py`, либо префиксные флаги realtime в `main.py`).

После каждого train/online автоматически обновляется `storage/model_status_report.json` (и timestamp-копия в `storage/train_reports/`), что позволяет проверять готовность артефактов и последнее online-решение.

## 5. Состав L2

- RF / AE / LSTM / embedding (порт+протокол+числа) / **CNN по hb_*** (сырые байты заголовков).
- Веса blend в `scripts/03_run_detection_batch.py` (`_network_score`).

## 6. Один прогон (пятница + hb_* + train + detect)

В корне репозитория (нужны `TrafficLabelling/*.csv`, `Friday-WorkingHours.pcap`, venv): **`.\run_full_tz_friday_example.cmd`**. В PowerShell команды из текущей папки запускают с **`.\`**; при блокировке скриптов см. обход через `.cmd`. Скрипт `scripts/run_full_tz_friday_example.ps1` хранится в **ASCII**, чтобы не зависеть от кодировки/BOM в Windows PowerShell 5.1.

Для отчётной проверки различий L1-gated и parallel-l2:

`python main.py detect --detect-compare-modes-report`

JSON сравнения сохраняется в `storage/train_reports/detect_compare_<timestamp>.json`.

## 7. Extended: packet-LSTM + PCAP plaintext + agg-IF gate

Дополнительный сценарий (данные того же дня PCAP ↔ CSV): **`run_extended_tz_friday_example.cmd`**. Перед запуском подставьте реальные пути к выровненному CSV (`17_build_*` или свой aligned) и к `Friday-WorkingHours.pcap`. Порядок: NPZ для packet-LSTM → `21_train_packet_lstm.py` → `prepare` с `--prepare-pcap-enrichment` → `train` → `detect` с `--detect-packet-lstm-scores` и опционально `--detect-log-wall-time`. Подробности и ограничения TLS / line-rate — `docs/TZ_CASE4.md` §1.1, §6–7.
