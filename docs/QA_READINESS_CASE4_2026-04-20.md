# Case 4 Readiness Report (2026-04-20)

## 1) Executive summary

Статус проекта после доукрепления: **READY** для демонстрации кейса 4.

- P1-риск по dashboard UX закрыт полуавтоматическим deep walkthrough + расширенными тестами.
- P1-риск по SIEM HTTP long-run закрыт soak-сценарием с деградациями (latency/timeout/5xx/bad payload) без падений detect.
- P2-риск large-scale perf закрыт baseline-замерами на 160k строк (prepare/train/detect режимы).
- P2-риск Windows encoding закрыт рабочим UTF-8 обходом без изменения CLI контрактов.
- Формальная трассировка ТЗ собрана в `docs/TZ_CASE4_TRACEABILITY.md`.

## 2) Что изменено (файлы и цель)

- `scripts/qa_dashboard_ux_protocol.py`
  - Полуавтоматический UX-протокол для фильтров/карты/таймсерии/карточек/рекомендаций/empty-state.
  - Артефакт: `storage/qa_dashboard_ux_protocol.json`.
- `tests/test_dashboard_components_smoke.py`
  - Smoke-регрессии для компонентов дашборда на пустых/частичных данных.
- `src/correlation/siem_loader.py`
  - Добавлены опциональные HTTP retries/backoff без изменения дефолтного контракта (`retries=0`).
- `scripts/03_run_detection_batch.py`
  - Проброс `siem.retries` и `siem.retry_backoff_seconds` в HTTP SIEM loader.
- `tests/test_siem_http.py`
  - Тест retry-path и проброса новых SIEM параметров в detection batch.
- `config/settings.yaml`
  - Добавлены параметры `siem.retries` и `siem.retry_backoff_seconds` (без изменения дефолтного поведения).
- `scripts/qa_siem_http_soak.py`
  - Soak harness: локальный HTTP SIEM с деградациями + detect smoke каждые N циклов.
  - Артефакт: `storage/qa_siem_http_soak_report.json`.
- `scripts/qa_perf_baseline.py`
  - Perf baseline harness на large synthetic dataset.
  - Артефакт: `storage/qa_perf_baseline_report.json`.
- `run_utf8.cmd`, `README.md`
  - Windows UTF-8 запуск для читабельного help/log.
- `docs/TZ_CASE4_TRACEABILITY.md`, `docs/TZ_CASE4.md`, `docs/TZ_PRODUCTION_PIPELINE.md`
  - Формальная матрица соответствия ТЗ и согласование ссылок между документами.

## 3) Закрытие рисков R1..R4 (до/после + evidence)

- **R1 Dashboard deep UX (P1)**
  - До: отсутствовал завершённый deep walkthrough с фиксацией Pass/Fail.
  - После: выполнен UX protocol на 9 проверок, `9/9 PASS`.
  - Evidence:
    - `python scripts/qa_dashboard_ux_protocol.py`
    - `storage/qa_dashboard_ux_protocol.json` (`checks_failed=0`)
    - `python -m pytest tests/test_dashboard_data_connector.py tests/test_dashboard_components_smoke.py -q`
- **R2 SIEM HTTP long-run/soak (P1)**
  - До: не было длительного сценария при сетевых деградациях.
  - После: выполнен soak `120` циклов с деградациями + detect smoke.
  - Evidence:
    - `python scripts/qa_siem_http_soak.py --iterations 120 --timeout 1 --detect-every 10`
    - `storage/qa_siem_http_soak_report.json`:
      - `ok_loads=94`, `empty_or_fallback_loads=26`, `loader_exceptions=0`
      - `detect_runs=12`, `detect_exceptions=0`
      - деградации зафиксированы: `slow=15`, `http_500=14`, `bad_payload=14`
    - `python -m pytest tests/test_siem_http.py tests/test_siem_ndjson.py -q`
- **R3 Large-scale performance baseline (P2)**
  - До: отсутствовал baseline на больших объёмах.
  - После: baseline выполнен на `160000` строк + torch path на `20000`.
  - Evidence:
    - `python scripts/qa_perf_baseline.py --repeat-factor 20 --detect-limit 50000 --chunk-rows 5000 --include-torch`
    - `storage/qa_perf_baseline_report.json`
- **R4 Windows console encoding UX (P2)**
  - До: mojibake в стандартной консоли при части help/log без UTF-8 профиля.
  - После: добавлен стабильный запуск UTF-8 без изменений entrypoint-ов.
  - Evidence:
    - `run_utf8.cmd`
    - `README.md` (раздел "Windows: читаемые UTF-8 логи/help")
    - `run_utf8.cmd scripts/03_run_detection_batch.py --help` (читабельный output)

## 4) ТЗ-матрица соответствия

Подробная трассировка: `docs/TZ_CASE4_TRACEABILITY.md`.

Ключевые пункты:

- Гибрид RF/IF + AE/LSTM: **Implemented**
- L1->L2 каскад: **Implemented**
- SIEM-корреляция + threat scoring: **Implemented**
- Dashboard (таймсерия/карта/рекомендации/детали): **Implemented**
- Online-retrain (15 min semantics): **Implemented**
- Ограничения (не full NGFW, нет TLS decryption, не line-rate гарантия): **Documented**

## 5) Performance results

Источник: `storage/qa_perf_baseline_report.json`.

- Dataset: `8000` базовых строк, repeat `x20` -> `160000` строк.
- `prepare` (160k): `68.552s`, rc=0.
- `train --skip-torch` (160k): `26.246s`, rc=0.
- `detect --detect-limit 50000`: `11.768s`, rc=0.
- `detect --detect-limit 50000 --detect-parallel-l2`: `341.609s`, rc=0.
- `detect --detect-limit 50000 --detect-stream-chunk-rows 5000`: `14.115s`, rc=0.
- Torch path: `train` на `20000` строках: `91.408s`, rc=0.

Safe operating envelope для демо/лаба:

- Базовый demo: `detect-limit 2000..10000`.
- Для больших объёмов без полного L2: `detect-limit 50000`, избегать `--detect-parallel-l2` если важна скорость.
- Для ограниченной RAM/времени: использовать `--detect-stream-chunk-rows 2000..5000`.
- Для тренировки deep path на CPU: выделять отдельное окно времени; на больших наборах запускать `--skip-torch` для быстрой итерации.

## 6) Оставшиеся риски и почему не блокируют

- Не снят телеметрический baseline по RAM/CPU в этом прогоне (нет `psutil` в окружении).
  - Impact: ограничение глубины perf-метрик, но wall-clock baseline получен.
  - Почему не блокирует: для демо и учебного режима достаточно wall-clock envelope + стабильности выполнения.
- В не-UTF8 профиле Windows возможен mojibake.
  - Impact: визуальный UX логов.
  - Почему не блокирует: есть рабочий и документированный запуск `run_utf8.cmd` / `chcp 65001`.

## 7) Финальный вердикт

**READY**

Критерии DoD:

- Нет open Critical/High дефектов: **выполнено по текущему regression set**.
- P1 риски закрыты evidence: **выполнено**.
- P2 закрыты/имеют строгий workaround: **выполнено**.
- E2E `generate -> prepare -> train -> detect -> online -> dashboard`: **выполнено** (CLI + dashboard smoke).
- Полный тестовый прогон: **`49 passed`**.
- Матрица ТЗ заполнена и согласована: **выполнено**.

## 8) Следующие шаги (3-5)

- Добавить optional perf profiler с RAM/CPU метриками (`psutil`) в `qa_perf_baseline.py`.
- Вынести soak-run в CI nightly job (дольше: 30-60 min; несколько timeout/retry профилей).
- Добавить UI e2e smoke для dashboard (Playwright/Selenium) на готовом sample dataset.
- Зафиксировать отдельный "pre-demo one-click" скрипт, который запускает весь smoke и сохраняет отчёт.
