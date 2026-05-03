# Final QA Audit — ids-ml-project (2026-04-20)

## 1. Executive summary

1. Проведена независимая ревалидация заявленных claims и исправлений, без опоры на прошлый verdict.
2. BUG-001..004 проверены повторно через `repro -> check -> evidence`; все 4 имеют статус **CONFIRMED**.
3. Полный E2E (`generate -> prepare -> train -> detect -> online -> dashboard`) воспроизводим, `overall_status=PASS` (`storage/qa_e2e_validation.json`).
4. P1-риск dashboard UX закрыт: протокол теперь фактически **10/10 PASS** (ранее декларировалось 9/9; это обновлённое фактическое состояние).
5. P1-риск SIEM HTTP soak закрыт: 120 циклов с деградациями, `loader_exceptions=0`, `detect_exceptions=0`.
6. P2-риск large-scale perf подтверждён baseline-замерами на 160k (wall-clock), без SLA-обещаний.
7. P2-риск Windows encoding частично закрыт через рабочий UTF-8 workflow: `run_utf8.cmd` и `run_pre_demo_smoke.cmd`.
8. Полный тестовый прогон зелёный: `49 passed`.
9. Трассировка ТЗ проверена и оформлена в верифицированной матрице.
10. Финальный статус по текущему стенду: **READY**.

## 2. Что подтверждено / что опровергнуто из прошлых claims

### Confirmed

- P1/P2 claims по R1..R4 — подтверждены артефактами в `storage/*.json`.
- BUG-001..004 — подтверждены (`storage/qa_claims_revalidation.json`).
- E2E готовность — подтверждена (`storage/qa_e2e_validation.json`).
- Test suite green — подтверждена (`49 passed`).
- Traceability по ТЗ — подтверждена и дополнена верифицированной матрицей.

### Rejected / Not confirmed

- **Нет отклонённых claims** по критичным пунктам.
- Уточнение: формулировка "UX 9/9" устарела; фактически сейчас **10/10 PASS** из-за добавленной проверки fallback-ветки. Это не дефект, а обновление объёма протокола.

## 3. Матрица BUG-001..N

| BUG | Severity | Статус | Evidence | Остаточный риск |
|---|---|---|---|---|
| BUG-001: help crash/encoding on Windows | High | **CONFIRMED fixed** | `scripts/03_run_detection_batch.py --help` => `rc=0`, без `UnicodeEncodeError` (`storage/qa_claims_revalidation.json`) | В non-UTF8 shell возможен mojibake отображения (не crash) |
| BUG-002: UTF-16 silent corruption in prepare | Critical | **CONFIRMED fixed** | `prepare` на UTF-16 => `rc=1` + явная ошибка UTF-8; hash `flows.csv` до/после совпал | Нет |
| BUG-003: tiny train uncontrolled traceback | High | **CONFIRMED fixed** | `prepare` tiny -> `train --skip-torch` => `rc=1` с контролируемым текстом "requires at least 2 rows", без raw traceback | Нет |
| BUG-004: no validation for `online.retrain_interval_minutes` | High | **CONFIRMED fixed** | `04_run_online_loop.py` с bad config => `rc=1`, сообщение о некорректном `retrain_interval_minutes` | Нет |

## 4. E2E статус и ключевые артефакты

- Отчёт: `storage/qa_e2e_validation.json` -> `overall_status=PASS`.
- Проверенные шаги:
  - `generate`, `prepare`, `train --skip-torch`, `train`, `detect` (normal / parallel-l2 / chunked), `online`.
  - `dashboard` smoke: Streamlit стартует, `Local URL` получен.
- Артефакты моделей на месте:
  - `rf_model.joblib`, `if_model.joblib`, `if_agg_model.joblib`, `ae_model.pt`, `lstm_model.pt`, `embedding_classifier.pt`.
- Выходы:
  - `storage/alerts_latest.json` валиден как JSON-массив.
  - `storage/retrain_history.jsonl` обновляется; последняя запись отражает валидируемый результат (`rejected` допустим по gate-логике).

## 5. Результаты по R1..R4 (до/после + evidence)

- **R1 Dashboard UX (P1)**  
  До: не было завершённого deep walkthrough.  
  После: `10/10 PASS` в `storage/qa_dashboard_ux_protocol.json`; доп. smoke тесты dashboard проходят.

- **R2 SIEM HTTP soak (P1)**  
  До: не было long-run проверки на деградациях.  
  После: `storage/qa_siem_http_soak_report.json` -> `120` итераций, `loader_exceptions=0`, `detect_exceptions=0`.

- **R3 Large-scale performance (P2)**  
  До: отсутствовал baseline на больших объёмах.  
  После: `storage/qa_perf_baseline_report.json` с реальными wall-clock метриками на `160000` строк.

- **R4 Windows UTF-8 UX (P2)**  
  До: mojibake в типичном shell-профиле.  
  После: рабочий documented workflow `run_utf8.cmd`; help/readability подтверждён через wrapper.

## 6. Coverage C->J

Принята практическая декомпозиция C->J как контрольных зон релиз-аудита.

| Зона | Объект покрытия | Статус | Почему |
|---|---|---|---|
| C | BUG re-validation | Completed | BUG-001..004 подтверждены evidence |
| D | E2E сценарий | Completed | Полный pipeline PASS |
| E | Dashboard UX | Completed | UX protocol + dashboard tests PASS |
| F | SIEM soak resilience | Completed | Деградации пройдены, исключений нет |
| G | Performance baseline | Completed | 160k baseline + safe envelope |
| H | Windows encoding UX | Completed | UTF-8 workaround documented and tested |
| I | TZ traceability | Completed | Верифицированная матрица собрана |
| J | Regression quality gate | Completed | `pytest tests -q` -> `49 passed` |

## 7. Performance baseline (контекст, цифры, ограничения)

Контекст: synthetic `8000` строк повторён `x20` -> `160000`.

- `prepare`: `73.019s`
- `train --skip-torch`: `29.342s`
- `detect --detect-limit 50000`: `12.433s`
- `detect --detect-limit 50000 --detect-parallel-l2`: `450.976s`
- `detect --detect-limit 50000 --detect-stream-chunk-rows 5000`: `13.575s`
- `train` (torch path, 20k): `87.659s`

Ограничения интерпретации:
- метрики RAM/CPU не собирались (нет `psutil`), только wall-clock;
- baseline не является SLA и не должен трактоваться как line-rate гарантия.

## 8. ТЗ-traceability

- Коротко: ключевые пункты ТЗ (hybrid stack, L1->L2, SIEM scoring, dashboard, online 15-min semantics, ограничения) подтверждены на коде и командах.
- Полный файл: `docs/TZ_CASE4_TRACEABILITY_VERIFIED_2026-04-20.md`.

## 9. Residual risks (P0/P1/P2) и workaround

- **P0:** не выявлено.
- **P1:** не выявлено незакрытых.
- **P2-1:** в non-UTF8 shell остаётся риск нечитаемой кириллицы.  
  Workaround: `run_utf8.cmd ...` или `chcp 65001`, `PYTHONUTF8=1`.
- **P2-2:** нет RAM/CPU профиля в baseline.  
  Workaround: использовать wall-clock envelope; при необходимости добавить `psutil`.

## 10. Final verdict

**READY**

Обоснование: open Critical/High не выявлены, ключевые claims подтверждены, E2E воспроизводим, тесты зелёные, traceability непротиворечива.

## 11. Release gate recommendation

**Можно выпускать** в учебную демонстрацию на текущем стенде.  
Условие good practice: запускать pre-demo smoke (`run_pre_demo_smoke.cmd`) непосредственно перед защитой.

## 12. Next actions (приоритет)

1. Добавить RAM/CPU telemetry в `qa_perf_baseline.py` (`psutil`).
2. Ночной CI job для soak (`30-60` мин, несколько retry/timeout профилей).
3. Автоматизировать UI e2e smoke (Streamlit front checks).
4. Зафиксировать baseline thresholds и trend-history в CI артефактах.
5. Вынести "commission bundle" (report + one-pager + latest JSON evidences) в отдельный каталог архивации.

## Что сказать комиссии за 30 секунд

Проект независимым аудитом подтверждён как READY для демонстрации кейса 4.  
Мы повторно проверили все критичные баги BUG-001..004, и каждый закрыт с воспроизводимыми доказательствами.  
Полный pipeline от генерации данных до online-retrain и dashboard запускается стабильно на Windows-стенде.  
Риски по UX дашборда и SIEM устойчивости закрыты отдельными протоколами и soak-тестом с сетевыми деградациями.  
Производительность на больших объёмах измерена, границы применимости задокументированы без завышенных SLA-обещаний.  
Требования ТЗ трассированы до кода и команд проверки в отдельной верифицированной матрице.  
Перед выступлением достаточно запустить one-click pre-demo smoke для повторного подтверждения готовности.
