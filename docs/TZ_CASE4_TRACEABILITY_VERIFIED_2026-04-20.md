# TZ Case 4 Traceability (Verified 2026-04-20)

Формат: `требование -> реализация -> команда проверки -> результат -> статус`.

## Core matrix

| Пункт ТЗ | Реализация (файл/модуль) | Команда проверки | Фактический результат | Статус |
|---|---|---|---|---|
| Hybrid RF/IF + AE/LSTM | `scripts/02_train_all.py`, `src/models/train_random_forest.py`, `src/models/train_isolation_forest.py`, `src/models/train_autoencoder.py`, `src/models/train_lstm.py` | `python scripts/qa_e2e_validation.py` | `train --skip-torch rc=0`, `train rc=0`; артефакты: `rf_model.joblib`, `if_model.joblib`, `if_agg_model.joblib`, `ae_model.pt`, `lstm_model.pt` | Completed |
| L1->L2 cascade + report mode | `src/pipeline/level1_filter.py`, `src/pipeline/ensemble_orchestrator.py`, `scripts/03_run_detection_batch.py` | `python scripts/qa_e2e_validation.py` | `detect rc=0`, `detect --detect-parallel-l2 rc=0`, chunked detect rc=0 | Completed |
| SIEM correlation + threat scoring | `src/correlation/siem_loader.py`, `src/correlation/threat_scoring.py`, `_load_siem` in `scripts/03_run_detection_batch.py` | `python scripts/qa_siem_http_soak.py --iterations 120 --timeout 1 --detect-every 10` | `loader_exceptions=0`, `detect_exceptions=0`; деградации обработаны (`slow/http_500/bad_payload`) | Completed |
| Dashboard: map/charts/recommendations/incident details | `dashboard/app.py`, `dashboard/components/*`, `dashboard/data_connector.py` | `python scripts/qa_dashboard_ux_protocol.py` | `checks_total=10`, `checks_failed=0`; фильтры/таймсерия/карта/рекомендации/карточка PASS | Completed |
| Online retrain 15-min semantics + validation gate | `scripts/04_run_online_loop.py`, `src/online/retrain_scheduler.py`, `config/settings.yaml` | `python scripts/qa_e2e_validation.py`; `python scripts/qa_claims_revalidation.py` | `main.py online rc=0`, в `retrain_history_last` есть `retrain_interval_minutes=15`; BUG-004 validation CONFIRMED | Completed |
| Ограничения (no TLS decrypt, no line-rate SLA) задокументированы | `docs/TZ_CASE4.md`, `README.md`, `docs/TZ_PRODUCTION_PIPELINE.md` | Док-ревью + smoke evidence | Ограничения согласованы между документами, явные disclaimers присутствуют | Completed |

## Related evidence artifacts

- `storage/qa_claims_revalidation.json`
- `storage/qa_e2e_validation.json`
- `storage/qa_dashboard_ux_protocol.json`
- `storage/qa_siem_http_soak_report.json`
- `storage/qa_perf_baseline_report.json`
