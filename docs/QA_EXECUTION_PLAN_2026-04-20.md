# QA Execution Plan (2026-04-20)

## Environment snapshot

- OS: Windows 10.0.26200
- Python: `3.14.3` (system + `.venv`)
- Pip: `25.3`
- Key deps import check: `sklearn 1.8.0`, `torch 2.11.0+cpu`, `streamlit 1.56.0`, `pandas 3.0.2`

## Command plan

1. Context/docs audit:
   - read `README.md`, `docs/TZ_CASE4.md`, `docs/TZ_PRODUCTION_PIPELINE.md`, `docs/TZ_CASE4_TRACEABILITY.md`, `docs/QA_READINESS_CASE4_*.md`, `config/*.yaml`
2. Bug re-validation:
   - `python scripts/qa_claims_revalidation.py`
3. E2E re-validation:
   - `python scripts/qa_e2e_validation.py`
4. R1 dashboard:
   - `python scripts/qa_dashboard_ux_protocol.py`
   - `python -m pytest tests/test_dashboard_data_connector.py tests/test_dashboard_components_smoke.py -q`
5. R2 SIEM soak:
   - `python scripts/qa_siem_http_soak.py --iterations 120 --timeout 1 --detect-every 10`
6. R3 performance:
   - `python scripts/qa_perf_baseline.py --repeat-factor 20 --detect-limit 50000 --chunk-rows 5000 --include-torch`
7. R4 UTF-8 workflow:
   - `python scripts/03_run_detection_batch.py --help`
   - `run_utf8.cmd scripts/03_run_detection_batch.py --help`
8. Quality gate:
   - `python -m pytest tests -q --tb=short`
9. Pre-demo one-click:
   - `run_pre_demo_smoke.cmd`
