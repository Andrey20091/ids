# IDS ML Case 4 — Commission One-Pager

## Verdict

**READY**

## Why this is credible

- Независимая ревалидация BUG-001..004: `4/4 CONFIRMED fixed`.
- E2E-пайплайн на Windows подтверждён: `generate -> prepare -> train -> detect -> online -> dashboard`.
- Полный regression test run: **`49 passed`**.
- Dashboard deep UX protocol: **`10/10 PASS`**.
- SIEM soak (latency/timeout/5xx/bad payload): `120` циклов, без критичных сбоев.
- Large-scale baseline выполнен на `160000` строках (wall-clock), safe envelope зафиксирован.
- Трассировка ТЗ «требование -> реализация -> проверка -> статус» оформлена и проверена.

## Key evidence files

- `storage/qa_claims_revalidation.json`
- `storage/qa_e2e_validation.json`
- `storage/qa_dashboard_ux_protocol.json`
- `storage/qa_siem_http_soak_report.json`
- `storage/qa_perf_baseline_report.json`
- `docs/TZ_CASE4_TRACEABILITY_VERIFIED_2026-04-20.md`
- `docs/QA_FINAL_AUDIT_CASE4_2026-04-20.md`

## Practical pre-demo command

```cmd
run_pre_demo_smoke.cmd
```

Результат: `storage/pre_demo_smoke_report.json` с gate-статусом PASS/FAIL.

## Residual risks (non-blocking)

- В shell без UTF-8 возможен mojibake (обход: `run_utf8.cmd`/`chcp 65001`).
- Нет RAM/CPU метрик в baseline (есть wall-clock; для учебной защиты достаточно).
