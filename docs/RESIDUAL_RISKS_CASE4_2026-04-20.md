# Residual Risks — Case 4 (2026-04-20)

## P0

- Нет открытых рисков уровня P0.

## P1

- Нет открытых рисков уровня P1 после ревалидации R1/R2.

## P2

### P2-1: Console readability in non-UTF8 profile

- Impact: снижение читаемости русскоязычных логов/help (mojibake) в дефолтном PowerShell/CMD профиле.
- Not blocking because: не влияет на функциональность, ошибки диагностичны, crash отсутствует.
- Mitigation:
  - `run_utf8.cmd <args>`
  - `chcp 65001`
  - `PYTHONUTF8=1`

### P2-2: No RAM/CPU telemetry in baseline

- Impact: ограниченная глубина perf-аналитики (только wall-clock).
- Not blocking because: для учебной демонстрации есть стабильный runtime baseline и safe envelope.
- Mitigation:
  - добавить `psutil`-телеметрию в `scripts/qa_perf_baseline.py`;
  - сохранять тренды в CI.
