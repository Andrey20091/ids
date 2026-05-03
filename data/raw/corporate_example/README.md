# Пример корпоративного размеченного экспорта

- **`labeled_flows_minimal.csv`** — минимальный набор строк для проверки колонок и `prepare`.
- **`labeled_flows_e2e.csv`** (~150 строк) — достаточный объём для демо RF/IF и детекции.

Пересборка демо-файла:

```powershell
python scripts/build_corporate_e2e_dataset.py
```

Полный сценарий из корня репозитория (Windows, как в репозитории): **`run_corporate_e2e_example.cmd`** — validate → prepare → `train --skip-torch` → `detect --detect-limit 500`.

## Шаги вручную

1. Проверка колонок:

   ```powershell
   python scripts/validate_corporate_csv.py --input data/raw/corporate_example/labeled_flows_e2e.csv
   ```

2. Подготовка признаков (выход по умолчанию — `data/processed/flows.csv`, см. `config/settings.yaml`):

   ```powershell
   python main.py prepare --input data/raw/corporate_example/labeled_flows_e2e.csv
   ```

3. Обучение и детекция (без torch для скорости):

   ```powershell
   python main.py train --skip-torch
   python main.py detect --detect-limit 500
   ```

Для **строгого baseline** на CICIDS2017 используйте `baseline-train` с `--dataset-tag cicids2017` и отдельным подготовленным CSV (см. корневой `README.md` и `docs/TZ_CASE4.md`).

Реальный корпоративный дамп должен содержать те же **ключевые** поля, что и MachineLearningCSV CICIDS (Flow ID, Timestamp, IP, порты, метки и числовые метрики потока). Недостающие числовые колонки `prepare` дополнит нулями до схемы из `config/feature_columns.yaml`. Колонки вроде URI/DNS (`http_request_uri`, `dns_qname` и др. по конфигу) усиливают HTTP/DNS эвристики (`src/features/`).

Подробнее: `docs/TZ_CASE4.md` §5.
