# Online-retrain каждые 15 минут (Windows, ТЗ кейс 4)

В `config/settings.yaml` задано `online.retrain_interval_minutes: 15`. Процесс `main.py online`
запускает одну итерацию; непрерывный цикл — `scripts/04_run_online_loop.py` (тот же интервал из настроек).

Важно для строгого lifecycle:
- online допускается только после baseline-обучения на CICIDS2017;
- baseline должен создать `storage/baseline_manifest.json`;
- при включённом `training_policy.require_baseline_before_online` запуск online без manifest будет `skipped` с явной причиной.

## Вариант A: Планировщик заданий (рекомендуется)

1. Укажите полный путь к интерпретатору venv, например:
   `C:\Users\<you>\Desktop\ids-ml-project\.venv\Scripts\python.exe`
2. Рабочая папка: корень проекта `ids-ml-project`.
3. Действие: программа — `python.exe` выше; аргументы: `main.py online`
4. Триггер: повторять каждые **15 минут**, без ограничения срока.

В **PowerShell от администратора** (подставьте свои пути):

```powershell
$action = New-ScheduledTaskAction -Execute "C:\path\to\ids-ml-project\.venv\Scripts\python.exe" `
  -Argument "main.py online" -WorkingDirectory "C:\path\to\ids-ml-project"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration ([TimeSpan]::MaxValue)
Register-ScheduledTask -TaskName "IDS_ML_OnlineRetrain" -Action $action -Trigger $trigger -Description "Кейс 4: online-retrain IDS"
```

Убедитесь, что перед online-итерацией обновляется `data/processed/flows.csv` (ingest/ETL по вашему контуру).

## Вариант B: Долгоживущий процесс

В консоли из корня проекта:

```powershell
.\.venv\Scripts\python.exe scripts\04_run_online_loop.py --loop
```

Скрипт читает `retrain_interval_minutes` из `settings.yaml` и засыпает между итерациями.
По умолчанию первый тик выполняется сразу (`immediate first tick`); чтобы сначала подождать интервал, добавьте `--delayed-first-tick`.
