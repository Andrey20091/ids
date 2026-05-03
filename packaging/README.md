# Сборка исполняемых файлов (Windows)

Сборка даёт локальные **onedir**-пакеты без установщика: `dist\ids-cli\`, `dist\ids-dashboard\`.

## Требования к машине сборки

- Python **3.10+**
- Зависимости проекта:

  ```powershell
  python -m pip install -r requirements.txt
  ```

- Для **полного** CLI (RF/IF + AE/LSTM/embedding) установите PyTorch **в тот же интерпретатор**, затем PyInstaller:

  ```powershell
  python -m pip install -r requirements-ml.txt --index-url https://download.pytorch.org/whl/cpu
  ```

В `ids-cli.spec` используется `collect_all('torch')`, поэтому **torch попадает внутрь `ids-cli.exe`** — на клиенте отдельно ставить torch не нужно.

## Сборка IDS CLI (рекомендуется)

Из корня репозитория:

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build_cli.ps1
```

Вручную:

```powershell
pyinstaller --noconfirm --clean ids-cli.spec
```

Результат: `dist\ids-cli\` (onedir). После добавления новых скриптов или модулей в точках входа **пересоберите** spec.

## Сборка дашборда

```powershell
pyinstaller --noconfirm --clean ids-dashboard.spec
```

Старый вариант одной строкой (если нужен без spec):

```powershell
pyinstaller --noconfirm --clean --onedir --name ids-dashboard dashboard_launcher.py --add-data "dashboard;dashboard" --add-data "storage;storage" --collect-all streamlit --collect-all plotly
```

## Режим распространения

Отдельный инсталлятор сейчас не используется; поддерживаются только локальные bundle из `dist\`.

## Проверка frozen CLI

```powershell
.\dist\ids-cli\ids-cli.exe -h
.\dist\ids-cli\ids-cli.exe check
```

В справке должны быть команды вроде `proxy`, `proxy-ingest`, `proxy-sync-buffer`, `validate` — в соответствии с текущим `main.py`.

При установке в **Program Files** данные и конфиг по умолчанию уезжают в `%LOCALAPPDATA%\IDS_ML_Project` (см. `main.py`, переменная `IDS_PROJECT_ROOT`).
