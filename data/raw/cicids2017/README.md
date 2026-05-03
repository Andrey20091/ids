# Срез CICIDS2017 для обучения

Исходные дневные CSV датасета **CICIDS2017** после распаковки кладите в каталог **`TrafficLabelling/`** в **корне репозитория** (он не входит в git; см. [CIC-IDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html)).

В этой папке (`data/raw/cicids2017/`) появляется **сгенерированный** срез после:

```powershell
python scripts/17_build_cicids_training_slice.py
```

Результат: `cicids2017_tz_slice.csv`. Далее подготовка признаков:

```powershell
python main.py prepare --input data/raw/cicids2017/cicids2017_tz_slice.csv
```

Один полный день можно обрабатывать напрямую из `TrafficLabelling/`, например:

```powershell
python main.py prepare --input TrafficLabelling/Monday-WorkingHours.pcap_ISCX.csv
```

Нормализация времени и схемы — `src/ingest/cicids2017.py`.
