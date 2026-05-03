# Сырые данные (`data/raw`)

## CICIDS2017

Полные дневные CSV с полной схемой (IP, Timestamp, Flow ID) лежат в **`TrafficLabelling/`** в корне проекта после скачивания датасета ([CIC-IDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html)). Каталог в репозитории не хранится — его нужно распаковать локально.

**Срез без загрузки всех дней:**

```powershell
python scripts/17_build_cicids_training_slice.py
python main.py prepare --input data/raw/cicids2017/cicids2017_tz_slice.csv
```

**Один день целиком:**

```powershell
python main.py prepare --input TrafficLabelling/Monday-WorkingHours.pcap_ISCX.csv
```

Подробности среза: `data/raw/cicids2017/README.md`.

## Демо без полного датасета

```powershell
python scripts/00_generate_demo_data.py
```

Создаёт `synthetic_cicids_demo.csv` для быстрых прогонов.

## PCAP → потоки

Нужен `scapy` (`pip install scapy`):

```powershell
python main.py pcap-flows --pcap path\to\capture.pcap --pcap-output data/raw/pcap_flows_raw.csv --pcap-prepare
```

Для сценариев с полнодневым PCAP (например пятница CICIDS2017) положите `.pcap` рядом с дневными CSV или в `data/corporate_pcap/`.

## Корпоративный размеченный CSV

Примеры и сценарий e2e: `data/raw/corporate_example/README.md`.

## Прокси-трафик

NDJSON с локального прокси по умолчанию: `data/raw/proxy_traffic.ndjson` (см. `python main.py proxy` / `proxy-ingest` в корневом `README.md`).
