@echo off
REM Extended кейс 4: packet-LSTM + prepare с PCAP enrichment + detect со скорами и логом времени.
REM Предусловия (пути подставьте под свой репозиторий):
REM   - TrafficLabelling CSV и Friday-WorkingHours.pcap из CICIDS2017
REM   - Выравненный по дню CSV: python scripts/17_build_cicids_training_slice.py (или свой aligned к PCAP)
REM   - venv: .venv\Scripts\python.exe
cd /d "%~dp0"
set PY=%~dp0.venv\Scripts\python.exe
if not exist "%PY%" set PY=py -3

echo [1] Dataset packet-LSTM (PCAP + flows CSV того же дня^)
%PY% "%~dp0scripts\20_build_packet_lstm_dataset.py" --pcap Friday-WorkingHours.pcap --flows-csv data\raw\cicids2017\cicids2017_friday_pcap_aligned.csv -o data\processed\packet_lstm_train.npz
if errorlevel 1 goto :eof

echo [2] Train packet-LSTM ^(torch^)
%PY% "%~dp0scripts\21_train_packet_lstm.py" --dataset data\processed\packet_lstm_train.npz
if errorlevel 1 goto :eof

echo [3] Prepare flows с PCAP plaintext признаками
%PY% "%~dp0main.py" prepare --input data\raw\cicids2017\cicids2017_friday_pcap_aligned.csv --prepare-pcap-enrichment Friday-WorkingHours.pcap
if errorlevel 1 goto :eof

echo [4] Train полный стек (AE/LSTM/...
%PY% "%~dp0main.py" train
if errorlevel 1 goto :eof

echo [5] Detect + packet scores + wall time ^(опционально stream^)
%PY% "%~dp0main.py" detect --detect-packet-lstm-scores data\processed\packet_lstm_scores.npz --detect-log-wall-time
exit /b %ERRORLEVEL%
