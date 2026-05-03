import importlib
import sys
from pathlib import Path
import subprocess


def test_main_routes_online_flags(monkeypatch):
    main_mod = importlib.import_module("main")
    called = {}

    def _fake_run_script(*argv):
        called["argv"] = list(argv)
        return 0

    monkeypatch.setattr(main_mod, "_run_script", _fake_run_script)
    monkeypatch.setattr(main_mod, "_ensure_frozen_writable_root", lambda: None)
    monkeypatch.setattr(main_mod, "_torch_probe", lambda: (True, ""))

    old_argv = sys.argv[:]
    try:
        sys.argv = [
            "main.py",
            "online",
            "--online-data",
            "data/processed/flows.csv",
            "--online-loop",
            "--online-delayed-first-tick",
        ]
        rc = main_mod.main()
    finally:
        sys.argv = old_argv

    assert rc == 0
    assert called["argv"][0] == "scripts/04_run_online_loop.py"
    assert "--data" in called["argv"]
    assert "--loop" in called["argv"]
    assert "--delayed-first-tick" in called["argv"]


def test_main_routes_detect_features_yaml(monkeypatch):
    main_mod = importlib.import_module("main")
    called = {}

    def _fake_run_script(*argv):
        called["argv"] = list(argv)
        return 0

    monkeypatch.setattr(main_mod, "_run_script", _fake_run_script)
    monkeypatch.setattr(main_mod, "_ensure_frozen_writable_root", lambda: None)
    monkeypatch.setattr(main_mod, "_torch_probe", lambda: (True, ""))

    old_argv = sys.argv[:]
    try:
        sys.argv = [
            "main.py",
            "detect",
            "--detect-features-yaml",
            "config/feature_columns.yaml",
        ]
        rc = main_mod.main()
    finally:
        sys.argv = old_argv

    assert rc == 0
    assert called["argv"][0] == "scripts/03_run_detection_batch.py"
    assert "--features-yaml" in called["argv"]


def test_main_routes_detect_dedup_and_proxy_rule_flags(monkeypatch):
    main_mod = importlib.import_module("main")
    called = {}

    def _fake_run_script(*argv):
        called["argv"] = list(argv)
        return 0

    monkeypatch.setattr(main_mod, "_run_script", _fake_run_script)
    monkeypatch.setattr(main_mod, "_ensure_frozen_writable_root", lambda: None)
    monkeypatch.setattr(main_mod, "_torch_probe", lambda: (True, ""))

    old_argv = sys.argv[:]
    try:
        sys.argv = [
            "main.py",
            "detect",
            "--detect-dedup-window-seconds",
            "30",
            "--detect-disable-proxy-rules",
        ]
        rc = main_mod.main()
    finally:
        sys.argv = old_argv

    assert rc == 0
    assert called["argv"][0] == "scripts/03_run_detection_batch.py"
    assert "--dedup-window-seconds" in called["argv"]
    assert "--disable-proxy-rules" in called["argv"]


def test_main_routes_prepare_extended_flags(monkeypatch, tmp_path):
    main_mod = importlib.import_module("main")
    called = {}

    def _fake_run_script(*argv):
        called["argv"] = list(argv)
        return 0

    monkeypatch.setattr(main_mod, "_run_script", _fake_run_script)
    monkeypatch.setattr(main_mod, "_ensure_frozen_writable_root", lambda: None)
    monkeypatch.setattr(main_mod, "_torch_probe", lambda: (True, ""))

    data_in = tmp_path / "raw.csv"
    data_in.write_text("Flow Duration\n1\n", encoding="utf-8")

    old_argv = sys.argv[:]
    try:
        sys.argv = [
            "main.py",
            "prepare",
            "--input",
            str(data_in),
            "--prepare-output",
            "data/processed/flows_new.csv",
            "--prepare-features-yaml",
            "config/feature_columns.yaml",
            "--prepare-no-cicids-normalize",
            "--prepare-append-output",
        ]
        rc = main_mod.main()
    finally:
        sys.argv = old_argv

    assert rc == 0
    assert called["argv"][0] == "scripts/01_prepare_data.py"
    assert "--output" in called["argv"]
    assert "--features-yaml" in called["argv"]
    assert "--no-cicids-normalize" in called["argv"]
    assert "--append-output" in called["argv"]


def test_main_routes_baseline_train_flags(monkeypatch):
    main_mod = importlib.import_module("main")
    called = {}

    def _fake_run_script(*argv):
        called["argv"] = list(argv)
        return 0

    monkeypatch.setattr(main_mod, "_run_script", _fake_run_script)
    monkeypatch.setattr(main_mod, "_ensure_frozen_writable_root", lambda: None)
    monkeypatch.setattr(main_mod, "_torch_probe", lambda: (True, ""))

    old_argv = sys.argv[:]
    try:
        sys.argv = [
            "main.py",
            "baseline-train",
            "--baseline-data",
            "data/processed/flows.csv",
            "--dataset-tag",
            "cicids2017",
            "--dataset-source",
            "CICIDS",
        ]
        rc = main_mod.main()
    finally:
        sys.argv = old_argv

    assert rc == 0
    assert called["argv"][0] == "scripts/02_train_all.py"
    assert "--baseline-train" in called["argv"]
    assert "--dataset-tag" in called["argv"]
    assert "--data" in called["argv"]


def test_main_routes_ingest_new_data_to_prepare(monkeypatch, tmp_path):
    main_mod = importlib.import_module("main")
    called = {}

    def _fake_run_script(*argv):
        called["argv"] = list(argv)
        return 0

    monkeypatch.setattr(main_mod, "_run_script", _fake_run_script)
    monkeypatch.setattr(main_mod, "_ensure_frozen_writable_root", lambda: None)
    monkeypatch.setattr(main_mod, "_torch_probe", lambda: (True, ""))

    data_in = tmp_path / "raw.csv"
    data_in.write_text("Flow Duration\n1\n", encoding="utf-8")

    old_argv = sys.argv[:]
    try:
        sys.argv = [
            "main.py",
            "ingest-new-data",
            "--input",
            str(data_in),
            "--prepare-output",
            "data/processed/flows_new_ingest.csv",
            "--ingest-append-output",
        ]
        rc = main_mod.main()
    finally:
        sys.argv = old_argv

    assert rc == 0
    assert called["argv"][0] == "scripts/01_prepare_data.py"
    assert "--input" in called["argv"]
    assert "--append-output" in called["argv"]


def test_main_online_defaults_to_flows_online_buffer(monkeypatch):
    main_mod = importlib.import_module("main")
    called = {}

    def _fake_run_script(*argv):
        called["argv"] = list(argv)
        return 0

    monkeypatch.setattr(main_mod, "_run_script", _fake_run_script)
    monkeypatch.setattr(main_mod, "_ensure_frozen_writable_root", lambda: None)
    monkeypatch.setattr(main_mod, "_torch_probe", lambda: (True, ""))
    monkeypatch.setattr(main_mod, "_read_path_default", lambda k, f: "data/processed/flows_online_buffer.csv" if k == "flows_online_buffer" else f)

    old_argv = sys.argv[:]
    try:
        sys.argv = ["main.py", "online"]
        rc = main_mod.main()
    finally:
        sys.argv = old_argv

    assert rc == 0
    assert called["argv"][0] == "scripts/04_run_online_loop.py"
    assert "--data" in called["argv"]
    assert any(str(a).endswith("data\\processed\\flows_online_buffer.csv") for a in called["argv"])


def test_main_realtime_defaults_to_flows_online_buffer(monkeypatch):
    main_mod = importlib.import_module("main")
    called = {}

    def _fake_run_script(*argv):
        called["argv"] = list(argv)
        return 0

    monkeypatch.setattr(main_mod, "_run_script", _fake_run_script)
    monkeypatch.setattr(main_mod, "_ensure_frozen_writable_root", lambda: None)
    monkeypatch.setattr(main_mod, "_torch_probe", lambda: (True, ""))
    monkeypatch.setattr(main_mod, "_read_path_default", lambda k, f: "data/processed/flows_online_buffer.csv" if k == "flows_online_buffer" else f)

    old_argv = sys.argv[:]
    try:
        sys.argv = ["main.py", "realtime", "--realtime-iterations", "1"]
        rc = main_mod.main()
    finally:
        sys.argv = old_argv

    assert rc == 0
    assert called["argv"][0] == "scripts/05_run_realtime_detection.py"
    assert "--data" in called["argv"]
    assert any(str(a).endswith("data\\processed\\flows_online_buffer.csv") for a in called["argv"])


def test_main_routes_proxy_ingest_incremental_flags(monkeypatch):
    main_mod = importlib.import_module("main")
    called = {}

    def _fake_run_script(*argv):
        called["argv"] = list(argv)
        return 0

    monkeypatch.setattr(main_mod, "_run_script", _fake_run_script)
    monkeypatch.setattr(main_mod, "_ensure_frozen_writable_root", lambda: None)
    monkeypatch.setattr(main_mod, "_torch_probe", lambda: (True, ""))

    old_argv = sys.argv[:]
    try:
        sys.argv = [
            "main.py",
            "proxy-ingest",
            "--ingest-ndjson",
            "data/raw/proxy_traffic.ndjson",
            "--ingest-csv-out",
            "data/raw/proxy_cicids_like.csv",
            "--ingest-state-file",
            "storage/proxy_ingest_state.json",
            "--ingest-incremental",
            "--ingest-append",
        ]
        rc = main_mod.main()
    finally:
        sys.argv = old_argv

    assert rc == 0
    assert called["argv"][0] == "scripts/07_ingest_proxy_ndjson.py"
    assert "--state-file" in called["argv"]
    assert "--incremental" in called["argv"]
    assert "--append" in called["argv"]


def test_main_routes_proxy_rotation_flags(monkeypatch):
    main_mod = importlib.import_module("main")
    called = {}

    def _fake_run_script(*argv):
        called["argv"] = list(argv)
        return 0

    monkeypatch.setattr(main_mod, "_run_script", _fake_run_script)
    monkeypatch.setattr(main_mod, "_ensure_frozen_writable_root", lambda: None)
    monkeypatch.setattr(main_mod, "_torch_probe", lambda: (True, ""))

    old_argv = sys.argv[:]
    try:
        sys.argv = [
            "main.py",
            "proxy",
            "--proxy-max-log-mb",
            "10",
            "--proxy-max-log-backups",
            "3",
        ]
        rc = main_mod.main()
    finally:
        sys.argv = old_argv

    assert rc == 0
    assert called["argv"][0] == "scripts/06_proxy_capture.py"
    assert "--max-log-mb" in called["argv"]
    assert "--max-log-backups" in called["argv"]


def test_run_script_handles_keyboard_interrupt(monkeypatch):
    main_mod = importlib.import_module("main")

    def _raise_keyboard_interrupt(*_args, **_kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(subprocess, "call", _raise_keyboard_interrupt)
    rc = main_mod._run_script("scripts/check_env.py")
    assert rc == 130
