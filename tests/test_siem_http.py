import pandas as pd
import runpy
import requests

from src.correlation.siem_loader import load_siem_events_http


class _FakeResponse:
    def __init__(self, payload, status_ok=True):
        self._payload = payload
        self._status_ok = status_ok

    def raise_for_status(self):
        if not self._status_ok:
            raise RuntimeError("http error")

    def json(self):
        return self._payload


def test_load_siem_events_http_success(monkeypatch):
    def _fake_get(url, timeout):
        assert url == "https://siem.local/events"
        assert timeout == 3
        return _FakeResponse(
            [{"ip": "1.1.1.1", "event_type": "failed_login"}],
            status_ok=True,
        )

    monkeypatch.setattr("src.correlation.siem_loader.requests.get", _fake_get)
    df = load_siem_events_http("https://siem.local/events", timeout_seconds=3)
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 1
    assert set(df.columns) >= {"ip", "event_type"}


def test_load_siem_events_http_retries_then_success(monkeypatch):
    calls = {"n": 0}

    def _fake_get(_url, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            raise requests.RequestException("transport error")
        return _FakeResponse([{"ip": "3.3.3.3", "event_type": "failed_login"}], status_ok=True)

    monkeypatch.setattr("src.correlation.siem_loader.requests.get", _fake_get)
    monkeypatch.setattr("src.correlation.siem_loader.time.sleep", lambda _s: None)
    df = load_siem_events_http("https://siem.local/events", timeout_seconds=2, retries=1)
    assert len(df) == 1
    assert calls["n"] == 2


def test_load_siem_events_http_non_list_payload(monkeypatch):
    monkeypatch.setattr(
        "src.correlation.siem_loader.requests.get",
        lambda *_args, **_kwargs: _FakeResponse({"unexpected": "shape"}, status_ok=True),
    )
    df = load_siem_events_http("https://siem.local/events")
    assert df.empty


def test_detection_script_load_siem_http_branch(monkeypatch):
    module = runpy.run_path("scripts/03_run_detection_batch.py")
    load_siem = module["_load_siem"]

    called = {"url": None, "timeout": None, "retries": None}

    def _fake_http(url, timeout_seconds=5, retries=0, retry_backoff_seconds=0.2):
        called["url"] = url
        called["timeout"] = timeout_seconds
        called["retries"] = retries
        return pd.DataFrame([{"ip": "2.2.2.2", "event_type": "config_change"}])

    monkeypatch.setattr(
        "src.correlation.siem_loader.load_siem_events_http",
        _fake_http,
    )

    settings = {
        "siem": {
            "source": "http",
            "http_url": "https://siem.local/api/events",
            "timeout_seconds": 7,
            "retries": 2,
        },
        "paths": {"siem_events": "storage/siem_events_sample.json"},
    }
    df = load_siem(settings)
    assert not df.empty
    assert called["url"] == "https://siem.local/api/events"
    assert called["timeout"] == 7
    assert called["retries"] == 2
