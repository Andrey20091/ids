from src.online.retrain_scheduler import sleep_loop


def test_sleep_loop_immediate_first_tick(monkeypatch):
    events: list[str] = []
    monkeypatch.setattr("src.online.retrain_scheduler.time.sleep", lambda *_a, **_k: events.append("sleep"))
    sleep_loop(1, lambda: events.append("callback"), max_iterations=1, initial_delay=False)
    assert events == ["callback"]


def test_sleep_loop_delayed_first_tick(monkeypatch):
    events: list[str] = []
    monkeypatch.setattr("src.online.retrain_scheduler.time.sleep", lambda *_a, **_k: events.append("sleep"))
    sleep_loop(1, lambda: events.append("callback"), max_iterations=1, initial_delay=True)
    assert events == ["sleep", "callback"]
