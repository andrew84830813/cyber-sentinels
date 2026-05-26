"""Unit tests for simulation scenario generators. No LLM calls."""
import pytest

REQUIRED_KEYS = {"timestamp", "pid", "name", "action"}


def _check_events(events, name):
    assert len(events) >= 4, f"{name}: expected >= 4 events, got {len(events)}"
    for i, e in enumerate(events):
        missing = REQUIRED_KEYS - set(e.keys())
        assert not missing, f"{name} event[{i}] missing keys: {missing}"
        assert isinstance(e["pid"], int), f"{name} event[{i}]: pid must be int"
        assert isinstance(e["name"], str), f"{name} event[{i}]: name must be str"


def test_scenario_a_structure():
    from cyber_sentinels.simulation.malicious import get_scenario_a
    events, name = get_scenario_a()
    _check_events(events, name)


def test_scenario_b_structure():
    from cyber_sentinels.simulation.malicious import get_scenario_b
    events, name = get_scenario_b()
    _check_events(events, name)


def test_scenario_c_structure():
    from cyber_sentinels.simulation.malicious import get_scenario_c
    events, name = get_scenario_c()
    _check_events(events, name)


def test_scenario_n_no_trigger():
    from cyber_sentinels.simulation.normal import get_normal_scenario
    from cyber_sentinels.sensor.monitor import is_trigger

    events, _ = get_normal_scenario()
    for e in events:
        snap = {
            "pid": e["pid"],
            "name": e["name"],
            "parent_pid": e.get("parent_pid"),
            "parent_name": e.get("parent_name"),
            "cmdline": e.get("cmdline", ""),
        }
        assert not is_trigger(snap), (
            f"Normal scenario event triggered unexpectedly: {e['name']} "
            f"cmdline={e.get('cmdline', '')}"
        )
