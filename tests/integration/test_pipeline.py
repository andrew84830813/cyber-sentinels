"""Integration test — requires ANTHROPIC_API_KEY. Run with: pytest -m slow"""
import os
import pytest

pytestmark = pytest.mark.slow


@pytest.fixture(autouse=True)
def require_api_key():
    if not os.getenv("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set — skipping integration test")


def test_scenario_a_full_pipeline():
    from cyber_sentinels.simulation.malicious import get_scenario_a
    from cyber_sentinels.agent.graph import run_scenario

    events, name = get_scenario_a()
    # Use the known trigger event (powershell.exe with -EncodedCommand)
    trigger = {k: events[2][k] for k in ("pid", "name", "parent_pid", "parent_name", "cmdline")}
    report = run_scenario(name, trigger, events, session_id="test_integration_a")

    assert report, "Report should not be empty"
    assert any(level in report for level in ("HIGH", "CRITICAL")), (
        "Scenario A should produce HIGH or CRITICAL threat level"
    )
    assert "T1059" in report, "Should reference PowerShell MITRE technique"
