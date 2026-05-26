"""Unit tests for the generate_report node. No LLM calls — injects state directly."""
import pytest
from cyber_ignition_agents.agent.graph import generate_report, ThreatState

_BASE_STATE: ThreatState = {
    "scenario_name":          "test_scenario",
    "session_id":             "test_session",
    "trigger":                {"pid": 1234, "name": "powershell.exe", "parent_name": "cmd.exe"},
    "process_events":         [],
    "process_sequence":       "[14:00:01] powershell.exe (pid 1234) spawned by cmd.exe (pid 5678)",
    "analysis":               "Test analysis text.",
    "classification":         {
        "threat_level": "HIGH",
        "confidence": 0.92,
        "techniques": ["T1059.001 - PowerShell"],
        "reasoning": "Test reasoning.",
        "recommended_actions": ["Isolate the host."],
    },
    "report":                 "",
    "orchestrator_reasoning": "",
}


def _run(extra=None):
    state = dict(_BASE_STATE)
    if extra:
        state.update(extra)
    # Patch save_threat to avoid ChromaDB/filesystem side-effects in unit tests
    import unittest.mock as mock
    with mock.patch("cyber_ignition_agents.agent.graph.save_threat"):
        return generate_report(state)["report"]


def test_report_category3_footer():
    report = _run({"orchestrator_reasoning": ""})
    assert "Initiated by: environment signal (process monitor)" in report
    assert "Human involvement: none at detection or analysis stage" in report
    assert "ORCHESTRATOR DECISION" not in report


def test_report_orchestrator_decision_block():
    report = _run({"orchestrator_reasoning": "Suspicious process chain detected."})
    assert "ORCHESTRATOR DECISION" in report
    assert "Decision:   INVESTIGATE" in report
    assert "Suspicious process chain detected." in report
    assert "Initiated by: autonomous orchestrator reasoning" in report
    assert "Human involvement: none at initiation, analysis, or detection stage" in report


def test_report_threat_level_present():
    report = _run()
    assert "HIGH" in report
    assert "0.92" in report


def test_report_contains_process_sequence():
    report = _run()
    assert "powershell.exe (pid 1234)" in report


def test_report_contains_recommended_actions():
    report = _run()
    assert "Isolate the host." in report
