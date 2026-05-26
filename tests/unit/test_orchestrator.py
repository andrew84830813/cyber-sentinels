"""Unit tests for orchestrator response parsing. No LLM calls."""
import pytest
from cyber_ignition_agents.sensor.orchestrator import _parse_orchestrator_response


def test_parse_investigate():
    text = "DECISION: INVESTIGATE\nNEXT_CHECK: 5\nREASONING: Suspicious process chain detected."
    decision, next_check, reasoning = _parse_orchestrator_response(text)
    assert decision == "INVESTIGATE"
    assert next_check == 5
    assert "Suspicious" in reasoning


def test_parse_continue():
    text = "DECISION: CONTINUE\nNEXT_CHECK: 10\nREASONING: Normal activity, no indicators."
    decision, next_check, reasoning = _parse_orchestrator_response(text)
    assert decision == "CONTINUE"
    assert next_check == 10
    assert "Normal" in reasoning


def test_parse_clamps_next_check_low():
    text = "DECISION: CONTINUE\nNEXT_CHECK: 1\nREASONING: All clear."
    _, next_check, _ = _parse_orchestrator_response(text)
    assert next_check == 3


def test_parse_clamps_next_check_high():
    text = "DECISION: CONTINUE\nNEXT_CHECK: 99\nREASONING: All clear."
    _, next_check, _ = _parse_orchestrator_response(text)
    assert next_check == 20


def test_parse_fallback_malformed():
    text = "I cannot determine the threat level at this time."
    decision, next_check, reasoning = _parse_orchestrator_response(text)
    assert decision == "CONTINUE"
    assert next_check == 8
    assert reasoning == text
