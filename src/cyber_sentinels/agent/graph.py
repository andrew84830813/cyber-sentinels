"""
LangGraph pipeline for cyber-sentinels threat analysis.

Five nodes in a fixed linear chain:
  trigger_received -> monitor_activity -> analyze_sequence -> classify_threat -> generate_report

The graph is compiled once and reused across scenarios.
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, TypedDict

import anthropic
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langgraph.graph import END, StateGraph

from .agent import get_agent
from .prompts import ANALYSIS_PROMPT, CLASSIFICATION_PROMPT, SYSTEM_PROMPT
from .tools import format_process_sequence, format_techniques
from ..memory.store import save_threat

load_dotenv()

_client: anthropic.Anthropic | None = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic()
    return _client


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class ThreatState(TypedDict):
    scenario_name:          str
    session_id:             str
    trigger:                Dict[str, Any]
    process_events:         List[Dict[str, Any]]
    process_sequence:       str
    analysis:               str
    classification:         Dict[str, Any]
    report:                 str
    orchestrator_reasoning: str  # empty string in rules/Category 3 mode


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------

def trigger_received(state: ThreatState) -> ThreatState:
    t = state["trigger"]
    cmdline = t.get("cmdline", [])
    if isinstance(cmdline, list):
        cmdline = " ".join(cmdline)
    print(f"  [1/5] trigger_received  — {t['name']} (pid {t['pid']}) "
          f"<- {t.get('parent_name', 'unknown')}")
    return state


def monitor_activity(state: ThreatState) -> ThreatState:
    events = state["process_events"]
    sequence = format_process_sequence(events)
    print(f"  [2/5] monitor_activity  — {len(events)} events collected")
    return {**state, "process_sequence": sequence}


def analyze_sequence(state: ThreatState) -> ThreatState:
    print(f"  [3/5] analyze_sequence  — invoking ReAct agent...")
    t = state["trigger"]
    cmdline = t.get("cmdline", [])
    if isinstance(cmdline, list):
        cmdline = " ".join(cmdline)

    prompt = ANALYSIS_PROMPT.format(
        trigger=f"{t['name']} (pid {t['pid']})  parent: {t.get('parent_name', 'unknown')}  cmdline: {cmdline}",
        process_sequence=state["process_sequence"],
    )

    config = {"configurable": {"thread_id": state.get("session_id", "default")}}
    result = get_agent().invoke({"messages": [HumanMessage(content=prompt)]}, config=config)

    content = result["messages"][-1].content
    if isinstance(content, list):
        analysis = " ".join(
            block["text"] if isinstance(block, dict) else str(block)
            for block in content
            if not isinstance(block, dict) or block.get("type") == "text"
        )
    else:
        analysis = content

    return {**state, "analysis": analysis}


def classify_threat(state: ThreatState) -> ThreatState:
    import time
    print(f"  [4/5] classify_threat   — calling LLM...")
    print(f"  [Anthropic API call] model=claude-sonnet-4-6  node=classify_threat  ts={time.strftime('%H:%M:%S')}")
    prompt = CLASSIFICATION_PROMPT.format(analysis=state["analysis"])

    response = _get_client().messages.create(
        model="claude-sonnet-4-6",
        max_tokens=600,
        system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": prompt}],
    )

    text = response.content[0].text.strip()

    # Strip markdown fences if the model wraps the JSON
    if "```" in text:
        parts = text.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            if part.startswith("{"):
                text = part
                break

    try:
        classification = json.loads(text)
    except json.JSONDecodeError:
        classification = {
            "threat_level": "UNKNOWN",
            "confidence": 0.5,
            "techniques": [],
            "reasoning": text,
            "recommended_actions": ["Review the analysis manually."],
        }

    return {**state, "classification": classification}


def generate_report(state: ThreatState) -> ThreatState:
    print(f"  [5/5] generate_report   — formatting output")
    c = state["classification"]
    t = state["trigger"]

    techniques_str = format_techniques(c.get("techniques", []))

    actions = c.get("recommended_actions", [])
    if actions:
        actions_str = "\n".join(f"{i + 1}. {a}" for i, a in enumerate(actions))
    else:
        actions_str = "1. Monitor for further activity.\n2. Review endpoint logs."

    orch_reasoning = state.get("orchestrator_reasoning", "")
    if orch_reasoning:
        initiation_block = (
            f"ORCHESTRATOR DECISION\n"
            f"---------------------\n"
            f"Decision:   INVESTIGATE\n"
            f"Reasoning:  {orch_reasoning}\n"
            f"\n"
            f"Initiated by: autonomous orchestrator reasoning (no pre-specified rules)\n"
            f"Human involvement: none at initiation, analysis, or detection stage\n"
            f"\n"
        )
    else:
        initiation_block = (
            f"Initiated by: environment signal (process monitor)\n"
            f"Human involvement: none at detection or analysis stage\n"
            f"\n"
        )

    report = (
        f"CYBER-SENSE THREAT REPORT\n"
        f"==========================\n"
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Trigger:   {t['name']} spawned from {t.get('parent_name', 'unknown')}\n"
        f"\n"
        f"{initiation_block}"
        f"PROCESS SEQUENCE\n"
        f"----------------\n"
        f"{state['process_sequence']}\n"
        f"\n"
        f"THREAT CLASSIFICATION\n"
        f"---------------------\n"
        f"Level:      {c.get('threat_level', 'UNKNOWN')}\n"
        f"Confidence: {c.get('confidence', 0.0):.2f}\n"
        f"Technique:  {techniques_str}\n"
        f"\n"
        f"ANALYSIS\n"
        f"--------\n"
        f"{state['analysis']}\n"
        f"\n"
        f"RECOMMENDED ACTIONS\n"
        f"-------------------\n"
        f"{actions_str}"
    )

    c = state["classification"]
    if c.get("threat_level", "BENIGN") != "BENIGN":
        save_threat(
            scenario_name=state["scenario_name"],
            threat_level=c.get("threat_level", "UNKNOWN"),
            confidence=c.get("confidence", 0.0),
            techniques=c.get("techniques", []),
            reasoning=c.get("reasoning", ""),
            analysis=state["analysis"],
        )

    return {**state, "report": report}


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def _build_graph() -> Any:
    g = StateGraph(ThreatState)

    g.add_node("trigger_received", trigger_received)
    g.add_node("monitor_activity", monitor_activity)
    g.add_node("analyze_sequence", analyze_sequence)
    g.add_node("classify_threat", classify_threat)
    g.add_node("generate_report", generate_report)

    g.add_edge("trigger_received", "monitor_activity")
    g.add_edge("monitor_activity", "analyze_sequence")
    g.add_edge("analyze_sequence", "classify_threat")
    g.add_edge("classify_threat", "generate_report")
    g.add_edge("generate_report", END)

    g.set_entry_point("trigger_received")
    return g.compile()


_compiled_graph: Any = None


def get_graph() -> Any:
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = _build_graph()
    return _compiled_graph


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_scenario(scenario_name: str, trigger: dict, events: list,
                 session_id: str = "default",
                 orchestrator_reasoning: str = "") -> str:
    """Run a scenario through the full pipeline and return the formatted report."""
    graph = get_graph()

    initial_state: ThreatState = {
        "scenario_name":          scenario_name,
        "session_id":             session_id,
        "trigger":                trigger,
        "process_events":         events,
        "process_sequence":       "",
        "analysis":               "",
        "classification":         {},
        "report":                 "",
        "orchestrator_reasoning": orchestrator_reasoning,
    }

    result = graph.invoke(initial_state)
    return result["report"]
