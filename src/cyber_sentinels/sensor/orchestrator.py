"""
Adaptive orchestrator — the Category 4 initiation layer for cyber-sense.

The orchestrator observes batches of process events and decides autonomously:
  - Whether to investigate (INVESTIGATE / CONTINUE)
  - When to observe again (next_check_events: N events before re-evaluation)

No human-specified trigger rules. The decision and its cadence emerge from
the orchestrator's own reasoning over general security knowledge.

This replaces the rule-based is_trigger() + triage_with_llm() two-step gate
in the Category 3 path. The human configured "notify me when processes appear."
The orchestrator decides everything else.

--------------------------------------------------------------------------------
SCAFFOLD — long-term architecture direction (not yet implemented)
--------------------------------------------------------------------------------

EscalationMode:
  When the orchestrator fires INVESTIGATE, instead of handing off to one pipeline
  it simultaneously spins specialist agents (ProcessAnalyst, NetworkAnalyst,
  FileSystemAnalyst) that run in parallel and report back. The orchestrator
  synthesizes their findings before generating the final report. During an active
  attack the orchestrator stays running continuously, managing all specialist
  instances and updating its threat picture as new evidence arrives.

SessionManager:
  Each OrchestratorSession is scoped to one potential threat chain. A
  SessionManager holds many active sessions simultaneously — one per suspected
  attack chain or host — each with its own event buffer, cadence, and state.
  The orchestrator cycles through sessions, allocating attention in proportion
  to each session's suspicion level.

MetaOrchestrator:
  Above the session layer, a MetaOrchestrator manages multiple
  session-level orchestrators across hosts or investigation contexts. It
  allocates Sonnet budget across sessions by severity, correlates cross-session
  patterns (same technique appearing on multiple endpoints), and produces
  organization-wide threat summaries. This is the "conductor of conductors."
--------------------------------------------------------------------------------
"""

import anthropic

from ..agent.prompts import ORCHESTRATOR_PROMPT


class OrchestratorSession:
    """
    Manages one potential threat investigation window.

    Accumulates process events, evaluates them with the LLM orchestrator at
    adaptive intervals, and signals when to fire the analysis pipeline.

    SCAFFOLD: In escalation_mode, many OrchestratorSessions run in parallel,
    each scoped to one suspected threat chain. A SessionManager and eventually
    a MetaOrchestrator would manage allocation across sessions.
    """

    def __init__(self, scenario_name: str, initial_check_interval: int = 5):
        self.scenario_name = scenario_name
        self.accumulated_events: list = []
        self.next_check_events: int = initial_check_interval
        self.events_since_last_eval: int = 0
        self.orchestrator_reasoning: str = ""
        self._client = anthropic.Anthropic()

    def add_event(self, event: dict) -> tuple:
        """
        Feed one new event into the session. Returns (should_investigate, reasoning)
        when the orchestrator decides to evaluate; otherwise returns (None, None).

        The caller should check for (True, reasoning) to fire the pipeline, and
        (False, reasoning) to print the CONTINUE decision and updated cadence.
        """
        self.accumulated_events.append(event)
        self.events_since_last_eval += 1

        if self.events_since_last_eval >= self.next_check_events:
            return self._evaluate()
        return None, None

    def evaluate_now(self) -> tuple:
        """Force an evaluation on the full accumulated window. Used at feed end."""
        return self._evaluate()

    def _evaluate(self) -> tuple:
        self.events_since_last_eval = 0

        lines = []
        for e in self.accumulated_events:
            cmdline = e.get("cmdline", "")
            if isinstance(cmdline, list):
                cmdline = " ".join(cmdline)
            lines.append(
                f"  [{e.get('timestamp', '?')}] {e.get('name', '?')} "
                f"(pid {e.get('pid', '?')}) <- {e.get('parent_name', '—')}  "
                f"cmdline: {cmdline}"
            )

        prompt = ORCHESTRATOR_PROMPT.format(
            window_size=len(self.accumulated_events),
            events="\n".join(lines) or "No events.",
        )

        response = self._client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=250,
            system=[{
                "type": "text",
                "text": (
                    "You are an adaptive security orchestrator. "
                    "Evaluate process activity and decide whether to investigate. "
                    "Follow the response format exactly."
                ),
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": prompt}],
        )

        text = response.content[0].text.strip()
        decision, next_check, reasoning = _parse_orchestrator_response(text)

        self.next_check_events = next_check
        self.orchestrator_reasoning = reasoning

        return decision == "INVESTIGATE", reasoning


def _parse_orchestrator_response(text: str) -> tuple:
    """Parse DECISION / NEXT_CHECK / REASONING from the orchestrator's response."""
    decision = "CONTINUE"
    next_check = 8
    reasoning = text

    for line in text.splitlines():
        stripped = line.strip()
        upper = stripped.upper()
        if upper.startswith("DECISION:"):
            val = stripped.split(":", 1)[1].strip().upper()
            decision = "INVESTIGATE" if "INVESTIGATE" in val else "CONTINUE"
        elif upper.startswith("NEXT_CHECK:"):
            try:
                next_check = max(3, min(20, int(stripped.split(":", 1)[1].strip())))
            except ValueError:
                pass
        elif upper.startswith("REASONING:"):
            reasoning = stripped.split(":", 1)[1].strip()

    return decision, next_check, reasoning
