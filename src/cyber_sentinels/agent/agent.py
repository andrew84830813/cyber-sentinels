"""
Reasoning layer — agent with MemorySaver for within-session memory.
Importable standalone. Does not depend on graph.py.

MemorySaver stores the agent's conversation thread across invocations.
When all scenarios in a demo run share the same session_id (thread_id),
the agent retains full context of earlier analyses in the same session.

Prompt caching: the system prompt is marked ephemeral so Anthropic caches it
across all tool-call turns in the agent loop. Only the first call in a new
cache window is full price; subsequent turns within 5 min are ~90% cheaper.
"""
import time
from langgraph.checkpoint.memory import MemorySaver
from langchain.agents import create_agent
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import SystemMessage
from langchain_core.callbacks import BaseCallbackHandler

from .tools import (
    format_process_tree,
    identify_attack_patterns,
    lookup_mitre_technique,
    get_similar_threats,
)
from .prompts import AGENT_SYSTEM_PROMPT

_tools = [format_process_tree, identify_attack_patterns, lookup_mitre_technique, get_similar_threats]
AGENT_TOOLS = _tools  # public alias for notebook inspection
_agent = None


class _APICallLogger(BaseCallbackHandler):
    """Prints a line every time the Anthropic API is invoked."""

    def on_chat_model_start(self, serialized, messages, **kwargs):
        model_name = (serialized.get("kwargs") or {}).get("model", "claude-sonnet-4-6")
        n_msgs = sum(len(turn) for turn in messages)
        print(f"  [Anthropic API call] model={model_name}  messages={n_msgs}  ts={time.strftime('%H:%M:%S')}")


def get_agent():
    """Return the compiled agent with MemorySaver (singleton)."""
    global _agent
    if _agent is None:
        model  = ChatAnthropic(model="claude-sonnet-4-6", callbacks=[_APICallLogger()])
        memory = MemorySaver()

        # Cache the system prompt across all agent loop turns (tool calls + synthesis).
        cached_system = SystemMessage(content=[{
            "type": "text",
            "text": AGENT_SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }])

        _agent = create_agent(
            model,
            _tools,
            system_prompt=cached_system,
            checkpointer=memory,
        )
    return _agent
