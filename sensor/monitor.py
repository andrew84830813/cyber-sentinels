"""
Process monitor — the ignition layer for cyber-sense.

This file has two modes:

  REAL MODE (--watch flag):
      Uses psutil to poll running processes. Fires the callback when a new
      process matches a trigger signature. Requires no elevated privileges
      for basic enumeration; some cmdline/parent info may need higher
      privileges on Windows.

  SIMULATED MODE (inject_simulated_event):
      Accepts a pre-built process snapshot directly. Used by demo.py to feed
      attack scenarios into the same callback pipeline that real monitoring
      uses. The agent layer cannot tell the difference — the callback
      signature is identical. This is the architectural point: ignition
      mechanism shape is preserved regardless of whether the trigger is real.

SIMULATION HOOK points are marked with:  # SIMULATION HOOK
"""

import argparse
import time
from typing import Callable, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ---------------------------------------------------------------------------
# Trigger signatures — process relationships that fire the agent pipeline
# ---------------------------------------------------------------------------
TRIGGER_SIGNATURES = [
    # PowerShell download cradle: encoded command flag
    {"process": "powershell.exe", "cmdline_contains": "-EncodedCommand"},
    {"process": "powershell.exe", "cmdline_contains": " -enc "},
    # Web shell: IIS or generic web worker spawning a shell
    {"parent": "w3wp.exe", "process": "cmd.exe"},
    {"parent": "w3wp.exe", "process": "powershell.exe"},
    {"parent": "httpd.exe", "process": "cmd.exe"},
    # Ransomware staging: shadow copy deletion
    {"process": "vssadmin.exe", "cmdline_contains": "delete shadows"},
]


def is_trigger(snapshot: dict) -> bool:
    """Return True if a process snapshot matches any trigger signature."""
    name = snapshot.get("name", "").lower()
    parent_name = (snapshot.get("parent_name") or "").lower()
    cmdline = snapshot.get("cmdline", "")
    if isinstance(cmdline, list):
        cmdline = " ".join(cmdline)
    cmdline = cmdline.lower()

    for sig in TRIGGER_SIGNATURES:
        if "process" in sig and sig["process"].lower() not in name:
            continue
        if "parent" in sig and sig["parent"].lower() not in parent_name:
            continue
        if "cmdline_contains" in sig and sig["cmdline_contains"].lower() not in cmdline:
            continue
        return True
    return False


def triage_with_llm(snapshot: dict, recent_events: list) -> tuple:
    """
    LLM triage using Claude Haiku with cached system prompt.
    Called only after the rule-based pre-filter fires (cost control).

    Returns (should_fire: bool, reasoning: str).
    """
    import anthropic
    from agent.prompts import TRIAGE_PROMPT

    client = anthropic.Anthropic()

    context_lines = []
    for e in recent_events[-5:]:
        context_lines.append(
            f"  [{e.get('timestamp', '?')}] {e.get('name', '?')} (pid {e.get('pid', '?')}) "
            f"<- {e.get('parent_name', '—')}  cmdline: {e.get('cmdline', '')}"
        )

    user_msg = TRIAGE_PROMPT.format(
        process_name=snapshot.get("name", "unknown"),
        pid=snapshot.get("pid", "?"),
        parent_name=snapshot.get("parent_name", "unknown"),
        cmdline=snapshot.get("cmdline", ""),
        recent_events="\n".join(context_lines) or "No recent events.",
    )

    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=150,
        system=[{
            "type": "text",
            "text": (
                "You are a fast cybersecurity triage filter. "
                "Given a process event and recent context, decide if it warrants full threat analysis. "
                "Reply with FIRE or SKIP on the first line, then one sentence of reasoning."
            ),
            "cache_control": {"type": "ephemeral"},
        }],
        messages=[{"role": "user", "content": user_msg}],
    )

    text = response.content[0].text.strip()
    should_fire = text.upper().startswith("FIRE")
    reasoning   = text.split("\n", 1)[1].strip() if "\n" in text else text
    return should_fire, reasoning


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------

def watch_real(callback: Callable, poll_interval: float = 1.0):
    """
    REAL MODE: Poll running processes with psutil and fire callback on trigger.

    The callback receives the same snapshot dict format used by the simulated
    mode so the pipeline above is identical in both cases.
    """
    if not PSUTIL_AVAILABLE:
        raise RuntimeError("psutil is not installed. Run: pip install psutil")

    seen_pids: set = set()
    print("[monitor] Watching real processes. Press Ctrl+C to stop.\n")

    while True:
        try:
            for proc in psutil.process_iter(["pid", "name", "ppid", "cmdline", "create_time"]):
                pid = proc.info["pid"]
                if pid in seen_pids:
                    continue
                seen_pids.add(pid)

                try:
                    parent = psutil.Process(proc.info["ppid"])
                    parent_name = parent.name()
                    parent_pid = proc.info["ppid"]
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    parent_name = "unknown"
                    parent_pid = proc.info["ppid"]

                snapshot = {
                    "pid": pid,
                    "name": proc.info["name"],
                    "parent_pid": parent_pid,
                    "parent_name": parent_name,
                    # SIMULATION HOOK: in demo mode, a pre-built cmdline is injected here
                    # instead of reading from the live process. Everything downstream is
                    # identical.
                    "cmdline": proc.info["cmdline"] or [],
                    "create_time": proc.info["create_time"],
                }

                if is_trigger(snapshot):
                    print(f"[monitor] Trigger: {snapshot['name']} (pid {snapshot['pid']}) "
                          f"<- {snapshot['parent_name']}")
                    callback(snapshot)

            time.sleep(poll_interval)

        except KeyboardInterrupt:
            print("\n[monitor] Stopped.")
            break
        except Exception as exc:
            print(f"[monitor] Warning: {exc}")
            continue


# ---------------------------------------------------------------------------
# Simulated mode
# ---------------------------------------------------------------------------

def watch_simulated(
    scenario_name: str,
    events: list,
    on_trigger: Callable,
    delay: float = 0.25,
) -> bool:
    """
    SIMULATED MODE: Feed a defined event sequence through the same trigger logic
    used in real psutil monitoring.

    Prints each event as it arrives, then checks is_trigger(). When a trigger
    fires, calls on_trigger(snapshot, all_events) and returns True.
    Returns False if the feed completes with no trigger detected.

    on_trigger receives:
        snapshot   — the event that matched a trigger signature (dict)
        all_events — the full event list for the monitoring window (list)
    """
    print(f"[sensor] Simulated feed: {scenario_name}")
    print(f"[sensor] Watching {len(events)} events...\n")

    for event in events:
        ts = event.get("timestamp", "??:??:??")
        name = event.get("name", "unknown")
        pid = event.get("pid", "?")
        parent = event.get("parent_name") or "—"
        action = event.get("action", "process_start")

        if action == "process_start":
            print(f"  [{ts}] {name} (pid {pid})  ←  {parent}")
        else:
            detail = event.get("detail", action)
            print(f"  [{ts}] {name} (pid {pid})  —  {detail}")

        time.sleep(delay)

        snapshot = {
            "pid": event.get("pid"),
            "name": event.get("name", ""),
            "parent_pid": event.get("parent_pid"),
            "parent_name": event.get("parent_name"),
            "cmdline": event.get("cmdline", ""),
        }

        if is_trigger(snapshot):
            print(f"\n[sensor] *** TRIGGER: {name} (pid {pid}) matched a signature ***")
            print(f"[sensor] Running LLM triage...")
            should_fire, triage_reason = triage_with_llm(snapshot, events)
            print(f"[sensor] [TRIAGE] {'FIRE' if should_fire else 'SKIP'} — {triage_reason}")
            if should_fire:
                print(f"[sensor] Environment signal confirmed — initiating pipeline...\n")
                on_trigger(snapshot, events)
                return True

    return False


# ---------------------------------------------------------------------------
# CLI entry point (real monitoring only)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="cyber-sense process monitor")
    parser.add_argument("--watch", action="store_true", help="Watch real processes with psutil")
    args = parser.parse_args()

    if args.watch:
        def on_trigger(snapshot: dict):
            cmdline = snapshot.get("cmdline", [])
            if isinstance(cmdline, list):
                cmdline = " ".join(cmdline)
            print(f"\n  [TRIGGER FIRED]")
            print(f"  Process : {snapshot['name']} (pid {snapshot['pid']})")
            print(f"  Parent  : {snapshot['parent_name']} (pid {snapshot['parent_pid']})")
            print(f"  Cmdline : {cmdline}\n")

        watch_real(on_trigger)
    else:
        print("Run with --watch to monitor real processes.")
        print("Import inject_simulated_event to use from demo scripts.")
