"""
Command-line entry points for cyber-ignition-agents.

demo_main()    — runs simulated attack scenarios (all four or one specific)
monitor_main() — runs continuous autonomous monitoring against real processes

Registered as console_scripts in pyproject.toml:
    cyber-ignition-agents         → cyber_ignition_agents.cli:demo_main
    cyber-ignition-agents-monitor → cyber_ignition_agents.cli:monitor_main
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Demo entry point
# ---------------------------------------------------------------------------

DIVIDER = "\n" + "=" * 62 + "\n"

SCENARIOS = {
    "A": ("get_scenario_a", "PowerShell Download Cradle"),
    "B": ("get_scenario_b", "Web Shell Activity"),
    "C": ("get_scenario_c", "Ransomware Staging"),
    "N": ("get_normal_scenario", "Normal User Activity (Baseline)"),
}


def _get_scenario_fn(key: str):
    from cyber_ignition_agents.simulation.malicious import get_scenario_a, get_scenario_b, get_scenario_c
    from cyber_ignition_agents.simulation.normal import get_normal_scenario
    fns = {
        "A": get_scenario_a,
        "B": get_scenario_b,
        "C": get_scenario_c,
        "N": get_normal_scenario,
    }
    return fns[key]


def _save_report(report: str, scenario_key: str) -> str:
    reports_dir = Path("output/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = reports_dir / f"scenario_{scenario_key}_{ts}.txt"
    path.write_text(report)
    return str(path)


def _finish(report: str, scenario_key: str):
    print(report)
    saved = _save_report(report, scenario_key)
    print(f"\n  [saved → {saved}]")


def _run_one(scenario_key: str, session_id: str = "default", mode: str = "orchestrator"):
    from cyber_ignition_agents.sensor.monitor import watch_simulated, watch_with_orchestrator
    from cyber_ignition_agents.agent.graph import run_scenario

    fn = _get_scenario_fn(scenario_key)
    _, label = SCENARIOS[scenario_key]
    events, name = fn()

    print(f"Scenario {scenario_key}: {label}")
    print(f"Mode: {'Category 4 — adaptive orchestrator' if mode == 'orchestrator' else 'Category 3 — rule-based signatures'}")
    print("-" * 50)

    if scenario_key == "N":
        if mode == "orchestrator":
            orch_reasoning_holder = []

            def on_trigger_orch(snapshot: dict, all_events: list, reasoning: str = ""):
                orch_reasoning_holder.append(reasoning)
                report = run_scenario(name, snapshot, all_events,
                                      session_id=session_id,
                                      orchestrator_reasoning=reasoning)
                print()
                _finish(report, scenario_key)

            fired = watch_with_orchestrator(name, events, on_trigger_orch, delay=0.25)

            if not fired:
                print("[orchestrator] No investigation initiated — running pipeline for BENIGN baseline.\n")
                trigger = {
                    "pid": events[0]["pid"],
                    "name": events[0]["name"],
                    "parent_pid": events[0].get("parent_pid"),
                    "parent_name": events[0].get("parent_name"),
                    "cmdline": events[0].get("cmdline", ""),
                }
                report = run_scenario(name, trigger, events, session_id=session_id)
                print()
                _finish(report, scenario_key)
        else:
            print("[sensor] Watching event stream...\n")
            for e in events:
                ts = e.get("timestamp", "??:??:??")
                n = e.get("name", "unknown")
                pid = e.get("pid", "?")
                parent = e.get("parent_name") or "—"
                print(f"  [{ts}] {n} (pid {pid})  ←  {parent}")

            print("\n[sensor] Feed complete — no trigger signatures detected.")
            print("[sensor] Benign baseline: running pipeline for BENIGN comparison.\n")

            trigger = {
                "pid": events[0]["pid"],
                "name": events[0]["name"],
                "parent_pid": events[0].get("parent_pid"),
                "parent_name": events[0].get("parent_name"),
                "cmdline": events[0].get("cmdline", ""),
            }
            report = run_scenario(name, trigger, events, session_id=session_id)
            print()
            _finish(report, scenario_key)

    else:
        if mode == "orchestrator":
            def on_trigger_orch(snapshot: dict, all_events: list, reasoning: str = ""):
                report = run_scenario(name, snapshot, all_events,
                                      session_id=session_id,
                                      orchestrator_reasoning=reasoning)
                print()
                _finish(report, scenario_key)

            fired = watch_with_orchestrator(name, events, on_trigger_orch, delay=0.25)
        else:
            def on_trigger_rules(snapshot: dict, all_events: list):
                report = run_scenario(name, snapshot, all_events, session_id=session_id)
                print()
                _finish(report, scenario_key)

            fired = watch_simulated(name, events, on_trigger_rules, delay=0.25)

        if not fired:
            print(f"\n[sensor] Warning: no trigger detected in scenario {scenario_key} feed.")


def demo_main():
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY is not set.")
        print("Add it to a .env file or export it in your shell:")
        print("  export ANTHROPIC_API_KEY=sk-ant-...")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="cyber-ignition-agents autonomous threat detection demo")
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()),
        metavar="SCENARIO",
        help="A=PowerShell, B=WebShell, C=Ransomware, N=Normal",
    )
    parser.add_argument(
        "--mode",
        choices=["orchestrator", "rules"],
        default="orchestrator",
        help="orchestrator=Category4 adaptive (default), rules=Category3 signature-based",
    )
    args = parser.parse_args()

    print("=" * 62)
    print("  CYBER-SENSE — Autonomous Threat Detection Demo")
    print("  Environment-triggered AI security analysis pipeline")
    print("=" * 62)
    print()
    if args.mode == "orchestrator":
        print("  Mode: Category 4 — Adaptive Orchestrator")
        print("  The orchestrator reasons over process events with no")
        print("  pre-specified rules and self-schedules its observation cadence.")
    else:
        print("  Mode: Category 3 — Rule-Based Signatures")
        print("  Hard-coded TRIGGER_SIGNATURES list fires on pattern match.")
        print("  (Use --mode orchestrator for Category 4 comparison)")
    print()

    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.scenario:
        print(DIVIDER)
        _run_one(args.scenario, session_id=session_id, mode=args.mode)
    else:
        for key in ["A", "B", "C", "N"]:
            print(DIVIDER)
            _run_one(key, session_id=session_id, mode=args.mode)

    print(DIVIDER)
    print("Demo complete.\n")


# ---------------------------------------------------------------------------
# Continuous monitor entry point
# ---------------------------------------------------------------------------

def monitor_main():
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY is not set.")
        print("Add it to a .env file or export it in your shell:")
        print("  export ANTHROPIC_API_KEY=sk-ant-...")
        sys.exit(1)

    try:
        import psutil  # noqa: F401
    except ImportError:
        print("Error: psutil is required for real process monitoring.")
        print("Run: pip install psutil")
        sys.exit(1)

    from cyber_ignition_agents.sensor.monitor import watch_real, TRIGGER_SIGNATURES
    from cyber_ignition_agents.agent.graph import run_scenario

    parser = argparse.ArgumentParser(
        description="cyber-ignition-agents continuous autonomous monitoring"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Sensor and triage only — print trigger events but do not run the full Sonnet pipeline",
    )
    args = parser.parse_args()

    session_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_continuous"

    print("=" * 62)
    if args.dry_run:
        print("  CYBER-SENSE — Sensor Dry Run (no Sonnet analysis)")
    else:
        print("  CYBER-SENSE — Continuous Autonomous Monitoring")
    print("  Watching real processes. Press Ctrl+C to stop.")
    print("=" * 62)
    print()

    if not args.dry_run:
        print("  COST NOTICE: each confirmed trigger makes a Sonnet LLM call.")
        print("  Review trigger signatures below before running on a busy system.")
        print()

    print("  Active trigger signatures:")
    for sig in TRIGGER_SIGNATURES:
        parts = [f"{k}={v!r}" for k, v in sig.items()]
        print(f"    {' AND '.join(parts)}")
    print()
    print("  Initiated by: environment signal (process monitor)")
    print("  Human involvement: none at detection or analysis stage")
    print()

    def on_trigger(snapshot: dict, recent_events: list):
        name = snapshot["name"]
        pid = snapshot["pid"]
        parent = snapshot.get("parent_name", "unknown")

        if args.dry_run:
            print(f"[dry-run] Would fire pipeline: {name} (pid {pid}) <- {parent}")
            print(f"          Context window: {len(recent_events)} events in buffer")
            return

        print(f"[pipeline] Running analysis: {name} (pid {pid}) <- {parent}")

        report = run_scenario(
            scenario_name=f"live_{name}_{pid}",
            trigger=snapshot,
            events=recent_events,
            session_id=session_id,
        )

        print(report)

        out_dir = Path("output/reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = out_dir / f"live_{name}_{ts}.txt"
        out_path.write_text(report)
        print(f"\n  [saved → {out_path}]")

    watch_real(on_trigger)
