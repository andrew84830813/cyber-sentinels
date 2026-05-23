#!/usr/bin/env python3
"""
cyber-sense demo — runs all four scenarios through the autonomous pipeline.

For scenarios A, B, C the sensor watches the event stream, detects a trigger
signature, and fires the LangGraph pipeline automatically — no human prompt.

For scenario N (normal/benign) no trigger fires. The pipeline runs directly
to demonstrate the BENIGN classification path.

Usage:
    python demo.py                  # all four scenarios
    python demo.py --scenario A     # PowerShell download cradle
    python demo.py --scenario B     # web shell activity
    python demo.py --scenario C     # ransomware staging
    python demo.py --scenario N     # normal activity (baseline, expects BENIGN)
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

if not os.getenv("ANTHROPIC_API_KEY"):
    print("Error: ANTHROPIC_API_KEY is not set.")
    print("Add it to a .env file or export it in your shell:")
    print("  export ANTHROPIC_API_KEY=sk-ant-...")
    sys.exit(1)

from simulation.malicious import get_scenario_a, get_scenario_b, get_scenario_c
from simulation.normal import get_normal_scenario
from sensor.monitor import watch_simulated
from agent.graph import run_scenario

SCENARIOS = {
    "A": (get_scenario_a, "PowerShell Download Cradle"),
    "B": (get_scenario_b, "Web Shell Activity"),
    "C": (get_scenario_c, "Ransomware Staging"),
    "N": (get_normal_scenario, "Normal User Activity (Baseline)"),
}

DIVIDER = "\n" + "=" * 62 + "\n"


def save_report(report: str, scenario_key: str) -> str:
    reports_dir = Path("output/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = reports_dir / f"scenario_{scenario_key}_{ts}.txt"
    path.write_text(report)
    return str(path)


def _finish(report: str, scenario_key: str):
    print(report)
    saved = save_report(report, scenario_key)
    print(f"\n  [saved → {saved}]")


def run_one(scenario_key: str, session_id: str = "default"):
    fn, label = SCENARIOS[scenario_key]
    events, name = fn()

    print(f"Scenario {scenario_key}: {label}")
    print("-" * 50)

    if scenario_key == "N":
        # No trigger signatures match normal activity — the sensor correctly stays silent.
        # Run the pipeline directly to show the BENIGN classification path.
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
        # Sensor-driven: watch_simulated detects the trigger and fires the pipeline.
        triggered = False

        def on_trigger(snapshot: dict, all_events: list):
            nonlocal triggered
            triggered = True
            report = run_scenario(name, snapshot, all_events, session_id=session_id)
            print()
            _finish(report, scenario_key)

        fired = watch_simulated(name, events, on_trigger, delay=0.25)

        if not fired:
            print(f"\n[sensor] Warning: no trigger detected in scenario {scenario_key} feed.")


def main():
    parser = argparse.ArgumentParser(description="cyber-sense autonomous threat detection demo")
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()),
        metavar="SCENARIO",
        help="A=PowerShell, B=WebShell, C=Ransomware, N=Normal",
    )
    args = parser.parse_args()

    print("=" * 62)
    print("  CYBER-SENSE — Autonomous Threat Detection Demo")
    print("  Environment-triggered AI security analysis pipeline")
    print("=" * 62)
    print()
    print("  Sensor watches process events → detects trigger →")
    print("  LangGraph pipeline fires → structured threat report")
    print()
    print("  Initiated by: environment signal (process monitor)")
    print("  Human involvement: none at detection or analysis stage")

    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.scenario:
        print(DIVIDER)
        run_one(args.scenario, session_id=session_id)
    else:
        for key in ["A", "B", "C", "N"]:
            print(DIVIDER)
            run_one(key, session_id=session_id)

    print(DIVIDER)
    print("Demo complete.\n")


if __name__ == "__main__":
    main()
