#!/usr/bin/env python3
"""
cyber-sense continuous mode — full autonomous pipeline against real processes.

The sensor watches live process events via psutil. When a trigger signature
fires, LLM triage (Haiku) confirms the signal, and the full LangGraph analysis
pipeline (Sonnet) runs autonomously. A structured threat report is printed and
saved to output/reports/. No human is involved at any stage.

This is the production architecture. demo.py runs the same pipeline against
simulated event sequences so the demo works on any machine without elevated
permissions. The agent code is identical in both modes — only the event source
changes.

─────────────────────────────────────────────────────────────
  COST WARNING
  Each confirmed trigger makes two LLM calls:
    - Haiku triage:    ~$0.0002 per trigger
    - Sonnet analysis: ~$0.01–0.03 per trigger
  On a busy system, trigger signatures can match frequently.
  Review TRIGGER_SIGNATURES in sensor/monitor.py and tune them
  to your environment before running continuously in production.
  Consider running with --dry-run first to see what fires.
─────────────────────────────────────────────────────────────

Usage:
    python run_continuous.py              # full pipeline, save reports
    python run_continuous.py --dry-run    # sensor + triage only, no Sonnet analysis

Permissions:
    Basic process enumeration works without elevated privileges on macOS/Linux.
    Full cmdline and parent access for system processes may require sudo/root
    on Linux, or running as Administrator on Windows.

Press Ctrl+C to stop.
"""

import os
import sys
import argparse
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

if not os.getenv("ANTHROPIC_API_KEY"):
    print("Error: ANTHROPIC_API_KEY is not set.")
    print("Add it to a .env file or export it in your shell:")
    print("  export ANTHROPIC_API_KEY=sk-ant-...")
    sys.exit(1)

try:
    import psutil
except ImportError:
    print("Error: psutil is required for real process monitoring.")
    print("Run: pip install psutil")
    sys.exit(1)

from sensor.monitor import watch_real, TRIGGER_SIGNATURES
from agent.graph import run_scenario


def main():
    parser = argparse.ArgumentParser(
        description="cyber-sense continuous autonomous monitoring"
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
        print("  ⚠  COST NOTICE: each confirmed trigger makes a Sonnet LLM call.")
        print("     Review trigger signatures below before running on a busy system.")
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


if __name__ == "__main__":
    main()
