# The Demo Story — What cyber-ignition-agents Does and Why

This document tells the full story of the `notebooks/cyber_ignition_agents_playground.ipynb` demo,
section by section, in plain language. It is meant to be read before running the notebook
so you can verify the demo matches your expectations.

---

## The argument the demo is making

The article "The Ignition Problem" draws a line between two kinds of autonomy:

- **Execution autonomy**: once the agent is running, it acts across multiple steps
  without asking for human approval at each one.
- **Initiation autonomy**: the agent starts without a human deciding to start it.
  The environment changes; the sensing layer detects it; the pipeline fires.

Most agents people call "autonomous" have execution autonomy but not initiation autonomy.
A human still types a prompt or clicks a button. The agent is autonomous during its run,
but someone had to ignite it.

This demo makes that distinction operational. It builds a system where:
- Three attack scenarios fire the pipeline on their own, triggered by process events.
- A normal scenario does not fire the pipeline — the sensing layer correctly filters it.
- The same five-node pipeline runs regardless of what fired it.
- The report's footer records who or what initiated the analysis.

The demo then shows two different versions of the sensing layer — Category 3 (rule-based)
and Category 4 (LLM orchestrator) — and demonstrates that the pipeline output is identical
in both cases. The difference is only in the initiation trail.

---

## The four layers

```
[Layer 1]  sensor/monitor.py + sensor/orchestrator.py   ← ignition layer
[Layer 2]  agent/graph.py  (LangGraph 5-node pipeline)  ← orchestration
[Layer 3]  agent/agent.py  (ReAct agent + 4 tools)      ← reasoning
[Layer 4]  memory/store.py (ChromaDB + JSON history)    ← persistence
```

Each layer is independent and inspectable. The notebook exposes each one so you can
see exactly what is passed between them.

---

## Section 1 — Setup

**What happens:** Finds the project root, adds `src/` to sys.path, loads the `.env`
file, and confirms the Anthropic API key is present.

**What you see:** Two lines confirming the project root path and Python version, then
a key-loaded confirmation showing the first 12 characters of your API key.

**Why it matters:** The notebook must run against the editable-installed package
(`src/cyber_ignition_agents/`), not any other installed version. The sys.path manipulation
ensures this regardless of which Jupyter kernel is active.

---

## Section 2 — Scenarios: the raw event data

**What happens:** Imports four scenario generators from `simulation/malicious.py` and
`simulation/normal.py`, loads them into variables, and prints summary counts and a
human-readable process tree for each.

**The four scenarios:**

| Key | Name | What it shows |
|-----|------|---------------|
| A | PowerShell Download Cradle | `explorer → cmd → powershell -EncodedCommand → certutil -urlcache` to a malicious URL |
| B | Web Shell Activity | `w3wp.exe` (IIS) spawning `cmd.exe`, then running `whoami`, `net user`, `net group "Domain Admins"` |
| C | Ransomware Staging | Unknown `update.exe` spawning `vssadmin delete shadows`, then mass file renames to `.locked` |
| N | Normal User Activity | `explorer → chrome`, `Code.exe → node.exe`, `Code.exe → python.exe` |

**What you see:** Each scenario prints as a process tree — `[timestamp] process (pid) ← parent_process`
with command lines indented below. You can inspect the exact dict format for any event
by running the single-event inspection cell.

**Why it matters:** These events are the only things the sensor ever sees — whether
running in simulation or against real psutil processes. The event format is identical
in both modes. Everything downstream is fed these dicts.

---

## Section 3 — Category 3: Rule-based sensor (dry-run, no LLM)

**What happens:** Runs `is_trigger()` against every event in every scenario. No API
calls are made. The cell marks which event, if any, would fire the pipeline.

**The trigger signatures** (six hard-coded rules in `sensor/monitor.py`):
- `powershell.exe` with `-EncodedCommand` in cmdline
- `powershell.exe` with ` -enc ` in cmdline
- `w3wp.exe` spawning `cmd.exe` (IIS web shell)
- `w3wp.exe` spawning `powershell.exe`
- `httpd.exe` spawning `cmd.exe`
- `vssadmin.exe` with `delete shadows` in cmdline

**What you see:**
- Scenario A: `powershell.exe` event marked `◀ TRIGGER`
- Scenario B: `cmd.exe` spawned by `w3wp.exe` marked `◀ TRIGGER`
- Scenario C: `vssadmin.exe` event marked `◀ TRIGGER`
- Scenario N: no trigger matched — all events pass cleanly

**The extension demonstration:** The section then shows adding a new rule at runtime
(`outlook.exe` spawning `mshta.exe`). Before the rule: the mshta event passes undetected.
After the rule is added to `TRIGGER_SIGNATURES`: the event is flagged. This illustrates
the Category 3 adaption model — a human authors a rule, the system detects it going forward.

**The point being made:** Category 3 is fast, deterministic, and costs nothing until a
rule fires. But it can only detect techniques a human anticipated and wrote a rule for.

---

## Section 4 — Category 4: Adaptive orchestrator (Haiku calls)

**What happens:** An `OrchestratorSession` (backed by `claude-haiku-4-5-20251001`)
receives events one at a time. No trigger signatures are consulted. After every N events
(where N is set by the model itself based on suspicion level), the orchestrator evaluates
the accumulated window and decides:

- `INVESTIGATE` — fire the pipeline now
- `CONTINUE` — keep watching, check again in X events (the model sets X)

**What you see for malicious scenarios:**
- The orchestrator prints each event as it arrives
- When a check interval triggers, it prints its INVESTIGATE/CONTINUE decision with 2–4
  sentences of reasoning
- For scenarios A/B/C, it eventually prints `*** INVESTIGATE ***` with the specific
  behavioral patterns it identified as suspicious
- For scenario N (normal activity), it reaches the end of the feed, runs a final
  evaluation, and prints `CONTINUE — No investigation warranted`

**The mshta comparison:** The same `outlook → mshta` events from Section 3 are run
through the orchestrator with no rule added. The orchestrator correctly identifies
this as suspicious from general security knowledge — no rule was needed.

**LLM calls made:** Each check interval triggers one Haiku call. Across all four
scenarios, expect 8–12 Haiku calls total in this section (~$0.002).

**The point being made:** The orchestrator can surface techniques that no human
pre-specified. It reasons from general security knowledge, not a lookup table. This
addresses the "rules only catch what you know" limitation of Category 3 — but
introduces per-event LLM cost and is harder to audit.

---

## Section 5 — Pipeline step-by-step (Sonnet calls)

**What happens:** Runs the five LangGraph nodes one at a time against Scenario A,
printing the pipeline state after each node.

**The five nodes:**

**Node 1 — `trigger_received`**
Receives the trigger snapshot (the process that matched the sensor) and the full
event list. Logs the trigger to console. Does not modify state. No LLM call.

**Node 2 — `monitor_activity`**
Formats the raw event list into a human-readable `process_sequence` string —
a structured process tree with timestamps, pids, parent-child relationships, and
command lines. No LLM call. What you see: the full process tree printed to output.

**Node 3 — `analyze_sequence`**
The ReAct agent (Claude Sonnet 4.6) receives the process tree and reasons about it
using four tools:
- `format_process_tree` — reformats the event JSON into a readable tree
- `identify_attack_patterns` — regex/string matching against known attack patterns
- `lookup_mitre_technique` — local lookup table for MITRE ATT&CK technique IDs
- `get_similar_threats` — semantic search over past detections in ChromaDB

The agent calls these tools in sequence (you see `[Anthropic API call]` lines as it
goes), then synthesizes a narrative threat analysis. One Sonnet call.

**Node 4 — `classify_threat`**
A separate Sonnet call produces a structured JSON verdict:
```json
{
  "threat_level": "HIGH",
  "confidence": 0.94,
  "techniques": ["T1059.001", "T1105"],
  "reasoning": "concise explanation"
}
```
No tools are used — just direct classification from the analysis text.

**Node 5 — `generate_report`**
Assembles the final report from all accumulated state fields. For non-BENIGN verdicts,
also saves the detection to ChromaDB and `output/threat_history.json`. No LLM call.

**What you see after each node:**
- After node 1: confirmation that state passed through
- After node 2: the formatted process tree
- After node 3: the first 1000 characters of the threat analysis narrative
- After node 4: the JSON classification dict
- After node 5: the complete formatted threat report

**LLM calls made:** Two Sonnet calls (~$0.02–0.04 for Scenario A).

**The point being made:** Each node has a single responsibility. The state object
accumulates context as it moves through the pipeline. By running nodes individually,
you can see exactly what each one contributes and verify the data handoffs.

---

## Section 6 — Agent tools & memory

**What happens:** Calls each of the four agent tools directly, without going through
the full agent loop, and inspects the ChromaDB threat history.

**Tool demonstrations:**

`format_process_tree` — takes raw event JSON as a string, returns a formatted process
tree. Useful for understanding what the agent sees when it calls this tool internally.

`identify_attack_patterns` — takes a process sequence string, returns matched pattern
names using string matching. No LLM. Shows which named attack patterns are detected
by the text-matching heuristics (e.g., "PowerShell download cradle", "web shell
reconnaissance").

`lookup_mitre_technique` — takes a technique ID like `T1059.001`, returns the technique
name and description from a local dict. No LLM. Demonstrates the reference data
the agent uses when building its analysis.

`get_similar_threats` — queries ChromaDB with a natural-language string, returns
semantically similar past detections. Will be empty until you've run Section 7 or 8
at least once to populate the store.

**Memory inspection:** Shows the JSON threat history (count of records, most recent
5), then runs a semantic similarity search so you can see what ChromaDB returns for
a query like "web shell reconnaissance whoami net user".

**The point being made:** The agent tools are plain Python functions decorated with
`@tool`. They can be called and tested independently of the agent loop. The memory
layer persists across runs — `get_similar_threats` genuinely searches past detections,
not a mock.

---

## Section 7 — Full run: rules mode (Category 3)

**What happens:** Runs `watch_simulated()` against a scenario you choose (default:
Scenario C, ransomware). This is the complete Category 3 path:

```
watch_simulated(events) → is_trigger() match → triage_with_llm() (Haiku) → run_scenario() (Sonnet)
```

If the scenario is malicious, `watch_simulated` prints each event as it arrives,
detects the trigger, calls Haiku to confirm, then fires `run_scenario()`. If the
scenario is normal (N), no trigger matches and the pipeline is called directly for
comparison purposes.

**What you see:**
- Each process event printed as it "arrives" (delay=0 in notebook mode for speed)
- `[sensor] *** TRIGGER: vssadmin.exe matched a signature ***`
- `[sensor] [TRIAGE] FIRE — <one sentence from Haiku>`
- `[sensor] Environment signal confirmed — initiating pipeline...`
- Then the LangGraph pipeline runs: `[1/5] trigger_received`, `[2/5] monitor_activity`,
  etc., with `[Anthropic API call]` lines from the ReAct agent
- The complete threat report printed in the next cell

**The report footer for Category 3:**
```
Initiated by: environment signal (process monitor)
Human involvement: none at detection or analysis stage
```

**LLM calls made:** 1 Haiku (triage) + 2 Sonnet (analyze + classify) (~$0.02–0.04).

---

## Section 8 — Full run: orchestrator mode (Category 4)

**What happens:** Runs `watch_with_orchestrator()` against a scenario you choose
(default: Scenario B, web shell). This is the complete Category 4 path:

```
watch_with_orchestrator(events) → OrchestratorSession evaluates rolling window
    → INVESTIGATE decision → run_scenario() with orchestrator_reasoning
```

**What you see:**
- `[orchestrator] Adaptive sensing: Web Shell Activity`
- `[orchestrator] No pre-specified rules — reasoning from general knowledge`
- Each event printed as it arrives
- At check intervals: `[orchestrator] CONTINUE — <reasoning>` or `*** INVESTIGATE ***`
- When INVESTIGATE fires: `[orchestrator] Initiating analysis pipeline...`
- The full LangGraph pipeline runs
- The complete threat report with an added `ORCHESTRATOR DECISION` block

**The report footer for Category 4:**
```
ORCHESTRATOR DECISION
---------------------
Decision:   INVESTIGATE
Reasoning:  <the orchestrator's 2–4 sentence reasoning, verbatim>

Initiated by: autonomous orchestrator reasoning (no pre-specified rules)
Human involvement: none at initiation, analysis, or detection stage
```

**LLM calls made:** 2–4 Haiku (orchestrator) + 2 Sonnet (analyze + classify) (~$0.02–0.05).

---

## Section 9 — Side-by-side: Category 3 vs Category 4

**What happens:** Runs Scenario A (PowerShell download cradle) through both modes,
then prints the first 25 lines of each report and extracts the initiation trail lines.

**What you see:**

```
Category 3:
  Initiated by: environment signal (process monitor)
  Human involvement: none at detection or analysis stage

Category 4:
  Initiated by: autonomous orchestrator reasoning (no pre-specified rules)
  Human involvement: none at initiation, analysis, or detection stage
```

Below the headers, the two reports are structurally identical: same PROCESS SEQUENCE
format, same THREAT CLASSIFICATION JSON fields, same ANALYSIS narrative structure,
same RECOMMENDED ACTIONS format. The threat level and confidence values may differ
slightly between runs (LLM non-determinism) but will both land at HIGH.

**The point being made:** This is the demo's central claim made visible. The pipeline
output is the same. The initiation trail is different. Category 3 was triggered because
a human wrote a rule that matched. Category 4 was triggered because a model reasoned
that the behavior was suspicious — no rule was needed, and no human was involved at
the initiation stage.

**LLM calls made:** Two full pipeline runs (~$0.05–0.10 total).

---

## What the report footer means

Every generated report ends with some version of these lines:

```
Initiated by: environment signal (process monitor)
Human involvement: none at detection or analysis stage
```

These lines are not cosmetic. They mark the autonomy class of the system:

- "environment signal" = initiation came from the process stream, not a human prompt
- "none at detection or analysis stage" = no human decided to look, no human decided to
  analyze, no human was in the loop at any point before the report was generated

Category 4 makes an even stronger claim:

```
Initiated by: autonomous orchestrator reasoning (no pre-specified rules)
Human involvement: none at initiation, analysis, or detection stage
```

"No pre-specified rules" distinguishes it from Category 3 — the decision to investigate
was made by a model reasoning from general knowledge, not by matching against
human-authored patterns.

---

## Total LLM cost for the full notebook

| Section | Calls | Approx. cost |
|---------|-------|-------------|
| 3 — sensor dry-run | none | $0 |
| 4 — orchestrator dry-run (4 scenarios) | 8–12 Haiku | ~$0.002 |
| 5 — pipeline step-by-step | 2 Sonnet | ~$0.03 |
| 6 — tools & memory | none | $0 |
| 7 — full run (rules) | 1 Haiku + 2 Sonnet | ~$0.03 |
| 8 — full run (orchestrator) | 2–4 Haiku + 2 Sonnet | ~$0.04 |
| 9 — side-by-side | 2 Haiku + 4 Sonnet | ~$0.07 |
| **Total** | | **~$0.17 (upper bound)** |

Sections 5, 7, 8, and 9 each make Sonnet calls. Run them in order — the memory layer
accumulates detections, and Section 6's `get_similar_threats` demo will have real data
to show after Section 7 or 8 has run.

---

## Things that are deliberately NOT in this demo

**No remediation actions.** The pipeline produces a report and saves to the vector store.
It does not isolate hosts, revoke credentials, or call external APIs. This is intentional —
the demo is making the architectural argument, not the action-layer argument.

**No real process monitoring in the notebook.** Sections 7–9 use simulated events.
Real psutil monitoring is available via `python run_continuous.py` but is out of scope
for the notebook demo. The simulation events are structurally identical to what
`watch_real()` would produce — that's the whole point of the SIMULATION HOOK comments.

**No adversarial scenarios.** The demo does not show evasion of trigger signatures or
LLM reasoning. That is a real limitation of both Category 3 and Category 4, documented
in the README's "What production systems will need to overcome" section.

**No multi-agent orchestration.** The article mentions A2A as the most powerful
combination. This demo shows the sensing → pipeline arc; A2A coordination between
multiple environment-triggered agents is described as future work, not demonstrated here.
