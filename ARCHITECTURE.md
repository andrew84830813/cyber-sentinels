# cyber-ignition-agents Architecture

> Architecture reference for the initiation-autonomous cybersecurity agent built to accompany [The Ignition Problem](./the-ignition-problem-v3.md).

The system demonstrates one architectural argument: **initiation autonomy** is a property of the surrounding infrastructure, not the agent itself. The sensing layer detects a threat and fires the pipeline — no human is in the initiation path. Environment changes; sensor fires; agent reasons and reports.

All five diagrams render natively in GitHub, VS Code (Mermaid Preview extension), and Notion. To view locally install the [Mermaid Preview](https://marketplace.visualstudio.com/items?itemName=bierner.markdown-mermaid) VS Code extension and open this file in the preview pane.

---

## 1. Four-Layer System Architecture

Components and data flows across all four layers. Dashed purple nodes are production-scale extension points scaffolded in `src/cyber_ignition_agents/sensor/orchestrator.py` and documented in the README.

```mermaid
graph TD
    ENV["Environment: Process Activity Stream<br/>real mode: psutil polling  |  demo mode: simulated events"]

    subgraph L1["Layer 1 — Sensing / Ignition   ·   src/cyber_ignition_agents/sensor/monitor.py + orchestrator.py"]
        C3["Category 3: Rule-Based Sensing<br/>TRIGGER_SIGNATURES → is_trigger()"]
        TRIAGE["LLM Triage Gate<br/>triage_with_llm()  ·  claude-haiku-4-5-20251001"]
        C4["Category 4: Adaptive Orchestrator<br/>OrchestratorSession  ·  claude-haiku-4-5-20251001<br/>adaptive cadence · no pre-specified rules"]
    end

    subgraph L2["Layer 2 — Orchestration   ·   src/cyber_ignition_agents/agent/graph.py"]
        GRAPH["LangGraph StateGraph<br/>ThreatState  ·  5-node linear pipeline<br/>compiled once, reused across all scenarios"]
    end

    subgraph L3["Layer 3 — Reasoning   ·   src/cyber_ignition_agents/agent/agent.py + tools.py"]
        AGENT["ReAct Agent<br/>claude-sonnet-4-6  ·  MemorySaver checkpointer"]
        TOOLS["4 Analysis Tools<br/>format_process_tree  ·  identify_attack_patterns<br/>lookup_mitre_technique  ·  get_similar_threats"]
    end

    subgraph L4["Layer 4 — Persistence   ·   src/cyber_ignition_agents/memory/store.py"]
        CHROMA[(ChromaDB<br/>src/cyber_ignition_agents/output/chroma_db/)]
        HIST["threat_history.json<br/>src/cyber_ignition_agents/output/threat_history.json"]
    end

    OUT["Threat Report<br/>output/reports/*.txt  ·  console"]

    ENV --> C3
    ENV --> C4
    C3 -- "signature match" --> TRIAGE
    TRIAGE -- "FIRE" --> GRAPH
    C4 -- "INVESTIGATE" --> GRAPH
    GRAPH --> AGENT
    AGENT <--> TOOLS
    TOOLS -- "get_similar_threats" --> CHROMA
    GRAPH -- "save_threat()" --> CHROMA
    GRAPH -- "save_threat()" --> HIST
    GRAPH --> OUT

    SM["SCALE: SessionManager<br/>N parallel OrchestratorSessions per host<br/>one per suspected attack chain"]
    META["SCALE: MetaOrchestrator<br/>cross-host graph coordination<br/>Sonnet budget allocation by severity"]
    SPEC["SCALE: Specialist Agents<br/>ProcessAnalyst  ·  NetworkAnalyst  ·  FileSystemAnalyst<br/>parallel execution + synthesizer node"]
    FLEET["SCALE: Fleet-wide vector store<br/>+ SIEM write-back (Splunk, Elastic, etc.)"]

    C4 -.-> SM
    GRAPH -.-> META
    AGENT -.-> SPEC
    CHROMA -.-> FLEET

    classDef scaleNode fill:#2a1a40,stroke:#9b59b6,stroke-dasharray:5 5,color:#d7aefb,font-style:italic
    class SM,META,SPEC,FLEET scaleNode
```

---

## 2. LangGraph Pipeline — Node Detail

Internal view of the five-node pipeline. Each node reads the full `ThreatState`, adds its field(s), and passes the accumulated state forward. No branching; no loops; no shared mutable state between nodes.

```mermaid
graph LR
    S([START])

    N1["trigger_received<br/>─────────────<br/>adds: trigger<br/>adds: process_events<br/>─────────────<br/>no LLM call"]

    N2["monitor_activity<br/>─────────────<br/>adds: process_sequence<br/>format_process_sequence()<br/>─────────────<br/>no LLM call"]

    N3["analyze_sequence<br/>─────────────<br/>adds: analysis<br/>ReAct agent loop<br/>─────────────<br/>claude-sonnet-4-6<br/>+ 4 tool calls"]

    N4["classify_threat<br/>─────────────<br/>adds: classification<br/>JSON verdict<br/>─────────────<br/>claude-sonnet-4-6<br/>direct call"]

    N5["generate_report<br/>─────────────<br/>adds: report<br/>save_threat()<br/>write to disk<br/>─────────────<br/>no LLM call"]

    E([END])

    S --> N1 --> N2 --> N3 --> N4 --> N5 --> E

    classDef llmNode fill:#1e3a5f,stroke:#4a9eff,color:#e0f0ff
    classDef noLlm fill:#1a3a1a,stroke:#27ae60,color:#a8e6a8
    class N3,N4 llmNode
    class N1,N2,N5 noLlm
```

**ThreatState fields accumulated by pipeline completion:**

| Field | Set by node | Content |
|---|---|---|
| `trigger` | trigger_received | snapshot dict that fired the sensor |
| `process_events` | trigger_received | full event list from monitoring window |
| `process_sequence` | monitor_activity | formatted process tree string |
| `analysis` | analyze_sequence | ReAct agent narrative |
| `classification` | classify_threat | `{threat_level, confidence, techniques, reasoning, recommended_actions}` |
| `report` | generate_report | final formatted report string |
| `orchestrator_reasoning` | set at invoke | empty in Category 3; orchestrator text in Category 4 |

---

## 3. Sequence Diagram — Category 3: Rule-Based Ignition

The rule-based sensing path: a hard-coded signature match gates a Haiku triage call, which confirms before the full Sonnet pipeline fires.

```mermaid
sequenceDiagram
    actor ENV as Environment
    participant MON as monitor.py
    participant HAIKU as Haiku (triage gate)
    participant GRAPH as LangGraph
    participant SONNET as Sonnet (ReAct)
    participant DB as ChromaDB
    participant FS as Filesystem

    ENV->>MON: process event {pid, name, parent_name, cmdline}
    MON->>MON: is_trigger(snapshot)?
    Note right of MON: TRIGGER_SIGNATURES matched<br/>e.g. powershell.exe -EncodedCommand

    MON->>+HAIKU: triage_with_llm(snapshot, recent_events)
    Note over HAIKU: cached system prompt<br/>max_tokens=150
    HAIKU-->>-MON: FIRE — "Encoded PowerShell confirms download cradle"

    Note over MON,GRAPH: Environment signal confirmed — initiating pipeline

    MON->>+GRAPH: invoke(ThreatState) — node 1: trigger_received
    Note over GRAPH: node 2: monitor_activity<br/>format_process_sequence() — no LLM

    GRAPH->>+SONNET: node 3: analyze_sequence — ReAct agent loop
    SONNET->>SONNET: format_process_tree(events_json)
    SONNET->>SONNET: identify_attack_patterns(process_sequence)
    SONNET->>SONNET: lookup_mitre_technique("T1059.001")
    SONNET->>+DB: get_similar_threats("PowerShell download cradle")
    DB-->>-SONNET: similar past detections (ChromaDB semantic search)
    SONNET-->>-GRAPH: analysis narrative

    GRAPH->>+SONNET: node 4: classify_threat — direct call, no tools
    Note over SONNET: cached system prompt<br/>max_tokens=600
    SONNET-->>-GRAPH: {"threat_level":"HIGH","confidence":0.94,"techniques":["T1059.001","T1105"],...}

    Note over GRAPH: node 5: generate_report — assemble output, no LLM
    GRAPH->>DB: save_threat(scenario, level, techniques, analysis)
    GRAPH->>FS: write output/reports/[timestamp].txt
    GRAPH-->>-MON: formatted report string

    Note over MON,FS: Initiated by: environment signal (process monitor)
    Note over MON,FS: Human involvement: none at detection or analysis stage
```

---

## 4. Sequence Diagram — Category 4: Adaptive Orchestrator Ignition

The orchestrator path: no trigger signatures are consulted. The `OrchestratorSession` evaluates a rolling event window at adaptive intervals and decides autonomously when to investigate.

```mermaid
sequenceDiagram
    actor ENV as Environment
    participant ORCH as OrchestratorSession
    participant HAIKU as Haiku (orchestrator)
    participant GRAPH as LangGraph
    participant SONNET as Sonnet (ReAct)
    participant DB as ChromaDB
    participant FS as Filesystem

    Note over ORCH: No TRIGGER_SIGNATURES consulted.<br/>Reasoning from general security knowledge.

    ENV->>ORCH: add_event() — explorer.exe spawned cmd.exe
    ENV->>ORCH: add_event() — cmd.exe spawned powershell.exe
    ENV->>ORCH: add_event() — powershell.exe -EncodedCommand [...]
    ENV->>ORCH: add_event() — certutil.exe -urlcache -f http://...
    ENV->>ORCH: add_event() — outbound connection attempt

    Note over ORCH: events_since_last_eval >= next_check_events (5)

    ORCH->>+HAIKU: _evaluate() — rolling window (5 events)
    Note over HAIKU: cached system prompt<br/>max_tokens=250
    HAIKU-->>-ORCH: DECISION: CONTINUE, NEXT_CHECK: 3, REASONING: "unusual but monitoring"

    Note over ORCH: CONTINUE — next check in 3 events

    ENV->>ORCH: add_event() — powershell.exe writes stage2.exe to %TEMP%
    ENV->>ORCH: add_event() — stage2.exe executes
    ENV->>ORCH: add_event() — stage2.exe spawns cmd.exe

    Note over ORCH: events_since_last_eval >= next_check_events (3)

    ORCH->>+HAIKU: _evaluate() — rolling window (8 events)
    HAIKU-->>-ORCH: DECISION: INVESTIGATE, NEXT_CHECK: 5, REASONING: "PowerShell cradle confirmed"

    Note over ORCH: *** INVESTIGATE ***

    ORCH->>+GRAPH: invoke(ThreatState, orchestrator_reasoning=...) — node 1
    Note over GRAPH,SONNET: Same 5-node pipeline as Category 3<br/>(nodes 2–5 identical)

    GRAPH->>SONNET: node 3: analyze_sequence + node 4: classify_threat
    SONNET->>DB: get_similar_threats(query)
    DB-->>SONNET: similar past detections
    SONNET-->>GRAPH: analysis narrative + JSON verdict

    Note over GRAPH: node 5: generate_report<br/>includes ORCHESTRATOR DECISION block
    GRAPH->>DB: save_threat()
    GRAPH->>FS: write output/reports/[timestamp].txt
    GRAPH-->>-ORCH: formatted report (with ORCHESTRATOR DECISION block)

    Note over ORCH,FS: Initiated by: autonomous orchestrator reasoning (no pre-specified rules)
    Note over ORCH,FS: Human involvement: none at initiation, analysis, or detection stage
```

---

## 5. Scalability Extension Map

The demo runs one sensor and one pipeline on one endpoint. The architecture is designed so each layer extends to fleet scale independently. Blue = current demo. Purple dashed = production extension points.

```mermaid
graph LR
    subgraph DEMO["Current Demo  (single endpoint)"]
        direction TB
        D1["Layer 1: Single Sensor<br/>Category 3 or Category 4<br/>src/cyber_ignition_agents/sensor/monitor.py"]
        D2["Layer 2: Single Pipeline<br/>LangGraph 5-node linear chain<br/>src/cyber_ignition_agents/agent/graph.py"]
        D3["Layer 3: Single ReAct Agent<br/>claude-sonnet-4-6  +  4 tools<br/>src/cyber_ignition_agents/agent/agent.py"]
        D4["Layer 4: Local ChromaDB<br/>single-host threat history<br/>src/cyber_ignition_agents/memory/store.py"]
        D1 --> D2 --> D3
        D3 <--> D4
    end

    subgraph SCALE["Production Scale  (fleet)"]
        direction TB
        S1["Fleet Sensor Mesh<br/>N endpoints, own sensing layer per host<br/>SessionManager: N parallel OrchestratorSessions per host"]
        S2["MetaOrchestrator<br/>cross-host LangGraph<br/>correlates attack chains across hosts<br/>rate limiting + Sonnet budget by severity"]
        S3["Specialist Agent Pool<br/>ProcessAnalyst  ·  NetworkAnalyst  ·  FileSystemAnalyst<br/>parallel execution + synthesizer node"]
        S4["Central Vector Store<br/>fleet-wide threat history + cross-host similarity<br/>+ SIEM write-back (Splunk / Elastic / PagerDuty)"]
        S1 --> S2 --> S3
        S3 <--> S4
    end

    subgraph ACTION["Action Layer  (not in demo)"]
        direction TB
        A1["Host Isolation"]
        A2["Credential Revocation"]
        A3["Incident Response Workflow"]
    end

    D1 -. "extends to" .-> S1
    D2 -. "extends to" .-> S2
    D3 -. "extends to" .-> S3
    D4 -. "extends to" .-> S4
    S2 -. "triggers" .-> ACTION

    classDef demo fill:#1e3a5f,stroke:#4a9eff,color:#e0f0ff
    classDef scale fill:#2a1a40,stroke:#9b59b6,stroke-dasharray:5 5,color:#d7aefb
    classDef action fill:#3a1a1a,stroke:#e74c3c,stroke-dasharray:5 5,color:#f5a0a0
    class D1,D2,D3,D4 demo
    class S1,S2,S3,S4 scale
    class A1,A2,A3 action
```

---

## Key Design Decisions

**Sensing and reasoning are separate layers with an identical callback interface.**
All three sensing modes (`watch_real`, `watch_simulated`, `watch_with_orchestrator`) share the same callback signature: `callback(snapshot, events[, orchestrator_reasoning])`. The pipeline cannot distinguish real from simulated events, or Category 3 from Category 4 ignition. This means the demo runs without elevated permissions or live threats while preserving the exact production architecture pattern. Swapping the event source does not touch any downstream code.

**The callback interface is the architectural seam.**
The line `callback(snapshot, events)` is where initiation autonomy lives. Everything to the left of that call is the ignition infrastructure (sensing, triage, orchestration decisions). Everything to the right is the analysis pipeline. The two halves are independently upgradeable. Category 4 replaced Category 3's rule-based gate with LLM reasoning without changing a single line of the pipeline.

**The five-node pipeline is deliberately linear.**
No branching, no parallel nodes, no conditional edges. Each node has one responsibility, reads the full `ThreatState`, adds its field(s), and passes forward. This makes the state transformation inspectable at each step (demonstrated in notebook Section 5) and keeps the graph trivially testable. Branching (e.g. routing high-confidence verdicts to an escalation path) is a production addition, not needed for the architectural argument this demo makes.

**The demo ends at report generation; the production system does not.**
In this demo the action layer is a printed report. In production the same pipeline would feed host isolation, credential revocation, or incident response workflow triggers. The cost of a false positive, a missed trigger, or an adversarially crafted signal scales directly with how consequential the downstream action is — which is why the sensing layer and triage gate are the system's highest-leverage security boundary, not an afterthought.
