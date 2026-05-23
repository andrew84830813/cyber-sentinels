"""
Tool definitions for the cyber-sense ReAct agent.

@tool-decorated functions are callable by the agent during reasoning.
Plain helpers at the bottom are called directly by graph.py nodes.
"""
import json
from typing import List

from langchain_core.tools import tool

from memory.store import search_similar_threats


@tool
def format_process_tree(events_json: str) -> str:
    """Parse a JSON list of process events and return a readable process tree
    showing parent-child relationships and execution sequence."""
    try:
        events: List[dict] = json.loads(events_json)
    except (json.JSONDecodeError, TypeError):
        return "Error: events_json must be a valid JSON array."
    lines = []
    for event in events:
        action      = event.get("action", "process_start")
        detail      = event.get("detail", "")
        ts          = event.get("timestamp", "??:??:??")
        name        = event.get("name", "unknown")
        pid         = event.get("pid", "?")
        parent_name = event.get("parent_name") or "—"
        parent_pid  = event.get("parent_pid") or "—"
        cmdline     = event.get("cmdline", "")
        if isinstance(cmdline, list):
            cmdline = " ".join(cmdline)
        if action == "process_start":
            line = f"[{ts}] {name} (pid {pid}) spawned by {parent_name} (pid {parent_pid})"
            if cmdline and cmdline.strip() != name:
                line += f"\n           cmdline: {cmdline}"
            if detail:
                line += f"\n           note:    {detail}"
        elif action in ("network_connection", "file_rename"):
            line = f"[{ts}] {name} (pid {pid}) — {detail}"
        else:
            line = f"[{ts}] {name} (pid {pid}) — {action}"
            if detail:
                line += f": {detail}"
        lines.append(line)
    return "\n".join(lines)


@tool
def identify_attack_patterns(process_sequence: str) -> str:
    """Match a process execution sequence against known attack patterns.
    Returns matched pattern names and MITRE ATT&CK technique IDs."""
    seq = process_sequence.lower()
    matches = []

    has_ps          = "powershell" in seq
    has_obfuscation = any(f in seq for f in [
        "-encodedcommand", "-enc ", "-ep bypass", "-nop", "-w hidden", "-windowstyle hidden"
    ])
    has_lolbin      = any(t in seq for t in ["certutil", "bitsadmin", "mshta"])
    if has_ps and has_obfuscation and has_lolbin:
        matches.append("PowerShell Download Cradle — Techniques: T1059.001, T1105, T1027")

    has_web_worker = any(p in seq for p in ["w3wp.exe", "httpd.exe", "php-cgi.exe"])
    has_recon      = any(c in seq for c in [
        "whoami", "net user", "net group", "ipconfig", "systeminfo"
    ])
    if has_web_worker and has_recon:
        matches.append(
            "Web Shell Execution — Techniques: T1505.003, T1033, T1087, T1016"
        )

    has_shadow_delete = "vssadmin" in seq and "delete shadows" in seq
    has_encryption    = any(i in seq for i in [
        ".locked", "readme_decrypt", "how_to_decrypt", "ransom", "_decrypt.txt"
    ])
    if has_shadow_delete or has_encryption:
        matches.append("Ransomware Staging — Techniques: T1490, T1486")

    if not matches:
        return "No known attack patterns matched. Sequence may be benign or use an unknown technique."
    return "\n".join(matches)


@tool
def lookup_mitre_technique(technique_id: str) -> str:
    """Return name, tactic, and description for a MITRE ATT&CK technique ID (e.g. T1059.001)."""
    TECHNIQUES = {
        "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution",
            "Abused via -EncodedCommand, -enc, -ep Bypass, -nop, -w hidden to evade logging."),
        "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", "Execution",
            "Web shells use w3wp.exe → cmd.exe for OS command execution on compromised servers."),
        "T1105":     ("Ingress Tool Transfer", "Command and Control",
            "certutil.exe, bitsadmin.exe, mshta.exe download remote payloads."),
        "T1505.003": ("Server Software Component: Web Shell", "Persistence",
            "Web worker (w3wp.exe, httpd.exe) spawning interactive shells is the primary indicator."),
        "T1490":     ("Inhibit System Recovery", "Impact",
            "'vssadmin delete shadows /all /quiet' destroys backups before ransomware."),
        "T1486":     ("Data Encrypted for Impact", "Impact",
            "Mass renames to .locked/.encrypted; ransom notes (README_DECRYPT.txt)."),
        "T1087":     ("Account Discovery", "Discovery",
            "net user, net group enumerate accounts for lateral movement."),
        "T1016":     ("System Network Configuration Discovery", "Discovery",
            "ipconfig /all, route print gather network layout."),
        "T1033":     ("System Owner/User Discovery", "Discovery",
            "whoami confirms code execution after initial access."),
        "T1027":     ("Obfuscated Files or Information", "Defense Evasion",
            "Base64 via -EncodedCommand hides commands from command-line logging."),
    }
    tid = technique_id.strip().upper()
    if tid in TECHNIQUES:
        name, tactic, desc = TECHNIQUES[tid]
        return f"ID: {tid}\nName: {name}\nTactic: {tactic}\nDescription: {desc}"
    return f"Technique {tid} not found in local reference."


@tool
def get_similar_threats(query: str) -> str:
    """Search persistent threat history for past detections semantically similar to the query.
    Use this to determine if a pattern has been seen before across previous runs."""
    records = search_similar_threats(query, n_results=3)
    if not records:
        return "No similar threats found in history. This appears to be a first-time detection."
    lines = [f"Found {len(records)} similar past detection(s):"]
    for r in records:
        lines.append(
            f"\n  [{r['timestamp'][:19]}] {r['threat_level']} (conf {r['confidence']:.2f})"
            f" — {r['scenario']}"
            f"\n  Techniques: {', '.join(r['techniques'][:3]) or 'none recorded'}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Plain helpers — called directly by graph.py nodes, not by the agent
# ---------------------------------------------------------------------------

def format_process_sequence(events: list) -> str:
    """Compatibility wrapper called by monitor_activity in graph.py."""
    return format_process_tree.invoke(json.dumps(events))


def format_techniques(techniques: list) -> str:
    """Format MITRE technique list for the report block."""
    if not techniques:
        return "N/A"
    first, *rest = techniques
    lines = [first]
    for t in rest:
        lines.append(f"            {t}")
    return "\n".join(lines)
