"""
Simulated normal/benign process activity for the cyber-sense demo.

Returns (events, name). No trigger signatures match these events, so the sensor
will not fire. demo.py runs the pipeline directly for the normal scenario to
demonstrate the BENIGN classification path.
"""

from datetime import datetime, timedelta


def _ts(base: datetime, seconds: int) -> str:
    return (base + timedelta(seconds=seconds)).strftime("%H:%M:%S")


def get_normal_scenario():
    """Normal user activity: browser, IDE, and a dev script."""
    base = datetime.now()

    events = [
        {
            "timestamp": _ts(base, 0),
            "pid": 1234,
            "name": "explorer.exe",
            "parent_pid": None,
            "parent_name": None,
            "cmdline": "explorer.exe",
            "action": "process_start",
        },
        {
            "timestamp": _ts(base, 1),
            "pid": 3456,
            "name": "chrome.exe",
            "parent_pid": 1234,
            "parent_name": "explorer.exe",
            "cmdline": "chrome.exe --no-sandbox",
            "action": "process_start",
        },
        {
            "timestamp": _ts(base, 2),
            "pid": 3457,
            "name": "chrome.exe",
            "parent_pid": 3456,
            "parent_name": "chrome.exe",
            "cmdline": "chrome.exe --type=renderer --no-sandbox",
            "action": "process_start",
            "detail": "Renderer process (tab)",
        },
        {
            "timestamp": _ts(base, 2),
            "pid": 3458,
            "name": "chrome.exe",
            "parent_pid": 3456,
            "parent_name": "chrome.exe",
            "cmdline": "chrome.exe --type=gpu-process --no-sandbox",
            "action": "process_start",
            "detail": "GPU process",
        },
        {
            "timestamp": _ts(base, 5),
            "pid": 4500,
            "name": "Code.exe",
            "parent_pid": 1234,
            "parent_name": "explorer.exe",
            "cmdline": "Code.exe /home/user/projects/myapp",
            "action": "process_start",
        },
        {
            "timestamp": _ts(base, 6),
            "pid": 4501,
            "name": "node.exe",
            "parent_pid": 4500,
            "parent_name": "Code.exe",
            "cmdline": "node.exe --max-old-space-size=4096 /home/user/.vscode/extensions/ms-python.python/pyls",
            "action": "process_start",
            "detail": "VS Code Python language server",
        },
        {
            "timestamp": _ts(base, 10),
            "pid": 5000,
            "name": "python.exe",
            "parent_pid": 4500,
            "parent_name": "Code.exe",
            "cmdline": "python.exe /home/user/projects/myapp/scripts/generate_report.py",
            "action": "process_start",
        },
    ]

    return events, "Normal User Activity (Baseline)"
