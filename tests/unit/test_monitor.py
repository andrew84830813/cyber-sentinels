"""Unit tests for is_trigger(). No LLM calls."""
import pytest
from cyber_ignition_agents.sensor.monitor import is_trigger


def _snap(name, parent=None, cmdline=""):
    return {"name": name, "parent_name": parent, "cmdline": cmdline, "pid": 1}


def test_is_trigger_powershell_encoded():
    assert is_trigger(_snap("powershell.exe", cmdline="powershell.exe -EncodedCommand abc123"))


def test_is_trigger_powershell_enc_short():
    assert is_trigger(_snap("powershell.exe", cmdline="powershell.exe -enc abc"))


def test_is_trigger_webshell_w3wp_cmd():
    assert is_trigger(_snap("cmd.exe", parent="w3wp.exe"))


def test_is_trigger_webshell_w3wp_powershell():
    assert is_trigger(_snap("powershell.exe", parent="w3wp.exe"))


def test_is_trigger_webshell_httpd_cmd():
    assert is_trigger(_snap("cmd.exe", parent="httpd.exe"))


def test_is_trigger_vssadmin_delete():
    assert is_trigger(_snap("vssadmin.exe", cmdline="vssadmin.exe delete shadows /all /quiet"))


def test_is_trigger_benign_chrome():
    assert not is_trigger(_snap("chrome.exe", parent="explorer.exe"))


def test_is_trigger_benign_python():
    assert not is_trigger(_snap("python.exe", parent="code.exe", cmdline="python script.py"))


def test_is_trigger_case_insensitive_process():
    assert is_trigger(_snap("PowerShell.EXE", cmdline="PowerShell.EXE -EncodedCommand xyz"))


def test_is_trigger_case_insensitive_parent():
    assert is_trigger(_snap("CMD.EXE", parent="W3WP.EXE"))
