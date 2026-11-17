import os
import socket
import subprocess
import sys
import urllib.request

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))
from intentguard import IntentGuard


SOCKET_PATH = "/tmp/intentguard.sock"


def daemon_available():
    if not os.path.exists(SOCKET_PATH):
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            client.connect(SOCKET_PATH)
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not daemon_available(), reason="IntentGuard daemon is unavailable or inaccessible"
)


def test_benign_execution():
    with IntentGuard().enforce(block_network=False, block_exec=False):
        assert subprocess.run(["echo", "hello"], capture_output=True, check=True).stdout.strip() == b"hello"
        with urllib.request.urlopen("http://example.com", timeout=5) as response:
            assert response.status < 500


def run_child(policy, action):
    operation = (
        "urllib.request.urlopen('http://example.com', timeout=5).read()"
        if action == "network"
        else "os.execv('/bin/echo', ['echo', 'blocked'])"
    )
    code = (
        "import os, subprocess, sys, urllib.request\n"
        "sys.path.insert(0, 'sdk/python')\n"
        "from intentguard import IntentGuard\n"
        f"with IntentGuard().enforce({policy}):\n"
        f"    {operation}\n"
    )
    return subprocess.run([sys.executable, "-c", code], cwd=os.path.dirname(os.path.dirname(__file__)))


def test_network_blocking():
    result = run_child("block_network=True", "network")
    assert result.returncode == -9


def test_exec_blocking():
    result = run_child("block_exec=True", "exec")
    assert result.returncode == -9
