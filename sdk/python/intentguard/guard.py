import json
import os
import socket
from contextlib import contextmanager


class IntentGuard:
    def __init__(self, socket_path="/tmp/intentguard.sock"):
        self.socket_path = socket_path

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    @contextmanager
    def enforce(self, block_network=False, block_exec=False):
        pid = os.getpid()
        self._request(
            {
                "pid": pid,
                "action": "set",
                "policy": {
                    "block_network": int(bool(block_network)),
                    "block_exec": int(bool(block_exec)),
                },
            }
        )
        try:
            yield self
        finally:
            self._request({"pid": pid, "action": "delete"})

    def _request(self, payload):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect(self.socket_path)
                client.sendall(json.dumps(payload).encode("utf-8") + b"\n")
                response = b""
                while not response.endswith(b"\n"):
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    response += chunk
        except OSError as exc:
            raise RuntimeError(
                f"unable to communicate with IntentGuard daemon at {self.socket_path}"
            ) from exc

        if not response:
            raise RuntimeError("IntentGuard daemon returned no response")
        try:
            result = json.loads(response)
        except json.JSONDecodeError as exc:
            raise RuntimeError("IntentGuard daemon returned invalid JSON") from exc
        if not result.get("ok"):
            raise RuntimeError(result.get("error", "IntentGuard request failed"))
