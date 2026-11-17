import argparse
import csv
import json
import os
import socket
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9)
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--socket", default="")
    parser.add_argument("--output", default="results/syscall.csv")
    args = parser.parse_args()
    if args.socket:
        payload = json.dumps({
            "pid": os.getpid(),
            "action": "set",
            "policy": {"block_network": 0, "block_exec": 0},
        }).encode()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(args.socket)
                client.sendall(payload + b"\n")
                if not client.recv(4096):
                    raise RuntimeError("daemon returned no ACK")
        except PermissionError as exc:
            raise SystemExit(
                f"permission denied for {args.socket}; run this benchmark as the "
                "daemon user or with sudo"
            ) from exc
        except ConnectionRefusedError as exc:
            raise SystemExit(
                f"no daemon is listening on {args.socket}; start ./intentguardd first"
            ) from exc
    samples = []
    for iteration in range(1, args.iterations + 1):
        started = time.perf_counter_ns()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(1)
        try:
            client.connect((args.host, args.port))
        except OSError:
            pass
        finally:
            client.close()
        samples.append((iteration, (time.perf_counter_ns() - started) / 1_000_000))
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(["iteration", "connect_ms"])
        writer.writerows(samples)
    if args.socket:
        payload = json.dumps({"pid": os.getpid(), "action": "delete"}).encode()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(args.socket)
            client.sendall(payload + b"\n")
            client.recv(4096)
    print(f"wrote {len(samples)} samples to {args.output}")


if __name__ == "__main__":
    main()
