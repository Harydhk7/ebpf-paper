import argparse
import csv
import os
import socket
import time


def request(path, payload):
    started = time.perf_counter_ns()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(path)
            client.sendall(payload + b"\n")
            response = b""
            while not response.endswith(b"\n"):
                chunk = client.recv(4096)
                if not chunk:
                    raise RuntimeError("daemon closed the socket without an ACK")
                response += chunk
    except PermissionError as exc:
        raise SystemExit(
            f"permission denied for {path}; run this benchmark as the daemon user "
            "or with sudo"
        ) from exc
    except ConnectionRefusedError as exc:
        raise SystemExit(
            f"no daemon is listening on {path}; start ./intentguardd first"
        ) from exc
    return (time.perf_counter_ns() - started) / 1_000_000


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", default="/tmp/intentguard.sock")
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--output", default="results/ipc.csv")
    args = parser.parse_args()
    pid = os.getpid()
    set_payload = (
        f'{{"pid":{pid},"action":"set","policy":{{"block_network":0,"block_exec":0}}}}'
    ).encode()
    delete_payload = f'{{"pid":{pid},"action":"delete"}}'.encode()
    samples = [request(args.socket, set_payload) for _ in range(args.iterations)]
    request(args.socket, delete_payload)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(["iteration", "round_trip_ms"])
        writer.writerows(enumerate(samples, 1))
    print(f"wrote {len(samples)} samples to {args.output}")


if __name__ == "__main__":
    main()
