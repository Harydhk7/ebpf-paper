import argparse
import csv
import os
import socket
import time


def find_daemon_pid():
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/comm", encoding="utf-8") as comm_file:
                if comm_file.read().strip() == "intentguardd":
                    return int(entry)
        except (FileNotFoundError, PermissionError):
            continue
    raise SystemExit("intentguardd is not running; start ./intentguardd first")


def daemon_usage(pid):
    with open(f"/proc/{pid}/stat", encoding="utf-8") as stat_file:
        fields = stat_file.read().split()
    with open(f"/proc/{pid}/status", encoding="utf-8") as status_file:
        rss = next(line for line in status_file if line.startswith("VmRSS:"))
    return int(rss.split()[1]), int(fields[13]) + int(fields[14])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", default="/tmp/intentguard.sock")
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--daemon-pid", type=int)
    parser.add_argument("--output", default="results/resource.csv")
    args = parser.parse_args()
    daemon_pid = args.daemon_pid or find_daemon_pid()
    pid = os.getpid()
    payload = (
        f'{{"pid":{pid},"action":"set","policy":{{"block_network":0,"block_exec":0}}}}'
    ).encode()
    started = time.monotonic()
    rows = []
    updates = 0
    while time.monotonic() - started < args.duration:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            try:
                client.connect(args.socket)
            except PermissionError as exc:
                raise SystemExit(
                    f"permission denied for {args.socket}; run this benchmark as "
                    "the daemon user or with sudo"
                ) from exc
            client.sendall(payload + b"\n")
            if not client.recv(4096):
                raise RuntimeError("daemon returned no ACK")
        updates += 1
        if updates % 100 == 0:
            rss, cpu_ticks = daemon_usage(daemon_pid)
            rows.append((time.monotonic() - started, rss, cpu_ticks))
    delete = f'{{"pid":{pid},"action":"delete"}}'.encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(args.socket)
        client.sendall(delete + b"\n")
        client.recv(4096)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as output:
        writer = csv.writer(output)
        writer.writerow(["elapsed_s", "daemon_rss_kb", "daemon_cpu_ticks", "updates"])
        writer.writerows((elapsed, rss, cpu, updates) for elapsed, rss, cpu in rows)
    print(f"wrote {len(rows)} samples and sent {updates} updates to {args.output}")


if __name__ == "__main__":
    main()
