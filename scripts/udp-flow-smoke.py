#!/usr/bin/env python3

"""Small UDP echo/load helper for the isolated routed-subnet packet proof."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time


def server(bind: str, port: int, receipt: str | None) -> int:
    receipt_file = open(receipt, "a", encoding="utf-8", buffering=1) if receipt else None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((bind, port))
        while True:
            payload, peer = sock.recvfrom(2048)
            if receipt_file is not None:
                receipt_file.write(payload.hex() + "\n")
            sock.sendto(payload, peer)


def client(
    source: str,
    target: str,
    port: int,
    count: int,
    first_source_port: int,
    timeout: float,
    allow_loss: bool,
    send_only: bool,
    interval: float,
) -> int:
    received = 0
    failures: list[int] = []
    for sequence in range(count):
        source_port = first_source_port + sequence
        payload = f"mesh-ecmp-{source_port}-{sequence}".encode()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.bind((source, source_port))
                sock.sendto(payload, (target, port))
                if send_only:
                    received += 1
                    if interval:
                        time.sleep(interval)
                    continue
                echoed, _ = sock.recvfrom(2048)
                if echoed != payload:
                    failures.append(source_port)
                    continue
                received += 1
        except (OSError, TimeoutError):
            failures.append(source_port)

    print(
        json.dumps(
            {
                "schema": "mesh-udp-flow-smoke-v1",
                "attempted": count,
                "received": received,
                "lost": len(failures),
                "failed_source_ports": failures,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0 if allow_loss or not failures else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("server")
    serve.add_argument("--bind", required=True)
    serve.add_argument("--port", type=int, required=True)
    serve.add_argument("--receipt")

    run = subparsers.add_parser("client")
    run.add_argument("--source", required=True)
    run.add_argument("--target", required=True)
    run.add_argument("--port", type=int, required=True)
    run.add_argument("--count", type=int, required=True)
    run.add_argument("--first-source-port", type=int, required=True)
    run.add_argument("--timeout", type=float, default=1.0)
    run.add_argument("--allow-loss", action="store_true")
    run.add_argument("--send-only", action="store_true")
    run.add_argument("--interval", type=float, default=0.0)

    args = parser.parse_args()
    if args.command == "server":
        return server(args.bind, args.port, args.receipt)
    if args.count < 1 or args.first_source_port < 1024 or args.first_source_port + args.count > 65535 or args.interval < 0:
        parser.error("client count/source-port range is invalid")
    return client(
        args.source,
        args.target,
        args.port,
        args.count,
        args.first_source_port,
        args.timeout,
        args.allow_loss,
        args.send_only,
        args.interval,
    )


if __name__ == "__main__":
    sys.exit(main())
