#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import time


def main() -> int:
    parser = argparse.ArgumentParser(description="Send deterministic UDP traffic.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--src-port", type=int)
    parser.add_argument("--packet-size", type=int, default=1316)
    parser.add_argument("--packets", type=int, default=100)
    parser.add_argument("--pps", type=float, default=100)
    args = parser.parse_args()

    if args.packet_size <= 0:
        parser.error("--packet-size must be greater than zero")
    if args.packets < 0:
        parser.error("--packets must not be negative")
    if args.pps <= 0:
        parser.error("--pps must be greater than zero")

    payload = bytes((index % 251 for index in range(args.packet_size)))
    delay = 1.0 / args.pps

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if args.src_port is not None:
            sock.bind(("", args.src_port))
        for _ in range(args.packets):
            sock.sendto(payload, (args.host, args.port))
            time.sleep(delay)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

