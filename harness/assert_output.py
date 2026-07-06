#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


REQUIRED_FIELDS = {
    "ts",
    "bucket_ms",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "ifindex",
    "ifname",
    "packets",
    "bytes",
    "layer",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate UDP analyzer JSON output.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--profile", choices=["generic", "dry-run", "ebpf"], default="generic")
    parser.add_argument("--allow-empty", action="store_true")
    args = parser.parse_args()

    rows = read_rows(Path(args.input))
    validate_rows(rows, allow_empty=args.allow_empty)

    if args.profile == "dry-run":
        validate_dry_run(rows)
    elif args.profile == "ebpf":
        validate_ebpf(rows, allow_empty=args.allow_empty)

    print(f"ok: validated {len(rows)} rows from {args.input}")
    return 0


def read_rows(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                rows.append(json.loads(stripped))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_number}: invalid JSON: {exc}") from exc
    return rows


def validate_rows(rows: list[dict[str, Any]], allow_empty: bool) -> None:
    if not rows and not allow_empty:
        raise SystemExit("no analyzer rows were produced")

    for index, row in enumerate(rows):
        missing = REQUIRED_FIELDS.difference(row)
        if missing:
            raise SystemExit(f"row {index}: missing fields: {sorted(missing)}")
        for field in ("src_port", "dst_port", "ifindex", "packets", "bytes"):
            if not isinstance(row[field], int):
                raise SystemExit(f"row {index}: {field} must be an integer")
        if row["packets"] < 0 or row["bytes"] < 0:
            raise SystemExit(f"row {index}: counters must not be negative")
        if row["layer"] not in {"ingress", "delivered"}:
            raise SystemExit(f"row {index}: unexpected layer {row['layer']!r}")


def validate_dry_run(rows: list[dict[str, Any]]) -> None:
    expected = {
        ("192.0.2.10", 5000, "delivered", "ffmpeg"),
        ("192.0.2.11", 5001, "delivered", "ffmpeg"),
        ("192.0.2.12", 5999, "ingress", ""),
    }
    present = {
        (
            row["src_ip"],
            row["dst_port"],
            row["layer"],
            row.get("process_name", ""),
        )
        for row in rows
    }
    missing = expected.difference(present)
    if missing:
        raise SystemExit(f"dry-run output missing expected rows: {sorted(missing)}")


def validate_ebpf(rows: list[dict[str, Any]], allow_empty: bool) -> None:
    if allow_empty and not rows:
        return
    if not any(row["layer"] == "ingress" for row in rows):
        raise SystemExit("eBPF output did not include ingress rows")
    if not any(row["packets"] > 0 for row in rows):
        raise SystemExit("eBPF output did not include positive packet counts")


if __name__ == "__main__":
    raise SystemExit(main())

