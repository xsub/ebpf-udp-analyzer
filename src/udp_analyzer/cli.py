from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Optional, Union

from .collectors import DryRunCollector, EbpfCollector
from .models import SampleFilter
from .output import emit_samples
from .writers import ClickHouseHttpWriter, DuckDBWriter, NullWriter, SQLiteWriter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="udp-analyzer",
        description="Universal UDP traffic analyzer with checkpointed storage.",
    )
    subparsers = parser.add_subparsers(dest="command")

    run = subparsers.add_parser("run", help="run the analyzer")
    run.add_argument("--collector", choices=["dry-run", "ebpf"], default="dry-run")
    run.add_argument("--bucket-ms", type=int, default=1000)
    run.add_argument("--watch", action="store_true", help="keep polling checkpoints")
    run.add_argument(
        "--duration",
        type=float,
        default=None,
        help="stop after N seconds; implies --watch",
    )
    run.add_argument("--output", choices=["table", "json", "none"], default="table")
    run.add_argument(
        "--storage",
        choices=["none", "sqlite", "duckdb", "clickhouse"],
        default="none",
    )
    run.add_argument("--db-path", default="data/udp_analyzer.sqlite")
    run.add_argument("--clickhouse-url", default="http://localhost:8123")
    run.add_argument("--clickhouse-table", default="udp_samples")
    run.add_argument("--src-ip")
    run.add_argument("--dst-ip")
    run.add_argument("--src-port", type=int)
    run.add_argument("--dst-port", type=int)
    run.add_argument("--ifname")
    run.add_argument("--process-name")
    run.add_argument("--layer", choices=["ingress", "delivered"])
    run.set_defaults(func=run_analyzer)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    try:
        args.func(args)
        return 0
    except KeyboardInterrupt:
        return 130
    except RuntimeError as exc:
        parser.exit(1, f"udp-analyzer: error: {exc}\n")


def run_analyzer(args: argparse.Namespace) -> None:
    sample_filter = SampleFilter(
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        src_port=args.src_port,
        dst_port=args.dst_port,
        ifname=args.ifname,
        process_name=args.process_name,
        layer=args.layer,
    )
    collector = create_collector(args.collector, args.bucket_ms, sample_filter)
    writer = create_writer(args)
    watch = args.watch or args.duration is not None
    deadline = time.monotonic() + args.duration if args.duration is not None else None

    try:
        while True:
            samples = collector.read_checkpoint()
            emit_samples(samples, args.output)
            writer.write_samples(samples)

            if not watch:
                break
            if deadline is not None and time.monotonic() >= deadline:
                break
            time.sleep(args.bucket_ms / 1000)
    finally:
        writer.flush()
        writer.close()


def create_collector(
    collector_name: str, bucket_ms: int, sample_filter: SampleFilter
) -> Union[DryRunCollector, EbpfCollector]:
    if bucket_ms <= 0:
        raise RuntimeError("--bucket-ms must be greater than zero")
    if collector_name == "dry-run":
        return DryRunCollector(bucket_ms=bucket_ms, sample_filter=sample_filter)
    if collector_name == "ebpf":
        return EbpfCollector(bucket_ms=bucket_ms, sample_filter=sample_filter)
    raise RuntimeError(f"unsupported collector: {collector_name}")


def create_writer(args: argparse.Namespace):
    if args.storage == "none":
        return NullWriter()
    if args.storage == "sqlite":
        return SQLiteWriter(Path(args.db_path))
    if args.storage == "duckdb":
        return DuckDBWriter(Path(args.db_path))
    if args.storage == "clickhouse":
        return ClickHouseHttpWriter(args.clickhouse_url, args.clickhouse_table)
    raise RuntimeError(f"unsupported storage: {args.storage}")
