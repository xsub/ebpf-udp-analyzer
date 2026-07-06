# ebpf-udp-analyzer

Universal eBPF UDP traffic analyzer with Python user space, checkpointed storage,
and a Docker/ffmpeg vertical harness.

The project is intentionally split into:

- eBPF hot path: collect UDP counters in kernel maps
- Python checkpoint daemon: drain counters, enrich metadata, write batches
- storage backends: local and networked history for later Python analysis
- harness: reproducible Dockerized ffmpeg workload

## Current Status

Implemented now:

- Python CLI skeleton
- deterministic `dry-run` collector
- generic UDP sample model and filters
- table and newline-delimited JSON output
- SQLite writer using WAL mode
- optional DuckDB writer
- ClickHouse HTTP JSONEachRow writer
- first eBPF C program for IPv4 UDP ingress counters at `tc` classifier attach
- basic Docker/ffmpeg harness files

Next implementation step:

- wire the Python `ebpf` collector to load/attach `bpf/udp_ingress.bpf.c` and
  drain `udp_ingress_counters`

## Quick Start

Requires Python 3.9 or newer.

Run one dry-run checkpoint:

```sh
PYTHONPATH=src python3 -m udp_analyzer run
```

Run JSON output:

```sh
PYTHONPATH=src python3 -m udp_analyzer run --output json
```

Run for three seconds and save samples to SQLite:

```sh
PYTHONPATH=src python3 -m udp_analyzer run \
  --watch \
  --duration 3 \
  --output table \
  --storage sqlite \
  --db-path data/udp_analyzer.sqlite
```

Filter to delivered ffmpeg samples:

```sh
PYTHONPATH=src python3 -m udp_analyzer run \
  --output json \
  --process-name ffmpeg \
  --layer delivered
```

## Storage Targets

Primary local target:

- DuckDB/Parquet for local analytical captures

Implemented local fallback:

- SQLite WAL for small captures and harness runs

Primary networked target:

- ClickHouse for high-rate append-heavy history

See `storage.md` for the full storage decision.

## eBPF Build Sketch

The first eBPF program lives at `bpf/udp_ingress.bpf.c`.

On a Linux machine with clang and libbpf headers:

```sh
make -C bpf
```

This currently builds only the BPF object. Python loading/attaching is the next
piece of implementation.

For CloudLinux/RHEL-like systems:

```sh
scripts/bootstrap-cloudlinux.sh
make -C bpf
```

For Ubuntu/Debian-like systems:

```sh
scripts/bootstrap-ubuntu.sh
make -C bpf
```

## Tests

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Docs

- `PROJECT_GOAL.md`: product goal and first vertical
- `roadmap.md`: implementation phases
- `harness.md`: Dockerized ffmpeg validation target
- `storage.md`: local and networked storage design
