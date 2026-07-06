# ebpf-udp-analyzer

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![eBPF](https://img.shields.io/badge/eBPF-enabled-orange)
![Linux](https://img.shields.io/badge/platform-linux-green)

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
- optional Parquet writer through DuckDB
- ClickHouse HTTP JSONEachRow writer
- first eBPF C program for IPv4 UDP ingress counters at `tc` classifier attach
- eBPF collector that attaches with `tc`, drains counters with `bpftool`, and
  emits checkpoint deltas
- optional `/proc` socket/process enrichment for delivered-process rows
- basic Docker/ffmpeg harness files

Next implementation step:

- extend process attribution beyond local-port correlation with receive-side
  socket cookies or kprobe/fentry attribution

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

Use SQLite:

```sh
PYTHONPATH=src python3 -m udp_analyzer run \
  --storage sqlite \
  --db-path data/udp_analyzer.sqlite
```

Use Parquet:

```sh
PYTHONPATH=src python3 -m udp_analyzer run \
  --storage parquet \
  --db-path data/udp_samples.parquet
```

## eBPF Build Sketch

The first eBPF program lives at `bpf/udp_ingress.bpf.c`.

On a Linux machine with clang and libbpf headers:

```sh
make -C bpf
```

Run the real eBPF collector on an interface:

```sh
PYTHONPATH=src python3 -m udp_analyzer run \
  --collector ebpf \
  --interface eth0 \
  --watch \
  --duration 10 \
  --output json
```

Add process/socket enrichment from `/proc`:

```sh
PYTHONPATH=src python3 -m udp_analyzer run \
  --collector ebpf \
  --interface eth0 \
  --watch \
  --duration 10 \
  --output json \
  --enrich-processes
```

Filter enriched rows to one process name:

```sh
PYTHONPATH=src python3 -m udp_analyzer run \
  --collector ebpf \
  --interface eth0 \
  --watch \
  --duration 10 \
  --output json \
  --enrich-processes \
  --process-name ffmpeg \
  --layer delivered
```

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

Run the dry-run harness:

```sh
DURATION=1 harness/run.sh dry-run
```

Run the eBPF harness on Linux:

```sh
INTERFACE=eth0 harness/run.sh ebpf
```

## Docs

- `PROJECT_GOAL.md`: product goal and first vertical
- `roadmap.md`: implementation phases
- `harness.md`: Dockerized ffmpeg validation target
- `storage.md`: local and networked storage design
