# ebpf-udp-analyzer

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![eBPF](https://img.shields.io/badge/eBPF-enabled-orange)
![Linux](https://img.shields.io/badge/platform-linux-green)

Universal eBPF UDP traffic analyzer with Python user space, checkpointed storage,
and a Docker/ffmpeg vertical harness.

## What It Does

`ebpf-udp-analyzer` monitors incoming IPv4 UDP traffic on a Linux interface.
The eBPF program runs at `tc ingress` and updates in-kernel counters keyed by:

- source IP
- destination IP
- source UDP port
- destination UDP port
- receiving interface

The Python user-space collector periodically reads those counters, converts
absolute eBPF map values into checkpoint deltas, optionally enriches rows with
`/proc` socket/process metadata, and writes the result as JSON, tables, or
storage rows.

Example ingress row:

```json
{"src_ip": "1.1.1.1", "src_port": 53, "dst_ip": "146.59.19.215", "dst_port": 58417, "ifname": "eth0", "packets": 1, "bytes": 61, "layer": "ingress"}
```

With process enrichment enabled, matching UDP sockets can also produce delivered
rows such as:

```json
{"process_name": "ffmpeg", "host_pid": 4242, "socket_id": 869157, "layer": "delivered"}
```

The project is intentionally split into:

- eBPF hot path: collect UDP counters in kernel maps
- Python checkpoint daemon: drain counters, enrich metadata, write batches
- storage backends: local and networked history for later Python analysis
- harness: reproducible Dockerized ffmpeg workload

## Text Screenshots

Dry-run table output:

```text
$ PYTHONPATH=src python3 -m udp_analyzer run --output table
ts                        layer      src_ip      src_port  dst_ip         dst_port  ifname  process_name  host_pid  packets  bytes
------------------------  ---------  ----------  --------  -------------  --------  ------  ------------  --------  -------  ------
2026-07-06T22:51:31.000Z  delivered  192.0.2.10  40000     198.51.100.20  5000      eth0    ffmpeg        4242      101      132916
2026-07-06T22:51:31.000Z  delivered  192.0.2.11  40010     198.51.100.20  5001      eth0    ffmpeg        4243      77       92400
2026-07-06T22:51:31.000Z  ingress    192.0.2.12  40020     198.51.100.20  5999      eth0                  0         15       7680
```

Filtered JSON output:

```text
$ PYTHONPATH=src python3 -m udp_analyzer run --output json --process-name ffmpeg --layer delivered
{"bytes": 132916, "dst_ip": "198.51.100.20", "dst_port": 5000, "ifname": "eth0", "layer": "delivered", "packets": 101, "process_name": "ffmpeg", "src_ip": "192.0.2.10", "src_port": 40000}
{"bytes": 92400, "dst_ip": "198.51.100.20", "dst_port": 5001, "ifname": "eth0", "layer": "delivered", "packets": 77, "process_name": "ffmpeg", "src_ip": "192.0.2.11", "src_port": 40010}
```

Real eBPF ingress sample captured on Linux:

```text
$ INTERFACE=eth0 harness/run.sh ebpf
ok: validated 1 rows from data/harness/udp_samples.ndjson
output: data/harness/udp_samples.ndjson
sqlite: data/harness/udp_samples.sqlite

{"bytes": 61, "dst_ip": "146.59.19.215", "dst_port": 58417, "ifname": "eth0", "layer": "ingress", "packets": 1, "src_ip": "1.1.1.1", "src_port": 53}
```

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
