# Harness

This harness defines the first vertical validation target for the universal UDP
traffic analyzer described in `PROJECT_GOAL.md`.

The universal analyzer should work for arbitrary UDP traffic. This harness uses
the concrete Dockerized `ffmpeg` workload to prove that the analyzer can handle a
real receive-side attribution problem.

The harness must prove that the analyzer can build a time-series history of
incoming UDP traffic grouped by generic UDP dimensions and the vertical-specific
`ffmpeg` process dimension:

- source IP address
- destination IP address
- source UDP port
- destination UDP port
- receiving network interface
- individual `ffmpeg` process running inside Docker

## Target Signal

The core analyzer should be able to emit generic records shaped like:

```text
time_bucket, src_ip, dst_ip, src_port, dst_port, ingress_ifindex, ingress_ifname
```

For the Dockerized `ffmpeg` vertical, delivered records should add:

```text
container_id, ffmpeg_pid, socket_id
```

The value for each key should include:

```text
packet_count, byte_count
```

`socket_id` should be stable for the lifetime of the socket. A socket cookie is
preferred when the eBPF attach point can expose one. `ffmpeg_pid` should be the
host PID or container PID, but the Python user-space reporter should make clear
which namespace that PID belongs to.

## Harness Topology

The harness should create one Docker container that runs multiple `ffmpeg`
receiver processes and one or more traffic sources that send deterministic UDP
traffic to those receivers.

Recommended minimal topology:

```text
source-a 192.0.2.10  --->  docker-host ingress interface  --->  ffmpeg-1 udp/:5000
source-b 192.0.2.11  --->  docker-host ingress interface  --->  ffmpeg-2 udp/:5001
source-c 192.0.2.12  --->  docker-host ingress interface  --->  ffmpeg-3 udp/:5002
```

For local-only development, the sources may be separate network namespaces or
separate containers on a Docker bridge. For production-like validation, at least
one source should send traffic through the real host ingress interface rather
than only through loopback.

## Required Components

The harness provides these files:

- `harness/compose.yaml`: starts the Docker test network and receiver container
- `harness/start_ffmpeg.sh`: starts multiple labeled `ffmpeg` UDP receivers
- `harness/send_udp.py`: sends deterministic UDP packet streams
- `harness/run.sh`: starts the analyzer, optionally generates probe traffic, and
  stores analyzer output
- `harness/assert_output.py`: checks analyzer output against expected packet and
  byte counts

The Dockerized ffmpeg receiver setup is still evolving. The dry-run and eBPF
probe harness paths are available now.

## Receiver Setup

Inside the Docker container, start multiple long-running `ffmpeg` processes.
Each process should listen on a distinct UDP destination port and include a
stable command-line label so the reporter can display a human-readable name.

Example receiver set:

```text
ffmpeg label=rx-5000 listens on udp://0.0.0.0:5000
ffmpeg label=rx-5001 listens on udp://0.0.0.0:5001
ffmpeg label=rx-5002 listens on udp://0.0.0.0:5002
```

The first harness version should use distinct ports per process. A later test
can add multiple `ffmpeg` processes on the same port only if the workload uses a
valid mechanism such as multicast or `SO_REUSEPORT`.

## Traffic Plan

Traffic generation must be deterministic enough that the analyzer output can be
checked automatically.

Minimum scenarios:

1. Single source, single destination port, single `ffmpeg` process.
2. Two sources sending to the same destination port and same `ffmpeg` process.
3. One source sending to multiple destination ports handled by different
   `ffmpeg` processes.
4. Multiple sources sending to multiple ports at the same time.
5. Traffic sent to a UDP port without an `ffmpeg` receiver, to confirm that the
   analyzer can distinguish packet-level ingress from process-delivered traffic.

For each stream, record:

```text
src_ip, dst_ip, src_port, dst_port, packet_size, packet_count, start_time,
duration
```

The expected byte count should be based on UDP payload bytes unless the analyzer
explicitly documents that it reports IP packet bytes or link-layer frame bytes.

## Analyzer Run

The harness should start the eBPF analyzer before traffic generation and keep it
running until after all senders finish.

Recommended analyzer output format for harness validation is newline-delimited
JSON:

```json
{"ts": "2026-07-06T12:00:01Z", "bucket_ms": 1000, "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "src_port": 40000, "dst_port": 5000, "ifname": "eth0", "container_id": "abc123", "ffmpeg_pid": 4242, "socket_id": 98765, "packets": 1000, "bytes": 1316000}
```

The human CLI can render tables, but the harness should validate a machine
readable output mode emitted by the Python user-space layer.

## Attribution Checks

The harness passes only if all of these are true:

- UDP packets are grouped by source IP.
- UDP packets are grouped by destination IP.
- UDP packets are grouped by source port.
- UDP packets are grouped by destination port.
- UDP packets are grouped by receiving interface.
- Delivered traffic is attributed to the correct individual `ffmpeg` process.
- Multiple `ffmpeg` processes inside the same Docker instance are not merged
  into a single process bucket.
- Traffic to an unopened UDP port appears as ingress traffic but not as
  delivered-to-ffmpeg traffic, if the implementation reports both layers.
- Packet and byte counts are within an agreed tolerance of generated traffic.

Suggested tolerance:

```text
packet_count: exact for controlled local tests
byte_count: exact when payload-byte accounting is used
time_bucket: allow one bucket of drift at stream boundaries
```

## Manual Smoke Test

Before the full harness exists, a manual smoke test should follow this shape:

1. Start a Docker container with at least three `ffmpeg` UDP receivers.
2. Record the container ID, host PIDs, container PIDs, and listening ports.
3. Start the UDP eBPF analyzer with JSON output enabled.
4. Send known UDP streams to each receiver from at least two source IPs.
5. Send one stream to an unopened UDP port.
6. Stop the analyzer and compare output against the traffic plan.

The smoke test is successful when the output clearly shows separate rows for
each source, destination, port, interface, and `ffmpeg` process.

## Open Design Decisions

- Which eBPF attach point provides the best combination of packet fields and
  process/socket attribution?
- Should the analyzer report only traffic delivered to `ffmpeg`, or both ingress
  traffic and delivered traffic?
- Should source identity be taken from packet headers, socket state, or both?
- Should process identity be reported as host PID, container PID, or both?
- How should short-lived `ffmpeg` processes be represented after they exit?
- Which user-space features can stay pure Python, and which require a compiled
  helper?
