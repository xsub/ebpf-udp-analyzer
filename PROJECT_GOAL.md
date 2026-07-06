# Project goal

Build a universal Linux eBPF UDP traffic analyzer that records UDP traffic volume
over time and can be specialized for concrete operational workloads.

The core analyzer should be workload-agnostic. It should collect packet and byte
history by common UDP dimensions such as:

- source IP address
- destination IP address
- source UDP port
- destination UDP port
- receiving network interface
- socket identity, when available
- process identity, when available
- container or network namespace identity, when available

The user-space layer should preferably be Python when it is sufficient for
loading, polling, enrichment, reporting, and harness automation. The kernel-side
eBPF code can still use C or another eBPF-supported form where required.

The analyzer should aggregate traffic in eBPF maps and let Python drain those
aggregates at checkpoint intervals. Python should then batch-write samples to a
local or networked storage target for later analysis. The preferred storage
targets are DuckDB/Parquet for local captures and ClickHouse for networked
captures.

## First Vertical: Dockerized ffmpeg

The first vertical use case is UDP traffic delivered to multiple `ffmpeg`
processes running inside the same Docker instance.

For this vertical, the analyzer must answer:

"Which source IPs are sending how much UDP traffic to which ports/interfaces,
and how much of that traffic reaches each individual Dockerized ffmpeg process?"

Because multiple `ffmpeg` processes can run inside the same Docker instance, the
process dimension should distinguish them by a stable runtime identifier such as
container PID, host PID, socket identity, or command-line label.
