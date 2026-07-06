# Storage Design

The analyzer should not write to a database from eBPF code and should not emit a
user-space event for every UDP packet.

The intended data path is:

```text
UDP packet
  -> eBPF program updates in-kernel counters/maps
  -> Python user-space daemon polls at a checkpoint interval
  -> Python enriches records with process/container/interface metadata
  -> Python writes batched rows to local or networked storage
  -> another Python analyzer queries the stored history later
```

This keeps the packet path small and makes storage latency independent from UDP
receive latency.

## Checkpoint Model

Recommended first implementation:

- eBPF stores counters in per-CPU maps keyed by UDP dimensions.
- Python polls maps every configurable interval, for example 1 second.
- Python computes deltas since the previous poll.
- Python writes one row per active key per checkpoint.
- Optional ring-buffer events are reserved for low-rate metadata changes, such
  as new socket identity or process attribution, not traffic volume per packet.

Example row shape:

```text
bucket_start_ns
ts
bucket_ms
src_ip
dst_ip
src_port
dst_port
ip_proto
ifindex
ifname
netns_id
container_id
process_name
host_pid
container_pid
socket_id
packets
bytes
layer
```

`layer` should distinguish `ingress` from `delivered` when both views are
reported.

## Local Storage Recommendation

Use DuckDB plus Parquet as the preferred local storage path.

Why:

- embedded, no server to operate
- excellent Python ergonomics
- SQL retrieval for later analysis
- columnar storage fits time-series scans and grouped aggregation
- Parquet files are portable and easy for other Python tools to read

Recommended local layout:

```text
data/
  duckdb/
    udp_analyzer.duckdb
  parquet/
    date=2026-07-06/hour=12/udp_samples.parquet
```

Recommended write strategy:

- buffer checkpoint rows in Python memory
- flush every 1 to 10 seconds or every N rows
- append to DuckDB for interactive local querying
- periodically export or directly write partitioned Parquet for archival

Use this when:

- the analyzer and later Python analysis run on the same host
- data volume is moderate to high but does not require a server
- interactive SQL over historical captures matters
- portability is useful

Avoid this when:

- many machines must write to one shared target at the same time
- multiple independent writers need concurrent writes into one local DB file

## Simple Local Fallback

Use SQLite in WAL mode when deployment simplicity matters more than analytical
scan speed.

Why:

- built into Python
- one local file
- good enough for small captures and metadata tables
- WAL mode allows readers and the writer to coexist better than rollback journal
  mode

Use this for:

- small test harness runs
- metadata catalogs
- low-volume captures
- environments where installing DuckDB is not acceptable

Avoid this for:

- high-cardinality long-running traffic history
- heavy analytical group-by queries over large captures
- network filesystems

## Networked Storage Recommendation

Use ClickHouse as the preferred networked database for high-rate UDP analyzer
history.

Why:

- columnar analytics database
- strong fit for append-heavy observability and time-series style data
- fast grouped queries over many dimensions
- efficient compression
- Python clients can batch inserts

Recommended table shape:

```sql
CREATE TABLE udp_samples
(
    ts DateTime64(3, 'UTC'),
    bucket_start_ns Int64,
    bucket_ms UInt32,
    src_ip IPv6,
    dst_ip IPv6,
    src_port UInt16,
    dst_port UInt16,
    ip_proto UInt8,
    ifindex UInt32,
    ifname LowCardinality(String),
    netns_id UInt64,
    container_id LowCardinality(String),
    process_name LowCardinality(String),
    host_pid UInt32,
    container_pid UInt32,
    socket_id UInt64,
    packets UInt64,
    bytes UInt64,
    layer LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (ts, dst_port, src_ip, dst_ip, ifindex, socket_id);
```

Recommended write strategy:

- batch rows client-side
- send inserts around once per second when possible
- use the native Python client format
- keep batches stable for retry safety
- optionally enable asynchronous inserts when many analyzers write small batches

Use this when:

- multiple hosts or containers write to one central target
- long retention and fast multidimensional queries matter
- dashboards or multiple Python analyzers will query the same data
- ingest rate may become large

## Networked Relational Alternative

Use TimescaleDB/PostgreSQL when the workload benefits from PostgreSQL semantics
more than maximum ingest speed.

Why:

- standard PostgreSQL ecosystem
- SQL, joins, views, indexes, permissions, and familiar tooling
- hypertables are natural for time-series data
- convenient for joining UDP history with operational metadata tables

Use this when:

- the team already runs PostgreSQL
- process/container metadata is relational and query-heavy
- retention and time-bucket queries are needed, but ingest rate is not extreme

Avoid this when:

- the main goal is maximum append throughput and large analytical scans
- the schema will be mostly wide event rows with many group-by dimensions

## Practical Default

Start with two storage targets:

1. `duckdb`: local default for development, harness runs, and offline analysis.
2. `clickhouse`: networked target for production or multi-host collection.

Keep the writer interface narrow:

```python
class SampleWriter:
    def write_samples(self, rows: list[dict]) -> None:
        ...

    def flush(self) -> None:
        ...

    def close(self) -> None:
        ...
```

Then implement:

- `DuckDBWriter`
- `ParquetWriter`
- `ClickHouseWriter`
- optional `SQLiteWriter`
- optional `TimescaleWriter`

## Retrieval Patterns

The storage schema should optimize these later Python analyzer queries:

- traffic by destination port over time
- top source IPs for one destination port
- traffic by interface
- ingress versus delivered byte delta
- traffic delivered to one process or socket
- all traffic for one Docker container
- source IPs feeding one `ffmpeg` process

Example generic query:

```sql
SELECT
    ts,
    dst_port,
    src_ip,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM udp_samples
WHERE ts >= ?
  AND ts < ?
GROUP BY ts, dst_port, src_ip
ORDER BY ts, bytes DESC;
```

## Decision

Use DuckDB/Parquet for local captures and ClickHouse for networked captures.
Treat SQLite and TimescaleDB/PostgreSQL as useful alternatives, not the primary
path.

## References

- DuckDB Python API: https://duckdb.org/docs/current/clients/python/overview
- SQLite write-ahead logging: https://www.sqlite.org/wal.html
- ClickHouse insert strategy: https://clickhouse.com/docs/best-practices/selecting-an-insert-strategy
- ClickHouse time-series operations: https://clickhouse.com/docs/use-cases/time-series/basic-operations
- Timescale hypertables: https://www.tigerdata.com/docs/use-timescale/latest/hypertables
