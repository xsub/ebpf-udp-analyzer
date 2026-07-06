from __future__ import annotations

import json
import sqlite3
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Protocol, Union

from .models import UdpSample


SCHEMA_COLUMNS = """
    bucket_start_ns INTEGER NOT NULL,
    bucket_ms INTEGER NOT NULL,
    ts TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    ip_proto INTEGER NOT NULL,
    ifindex INTEGER NOT NULL,
    ifname TEXT NOT NULL,
    netns_id INTEGER NOT NULL,
    container_id TEXT NOT NULL,
    process_name TEXT NOT NULL,
    host_pid INTEGER NOT NULL,
    container_pid INTEGER NOT NULL,
    socket_id INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    layer TEXT NOT NULL
"""


INSERT_COLUMNS = [
    "bucket_start_ns",
    "bucket_ms",
    "ts",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "ip_proto",
    "ifindex",
    "ifname",
    "netns_id",
    "container_id",
    "process_name",
    "host_pid",
    "container_pid",
    "socket_id",
    "packets",
    "bytes",
    "layer",
]


class SampleWriter(Protocol):
    def write_samples(self, rows: list[UdpSample]) -> None:
        ...

    def flush(self) -> None:
        ...

    def close(self) -> None:
        ...


class NullWriter:
    def write_samples(self, rows: list[UdpSample]) -> None:
        return None

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None


def sample_values(sample: UdpSample) -> tuple[Union[int, str], ...]:
    data = sample.to_dict()
    return tuple(data[column] for column in INSERT_COLUMNS)


class SQLiteWriter:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute(f"CREATE TABLE IF NOT EXISTS udp_samples ({SCHEMA_COLUMNS})")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS udp_samples_time_idx "
            "ON udp_samples (bucket_start_ns, dst_port, src_ip)"
        )

    def write_samples(self, rows: list[UdpSample]) -> None:
        if not rows:
            return
        placeholders = ", ".join("?" for _ in INSERT_COLUMNS)
        columns = ", ".join(INSERT_COLUMNS)
        self.conn.executemany(
            f"INSERT INTO udp_samples ({columns}) VALUES ({placeholders})",
            [sample_values(row) for row in rows],
        )
        self.conn.commit()

    def flush(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


class DuckDBWriter:
    def __init__(self, path: Path):
        try:
            import duckdb
        except ImportError as exc:
            raise RuntimeError(
                "DuckDB storage requires the optional dependency: "
                "pip install 'ebpf-udp-analyzer[duckdb]'"
            ) from exc

        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(str(self.path))
        self.conn.execute(f"CREATE TABLE IF NOT EXISTS udp_samples ({SCHEMA_COLUMNS})")

    def write_samples(self, rows: list[UdpSample]) -> None:
        if not rows:
            return
        placeholders = ", ".join("?" for _ in INSERT_COLUMNS)
        columns = ", ".join(INSERT_COLUMNS)
        self.conn.executemany(
            f"INSERT INTO udp_samples ({columns}) VALUES ({placeholders})",
            [sample_values(row) for row in rows],
        )

    def flush(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


class ParquetWriter:
    def __init__(self, path: Path):
        try:
            import duckdb
        except ImportError as exc:
            raise RuntimeError(
                "Parquet storage requires DuckDB: "
                "pip install 'ebpf-udp-analyzer[duckdb]'"
            ) from exc

        self.duckdb = duckdb
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.rows: list[UdpSample] = []

    def write_samples(self, rows: list[UdpSample]) -> None:
        self.rows.extend(rows)

    def flush(self) -> None:
        if not self.rows:
            return

        conn = self.duckdb.connect(":memory:")
        try:
            conn.execute(f"CREATE TABLE udp_samples ({SCHEMA_COLUMNS})")
            placeholders = ", ".join("?" for _ in INSERT_COLUMNS)
            columns = ", ".join(INSERT_COLUMNS)
            conn.executemany(
                f"INSERT INTO udp_samples ({columns}) VALUES ({placeholders})",
                [sample_values(row) for row in self.rows],
            )
            conn.execute(
                "COPY udp_samples TO ? (FORMAT PARQUET)",
                [str(self.path)],
            )
        finally:
            conn.close()

    def close(self) -> None:
        self.flush()


class ClickHouseHttpWriter:
    def __init__(self, url: str, table: str):
        self.url = url.rstrip("/")
        self.table = table

    def write_samples(self, rows: list[UdpSample]) -> None:
        if not rows:
            return

        body = "\n".join(json.dumps(row.to_dict()) for row in rows).encode()
        query = urllib.parse.urlencode(
            {"query": f"INSERT INTO {self.table} FORMAT JSONEachRow"}
        )
        request = urllib.request.Request(
            f"{self.url}/?{query}",
            data=body,
            method="POST",
            headers={"Content-Type": "application/x-ndjson"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status >= 300:
                raise RuntimeError(f"ClickHouse insert failed: HTTP {response.status}")

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None
