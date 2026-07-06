from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Union


UDP_PROTO = 17


@dataclass(frozen=True)
class UdpSample:
    bucket_start_ns: int
    bucket_ms: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ifindex: int
    ifname: str
    packets: int
    bytes: int
    ip_proto: int = UDP_PROTO
    netns_id: int = 0
    container_id: str = ""
    process_name: str = ""
    host_pid: int = 0
    container_pid: int = 0
    socket_id: int = 0
    layer: str = "ingress"

    @property
    def bucket_start_iso(self) -> str:
        seconds = self.bucket_start_ns / 1_000_000_000
        return (
            datetime.fromtimestamp(seconds, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

    def to_dict(self) -> dict[str, Union[int, str]]:
        return {
            "ts": self.bucket_start_iso,
            "bucket_start_ns": self.bucket_start_ns,
            "bucket_ms": self.bucket_ms,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "ip_proto": self.ip_proto,
            "ifindex": self.ifindex,
            "ifname": self.ifname,
            "netns_id": self.netns_id,
            "container_id": self.container_id,
            "process_name": self.process_name,
            "host_pid": self.host_pid,
            "container_pid": self.container_pid,
            "socket_id": self.socket_id,
            "packets": self.packets,
            "bytes": self.bytes,
            "layer": self.layer,
        }


@dataclass(frozen=True)
class SampleFilter:
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    ifname: Optional[str] = None
    process_name: Optional[str] = None
    layer: Optional[str] = None

    def matches(self, sample: UdpSample) -> bool:
        checks = (
            self.src_ip is None or sample.src_ip == self.src_ip,
            self.dst_ip is None or sample.dst_ip == self.dst_ip,
            self.src_port is None or sample.src_port == self.src_port,
            self.dst_port is None or sample.dst_port == self.dst_port,
            self.ifname is None or sample.ifname == self.ifname,
            self.process_name is None or sample.process_name == self.process_name,
            self.layer is None or sample.layer == self.layer,
        )
        return all(checks)


def bucket_start_ns(now_ns: int, bucket_ms: int) -> int:
    bucket_ns = bucket_ms * 1_000_000
    return (now_ns // bucket_ns) * bucket_ns
