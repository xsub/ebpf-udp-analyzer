from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional, Protocol

from .models import SampleFilter, UdpSample, bucket_start_ns


class Collector(Protocol):
    def read_checkpoint(self) -> list[UdpSample]:
        """Return delta samples for one checkpoint."""


@dataclass(frozen=True)
class DryRunStream:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ifindex: int
    ifname: str
    payload_size: int
    packet_base: int
    layer: str
    container_id: str = ""
    process_name: str = ""
    host_pid: int = 0
    container_pid: int = 0
    socket_id: int = 0


class DryRunCollector:
    """Deterministic collector used for CLI, storage, and harness development."""

    def __init__(self, bucket_ms: int, sample_filter: Optional[SampleFilter] = None):
        self.bucket_ms = bucket_ms
        self.sample_filter = sample_filter or SampleFilter()
        self.tick = 0
        self.streams = [
            DryRunStream(
                src_ip="192.0.2.10",
                dst_ip="198.51.100.20",
                src_port=40000,
                dst_port=5000,
                ifindex=2,
                ifname="eth0",
                payload_size=1316,
                packet_base=100,
                layer="delivered",
                container_id="demo-ffmpeg",
                process_name="ffmpeg",
                host_pid=4242,
                container_pid=101,
                socket_id=500001,
            ),
            DryRunStream(
                src_ip="192.0.2.11",
                dst_ip="198.51.100.20",
                src_port=40010,
                dst_port=5001,
                ifindex=2,
                ifname="eth0",
                payload_size=1200,
                packet_base=75,
                layer="delivered",
                container_id="demo-ffmpeg",
                process_name="ffmpeg",
                host_pid=4243,
                container_pid=102,
                socket_id=500002,
            ),
            DryRunStream(
                src_ip="192.0.2.12",
                dst_ip="198.51.100.20",
                src_port=40020,
                dst_port=5999,
                ifindex=2,
                ifname="eth0",
                payload_size=512,
                packet_base=12,
                layer="ingress",
            ),
        ]

    def read_checkpoint(self) -> list[UdpSample]:
        now_ns = time.time_ns()
        bucket_ns = bucket_start_ns(now_ns, self.bucket_ms)
        self.tick += 1
        samples: list[UdpSample] = []

        for index, stream in enumerate(self.streams):
            packets = stream.packet_base + self.tick + index
            sample = UdpSample(
                bucket_start_ns=bucket_ns,
                bucket_ms=self.bucket_ms,
                src_ip=stream.src_ip,
                dst_ip=stream.dst_ip,
                src_port=stream.src_port,
                dst_port=stream.dst_port,
                ifindex=stream.ifindex,
                ifname=stream.ifname,
                packets=packets,
                bytes=packets * stream.payload_size,
                layer=stream.layer,
                container_id=stream.container_id,
                process_name=stream.process_name,
                host_pid=stream.host_pid,
                container_pid=stream.container_pid,
                socket_id=stream.socket_id,
            )
            if self.sample_filter.matches(sample):
                samples.append(sample)

        return samples


class EbpfCollector:
    """Placeholder for the real eBPF map-draining collector."""

    def __init__(self, bucket_ms: int, sample_filter: Optional[SampleFilter] = None):
        self.bucket_ms = bucket_ms
        self.sample_filter = sample_filter or SampleFilter()

    def read_checkpoint(self) -> list[UdpSample]:
        raise RuntimeError(
            "eBPF collector is not wired yet. Use --collector dry-run for now; "
            "the first eBPF program lives in bpf/udp_ingress.bpf.c."
        )
