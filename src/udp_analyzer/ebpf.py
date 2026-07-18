from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .models import SampleFilter, UdpSample, bucket_start_ns
from .processes import ProcessSocketEnricher


UDP_INGRESS_PROGRAM_NAME = "udp_ingress"
UDP_INGRESS_MAP_NAME = "udp_ingress_counters"


@dataclass(frozen=True)
class UdpMapKey:
    family: int
    ip_proto: int
    src_port: int
    dst_port: int
    ifindex: int
    src_ip4: int
    dst_ip4: int

    @property
    def src_ip(self) -> str:
        return ipv4_from_bpf_int(self.src_ip4)

    @property
    def dst_ip(self) -> str:
        return ipv4_from_bpf_int(self.dst_ip4)

    def identity(self) -> tuple[int, int, int, int, int, int, int]:
        return (
            self.family,
            self.ip_proto,
            self.src_port,
            self.dst_port,
            self.ifindex,
            self.src_ip4,
            self.dst_ip4,
        )


@dataclass(frozen=True)
class UdpMapCounters:
    packets: int
    bytes: int


@dataclass(frozen=True)
class UdpMapEntry:
    key: UdpMapKey
    counters: UdpMapCounters


class CommandRunner:
    def run_json(self, args: list[str], sudo: bool = False) -> Any:
        result = self.run(args, sudo=sudo)
        try:
            return json.loads(result.stdout or "null")
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"command did not return JSON: {' '.join(args)}\n{result.stdout}"
            ) from exc

    def run(
        self, args: list[str], sudo: bool = False, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        command = ["sudo", "-n", *args] if sudo else args
        try:
            result = subprocess.run(
                command,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(f"required command not found: {command[0]}") from exc
        except PermissionError as exc:
            raise RuntimeError(f"permission denied running command: {command[0]}") from exc
        if check and result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"command failed: {' '.join(command)}\n{detail}")
        return result


class TcBpfAttachment:
    def __init__(
        self,
        ifname: str,
        object_path: Path,
        section: str,
        pref: int,
        runner: Optional[CommandRunner] = None,
    ):
        self.ifname = ifname
        self.object_path = object_path
        self.section = section
        self.pref = pref
        self.runner = runner or CommandRunner()
        self.attached = False

    def attach(self) -> None:
        if not self.object_path.exists():
            raise RuntimeError(f"BPF object does not exist: {self.object_path}")

        qdisc_result = self.runner.run(
            ["tc", "qdisc", "add", "dev", self.ifname, "clsact"],
            sudo=True,
            check=False,
        )
        qdisc_already_exists = (
            "File exists" in qdisc_result.stderr
            or "Exclusivity flag on" in qdisc_result.stderr
        )
        if qdisc_result.returncode != 0 and not qdisc_already_exists:
            raise RuntimeError(qdisc_result.stderr.strip())

        self.detach(ignore_missing=True)
        self.runner.run(
            [
                "tc",
                "filter",
                "add",
                "dev",
                self.ifname,
                "ingress",
                "protocol",
                "ip",
                "pref",
                str(self.pref),
                "bpf",
                "da",
                "obj",
                str(self.object_path),
                "sec",
                self.section,
            ],
            sudo=True,
        )
        self.attached = True

    def detach(self, ignore_missing: bool = False) -> None:
        result = self.runner.run(
            [
                "tc",
                "filter",
                "del",
                "dev",
                self.ifname,
                "ingress",
                "pref",
                str(self.pref),
            ],
            sudo=True,
            check=False,
        )
        if result.returncode == 0:
            self.attached = False
            return
        if ignore_missing:
            return
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"failed to detach tc filter: {detail}")


class BpftoolMapReader:
    def __init__(
        self,
        program_name: str = UDP_INGRESS_PROGRAM_NAME,
        map_name: str = UDP_INGRESS_MAP_NAME,
        runner: Optional[CommandRunner] = None,
    ):
        self.program_name = program_name
        self.map_name = map_name
        self.runner = runner or CommandRunner()
        self.map_id: Optional[int] = None

    def refresh_map_id(self) -> int:
        programs = self.runner.run_json(["bpftool", "-j", "prog", "show"], sudo=True)
        candidates = [
            program
            for program in programs
            if program.get("name") == self.program_name and program.get("map_ids")
        ]
        if not candidates:
            raise RuntimeError(
                f"could not find loaded BPF program named {self.program_name!r}"
            )

        newest = sorted(candidates, key=lambda item: int(item.get("id", 0)))[-1]
        map_ids = newest.get("map_ids") or []
        self.map_id = int(map_ids[0])
        return self.map_id

    def dump_entries(self) -> list[UdpMapEntry]:
        map_id = self.map_id or self.refresh_map_id()
        raw_entries = self.runner.run_json(
            ["bpftool", "-j", "map", "dump", "id", str(map_id)], sudo=True
        )
        if raw_entries is None:
            return []
        return [parse_bpftool_entry(entry) for entry in raw_entries]


class EbpfIngressCollector:
    def __init__(
        self,
        ifname: Optional[str],
        object_path: Path,
        section: str,
        pref: int,
        bucket_ms: int,
        sample_filter: Optional[SampleFilter] = None,
        attach: bool = True,
        detach_on_close: bool = True,
        process_enricher: Optional[ProcessSocketEnricher] = None,
    ):
        if attach:
            self.ifname = ifname or default_route_interface()
        else:
            self.ifname = ifname or "unknown"
        self.bucket_ms = bucket_ms
        self.sample_filter = sample_filter or SampleFilter()
        self.detach_on_close = detach_on_close
        self.process_enricher = process_enricher
        self.runner = CommandRunner()
        self.attachment = TcBpfAttachment(
            ifname=self.ifname,
            object_path=object_path,
            section=section,
            pref=pref,
            runner=self.runner,
        )
        self.reader = BpftoolMapReader(runner=self.runner)
        self.previous: dict[tuple[int, int, int, int, int, int, int], UdpMapCounters] = {}

        if attach:
            self.attachment.attach()
        self.reader.refresh_map_id()

    def read_checkpoint(self) -> list[UdpSample]:
        bucket_ns = bucket_start_ns(time.time_ns(), self.bucket_ms)
        samples: list[UdpSample] = []

        # AGGREGATE BY IDENTITY FIRST, then diff — never per raw map entry.
        # identity() deliberately ignores the key's padding bytes, so several map
        # entries can share one identity. Diffing per entry made `self.previous`
        # get overwritten by each duplicate in turn, so the "delta" was the
        # difference between two UNRELATED counters — it telescoped to noise
        # (rows of 1-2 packets for a 570 pps channel). Summing first is also
        # simply correct for a PERCPU map read that may split a flow.
        totals: dict[tuple, UdpMapCounters] = {}
        first_entry: dict[tuple, object] = {}
        for entry in self.reader.dump_entries():
            identity = entry.key.identity()
            acc = totals.get(identity)
            totals[identity] = UdpMapCounters(
                packets=(acc.packets if acc else 0) + entry.counters.packets,
                bytes=(acc.bytes if acc else 0) + entry.counters.bytes,
            )
            first_entry.setdefault(identity, entry)

        # a flow that vanished from the map is gone for good (a re-created entry
        # restarts at 0); dropping it keeps `previous` bounded and avoids a bogus
        # negative delta if the same 5-tuple comes back.
        for stale in set(self.previous) - set(totals):
            del self.previous[stale]

        for identity, counters in totals.items():
            entry = first_entry[identity]
            previous = self.previous.get(identity, UdpMapCounters(packets=0, bytes=0))
            self.previous[identity] = counters

            packet_delta = counters.packets - previous.packets
            byte_delta = counters.bytes - previous.bytes
            if packet_delta <= 0 and byte_delta <= 0:
                continue

            sample = UdpSample(
                bucket_start_ns=bucket_ns,
                bucket_ms=self.bucket_ms,
                src_ip=entry.key.src_ip,
                dst_ip=entry.key.dst_ip,
                src_port=entry.key.src_port,
                dst_port=entry.key.dst_port,
                ip_proto=entry.key.ip_proto,
                ifindex=entry.key.ifindex,
                ifname=ifname_from_index(entry.key.ifindex, self.ifname),
                packets=max(packet_delta, 0),
                bytes=max(byte_delta, 0),
                layer="ingress",
            )
            enriched_samples = (
                self.process_enricher.enrich(sample)
                if self.process_enricher is not None
                else [sample]
            )
            for enriched_sample in enriched_samples:
                if self.sample_filter.matches(enriched_sample):
                    samples.append(enriched_sample)

        return samples

    def close(self) -> None:
        if self.detach_on_close:
            self.attachment.detach(ignore_missing=True)


def parse_bpftool_entry(entry: dict[str, Any]) -> UdpMapEntry:
    key = parse_bpftool_key(entry.get("key"))
    value = entry.get("value")
    values = entry.get("values")
    counters = parse_bpftool_counters(value=value, values=values)
    return UdpMapEntry(key=key, counters=counters)


def parse_bpftool_key(raw_key: Any) -> UdpMapKey:
    if isinstance(raw_key, dict):
        return UdpMapKey(
            family=int(raw_key["family"]),
            ip_proto=int(raw_key["ip_proto"]),
            src_port=int(raw_key["src_port"]),
            dst_port=int(raw_key["dst_port"]),
            ifindex=int(raw_key["ifindex"]),
            src_ip4=int(raw_key["src_ip4"]),
            dst_ip4=int(raw_key["dst_ip4"]),
        )

    key_bytes = raw_bytes(raw_key)
    if len(key_bytes) < 20:
        raise RuntimeError(f"unexpected udp_key size from bpftool: {len(key_bytes)}")

    family, ip_proto, src_port, dst_port, ifindex, src_ip4, dst_ip4 = struct.unpack(
        "<BBHH2xIII", key_bytes[:20]
    )
    return UdpMapKey(
        family=family,
        ip_proto=ip_proto,
        src_port=src_port,
        dst_port=dst_port,
        ifindex=ifindex,
        src_ip4=src_ip4,
        dst_ip4=dst_ip4,
    )


def parse_bpftool_counters(value: Any, values: Any) -> UdpMapCounters:
    if values is not None:
        packets = 0
        bytes_seen = 0
        for cpu_value in values:
            parsed = parse_bpftool_counters(value=cpu_value.get("value"), values=None)
            packets += parsed.packets
            bytes_seen += parsed.bytes
        return UdpMapCounters(packets=packets, bytes=bytes_seen)

    if isinstance(value, dict):
        return UdpMapCounters(packets=int(value["packets"]), bytes=int(value["bytes"]))

    value_bytes = raw_bytes(value)
    if len(value_bytes) < 16:
        raise RuntimeError(
            f"unexpected udp_counters size from bpftool: {len(value_bytes)}"
        )
    packets, bytes_seen = struct.unpack("<QQ", value_bytes[:16])
    return UdpMapCounters(packets=packets, bytes=bytes_seen)


def raw_bytes(value: Any) -> bytes:
    if not isinstance(value, list):
        raise RuntimeError(f"expected bpftool byte list, got: {value!r}")
    return bytes(int(part, 16) if isinstance(part, str) else int(part) for part in value)


def ipv4_from_bpf_int(value: int) -> str:
    return str(ipaddress.IPv4Address(struct.pack("<I", value)))


def ifname_from_index(ifindex: int, fallback: str) -> str:
    try:
        return socket.if_indextoname(ifindex)
    except OSError:
        return fallback


def default_route_interface() -> str:
    result = CommandRunner().run(["ip", "route", "show", "default"], check=False)
    if result.returncode == 0:
        words = result.stdout.split()
        if "dev" in words:
            dev_index = words.index("dev") + 1
            if dev_index < len(words):
                return words[dev_index]

    env_ifname = os.environ.get("UDP_ANALYZER_IFACE")
    if env_ifname:
        return env_ifname

    raise RuntimeError(
        "could not detect default interface; pass --interface or set "
        "UDP_ANALYZER_IFACE"
    )
