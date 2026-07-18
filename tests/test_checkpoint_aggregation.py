"""Regression: one 5-tuple spread over several map entries must be SUMMED, not
diffed entry-by-entry.

Background (found in production on a TV recorder): `struct udp_key` had an
uninitialized 2-byte padding hole, so a single flow scattered across thousands of
distinct map entries and the 65536-entry map saturated within seconds. The BPF
side is fixed by memset-ing the key, but the reader must be robust anyway:
`identity()` ignores the padding, so several entries can legitimately collapse
onto one identity (and a PERCPU read may split a flow). Diffing per entry made
`self.previous[identity]` get overwritten by each duplicate in turn, so the
"delta" was the difference between two UNRELATED counters — it telescoped into
noise (rows of 1-2 packets for a ~570 pps channel).
"""
import unittest
from pathlib import Path
from unittest import mock

from udp_analyzer.ebpf import EbpfIngressCollector, UdpMapCounters


def _entry(packets, bytes_, *, src_port=40000, dst_port=5000):
    """A bpftool-shaped entry for one and the same 5-tuple."""
    return {
        "key": {
            "family": 2, "ip_proto": 17,
            "src_port": src_port, "dst_port": dst_port, "ifindex": 2,
            "src_ip4": 0x0A0200C0, "dst_ip4": 0x140064C6,
        },
        "values": [{"cpu": 0, "value": {"packets": packets, "bytes": bytes_}}],
    }


class _FakeReader:
    """Stands in for BpftoolMapReader; returns whatever entries the test queues."""

    def __init__(self, runner=None):
        self.batches = []

    def refresh_map_id(self):
        return 1

    def dump_entries(self):
        from udp_analyzer.ebpf import parse_bpftool_entry

        return [parse_bpftool_entry(e) for e in self.batches.pop(0)]


def _collector():
    """__init__ calls reader.refresh_map_id() (real bpftool + sudo), so substitute
    the reader class for the duration of construction."""
    reader = _FakeReader()
    with mock.patch("udp_analyzer.ebpf.BpftoolMapReader", return_value=reader):
        c = EbpfIngressCollector(
            ifname="eth0", object_path=Path("bpf/udp_ingress.bpf.o"),
            section="classifier/udp_ingress", pref=49152, bucket_ms=1000,
            attach=False, detach_on_close=False,
        )
    assert c.reader is reader
    return c


class CheckpointAggregationTests(unittest.TestCase):
    def test_duplicate_entries_of_one_flow_are_summed(self):
        c = _collector()
        # tick 1: the flow is split across 3 entries (cumulative counters)
        c.reader.batches.append([_entry(100, 131600), _entry(200, 263200),
                                 _entry(270, 355320)])
        first = c.read_checkpoint()
        # first sight: previous=0, so the delta is the full 570 packets
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0].packets, 570)
        self.assertEqual(first[0].bytes, 131600 + 263200 + 355320)

        # tick 2: each entry advanced; the delta must be the SUM of the increments
        c.reader.batches.append([_entry(150, 197400), _entry(400, 526400),
                                 _entry(590, 776440)])
        second = c.read_checkpoint()
        self.assertEqual(len(second), 1)
        self.assertEqual(second[0].packets, (150 + 400 + 590) - 570)   # = 570

    def test_no_traffic_emits_nothing(self):
        c = _collector()
        c.reader.batches.append([_entry(570, 750120)])
        c.read_checkpoint()
        c.reader.batches.append([_entry(570, 750120)])          # unchanged
        self.assertEqual(c.read_checkpoint(), [])

    def test_vanished_flow_is_dropped_from_previous(self):
        c = _collector()
        c.reader.batches.append([_entry(100, 131600)])
        c.read_checkpoint()
        self.assertEqual(len(c.previous), 1)
        c.reader.batches.append([])                             # flow gone from the map
        c.read_checkpoint()
        self.assertEqual(c.previous, {})                        # state stays bounded

        # and when the same 5-tuple returns, its counters restart from 0 without
        # producing a bogus negative delta
        c.reader.batches.append([_entry(42, 55272)])
        again = c.read_checkpoint()
        self.assertEqual(len(again), 1)
        self.assertEqual(again[0].packets, 42)

    def test_distinct_flows_stay_separate(self):
        c = _collector()
        c.reader.batches.append([_entry(100, 131600, dst_port=5000),
                                 _entry(300, 394800, dst_port=5001)])
        rows = c.read_checkpoint()
        self.assertEqual(sorted(r.packets for r in rows), [100, 300])


if __name__ == "__main__":
    unittest.main()
