import unittest

from udp_analyzer.ebpf import (
    ipv4_from_bpf_int,
    parse_bpftool_entry,
    parse_bpftool_key,
)


class EbpfParserTests(unittest.TestCase):
    def test_parse_pretty_bpftool_entry_sums_per_cpu_values(self):
        entry = {
            "key": {
                "family": 2,
                "ip_proto": 17,
                "src_port": 40000,
                "dst_port": 5000,
                "ifindex": 2,
                "src_ip4": 0x0A0200C0,
                "dst_ip4": 0x140064C6,
            },
            "values": [
                {"cpu": 0, "value": {"packets": 5, "bytes": 500}},
                {"cpu": 1, "value": {"packets": 7, "bytes": 700}},
            ],
        }

        parsed = parse_bpftool_entry(entry)

        self.assertEqual(parsed.key.src_ip, "192.0.2.10")
        self.assertEqual(parsed.key.dst_ip, "198.100.0.20")
        self.assertEqual(parsed.key.src_port, 40000)
        self.assertEqual(parsed.key.dst_port, 5000)
        self.assertEqual(parsed.counters.packets, 12)
        self.assertEqual(parsed.counters.bytes, 1200)

    def test_parse_raw_bpftool_key(self):
        raw_key = [
            "0x02",
            "0x11",
            "0x40",
            "0x9c",
            "0x88",
            "0x13",
            "0x00",
            "0x00",
            "0x02",
            "0x00",
            "0x00",
            "0x00",
            "0xc0",
            "0x00",
            "0x02",
            "0x0a",
            "0xc6",
            "0x64",
            "0x00",
            "0x14",
        ]

        parsed = parse_bpftool_key(raw_key)

        self.assertEqual(parsed.family, 2)
        self.assertEqual(parsed.ip_proto, 17)
        self.assertEqual(parsed.src_port, 40000)
        self.assertEqual(parsed.dst_port, 5000)
        self.assertEqual(parsed.ifindex, 2)
        self.assertEqual(parsed.src_ip, "192.0.2.10")
        self.assertEqual(parsed.dst_ip, "198.100.0.20")

    def test_ipv4_from_bpf_int_uses_packet_byte_order(self):
        self.assertEqual(ipv4_from_bpf_int(0x0A0200C0), "192.0.2.10")


if __name__ == "__main__":
    unittest.main()

