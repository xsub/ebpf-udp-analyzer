import json
import tempfile
import unittest
from pathlib import Path

from harness.assert_output import read_rows, validate_dry_run, validate_rows


class HarnessAssertOutputTests(unittest.TestCase):
    def test_validates_dry_run_profile(self):
        rows = [
            {
                "ts": "2026-07-06T12:00:00.000Z",
                "bucket_ms": 1000,
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.20",
                "src_port": 40000,
                "dst_port": 5000,
                "ifindex": 2,
                "ifname": "eth0",
                "packets": 1,
                "bytes": 1316,
                "layer": "delivered",
                "process_name": "ffmpeg",
            },
            {
                "ts": "2026-07-06T12:00:00.000Z",
                "bucket_ms": 1000,
                "src_ip": "192.0.2.11",
                "dst_ip": "198.51.100.20",
                "src_port": 40010,
                "dst_port": 5001,
                "ifindex": 2,
                "ifname": "eth0",
                "packets": 1,
                "bytes": 1200,
                "layer": "delivered",
                "process_name": "ffmpeg",
            },
            {
                "ts": "2026-07-06T12:00:00.000Z",
                "bucket_ms": 1000,
                "src_ip": "192.0.2.12",
                "dst_ip": "198.51.100.20",
                "src_port": 40020,
                "dst_port": 5999,
                "ifindex": 2,
                "ifname": "eth0",
                "packets": 1,
                "bytes": 512,
                "layer": "ingress",
                "process_name": "",
            },
        ]

        validate_rows(rows, allow_empty=False)
        validate_dry_run(rows)

    def test_reads_json_lines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "samples.ndjson"
            path.write_text(json.dumps({"packets": 1}) + "\n", encoding="utf-8")

            self.assertEqual(read_rows(path), [{"packets": 1}])


if __name__ == "__main__":
    unittest.main()

