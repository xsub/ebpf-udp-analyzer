import sqlite3
import tempfile
import unittest
from pathlib import Path

from udp_analyzer.models import UdpSample
from udp_analyzer.writers import SQLiteWriter


class WriterTests(unittest.TestCase):
    def test_sqlite_writer_persists_samples(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "samples.sqlite"
            writer = SQLiteWriter(db_path)
            writer.write_samples(
                [
                    UdpSample(
                        bucket_start_ns=1_000_000_000,
                        bucket_ms=1000,
                        src_ip="192.0.2.10",
                        dst_ip="198.51.100.20",
                        src_port=40000,
                        dst_port=5000,
                        ifindex=2,
                        ifname="eth0",
                        packets=10,
                        bytes=13160,
                    )
                ]
            )
            writer.close()

            conn = sqlite3.connect(db_path)
            count, packets, bytes_seen = conn.execute(
                "SELECT count(*), sum(packets), sum(bytes) FROM udp_samples"
            ).fetchone()
            conn.close()

            self.assertEqual(count, 1)
            self.assertEqual(packets, 10)
            self.assertEqual(bytes_seen, 13160)


if __name__ == "__main__":
    unittest.main()
