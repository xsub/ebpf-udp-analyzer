import unittest

from udp_analyzer.models import SampleFilter, UdpSample, bucket_start_ns


class ModelTests(unittest.TestCase):
    def test_bucket_start_ns_aligns_to_bucket(self):
        self.assertEqual(bucket_start_ns(1_234_567_890, 1000), 1_000_000_000)

    def test_sample_filter_matches_selected_fields(self):
        sample = UdpSample(
            bucket_start_ns=1_000_000_000,
            bucket_ms=1000,
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            src_port=40000,
            dst_port=5000,
            ifindex=2,
            ifname="eth0",
            packets=10,
            bytes=1000,
            process_name="ffmpeg",
            layer="delivered",
        )

        self.assertTrue(SampleFilter(dst_port=5000, process_name="ffmpeg").matches(sample))
        self.assertFalse(SampleFilter(dst_port=5001).matches(sample))


if __name__ == "__main__":
    unittest.main()
