import unittest

from pinginfo.icmp import _checksum
from pinginfo.models import PingResult, PingStatus


class ModelsTest(unittest.TestCase):
    def test_record_ping(self):
        row = PingResult(hostname="8.8.8.8")
        row.record_ping(True, 12.3, None)
        self.assertEqual(row.status, PingStatus.ONLINE)
        self.assertEqual(row.sent, 1)
        self.assertEqual(row.received, 1)
        row.record_ping(False, None, "Request timeout")
        self.assertEqual(row.status, PingStatus.ONLINE)
        row.record_ping(False, None, "Request timeout")
        self.assertEqual(row.status, PingStatus.OFFLINE)
        self.assertAlmostEqual(row.packet_loss, 200.0 / 3.0, places=4)

    def test_latency_stats_and_ttl(self):
        row = PingResult(hostname="1.1.1.1")
        row.record_ping(True, 10.0, None, ttl=64)
        row.record_ping(True, 20.0, None, ttl=63)
        self.assertEqual(row.ttl, 63)
        self.assertAlmostEqual(row.min_latency, 10.0)
        self.assertAlmostEqual(row.max_latency, 20.0)
        self.assertAlmostEqual(row.average_latency, 15.0)
        self.assertIsNotNone(row.jitter)
        values = row.as_row()
        self.assertEqual(values[0], "在线")
        self.assertEqual(len(values), 15)

    def test_checksum_even(self):
        data = bytes(range(16))
        self.assertTrue(0 <= _checksum(data) <= 0xFFFF)
        payload = b"\x08\x00\x00\x00\x12\x34\x00\x01" + b"abcd"
        ck = _checksum(payload)
        packed = payload[:2] + ck.to_bytes(2, "big") + payload[4:]
        self.assertEqual(_checksum(packed), 0)


if __name__ == "__main__":
    unittest.main()
