import time
import unittest
from unittest.mock import patch

from pinginfo.engine import PingEngine
from pinginfo.icmp import PingReply
from pinginfo.models import PingStatus


class EngineTest(unittest.TestCase):
    def test_run_once_records_replies(self):
        engine = PingEngine()
        engine.timeout = 0.2
        engine.ping_interval = 0.05

        def fake_ping(pairs, timeout, send_pause=0.0):
            return {ip: PingReply(True, rtt_ms=4.2, ttl=64) for ip, _family in pairs}

        with patch("pinginfo.engine.ping_many", side_effect=fake_ping):
            warnings, count = engine.run_once("8.8.8.8\n1.1.1.1", rounds=1)
        self.assertEqual(warnings, [])
        self.assertEqual(count, 2)
        rows = engine.snapshot()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r.status == PingStatus.ONLINE for r in rows))
        self.assertTrue(all(r.sent >= 1 for r in rows))
        self.assertTrue(all(r.ttl == 64 for r in rows))

    def test_interval_waits_between_rounds(self):
        engine = PingEngine()
        engine.timeout = 0.05
        engine.ping_interval = 0.25
        calls = {"n": 0}

        def fake_ping(pairs, timeout, send_pause=0.0):
            calls["n"] += 1
            return {ip: PingReply(True, rtt_ms=1.0, ttl=32) for ip, _family in pairs}

        started = time.perf_counter()
        with patch("pinginfo.engine.ping_many", side_effect=fake_ping):
            engine.run_once("127.0.0.1", rounds=2)
        elapsed = time.perf_counter() - started
        self.assertGreaterEqual(calls["n"], 2)
        self.assertGreaterEqual(elapsed, 0.2)
