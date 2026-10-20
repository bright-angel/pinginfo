import unittest
from io import StringIO
from unittest.mock import patch

from pinginfo.cli import build_parser, main


class CliTest(unittest.TestCase):
    def test_parser_version(self):
        parser = build_parser()
        with self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_main_does_not_start_gui_on_version(self):
        with patch("sys.stdout", new_callable=StringIO) as out:
            with self.assertRaises(SystemExit):
                main(["--version"])
        self.assertIn("pinginfo", out.getvalue())

    def test_once_requires_targets(self):
        with patch("sys.stdin.isatty", return_value=True):
            code = main(["--once"])
        self.assertEqual(code, 2)

    def test_once_writes_csv(self):
        from pinginfo.icmp import PingReply

        fake = PingReply(True, rtt_ms=3.5, ttl=64)

        with patch("sys.stdout", new_callable=StringIO) as out:
            with patch("pinginfo.engine.ping_many", return_value={"8.8.8.8": fake}):
                code = main(
                    ["--once", "--targets", "8.8.8.8", "--timeout", "0.2", "--interval", "0.05"]
                )
        self.assertEqual(code, 0)
        self.assertIn("8.8.8.8", out.getvalue())


if __name__ == "__main__":
    unittest.main()
