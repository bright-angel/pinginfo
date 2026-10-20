import unittest

from pinginfo.expander import expand_all, expand_cidr, expand_ipv6_range


class EngineExpandTest(unittest.TestCase):
    def test_ipv6_cidr_small(self):
        hosts = expand_cidr("2001:db8::/126")
        self.assertGreaterEqual(len(hosts), 2)
        self.assertTrue(all(":" in h for h in hosts))

    def test_ipv6_range(self):
        hosts = expand_ipv6_range("2001:db8::1-2001:db8::3")
        self.assertEqual(hosts, ["2001:db8::1", "2001:db8::2", "2001:db8::3"])

    def test_mixed_input_count(self):
        hosts, invalid, warnings = expand_all(
            "8.8.8.8\n192.168.1.1-4\n::1\nnot a host!!\n10.0.0.0/30"
        )
        self.assertIn("8.8.8.8", hosts)
        self.assertIn("::1", hosts)
        self.assertEqual(len([h for h in hosts if h.startswith("192.168.1.")]), 4)
        self.assertTrue(invalid)
        self.assertEqual(warnings, [])


if __name__ == "__main__":
    unittest.main()
